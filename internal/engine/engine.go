// Package engine is the Sentra WAF data plane. It is deliberately free of any
// Caddy or storage dependency: it evaluates an immutable compiled ruleset and
// IP/rate-limit state entirely in memory.
package engine

import (
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/ipset"
	"github.com/Xwudao/sentra/internal/metrics"
	"github.com/Xwudao/sentra/internal/ratelimit"
	"github.com/Xwudao/sentra/internal/rule"
)

// BodyLimitAction decides what happens when the body exceeds the inspection
// window.
type BodyLimitAction string

const (
	BodyLimitAllow BodyLimitAction = "allow"
	BodyLimitBlock BodyLimitAction = "block"
)

// Config holds the tunables that may change at runtime.
type Config struct {
	MaxRequestBodySize int64            `json:"max_request_body_size"`
	BodyLimitAction    BodyLimitAction  `json:"body_limit_action"`
	AnomalyThreshold   int              `json:"anomaly_threshold"`
	TrustedProxies     []netip.Prefix   `json:"trusted_proxies"`
	ClientIPHeader     string           `json:"client_ip_header"`
	RateLimit          ratelimit.Config `json:"-"`
}

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{
		MaxRequestBodySize: defaultMaxBody,
		BodyLimitAction:    BodyLimitAllow,
		AnomalyThreshold:   0,
	}
}

// Options wires optional collaborators into an Engine.
type Options struct {
	Metrics *metrics.Metrics
	Events  *event.Writer
	Logger  *slog.Logger
}

// Engine evaluates requests against the current immutable snapshot.
type Engine struct {
	cfg atomic.Pointer[Config]

	rules   atomic.Pointer[rule.CompiledRuleset]
	ips     atomic.Pointer[ipset.Set]
	limiter *ratelimit.Limiter

	events  *event.Writer
	metrics *metrics.Metrics
	logger  *slog.Logger

	version atomic.Int64
}

// New builds an Engine.
func New(cfg Config, opt Options) *Engine {
	if cfg.MaxRequestBodySize <= 0 {
		cfg.MaxRequestBodySize = defaultMaxBody
	}
	if cfg.BodyLimitAction == "" {
		cfg.BodyLimitAction = BodyLimitAllow
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	e := &Engine{
		events:  opt.Events,
		metrics: opt.Metrics,
		logger:  opt.Logger,
	}
	if e.metrics == nil {
		e.metrics = &metrics.Metrics{}
	}
	e.cfg.Store(&cfg)
	e.limiter = ratelimit.New(nil, cfg.RateLimit)
	// Publish an empty ruleset so Evaluate never sees nil.
	empty, _ := rule.Compile(nil, 0)
	e.rules.Store(empty)
	emptyIP, _ := ipset.Build(nil)
	e.ips.Store(emptyIP)
	return e
}

// Metrics exposes the engine counters.
func (e *Engine) Metrics() *metrics.Metrics { return e.metrics }

// Config returns the current configuration snapshot.
func (e *Engine) Config() Config { return *e.cfg.Load() }

// SetConfig replaces the runtime configuration.
func (e *Engine) SetConfig(cfg Config) {
	if cfg.MaxRequestBodySize <= 0 {
		cfg.MaxRequestBodySize = defaultMaxBody
	}
	if cfg.BodyLimitAction == "" {
		cfg.BodyLimitAction = BodyLimitAllow
	}
	e.cfg.Store(&cfg)
}

// Close stops background helpers owned by the engine.
func (e *Engine) Close() {
	if e.limiter != nil {
		e.limiter.Stop()
	}
}

// Ruleset returns the live compiled ruleset (read-only).
func (e *Engine) Ruleset() *rule.CompiledRuleset { return e.rules.Load() }

// ReloadRules compiles rules and atomically publishes the result. On error the
// previous ruleset remains active and the error is returned.
func (e *Engine) ReloadRules(rules []rule.Rule) (*rule.CompiledRuleset, error) {
	v := e.version.Add(1)
	cs, err := rule.Compile(rules, v)
	if err != nil {
		e.version.Add(-1)
		return nil, err
	}
	e.rules.Store(cs)
	e.metrics.RulesLoaded.Store(int64(cs.RuleCount))
	return cs, nil
}

// ReloadIPRules compiles IP rules and atomically publishes them.
func (e *Engine) ReloadIPRules(entries []ipset.Entry) error {
	set, err := ipset.Build(entries)
	if err != nil {
		return err
	}
	e.ips.Store(set)
	e.metrics.IPRulesLoaded.Store(int64(set.Size()))
	return nil
}

// ReloadRateLimit replaces the rate-limit policies while preserving counters.
func (e *Engine) ReloadRateLimit(rules []ratelimit.Rule) {
	e.limiter.Reload(rules)
}

// NewContext builds a RequestContext and resolves the trusted client IP.
func (e *Engine) NewContext(r *http.Request) *RequestContext {
	cfg := e.cfg.Load()
	ctx := NewRequestContext(r, cfg.MaxRequestBodySize)
	ctx.ClientIP = ResolveClientIP(r, cfg.TrustedProxies, cfg.ClientIPHeader)
	return ctx
}

// Evaluate runs the full data-plane pipeline for a request.
func (e *Engine) Evaluate(ctx *RequestContext) Decision {
	return e.evaluate(ctx, false)
}

// EvaluateDebug runs evaluation in playground mode: no events are emitted and
// matches include raw/transformed values.
func (e *Engine) EvaluateDebug(ctx *RequestContext) Decision {
	return e.evaluate(ctx, true)
}

func (e *Engine) evaluate(ctx *RequestContext, debug bool) Decision {
	start := time.Now()
	cfg := e.cfg.Load()
	d := Decision{Action: rule.ActionAllow}

	if !debug {
		e.metrics.RequestsTotal.Add(1)
	}

	// 1. IP allow / block. Allow wins and bypasses the WAF entirely.
	if set := e.ips.Load(); set != nil && ctx.ClientIP.IsValid() {
		if action, ok := set.ActionFor(ctx.ClientIP); ok {
			if action == ipset.ActionAllow {
				d.AllowedByIP = true
				d.Action = rule.ActionAllow
				e.finish(ctx, &d, debug, start)
				return d
			}
			d.BlockedByIP = true
			d.Blocked = true
			d.Action = rule.ActionBlock
			d.StatusCode = http.StatusForbidden
			e.finish(ctx, &d, debug, start)
			return d
		}
	}

	// 2. Rate limit.
	if !debug && ctx.ClientIP.IsValid() {
		if allowed, retry := e.limiter.Allow(ctx.ClientIP, ctx.Path, start); !allowed {
			d.Blocked = true
			d.RateLimited = true
			d.Action = rule.ActionBlock
			d.StatusCode = http.StatusTooManyRequests
			_ = retry
			e.metrics.RateLimitBlocked.Add(1)
			e.finish(ctx, &d, debug, start)
			return d
		}
	}

	// 3. WAF rules.
	rs := e.rules.Load()
	e.runRules(ctx, rs, cfg, &d, debug)

	// 4. Body-size policy.
	if rs.NeedBody && ctx.BodyTruncated() && cfg.BodyLimitAction == BodyLimitBlock {
		d.Blocked = true
		d.Action = rule.ActionBlock
		if d.StatusCode == 0 {
			d.StatusCode = http.StatusRequestEntityTooLarge
		}
	}

	if d.Blocked {
		d.Action = rule.ActionBlock
		if d.StatusCode == 0 {
			d.StatusCode = http.StatusForbidden
		}
	} else if len(d.Matches) > 0 {
		d.Action = rule.ActionLog
	}

	e.finish(ctx, &d, debug, start)
	return d
}

func (e *Engine) runRules(ctx *RequestContext, rs *rule.CompiledRuleset, cfg *Config, d *Decision, debug bool) {
	if rs == nil {
		return
	}
	blocked := false
	for _, g := range rs.Groups {
		if blocked && !debug {
			break
		}
		values := ctx.Extract(g.Target)
		if len(values) == 0 {
			continue
		}
		transformed := g.Pipeline.Apply(values)
		for _, gm := range g.Matchers {
			for i, tv := range transformed {
				if !gm.Matcher.Match(tv) {
					continue
				}
				m := Match{
					RuleID:   gm.Rule.ID,
					RuleName: gm.Rule.Name,
					Target:   g.Target.String(),
					Severity: string(gm.Rule.Severity),
					Score:    gm.Rule.Score,
					Action:   gm.Rule.Action,
				}
				if debug {
					if i < len(values) {
						m.Raw = string(values[i])
					}
					m.Transformed = string(tv)
				}
				d.Matches = append(d.Matches, m)
				d.Score += gm.Rule.Score
				if !debug {
					e.metrics.RuleMatchesTotal.Add(1)
				}
				switch gm.Rule.Action {
				case rule.ActionAllow:
					d.Action = rule.ActionAllow
					d.Blocked = false
					return
				case rule.ActionBlock:
					d.Blocked = true
					blocked = true
				}
				break // one hit per rule per group is sufficient
			}
		}
	}
	if !d.Blocked && cfg.AnomalyThreshold > 0 && d.Score >= cfg.AnomalyThreshold {
		d.Blocked = true
		d.Action = rule.ActionBlock
		if d.StatusCode == 0 {
			d.StatusCode = http.StatusForbidden
		}
	}
}

func (e *Engine) finish(ctx *RequestContext, d *Decision, debug bool, start time.Time) {
	elapsed := time.Since(start)
	if debug {
		d.Debug = &DebugResult{Matches: d.Matches}
		return
	}
	if d.Blocked {
		e.metrics.RequestsBlocked.Add(1)
	} else {
		e.metrics.RequestsAllowed.Add(1)
	}
	e.metrics.ObserveDuration(elapsed.Seconds())
	e.metrics.ObserveRequest(d.Blocked)

	if e.events != nil && (d.Blocked || len(d.Matches) > 0) {
		e.events.Emit(e.buildEvent(ctx, d, elapsed))
	}
}

func (e *Engine) buildEvent(ctx *RequestContext, d *Decision, elapsed time.Duration) event.SecurityEvent {
	matches := make([]event.Match, 0, len(d.Matches))
	for _, m := range d.Matches {
		matches = append(matches, event.Match{
			RuleID:   m.RuleID,
			RuleName: m.RuleName,
			Target:   m.Target,
			Severity: m.Severity,
			Score:    m.Score,
			Action:   string(m.Action),
		})
	}
	ev := event.SecurityEvent{
		ClientIP:      ctx.ClientIP.String(),
		Method:        ctx.Method,
		Host:          ctx.Host,
		Path:          ctx.Path,
		Query:         ctx.Query,
		UserAgent:     ctx.Headers.Get("User-Agent"),
		Action:        string(d.Action),
		Status:        d.StatusCode,
		Score:         d.Score,
		Matches:       matches,
		DurationUS:    elapsed.Microseconds(),
		BodyTruncated: ctx.BodyTruncated(),
	}
	return ev
}
