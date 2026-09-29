// Package ratelimit implements a bounded, sharded, fixed-window rate limiter
// keyed by client IP and a path pattern. It is designed to fail open and to
// never grow without bound, even under a spray of random source IPs.
package ratelimit

import (
	"hash/fnv"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Rule is a single rate-limit policy.
type Rule struct {
	ID       string   `json:"id"`
	Paths    []string `json:"paths"`
	Requests int      `json:"requests"`
	Window   int      `json:"window"` // window length in seconds
}

// Seconds returns the window as a duration.
func (r Rule) Seconds() time.Duration { return time.Duration(r.Window) * time.Second }

type compiledRule struct {
	id      string
	paths   []string
	limit   int64
	window  int64 // nanoseconds
	windowD time.Duration
}

func compile(rules []Rule) []compiledRule {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		if r.Requests <= 0 {
			continue
		}
		w := time.Duration(r.Window) * time.Second
		if w <= 0 {
			w = time.Minute
		}
		out = append(out, compiledRule{
			id:      r.ID,
			paths:   append([]string(nil), r.Paths...),
			limit:   int64(r.Requests),
			window:  int64(w),
			windowD: w,
		})
	}
	return out
}

func (r *compiledRule) matches(path string) bool {
	for _, p := range r.paths {
		if matchPath(p, path) {
			return true
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	switch {
	case pattern == "", pattern == "*", pattern == "/*":
		return true
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	default:
		return path == pattern
	}
}

const numShards = 32

type counter struct {
	windowStart int64
	expiresAt   int64
	count       int64
}

type shard struct {
	mu sync.Mutex
	m  map[string]*counter
}

// Limiter holds a swappable rule set over a stable, bounded counter table.
type Limiter struct {
	rules      atomic.Pointer[[]compiledRule]
	shards     [numShards]shard
	maxEntries int64
	count      atomic.Int64
	stop       chan struct{}
	stopOnce   sync.Once
}

// Config controls the limiter's memory bounds and cleanup cadence.
type Config struct {
	MaxEntries int
	Cleanup    time.Duration
}

// New creates a limiter and starts its cleanup goroutine.
func New(rules []Rule, cfg Config) *Limiter {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 100_000
	}
	if cfg.Cleanup <= 0 {
		cfg.Cleanup = time.Minute
	}
	l := &Limiter{
		maxEntries: int64(cfg.MaxEntries),
		stop:       make(chan struct{}),
	}
	for i := range l.shards {
		l.shards[i].m = make(map[string]*counter)
	}
	l.Reload(rules)
	go l.cleanupLoop(cfg.Cleanup)
	return l
}

// Reload atomically replaces the policy set while preserving counters.
func (l *Limiter) Reload(rules []Rule) {
	compiled := compile(rules)
	l.rules.Store(&compiled)
}

// Stop terminates the cleanup goroutine.
func (l *Limiter) Stop() {
	l.stopOnce.Do(func() { close(l.stop) })
}

// Allow reports whether the request is within the applicable limit. It fails
// open when the table is saturated.
func (l *Limiter) Allow(ip netip.Addr, path string, now time.Time) (bool, time.Duration) {
	ptr := l.rules.Load()
	if ptr == nil {
		return true, 0
	}
	rules := *ptr
	if len(rules) == 0 {
		return true, 0
	}
	var rule *compiledRule
	for i := range rules {
		if rules[i].matches(path) {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		return true, 0
	}

	key := rule.id + "|" + ip.String()
	s := &l.shards[shardIndex(key)]
	nowN := now.UnixNano()

	s.mu.Lock()
	c, ok := s.m[key]
	if !ok {
		if l.count.Load() >= l.maxEntries {
			s.mu.Unlock()
			return true, 0 // fail open rather than grow unbounded
		}
		c = &counter{windowStart: nowN}
		s.m[key] = c
		l.count.Add(1)
	}
	if nowN-c.windowStart >= rule.window {
		c.windowStart = nowN
		c.count = 0
	}
	c.expiresAt = nowN + rule.window
	if c.count >= rule.limit {
		retry := time.Duration(c.windowStart + rule.window - nowN)
		s.mu.Unlock()
		return false, retry
	}
	c.count++
	s.mu.Unlock()
	return true, 0
}

func shardIndex(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return h.Sum32() % numShards
}

func (l *Limiter) cleanupLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case now := <-t.C:
			l.cleanup(now)
		}
	}
}

func (l *Limiter) cleanup(now time.Time) {
	nowN := now.UnixNano()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for k, c := range s.m {
			if nowN >= c.expiresAt {
				delete(s.m, k)
				l.count.Add(-1)
			}
		}
		s.mu.Unlock()
	}
}

// Len returns the current number of tracked counters (approximate under
// concurrency).
func (l *Limiter) Len() int { return int(l.count.Load()) }
