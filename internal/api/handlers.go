package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Xwudao/sentra/internal/engine"
	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/ipset"
	"github.com/Xwudao/sentra/internal/ratelimit"
	"github.com/Xwudao/sentra/internal/rule"
	"github.com/Xwudao/sentra/internal/storage"
)

const settingsKey = "api_settings"

// Settings is the editable configuration surface.
type Settings struct {
	MaxRequestBodySize int64            `json:"max_request_body_size"`
	BodyLimitAction    string           `json:"body_limit_action"`
	AnomalyThreshold   int              `json:"anomaly_threshold"`
	ClientIPHeader     string           `json:"client_ip_header"`
	TrustedProxies     []string         `json:"trusted_proxies,omitempty"`
	RateLimit          []ratelimit.Rule `json:"rate_limit"`
}

// ----------------------------------------------------------- dashboard

type dashboardResponse struct {
	Version       string              `json:"version"`
	Metrics       any                 `json:"metrics"`
	EventsTotal   int64               `json:"events_total"`
	EventsBlocked int64               `json:"events_blocked"`
	TopIPs        []storage.StatCount `json:"top_ips"`
	TopPaths      []storage.StatCount `json:"top_paths"`
	TopRules      []storage.StatCount `json:"top_rules"`
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := time.Now().Add(-24 * time.Hour)
	ips, paths, rules, err := s.store.AggregateEvents(ctx, since)
	if err != nil {
		s.logger.Error("dashboard aggregate failed", "error", err)
	}
	total, _ := s.store.CountEvents(ctx, storage.EventFilter{})
	blocked, _ := s.store.CountEvents(ctx, storage.EventFilter{Action: "block"})
	writeJSON(w, http.StatusOK, dashboardResponse{
		Version:       s.cfg.Version,
		Metrics:       s.engine.Metrics().Snapshot(),
		EventsTotal:   total,
		EventsBlocked: blocked,
		TopIPs:        orEmpty(ips),
		TopPaths:      orEmpty(paths),
		TopRules:      orEmpty(rules),
	})
}

func orEmpty(v []storage.StatCount) []storage.StatCount {
	if v == nil {
		return []storage.StatCount{}
	}
	return v
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Metrics().Snapshot())
}

// -------------------------------------------------------------- events

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := storage.EventFilter{
		Action: q.Get("action"),
		IP:     q.Get("ip"),
		Rule:   q.Get("rule"),
		Path:   q.Get("path"),
		From:   parseTime(q.Get("from")),
		To:     parseTime(q.Get("to")),
		Limit:  atoiDefault(q.Get("limit"), 100),
		Offset: atoiDefault(q.Get("offset"), 0),
	}
	events, err := s.store.ListEvents(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	total, _ := s.store.CountEvents(r.Context(), f)
	if events == nil {
		events = []event.SecurityEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "total": total})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.GetEvent(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// --------------------------------------------------------------- rules

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []rule.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (s *Server) handleGetRule(w http.ResponseWriter, r *http.Request) {
	rul, err := s.store.GetRule(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, rul)
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var rul rule.Rule
	if !decodeJSON(w, r, &rul) {
		return
	}
	if rul.ID == "" {
		rul.ID = slugify(rul.Name)
	}
	rul.Normalize()
	if err := rule.Validate(&rul); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.store.GetRule(r.Context(), rul.ID); err == nil {
		writeError(w, http.StatusConflict, "rule already exists")
		return
	}
	rules, err := s.store.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := compileCheck(append(rules, rul)); err != nil {
		writeError(w, http.StatusBadRequest, "rule did not compile: "+err.Error())
		return
	}
	if err := s.store.UpsertRule(r.Context(), rul, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.recompileRules(r); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rul)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetRule(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	var rul rule.Rule
	if !decodeJSON(w, r, &rul) {
		return
	}
	rul.ID = id
	rul.Normalize()
	if err := rule.Validate(&rul); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rules, err := s.store.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	prospective := replaceRule(rules, rul)
	if err := compileCheck(prospective); err != nil {
		writeError(w, http.StatusBadRequest, "rules did not compile; runtime unchanged: "+err.Error())
		return
	}
	if err := s.store.UpsertRule(r.Context(), rul, false); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.recompileRules(r); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rul)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetRule(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err := s.store.DeleteRule(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err := s.recompileRules(r); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func compileCheck(rules []rule.Rule) error {
	_, err := rule.Compile(rules, 0)
	return err
}

func replaceRule(rules []rule.Rule, r rule.Rule) []rule.Rule {
	out := make([]rule.Rule, 0, len(rules)+1)
	replaced := false
	for _, existing := range rules {
		if existing.ID == r.ID {
			out = append(out, r)
			replaced = true
			continue
		}
		out = append(out, existing)
	}
	if !replaced {
		out = append(out, r)
	}
	return out
}

func (s *Server) recompileRules(r *http.Request) error {
	rules, err := s.store.ListRules(r.Context())
	if err != nil {
		return err
	}
	_, err = s.engine.ReloadRules(rules)
	return err
}

// ------------------------------------------------------------ playground

// PlaygroundRequest is a synthetic request supplied by the rule playground.
type PlaygroundRequest struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	ClientIP string            `json:"client_ip"`
}

type playgroundResponse struct {
	Action        string         `json:"action"`
	Score         int            `json:"score"`
	Status        int            `json:"status"`
	Blocked       bool           `json:"blocked"`
	RateLimited   bool           `json:"rate_limited"`
	BodyTruncated bool           `json:"body_truncated"`
	Matches       []engine.Match `json:"matches"`
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	var in PlaygroundRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	req, err := buildPlaygroundRequest(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d := s.engine.EvaluateDebug(s.engine.NewContext(req))
	matches := d.Matches
	if matches == nil {
		matches = []engine.Match{}
	}
	writeJSON(w, http.StatusOK, playgroundResponse{
		Action:        string(d.Action),
		Score:         d.Score,
		Status:        d.StatusCode,
		Blocked:       d.Blocked,
		RateLimited:   d.RateLimited,
		BodyTruncated: d.BodyTruncated,
		Matches:       matches,
	})
}

func buildPlaygroundRequest(in PlaygroundRequest) (*http.Request, error) {
	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	raw := strings.TrimSpace(in.URL)
	if raw == "" {
		raw = "/"
	}
	if !strings.Contains(raw, "://") {
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		raw = "http://playground.local" + raw
	}
	var body *strings.Reader
	if in.Body != "" {
		body = strings.NewReader(in.Body)
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, raw, body)
	} else {
		req, err = http.NewRequest(method, raw, nil)
	}
	if err != nil {
		return nil, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	if in.ClientIP != "" {
		req.RemoteAddr = in.ClientIP + ":0"
	}
	return req, nil
}

// ------------------------------------------------------------ ip rules

func (s *Server) handleListIPRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListIPRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []storage.IPRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip_rules": rules})
}

func (s *Server) handleCreateIPRule(w http.ResponseWriter, r *http.Request) {
	var in storage.IPRule
	if !decodeJSON(w, r, &in) {
		return
	}
	p, err := netip.ParsePrefix(in.CIDR)
	if err != nil {
		if a, aerr := netip.ParseAddr(in.CIDR); aerr == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			writeError(w, http.StatusBadRequest, "invalid CIDR or IP")
			return
		}
	}
	in.CIDR = p.String()
	switch in.Action {
	case "allow", "block":
	default:
		writeError(w, http.StatusBadRequest, "action must be allow or block")
		return
	}
	if in.ID == "" {
		in.ID = event.NewID()
	}
	if err := s.store.UpsertIPRule(r.Context(), in); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reloadIPRules(r); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) handleDeleteIPRule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteIPRule(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "ip rule not found")
		return
	}
	if err := s.reloadIPRules(r); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) reloadIPRules(r *http.Request) error {
	stored, err := s.store.ListIPRules(r.Context())
	if err != nil {
		return err
	}
	entries := make([]ipset.Entry, 0, len(stored))
	for _, e := range stored {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			continue
		}
		action := ipset.ActionBlock
		if e.Action == "allow" {
			action = ipset.ActionAllow
		}
		entries = append(entries, ipset.Entry{ID: e.ID, Prefix: p, Action: action, Note: e.Note})
	}
	return s.engine.ReloadIPRules(entries)
}

// ------------------------------------------------------------ settings

func (s *Server) currentSettings() Settings {
	cfg := s.engine.Config()
	proxies := make([]string, 0, len(cfg.TrustedProxies))
	for _, p := range cfg.TrustedProxies {
		proxies = append(proxies, p.String())
	}
	return Settings{
		MaxRequestBodySize: cfg.MaxRequestBodySize,
		BodyLimitAction:    string(cfg.BodyLimitAction),
		AnomalyThreshold:   cfg.AnomalyThreshold,
		ClientIPHeader:     cfg.ClientIPHeader,
		TrustedProxies:     proxies,
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	out := s.currentSettings()
	if raw, err := s.store.GetSetting(r.Context(), settingsKey); err == nil {
		var stored Settings
		if err := decodeRaw(raw, &stored); err == nil {
			out.RateLimit = stored.RateLimit
		}
	}
	if out.RateLimit == nil {
		out.RateLimit = []ratelimit.Rule{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.BodyLimitAction != "" && in.BodyLimitAction != "allow" && in.BodyLimitAction != "block" {
		writeError(w, http.StatusBadRequest, "body_limit_action must be allow or block")
		return
	}
	for _, rr := range in.RateLimit {
		if rr.Requests <= 0 || rr.Window <= 0 {
			writeError(w, http.StatusBadRequest, "rate limit rules require positive requests and window")
			return
		}
	}
	cfg := s.engine.Config()
	if in.MaxRequestBodySize > 0 {
		cfg.MaxRequestBodySize = in.MaxRequestBodySize
	}
	if in.BodyLimitAction != "" {
		cfg.BodyLimitAction = engine.BodyLimitAction(in.BodyLimitAction)
	}
	cfg.AnomalyThreshold = in.AnomalyThreshold
	if in.ClientIPHeader != "" {
		cfg.ClientIPHeader = in.ClientIPHeader
	}
	s.engine.SetConfig(cfg)
	s.engine.ReloadRateLimit(in.RateLimit)

	persist := in
	persist.TrustedProxies = nil
	if raw, err := encodeRaw(persist); err == nil {
		if err := s.store.SetSetting(r.Context(), settingsKey, raw); err != nil {
			s.logger.Error("failed to persist settings", "error", err)
		}
	}
	out := s.currentSettings()
	out.RateLimit = in.RateLimit
	writeJSON(w, http.StatusOK, out)
}

// LoadSettings applies persisted settings to the engine at boot. Missing
// settings are not an error.
func LoadSettings(eng *engine.Engine, store storage.Store) error {
	raw, err := store.GetSetting(context.Background(), settingsKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return err
	}
	var s Settings
	if err := decodeRaw(raw, &s); err != nil {
		return err
	}
	cfg := eng.Config()
	if s.MaxRequestBodySize > 0 {
		cfg.MaxRequestBodySize = s.MaxRequestBodySize
	}
	if s.BodyLimitAction != "" {
		cfg.BodyLimitAction = engine.BodyLimitAction(s.BodyLimitAction)
	}
	cfg.AnomalyThreshold = s.AnomalyThreshold
	if s.ClientIPHeader != "" {
		cfg.ClientIPHeader = s.ClientIPHeader
	}
	eng.SetConfig(cfg)
	eng.ReloadRateLimit(s.RateLimit)
	return nil
}

// ------------------------------------------------------------- helpers

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(ms)
	}
	return time.Time{}
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
			lastDash = false
		case c == ' ' || c == '_' || c == '-' || c == '.':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = event.NewID()[:12]
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
