package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Xwudao/sentra/internal/ipset"
	"github.com/Xwudao/sentra/internal/ratelimit"
	"github.com/Xwudao/sentra/internal/rule"
)

func newTestEngine(t *testing.T, rules []rule.Rule) *Engine {
	t.Helper()
	e := New(DefaultConfig(), Options{})
	t.Cleanup(e.Close)
	if rules != nil {
		if _, err := e.ReloadRules(rules); err != nil {
			t.Fatalf("ReloadRules: %v", err)
		}
	}
	return e
}

func sqliRule() rule.Rule {
	return rule.Rule{
		ID: "sqli-basic", Name: "Basic SQL Injection", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"query"}, Operator: rule.OpRegex, Value: `(?i)union\s+select`,
		Transforms: []string{"url_decode", "remove_nulls", "compress_whitespace"},
		Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh,
	}
}

func do(t *testing.T, e *Engine, method, target, body string) Decision {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	return e.Evaluate(e.NewContext(r))
}

func TestNoRulesAllow(t *testing.T) {
	e := newTestEngine(t, nil)
	d := do(t, e, "GET", "http://example.com/", "")
	if d.Blocked {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestSQLiBlocked(t *testing.T) {
	e := newTestEngine(t, []rule.Rule{sqliRule()})
	d := do(t, e, "GET", "http://example.com/search?q=1%20UNION%20SELECT%20password", "")
	if !d.Blocked {
		t.Fatalf("expected block, got %+v", d)
	}
	if d.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d want 403", d.StatusCode)
	}
	if len(d.Matches) != 1 || d.Matches[0].RuleID != "sqli-basic" {
		t.Fatalf("unexpected matches: %+v", d.Matches)
	}
	if d.Score != 10 {
		t.Errorf("score=%d want 10", d.Score)
	}
}

func TestBenignQueryAllowed(t *testing.T) {
	e := newTestEngine(t, []rule.Rule{sqliRule()})
	d := do(t, e, "GET", "http://example.com/article/how-to-use-select-in-sql", "")
	if d.Blocked {
		t.Fatalf("benign request blocked: %+v", d)
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("body read when not needed") }
func (panicReader) Close() error             { return nil }

func TestBodyNotReadWithoutBodyRules(t *testing.T) {
	e := newTestEngine(t, []rule.Rule{sqliRule()})
	r := httptest.NewRequest("POST", "http://example.com/", nil)
	r.Body = panicReader{}
	// Must not panic: no rule targets the body.
	e.Evaluate(e.NewContext(r))
}

func TestBodyRestoredForDownstream(t *testing.T) {
	bodyRule := rule.Rule{
		ID: "body-xss", Name: "XSS", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"body"}, Operator: rule.OpContains, Value: "<script>",
		Transforms: []string{"url_decode", "lowercase"}, Action: rule.ActionBlock,
		Score: 10, Severity: rule.SeverityHigh,
	}
	e := newTestEngine(t, []rule.Rule{bodyRule})
	payload := "name=<script>alert(1)</script>&other=1"
	r := httptest.NewRequest("POST", "http://example.com/x", strings.NewReader(payload))
	d := e.Evaluate(e.NewContext(r))
	if !d.Blocked {
		t.Fatalf("expected block, got %+v", d)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("downstream body mismatch: got %q want %q", got, payload)
	}
}

func TestBodyTruncatedAndRestored(t *testing.T) {
	e := New(Config{MaxRequestBodySize: 8, BodyLimitAction: BodyLimitAllow}, Options{})
	defer e.Close()
	bodyRule := rule.Rule{
		ID: "body-x", Name: "body", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"body"}, Operator: rule.OpContains, Value: "needle",
		Action: rule.ActionLog, Score: 1, Severity: rule.SeverityLow,
	}
	if _, err := e.ReloadRules([]rule.Rule{bodyRule}); err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("a", 20)
	r := httptest.NewRequest("POST", "http://example.com/", strings.NewReader(payload))
	ctx := e.NewContext(r)
	e.Evaluate(ctx)
	if !ctx.BodyTruncated() {
		t.Error("expected BodyTruncated")
	}
	got, _ := io.ReadAll(r.Body)
	if string(got) != payload {
		t.Fatalf("restored body mismatch: %q", got)
	}
}

func TestBodyLimitBlock(t *testing.T) {
	e := New(Config{MaxRequestBodySize: 4, BodyLimitAction: BodyLimitBlock}, Options{})
	defer e.Close()
	bodyRule := rule.Rule{
		ID: "body-x", Name: "body", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"body"}, Operator: rule.OpContains, Value: "zzz",
		Action: rule.ActionLog, Score: 1, Severity: rule.SeverityLow,
	}
	e.ReloadRules([]rule.Rule{bodyRule})
	d := do(t, e, "POST", "http://example.com/", "0123456789")
	if !d.Blocked || d.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %+v", d)
	}
}

func TestAnomalyThreshold(t *testing.T) {
	r := sqliRule()
	r.Action = rule.ActionLog
	r.Score = 12
	e := New(Config{AnomalyThreshold: 10}, Options{})
	defer e.Close()
	e.ReloadRules([]rule.Rule{r})
	d := do(t, e, "GET", "http://example.com/?q=union%20select", "")
	if !d.Blocked {
		t.Fatalf("expected threshold block, got %+v", d)
	}
}

func TestIPRules(t *testing.T) {
	e := newTestEngine(t, nil)
	if err := e.ReloadIPRules([]ipset.Entry{
		{ID: "a", Prefix: netip.MustParsePrefix("10.0.0.0/8"), Action: ipset.ActionAllow},
		{ID: "b", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: ipset.ActionBlock},
	}); err != nil {
		t.Fatal(err)
	}
	allowed := e.Evaluate(e.NewContext(httptest.NewRequest("GET", "http://x/", nil)))
	_ = allowed
	// Build requests with explicit remote addresses.
	rAllow := httptest.NewRequest("GET", "http://x/", nil)
	rAllow.RemoteAddr = "10.0.0.5:1234"
	if d := e.Evaluate(e.NewContext(rAllow)); !d.AllowedByIP {
		t.Fatalf("expected IP allow, got %+v", d)
	}
	rBlock := httptest.NewRequest("GET", "http://x/", nil)
	rBlock.RemoteAddr = "203.0.113.7:1234"
	d := e.Evaluate(e.NewContext(rBlock))
	if !d.BlockedByIP || d.StatusCode != http.StatusForbidden {
		t.Fatalf("expected IP block, got %+v", d)
	}
}

func TestRateLimit(t *testing.T) {
	e := newTestEngine(t, nil)
	e.ReloadRateLimit([]ratelimit.Rule{{ID: "login", Paths: []string{"/login"}, Requests: 1, Window: 60}})
	r1 := httptest.NewRequest("POST", "http://x/login", nil)
	r1.RemoteAddr = "1.2.3.4:5555"
	if d := e.Evaluate(e.NewContext(r1)); d.Blocked {
		t.Fatalf("first request should pass: %+v", d)
	}
	r2 := httptest.NewRequest("POST", "http://x/login", nil)
	r2.RemoteAddr = "1.2.3.4:5555"
	d := e.Evaluate(e.NewContext(r2))
	if !d.RateLimited || d.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %+v", d)
	}
}

func TestDebugModeHasRawValues(t *testing.T) {
	e := newTestEngine(t, []rule.Rule{sqliRule()})
	r := httptest.NewRequest("GET", "http://x/?q=1%20UNION%20SELECT", nil)
	d := e.EvaluateDebug(e.NewContext(r))
	if !d.Blocked {
		t.Fatalf("expected block in debug: %+v", d)
	}
	if d.Debug == nil || len(d.Debug.Matches) == 0 {
		t.Fatal("expected debug matches")
	}
	m := d.Debug.Matches[0]
	if m.Raw == "" || m.Transformed == "" {
		t.Fatalf("expected raw+transformed, got %+v", m)
	}
}

func TestResolveClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.RemoteAddr = "10.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.2")
	if got := ResolveClientIP(r, trusted, ""); got != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("XFF resolution got %s want 1.1.1.1", got)
	}
	if got := ResolveClientIP(r, trusted, "CF-Connecting-IP"); got != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("absent CF header should fall back to XFF, got %s", got)
	}
	r.Header.Set("CF-Connecting-IP", "9.9.9.9, 10.0.0.1")
	if got := ResolveClientIP(r, trusted, "CF-Connecting-IP"); got != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("comma-separated client IP header should use first entry, got %s", got)
	}
	// Untrusted peer: headers ignored.
	r2 := httptest.NewRequest("GET", "http://x/", nil)
	r2.RemoteAddr = "8.8.8.8:1"
	r2.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := ResolveClientIP(r2, trusted, ""); got != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("untrusted peer got %s want 8.8.8.8", got)
	}
}

func TestReloadFailureKeepsOldRuleset(t *testing.T) {
	e := newTestEngine(t, []rule.Rule{sqliRule()})
	bad := sqliRule()
	bad.Operator = rule.OpRegex
	bad.Value = "("
	bad.ID = "broken"
	if _, err := e.ReloadRules([]rule.Rule{bad}); err == nil {
		t.Fatal("expected reload error")
	}
	// Old rule still blocks.
	d := do(t, e, "GET", "http://x/?q=union%20select", "")
	if !d.Blocked {
		t.Fatalf("old ruleset should remain: %+v", d)
	}
}
