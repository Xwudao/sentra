package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xwudao/sentra/internal/webassets"

	"github.com/Xwudao/sentra/internal/defaults"
	"github.com/Xwudao/sentra/internal/engine"
	"github.com/Xwudao/sentra/internal/storage"
)

func newTestServer(t *testing.T, token string) (*httptest.Server, *engine.Engine, *storage.SQLite) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(engine.DefaultConfig(), engine.Options{})
	srv := New(eng, store, nil, Config{AdminToken: token, Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		eng.Close()
		store.Close()
	})
	return ts, eng, store
}

func request(t *testing.T, ts *httptest.Server, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, ts.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp, out.Bytes()
}

func TestAuthRequired(t *testing.T) {
	ts, _, _ := newTestServer(t, "secret")
	resp, _ := request(t, ts, "GET", "/api/dashboard", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp, _ = request(t, ts, "GET", "/api/dashboard", "wrong", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d", resp.StatusCode)
	}
	resp, _ = request(t, ts, "GET", "/api/dashboard", "secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRuleCRUDAndPlayground(t *testing.T) {
	ts, eng, _ := newTestServer(t, "secret")
	ruleBody := map[string]any{
		"id": "sqli-test", "name": "SQLi test", "enabled": true, "phase": "request",
		"targets": []string{"query"}, "operator": "regex", "value": `(?i)union\s+select`,
		"transforms": []string{"url_decode"}, "action": "block", "score": 10, "severity": "high",
	}
	resp, body := request(t, ts, "POST", "/api/rules", "secret", ruleBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	if eng.Ruleset().RuleCount != 1 {
		t.Fatalf("engine should have 1 rule, got %d", eng.Ruleset().RuleCount)
	}

	// Playground blocks.
	pg := map[string]any{"method": "GET", "url": "/search?q=1%20UNION%20SELECT", "client_ip": "1.2.3.4"}
	resp, body = request(t, ts, "POST", "/api/rules/test", "secret", pg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("playground: %d %s", resp.StatusCode, body)
	}
	var result playgroundResponse
	json.Unmarshal(body, &result)
	if !result.Blocked || result.Score != 10 {
		t.Fatalf("unexpected playground result: %+v", result)
	}
	if len(result.Matches) == 0 || result.Matches[0].Raw == "" {
		t.Fatalf("expected debug match detail: %+v", result.Matches)
	}

	// Invalid regex is rejected and runtime is unchanged.
	bad := map[string]any{
		"id": "bad", "name": "bad", "enabled": true, "phase": "request",
		"targets": []string{"query"}, "operator": "regex", "value": "(",
		"action": "block", "score": 1, "severity": "low",
	}
	resp, _ = request(t, ts, "POST", "/api/rules", "secret", bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad regex, got %d", resp.StatusCode)
	}
	if eng.Ruleset().RuleCount != 1 {
		t.Fatalf("ruleset should be unchanged, got %d rules", eng.Ruleset().RuleCount)
	}

	// Delete.
	resp, _ = request(t, ts, "DELETE", "/api/rules/sqli-test", "secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if eng.Ruleset().RuleCount != 0 {
		t.Fatalf("expected empty ruleset, got %d", eng.Ruleset().RuleCount)
	}
}

func TestRestoreDefaultRules(t *testing.T) {
	ts, eng, store := newTestServer(t, "secret")
	ctx := context.Background()
	builtins := defaults.Rules()
	if err := store.ReplaceRules(ctx, builtins); err != nil {
		t.Fatal(err)
	}
	modified := builtins[0]
	modified.Name = "Modified"
	modified.Enabled = false
	if err := store.UpsertRule(ctx, modified, true); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRule(ctx, builtins[1].ID); err != nil {
		t.Fatal(err)
	}
	custom := builtins[0]
	custom.ID = "custom"
	if err := store.UpsertRule(ctx, custom, false); err != nil {
		t.Fatal(err)
	}
	resp, _ := request(t, ts, "POST", "/api/rules/restore", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized restore: %d", resp.StatusCode)
	}
	resp, body := request(t, ts, "POST", "/api/rules/restore", "secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore: %d %s", resp.StatusCode, body)
	}
	rules, err := store.ListRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(builtins) || eng.Ruleset().RuleCount != len(builtins) {
		t.Fatalf("restored count: stored=%d live=%d want=%d", len(rules), eng.Ruleset().RuleCount, len(builtins))
	}
	if _, err := store.GetRule(ctx, custom.ID); err == nil {
		t.Fatal("custom rule was not removed")
	}
	got, err := store.GetRule(ctx, modified.ID)
	if err != nil || got.Name != builtins[0].Name || got.Enabled != builtins[0].Enabled {
		t.Fatalf("modified rule not restored: %+v, %v", got, err)
	}
	if _, err := store.GetRule(ctx, builtins[1].ID); err != nil {
		t.Fatalf("deleted builtin not restored: %v", err)
	}
	resp, body = request(t, ts, "POST", "/api/rules/restore", "secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("repeat restore: %d %s", resp.StatusCode, body)
	}
}

func TestIPRuleAPI(t *testing.T) {
	ts, eng, _ := newTestServer(t, "secret")
	resp, body := request(t, ts, "POST", "/api/ip-rules", "secret", map[string]any{"cidr": "203.0.113.0/24", "action": "block"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create ip: %d %s", resp.StatusCode, body)
	}
	if eng.Metrics().IPRulesLoaded.Load() != 1 {
		t.Fatalf("expected 1 ip rule loaded")
	}
	resp, _ = request(t, ts, "POST", "/api/ip-rules", "secret", map[string]any{"cidr": "not-a-cidr", "action": "block"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid cidr, got %d", resp.StatusCode)
	}
}

func TestSettingsAPI(t *testing.T) {
	ts, eng, _ := newTestServer(t, "secret")
	resp, body := request(t, ts, "PUT", "/api/settings", "secret", map[string]any{
		"max_request_body_size": 1048576,
		"body_limit_action":     "block",
		"anomaly_threshold":     25,
		"rate_limit":            []map[string]any{{"id": "login", "paths": []string{"/login"}, "requests": 5, "window": 60}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	cfg := eng.Config()
	if cfg.AnomalyThreshold != 25 || cfg.MaxRequestBodySize != 1048576 || cfg.BodyLimitAction != engine.BodyLimitBlock {
		t.Fatalf("settings not applied: %+v", cfg)
	}
	resp, body = request(t, ts, "GET", "/api/settings", "secret", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get settings: %d", resp.StatusCode)
	}
	var s Settings
	json.Unmarshal(body, &s)
	if len(s.RateLimit) != 1 {
		t.Fatalf("expected rate limit persisted, got %+v", s)
	}
}

func TestSPAFallback(t *testing.T) {
	ts, _, _ := newTestServer(t, "")
	resp, _ := request(t, ts, "GET", "/some/spa/route", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected SPA fallback 200, got %d", resp.StatusCode)
	}
}

func TestSPAPrecompressed(t *testing.T) {
	ts, _, _ := newTestServer(t, "")
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	entries, err := fs.ReadDir(webassets.Dist(), "assets")
	if err != nil {
		t.Fatal(err)
	}
	var js string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".js.gz") {
			js = "/assets/" + strings.TrimSuffix(entry.Name(), ".gz")
			break
		}
	}
	if js == "" {
		t.Fatal("no embedded JS gzip sidecar; run make web")
	}
	for _, asset := range []string{js, "/some/spa/route"} {
		get := func(encoding string) (*http.Response, []byte) {
			t.Helper()
			req, err := http.NewRequest(http.MethodGet, ts.URL+asset, nil)
			if err != nil {
				t.Fatal(err)
			}
			if encoding != "" {
				req.Header.Set("Accept-Encoding", encoding)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			return resp, body
		}
		plain, original := get("gzip;q=0")
		if plain.StatusCode != http.StatusOK || plain.Header.Get("Content-Encoding") != "" {
			t.Fatalf("%s: expected uncompressed 200, got %d %q", asset, plain.StatusCode, plain.Header.Get("Content-Encoding"))
		}
		compressed, body := get("br, gzip")
		if compressed.StatusCode != http.StatusOK || compressed.Header.Get("Content-Encoding") != "gzip" || compressed.Header.Get("Vary") != "Accept-Encoding" {
			t.Fatalf("%s: expected gzip 200 with Vary, got %d %q %q", asset, compressed.StatusCode, compressed.Header.Get("Content-Encoding"), compressed.Header.Get("Vary"))
		}
		if compressed.Header.Get("Content-Type") != plain.Header.Get("Content-Type") {
			t.Fatalf("%s: content type differs: %q vs %q", asset, compressed.Header.Get("Content-Type"), plain.Header.Get("Content-Type"))
		}
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(decoded, original) {
			t.Fatalf("%s: gzip body does not match original: %v", asset, err)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+js+".gz", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("direct .gz request: got %d, want 404", resp.StatusCode)
	}
}
