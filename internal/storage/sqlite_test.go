package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/rule"
)

func openTest(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentra.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRuleCRUD(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	r := rule.Rule{
		ID: "sqli-basic", Name: "SQLi", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"query", "body"}, Operator: rule.OpRegex, Value: `union\s+select`,
		Transforms: []string{"url_decode"}, Action: rule.ActionBlock, Score: 10,
		Severity: rule.SeverityHigh, Priority: 5, Tags: []string{"sqli"},
	}
	if err := s.UpsertRule(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRule(ctx, "sqli-basic")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != r.Name || len(got.Targets) != 2 || got.Priority != 5 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	list, err := s.ListRules(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListRules=%v err=%v", list, err)
	}
	r.Name = "updated"
	if err := s.UpsertRule(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRule(ctx, "sqli-basic")
	if got.Name != "updated" {
		t.Fatalf("update failed: %+v", got)
	}
	if err := s.DeleteRule(ctx, "sqli-basic"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRule(ctx, "sqli-basic"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestIPRuleCRUD(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.UpsertIPRule(ctx, IPRule{ID: "a", CIDR: "10.0.0.0/8", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListIPRules(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	if err := s.DeleteIPRule(ctx, "a"); err != nil {
		t.Fatal(err)
	}
}

func TestSettings(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SetSetting(ctx, "config", []byte(`{"anomaly_threshold":10}`)); err != nil {
		t.Fatal(err)
	}
	v, err := s.GetSetting(ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != `{"anomaly_threshold":10}` {
		t.Fatalf("got %s", v)
	}
	all, _ := s.ListSettings(ctx)
	if len(all) != 1 {
		t.Fatalf("expected 1 setting, got %d", len(all))
	}
}

func TestEvents(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	evs := []event.SecurityEvent{
		{ID: "e1", Timestamp: now, ClientIP: "1.1.1.1", Method: "GET", Host: "x", Path: "/a",
			Action: "block", Status: 403, Score: 10, Matches: []event.Match{{RuleID: "sqli", Target: "query"}}},
		{ID: "e2", Timestamp: now.Add(-time.Hour), ClientIP: "2.2.2.2", Method: "GET", Host: "x", Path: "/b",
			Action: "block", Status: 403, Score: 5, Matches: []event.Match{{RuleID: "xss", Target: "query"}}},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListEvents(ctx, EventFilter{Limit: 10})
	if err != nil || len(list) != 2 {
		t.Fatalf("list=%d err=%v", len(list), err)
	}
	// Newest first.
	if list[0].ID != "e1" {
		t.Fatalf("expected newest first, got %s", list[0].ID)
	}
	n, _ := s.CountEvents(ctx, EventFilter{Action: "block"})
	if n != 2 {
		t.Fatalf("count=%d", n)
	}
	n, _ = s.CountEvents(ctx, EventFilter{Rule: "xss"})
	if n != 1 {
		t.Fatalf("rule filter count=%d", n)
	}
	got, err := s.GetEvent(ctx, "e1")
	if err != nil || got.Score != 10 || len(got.Matches) != 1 {
		t.Fatalf("get event: %+v err=%v", got, err)
	}
	ips, paths, rules, err := s.AggregateEvents(ctx, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 || len(paths) != 2 || len(rules) != 2 {
		t.Fatalf("aggregates: ips=%v paths=%v rules=%v", ips, paths, rules)
	}
}

func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentra.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}
