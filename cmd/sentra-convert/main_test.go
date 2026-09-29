package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Xwudao/sentra/internal/rule"
	"github.com/Xwudao/sentra/internal/storage"
)

func TestMapTarget(t *testing.T) {
	cases := map[string]string{
		"ARGS":               "query",
		"BODY":               "body",
		"URI":                "uri",
		"HEADERS":            "header",
		"HEADERS:User-Agent": "header:user-agent",
		"COOKIES":            "cookie",
	}
	for in, want := range cases {
		got, err := mapTarget(in)
		if err != nil {
			t.Fatalf("mapTarget(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("mapTarget(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := mapTarget("REMOTE_IP"); err == nil {
		t.Errorf("expected unsupported target to fail")
	}
}

func TestConvertAcceptsRequestPhases(t *testing.T) {
	for _, phase := range []int{0, 1, 2} {
		r, err := convert(caddyWAFRule{
			ID: "x", Phase: phase, Pattern: `\.\./`, Targets: []string{"ARGS"},
			Severity: "HIGH", Action: "block", Score: 10,
		}, "fw-", []string{"url_decode"}, "test")
		if err != nil {
			t.Fatalf("phase %d: %v", phase, err)
		}
		if r.ID != "fw-x" || r.Action != rule.ActionBlock || r.Targets[0] != "query" {
			t.Errorf("phase %d: unexpected rule %+v", phase, r)
		}
	}
	if _, err := convert(caddyWAFRule{ID: "y", Phase: 3, Pattern: "x", Targets: []string{"BODY"}}, "fw-", nil, "test"); err == nil {
		t.Errorf("expected response phase to fail")
	}
}

func TestReadIPListDedupAndErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte("1.2.3.4\n1.2.3.4\n# comment\n\n10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readIPList(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %v", len(got), got)
	}

	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("not-an-ip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIPList(bad); err == nil {
		t.Errorf("expected invalid entry to fail")
	}
}

func TestConvertAndImport(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.json")
	const src = `[
	  {"id":"block-scanners","phase":1,"pattern":"(?i)sqlmap","targets":["HEADERS:User-Agent"],"severity":"CRITICAL","action":"block","score":10,"description":"ua"},
	  {"id":"path-traversal","phase":2,"pattern":"\\.\\./","targets":["URI","ARGS"],"severity":"HIGH","action":"block","score":9}
	]`
	if err := os.WriteFile(rulesFile, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	ipsFile := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(ipsFile, []byte("66.103.211.214\n2001:470:a:107::2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := loadAndConvert([]string{rulesFile}, "fw-", []string{"url_decode"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[1].ID != "fw-path-traversal" {
		t.Errorf("unexpected id %q", rules[1].ID)
	}

	ctx := context.Background()
	db := filepath.Join(dir, "sentra.db")
	store, err := storage.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, r := range rules {
		if err := store.UpsertRule(ctx, r, false); err != nil {
			t.Fatal(err)
		}
	}
	prefixes, err := readIPList(ipsFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importIPRules(ctx, store, prefixes, "block"); err != nil {
		t.Fatal(err)
	}
	ipRules, err := store.ListIPRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipRules) != 2 {
		t.Fatalf("got %d ip rules, want 2", len(ipRules))
	}
}
