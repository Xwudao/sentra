package defaults

import (
	"bufio"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xwudao/sentra/internal/engine"
)

func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	e := engine.New(engine.DefaultConfig(), engine.Options{})
	t.Cleanup(e.Close)
	if _, err := e.ReloadRules(Rules()); err != nil {
		t.Fatalf("compile default rules: %v", err)
	}
	return e
}

func evaluate(t *testing.T, e *engine.Engine, target string) (blocked bool, ruleIDs []string) {
	t.Helper()
	target = strings.ReplaceAll(target, " ", "%20")
	r := httptest.NewRequest("GET", "http://example.com"+target, nil)
	d := e.Evaluate(e.NewContext(r))
	for _, m := range d.Matches {
		ruleIDs = append(ruleIDs, m.RuleID)
	}
	return d.Blocked, ruleIDs
}

func TestAttackCorpusBlocked(t *testing.T) {
	e := newEngine(t)
	files := mustGlob(t, "../../testdata/attacks/*.txt")
	if len(files) == 0 {
		t.Fatal("no attack corpus files found")
	}
	for _, f := range files {
		for _, line := range readLines(t, f) {
			blocked, ids := evaluate(t, e, line)
			if !blocked {
				t.Errorf("%s: expected block for %q (matches=%v)", filepath.Base(f), line, ids)
			}
		}
	}
}

func TestBenignCorpusAllowed(t *testing.T) {
	e := newEngine(t)
	files := mustGlob(t, "../../testdata/benign/*.txt")
	for _, f := range files {
		for _, line := range readLines(t, f) {
			blocked, ids := evaluate(t, e, line)
			if blocked {
				t.Errorf("%s: false positive for %q (matches=%v)", filepath.Base(f), line, ids)
			}
		}
	}
}

func TestDefaultRulesValid(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("duplicate default rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Description == "" {
			t.Errorf("rule %s missing description", r.ID)
		}
		if len(r.Tags) == 0 {
			t.Errorf("rule %s missing tags", r.ID)
		}
	}
	if _, err := engine.New(engine.DefaultConfig(), engine.Options{}).ReloadRules(Rules()); err != nil {
		t.Fatal(err)
	}
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
