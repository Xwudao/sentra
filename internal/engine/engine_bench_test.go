package engine

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Xwudao/sentra/internal/rule"
)

func benchRules(n int) []rule.Rule {
	rules := make([]rule.Rule, 0, n)
	for i := 0; i < n; i++ {
		rules = append(rules, rule.Rule{
			ID:         fmt.Sprintf("rule-%03d", i),
			Name:       "bench",
			Enabled:    true,
			Phase:      rule.PhaseRequest,
			Targets:    []string{"query"},
			Operator:   rule.OpContains,
			Value:      fmt.Sprintf("needle-%03d", i),
			Transforms: []string{"url_decode", "lowercase"},
			Action:     rule.ActionBlock,
			Score:      1,
			Severity:   rule.SeverityMedium,
		})
	}
	return rules
}

func benchEngine(b *testing.B, n int, target string) {
	e := New(DefaultConfig(), Options{})
	defer e.Close()
	if _, err := e.ReloadRules(benchRules(n)); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", target, nil)
		e.Evaluate(e.NewContext(r))
	}
}

func BenchmarkEngineNoRules(b *testing.B) {
	e := New(DefaultConfig(), Options{})
	defer e.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "http://example.com/health?x=1", nil)
		e.Evaluate(e.NewContext(r))
	}
}

func BenchmarkEngine10Rules(b *testing.B)  { benchEngine(b, 10, "http://example.com/products?id=42") }
func BenchmarkEngine100Rules(b *testing.B) { benchEngine(b, 100, "http://example.com/products?id=42") }
func BenchmarkEngine500Rules(b *testing.B) { benchEngine(b, 500, "http://example.com/products?id=42") }

func BenchmarkQuerySQLi(b *testing.B) {
	e := New(DefaultConfig(), Options{})
	defer e.Close()
	if _, err := e.ReloadRules([]rule.Rule{sqliRule()}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "http://example.com/search?q=1+UNION+SELECT+password+FROM+users", nil)
		e.Evaluate(e.NewContext(r))
	}
}

func BenchmarkBodySQLi(b *testing.B) {
	e := New(DefaultConfig(), Options{})
	defer e.Close()
	bodyRule := rule.Rule{
		ID: "body-sqli", Name: "Body SQLi", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"body"}, Operator: rule.OpRegex, Value: `(?i)union\s+select`,
		Transforms: []string{"url_decode", "remove_nulls", "compress_whitespace"},
		Action:     rule.ActionBlock, Score: 10, Severity: rule.SeverityHigh,
	}
	if _, err := e.ReloadRules([]rule.Rule{bodyRule}); err != nil {
		b.Fatal(err)
	}
	payload := "q=1+UNION+SELECT+password+FROM+users&submit=Search"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "http://example.com/search", strings.NewReader(payload))
		e.Evaluate(e.NewContext(r))
	}
}

func BenchmarkSmallJSON(b *testing.B) {
	e := New(DefaultConfig(), Options{})
	defer e.Close()
	jsonRule := rule.Rule{
		ID: "json-xss", Name: "JSON XSS", Enabled: true, Phase: rule.PhaseRequest,
		Targets: []string{"json:user.name"}, Operator: rule.OpContains, Value: "<script>",
		Transforms: []string{"html_decode", "lowercase"}, Action: rule.ActionBlock,
		Score: 10, Severity: rule.SeverityHigh,
	}
	if _, err := e.ReloadRules([]rule.Rule{jsonRule}); err != nil {
		b.Fatal(err)
	}
	payload := `{"user":{"name":"alice","id":42},"tags":["a","b"]}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		e.Evaluate(e.NewContext(r))
	}
}

// BenchmarkParallel measures contention on the lock-free snapshot path.
func BenchmarkParallel(b *testing.B) {
	e := New(DefaultConfig(), Options{})
	defer e.Close()
	if _, err := e.ReloadRules(benchRules(100)); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest("GET", "http://example.com/?q=union+select", nil)
			e.Evaluate(e.NewContext(r))
		}
	})
}
