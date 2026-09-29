package matcher

import "testing"

func TestOperators(t *testing.T) {
	cases := []struct {
		op     string
		value  string
		values []string
		in     string
		want   bool
	}{
		{"regex", `union\s+select`, nil, "1 UNION SELECT", false},
		{"regex", `(?i)union\s+select`, nil, "1 UNION SELECT", true},
		{"contains", "select", nil, "please select one", true},
		{"contains", "select", nil, "SELECT", false},
		{"equals", "abc", nil, "abc", true},
		{"equals", "abc", nil, "abcd", false},
		{"prefix", "abc", nil, "abcdef", true},
		{"prefix", "abc", nil, "xabc", false},
		{"suffix", "abc", nil, "xxabc", true},
		{"suffix", "abc", nil, "abcx", false},
		{"keyword_set", "", []string{"onerror", "javascript:"}, "<img onerror=alert(1)>", true},
		{"keyword_set", "", []string{"onerror", "javascript:"}, "plain text", false},
	}
	for _, c := range cases {
		m, err := Build(c.op, c.value, c.values)
		if err != nil {
			t.Fatalf("Build(%q): %v", c.op, err)
		}
		if got := m.Match([]byte(c.in)); got != c.want {
			t.Errorf("%s(%q).Match(%q)=%v want %v", c.op, c.value, c.in, got, c.want)
		}
	}
}

func TestBuildErrors(t *testing.T) {
	if _, err := Build("regex", "(", nil); err == nil {
		t.Error("expected regex compile error")
	}
	if _, err := Build("keyword_set", "", nil); err == nil {
		t.Error("expected empty keyword_set error")
	}
	if _, err := Build("nope", "x", nil); err == nil {
		t.Error("expected unknown operator error")
	}
}
