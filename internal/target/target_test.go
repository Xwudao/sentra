package target

import "testing"

func TestParseValid(t *testing.T) {
	cases := []struct {
		in   string
		kind Kind
		arg  string
	}{
		{"method", KindMethod, ""},
		{"host", KindHost, ""},
		{"path", KindPath, ""},
		{"uri", KindURI, ""},
		{"query", KindQuery, ""},
		{"body", KindBody, ""},
		{"header", KindHeader, ""},
		{"header:User-Agent", KindHeader, "User-Agent"},
		{"cookie:session", KindCookie, "session"},
		{"query_param:id", KindQueryParam, "id"},
		{"json:data.items.0.id", KindJSON, "data.items.0.id"},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if got.Kind != c.kind || got.Arg != c.arg {
			t.Errorf("Parse(%q)=%+v want kind=%v arg=%q", c.in, got, c.kind, c.arg)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{"", "nope", "header:", "cookie:", "query_param", "query_param:", "json", "json:", "json:a..b", "path:x"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) expected error", in)
		}
	}
}

func TestTargetKeyCaseInsensitive(t *testing.T) {
	a, _ := Parse("header:User-Agent")
	b, _ := Parse("header:user-agent")
	if a.Key() != b.Key() {
		t.Errorf("header keys should be case-insensitive: %q vs %q", a.Key(), b.Key())
	}
	q1, _ := Parse("query_param:ID")
	q2, _ := Parse("query_param:id")
	if q1.Key() == q2.Key() {
		t.Errorf("query_param keys should be case-sensitive")
	}
}

func TestIsAll(t *testing.T) {
	h, _ := Parse("header")
	if !h.IsAll() {
		t.Error("header should be all")
	}
	hn, _ := Parse("header:x")
	if hn.IsAll() {
		t.Error("header:x should not be all")
	}
}
