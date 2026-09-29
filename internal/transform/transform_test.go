package transform

import (
	"bytes"
	"testing"
)

func TestURLDecode(t *testing.T) {
	cases := map[string]string{
		"a%20b":       "a b",
		"a+b":         "a b",
		"%2e%2e%2f":   "../",
		"%252e%252e":  "%2e%2e",
		"no+encoding": "no encoding",
		"bad%zz":      "bad%zz",
		"trailing%":   "trailing%",
		"100%25":      "100%",
		"":            "",
		"%41%42%43":   "ABC",
		"%e4%b8%ad":   "中",
	}
	for in, want := range cases {
		if got := string(URLDecode([]byte(in))); got != want {
			t.Errorf("URLDecode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRemoveNulls(t *testing.T) {
	if got := RemoveNulls([]byte("a\x00b\x00")); !bytes.Equal(got, []byte("ab")) {
		t.Errorf("got %q", got)
	}
	in := []byte("clean")
	if &in[0] != &RemoveNulls(in)[0] {
		t.Errorf("expected no allocation for clean input")
	}
}

func TestCompressWhitespace(t *testing.T) {
	cases := map[string]string{
		"a  b":      "a b",
		"a\t\tb":    "a b",
		"a\n\r\n b": "a b",
		" a ":       " a ",
		"a":         "a",
	}
	for in, want := range cases {
		if got := string(CompressWhitespace([]byte(in))); got != want {
			t.Errorf("CompressWhitespace(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLowercaseAndHTML(t *testing.T) {
	if got := string(Lowercase([]byte("AbC"))); got != "abc" {
		t.Errorf("lowercase=%q", got)
	}
	if got := string(HTMLDecode([]byte("&lt;script&gt;"))); got != "<script>" {
		t.Errorf("html=%q", got)
	}
}

func TestPipelineApply(t *testing.T) {
	p, _, err := buildTestPipeline([]string{"url_decode", "lowercase"})
	if err != nil {
		t.Fatal(err)
	}
	out := p.Apply([][]byte{[]byte("A%20B")})
	if string(out[0]) != "a b" {
		t.Fatalf("got %q", out[0])
	}
	// Empty pipeline must not allocate.
	in := [][]byte{[]byte("x")}
	if &in[0][0] != &(Pipeline{}).Apply(in)[0][0] {
		t.Fatalf("empty pipeline should return input unchanged")
	}
}

func buildTestPipeline(names []string) (Pipeline, []string, error) {
	p := make(Pipeline, len(names))
	for i, n := range names {
		fn, ok := Lookup(n)
		if !ok {
			return nil, nil, errUnknown(n)
		}
		p[i] = fn
	}
	return p, names, nil
}

type errUnknown string

func (e errUnknown) Error() string { return "unknown transform " + string(e) }
