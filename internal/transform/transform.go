// Package transform implements the request normalisation functions available
// to rules and the ordered pipelines built from them.
package transform

import (
	"bytes"
	"html"
	"sort"
	"strings"
)

// Func normalises a byte slice. Implementations must not mutate their input:
// the same raw value is shared by every rule group that references a target.
type Func func([]byte) []byte

// Pipeline is an ordered list of transforms. The zero value is a no-op.
type Pipeline []Func

// Apply runs the pipeline over every value. When the pipeline is empty the
// input slice is returned unchanged, avoiding an allocation on the common
// "no transforms" path.
func (p Pipeline) Apply(values [][]byte) [][]byte {
	if len(p) == 0 || len(values) == 0 {
		return values
	}
	out := make([][]byte, len(values))
	for i, v := range values {
		out[i] = p.applyOne(v)
	}
	return out
}

func (p Pipeline) applyOne(v []byte) []byte {
	for _, fn := range p {
		v = fn(v)
	}
	return v
}

var registry = map[string]Func{
	"lowercase":           Lowercase,
	"url_decode":          URLDecode,
	"html_decode":         HTMLDecode,
	"remove_nulls":        RemoveNulls,
	"compress_whitespace": CompressWhitespace,
	"trim":                Trim,
}

// Lookup returns the transform registered under name.
func Lookup(name string) (Func, bool) {
	fn, ok := registry[name]
	return fn, ok
}

// Names returns the sorted list of registered transform names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lowercase ASCII/Unicode lower-cases the input. It always returns a fresh
// slice so callers may retain it independently of the source.
func Lowercase(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		} else {
			out[i] = c
		}
	}
	return out
}

// Trim removes leading and trailing whitespace. The result aliases the input.
func Trim(b []byte) []byte {
	return bytes.TrimSpace(b)
}

// RemoveNulls drops NUL bytes. If none are present the input is returned.
func RemoveNulls(b []byte) []byte {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return b
	}
	out := make([]byte, 0, len(b)-1)
	out = append(out, b[:i]...)
	for _, c := range b[i+1:] {
		if c != 0 {
			out = append(out, c)
		}
	}
	return out
}

// CompressWhitespace collapses runs of whitespace into a single space.
func CompressWhitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inSpace := false
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			if !inSpace {
				out = append(out, ' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		out = append(out, c)
	}
	return out
}

// URLDecode percent-decodes the input and translates '+' to space. Invalid
// escapes are copied verbatim, matching the permissive behaviour expected of
// a WAF normaliser.
func URLDecode(b []byte) []byte {
	hasPercent := bytes.IndexByte(b, '%') >= 0
	hasPlus := bytes.IndexByte(b, '+') >= 0
	if !hasPercent && !hasPlus {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '%' && i+2 < len(b):
			hi, ok1 := unhex(b[i+1])
			lo, ok2 := unhex(b[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
			out = append(out, b[i])
		case b[i] == '+':
			out = append(out, ' ')
		default:
			out = append(out, b[i])
		}
	}
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// HTMLDecode resolves HTML entities. It delegates to the standard library,
// which covers named and numeric entities.
func HTMLDecode(b []byte) []byte {
	if bytes.IndexByte(b, '&') < 0 {
		return b
	}
	s := html.UnescapeString(string(b))
	return []byte(s)
}

// JoinNames produces a stable textual representation of a transform list,
// suitable for use as a grouping key.
func JoinNames(names []string) string {
	return strings.Join(names, ",")
}
