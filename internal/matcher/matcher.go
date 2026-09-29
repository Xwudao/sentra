// Package matcher provides the compiled operators used by rules. Every
// matcher is built once when a ruleset is loaded; nothing here may compile a
// pattern at request time.
package matcher

import (
	"bytes"
	"fmt"
	"regexp"
)

// Matcher reports whether a (already transformed) value matches.
type Matcher interface {
	Match(b []byte) bool
}

// Build compiles an operator into a Matcher.
//
//   - regex:       value is a RE2 pattern (case-insensitive via (?i)).
//   - contains:    value is a literal substring.
//   - equals:      value is the exact expected value.
//   - prefix:      value is the expected prefix.
//   - suffix:      value is the expected suffix.
//   - keyword_set: values is a non-empty set of literal substrings; matches
//     when any element is present.
func Build(operator, value string, values []string) (Matcher, error) {
	switch operator {
	case "regex":
		re, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", value, err)
		}
		return &regexMatcher{re: re, pattern: value}, nil
	case "contains":
		return &containsMatcher{needle: []byte(value)}, nil
	case "equals":
		return &equalsMatcher{want: []byte(value)}, nil
	case "prefix":
		return &prefixMatcher{prefix: []byte(value)}, nil
	case "suffix":
		return &suffixMatcher{suffix: []byte(value)}, nil
	case "keyword_set":
		if len(values) == 0 {
			return nil, fmt.Errorf("keyword_set requires at least one value")
		}
		set := make([][]byte, 0, len(values))
		for _, v := range values {
			if v == "" {
				return nil, fmt.Errorf("keyword_set contains an empty keyword")
			}
			set = append(set, []byte(v))
		}
		return &keywordSetMatcher{set: set}, nil
	default:
		return nil, fmt.Errorf("unknown operator %q", operator)
	}
}

type regexMatcher struct {
	re      *regexp.Regexp
	pattern string
}

func (m *regexMatcher) Match(b []byte) bool { return m.re.Match(b) }

// Pattern exposes the source pattern for diagnostics.
func (m *regexMatcher) Pattern() string { return m.pattern }

type containsMatcher struct{ needle []byte }

func (m *containsMatcher) Match(b []byte) bool { return bytes.Contains(b, m.needle) }

type equalsMatcher struct{ want []byte }

func (m *equalsMatcher) Match(b []byte) bool { return bytes.Equal(b, m.want) }

type prefixMatcher struct{ prefix []byte }

func (m *prefixMatcher) Match(b []byte) bool { return bytes.HasPrefix(b, m.prefix) }

type suffixMatcher struct{ suffix []byte }

func (m *suffixMatcher) Match(b []byte) bool { return bytes.HasSuffix(b, m.suffix) }

type keywordSetMatcher struct{ set [][]byte }

func (m *keywordSetMatcher) Match(b []byte) bool {
	for _, kw := range m.set {
		if bytes.Contains(b, kw) {
			return true
		}
	}
	return false
}
