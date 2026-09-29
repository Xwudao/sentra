// Package target parses and canonicalises rule targets such as
// "query", "header:user-agent" or "json:data.items.0.id".
package target

import (
	"fmt"
	"strconv"
	"strings"
)

// Kind is the class of request datum a target points at.
type Kind uint8

const (
	KindMethod Kind = iota
	KindHost
	KindPath
	KindURI
	KindQuery
	KindBody
	KindHeader
	KindCookie
	KindQueryParam
	KindJSON
)

var kindNames = map[Kind]string{
	KindMethod:     "method",
	KindHost:       "host",
	KindPath:       "path",
	KindURI:        "uri",
	KindQuery:      "query",
	KindBody:       "body",
	KindHeader:     "header",
	KindCookie:     "cookie",
	KindQueryParam: "query_param",
	KindJSON:       "json",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// Target is a parsed rule target. Arg is only meaningful for the parametrised
// kinds (header, cookie, query_param, json).
type Target struct {
	Kind Kind
	Arg  string
}

// Parse converts a textual target into a Target. Target text is matched
// case-sensitively for the kind name (rules are authored in lowercase), but
// header and cookie names are matched case-insensitively at extraction time.
func Parse(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	name, arg, hasArg := strings.Cut(s, ":")
	switch name {
	case "method":
		if hasArg {
			return Target{}, fmt.Errorf("target %q does not take an argument", name)
		}
		return Target{Kind: KindMethod}, nil
	case "host":
		if hasArg {
			return Target{}, fmt.Errorf("target %q does not take an argument", name)
		}
		return Target{Kind: KindHost}, nil
	case "path":
		if hasArg {
			return Target{}, fmt.Errorf("target %q does not take an argument", name)
		}
		return Target{Kind: KindPath}, nil
	case "uri":
		if hasArg {
			return Target{}, fmt.Errorf("target %q does not take an argument", name)
		}
		return Target{Kind: KindURI}, nil
	case "query":
		if hasArg {
			return Target{}, fmt.Errorf("target %q does not take an argument", name)
		}
		return Target{Kind: KindQuery}, nil
	case "body":
		if hasArg {
			return Target{}, fmt.Errorf("target %q does not take an argument", name)
		}
		return Target{Kind: KindBody}, nil
	case "header":
		if hasArg && strings.TrimSpace(arg) == "" {
			return Target{}, fmt.Errorf("target %q requires a non-empty header name", s)
		}
		return Target{Kind: KindHeader, Arg: arg}, nil
	case "cookie":
		if hasArg && strings.TrimSpace(arg) == "" {
			return Target{}, fmt.Errorf("target %q requires a non-empty cookie name", s)
		}
		return Target{Kind: KindCookie, Arg: arg}, nil
	case "query_param":
		if !hasArg || strings.TrimSpace(arg) == "" {
			return Target{}, fmt.Errorf("target %q requires a parameter name", s)
		}
		return Target{Kind: KindQueryParam, Arg: arg}, nil
	case "json":
		if !hasArg || strings.TrimSpace(arg) == "" {
			return Target{}, fmt.Errorf("target %q requires a dotted path", s)
		}
		if err := validateJSONPath(arg); err != nil {
			return Target{}, err
		}
		return Target{Kind: KindJSON, Arg: arg}, nil
	default:
		return Target{}, fmt.Errorf("unknown target %q", name)
	}
}

func validateJSONPath(p string) error {
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			return fmt.Errorf("json path %q contains an empty segment", p)
		}
	}
	return nil
}

// String renders the target back to its textual form.
func (t Target) String() string {
	if t.Arg == "" {
		return t.Kind.String()
	}
	return t.Kind.String() + ":" + t.Arg
}

// Key returns the canonical grouping key used by the compiler. Two targets
// with the same Key can be extracted with a single lookup.
func (t Target) Key() string {
	if t.Kind == KindHeader || t.Kind == KindCookie {
		// Header/cookie names are case-insensitive.
		return t.Kind.String() + ":" + strings.ToLower(t.Arg)
	}
	return t.String()
}

// IsAll reports whether the target expands to every value of its kind rather
// than a single named value.
func (t Target) IsAll() bool {
	return (t.Kind == KindHeader || t.Kind == KindCookie) && t.Arg == ""
}
