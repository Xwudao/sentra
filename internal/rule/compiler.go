package rule

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Xwudao/sentra/internal/matcher"
	"github.com/Xwudao/sentra/internal/target"
	"github.com/Xwudao/sentra/internal/transform"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Validate checks a single rule for structural correctness. It does not
// compile the matcher; ValidateMatcher performs operator-specific checks.
func Validate(r *Rule) error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("id %q must match %s", r.ID, idPattern)
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if r.Phase != PhaseRequest {
		return fmt.Errorf("phase %q is not supported (only %q)", r.Phase, PhaseRequest)
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	for _, t := range r.Targets {
		if _, err := target.Parse(t); err != nil {
			return err
		}
	}
	if !validOperator(r.Operator) {
		return fmt.Errorf("unknown operator %q", r.Operator)
	}
	if r.Operator != OpKeywordSet && r.Value == "" {
		return fmt.Errorf("operator %q requires a value", r.Operator)
	}
	for _, name := range r.Transforms {
		if _, ok := transform.Lookup(name); !ok {
			return fmt.Errorf("unknown transform %q", name)
		}
	}
	if !ValidAction(r.Action) {
		return fmt.Errorf("unknown action %q", r.Action)
	}
	if r.Score < 0 {
		return fmt.Errorf("score must not be negative")
	}
	if !ValidSeverity(r.Severity) {
		return fmt.Errorf("unknown severity %q", r.Severity)
	}
	return nil
}

// TargetGroup is a batch of rule matchers that share an extracted target and
// transform pipeline. The request path extracts and transforms once per
// group, never once per rule.
type TargetGroup struct {
	Target   target.Target
	Pipeline transform.Pipeline
	Matchers []GroupMatcher
	Priority int
}

// GroupMatcher pairs a rule's metadata with its compiled matcher.
type GroupMatcher struct {
	Rule    *Rule
	Matcher matcher.Matcher
}

// CompiledRuleset is an immutable execution plan. Once published it is never
// mutated; reloads build a new value and atomically swap it in.
type CompiledRuleset struct {
	Version    int64
	Groups     []*TargetGroup
	NeedBody   bool
	NeedJSON   bool
	NeedCookie bool
	RuleCount  int
}

// GroupCount reports the number of compiled target groups.
func (c *CompiledRuleset) GroupCount() int { return len(c.Groups) }

// Compile validates and compiles rules into an execution plan. Disabled rules
// are ignored. Any error aborts the whole compilation so the caller can keep
// the previous ruleset.
func Compile(rules []Rule, version int64) (*CompiledRuleset, error) {
	cs := &CompiledRuleset{Version: version}
	groups := make(map[string]*TargetGroup)
	seen := make(map[string]struct{}, len(rules))

	for i := range rules {
		r := rules[i].Clone()
		r.Normalize()
		if !r.Enabled {
			continue
		}
		rule := &r
		if _, dup := seen[rule.ID]; dup {
			return nil, fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if err := Validate(rule); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		m, err := matcher.Build(string(rule.Operator), rule.Value, rule.Values)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}

		pipeline, names, err := buildPipeline(rule.Transforms)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}

		addedTargets := make(map[string]struct{}, len(rule.Targets))
		for _, ts := range rule.Targets {
			t, err := target.Parse(ts)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			key := t.Key() + "\x00" + transform.JoinNames(names)
			if _, done := addedTargets[key]; done {
				continue
			}
			addedTargets[key] = struct{}{}

			g, ok := groups[key]
			if !ok {
				g = &TargetGroup{Target: t, Pipeline: pipeline}
				groups[key] = g
				applyNeedFlags(cs, t)
			}
			if rule.Priority > g.Priority {
				g.Priority = rule.Priority
			}
			g.Matchers = append(g.Matchers, GroupMatcher{Rule: rule, Matcher: m})
		}
		cs.RuleCount++
	}

	cs.Groups = make([]*TargetGroup, 0, len(groups))
	for _, g := range groups {
		cs.Groups = append(cs.Groups, g)
	}
	sortGroups(cs.Groups)
	return cs, nil
}

func buildPipeline(names []string) (transform.Pipeline, []string, error) {
	if len(names) == 0 {
		return nil, nil, nil
	}
	out := make([]string, len(names))
	p := make(transform.Pipeline, len(names))
	for i, name := range names {
		fn, ok := transform.Lookup(name)
		if !ok {
			return nil, nil, fmt.Errorf("unknown transform %q", name)
		}
		out[i] = name
		p[i] = fn
	}
	return p, out, nil
}

func applyNeedFlags(cs *CompiledRuleset, t target.Target) {
	switch t.Kind {
	case target.KindBody:
		cs.NeedBody = true
	case target.KindJSON:
		cs.NeedBody = true
		cs.NeedJSON = true
	case target.KindCookie:
		cs.NeedCookie = true
	}
}

func sortGroups(groups []*TargetGroup) {
	// Higher priority first; stable tie-break on the canonical key so the
	// execution order is deterministic and inspectable.
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.Target.Key() < b.Target.Key()
	})
}
