// Package rule defines the Sentra rule model and compiles rules into an
// immutable execution plan.
package rule

import (
	"fmt"
	"strings"
)

// Phase identifies the point in the request lifecycle a rule applies to.
// Only PhaseRequest is implemented in the first release; PhaseResponse is
// reserved so persisted rules and the JSON schema remain forward compatible.
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

// Action is what happens when a rule matches.
type Action string

const (
	ActionAllow Action = "allow"
	ActionLog   Action = "log"
	ActionBlock Action = "block"
)

// Severity is the qualitative impact attached to a match.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Operator selects the matcher implementation.
type Operator string

const (
	OpRegex      Operator = "regex"
	OpContains   Operator = "contains"
	OpEquals     Operator = "equals"
	OpPrefix     Operator = "prefix"
	OpSuffix     Operator = "suffix"
	OpKeywordSet Operator = "keyword_set"
	// OpIPMatch is reserved for a future release. IP handling currently lives
	// in the dedicated ipset subsystem.
	OpIPMatch Operator = "ip_match"
)

// ValidAction reports whether a is a supported action.
func ValidAction(a Action) bool {
	switch a {
	case ActionAllow, ActionLog, ActionBlock:
		return true
	}
	return false
}

// ValidSeverity reports whether s is a supported severity.
func ValidSeverity(s Severity) bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// validOperator reports whether op can be compiled.
func validOperator(op Operator) bool {
	switch op {
	case OpRegex, OpContains, OpEquals, OpPrefix, OpSuffix, OpKeywordSet:
		return true
	}
	return false
}

// Rule is the persisted, user-facing description of a detection. It is
// intentionally independent from the compiled representation.
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	Phase       Phase    `json:"phase"`
	Targets     []string `json:"targets"`
	Operator    Operator `json:"operator"`
	Value       string   `json:"value"`
	Values      []string `json:"values,omitempty"` // keyword_set only
	Transforms  []string `json:"transforms"`
	Action      Action   `json:"action"`
	Score       int      `json:"score"`
	Severity    Severity `json:"severity"`
	Priority    int      `json:"priority"`
	Tags        []string `json:"tags"`
	Description string   `json:"description"`
}

// Clone returns a deep copy so callers cannot mutate a live ruleset through a
// shared Rule pointer.
func (r Rule) Clone() Rule {
	c := r
	c.Targets = append([]string(nil), r.Targets...)
	c.Values = append([]string(nil), r.Values...)
	c.Transforms = append([]string(nil), r.Transforms...)
	c.Tags = append([]string(nil), r.Tags...)
	return c
}

// Normalize fills in defaults for optional fields and canonicalises enum
// casing. It does not validate required fields.
func (r *Rule) Normalize() {
	r.Phase = Phase(strings.ToLower(string(r.Phase)))
	if r.Phase == "" {
		r.Phase = PhaseRequest
	}
	r.Operator = Operator(strings.ToLower(string(r.Operator)))
	r.Action = Action(strings.ToLower(string(r.Action)))
	if r.Action == "" {
		r.Action = ActionBlock
	}
	r.Severity = Severity(strings.ToLower(string(r.Severity)))
	if r.Severity == "" {
		r.Severity = SeverityMedium
	}
	if r.Score < 0 {
		r.Score = 0
	}
}

func (r Rule) String() string {
	if r.Name != "" {
		return fmt.Sprintf("%s (%s)", r.ID, r.Name)
	}
	return r.ID
}
