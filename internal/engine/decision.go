package engine

import "github.com/Xwudao/sentra/internal/rule"

// Decision is the outcome of evaluating a request against the WAF.
type Decision struct {
	Action        rule.Action
	StatusCode    int
	Score         int
	Matches       []Match
	Blocked       bool
	RateLimited   bool
	AllowedByIP   bool
	BlockedByIP   bool
	BodyTruncated bool
	Debug         *DebugResult
}

// Match describes a single rule hit.
type Match struct {
	RuleID   string      `json:"rule_id"`
	RuleName string      `json:"rule_name"`
	Target   string      `json:"target"`
	Severity string      `json:"severity,omitempty"`
	Score    int         `json:"score"`
	Action   rule.Action `json:"action"`

	// Raw and Transformed are populated only in debug/playground mode.
	Raw         string `json:"raw_value,omitempty"`
	Transformed string `json:"transformed_value,omitempty"`
}

// DebugResult carries playground-only detail.
type DebugResult struct {
	Matches []Match `json:"matches"`
}
