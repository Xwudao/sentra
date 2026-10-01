// Package storage persists rules, IP rules, settings and security events in
// SQLite. It is part of the control plane and is never touched on the request
// hot path.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/rule"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = sql.ErrNoRows

// IPRule is an allow/block entry.
type IPRule struct {
	ID        string    `json:"id"`
	CIDR      string    `json:"cidr"`
	Action    string    `json:"action"` // allow | block
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// EventFilter narrows an event query.
type EventFilter struct {
	Action string
	IP     string
	Rule   string
	Path   string
	From   time.Time
	To     time.Time
	Limit  int
	Offset int
}

// TimelinePoint is a single hourly bucket for the dashboard chart.
type TimelinePoint struct {
	Hour     int64 `json:"hour"`
	Requests int64 `json:"requests"`
	Blocked  int64 `json:"blocked"`
}

// StatCount is a keyed aggregate.
type StatCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Store is the persistence contract used by the API. InsertEvents also
// satisfies event.Store.
type Store interface {
	// Rules
	ListRules(ctx context.Context) ([]rule.Rule, error)
	GetRule(ctx context.Context, id string) (rule.Rule, error)
	UpsertRule(ctx context.Context, r rule.Rule, builtin bool) error
	DeleteRule(ctx context.Context, id string) error
	ReplaceRules(ctx context.Context, rules []rule.Rule) error

	// IP rules
	ListIPRules(ctx context.Context) ([]IPRule, error)
	UpsertIPRule(ctx context.Context, r IPRule) error
	InsertIPRules(ctx context.Context, rules []IPRule) error
	DeleteIPRule(ctx context.Context, id string) error

	// Settings
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
	SetSetting(ctx context.Context, key string, value json.RawMessage) error
	ListSettings(ctx context.Context) (map[string]json.RawMessage, error)

	// Events
	InsertEvents(ctx context.Context, events []event.SecurityEvent) error
	ListEvents(ctx context.Context, f EventFilter) ([]event.SecurityEvent, error)
	GetEvent(ctx context.Context, id string) (event.SecurityEvent, error)
	CountEvents(ctx context.Context, f EventFilter) (int64, error)
	PruneEvents(ctx context.Context, before time.Time) (int64, error)
	ClearEvents(ctx context.Context) error
	AggregateEvents(ctx context.Context, since time.Time) (ips, paths, rules []StatCount, err error)

	Close() error
}
