package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Xwudao/sentra/internal/event"
	"github.com/Xwudao/sentra/internal/rule"
	_ "modernc.org/sqlite"
)

// SQLite is the database/sql-backed Store implementation.
type SQLite struct {
	db   *sql.DB
	path string
}

// Open opens (creating if needed) the SQLite database and applies migrations.
func Open(path string) (*SQLite, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection keeps modernc/sqlite free of SQLITE_BUSY churn. The
	// control plane is low-throughput, so this is not a bottleneck.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db, path: path}, nil
}

// Path returns the database file path.
func (s *SQLite) Path() string { return s.path }

// DB exposes the underlying handle for tests.
func (s *SQLite) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func unmarshalStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// ---------------------------------------------------------------- rules

const ruleColumns = `id, name, enabled, phase, targets, operator, value, match_values, transforms,
	action, score, severity, priority, tags, description`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRule(sc rowScanner) (rule.Rule, error) {
	var r rule.Rule
	var enabled int
	var targets, values, transforms, tags string
	if err := sc.Scan(
		&r.ID, &r.Name, &enabled, &r.Phase, &targets, &r.Operator, &r.Value, &values,
		&transforms, &r.Action, &r.Score, &r.Severity, &r.Priority, &tags, &r.Description,
	); err != nil {
		return rule.Rule{}, err
	}
	r.Enabled = enabled != 0
	r.Targets = unmarshalStrings(targets)
	r.Values = unmarshalStrings(values)
	r.Transforms = unmarshalStrings(transforms)
	r.Tags = unmarshalStrings(tags)
	return r, nil
}

// ListRules returns all rules ordered by priority then id.
func (s *SQLite) ListRules(ctx context.Context) ([]rule.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+ruleColumns+` FROM rules ORDER BY priority DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rule.Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRule returns a single rule.
func (s *SQLite) GetRule(ctx context.Context, id string) (rule.Rule, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+ruleColumns+` FROM rules WHERE id = ?`, id)
	return scanRule(row)
}

// UpsertRule inserts or replaces a rule.
func (s *SQLite) UpsertRule(ctx context.Context, r rule.Rule, builtin bool) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rules (id, name, enabled, phase, targets, operator, value, match_values, transforms,
			action, score, severity, priority, tags, description, builtin, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, enabled=excluded.enabled, phase=excluded.phase,
			targets=excluded.targets, operator=excluded.operator, value=excluded.value,
			match_values=excluded.match_values, transforms=excluded.transforms, action=excluded.action,
			score=excluded.score, severity=excluded.severity, priority=excluded.priority,
			tags=excluded.tags, description=excluded.description, updated_at=excluded.updated_at`,
		r.ID, r.Name, boolInt(r.Enabled), r.Phase, mustJSON(r.Targets), r.Operator, r.Value,
		mustJSON(r.Values), mustJSON(r.Transforms), r.Action, r.Score, r.Severity, r.Priority,
		mustJSON(r.Tags), r.Description, boolInt(builtin), now, now)
	return err
}

// ReplaceRules atomically replaces all stored rules with the supplied built-in rules.
func (s *SQLite) ReplaceRules(ctx context.Context, rules []rule.Rule) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM rules`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO rules (id, name, enabled, phase, targets, operator, value, match_values, transforms,
			action, score, severity, priority, tags, description, builtin, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, r := range rules {
		if _, err = stmt.ExecContext(ctx,
			r.ID, r.Name, boolInt(r.Enabled), r.Phase, mustJSON(r.Targets), r.Operator, r.Value,
			mustJSON(r.Values), mustJSON(r.Transforms), r.Action, r.Score, r.Severity, r.Priority,
			mustJSON(r.Tags), r.Description, 1, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteRule removes a rule.
func (s *SQLite) DeleteRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ------------------------------------------------------------ ip rules

// ListIPRules returns all IP rules.
func (s *SQLite) ListIPRules(ctx context.Context) ([]IPRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, cidr, action, note, created_at FROM ip_rules ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPRule
	for rows.Next() {
		var r IPRule
		var created string
		if err := rows.Scan(&r.ID, &r.CIDR, &r.Action, &r.Note, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertIPRule inserts or replaces an IP rule.
func (s *SQLite) UpsertIPRule(ctx context.Context, r IPRule) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ip_rules (id, cidr, action, note, created_at) VALUES (?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET cidr=excluded.cidr, action=excluded.action, note=excluded.note`,
		r.ID, r.CIDR, r.Action, r.Note, r.CreatedAt.Format(time.RFC3339Nano))
	return err
}

// DeleteIPRule removes an IP rule.
func (s *SQLite) DeleteIPRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ip_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ------------------------------------------------------------ settings

// GetSetting returns a raw JSON setting value.
func (s *SQLite) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(v), nil
}

// SetSetting writes a raw JSON setting value.
func (s *SQLite) SetSetting(ctx context.Context, key string, value json.RawMessage) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, string(value), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ListSettings returns all settings.
func (s *SQLite) ListSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = json.RawMessage(v)
	}
	return out, rows.Err()
}

// -------------------------------------------------------------- events

// InsertEvents persists a batch atomically.
func (s *SQLite) InsertEvents(ctx context.Context, events []event.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO security_events
			(id, ts, client_ip, method, host, path, query, action, status, score,
			 duration_us, body_truncated, user_agent, matches)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		var truncated int
		if e.BodyTruncated {
			truncated = 1
		}
		if _, err := stmt.ExecContext(ctx,
			e.ID, e.Timestamp.UnixMilli(), e.ClientIP, e.Method, e.Host, e.Path, e.Query,
			e.Action, e.Status, e.Score, e.DurationUS, truncated, e.UserAgent, mustJSON(e.Matches),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// PruneEvents deletes security events older than the cutoff and returns the
// number of rows removed. Old events are re-inserted by nothing, so this is
// only ever called by the background janitor.
func (s *SQLite) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM security_events WHERE ts < ?`, before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func eventWhere(f EventFilter) (string, []any) {
	var clauses []string
	var args []any
	if f.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, f.Action)
	}
	if f.IP != "" {
		clauses = append(clauses, "client_ip = ?")
		args = append(args, f.IP)
	}
	if f.Path != "" {
		clauses = append(clauses, "path LIKE ?")
		args = append(args, "%"+f.Path+"%")
	}
	if f.Rule != "" {
		clauses = append(clauses, "matches LIKE ?")
		args = append(args, "%"+f.Rule+"%")
	}
	if !f.From.IsZero() {
		clauses = append(clauses, "ts >= ?")
		args = append(args, f.From.UnixMilli())
	}
	if !f.To.IsZero() {
		clauses = append(clauses, "ts <= ?")
		args = append(args, f.To.UnixMilli())
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// ListEvents returns matching events, newest first.
func (s *SQLite) ListEvents(ctx context.Context, f EventFilter) ([]event.SecurityEvent, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	where, args := eventWhere(f)
	query := `SELECT id, ts, client_ip, method, host, path, query, action, status, score,
		duration_us, body_truncated, user_agent, matches FROM security_events` + where +
		` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []event.SecurityEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEvent returns one event by id.
func (s *SQLite) GetEvent(ctx context.Context, id string) (event.SecurityEvent, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, ts, client_ip, method, host, path, query, action, status, score,
		duration_us, body_truncated, user_agent, matches FROM security_events WHERE id = ?`, id)
	return scanEvent(row)
}

// CountEvents counts matching events.
func (s *SQLite) CountEvents(ctx context.Context, f EventFilter) (int64, error) {
	where, args := eventWhere(f)
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_events`+where, args...).Scan(&n)
	return n, err
}

func scanEvent(sc rowScanner) (event.SecurityEvent, error) {
	var e event.SecurityEvent
	var ts int64
	var truncated int
	var matches string
	if err := sc.Scan(&e.ID, &ts, &e.ClientIP, &e.Method, &e.Host, &e.Path, &e.Query,
		&e.Action, &e.Status, &e.Score, &e.DurationUS, &truncated, &e.UserAgent, &matches); err != nil {
		return event.SecurityEvent{}, err
	}
	e.Timestamp = time.UnixMilli(ts).UTC()
	e.BodyTruncated = truncated != 0
	if matches != "" {
		_ = json.Unmarshal([]byte(matches), &e.Matches)
	}
	return e, nil
}

// AggregateEvents returns top IPs, paths and rules since the given time.
func (s *SQLite) AggregateEvents(ctx context.Context, since time.Time) (ips, paths, rules []StatCount, err error) {
	ts := since.UnixMilli()
	if ips, err = s.groupCount(ctx, "client_ip", ts, 10); err != nil {
		return nil, nil, nil, err
	}
	if paths, err = s.groupCount(ctx, "path", ts, 10); err != nil {
		return nil, nil, nil, err
	}
	rules, err = s.topRules(ctx, ts, 10)
	if err != nil {
		return nil, nil, nil, err
	}
	return ips, paths, rules, nil
}

func (s *SQLite) groupCount(ctx context.Context, column string, sinceMs int64, limit int) ([]StatCount, error) {
	// column is chosen from a fixed allow-list by callers.
	q := fmt.Sprintf(`SELECT %s, COUNT(*) c FROM security_events WHERE ts >= ? GROUP BY %s ORDER BY c DESC LIMIT ?`, column, column)
	rows, err := s.db.QueryContext(ctx, q, sinceMs, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatCount
	for rows.Next() {
		var sc StatCount
		if err := rows.Scan(&sc.Key, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *SQLite) topRules(ctx context.Context, sinceMs int64, limit int) ([]StatCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT matches FROM security_events WHERE ts >= ? ORDER BY ts DESC LIMIT 20000`, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ms []event.Match
		if err := json.Unmarshal([]byte(raw), &ms); err != nil {
			continue
		}
		seen := map[string]bool{}
		for _, m := range ms {
			if seen[m.RuleID] {
				continue
			}
			seen[m.RuleID] = true
			counts[m.RuleID]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]StatCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, StatCount{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var _ Store = (*SQLite)(nil)
var _ event.Store = (*SQLite)(nil)
