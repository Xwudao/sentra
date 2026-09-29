package storage

import (
	"database/sql"
	"fmt"
)

type migration struct {
	version    int
	name       string
	statements []string
}

// migrations are forward-only and append-only. Never edit a released
// migration; add a new one instead.
var migrations = []migration{
	{
		version: 1,
		name:    "init",
		statements: []string{
			`CREATE TABLE IF NOT EXISTS rules (
				id          TEXT PRIMARY KEY,
				name        TEXT NOT NULL,
				enabled     INTEGER NOT NULL DEFAULT 1,
				phase       TEXT NOT NULL DEFAULT 'request',
				targets     TEXT NOT NULL,
				operator    TEXT NOT NULL,
				value       TEXT NOT NULL DEFAULT '',
				match_values TEXT NOT NULL DEFAULT '[]',
				transforms  TEXT NOT NULL DEFAULT '[]',
				action      TEXT NOT NULL DEFAULT 'block',
				score       INTEGER NOT NULL DEFAULT 0,
				severity    TEXT NOT NULL DEFAULT 'medium',
				priority    INTEGER NOT NULL DEFAULT 0,
				tags        TEXT NOT NULL DEFAULT '[]',
				description TEXT NOT NULL DEFAULT '',
				builtin     INTEGER NOT NULL DEFAULT 0,
				created_at  TEXT NOT NULL,
				updated_at  TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS security_events (
				id             TEXT PRIMARY KEY,
				ts             INTEGER NOT NULL,
				client_ip      TEXT NOT NULL,
				method         TEXT NOT NULL,
				host           TEXT NOT NULL,
				path           TEXT NOT NULL,
				query          TEXT NOT NULL DEFAULT '',
				action         TEXT NOT NULL,
				status         INTEGER NOT NULL DEFAULT 0,
				score          INTEGER NOT NULL DEFAULT 0,
				duration_us    INTEGER NOT NULL DEFAULT 0,
				body_truncated INTEGER NOT NULL DEFAULT 0,
				user_agent     TEXT NOT NULL DEFAULT '',
				matches        TEXT NOT NULL DEFAULT '[]'
			)`,
			`CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(ts DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(client_ip)`,
			`CREATE INDEX IF NOT EXISTS idx_events_action ON security_events(action)`,
			`CREATE TABLE IF NOT EXISTS ip_rules (
				id         TEXT PRIMARY KEY,
				cidr       TEXT NOT NULL,
				action     TEXT NOT NULL,
				note       TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS settings (
				key        TEXT PRIMARY KEY,
				value      TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
		},
	},
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range m.statements {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))`, m.version); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
