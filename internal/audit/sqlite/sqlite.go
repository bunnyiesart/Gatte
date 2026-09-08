// Package sqlite is the SQLite adapter for the Audit Trail component's
// domain package, internal/audit. It is the only place SQL for the audit
// trail lives -- per the ports & adapters split
// (docs/context/05-testabilidade-e-contratos.md), the audit
// package itself contains no infrastructure detail.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// timeLayout is the on-disk representation of Record.Timestamp: RFC3339
// with nanosecond precision, so round-tripping through TEXT storage loses
// neither precision nor the original offset.
const timeLayout = time.RFC3339Nano

// Migrate creates the audit_records table and its supporting index if
// they do not already exist. It is idempotent and safe to call on every
// startup.
//
// audit_records has an internal auto-increment id column purely so
// SQLite has a stable row identity; it is not exposed through
// audit.Record or through Recorder's methods.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS audit_records (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	analyst_identity TEXT NOT NULL,
	tool             TEXT NOT NULL,
	target_upstream  TEXT NOT NULL,
	timestamp        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_records_timestamp
	ON audit_records (timestamp);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("audit/sqlite: migrate: %w", err)
	}
	return nil
}

// Recorder is the SQLite-backed implementation of audit.Recorder.
type Recorder struct {
	db *sql.DB
}

var _ audit.Recorder = (*Recorder)(nil)

// New returns a Recorder that stores and retrieves records through db.
// db must already have been migrated with Migrate.
func New(db *sql.DB) *Recorder {
	return &Recorder{db: db}
}

// Record implements audit.Recorder.
func (r *Recorder) Record(ctx context.Context, rec audit.Record) error {
	if err := rec.Validate(); err != nil {
		return err
	}

	const stmt = `
INSERT INTO audit_records (analyst_identity, tool, target_upstream, timestamp)
VALUES (?, ?, ?, ?)
`
	_, err := r.db.ExecContext(ctx, stmt,
		rec.AnalystIdentity, rec.Tool, rec.TargetUpstream, rec.Timestamp.Format(timeLayout))
	if err != nil {
		return fmt.Errorf("audit/sqlite: record: %w", err)
	}
	return nil
}

// List implements audit.Recorder.
func (r *Recorder) List(ctx context.Context) ([]audit.Record, error) {
	const stmt = `
SELECT analyst_identity, tool, target_upstream, timestamp
FROM audit_records
ORDER BY timestamp ASC
`
	rows, err := r.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: list: %w", err)
	}
	defer rows.Close()

	records := []audit.Record{}
	for rows.Next() {
		var rec audit.Record
		var ts string
		if err := rows.Scan(&rec.AnalystIdentity, &rec.Tool, &rec.TargetUpstream, &ts); err != nil {
			return nil, fmt.Errorf("audit/sqlite: list: scan: %w", err)
		}
		rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			return nil, fmt.Errorf("audit/sqlite: list: parse timestamp: %w", err)
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit/sqlite: list: %w", err)
	}
	return records, nil
}
