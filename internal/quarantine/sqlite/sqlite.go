// Package sqlite is the SQLite adapter for the Tool Quarantine
// component's domain package, internal/quarantine. It is the only place
// SQL for the quarantine lives -- per the ports & adapters split
// (docs/context/05-testabilidade-e-contratos.md), the
// quarantine package itself contains no infrastructure detail.
//
// This adapter deliberately holds no policy. Every state transition is
// computed by the domain (quarantine.NewTool, Tool.Observed,
// Tool.Approved) and merely written here, so the rules that decide whether
// a tool is usable can never diverge between the Go code and an UPDATE
// statement.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// timeLayout is the on-disk representation of the quarantine's
// timestamps: RFC3339 with nanosecond precision, so round-tripping
// through TEXT storage loses neither precision nor the original offset.
const timeLayout = time.RFC3339Nano

// Migrate creates the quarantined_tools table if it does not already
// exist. It is idempotent and safe to call on every startup.
//
// The primary key is (server_name, tool_name): quarantine state is
// per-tool, not per-server (design/adr/0003-security-controls.md item 2),
// so two tools on the same upstream hold independent approval state and
// one changing never disturbs the other.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS quarantined_tools (
	server_name   TEXT NOT NULL,
	tool_name     TEXT NOT NULL,
	status        TEXT NOT NULL,
	approved_hash TEXT NOT NULL,
	observed_hash TEXT NOT NULL,
	first_seen_at TEXT NOT NULL,
	updated_at    TEXT NOT NULL,
	PRIMARY KEY (server_name, tool_name)
);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("quarantine/sqlite: migrate: %w", err)
	}
	return nil
}

// Store is the SQLite-backed implementation of quarantine.Store.
type Store struct {
	db *sql.DB
}

var _ quarantine.Store = (*Store)(nil)

// New returns a Store that persists quarantine state through db. db must
// already have been migrated with Migrate.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Observe implements quarantine.Store.
//
// The read of the existing row and the write of its successor run in one
// transaction: two concurrent discovery cycles observing the same tool
// must not interleave into a state neither of them computed, and in
// particular must not let a "changed" verdict be overwritten by a
// concurrent "still approved" one.
func (s *Store) Observe(ctx context.Context, serverName string, t quarantine.ToolIdentity) (quarantine.Tool, error) {
	observedHash := quarantine.Hash(t)
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: %w", serverName, t.Name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded

	prev, err := get(ctx, tx, serverName, t.Name)
	switch {
	case err == nil:
		// Known tool: let the domain decide the next state.
		next, err := prev.Observed(observedHash, now)
		if err != nil {
			return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: %w", serverName, t.Name, err)
		}
		if err := update(ctx, tx, next); err != nil {
			return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: %w", serverName, t.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: commit: %w", serverName, t.Name, err)
		}
		return next, nil

	case errors.Is(err, quarantine.ErrNotFound):
		// First sighting: born pending, never usable until approved.
		next := quarantine.NewTool(serverName, t.Name, observedHash, now)
		if err := insert(ctx, tx, next); err != nil {
			return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: %w", serverName, t.Name, err)
		}
		if err := tx.Commit(); err != nil {
			return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: commit: %w", serverName, t.Name, err)
		}
		return next, nil

	default:
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: %w", serverName, t.Name, err)
	}
}

// Approve implements quarantine.Store.
func (s *Store) Approve(ctx context.Context, serverName, toolName string) (quarantine.Tool, error) {
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: %w", serverName, toolName, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded

	prev, err := get(ctx, tx, serverName, toolName)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: %w", serverName, toolName, err)
	}

	next := prev.Approved(now)
	if err := update(ctx, tx, next); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: %w", serverName, toolName, err)
	}
	if err := tx.Commit(); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: commit: %w", serverName, toolName, err)
	}
	return next, nil
}

// Get implements quarantine.Store.
func (s *Store) Get(ctx context.Context, serverName, toolName string) (quarantine.Tool, error) {
	t, err := get(ctx, s.db, serverName, toolName)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: get %q/%q: %w", serverName, toolName, err)
	}
	return t, nil
}

// List implements quarantine.Store.
func (s *Store) List(ctx context.Context, serverName string) ([]quarantine.Tool, error) {
	// An empty serverName means "every server". The predicate is written
	// as a parameterized OR rather than by building two query strings so
	// there is only one SELECT to keep in sync.
	const stmt = `
SELECT server_name, tool_name, status, approved_hash, observed_hash, first_seen_at, updated_at
FROM quarantined_tools
WHERE ? = '' OR server_name = ?
ORDER BY server_name, tool_name
`
	rows, err := s.db.QueryContext(ctx, stmt, serverName, serverName)
	if err != nil {
		return nil, fmt.Errorf("quarantine/sqlite: list: %w", err)
	}
	defer rows.Close()

	tools := []quarantine.Tool{}
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, fmt.Errorf("quarantine/sqlite: list: %w", err)
		}
		tools = append(tools, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("quarantine/sqlite: list: %w", err)
	}
	return tools, nil
}

// querier is satisfied by both *sql.DB and *sql.Tx, so the row-level
// helpers below serve the transactional and non-transactional paths alike.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// get reads one entry, returning quarantine.ErrNotFound (unwrapped, for
// callers here to wrap with their own context) when there is no such row.
func get(ctx context.Context, q querier, serverName, toolName string) (quarantine.Tool, error) {
	const stmt = `
SELECT server_name, tool_name, status, approved_hash, observed_hash, first_seen_at, updated_at
FROM quarantined_tools
WHERE server_name = ? AND tool_name = ?
`
	t, err := scanTool(q.QueryRowContext(ctx, stmt, serverName, toolName))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return quarantine.Tool{}, quarantine.ErrNotFound
		}
		return quarantine.Tool{}, err
	}
	return t, nil
}

func insert(ctx context.Context, q querier, t quarantine.Tool) error {
	const stmt = `
INSERT INTO quarantined_tools
	(server_name, tool_name, status, approved_hash, observed_hash, first_seen_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`
	_, err := q.ExecContext(ctx, stmt,
		t.ServerName, t.ToolName, string(t.Status), t.ApprovedHash, t.ObservedHash,
		t.FirstSeenAt.Format(timeLayout), t.UpdatedAt.Format(timeLayout))
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}

func update(ctx context.Context, q querier, t quarantine.Tool) error {
	const stmt = `
UPDATE quarantined_tools
SET status = ?, approved_hash = ?, observed_hash = ?, updated_at = ?
WHERE server_name = ? AND tool_name = ?
`
	res, err := q.ExecContext(ctx, stmt,
		string(t.Status), t.ApprovedHash, t.ObservedHash, t.UpdatedAt.Format(timeLayout),
		t.ServerName, t.ToolName)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if n == 0 {
		return quarantine.ErrNotFound
	}
	return nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTool(row rowScanner) (quarantine.Tool, error) {
	var (
		t                      quarantine.Tool
		status                 string
		firstSeenAt, updatedAt string
	)

	if err := row.Scan(&t.ServerName, &t.ToolName, &status, &t.ApprovedHash, &t.ObservedHash,
		&firstSeenAt, &updatedAt); err != nil {
		return quarantine.Tool{}, err
	}

	t.Status = quarantine.Status(status)
	// A status the domain does not define means the row is corrupt or was
	// hand-edited. Fail loudly rather than hand back a Tool whose Usable()
	// happens to answer false for the wrong reason.
	if !t.Status.Valid() {
		return quarantine.Tool{}, fmt.Errorf("%w: %q", quarantine.ErrInvalidStatus, status)
	}

	firstSeen, err := time.Parse(timeLayout, firstSeenAt)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("parse first_seen_at: %w", err)
	}
	t.FirstSeenAt = firstSeen

	updated, err := time.Parse(timeLayout, updatedAt)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("parse updated_at: %w", err)
	}
	t.UpdatedAt = updated

	return t, nil
}
