// Package sqlite is the SQLite adapter for the Access Control component's
// blocklist (design/adr/0031-bloqueio-imediato-por-analista.md). It is the
// only place SQL for blocked subjects lives; internal/access holds the
// port and the validation, and no policy is decided here.
//
// Roles are NOT in this table and never will be: a role is policy, lives
// in the reviewed TOML file (ADR-0009 §2), and widening one is a diff. A
// block only ever narrows -- it takes one subject out -- which is why it
// can be state, changed from the console, with the audit trail as its
// history.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// timeLayout matches the audit trail's and the quarantine's, so one file
// has one date format.
const timeLayout = time.RFC3339Nano

// Migrate creates the blocked_subjects table if it does not exist. It is
// idempotent and must be named in the composition root's migration map:
// a missing table would fail every request closed -- the Gateway refuses
// when it cannot read the blocklist -- which is an outage, not a startup
// error, unless openStore creates it.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS blocked_subjects (
	subject    TEXT PRIMARY KEY,
	reason     TEXT NOT NULL DEFAULT '',
	blocked_by TEXT NOT NULL,
	blocked_at TEXT NOT NULL
);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("access/sqlite: migrate: %w", err)
	}
	return nil
}

// Store is the SQLite-backed access.BlockStore.
//
// One type satisfies both ports; which one a caller holds decides what it
// can do. The composition root hands the Gateway an access.Blocklist, which
// can only ask, and the console an access.BlockStore.
type Store struct {
	db *sql.DB
}

var (
	_ access.Blocklist  = (*Store)(nil)
	_ access.BlockStore = (*Store)(nil)
)

// New returns a Store over db, which must already be migrated.
func New(db *sql.DB) *Store { return &Store{db: db} }

// Blocked implements access.Blocklist. It is a primary-key point read, on
// every request, and that is its whole cost.
func (s *Store) Blocked(ctx context.Context, subject string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM blocked_subjects WHERE subject = ?`, subject).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("%w: %w", access.ErrBlocklistUnavailable, err)
	}
	return true, nil
}

// Block implements access.BlockStore. ON CONFLICT DO NOTHING keeps the
// first block's author and time: re-blocking somebody already blocked is
// not a new event and must not rewrite who did it.
func (s *Store) Block(ctx context.Context, b access.Block) (bool, error) {
	if err := access.ValidateBlock(b); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO blocked_subjects (subject, reason, blocked_by, blocked_at)
VALUES (?, ?, ?, ?)
ON CONFLICT (subject) DO NOTHING`,
		b.Subject, b.Reason, b.By, b.At.UTC().Format(timeLayout))
	if err != nil {
		return false, fmt.Errorf("access/sqlite: block: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("access/sqlite: block: %w", err)
	}
	return n == 1, nil
}

// Unblock implements access.BlockStore.
func (s *Store) Unblock(ctx context.Context, subject string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM blocked_subjects WHERE subject = ?`, subject)
	if err != nil {
		return false, fmt.Errorf("access/sqlite: unblock: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("access/sqlite: unblock: %w", err)
	}
	return n == 1, nil
}

// Blocks implements access.BlockStore. An unparseable time fails the read
// rather than being skipped: every row this adapter writes formats it with
// timeLayout, so one that does not parse was written by something else,
// and the operator reading the list needs to be told.
func (s *Store) Blocks(ctx context.Context) ([]access.Block, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT subject, reason, blocked_by, blocked_at
FROM blocked_subjects
ORDER BY blocked_at, subject`)
	if err != nil {
		return nil, fmt.Errorf("access/sqlite: list: %w", err)
	}
	defer rows.Close()

	out := []access.Block{}
	for rows.Next() {
		var b access.Block
		var at string
		if err := rows.Scan(&b.Subject, &b.Reason, &b.By, &at); err != nil {
			return nil, fmt.Errorf("access/sqlite: list: scan: %w", err)
		}
		b.At, err = time.Parse(timeLayout, at)
		if err != nil {
			return nil, fmt.Errorf("access/sqlite: list: block on %q has an unreadable time %q: %w", b.Subject, at, err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("access/sqlite: list: %w", err)
	}
	return out, nil
}
