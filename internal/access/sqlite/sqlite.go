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
	"sort"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// timeLayout matches the audit trail's and the quarantine's, so one file
// has one date format.
const timeLayout = time.RFC3339Nano

// untilLayout is the end of a block (design/adr/0046), always UTC and of
// fixed width, so that SQL compares two of them as it compares instants.
// RFC3339Nano drops trailing zeros, and "12:00:05Z" sorts after
// "12:00:05.1Z" as text although it is earlier.
const untilLayout = "2006-01-02T15:04:05.000000000Z"

func formatUntil(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(untilLayout)
}

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
	// design/adr/0046: a block may end by itself. '' is a block with no
	// end, which is what every row written before the column meant. SQLite
	// has no ADD COLUMN IF NOT EXISTS; a duplicate column is success.
	if _, err := db.Exec(`ALTER TABLE blocked_subjects ADD COLUMN blocked_until TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
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
	db  *sql.DB
	now func() time.Time
}

var (
	_ access.Blocklist     = (*Store)(nil)
	_ access.BlockStore    = (*Store)(nil)
	_ access.BlockReplacer = (*Store)(nil)
)

// New returns a Store over db, which must already be migrated.
func New(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

// WithClock returns a Store over the same database that reads "now" from
// now: the instant a block's end is compared against.
func (s *Store) WithClock(now func() time.Time) *Store { return &Store{db: s.db, now: now} }

// Blocked implements access.Blocklist. It is a primary-key point read, on
// every request, and that is its whole cost.
//
// A block with an end is enforced until that end and not after it
// (design/adr/0046): this is the gateway's admission check, so the
// expiry takes effect at the instant stated, not at the next sweep. An end
// that does not parse keeps the subject blocked: a kill switch that
// opens on a row it cannot read is off exactly when someone wrote a
// strange row.
func (s *Store) Blocked(ctx context.Context, subject string) (bool, error) {
	var until string
	err := s.db.QueryRowContext(ctx, `SELECT blocked_until FROM blocked_subjects WHERE subject = ?`, subject).Scan(&until)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("%w: %w", access.ErrBlocklistUnavailable, err)
	}
	if until == "" {
		return true, nil
	}
	end, err := time.Parse(untilLayout, until)
	if err != nil {
		return true, nil
	}
	return s.now().Before(end), nil
}

// Block implements access.BlockStore. A conflict keeps the first block's
// author and time: re-blocking somebody already blocked is not a new event
// and must not rewrite who did it. The one exception is a block whose end
// has passed (design/adr/0046), which no longer blocks anyone and is
// replaced.
func (s *Store) Block(ctx context.Context, b access.Block) (bool, error) {
	if err := access.ValidateBlock(b); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO blocked_subjects (subject, reason, blocked_by, blocked_at, blocked_until)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (subject) DO UPDATE SET
	reason = excluded.reason, blocked_by = excluded.blocked_by,
	blocked_at = excluded.blocked_at, blocked_until = excluded.blocked_until
WHERE blocked_subjects.blocked_until <> '' AND blocked_subjects.blocked_until <= ?`,
		b.Subject, b.Reason, b.By, b.At.UTC().Format(timeLayout), formatUntil(b.Until), formatUntil(s.now()))
	if err != nil {
		return false, fmt.Errorf("access/sqlite: block: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("access/sqlite: block: %w", err)
	}
	return n == 1, nil
}

// BlockReplacing implements access.BlockReplacer: Block, and the block it
// replaced, read and replaced in one transaction so no other writer can
// slip between the two.
func (s *Store) BlockReplacing(ctx context.Context, b access.Block) (bool, *access.Block, error) {
	if err := access.ValidateBlock(b); err != nil {
		return false, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, nil, fmt.Errorf("access/sqlite: block: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var old access.Block
	var at, until string
	err = tx.QueryRowContext(ctx, `SELECT subject, reason, blocked_by, blocked_at, blocked_until FROM blocked_subjects WHERE subject = ?`, b.Subject).
		Scan(&old.Subject, &old.Reason, &old.By, &at, &until)
	existed := err == nil
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, nil, fmt.Errorf("access/sqlite: block: %w", err)
	default:
		if old.At, err = time.Parse(timeLayout, at); err != nil {
			return false, nil, fmt.Errorf("access/sqlite: block on %q has an unreadable time %q: %w", old.Subject, at, err)
		}
		if until != "" {
			if old.Until, err = time.Parse(untilLayout, until); err != nil {
				return false, nil, fmt.Errorf("access/sqlite: block on %q has an unreadable end %q: %w", old.Subject, until, err)
			}
		}
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO blocked_subjects (subject, reason, blocked_by, blocked_at, blocked_until)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (subject) DO UPDATE SET
	reason = excluded.reason, blocked_by = excluded.blocked_by,
	blocked_at = excluded.blocked_at, blocked_until = excluded.blocked_until
WHERE blocked_subjects.blocked_until <> '' AND blocked_subjects.blocked_until <= ?`,
		b.Subject, b.Reason, b.By, b.At.UTC().Format(timeLayout), formatUntil(b.Until), formatUntil(s.now()))
	if err != nil {
		return false, nil, fmt.Errorf("access/sqlite: block: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, nil, fmt.Errorf("access/sqlite: block: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("access/sqlite: block: %w", err)
	}
	if n != 1 {
		return false, nil, nil
	}
	if existed {
		return true, &old, nil
	}
	return true, nil, nil
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
SELECT subject, reason, blocked_by, blocked_at, blocked_until
FROM blocked_subjects
ORDER BY blocked_at, subject`)
	if err != nil {
		return nil, fmt.Errorf("access/sqlite: list: %w", err)
	}
	defer rows.Close()

	out := []access.Block{}
	for rows.Next() {
		var b access.Block
		var at, until string
		if err := rows.Scan(&b.Subject, &b.Reason, &b.By, &at, &until); err != nil {
			return nil, fmt.Errorf("access/sqlite: list: scan: %w", err)
		}
		b.At, err = time.Parse(timeLayout, at)
		if err != nil {
			return nil, fmt.Errorf("access/sqlite: list: block on %q has an unreadable time %q: %w", b.Subject, at, err)
		}
		if until != "" {
			if b.Until, err = time.Parse(untilLayout, until); err != nil {
				return nil, fmt.Errorf("access/sqlite: list: block on %q has an unreadable end %q: %w", b.Subject, until, err)
			}
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("access/sqlite: list: %w", err)
	}
	return out, nil
}

// Expired returns every block whose end has passed, oldest end first
// (design/adr/0046). Blocked already ignores them; this is for the
// gateway's round, which records each expiry and then removes the row with
// RemoveExpired.
func (s *Store) Expired(ctx context.Context) ([]access.Block, error) {
	all, err := s.Blocks(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []access.Block
	for _, b := range all {
		if !b.ActiveAt(now) {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out, nil
}

// RemoveExpired deletes the expired block on subject, and only the one
// whose end is until: a block placed again since the caller read it (a new
// row, another end) stays. It reports whether a row was removed.
func (s *Store) RemoveExpired(ctx context.Context, subject string, until time.Time) (bool, error) {
	if until.IsZero() {
		return false, errors.New("access/sqlite: remove expired: a block with no end never expires")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM blocked_subjects WHERE subject = ? AND blocked_until = ? AND blocked_until <= ?`,
		subject, formatUntil(until), formatUntil(s.now()))
	if err != nil {
		return false, fmt.Errorf("access/sqlite: remove expired: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("access/sqlite: remove expired: %w", err)
	}
	return n == 1, nil
}
