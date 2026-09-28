// Package sqlite is the SQLite adapter for the per-analyst quota
// component's domain package, internal/quota. It is the only place SQL for
// the quota lives -- per the ports & adapters split
// (context/05-testabilidade-e-contratos.md), the quota
// package itself contains no infrastructure detail.
//
// This adapter holds no policy, in the same sense the quarantine adapter
// holds none. What a call costs, which window it falls in and whether a
// limit has been passed are all decided by pure functions in the domain
// (quota.Plan.Charges, quota.Provider.WindowStart, quota.Charge.Fits);
// this file only applies the debit atomically and asks the domain about
// the result. In particular the comparison against the limit is NOT in a
// WHERE clause, so there is no second implementation of "is it exhausted"
// to drift away from the first.
//
// # The schema has nowhere to put a limit, deliberately
//
// A counter row is (analyst, provider, window, used) and nothing else. The
// limit arrives with each Charge, from the operator's reviewed TOML, and
// is never written here. That is ADR-0009 §2's split made structural: a
// limit in this table would be policy widened by an UPDATE, with no diff,
// no review and no history beyond the database file -- which is precisely
// the arrangement that ADR rejected for roles.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quota"
)

// timeLayout is the on-disk representation of a window start: RFC3339 with
// nanosecond precision, the same layout the audit trail and the quarantine
// use, so an operator reading the file by hand sees one date format.
//
// The window start is part of the row's identity, so its *spelling*
// matters and not only the instant it denotes: 2026-09-14T00:00:00Z and
// 2026-09-13T21:00:00-03:00 are one instant and two primary keys, and two
// primary keys are two allowances. quota.Charge.Validate refuses any
// window start carrying a non-zero offset, which is what makes formatting
// it here unambiguous.
const timeLayout = time.RFC3339Nano

// Migrate creates the quota_counters table if it does not already exist.
// It is idempotent and safe to call on every startup, and must be
// registered in the composition root's migration map beside the other
// four -- a component whose table is missing fails at its first query,
// deep inside a request on the production host, rather than at startup.
//
// The primary key is (analyst, provider, window_start). Per analyst,
// because ADR-0030 decision 4 makes the limit per analyst and not a pool:
// a pooled ceiling would let the first analyst in a loop exhaust everybody,
// which is the defect the component exists to remove. Per provider,
// because the counted unit is an account at a third party, not an upstream
// and not a tool. Per window, because the allowance is periodic -- and
// because keeping each window as its own row means a window that has
// rolled over is not rewritten, only left behind.
//
// There is no ALTER TABLE list below yet. When a column is eventually
// added, it goes in one -- appended, never reordered or rewritten, with a
// DEFAULT and a "duplicate column name" error treated as success -- in the
// shape internal/audit/sqlite and internal/registry/sqlite already use.
//
// Rows accumulate: one per (analyst, account, window) forever. With seven
// analysts, eight accounts and a 24h window that is under twenty thousand
// rows a year, so nothing prunes them. Note what a pruning command would
// be if one were ever written: deleting a *current* window's row hands
// that analyst their allowance back, which is the `quota reset` ADR-0030
// decision 8 refuses on the grounds that returning units to one analyst
// does not create requests at VirusTotal -- it takes them from the rest of
// the team.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS quota_counters (
	analyst      TEXT NOT NULL,
	provider     TEXT NOT NULL,
	window_start TEXT NOT NULL,
	used         INTEGER NOT NULL,
	PRIMARY KEY (analyst, provider, window_start)
);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("quota/sqlite: migrate: %w", err)
	}
	return nil
}

// Store is the SQLite-backed implementation of quota.Store.
type Store struct {
	db *sql.DB
}

// One type satisfies both ports, and that is not the same as one port.
// The Gateway is handed this value as a quota.Store and can therefore only
// reserve; the Operator Console is handed it as a quota.Reader and can
// therefore only read. Which capability a caller has is decided by the
// interface the composition root hands it, and neither interface can be
// widened into the other -- see the two port declarations for why the
// request path must not be able to read a counter.
var (
	_ quota.Store  = (*Store)(nil)
	_ quota.Reader = (*Store)(nil)
)

// New returns a Store that counts through db. db must already have been
// migrated with Migrate.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Reserve implements quota.Store.
//
// # Why the debit comes first and the question second
//
// Each charge is applied with an upsert that increments and returns the
// new value in one statement, and only then is the domain asked whether
// that value still fits. The obvious alternative -- read the counter,
// compare, write it back -- is what this must not be. Dispatch does not
// serialise calls: N goroutines for N analysts call concurrently over one
// session with no queue, no semaphore and no pool, so a read-then-write
// lets N callers all read limit-1 and all pass. Incrementing first makes
// the reservation the same operation as the count.
//
// # All or nothing
//
// Everything runs in one transaction, and the deferred Rollback is what
// makes a refusal cost nothing: the first charge that does not fit returns
// without committing, so the charges already incremented above it are
// discarded. That is the rule for `lookup_ip`, which spends six accounts
// at once -- the gateway cannot ask the upstream for five sixths of a
// fan-out it does not control, so a call with one spent account is refused
// whole and debits none of the others.
//
// # Contention
//
// Because the first statement in the transaction is a write, two
// concurrent reservations do not both read a stale count: the second waits
// for the first, or fails. Failing is a refusal, never a pass. That
// refusal is the same write contention the audit trail already has on the
// same file -- Dispatch writes a row per call three lines later -- so it
// is not a new unavailability mode (ADR-0030 decision 6).
func (s *Store) Reserve(ctx context.Context, r quota.Reservation) error {
	// Refuse a malformed reservation before opening a transaction, and
	// write nothing. The domain classifies this as a refusal, not a pass.
	if err := r.Validate(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("quota/sqlite: reserve: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded, and the discard is the point on every other path

	for _, c := range r.Charges {
		used, err := debit(ctx, tx, r.Analyst, c)
		if err != nil {
			return fmt.Errorf("quota/sqlite: reserve %q: %w", c.Provider, err)
		}
		// The rule itself lives in the domain. This adapter asks; it does
		// not decide, and it never phrases the comparison in SQL.
		if !c.Fits(used) {
			// Deliberately returns without committing: nothing this
			// reservation incremented survives, so a refused call has
			// spent no quota at all.
			return quota.Exhausted(c)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("quota/sqlite: reserve: commit: %w", err)
	}
	return nil
}

// debit increments one counter by one and returns its new value, creating
// the row if this is the window's first call.
//
// INSERT ... ON CONFLICT DO UPDATE ... RETURNING is one statement on
// purpose: the increment and the reading of the result cannot be
// interleaved by another writer, which is the property the whole component
// rests on. Note that the limit appears nowhere in this statement -- see
// the package comment.
func debit(ctx context.Context, tx *sql.Tx, analyst string, c quota.Charge) (int, error) {
	const stmt = `
INSERT INTO quota_counters (analyst, provider, window_start, used)
VALUES (?, ?, ?, 1)
ON CONFLICT (analyst, provider, window_start)
DO UPDATE SET used = used + 1
RETURNING used
`
	var used int
	err := tx.QueryRowContext(ctx, stmt, analyst, c.Provider, c.WindowStart.Format(timeLayout)).Scan(&used)
	if err != nil {
		return 0, err
	}
	return used, nil
}

// Usage implements quota.Reader.
//
// Ordered in SQL rather than in the caller so that the port's promise --
// analyst, then account, then window -- is kept in one place and cannot
// drift between two readers. The ORDER BY is on the primary key's columns,
// so it costs no sort.
//
// A window start that cannot be parsed fails the whole read rather than
// being skipped or zeroed. Every row this component writes formats it with
// timeLayout, so an unparseable one means something other than this
// adapter has written to the table -- which an operator reading consumption
// needs to be told about, not handed a silently shortened list of.
func (s *Store) Usage(ctx context.Context) ([]quota.Usage, error) {
	const stmt = `
SELECT analyst, provider, window_start, used
FROM quota_counters
ORDER BY analyst, provider, window_start
`
	rows, err := s.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("quota/sqlite: usage: %w", err)
	}
	defer rows.Close()

	var out []quota.Usage
	for rows.Next() {
		var (
			u     quota.Usage
			start string
		)
		if err := rows.Scan(&u.Analyst, &u.Provider, &start, &u.Used); err != nil {
			return nil, fmt.Errorf("quota/sqlite: usage: scan: %w", err)
		}
		parsed, err := time.Parse(timeLayout, start)
		if err != nil {
			return nil, fmt.Errorf("quota/sqlite: usage: counter for %q has an unreadable window start %q: %w",
				u.Provider, start, err)
		}
		// Back to UTC on the way out. Charge.Validate refuses any window
		// start carrying an offset, so what was written is already UTC --
		// this keeps a row hand-edited into another offset from reading
		// back as a different-looking window than the one it counts.
		u.WindowStart = parsed.UTC()
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("quota/sqlite: usage: %w", err)
	}
	return out, nil
}
