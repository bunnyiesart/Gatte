// Package sqlite is the SQLite adapter for the Audit Trail component's
// domain package, internal/audit. It is the only place SQL for the audit
// trail lives -- per the ports & adapters split
// (docs/context/05-testabilidade-e-contratos.md), the audit
// package itself contains no infrastructure detail.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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
	timestamp        TEXT NOT NULL,
	outcome          TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT '',
	source_address   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_records_timestamp
	ON audit_records (timestamp);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("audit/sqlite: migrate: %w", err)
	}

	// outcome, reason and source_address were each added after the table
	// already existed in working databases, so CREATE TABLE IF NOT EXISTS
	// alone would leave those without the columns. SQLite has no ADD
	// COLUMN IF NOT EXISTS, and re-adding an existing column is an error
	// rather than a no-op, so each is attempted and a "duplicate column"
	// response treated as success. The DEFAULT '' matters: rows written
	// before a migration genuinely have nothing to say for the new column
	// -- they predate the gateway's dispatch path, or predate its knowing
	// where a call came from -- and an empty string says that honestly
	// rather than claiming they were allowed, or claiming an address.
	//
	// This list only ever grows, and never in place: reordering or
	// rewriting an entry would change what a database that has already
	// run part of it ends up with. Append.
	for _, col := range []string{
		`ALTER TABLE audit_records ADD COLUMN outcome TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_records ADD COLUMN reason TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_records ADD COLUMN source_address TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_records ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE audit_records ADD COLUMN hash TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(col); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("audit/sqlite: migrate: %w", err)
		}
	}

	const metaStmt = `
CREATE TABLE IF NOT EXISTS audit_chain_meta (
	id                      INTEGER PRIMARY KEY CHECK (id = 1),
	retroactive_boundary_id INTEGER NOT NULL
);
`
	if _, err := db.Exec(metaStmt); err != nil {
		return fmt.Errorf("audit/sqlite: migrate: %w", err)
	}
	return backfillChain(db)
}

// backfillChain hashes rows that predate the chain, in id order, and
// records where that backfill stopped
// (design/adr/0015-audit-tamper-evidence.md, item 4).
//
// It runs once: the presence of the meta row is what says it already ran,
// so a second call is a no-op even though rows keep being appended. On a
// fresh database it writes boundary 0 -- nothing was retroactive -- which
// is what makes "has this database ever been backfilled" answerable
// without guessing from row contents.
//
// The backfill produces a chain that verifies. It does NOT make the rows
// it covers trustworthy: if one was already altered, this signs the
// altered version without complaint. That is exactly why the boundary is
// stored rather than discarded -- so VerifyChain can say how much of an
// intact result rests on it.
func backfillChain(db *sql.DB) error {
	var boundary int64
	err := db.QueryRow(`SELECT retroactive_boundary_id FROM audit_chain_meta WHERE id = 1`).Scan(&boundary)
	if err == nil {
		return nil // already backfilled
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit/sqlite: migrate: read chain meta: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("audit/sqlite: migrate: begin backfill: %w", err)
	}
	defer tx.Rollback()

	type row struct {
		id  int64
		rec audit.Record
	}
	var rows []row
	cur, err := tx.Query(`
SELECT id, analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address
FROM audit_records ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("audit/sqlite: migrate: scan for backfill: %w", err)
	}
	for cur.Next() {
		var r row
		var ts, outcome string
		if err := cur.Scan(&r.id, &r.rec.AnalystIdentity, &r.rec.Tool, &r.rec.TargetUpstream,
			&ts, &outcome, &r.rec.Reason, &r.rec.SourceAddress); err != nil {
			cur.Close()
			return fmt.Errorf("audit/sqlite: migrate: scan for backfill: %w", err)
		}
		r.rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			cur.Close()
			return fmt.Errorf("audit/sqlite: migrate: parse timestamp for backfill: %w", err)
		}
		r.rec.Outcome = audit.Outcome(outcome)
		rows = append(rows, r)
	}
	if err := cur.Err(); err != nil {
		cur.Close()
		return fmt.Errorf("audit/sqlite: migrate: scan for backfill: %w", err)
	}
	cur.Close()

	prev := audit.GenesisHash
	var last int64
	for _, r := range rows {
		h := audit.ChainHash(prev, r.rec)
		if _, err := tx.Exec(`UPDATE audit_records SET prev_hash = ?, hash = ? WHERE id = ?`, prev, h, r.id); err != nil {
			return fmt.Errorf("audit/sqlite: migrate: backfill: %w", err)
		}
		prev = h
		last = r.id
	}
	if _, err := tx.Exec(`INSERT INTO audit_chain_meta (id, retroactive_boundary_id) VALUES (1, ?)`, last); err != nil {
		return fmt.Errorf("audit/sqlite: migrate: record chain boundary: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit/sqlite: migrate: commit backfill: %w", err)
	}
	return nil
}

// isDuplicateColumn reports whether err is SQLite complaining that a
// column being added already exists. modernc.org/sqlite does not expose a
// typed error for this, so the check is on the message -- the same
// approach the registry adapter takes for UNIQUE violations.
func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
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
//
// Reading the chain head and appending happen inside one BEGIN IMMEDIATE
// transaction (design/adr/0015-audit-tamper-evidence.md, item 3). Two
// concurrent writers that each read the same head would produce a fork --
// two records naming the same predecessor -- and verification would then
// report a break in a database nobody tampered with. IMMEDIATE rather than
// a plain BEGIN because the deferred form takes the write lock only at the
// INSERT, which is a lock upgrade, and SQLite answers a contended upgrade
// with SQLITE_BUSY instead of waiting.
func (r *Recorder) Record(ctx context.Context, rec audit.Record) error {
	if err := rec.Validate(); err != nil {
		return err
	}

	conn, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("audit/sqlite: record: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("audit/sqlite: record: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			// Best effort: the connection is about to be returned to the
			// pool, and leaving a transaction open on it would poison the
			// next caller.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`)
		}
	}()

	var prev string
	err = conn.QueryRowContext(ctx, `SELECT hash FROM audit_records ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if errors.Is(err, sql.ErrNoRows) {
		prev = audit.GenesisHash
	} else if err != nil {
		return fmt.Errorf("audit/sqlite: record: read chain head: %w", err)
	}

	const stmt = `
INSERT INTO audit_records (analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`
	if _, err := conn.ExecContext(ctx, stmt,
		rec.AnalystIdentity, rec.Tool, rec.TargetUpstream, rec.Timestamp.Format(timeLayout),
		string(rec.Outcome), rec.Reason, rec.SourceAddress,
		prev, audit.ChainHash(prev, rec)); err != nil {
		return fmt.Errorf("audit/sqlite: record: %w", err)
	}

	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("audit/sqlite: record: commit: %w", err)
	}
	committed = true
	return nil
}

var _ audit.ChainVerifier = (*Recorder)(nil)

// VerifyChain implements audit.ChainVerifier.
//
// The walk is in id order, not timestamp order: id is the insertion order
// the chain was built in, and timestamps both tie and come from the
// caller (ADR-0015 item 2). List orders by timestamp because that is what
// an operator reads; this deliberately does not.
//
// After a mismatch the walk continues from the hash stored on disk rather
// than the recomputed one, so a single edited row is reported once instead
// of making every row after it look broken too.
func (r *Recorder) VerifyChain(ctx context.Context) (audit.ChainCheck, error) {
	var boundary int64
	err := r.db.QueryRowContext(ctx, `SELECT retroactive_boundary_id FROM audit_chain_meta WHERE id = 1`).Scan(&boundary)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return audit.ChainCheck{}, fmt.Errorf("audit/sqlite: verify: read chain meta: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT id, analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, prev_hash, hash
FROM audit_records ORDER BY id ASC`)
	if err != nil {
		return audit.ChainCheck{}, fmt.Errorf("audit/sqlite: verify: %w", err)
	}
	defer rows.Close()

	check := audit.ChainCheck{Head: audit.GenesisHash}
	prev := audit.GenesisHash
	for rows.Next() {
		var id int64
		var rec audit.Record
		var ts, outcome, storedPrev, storedHash string
		if err := rows.Scan(&id, &rec.AnalystIdentity, &rec.Tool, &rec.TargetUpstream,
			&ts, &outcome, &rec.Reason, &rec.SourceAddress, &storedPrev, &storedHash); err != nil {
			return audit.ChainCheck{}, fmt.Errorf("audit/sqlite: verify: scan: %w", err)
		}
		rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			return audit.ChainCheck{}, fmt.Errorf("audit/sqlite: verify: parse timestamp: %w", err)
		}
		rec.Outcome = audit.Outcome(outcome)

		check.Count++
		if id <= boundary {
			check.RetroactivelyChained++
		}

		// Two independent ways to be wrong, and they catch different
		// things: a link that no longer points at the record before it is
		// a DELETION in the middle, while a hash that does not match the
		// record's own fields is an EDIT.
		want := audit.ChainHash(storedPrev, rec)
		if check.FirstBreak == nil && (storedPrev != prev || storedHash != want) {
			broken := rec
			check.FirstBreak = &audit.ChainBreak{
				Position: check.Count,
				Record:   broken,
				Want:     audit.ChainHash(prev, rec),
				Got:      storedHash,
			}
		}
		prev = storedHash
	}
	if err := rows.Err(); err != nil {
		return audit.ChainCheck{}, fmt.Errorf("audit/sqlite: verify: %w", err)
	}
	check.Head = prev
	return check, nil
}

// List implements audit.Recorder.
func (r *Recorder) List(ctx context.Context) ([]audit.Record, error) {
	const stmt = `
SELECT analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address
FROM audit_records
ORDER BY timestamp ASC, id ASC
`
	rows, err := r.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: list: %w", err)
	}
	defer rows.Close()

	records := []audit.Record{}
	for rows.Next() {
		var rec audit.Record
		var ts, outcome string
		if err := rows.Scan(&rec.AnalystIdentity, &rec.Tool, &rec.TargetUpstream, &ts, &outcome, &rec.Reason, &rec.SourceAddress); err != nil {
			return nil, fmt.Errorf("audit/sqlite: list: scan: %w", err)
		}
		rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			return nil, fmt.Errorf("audit/sqlite: list: parse timestamp: %w", err)
		}
		rec.Outcome = audit.Outcome(outcome)
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit/sqlite: list: %w", err)
	}
	return records, nil
}
