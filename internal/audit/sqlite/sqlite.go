// Package sqlite is the SQLite adapter for the Audit Trail component's
// domain package, internal/audit. It is the only place SQL for the audit
// trail lives -- per the ports & adapters split
// (context/05-testabilidade-e-contratos.md), the audit
// package itself contains no infrastructure detail.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
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
	source_address   TEXT NOT NULL DEFAULT '',
	analyst_name     TEXT NOT NULL DEFAULT ''
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
		// design/adr/0037. '' is also what every existing row's hash was
		// computed over: an unnamed record encodes as chain v1, so rows
		// migrated in keep verifying without being touched.
		`ALTER TABLE audit_records ADD COLUMN analyst_name TEXT NOT NULL DEFAULT ''`,
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
	// ONLY rows that have no hash yet. A row that already carries one is
	// never re-hashed, and that restriction is load-bearing rather than an
	// optimisation.
	//
	// The guard above -- "the meta row exists, so the backfill already
	// ran" -- is one DELETE away from being false, and the same actor this
	// whole ADR is about can issue it. Without this WHERE clause, dropping
	// that single row made the next start re-chain the WHOLE table over
	// whatever it currently held: edit a record, delete one row from a
	// second table, restart, and the gateway itself signs the edited
	// trail, having required the attacker to compute no hashes at all. It
	// also overwrote the retroactive boundary, erasing the disclosure that
	// exists so an intact result cannot be read as "authentic since
	// written".
	//
	// Reproduced in TestMigrate_DeletingChainMetaDoesNotResignATamperedTrail.
	cur, err := tx.Query(`
SELECT id, analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, analyst_name
FROM audit_records WHERE hash = '' ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("audit/sqlite: migrate: scan for backfill: %w", err)
	}
	for cur.Next() {
		var r row
		var ts, outcome string
		if err := cur.Scan(&r.id, &r.rec.AnalystIdentity, &r.rec.Tool, &r.rec.TargetUpstream,
			&ts, &outcome, &r.rec.Reason, &r.rec.SourceAddress, &r.rec.AnalystName); err != nil {
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

	// Unhashed rows chain onto whatever the existing tail already is, not
	// onto genesis: on a database that has been chained before, the rows
	// selected above sit after it, and restarting the chain from empty
	// would fork it.
	prev := audit.GenesisHash
	if err := tx.QueryRow(
		`SELECT hash FROM audit_records WHERE hash != '' ORDER BY id DESC LIMIT 1`,
	).Scan(&prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit/sqlite: migrate: read chain head for backfill: %w", err)
	}

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

// Record implements audit.Recorder. It is RecordChained with the link
// dropped, so there is exactly one insert path and no chance of the two
// drifting into different transaction shapes.
func (r *Recorder) Record(ctx context.Context, rec audit.Record) error {
	_, err := r.RecordChained(ctx, rec)
	return err
}

var _ audit.ChainedRecorder = (*Recorder)(nil)

// RecordChained implements audit.ChainedRecorder.
//
// Reading the chain head and appending happen inside one BEGIN IMMEDIATE
// transaction (design/adr/0015-audit-tamper-evidence.md, item 3). Two
// concurrent writers that each read the same head would produce a fork --
// two records naming the same predecessor -- and verification would then
// report a break in a database nobody tampered with. IMMEDIATE rather than
// a plain BEGIN because the deferred form takes the write lock only at the
// INSERT, which is a lock upgrade, and SQLite answers a contended upgrade
// with SQLITE_BUSY instead of waiting.
//
// The returned link is the pair actually written in that transaction, read
// from the same variables the INSERT used rather than recomputed
// afterwards: a second computation outside the transaction would race the
// next writer and could report a predecessor this row does not have.
//
// On any error the zero ChainLink is returned. See the port's doc for why
// that must not be read as "first record in the chain".
func (r *Recorder) RecordChained(ctx context.Context, rec audit.Record) (audit.ChainLink, error) {
	if err := rec.Validate(); err != nil {
		return audit.ChainLink{}, err
	}

	conn, err := r.db.Conn(ctx)
	if err != nil {
		return audit.ChainLink{}, fmt.Errorf("audit/sqlite: record: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return audit.ChainLink{}, fmt.Errorf("audit/sqlite: record: begin: %w", err)
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
		return audit.ChainLink{}, fmt.Errorf("audit/sqlite: record: read chain head: %w", err)
	}

	link := audit.ChainLink{Prev: prev, Hash: audit.ChainHash(prev, rec)}

	const stmt = `
INSERT INTO audit_records (analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, analyst_name, prev_hash, hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`
	if _, err := conn.ExecContext(ctx, stmt,
		rec.AnalystIdentity, rec.Tool, rec.TargetUpstream, rec.Timestamp.Format(timeLayout),
		string(rec.Outcome), rec.Reason, rec.SourceAddress, rec.AnalystName,
		link.Prev, link.Hash); err != nil {
		return audit.ChainLink{}, fmt.Errorf("audit/sqlite: record: %w", err)
	}

	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return audit.ChainLink{}, fmt.Errorf("audit/sqlite: record: commit: %w", err)
	}
	committed = true
	return link, nil
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
SELECT id, analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, analyst_name, prev_hash, hash
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
			&ts, &outcome, &rec.Reason, &rec.SourceAddress, &rec.AnalystName, &storedPrev, &storedHash); err != nil {
			return audit.ChainCheck{}, fmt.Errorf("audit/sqlite: verify: scan: %w", err)
		}
		rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			// A row whose timestamp will not parse is a row that has been
			// damaged -- which is the thing this function exists to
			// report, not a reason to stop reporting. Returning an error
			// here made ONE bad row turn the whole trail unreadable, and
			// handed an attacker a cheaper move than re-chaining: corrupt
			// a single timestamp and `audit -verify` answers with an error
			// instead of with the trail.
			//
			// It is recorded as the first break and the walk stops, because
			// nothing after it can be chained to something unreadable.
			if check.FirstBreak == nil {
				rec.Timestamp = time.Time{}
				check.FirstBreak = &audit.ChainBreak{
					Position: check.Count + 1,
					Record:   rec,
					Want:     "unreadable: " + err.Error(),
					Got:      storedHash,
				}
			}
			check.Count++
			check.Head = storedHash
			return check, nil
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
//
// The chronological order audit.Recorder promises is established here, in
// Go, on the parsed instants -- not by SQL on the stored text. `ORDER BY
// timestamp` compared RFC3339Nano strings byte by byte, and that is not
// time order: trailing zeros are dropped, and '.' sorts before 'Z', so on a
// UTC host "03:00:00.5Z" came back before "03:00:00Z"; and rows written
// under different zone offsets sorted by wall-clock text rather than by
// instant. `mcp-gateway audit -limit N` takes the newest N from the end of
// this list, so it could show the wrong rows during an incident. Sorting
// after parsing fixes rows already on disk too, which re-encoding new rows
// would not. Rows are read in insertion (id) order and the sort is stable,
// so id still breaks ties between equal instants.
//
// Only this presentation order changes. The hash chain is built (the
// head is the highest id) and verified (VerifyChain) in id order, which
// this does not touch.
func (r *Recorder) List(ctx context.Context) ([]audit.Record, error) {
	records, err := r.ChainOrder(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(records, func(a, b audit.Record) int { return a.Timestamp.Compare(b.Timestamp) })
	return records, nil
}

// ChainOrder returns every record in insertion (id) order, the order the
// chain is built and verified in: the record at index i is at chain
// position i+1, the position VerifyChain reports. The management API pages
// the trail by that position (design/adr/0040), because it is stable --
// the trail is append-only -- where a timestamp is the caller's clock.
func (r *Recorder) ChainOrder(ctx context.Context) ([]audit.Record, error) {
	const stmt = `
SELECT analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, analyst_name
FROM audit_records
ORDER BY id ASC
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
		if err := rows.Scan(&rec.AnalystIdentity, &rec.Tool, &rec.TargetUpstream, &ts, &outcome, &rec.Reason, &rec.SourceAddress, &rec.AnalystName); err != nil {
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

// Page returns the newest q.Limit records matching q, newest first, each
// with its chain position, and whether more match further back. It reads
// row by row and keeps only the page (design/adr/0040): the trail gets a
// row per MCP call, and a management request must not hold all of them.
//
// A trail whose ids run 1..COUNT, which is every trail no one deleted
// from, has position = id, and the filters and the Before bound go to the
// database. A trail with a gap (a deleted row, which VerifyChain reports)
// is walked newest first from COUNT down, so positions stay those
// VerifyChain names. Since and Until are compared in Go on the parsed
// instant, for the reason List gives. Both reads run in one transaction, so a row
// appended meanwhile cannot shift the positions.
func (r *Recorder) Page(ctx context.Context, q audit.TrailQuery) ([]audit.PositionedRecord, bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("audit/sqlite: page: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var count, maxID int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(id), 0) FROM audit_records`).Scan(&count, &maxID); err != nil {
		return nil, false, fmt.Errorf("audit/sqlite: page: %w", err)
	}
	contiguous := count == maxID
	var where []string
	var args []any
	if contiguous {
		if q.Before > 0 {
			where, args = append(where, "id < ?"), append(args, q.Before)
		}
		for _, f := range []struct{ col, v string }{{"analyst_identity", q.Subject}, {"outcome", q.Outcome}, {"source_address", q.Source},
			{"tool", q.Tool}, {"target_upstream", q.Server}} {
			if f.v != "" {
				where, args = append(where, f.col+" = ?"), append(args, f.v)
			}
		}
	}
	stmt := `SELECT id, analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, analyst_name FROM audit_records`
	if len(where) > 0 {
		stmt += " WHERE " + strings.Join(where, " AND ")
	}
	stmt += " ORDER BY id DESC"
	rows, err := tx.QueryContext(ctx, stmt, args...)
	if err != nil {
		return nil, false, fmt.Errorf("audit/sqlite: page: %w", err)
	}
	defer rows.Close()
	out := []audit.PositionedRecord{}
	pos := int(count) + 1
	for rows.Next() {
		var id int64
		var rec audit.Record
		var ts, outcome string
		if err := rows.Scan(&id, &rec.AnalystIdentity, &rec.Tool, &rec.TargetUpstream, &ts, &outcome, &rec.Reason, &rec.SourceAddress, &rec.AnalystName); err != nil {
			return nil, false, fmt.Errorf("audit/sqlite: page: scan: %w", err)
		}
		rec.Outcome = audit.Outcome(outcome)
		p := int(id)
		if !contiguous {
			pos--
			p = pos
			if q.Before > 0 && p >= q.Before ||
				q.Subject != "" && rec.AnalystIdentity != q.Subject ||
				q.Outcome != "" && outcome != q.Outcome ||
				q.Source != "" && rec.SourceAddress != q.Source ||
				q.Tool != "" && rec.Tool != q.Tool ||
				q.Server != "" && rec.TargetUpstream != q.Server {
				continue
			}
		}
		rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			return nil, false, fmt.Errorf("audit/sqlite: page: parse timestamp: %w", err)
		}
		if !q.Since.IsZero() && rec.Timestamp.Before(q.Since) || !q.Until.IsZero() && !rec.Timestamp.Before(q.Until) {
			continue
		}
		if len(out) == q.Limit {
			return out, true, nil
		}
		out = append(out, audit.PositionedRecord{Position: p, Record: rec})
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("audit/sqlite: page: %w", err)
	}
	return out, false, nil
}

// Analysts summarises, in the database, every identity on the trail that
// is a person's: not empty and not in parentheses ("(gateway)",
// "(operator:x)", "(unauthenticated)"). LastCall is the timestamp of the
// identity's newest row, and Name the newest non-empty name it was
// written with. Memory is one entry per identity, not per row.
func (r *Recorder) Analysts(ctx context.Context) ([]audit.AnalystSeen, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: analysts: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	const person = `analyst_identity <> '' AND substr(analyst_identity, 1, 1) <> '('`
	// SQLite gives a bare column of a MAX() aggregate the value of the row
	// that holds the maximum: timestamp and analyst_name below are the
	// newest row's.
	rows, err := tx.QueryContext(ctx, `SELECT analyst_identity, COUNT(*), MAX(id), timestamp FROM audit_records WHERE `+person+` GROUP BY analyst_identity`)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: analysts: %w", err)
	}
	var out []audit.AnalystSeen
	index := map[string]int{}
	for rows.Next() {
		var a audit.AnalystSeen
		var maxID int64
		var ts string
		if err := rows.Scan(&a.Identity, &a.Calls, &maxID, &ts); err != nil {
			rows.Close()
			return nil, fmt.Errorf("audit/sqlite: analysts: scan: %w", err)
		}
		if a.LastCall, err = time.Parse(timeLayout, ts); err != nil {
			rows.Close()
			return nil, fmt.Errorf("audit/sqlite: analysts: parse timestamp: %w", err)
		}
		index[a.Identity] = len(out)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("audit/sqlite: analysts: %w", err)
	}
	rows.Close()
	names, err := tx.QueryContext(ctx, `SELECT analyst_identity, MAX(id), analyst_name FROM audit_records WHERE `+person+` AND analyst_name <> '' GROUP BY analyst_identity`)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: analysts: %w", err)
	}
	defer names.Close()
	for names.Next() {
		var id, name string
		var maxID int64
		if err := names.Scan(&id, &maxID, &name); err != nil {
			return nil, fmt.Errorf("audit/sqlite: analysts: scan: %w", err)
		}
		if i, ok := index[id]; ok {
			out[i].Name = name
		}
	}
	if err := names.Err(); err != nil {
		return nil, fmt.Errorf("audit/sqlite: analysts: %w", err)
	}
	return out, nil
}

// HasAnalyst reports whether any record on the trail carries identity as
// its ANALYST. The Operator Console asks it after `access block`, so a
// subject with a typo in it -- which would block nobody, since matching is
// exact -- is flagged to the operator (design/adr/0031 §4). A console
// question, not a request-path one: it scans the table.
func (r *Recorder) HasAnalyst(ctx context.Context, identity string) (bool, error) {
	var one int
	err := r.db.QueryRowContext(ctx, `SELECT 1 FROM audit_records WHERE analyst_identity = ? LIMIT 1`, identity).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("audit/sqlite: has analyst: %w", err)
	}
	return true, nil
}
