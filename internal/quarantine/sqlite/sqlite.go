// Package sqlite is the SQLite adapter for the Tool Quarantine
// component's domain package, internal/quarantine. It is the only place
// SQL for the quarantine lives -- per the ports & adapters split
// (context/05-testabilidade-e-contratos.md), the
// quarantine package itself contains no infrastructure detail.
//
// This adapter deliberately holds no policy. Every state transition is
// computed by the domain (quarantine.NewTool, Tool.Observed, Tool.Approved,
// Tool.Revoked) and merely written here, so the rules that decide whether a
// tool is usable can never diverge between the Go code and an UPDATE
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
	for _, stmt := range definitionsSchema {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("quarantine/sqlite: migrate tool_definitions: %w", err)
		}
	}
	return nil
}

// definitionsSchema is the table of the tool definitions the quarantine
// state refers to, keyed by fingerprint (design/adr/0032 item 1).
//
// Content-addressed: the key is quarantine.Hash of the row, so the same
// definition advertised by two upstreams is one row, and a row whose
// content no longer hashes to its key is detectably edited (Definition
// refuses it). Nothing is keyed by server, because nothing about a
// definition depends on who advertised it -- the quarantined_tools row is
// what ties a (server, tool) to a hash.
//
// Kept while referenced, never rewritten. A row stays for as long as some
// quarantined_tools row names it as approved_hash or observed_hash; when
// the last reference moves on, the adapter deletes it in the same
// transaction (pruneDefinitions). That bounds the table at two rows per
// (server, tool) -- the baseline and the latest observation -- whatever a
// backend rotating its description every interval does, which on a single
// small VM sharing its disk with the audit trail is the point. The
// intermediate definitions are not lost as facts: each transition's hashes
// are on the audit trail.
//
// The triggers say so to anything going through SQL. They are not a
// defence against whoever holds the file (DROP TRIGGER is one statement);
// they stop this code, or a later version of it, from rewriting or
// dropping evidence still in use by mistake. The hash check on read is
// what catches a deliberate edit.
var definitionsSchema = []string{
	`CREATE TABLE IF NOT EXISTS tool_definitions (
	hash          TEXT NOT NULL PRIMARY KEY,
	name          TEXT NOT NULL,
	description   TEXT NOT NULL,
	input_schema  BLOB NOT NULL,
	output_schema BLOB NOT NULL,
	first_seen_at TEXT NOT NULL
)`,
	`CREATE TRIGGER IF NOT EXISTS tool_definitions_no_update
BEFORE UPDATE ON tool_definitions
BEGIN SELECT RAISE(ABORT, 'tool_definitions rows are never rewritten'); END`,
	// The first form of this table refused every DELETE, which left a
	// rotating backend free to fill the disk; it is replaced, not kept.
	`DROP TRIGGER IF EXISTS tool_definitions_no_delete`,
	`CREATE TRIGGER IF NOT EXISTS tool_definitions_no_delete_referenced
BEFORE DELETE ON tool_definitions
WHEN EXISTS (SELECT 1 FROM quarantined_tools
             WHERE approved_hash = OLD.hash OR observed_hash = OLD.hash)
BEGIN SELECT RAISE(ABORT, 'tool_definitions: a definition the quarantine references cannot be deleted'); END`,
}

// pruneDefinitions deletes the candidate definitions no quarantined_tools
// row references any more. Called with the hashes a transition just moved
// away from, inside that transition's transaction, so a definition leaves
// exactly when its last reference does.
func pruneDefinitions(ctx context.Context, q querier, candidates ...string) error {
	const stmt = `
DELETE FROM tool_definitions
WHERE hash = ?
  AND NOT EXISTS (SELECT 1 FROM quarantined_tools
                  WHERE approved_hash = tool_definitions.hash OR observed_hash = tool_definitions.hash)
`
	for _, h := range candidates {
		if h == "" {
			continue
		}
		if _, err := q.ExecContext(ctx, stmt, h); err != nil {
			return fmt.Errorf("prune definition %s: %w", h, err)
		}
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
// The read of the existing row, the write of its successor and the write
// of the definition run in one transaction: two concurrent discovery
// cycles observing the same tool must not interleave into a state neither
// of them computed, and in particular must not let a "changed" verdict be
// overwritten by a concurrent "still approved" one -- or both report the
// same transition. A fingerprint stored with no definition behind it
// would be the pre-ADR-0032 blind spot again, so the two commit together
// or not at all.
func (s *Store) Observe(ctx context.Context, serverName string, t quarantine.ToolIdentity) (quarantine.Observation, error) {
	observedHash := quarantine.Hash(t)
	now := time.Now().UTC()
	fail := func(err error) (quarantine.Observation, error) {
		return quarantine.Observation{}, fmt.Errorf("quarantine/sqlite: observe %q/%q: %w", serverName, t.Name, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded

	if err := keepDefinition(ctx, tx, observedHash, t, now); err != nil {
		return fail(err)
	}

	var obs quarantine.Observation
	prev, err := get(ctx, tx, serverName, t.Name)
	switch {
	case err == nil:
		// Known tool: let the domain decide the next state.
		next, err := prev.Observed(observedHash, now)
		if err != nil {
			return fail(err)
		}
		if err := update(ctx, tx, next); err != nil {
			return fail(err)
		}
		if err := pruneDefinitions(ctx, tx, prev.ObservedHash, prev.ApprovedHash); err != nil {
			return fail(err)
		}
		obs = quarantine.Observation{Tool: next, Event: quarantine.EventOf(prev, next)}

	case errors.Is(err, quarantine.ErrNotFound):
		// First sighting: born pending, never usable until approved.
		next := quarantine.NewTool(serverName, t.Name, observedHash, now)
		if err := insert(ctx, tx, next); err != nil {
			return fail(err)
		}
		obs = quarantine.Observation{Tool: next, Event: quarantine.EventFirstSeen}

	default:
		return fail(err)
	}

	if err := tx.Commit(); err != nil {
		return fail(fmt.Errorf("commit: %w", err))
	}
	return obs, nil
}

// keepDefinition stores t under hash unless a definition is already stored
// there. INSERT OR IGNORE, not an upsert: rows are never rewritten, and a
// row that is already there is by construction the same content.
func keepDefinition(ctx context.Context, q querier, hash string, t quarantine.ToolIdentity, now time.Time) error {
	const stmt = `
INSERT OR IGNORE INTO tool_definitions
	(hash, name, description, input_schema, output_schema, first_seen_at)
VALUES (?, ?, ?, ?, ?, ?)
`
	// Nil and empty hash the same (quarantine.Hash); store both as an
	// empty blob so NOT NULL holds and the read-back hashes identically.
	in, out := t.InputSchema, t.OutputSchema
	if in == nil {
		in = []byte{}
	}
	if out == nil {
		out = []byte{}
	}
	if _, err := q.ExecContext(ctx, stmt, hash, t.Name, t.Description, in, out, now.Format(timeLayout)); err != nil {
		return fmt.Errorf("keep definition: %w", err)
	}
	return nil
}

// Definition implements quarantine.Store.
//
// The row is re-hashed on the way out. The triggers stop an UPDATE made
// through SQL by this code; they do not stop whoever holds the file, and
// the one thing worse than "the approved definition was not kept" is an
// edited text presented as the approved one.
func (s *Store) Definition(ctx context.Context, hash string) (quarantine.ToolIdentity, error) {
	const stmt = `
SELECT name, description, input_schema, output_schema
FROM tool_definitions
WHERE hash = ?
`
	var t quarantine.ToolIdentity
	err := s.db.QueryRowContext(ctx, stmt, hash).Scan(&t.Name, &t.Description, &t.InputSchema, &t.OutputSchema)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return quarantine.ToolIdentity{}, fmt.Errorf("quarantine/sqlite: definition %s: %w", hash, quarantine.ErrDefinitionNotKept)
	case err != nil:
		return quarantine.ToolIdentity{}, fmt.Errorf("quarantine/sqlite: definition %s: %w", hash, err)
	}
	if got := quarantine.Hash(t); got != hash {
		return quarantine.ToolIdentity{}, fmt.Errorf("quarantine/sqlite: definition %s hashes to %s: %w", hash, got, quarantine.ErrDefinitionMismatch)
	}
	return t, nil
}

// Approve implements quarantine.Store.
func (s *Store) Approve(ctx context.Context, serverName, toolName string) (quarantine.Tool, error) {
	return s.approve(ctx, serverName, toolName, func(prev quarantine.Tool, now time.Time) (quarantine.Tool, error) {
		return prev.Approved(now), nil
	})
}

// ApproveFingerprint implements quarantine.Store. The comparison runs on
// the row read inside the write transaction, not on an earlier Get, which
// is the whole point: a check made outside the transaction would only move
// the race, not close it.
func (s *Store) ApproveFingerprint(ctx context.Context, serverName, toolName, reviewedHash string) (quarantine.Tool, error) {
	return s.approve(ctx, serverName, toolName, func(prev quarantine.Tool, now time.Time) (quarantine.Tool, error) {
		return prev.ApprovedFingerprint(reviewedHash, now)
	})
}

// approve is the shared read-transition-write of Approve and
// ApproveFingerprint; the transition itself is the domain's.
func (s *Store) approve(ctx context.Context, serverName, toolName string, transition func(quarantine.Tool, time.Time) (quarantine.Tool, error)) (quarantine.Tool, error) {
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

	next, err := transition(prev, now)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: %w", serverName, toolName, err)
	}
	if err := update(ctx, tx, next); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: %w", serverName, toolName, err)
	}
	if err := pruneDefinitions(ctx, tx, prev.ApprovedHash, prev.ObservedHash); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: %w", serverName, toolName, err)
	}
	if err := tx.Commit(); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: approve %q/%q: commit: %w", serverName, toolName, err)
	}
	return next, nil
}

// ApproveReviewSet implements quarantine.Store.
//
// The set is read, compared with manifest and written in one transaction,
// for the reason ApproveFingerprint compares inside its own: a discovery
// cycle committing between a read here and the writes would otherwise get
// a definition nobody was shown baselined along with the rest. SQLite
// serialises writers, so an Observe either lands before this transaction's
// read -- and the manifest no longer matches -- or after its commit, and
// then observes approved tools the ordinary way.
func (s *Store) ApproveReviewSet(ctx context.Context, serverName, manifest string) ([]quarantine.Approval, error) {
	fail := func(err error) ([]quarantine.Approval, error) {
		return nil, fmt.Errorf("quarantine/sqlite: approve review set of %q: %w", serverName, err)
	}
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded

	tools, err := list(ctx, tx, serverName)
	if err != nil {
		return fail(err)
	}
	approvals, err := quarantine.ApprovedSet(serverName, tools, manifest, now)
	if err != nil {
		return fail(err)
	}
	for _, a := range approvals {
		if err := update(ctx, tx, a.After); err != nil {
			return fail(err)
		}
		if err := pruneDefinitions(ctx, tx, a.Before.ApprovedHash, a.Before.ObservedHash); err != nil {
			return fail(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fail(fmt.Errorf("commit: %w", err))
	}
	return approvals, nil
}

// Revoke implements quarantine.Store.
//
// Read and write share one transaction for the same reason Observe's do: a
// discovery cycle running concurrently must not compute its next state from
// a row this method is about to replace, which would let an observation
// write back the approval a human just withdrew.
//
// The refusal of a changed tool is the domain's (Tool.Revoked), not this
// adapter's. Nothing here decides anything about status -- if it did, there
// would be two implementations of the rule and one of them would be in SQL.
func (s *Store) Revoke(ctx context.Context, serverName, toolName string) (quarantine.Tool, error) {
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: revoke %q/%q: %w", serverName, toolName, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded

	prev, err := get(ctx, tx, serverName, toolName)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: revoke %q/%q: %w", serverName, toolName, err)
	}

	next, err := prev.Revoked(now)
	if err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: revoke %q/%q: %w", serverName, toolName, err)
	}
	if err := update(ctx, tx, next); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: revoke %q/%q: %w", serverName, toolName, err)
	}
	if err := pruneDefinitions(ctx, tx, prev.ApprovedHash, prev.ObservedHash); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: revoke %q/%q: %w", serverName, toolName, err)
	}
	if err := tx.Commit(); err != nil {
		return quarantine.Tool{}, fmt.Errorf("quarantine/sqlite: revoke %q/%q: commit: %w", serverName, toolName, err)
	}
	return next, nil
}

// Forget implements quarantine.Store.
//
// No schema change was needed for this, or for Revoke, beyond the
// definitions table: both work the quarantined_tools table -- a DELETE by
// server_name and an UPDATE the domain computed.
//
// The definitions only this server referenced leave with its rows, in the
// same transaction; one another upstream still references stays. This is
// also the operator's way to reclaim what an upstream that invents new
// tool names every interval has accumulated: `upstream deregister` ends in
// here.
func (s *Store) Forget(ctx context.Context, serverName string) (int, error) {
	fail := func(err error) (int, error) {
		return 0, fmt.Errorf("quarantine/sqlite: forget %q: %w", serverName, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeded

	res, err := tx.ExecContext(ctx, `DELETE FROM quarantined_tools WHERE server_name = ?`, serverName)
	if err != nil {
		return fail(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fail(fmt.Errorf("counting removed entries: %w", err))
	}
	const orphans = `
DELETE FROM tool_definitions
WHERE NOT EXISTS (SELECT 1 FROM quarantined_tools
                  WHERE approved_hash = tool_definitions.hash OR observed_hash = tool_definitions.hash)
`
	if _, err := tx.ExecContext(ctx, orphans); err != nil {
		return fail(fmt.Errorf("prune definitions: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return fail(fmt.Errorf("commit: %w", err))
	}
	return int(n), nil
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
	tools, err := list(ctx, s.db, serverName)
	if err != nil {
		return nil, fmt.Errorf("quarantine/sqlite: list: %w", err)
	}
	return tools, nil
}

// lister is satisfied by both *sql.DB and *sql.Tx.
type lister interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// list reads the entries of serverName, or of every server when it is
// empty, ordered by server then tool name.
func list(ctx context.Context, q lister, serverName string) ([]quarantine.Tool, error) {
	// An empty serverName means "every server". The predicate is written
	// as a parameterized OR rather than by building two query strings so
	// there is only one SELECT to keep in sync.
	const stmt = `
SELECT server_name, tool_name, status, approved_hash, observed_hash, first_seen_at, updated_at
FROM quarantined_tools
WHERE ? = '' OR server_name = ?
ORDER BY server_name, tool_name
`
	rows, err := q.QueryContext(ctx, stmt, serverName, serverName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tools := []quarantine.Tool{}
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
