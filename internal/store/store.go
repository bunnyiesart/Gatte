// Package store owns the single embedded SQLite connection shared by every
// adapter that needs one -- Upstream Registry, Audit Trail, Tool
// Quarantine, and entry signatures (design/adr/0001, "one embedded SQLite
// ... never for secrets"). It knows nothing about what any table holds;
// each adapter package migrates and queries its own tables through this
// *sql.DB, and cmd/mcp-gateway runs all four migrations together at
// startup so a missing table surfaces there rather than mid-request.
//
// One thing deliberately does not live here: the public keys that entry
// signatures are checked against. A trust anchor stored in the same file
// as what it authenticates is not an anchor -- whoever can rewrite a
// signature row can rewrite the key beside it -- so those live in the
// configuration file instead. See design/adr/0010-signature-trust-anchor.md.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open returns a ready-to-use SQLite connection at path. Pass ":memory:" for
// tests. Foreign keys and WAL mode are enabled because the default SQLite
// config leaves both off, and a multi-table registry/audit schema wants
// referential integrity enforced, not assumed.
//
// For ":memory:", the pool is pinned to a single connection. This is not a
// tuning choice, it is a correctness one: SQLite gives every *connection*
// to ":memory:" its own private, empty database, so the moment
// database/sql opens a second pooled connection, that connection sees no
// tables at all. Verified directly -- a second conn on an unpinned pool
// fails with "no such table" against a table the first one created.
//
// Without the pin, every test in this repository using an in-memory store
// is silently relying on the pool never growing past one connection, and
// would start failing nondeterministically the moment anything ran
// queries concurrently. `file::memory:?cache=shared` is the usual
// alternative and is deliberately not used: it shares one database across
// the whole process, so two independent Open(":memory:") calls would
// collide with each other, trading this bug for a worse one in tests.
// # Why the pragmas are in the DSN and not Exec'd
//
// A PRAGMA is per-CONNECTION, and database/sql hands out a pool. Setting
// one with db.Exec configures whichever connection happened to serve that
// call and leaves every connection the pool opens later on the SQLite
// defaults -- so the setting appears to be on, and silently is not for
// most of the process's work.
//
// That was not theoretical here: foreign_keys was Exec'd, which means
// referential integrity was enforced on one connection out of however many
// the pool grew to. It surfaced while adding busy_timeout for the audit
// chain's serialised append (ADR-0015 item 3), whose concurrency test kept
// failing with SQLITE_BUSY against a timeout that was, on that connection,
// never set. modernc.org/sqlite applies `_pragma=` DSN parameters to every
// connection it opens, which is the only form that means what it says.
func Open(path string) (*sql.DB, error) {
	dsn := path
	if path != ":memory:" {
		// busy_timeout: without it SQLite answers a contended write lock
		// by returning SQLITE_BUSY at once rather than waiting, and the
		// second writer simply loses its write. WAL narrows that window --
		// readers stop blocking writers -- but writers still exclude each
		// other. Five seconds is a ceiling on waiting, not a target.
		dsn = "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
		// Safe as an Exec only because the pool is pinned to exactly one
		// connection above; on any other path this would be the bug
		// described here.
		if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: enable foreign_keys: %w", err)
		}
	}
	return db, nil
}
