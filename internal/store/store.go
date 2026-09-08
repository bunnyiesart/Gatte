// Package store owns the single embedded SQLite connection shared by every
// adapter that needs one (Upstream Registry, Audit Trail, and later Tool
// Quarantine -- design/adr/0001, "one embedded SQLite ... never for
// secrets"). It knows nothing about what any table holds; each adapter
// package migrates and queries its own tables through this *sql.DB.
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
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: enable foreign_keys: %w", err)
	}
	if path != ":memory:" {
		if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: enable WAL: %w", err)
		}
	}
	return db, nil
}
