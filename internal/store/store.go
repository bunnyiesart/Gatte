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
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
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
