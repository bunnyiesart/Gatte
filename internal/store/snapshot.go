package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Snapshot writes a consistent copy of db to dst, which must not exist
// (design/adr/0045 item 2).
//
// It is VACUUM INTO, which reads the whole database inside one read
// transaction: under WAL a running `serve` keeps writing while it runs, and
// the copy is the database as of the moment the transaction began, every
// committed row before it and none after. The copy is a single file,
// rollback-journal mode, compacted; nothing about it depends on the -wal
// and -shm files beside the source. A plain file copy of a WAL database
// taken while it is written has none of those properties.
func Snapshot(ctx context.Context, db *sql.DB, dst string) error {
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return fmt.Errorf("store: snapshot into %s: %w", dst, err)
	}
	return nil
}

// IntegrityCheck runs PRAGMA integrity_check and returns the problems it
// reports, or nil when SQLite answers "ok". A non-nil error means the check
// could not run at all, which a caller treats as a failed check too.
func IntegrityCheck(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return nil, fmt.Errorf("store: integrity check: %w", err)
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, fmt.Errorf("store: integrity check: %w", err)
		}
		if strings.TrimSpace(line) != "ok" {
			problems = append(problems, line)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: integrity check: %w", err)
	}
	return problems, nil
}

// OpenReadOnly opens path for reading only, for the commands that inspect
// a database and must not change it (mcp-gateway check). No migration may
// run on the connection it returns, and SQLite refuses any write on it.
func OpenReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	return db, nil
}
