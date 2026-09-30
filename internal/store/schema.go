package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion is the database schema this binary writes, recorded in
// the file's header as PRAGMA user_version (design/adr/0045 item 3).
//
// Every adapter migrates its own tables additively, so a database written
// by an older binary is brought up to date at the next start. The other
// direction has no such answer: a binary does not know what a newer one
// added, and an older binary writing into a newer file can break it in
// ways no test of the older binary saw. So a binary refuses a file whose
// version is above this number (CheckSchema), and the way back from an
// upgrade is the backup taken before it, not the old binary.
//
// Raise it by one in the same change that alters any adapter's schema.
// cmd/mcp-gateway TestSchemaFingerprintMatchesTheVersion fails until you
// do: it compares the schema openStore produces with the golden copy
// named after this number.
//
// 1 (30 Sep 2026): the first recorded version. It covers every table the
// seven adapters create at that date; a file from any binary before it
// reads user_version 0 and is migrated as it always was.
const SchemaVersion = 1

// ErrSchemaTooNew means the file was written by a binary that knows a
// newer schema than this one.
var ErrSchemaTooNew = errors.New("store: the database schema is newer than this binary")

// SchemaOf returns the schema version recorded in db's header: 0 for a
// file no guarded binary has written, including a new one.
func SchemaOf(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}

// CheckSchema returns the recorded version, or an error wrapping
// ErrSchemaTooNew when the file is newer than SchemaVersion. It writes
// nothing, so it runs before any migration touches the file.
func CheckSchema(ctx context.Context, db *sql.DB) (int, error) {
	v, err := SchemaOf(ctx, db)
	if err != nil {
		return 0, err
	}
	if v > SchemaVersion {
		return v, fmt.Errorf("%w: the file is at schema %d and this binary knows up to %d. "+
			"It was written by a newer mcp-gateway: run that binary, or restore the backup "+
			"taken before the upgrade (mcp-gateway restore, docs/upgrade.md). Nothing was changed",
			ErrSchemaTooNew, v, SchemaVersion)
	}
	return v, nil
}

// RecordSchema raises the recorded version to SchemaVersion, after the
// migrations have run. It never lowers it: CheckSchema has already
// refused a newer file, and a lower number written over a higher one
// would erase the one fact the guard reads.
func RecordSchema(ctx context.Context, db *sql.DB) error {
	v, err := SchemaOf(ctx, db)
	if err != nil {
		return err
	}
	if v >= SchemaVersion {
		return nil
	}
	// PRAGMA takes no bound parameter; the value is this package's own
	// constant, never input.
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
		return fmt.Errorf("store: record schema version: %w", err)
	}
	return nil
}

// SchemaText is every table, index, trigger and view of db, in a stable
// order, as SQLite stores their CREATE statements. It is what the
// fingerprint test compares against the golden copy of SchemaVersion.
func SchemaText(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT type, name, COALESCE(sql, '') FROM sqlite_master
		 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		return "", fmt.Errorf("store: read schema: %w", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var typ, name, stmt string
		if err := rows.Scan(&typ, &name, &stmt); err != nil {
			return "", fmt.Errorf("store: read schema: %w", err)
		}
		fmt.Fprintf(&b, "-- %s %s\n%s;\n\n", typ, name, strings.TrimSpace(stmt))
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("store: read schema: %w", err)
	}
	return b.String(), nil
}

// SchemaShape is what of db's schema a restore or a check holds a file
// to (design/adr/0045): every trigger, view and index by its exact CREATE
// statement, and every table by name and by the set of its columns (name,
// type, NOT NULL, default, primary key).
//
// A table is compared by its columns and not by its CREATE text because
// that text records history: a column added by an ALTER TABLE lands at the
// end of it, so a file an older binary created and this one migrated
// reads differently from a new file with the same columns. A trigger or
// an index has no such history -- they are created whole or not at all
// -- and they are where a file could carry a rule of its own: a trigger
// that approves a tool as it is observed, deletes a block as it is placed,
// or a same-named trigger with its guard removed, which a migration's
// CREATE TRIGGER IF NOT EXISTS would leave in place.
//
// Not compared: a table's CHECK and UNIQUE clauses beyond its primary key.
func SchemaShape(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT type, name, COALESCE(sql, '') FROM sqlite_master
		 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema: %w", err)
	}
	shape := map[string]string{}
	var tables []string
	for rows.Next() {
		var typ, name, stmt string
		if err := rows.Scan(&typ, &name, &stmt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: read schema: %w", err)
		}
		if typ == "table" {
			tables = append(tables, name)
			continue
		}
		shape[typ+" "+name] = strings.TrimSpace(stmt)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("store: read schema: %w", err)
	}
	rows.Close()
	for _, t := range tables {
		cols, err := tableColumns(ctx, db, t)
		if err != nil {
			return nil, err
		}
		shape["table "+t] = cols
	}
	return shape, nil
}

func tableColumns(ctx context.Context, db *sql.DB, table string) (string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT name, type, "notnull", COALESCE(dflt_value, 'NULL'), pk FROM pragma_table_xinfo(?) ORDER BY name`, table)
	if err != nil {
		return "", fmt.Errorf("store: read columns of %s: %w", table, err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var name, typ, dflt string
		var notNull, pk int
		if err := rows.Scan(&name, &typ, &notNull, &dflt, &pk); err != nil {
			return "", fmt.Errorf("store: read columns of %s: %w", table, err)
		}
		cols = append(cols, fmt.Sprintf("%s %s notnull=%d default=%s pk=%d", name, typ, notNull, dflt, pk))
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("store: read columns of %s: %w", table, err)
	}
	return strings.Join(cols, "; "), nil
}

// SchemaDrift compares a file's shape with the one this binary's
// migrations produce, and names every object that is extra, missing or
// different, sorted. Empty means they agree.
func SchemaDrift(got, want map[string]string) []string {
	var out []string
	for k, w := range want {
		g, ok := got[k]
		switch {
		case !ok:
			out = append(out, "missing "+k)
		case g != w:
			out = append(out, "different "+k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			out = append(out, "extra "+k)
		}
	}
	sort.Strings(out)
	return out
}
