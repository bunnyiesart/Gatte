// Package sqlite is the SQLite adapter for internal/health
// (design/adr/0041): the maintenance rows an operator writes, and the
// backend health, last live listing and serve status the gateway process
// writes about itself. It is the only place SQL for them lives.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bunnyiesart/Gatte/internal/health"
)

// timeLayout matches the other adapters', so one file has one date format.
const timeLayout = time.RFC3339Nano

// Migrate creates the four tables if they do not exist. Idempotent, and
// named in the composition root's migration map: a gateway whose
// maintenance table is missing would read "no maintenance" on every call
// (the read is fail-open) and log an error per call instead of failing at
// startup.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS maintenance (
	target     TEXT PRIMARY KEY,
	message    TEXT NOT NULL,
	until      TEXT NOT NULL DEFAULT '',
	started_at TEXT NOT NULL,
	set_by     TEXT NOT NULL,
	set_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS backend_health (
	backend      TEXT PRIMARY KEY,
	live         INTEGER NOT NULL,
	since        TEXT NOT NULL,
	last_attempt TEXT NOT NULL DEFAULT '',
	next_attempt TEXT NOT NULL DEFAULT '',
	cause        TEXT NOT NULL DEFAULT '',
	updated_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS backend_listing (
	backend   TEXT NOT NULL,
	tool      TEXT NOT NULL,
	hash      TEXT NOT NULL,
	listed_at TEXT NOT NULL,
	PRIMARY KEY (backend, tool)
);
CREATE TABLE IF NOT EXISTS serve_status (
	id                     INTEGER PRIMARY KEY CHECK (id = 1),
	boot                   TEXT NOT NULL,
	last_round_at          TEXT NOT NULL,
	round_interval_seconds INTEGER NOT NULL
);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("health/sqlite: migrate: %w", err)
	}
	return nil
}

// Store is the SQLite-backed implementation of every health port. Which
// port a caller holds decides what it can do: the Gateway gets a
// MaintenanceReader and a StateStore, the management service a
// MaintenanceStore and a StateReader.
type Store struct {
	db *sql.DB
}

var (
	_ health.MaintenanceStore = (*Store)(nil)
	_ health.StateStore       = (*Store)(nil)
	_ health.StateReader      = (*Store)(nil)
)

// New returns a Store over db, which must already be migrated.
func New(db *sql.DB) *Store { return &Store{db: db} }

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(timeLayout, s)
}

func unavailable(what string, err error) error {
	return fmt.Errorf("%w: health/sqlite: %s: %w", health.ErrUnavailable, what, err)
}

// Maintenance implements health.MaintenanceReader: the whole table, by
// target. It is read on every call, and is a handful of rows.
func (s *Store) Maintenance(ctx context.Context) ([]health.Maintenance, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target, message, until, started_at, set_by, set_at FROM maintenance ORDER BY target`)
	if err != nil {
		return nil, unavailable("maintenance", err)
	}
	defer rows.Close()
	out := []health.Maintenance{}
	for rows.Next() {
		m, err := scanMaintenance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("maintenance", err)
	}
	return out, nil
}

type scanner interface{ Scan(dest ...any) error }

func scanMaintenance(r scanner) (health.Maintenance, error) {
	var m health.Maintenance
	var until, started, setAt string
	if err := r.Scan(&m.Target, &m.Message, &until, &started, &m.SetBy, &setAt); err != nil {
		return m, unavailable("maintenance: scan", err)
	}
	var err error
	if m.Until, err = parseTime(until); err != nil {
		return m, unavailable("maintenance: until of "+m.Target, err)
	}
	if m.StartedAt, err = parseTime(started); err != nil {
		return m, unavailable("maintenance: started_at of "+m.Target, err)
	}
	if m.SetAt, err = parseTime(setAt); err != nil {
		return m, unavailable("maintenance: set_at of "+m.Target, err)
	}
	return m, nil
}

// Start implements health.MaintenanceStore, reading and writing the row in
// one transaction so two operators cannot both open it.
func (s *Store) Start(ctx context.Context, m health.Maintenance) (health.StartResult, error) {
	if m.Target == "" || m.Message == "" || m.SetBy == "" || m.SetAt.IsZero() {
		return health.StartResult{}, fmt.Errorf("%w: target, message, set_by and set_at are required", health.ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return health.StartResult{}, unavailable("maintenance start", err)
	}
	defer func() { _ = tx.Rollback() }()

	var previous *health.Maintenance
	row := tx.QueryRowContext(ctx, `SELECT target, message, until, started_at, set_by, set_at FROM maintenance WHERE target = ?`, m.Target)
	switch old, err := scanMaintenance(row); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return health.StartResult{}, err
	default:
		previous = &old
	}

	if previous != nil && previous.Message == m.Message && previous.Until.Equal(m.Until) {
		return health.StartResult{Stored: *previous, Previous: previous}, nil
	}
	m.StartedAt = m.SetAt
	if previous != nil {
		m.StartedAt = previous.StartedAt
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO maintenance (target, message, until, started_at, set_by, set_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (target) DO UPDATE SET message = excluded.message, until = excluded.until, set_by = excluded.set_by, set_at = excluded.set_at`,
		m.Target, m.Message, formatTime(m.Until), formatTime(m.StartedAt), m.SetBy, formatTime(m.SetAt)); err != nil {
		return health.StartResult{}, unavailable("maintenance start", err)
	}
	if err := tx.Commit(); err != nil {
		return health.StartResult{}, unavailable("maintenance start", err)
	}
	m.Until, m.StartedAt, m.SetAt = m.Until.UTC(), m.StartedAt.UTC(), m.SetAt.UTC()
	if m.Until.IsZero() {
		m.Until = time.Time{}
	}
	return health.StartResult{Stored: m, Previous: previous, Changed: true}, nil
}

// End implements health.MaintenanceStore.
func (s *Store) End(ctx context.Context, target string) (*health.Maintenance, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, unavailable("maintenance end", err)
	}
	defer func() { _ = tx.Rollback() }()
	row := tx.QueryRowContext(ctx, `SELECT target, message, until, started_at, set_by, set_at FROM maintenance WHERE target = ?`, target)
	old, err := scanMaintenance(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM maintenance WHERE target = ?`, target); err != nil {
		return nil, unavailable("maintenance end", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, unavailable("maintenance end", err)
	}
	return &old, nil
}

// WriteState implements health.StateStore, in one transaction: a
// backend's listing is never rewritten without its health row.
func (s *Store) WriteState(ctx context.Context, snap health.Snapshot) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return unavailable("write state", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM backend_health`); err != nil {
		return unavailable("write state", err)
	}
	for _, b := range snap.Backends {
		live := 0
		if b.Live {
			live = 1
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO backend_health (backend, live, since, last_attempt, next_attempt, cause, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			b.Backend, live, formatTime(b.Since), formatTime(b.LastAttempt), formatTime(b.NextAttempt), string(b.Cause), formatTime(b.UpdatedAt)); err != nil {
			return unavailable("write state: health of "+b.Backend, err)
		}
	}
	names := make([]string, 0, len(snap.Listings))
	for name := range snap.Listings {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if _, err := tx.ExecContext(ctx, `DELETE FROM backend_listing WHERE backend = ?`, name); err != nil {
			return unavailable("write state: listing of "+name, err)
		}
		for _, lt := range snap.Listings[name] {
			if _, err := tx.ExecContext(ctx, `INSERT INTO backend_listing (backend, tool, hash, listed_at) VALUES (?, ?, ?, ?)`,
				name, lt.Tool, lt.Hash, formatTime(snap.ListedAt)); err != nil {
				return unavailable("write state: listing of "+name, err)
			}
		}
	}
	if st := snap.Serve; st != nil {
		secs := int64(st.RoundInterval / time.Second)
		if secs < 1 {
			secs = 1
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO serve_status (id, boot, last_round_at, round_interval_seconds) VALUES (1, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET boot = excluded.boot, last_round_at = excluded.last_round_at, round_interval_seconds = excluded.round_interval_seconds`,
			formatTime(st.Boot), formatTime(st.LastRoundAt), secs); err != nil {
			return unavailable("write state: serve status", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return unavailable("write state", err)
	}
	return nil
}

// Listings implements health.StateStore.
func (s *Store) Listings(ctx context.Context) (map[string][]health.ListedTool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT backend, tool, hash FROM backend_listing ORDER BY backend, tool`)
	if err != nil {
		return nil, unavailable("listings", err)
	}
	defer rows.Close()
	out := map[string][]health.ListedTool{}
	for rows.Next() {
		var backend string
		var lt health.ListedTool
		if err := rows.Scan(&backend, &lt.Tool, &lt.Hash); err != nil {
			return nil, unavailable("listings: scan", err)
		}
		out[backend] = append(out[backend], lt)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("listings", err)
	}
	return out, nil
}

// Backends implements health.StateReader.
func (s *Store) Backends(ctx context.Context) ([]health.BackendRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT backend, live, since, last_attempt, next_attempt, cause, updated_at FROM backend_health ORDER BY backend`)
	if err != nil {
		return nil, unavailable("backend health", err)
	}
	defer rows.Close()
	out := []health.BackendRecord{}
	for rows.Next() {
		var b health.BackendRecord
		var live int
		var since, last, next, cause, updated string
		if err := rows.Scan(&b.Backend, &live, &since, &last, &next, &cause, &updated); err != nil {
			return nil, unavailable("backend health: scan", err)
		}
		b.Live, b.Cause = live == 1, health.Cause(cause)
		for _, f := range []struct {
			dst *time.Time
			src string
		}{{&b.Since, since}, {&b.LastAttempt, last}, {&b.NextAttempt, next}, {&b.UpdatedAt, updated}} {
			if *f.dst, err = parseTime(f.src); err != nil {
				return nil, unavailable("backend health: time of "+b.Backend, err)
			}
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("backend health", err)
	}
	return out, nil
}

// Serve implements health.StateReader.
func (s *Store) Serve(ctx context.Context) (health.ServeStatus, bool, error) {
	var boot, last string
	var secs int64
	err := s.db.QueryRowContext(ctx, `SELECT boot, last_round_at, round_interval_seconds FROM serve_status WHERE id = 1`).Scan(&boot, &last, &secs)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return health.ServeStatus{}, false, nil
	case err != nil:
		return health.ServeStatus{}, false, unavailable("serve status", err)
	}
	var st health.ServeStatus
	if st.Boot, err = parseTime(boot); err != nil {
		return st, false, unavailable("serve status: boot", err)
	}
	if st.LastRoundAt, err = parseTime(last); err != nil {
		return st, false, unavailable("serve status: last round", err)
	}
	st.RoundInterval = time.Duration(secs) * time.Second
	return st, true, nil
}

// Forget removes the maintenance, health and listing of name, for
// `upstream deregister`: a name registered again inherits nothing, for the
// reason quarantine.Store.Forget gives.
func (s *Store) Forget(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return unavailable("forget", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`DELETE FROM maintenance WHERE target = ?`,
		`DELETE FROM backend_health WHERE backend = ?`,
		`DELETE FROM backend_listing WHERE backend = ?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, name); err != nil {
			return unavailable("forget "+name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return unavailable("forget", err)
	}
	return nil
}
