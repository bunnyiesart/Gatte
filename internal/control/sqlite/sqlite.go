// Package sqlite is the SQLite adapter for internal/control
// (design/adr/0044): the gateway process's own row and the operator's
// requests to it. It is the only place SQL for them lives.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/control"
)

const timeLayout = time.RFC3339Nano

// Migrate creates the two tables if they do not exist. Idempotent, and
// named in the composition root's migration map.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS serve_process (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	pid         INTEGER NOT NULL,
	boot        TEXT NOT NULL,
	start_token TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS serve_request (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	kind         TEXT NOT NULL,
	target       TEXT NOT NULL DEFAULT '',
	actor        TEXT NOT NULL,
	tag          TEXT NOT NULL DEFAULT '',
	requested_at TEXT NOT NULL,
	state        TEXT NOT NULL,
	done_at      TEXT NOT NULL DEFAULT '',
	outcome      TEXT NOT NULL DEFAULT '',
	result       TEXT NOT NULL DEFAULT '',
	boot         TEXT NOT NULL DEFAULT ''
);
`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("control/sqlite: migrate: %w", err)
	}
	return nil
}

// Store implements control.Store and control.Requester.
type Store struct{ db *sql.DB }

var (
	_ control.Store     = (*Store)(nil)
	_ control.Requester = (*Store)(nil)
)

// New returns a Store over db, which must already be migrated.
func New(db *sql.DB) *Store { return &Store{db: db} }

func unavailable(what string, err error) error {
	return fmt.Errorf("%w: control/sqlite: %s: %w", control.ErrUnavailable, what, err)
}

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

// RecordProcess replaces the process row.
func (s *Store) RecordProcess(ctx context.Context, p control.Process) error {
	if p.PID <= 0 || p.Boot.IsZero() {
		return fmt.Errorf("%w: a process needs its pid and boot", control.ErrInvalid)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO serve_process (id, pid, boot, start_token) VALUES (1, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET pid = excluded.pid, boot = excluded.boot, start_token = excluded.start_token`,
		p.PID, formatTime(p.Boot), p.StartToken); err != nil {
		return unavailable("record process", err)
	}
	return nil
}

// Process returns the process row, or control.ErrNoProcess.
func (s *Store) Process(ctx context.Context) (control.Process, error) {
	var p control.Process
	var boot string
	err := s.db.QueryRowContext(ctx, `SELECT pid, boot, start_token FROM serve_process WHERE id = 1`).Scan(&p.PID, &boot, &p.StartToken)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return p, control.ErrNoProcess
	case err != nil:
		return p, unavailable("process", err)
	}
	if p.Boot, err = parseTime(boot); err != nil {
		return p, unavailable("process: boot", err)
	}
	return p, nil
}

// Submit files a pending request and returns its id.
func (s *Store) Submit(ctx context.Context, r control.Request) (int64, error) {
	switch {
	case r.Kind != control.KindReload && r.Kind != control.KindRedial:
		return 0, fmt.Errorf("%w: kind %q", control.ErrInvalid, r.Kind)
	case r.Kind == control.KindRedial && r.Target == "":
		return 0, fmt.Errorf("%w: a redial names its backend", control.ErrInvalid)
	case r.Kind == control.KindReload && r.Target != "":
		return 0, fmt.Errorf("%w: a reload names no backend", control.ErrInvalid)
	case r.Actor == "" || r.RequestedAt.IsZero():
		return 0, fmt.Errorf("%w: a request needs its actor and time", control.ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO serve_request (kind, target, actor, tag, requested_at, state) VALUES (?, ?, ?, ?, ?, ?)`,
		r.Kind, r.Target, r.Actor, r.Tag, formatTime(r.RequestedAt), control.StatePending)
	if err != nil {
		return 0, unavailable("submit", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, unavailable("submit", err)
	}
	return id, nil
}

const requestColumns = `id, kind, target, actor, tag, requested_at, state, done_at, outcome, result, boot`

type scanner interface{ Scan(dest ...any) error }

func scanRequest(r scanner) (control.Request, error) {
	var q control.Request
	var requested, done, result, boot string
	if err := r.Scan(&q.ID, &q.Kind, &q.Target, &q.Actor, &q.Tag, &requested, &q.State, &done, &q.Outcome, &result, &boot); err != nil {
		return q, err
	}
	var err error
	if q.RequestedAt, err = parseTime(requested); err != nil {
		return q, unavailable("request: requested_at", err)
	}
	if q.DoneAt, err = parseTime(done); err != nil {
		return q, unavailable("request: done_at", err)
	}
	if q.Boot, err = parseTime(boot); err != nil {
		return q, unavailable("request: boot", err)
	}
	if result != "" {
		q.Result = []byte(result)
	}
	return q, nil
}

// Get returns one request, or control.ErrNotFound.
func (s *Store) Get(ctx context.Context, id int64) (control.Request, error) {
	q, err := scanRequest(s.db.QueryRowContext(ctx, `SELECT `+requestColumns+` FROM serve_request WHERE id = ?`, id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return q, control.ErrNotFound
	case err != nil && !errors.Is(err, control.ErrUnavailable):
		return q, unavailable("get", err)
	}
	return q, err
}

// Pending returns every pending request, oldest first.
func (s *Store) Pending(ctx context.Context) ([]control.Request, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+requestColumns+` FROM serve_request WHERE state = ? ORDER BY id`, control.StatePending)
	if err != nil {
		return nil, unavailable("pending", err)
	}
	defer rows.Close()
	var out []control.Request
	for rows.Next() {
		q, err := scanRequest(rows)
		if err != nil {
			if errors.Is(err, control.ErrUnavailable) {
				return nil, err
			}
			return nil, unavailable("pending: scan", err)
		}
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("pending", err)
	}
	return out, nil
}

// Finish marks a pending request done with its outcome. A request already
// done is left as it is: the first answer stands.
func (s *Store) Finish(ctx context.Context, id int64, outcome string, result []byte, boot, at time.Time) error {
	if outcome != control.OutcomeApplied && outcome != control.OutcomeRefused {
		return fmt.Errorf("%w: outcome %q", control.ErrInvalid, outcome)
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE serve_request SET state = ?, done_at = ?, outcome = ?, result = ?, boot = ? WHERE id = ? AND state = ?`,
		control.StateDone, formatTime(at), outcome, string(result), formatTime(boot), id, control.StatePending)
	if err != nil {
		return unavailable("finish", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		if _, err := s.Get(ctx, id); errors.Is(err, control.ErrNotFound) {
			return err
		}
	}
	return nil
}

// Abandon implements control.Requester: a pending request is finished as
// refused, by the requester, with no boot.
func (s *Store) Abandon(ctx context.Context, id int64, result []byte, at time.Time) error {
	return s.Finish(ctx, id, control.OutcomeRefused, result, time.Time{}, at)
}
