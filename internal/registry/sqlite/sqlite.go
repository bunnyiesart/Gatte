// Package sqlite is the SQLite adapter for the Upstream Registry
// component (design/02-components.md). It is the only place SQL for the
// registry lives; the registry package itself (the domain/port) never
// references database/sql.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

// Migrate creates the upstream_servers table if it does not already
// exist. It is safe to call on every startup.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS upstream_servers (
	name          TEXT PRIMARY KEY,
	transport     TEXT NOT NULL,
	command       TEXT NOT NULL,
	args          TEXT NOT NULL,
	url           TEXT NOT NULL,
	env_var_names TEXT NOT NULL,
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL
)`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("sqlite: migrate upstream_servers: %w", err)
	}
	return nil
}

// Repository is a SQLite-backed implementation of registry.Repository.
type Repository struct {
	db *sql.DB
}

var _ registry.Repository = (*Repository)(nil)

// New returns a Repository that stores UpstreamServer entries in db. The
// caller is responsible for having run Migrate against db beforehand.
func New(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Register implements registry.Repository.
func (r *Repository) Register(ctx context.Context, s registry.UpstreamServer) error {
	if err := s.Validate(); err != nil {
		return err
	}

	// Normalize nil slices to empty before encoding: json.Marshal(nil)
	// produces the literal "null", and we want the stored (and later
	// round-tripped) value to always be an empty JSON array, never null,
	// so callers of Get/List never have to distinguish "no entries" from
	// "field absent."
	if s.Args == nil {
		s.Args = []string{}
	}
	if s.EnvVarNames == nil {
		s.EnvVarNames = []string{}
	}

	args, err := json.Marshal(s.Args)
	if err != nil {
		return fmt.Errorf("sqlite: marshal args: %w", err)
	}
	envVarNames, err := json.Marshal(s.EnvVarNames)
	if err != nil {
		return fmt.Errorf("sqlite: marshal env var names: %w", err)
	}

	now := time.Now().UTC()
	s.CreatedAt = now
	s.UpdatedAt = now

	const stmt = `
INSERT INTO upstream_servers (name, transport, command, args, url, env_var_names, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.db.ExecContext(ctx, stmt,
		s.Name,
		string(s.Transport),
		s.Command,
		string(args),
		s.URL,
		string(envVarNames),
		s.CreatedAt.Format(time.RFC3339),
		s.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("sqlite: register %q: %w", s.Name, registry.ErrAlreadyExists)
		}
		return fmt.Errorf("sqlite: register %q: %w", s.Name, err)
	}
	return nil
}

// Get implements registry.Repository.
func (r *Repository) Get(ctx context.Context, name string) (registry.UpstreamServer, error) {
	const stmt = `
SELECT name, transport, command, args, url, env_var_names, created_at, updated_at
FROM upstream_servers
WHERE name = ?`
	row := r.db.QueryRowContext(ctx, stmt, name)

	s, err := scanUpstreamServer(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return registry.UpstreamServer{}, fmt.Errorf("sqlite: get %q: %w", name, registry.ErrNotFound)
		}
		return registry.UpstreamServer{}, fmt.Errorf("sqlite: get %q: %w", name, err)
	}
	return s, nil
}

// List implements registry.Repository.
func (r *Repository) List(ctx context.Context) ([]registry.UpstreamServer, error) {
	const stmt = `
SELECT name, transport, command, args, url, env_var_names, created_at, updated_at
FROM upstream_servers
ORDER BY name`
	rows, err := r.db.QueryContext(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list: %w", err)
	}
	defer rows.Close()

	servers := make([]registry.UpstreamServer, 0)
	for rows.Next() {
		s, err := scanUpstreamServer(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: list: scan: %w", err)
		}
		servers = append(servers, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: list: %w", err)
	}
	return servers, nil
}

// Deregister implements registry.Repository.
func (r *Repository) Deregister(ctx context.Context, name string) error {
	const stmt = `DELETE FROM upstream_servers WHERE name = ?`
	res, err := r.db.ExecContext(ctx, stmt, name)
	if err != nil {
		return fmt.Errorf("sqlite: deregister %q: %w", name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: deregister %q: %w", name, err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: deregister %q: %w", name, registry.ErrNotFound)
	}
	return nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows, letting
// scanUpstreamServer serve Get and List alike.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUpstreamServer(row rowScanner) (registry.UpstreamServer, error) {
	var (
		s                    registry.UpstreamServer
		transport            string
		args, envVarNames    string
		createdAt, updatedAt string
	)

	if err := row.Scan(&s.Name, &transport, &s.Command, &args, &s.URL, &envVarNames, &createdAt, &updatedAt); err != nil {
		return registry.UpstreamServer{}, err
	}

	s.Transport = registry.Transport(transport)

	if err := json.Unmarshal([]byte(args), &s.Args); err != nil {
		return registry.UpstreamServer{}, fmt.Errorf("unmarshal args: %w", err)
	}
	if s.Args == nil {
		s.Args = []string{}
	}

	if err := json.Unmarshal([]byte(envVarNames), &s.EnvVarNames); err != nil {
		return registry.UpstreamServer{}, fmt.Errorf("unmarshal env var names: %w", err)
	}
	if s.EnvVarNames == nil {
		s.EnvVarNames = []string{}
	}

	createdAtTime, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return registry.UpstreamServer{}, fmt.Errorf("parse created_at: %w", err)
	}
	s.CreatedAt = createdAtTime

	updatedAtTime, err := time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return registry.UpstreamServer{}, fmt.Errorf("parse updated_at: %w", err)
	}
	s.UpdatedAt = updatedAtTime

	return s, nil
}

// isUniqueConstraintErr reports whether err was caused by a UNIQUE/PRIMARY
// KEY constraint violation. modernc.org/sqlite does not expose a typed
// error for this, so the check is on the driver's error message.
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed: UNIQUE")
}
