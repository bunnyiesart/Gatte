// Package sqlite is the SQLite adapter for the Definition Signer
// component (design/02-components.md). It is the only place SQL for
// signatures lives; the signer package itself (the domain/port) never
// references database/sql.
//
// Signatures live in their own entry_signatures table rather than as a
// column of upstream_servers, per
// design/adr/0006-signing-key-and-signature-storage.md item 2: the entry
// is configuration data owned by the Upstream Registry, the signature is
// an assertion about that data owned by this component, and the registry's
// adapter should not be able to write the field that attests to it.
package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bunnyiesart/Gatte/internal/signer"
)

// Migrate creates the entry_signatures table if it does not already exist.
// It is safe to call on every startup.
//
// There is deliberately no foreign key to upstream_servers: this table is
// owned by a different component, and coupling the two schemas is exactly
// what ADR-0006 item 2 decided against. A signature for a deregistered
// entry is harmless -- it simply never matches anything again.
func Migrate(db *sql.DB) error {
	const stmt = `
CREATE TABLE IF NOT EXISTS entry_signatures (
	name       TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	signature  BLOB NOT NULL
)`
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("sqlite: migrate entry_signatures: %w", err)
	}
	return nil
}

// Store is a SQLite-backed implementation of signer.Store.
type Store struct {
	db *sql.DB
}

var _ signer.Store = (*Store)(nil)

// New returns a Store that persists signatures in db. The caller is
// responsible for having run Migrate against db beforehand.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// Put implements signer.Store.
func (s *Store) Put(ctx context.Context, name string, sig signer.Signature) error {
	// Reject malformed material at the boundary rather than storing it:
	// a row that can never verify is indistinguishable, later, from a row
	// that was tampered with, and the two deserve very different reactions.
	if len(sig.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("sqlite: put %q: %w: malformed public key", name, signer.ErrInvalidSignature)
	}
	if len(sig.Bytes) != ed25519.SignatureSize {
		return fmt.Errorf("sqlite: put %q: %w: malformed signature", name, signer.ErrInvalidSignature)
	}

	const stmt = `
INSERT INTO entry_signatures (name, public_key, signature)
VALUES (?, ?, ?)
ON CONFLICT(name) DO UPDATE SET public_key = excluded.public_key, signature = excluded.signature`
	if _, err := s.db.ExecContext(ctx, stmt, name, []byte(sig.PublicKey), sig.Bytes); err != nil {
		return fmt.Errorf("sqlite: put %q: %w", name, err)
	}
	return nil
}

// Get implements signer.Store.
func (s *Store) Get(ctx context.Context, name string) (signer.Signature, error) {
	const stmt = `SELECT public_key, signature FROM entry_signatures WHERE name = ?`

	var publicKey, signature []byte
	err := s.db.QueryRowContext(ctx, stmt, name).Scan(&publicKey, &signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return signer.Signature{}, fmt.Errorf("sqlite: get %q: %w", name, signer.ErrNotFound)
		}
		return signer.Signature{}, fmt.Errorf("sqlite: get %q: %w", name, err)
	}

	return signer.Signature{
		Bytes:     signature,
		PublicKey: ed25519.PublicKey(publicKey),
	}, nil
}

// Delete implements signer.Store.
func (s *Store) Delete(ctx context.Context, name string) error {
	const stmt = `DELETE FROM entry_signatures WHERE name = ?`

	res, err := s.db.ExecContext(ctx, stmt, name)
	if err != nil {
		return fmt.Errorf("sqlite: delete %q: %w", name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: delete %q: %w", name, err)
	}
	if n == 0 {
		return fmt.Errorf("sqlite: delete %q: %w", name, signer.ErrNotFound)
	}
	return nil
}
