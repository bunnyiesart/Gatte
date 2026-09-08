// Package vault is the domain package for the Credential Vault component
// (design/02-components.md): resolving a secret reference to its real
// value, in memory, for injection into an upstream server's environment
// at spawn time -- never persisted to disk, never logged.
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to sops, age, os/exec, or any other
// infrastructure detail. The sopsage subpackage is the adapter.
package vault

import (
	"context"
	"errors"
)

// ErrNotFound is returned by Provider.Resolve when no secret is stored
// under the requested name.
var ErrNotFound = errors.New("vault: secret not found")

// Secret is a resolved credential value. It exists as a distinct type,
// not a bare string, precisely so that "does anything outside the
// Credential Vault's public interface read a secret value directly"
// (design/adr/0001-monolithic-modular-style.md, Compliance section) has
// one concrete shape to check for wherever a secret value crosses a
// package boundary -- a fitness function can grep for vault.Secret as the
// one sanctioned carrier.
type Secret struct {
	value string
}

// NewSecret wraps value as a Secret. It exists for Provider
// implementations; application code should obtain a Secret only from
// Provider.Resolve, never construct one from a value it already holds.
func NewSecret(value string) Secret {
	return Secret{value: value}
}

// Value returns the resolved secret value. Callers must not log it, write
// it to disk, or embed it in anything that itself gets logged -- keeping
// this the only path to the plaintext is Resolve's entire contract (see
// Provider).
func (s Secret) Value() string {
	return s.value
}

// Provider resolves a secret reference to its current value.
// Implementations are adapters (e.g. the sopsage subpackage) and must
// never persist a resolved value to disk, nor write it to a log line,
// error message, or any other output that isn't the returned Secret
// itself.
type Provider interface {
	// Resolve returns the current value of the secret registered under
	// name. It returns ErrNotFound if no secret exists under that name.
	Resolve(ctx context.Context, name string) (Secret, error)
}
