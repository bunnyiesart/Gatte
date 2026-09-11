// Package vault is the domain package for the Credential Vault component
// (design/02-components.md): resolving a secret reference to its real
// value, in memory, for injection into an upstream server's environment
// at spawn time -- never persisted to disk, never logged.
//
// **Resolution happens at spawn, and that has a rotation consequence.**
// The value a Provider returns is copied into the upstream subprocess's
// environment when that upstream is dialed, so it is fixed for the life
// of the connection. Changing the underlying store afterwards affects
// only the *next* dial: an already-connected upstream keeps the old value
// until the gateway restarts. This matters because rotation usually means
// someone believes the old credential is compromised.
//
// Something does tell them now (GAB-20): the Gateway keeps a keyed digest
// of what each upstream was handed at dial time and re-compares it against
// the vault once per refresh tick, so a rotation that has not taken effect
// is reported instead of silent. It is a warning and not a fix -- the
// upstream keeps the old value until the gateway is restarted, which is
// the remedy. See deploy/freebsd-jail.md ("Rotating credentials").
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to sops, age, os/exec, or any other
// infrastructure detail. The sopsage subpackage is the adapter.
package vault

import (
	"context"
	"errors"
	"log/slog"
)

// ErrNotFound is returned by Provider.Resolve when no secret is stored
// under the requested name.
var ErrNotFound = errors.New("vault: secret not found")

// redactedSecret is what a Secret renders as through every formatting
// path. It is deliberately not a plausible credential and names the type,
// so that finding it in a log tells the reader a redaction fired rather
// than leaving them wondering what the empty string meant.
const redactedSecret = "vault.Secret([redacted])"

// Secret is a resolved credential value. It exists as a distinct type,
// not a bare string, precisely so that "does anything outside the
// Credential Vault's public interface read a secret value directly"
// (design/adr/0001-monolithic-modular-style.md, Compliance section) has
// one concrete shape to check for wherever a secret value crosses a
// package boundary -- a fitness function can grep for vault.Secret as the
// one sanctioned carrier.
//
// Being a distinct type is not by itself a guard, and until 11 Sep 2026 it
// was mistaken for one. A struct with an unexported string field is opaque
// to the compiler and wide open to reflection: fmt and slog read unexported
// fields, so %v, %+v, %#v, %s, slog.Any and any enclosing struct printed
// with %+v all rendered the plaintext. Two things close that here. The four
// methods below occupy every hook fmt and slog consult before falling back
// to reflection. And the value is held behind a pointer, because a method
// cannot be reached at all when a Secret sits in an *unexported* field of
// some other struct -- fmt cannot take that field's interface, so it
// reflects straight through to the representation, and the representation
// it finds must therefore be an address rather than the key itself.
type Secret struct {
	// value is a pointer, not a string, for the reflection reason above.
	// nil is the zero Secret, which Provider implementations return on
	// every error path; Value reports it as the empty string.
	value *string
}

// NewSecret wraps value as a Secret. It exists for Provider
// implementations; application code should obtain a Secret only from
// Provider.Resolve, never construct one from a value it already holds.
func NewSecret(value string) Secret {
	return Secret{value: &value}
}

// Value returns the resolved secret value. Callers must not log it, write
// it to disk, or embed it in anything that itself gets logged -- keeping
// this the only path to the plaintext is Resolve's entire contract (see
// Provider). "Only path" is now enforced against the accidents, not merely
// asked for: printing or logging a Secret yields redactedSecret instead.
// It is not enforced against a caller who goes after the field with
// reflect and unsafe, and no in-process representation could be.
func (s Secret) Value() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// String keeps the %v, %s and %q verbs -- and every fmt.Errorf that
// interpolates a Secret -- from reaching the plaintext by reflection.
func (s Secret) String() string {
	return redactedSecret
}

// GoString covers %#v, which fmt routes to GoStringer and not to Stringer.
// The rendering stays Go-shaped because that is what %#v promises a reader.
func (s Secret) GoString() string {
	return "vault.Secret{/* redacted */}"
}

// LogValue covers slog. slog.Any on a Stringer still formats the value
// with fmt, so implementing Stringer alone would already redact, but
// LogValuer is the interface slog documents for exactly this purpose and
// is checked first; relying on the fmt fallback would make the guard an
// accident of another package's implementation.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redactedSecret)
}

// MarshalText covers encoding/json and anything else that prefers a
// TextMarshaler. encoding/json alone was already safe -- it cannot see
// unexported fields and rendered a Secret as {} -- but {} is silent about
// why it is empty, and a marshaller that is not encoding/json may not
// share that blind spot.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redactedSecret), nil
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
