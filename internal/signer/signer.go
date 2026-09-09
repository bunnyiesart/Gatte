// Package signer is the domain package for the Definition Signer component
// (design/02-components.md): Ed25519 signing and verification of Upstream
// Registry entries, so that a registry entry altered behind the gateway's
// back is detected before it is ever served.
//
// The canonical form a signature covers deliberately excludes every secret
// value -- see Canonical -- so that rotating a credential never invalidates
// a signature (design/adr/0003-security-controls.md, item 3).
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter.
package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

// Sentinel errors returned by this package and by Store implementations.
// Callers should check these with errors.Is, since adapters wrap them with
// additional context.
var (
	// ErrInvalidSignature is returned by Verifier.Verify when a signature
	// does not authenticate the entry it was presented with -- including
	// when the signature or public key is malformed, and including when it
	// was made by a key outside the trusted set
	// (design/adr/0010-signature-trust-anchor.md item 2). Per
	// design/adr/0006-signing-key-and-signature-storage.md item 3, this is
	// positive evidence of tampering and has no benign reading: the entry
	// must not be served.
	ErrInvalidSignature = errors.New("signer: invalid signature")
	// ErrNotFound is returned when no signature is stored for the
	// requested entry name. Unlike ErrInvalidSignature, an absent
	// signature is not evidence of tampering -- ADR-0006 item 3 makes how
	// to react to it a configuration decision, not this package's.
	ErrNotFound = errors.New("signer: no signature stored for entry")
	// ErrNoKey is returned when a key is required but absent, unreadable as
	// a key, or not an Ed25519 key of the right size. It covers both halves
	// of the pair: the private key LoadKey reads, and a public key offered
	// to NewVerifier as a trust anchor.
	ErrNoKey = errors.New("signer: no usable key")
)

// canonicalTag is a domain-separation prefix, length-prefixed like every
// other field, so that a canonical encoding produced here can never be
// confused with some other length-prefixed blob this project might sign in
// the future. The trailing version number is what lets the encoding change
// later without silently making old and new signatures interchangeable.
const canonicalTag = "mcp-gateway/signer/canonical/v1"

// Canonical returns the exact bytes a signature over s covers.
//
// # What is covered, and what is deliberately not
//
// Covered: the tag above, Name, Transport, Command, URL, Args in order,
// and EnvVarNames *sorted*.
//
// Name is covered although ADR-0003 lists only command/url, args and env
// var names. Including it binds a signature to the entry it was made for,
// so a signature row cannot be transplanted onto a differently-named entry
// that happens to run the same command -- a strengthening of that ADR's
// rule, never a relaxation of it, and it costs nothing because renaming an
// entry is a deregister plus a register, which needs a fresh signature
// regardless.
//
// Sorting EnvVarNames matters because the order the names happen to be
// stored in carries no meaning -- the environment is a set -- so leaving
// them unsorted would let a signature break (or, worse, be made to break
// selectively) on a reordering that changed nothing.
//
// Not covered: CreatedAt and UpdatedAt. Timestamps move on writes that do
// not change what the entry actually instructs the gateway to run;
// including them would invalidate signatures for no security reason.
//
// Not covered, and the whole point of the design: any secret *value*.
// registry.UpstreamServer has no field capable of holding one --
// EnvVarNames holds names only, and resolving a name to a value is the
// Credential Vault's job. A credential rotation therefore changes nothing
// this function reads, which is precisely why rotation can never invalidate
// a signature (design/adr/0003-security-controls.md, item 3).
//
// # Why the encoding is length-prefixed
//
// Every string is written as an 8-byte big-endian length followed by its
// raw bytes, and every list is preceded by an 8-byte big-endian element
// count. Naive concatenation would make Command "ab" + Args ["c"] and
// Command "a" + Args ["bc"] hash identically, which is a signature-forgery
// vector: a signature obtained for one entry would authenticate a
// different one. With lengths in front, no byte string can span a field
// boundary and no field boundary is ambiguous, so distinct entries always
// produce distinct canonical bytes.
//
// Canonical never mutates s, including its slices.
func Canonical(s registry.UpstreamServer) []byte {
	var buf []byte

	buf = appendField(buf, canonicalTag)
	buf = appendField(buf, s.Name)
	buf = appendField(buf, string(s.Transport))
	// Command and URL are both always written, even though only one is
	// meaningful for a given Transport: a fixed field layout is one less
	// thing for an attacker to shift around than a conditional one.
	buf = appendField(buf, s.Command)
	buf = appendField(buf, s.URL)

	buf = appendCount(buf, len(s.Args))
	for _, arg := range s.Args {
		buf = appendField(buf, arg)
	}

	// Clone before sorting: Canonical must not reorder the caller's slice
	// as a side effect of hashing it.
	envVarNames := slices.Clone(s.EnvVarNames)
	slices.Sort(envVarNames)
	buf = appendCount(buf, len(envVarNames))
	for _, name := range envVarNames {
		buf = appendField(buf, name)
	}

	return buf
}

// appendField appends the 8-byte big-endian length of v followed by v.
func appendField(buf []byte, v string) []byte {
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(v)))
	return append(buf, v...)
}

// appendCount appends an 8-byte big-endian element count, so a list's
// arity is part of the signed bytes rather than inferred from what follows.
func appendCount(buf []byte, n int) []byte {
	return binary.BigEndian.AppendUint64(buf, uint64(n))
}

// Signature is an Ed25519 signature over Canonical(entry), together with
// the public key that produced it.
//
// PublicKey is *diagnostic only*, and that distinction is the whole subject
// of design/adr/0010-signature-trust-anchor.md. It travels in the same row,
// in the same SQLite file, as the entry it attests to, so anyone who can
// rewrite the entry can rewrite it too; a key supplied by whoever supplied
// the signature proves nothing but that the two were generated together.
// What it is good for is telling an operator *which* key signed an entry --
// naming a key that is no longer trusted, or one that was never trusted --
// and that is the only job it has.
type Signature struct {
	// Bytes is the raw Ed25519 signature, ed25519.SignatureSize bytes.
	Bytes []byte
	// PublicKey is the Ed25519 public key that claims to have produced
	// Bytes, ed25519.PublicKeySize bytes. Never an input to the trust
	// decision -- see Verifier.Verify.
	PublicKey ed25519.PublicKey
}

// Store is the port through which signatures are persisted and retrieved,
// keyed by the registry entry's name. Implementations are adapters (e.g.
// the sqlite subpackage) and must honor the contracts documented on each
// method.
//
// Signatures live in their own store, not as a column of the registry's
// own table: the entry is configuration data, the signature is an
// assertion *about* that data made by a different component
// (design/adr/0006-signing-key-and-signature-storage.md item 2).
type Store interface {
	// Put stores sig for the entry named name, replacing any signature
	// already stored under that name. It returns ErrInvalidSignature if
	// sig is malformed (wrong signature or public key size).
	Put(ctx context.Context, name string, sig Signature) error

	// Get returns the signature stored for the entry named name. It
	// returns ErrNotFound if no signature has been stored for that name.
	Get(ctx context.Context, name string) (Signature, error)

	// Delete removes the signature stored for the entry named name. It
	// returns ErrNotFound if no signature has been stored for that name.
	Delete(ctx context.Context, name string) error
}

// Signer produces signatures over registry entries with one Ed25519
// private key. It is used by the Operator when registering or updating an
// entry -- never by the request path, which has no business holding
// signing material (ADR-0006 item 1).
type Signer struct {
	key ed25519.PrivateKey
}

// NewSigner returns a Signer that signs with key. It returns ErrNoKey if
// key is nil or is not a well-formed Ed25519 private key.
func NewSigner(key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expected a %d-byte ed25519 private key", ErrNoKey, ed25519.PrivateKeySize)
	}
	return &Signer{key: key}, nil
}

// PublicKey returns the public key matching this Signer's private key.
// Handing out the public half is what lets an operator record which key an
// entry was signed with without the private half leaving this type.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}

// Sign returns a Signature over Canonical(entry).
func (s *Signer) Sign(entry registry.UpstreamServer) Signature {
	return Signature{
		Bytes:     ed25519.Sign(s.key, Canonical(entry)),
		PublicKey: s.PublicKey(),
	}
}

// Verifier decides whether a signature authenticates an entry, using a
// fixed set of trusted public keys -- the gateway's trust anchor
// (design/adr/0010-signature-trust-anchor.md).
//
// # Why this is a type and not a free function
//
// It used to be a free function taking only the entry and the signature,
// on the reasoning that verification needs nothing but the public key
// travelling inside sig. That reasoning was wrong, and it was proven
// exploitable: an attacker with write access to the database tampers with
// the entry, generates a fresh Ed25519 pair, signs the tampered entry with
// it, and writes both the entry and the new (key, signature) pair. Every
// check passed. `upstream list` printed SIGNED: yes.
//
// A signature is only ever evidence *relative to a key you already
// trusted*. So the key set has to come from somewhere the attacker being
// modelled cannot reach -- here, the configuration file, which is
// versioned and reviewed and lives outside the SQLite file that holds both
// the entries and their signatures. Making the trusted set a constructor
// argument is what forces every caller to name it: there is no way to
// verify without having said, in code, what you trust.
//
// A Verifier is immutable and safe for concurrent use.
type Verifier struct {
	trusted []ed25519.PublicKey
}

// NewVerifier returns a Verifier that accepts signatures made by any key in
// trusted, and nothing else. It returns ErrNoKey if any element is not a
// well-formed Ed25519 public key, naming its position -- a malformed trust
// anchor is a configuration error, and inferring intent from it (skipping
// it, say) would quietly shrink the set the operator wrote down.
//
// An empty trusted set is allowed and means "trust nobody": every signature
// is then refused as invalid. That is a coherent state for a deployment
// that has set require_signed = false and simply does not use signing --
// config.Config.Validate is what refuses the incoherent combination of
// requiring signatures with nothing to check them against.
//
// NewVerifier copies trusted, so a later mutation of the caller's slice
// cannot change what this Verifier accepts.
func NewVerifier(trusted []ed25519.PublicKey) (*Verifier, error) {
	keys := make([]ed25519.PublicKey, 0, len(trusted))
	for i, pub := range trusted {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: trusted key %d is not a %d-byte ed25519 public key", ErrNoKey, i, ed25519.PublicKeySize)
		}
		keys = append(keys, slices.Clone(pub))
	}
	return &Verifier{trusted: keys}, nil
}

// Trusts reports whether pub is one of the keys this Verifier was built
// with. It answers a question about configuration, not about any particular
// signature: `sign` uses it to tell an operator that the key just used to
// sign an entry is not one the gateway will accept.
func (v *Verifier) Trusts(pub ed25519.PublicKey) bool {
	for _, k := range v.trusted {
		// ed25519.PublicKey.Equal, not bytes.Equal: it is the type's own
		// notion of equality, and it does not care that these are public
		// values for which timing is irrelevant.
		if k.Equal(pub) {
			return true
		}
	}
	return false
}

// TrustedCount reports how many keys this Verifier accepts. Callers use it
// to say "no trusted key is configured" out loud rather than letting that
// state show up only as every entry mysteriously failing.
func (v *Verifier) TrustedCount() int { return len(v.trusted) }

// Verify reports whether sig authenticates entry *against a trusted key*,
// returning nil when it does and ErrInvalidSignature when it does not.
//
// The trust decision is structural: Canonical(entry) is checked against
// each configured key in turn, and sig.PublicKey is never passed to
// ed25519.Verify. It is read below the decision, to say which key the row
// claims -- so a future edit here cannot accidentally reintroduce the flaw
// ADR-0010 removed, because the attacker-supplied key is not on the path
// that can return nil.
//
// A signature made by a key outside the trusted set is ErrInvalidSignature,
// not ErrNotFound: it is positive evidence that somebody signed this entry
// with a key this gateway does not recognise, and that has no benign
// reading -- the same judgement ADR-0006 item 3 makes about a signature
// that does not match.
func (v *Verifier) Verify(entry registry.UpstreamServer, sig Signature) error {
	// Shape checks first, including on the diagnostic key. Refusing a row
	// that cannot even say which key produced it is not part of the trust
	// decision -- it is this project's general refusal to reason about
	// malformed input, and it keeps the message below honest.
	if len(sig.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed public key", ErrInvalidSignature)
	}
	if len(sig.Bytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrInvalidSignature)
	}

	canonical := Canonical(entry)
	for _, pub := range v.trusted {
		if ed25519.Verify(pub, canonical, sig.Bytes) {
			return nil
		}
	}

	// Nothing below can return nil. Everything here exists so the operator
	// reading the log learns which of two very different things happened.
	switch {
	case len(v.trusted) == 0:
		return fmt.Errorf(
			"%w: entry %q carries a signature but no trusted key is configured to check it against -- set signer.trusted_keys",
			ErrInvalidSignature, entry.Name,
		)
	case v.Trusts(sig.PublicKey):
		// A key we do trust, over content that is not what we were given:
		// the entry changed after it was signed.
		return fmt.Errorf("%w: signature does not match entry %q", ErrInvalidSignature, entry.Name)
	default:
		return fmt.Errorf(
			"%w: entry %q is signed by %s, which is not in signer.trusted_keys (%d trusted)",
			ErrInvalidSignature, entry.Name, KeyFingerprint(sig.PublicKey), len(v.trusted),
		)
	}
}

// KeyFingerprint names a public key without printing it: the hex SHA-256 of
// the key bytes, prefixed so a reader knows what they are looking at.
//
// Used in operator messages and in verification errors. It takes the public
// half only, so no formatting mistake at a call site can leak signing
// material -- the private key has no path into this function.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// keyPEMType is the PEM block type used by LoadKey and WriteKey.
const keyPEMType = "PRIVATE KEY"

// GenerateKey returns a fresh Ed25519 private key from crypto/rand.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("signer: generate key: %w", err)
	}
	return key, nil
}

// LoadKey reads the Ed25519 signing key stored at path.
//
// # File format
//
// A single PEM block of type "PRIVATE KEY" whose contents are the key in
// PKCS#8 DER (RFC 5958) -- the same shape `openssl genpkey -algorithm
// ed25519` writes, so the key is inspectable and replaceable with ordinary
// tooling and is not locked into a format only this program understands.
// WriteKey produces exactly this.
//
// # Permissions
//
// The key lives in its own file on the gateway host, owner-readable only
// (design/adr/0006-signing-key-and-signature-storage.md item 1). LoadKey
// refuses a file that any group or other user can read: on a shared host
// that is the difference between one operator being able to sign entries
// and anyone with a login being able to. The check is on the already-open
// file descriptor rather than a separate stat of the path, so the file
// whose mode is checked is the file whose bytes are read.
//
// No error returned by LoadKey contains key material.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open key file %s: %w", ErrNoKey, path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot stat key file %s: %w", ErrNoKey, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: key file %s is not a regular file", ErrNoKey, path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf(
			"%w: key file %s is group- or world-readable (mode %04o); "+
				"the signing key must be readable only by its owner -- chmod 600 %s",
			ErrNoKey, path, perm, path,
		)
	}

	// Read from the same descriptor whose mode was just checked, not by
	// re-opening path, so there is no window in which the file could be
	// swapped between the permission check and the read.
	pemBytes, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read key file %s: %w", ErrNoKey, path, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != keyPEMType {
		return nil, fmt.Errorf("%w: key file %s is not a PEM %q block", ErrNoKey, path, keyPEMType)
	}

	// Parse failures are reported with a fixed message rather than by
	// wrapping the x509/asn1 error: those messages can quote fragments of
	// the input they choked on, and the input here is private key
	// material.
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: key file %s does not contain a valid PKCS#8 private key", ErrNoKey, path)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: key file %s contains a %T, not an ed25519 private key", ErrNoKey, path, parsed)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: key file %s contains a malformed ed25519 private key", ErrNoKey, path)
	}
	return key, nil
}

// WriteKey writes key to path in the format LoadKey expects, creating the
// file with mode 0600.
//
// WriteKey refuses to overwrite an existing file: silently replacing a
// signing key would invalidate every signature made with the old one, and
// that should be a deliberate act (remove the old file first), not a
// side effect of running a command twice.
//
// No error returned by WriteKey contains key material.
func WriteKey(path string, key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: refusing to write a malformed ed25519 private key", ErrNoKey)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("signer: marshal key for %s: cannot encode as PKCS#8", path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("signer: create key file %s: %w", path, err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: keyPEMType, Bytes: der}); err != nil {
		return fmt.Errorf("signer: write key file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("signer: close key file %s: %w", path, err)
	}
	return nil
}
