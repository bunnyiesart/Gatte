package signer

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

// irisEntry is the shape of a real entry from AGENTS.md §1: a stdio server
// spawned through docker, whose credentials reach it as environment
// variables the Credential Vault resolves at spawn time. The entry itself
// holds only the variable *names*.
func irisEntry() registry.UpstreamServer {
	return registry.UpstreamServer{
		Name:        "casemgmt",
		Transport:   registry.TransportStdio,
		Command:     "docker",
		Args:        []string{"run", "--rm", "-i", "casemgmt-mcp:latest"},
		EnvVarNames: []string{"CASEMGMT_API_KEY", "CASEMGMT_URL"},
		CreatedAt:   time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
	}
}

func newSigner(t *testing.T) *Signer {
	t.Helper()

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// newVerifier builds the trust anchor the gateway would build from
// signer.trusted_keys, out of the signers whose keys the test says are
// trusted. Passing none is the "trust nobody" case.
func newVerifier(t *testing.T, trusted ...*Signer) *Verifier {
	t.Helper()

	keys := make([]ed25519.PublicKey, 0, len(trusted))
	for _, s := range trusted {
		keys = append(keys, s.PublicKey())
	}
	v, err := NewVerifier(keys)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestCredentialRotationDoesNotInvalidateSignature is the test
// design/adr/0003-security-controls.md names explicitly, and the reason
// the canonical form excludes secret values in the first place.
//
// A rotation in this system changes a secret's *value*, which lives in the
// sops-encrypted store the Credential Vault reads -- never in the registry
// entry. So the entry after a rotation is the same entry, with the same
// EnvVarNames, and the signature must still verify.
//
// # Why this test is shaped the way it is
//
// It used to read `before := irisEntry(); sig := Sign(before); after :=
// irisEntry()` and then assert Canonical(before) == Canonical(after). Those
// two values are byte-identical by construction, so the assertion was
// Canonical(x) == Canonical(x): it would have passed against an
// implementation that hashed the secret values, against one that hashed
// nothing at all, and against every bug it was cited as ruling out. A test
// that cannot fail is not evidence, and ADR-0006 cited this one as evidence.
//
// So the rotation is modelled where it actually happens -- in the vault --
// and the entry is *derived* from the vault's contents rather than written
// out twice by hand. The setup guard below is what the old version lacked:
// it fails the test if the two vault states are the same, so a refactor
// that quietly stops rotating anything is caught rather than rewarded.
func TestCredentialRotationDoesNotInvalidateSignature(t *testing.T) {
	// The Credential Vault, before and after rotating CASEMGMT_API_KEY. Values
	// live here and nowhere else; the whole design rests on them having no
	// path into a registry entry.
	vaultBefore := map[string]string{
		"CASEMGMT_API_KEY": "casemgmt-key-BEFORE-8f31c0d2",
		"CASEMGMT_URL":     "https://casemgmt.soc.internal",
	}
	vaultAfter := map[string]string{
		"CASEMGMT_API_KEY": "casemgmt-key-AFTER-4a97e15b",
		"CASEMGMT_URL":     "https://casemgmt.soc.internal",
	}
	if maps.Equal(vaultBefore, vaultAfter) {
		t.Fatal("test setup: nothing was rotated, so this test would assert nothing")
	}

	// entryFor builds the registry entry the Operator would have written
	// for a given vault state. It copies the *names* across and cannot copy
	// a value even by accident, because UpstreamServer has no field to put
	// one in -- which is the property under test.
	entryFor := func(v map[string]string) registry.UpstreamServer {
		e := irisEntry()
		e.EnvVarNames = slices.Sorted(maps.Keys(v))
		return e
	}

	before := entryFor(vaultBefore)
	s := newSigner(t)
	verifier := newVerifier(t, s)
	sig := s.Sign(before)

	// A rotation is also a write, and a write moves UpdatedAt. Including
	// that here keeps the test honest about what a real rotation leaves
	// behind, rather than testing an idealised no-op.
	after := entryFor(vaultAfter)
	after.UpdatedAt = before.UpdatedAt.Add(90 * time.Minute)

	if !bytes.Equal(Canonical(before), Canonical(after)) {
		t.Error("canonical bytes changed across a credential rotation; the hash must not depend on secret values")
	}
	if err := verifier.Verify(after, sig); err != nil {
		t.Errorf("Verify after rotation = %v, want nil", err)
	}

	// And the direct statement of ADR-0003 item 3: neither the old nor the
	// new secret is anywhere in the bytes a signature covers. This is what
	// makes the equality above mean something rather than being an accident
	// of how the two entries were built.
	signed := Canonical(after)
	for _, secret := range []string{vaultBefore["CASEMGMT_API_KEY"], vaultAfter["CASEMGMT_API_KEY"]} {
		if bytes.Contains(signed, []byte(secret)) {
			t.Errorf("a secret value reached the signed bytes: %q", secret)
		}
	}
}

// TestVerify_RefusesAnEntryResignedWithAnUntrustedKey is the regression
// test for design/adr/0010-signature-trust-anchor.md, and it reproduces the
// attack that ADR recorded as proven against the code as it stood.
//
// Verification used to run against sig.PublicKey -- the key stored in the
// signature row, in the same SQLite file as the entry it attests to. So an
// attacker with write access to that file did this:
//
//  1. rewrite the entry's Command to /tmp/evil;
//  2. generate a fresh Ed25519 pair, sign the rewritten entry with it, and
//     write the signature and the new public key into the signature row.
//
// Both halves are one permission -- the two tables share a file -- and the
// result verified. `upstream list` printed SIGNED: yes. require_signed did
// not help, because the entry *was* signed. The gateway would then spawn
// /tmp/evil with every credential the entry names injected into it.
//
// Step 1 alone was always refused and is asserted here too, because the
// difference between the two steps is the entire point: the old code got
// the easy half right, which is what made the missing half easy to miss.
func TestVerify_RefusesAnEntryResignedWithAnUntrustedKey(t *testing.T) {
	operator := newSigner(t)
	verifier := newVerifier(t, operator)

	entry := irisEntry()
	legitimate := operator.Sign(entry)
	if err := verifier.Verify(entry, legitimate); err != nil {
		t.Fatalf("test setup: the operator's own signature must verify: %v", err)
	}

	tampered := irisEntry()
	tampered.Command = "/tmp/evil"
	if bytes.Equal(Canonical(entry), Canonical(tampered)) {
		t.Fatal("test setup: the tampered entry is indistinguishable from the original")
	}

	// Step 1: tamper, present the legitimate signature.
	if err := verifier.Verify(tampered, legitimate); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("tampered entry with the operator's signature = %v, want ErrInvalidSignature", err)
	}

	// Step 2: tamper, then re-sign with a key nobody put in trusted_keys.
	// Internally consistent, and worthless: it says only that whoever made
	// this pair made both halves of it.
	attacker := newSigner(t)
	forged := attacker.Sign(tampered)
	if ed25519.Verify(attacker.PublicKey(), Canonical(tampered), forged.Bytes) != true {
		t.Fatal("test setup: the forged pair is not self-consistent, so it does not model the attack")
	}
	if err := verifier.Verify(tampered, forged); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("FORGERY ACCEPTED: tampered entry re-signed with an untrusted key = %v, want ErrInvalidSignature", err)
	}

	// The untampered entry re-signed by the attacker must go the same way.
	// Otherwise an attacker who cannot change an entry could still take
	// ownership of the signature on it, and the next rotation of the real
	// key would silently leave their key as the one that vouches for it.
	if err := verifier.Verify(entry, attacker.Sign(entry)); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("untouched entry signed by an untrusted key = %v, want ErrInvalidSignature", err)
	}
}

// TestVerify_TrustsEveryConfiguredKey pins what makes key rotation possible
// without a window in which nothing verifies: trusted_keys is a list, and
// any key in it is sufficient. ADR-0010 names this as the reason the field
// is plural.
func TestVerify_TrustsEveryConfiguredKey(t *testing.T) {
	retiring := newSigner(t)
	incoming := newSigner(t)
	verifier := newVerifier(t, retiring, incoming)

	entry := irisEntry()
	for name, s := range map[string]*Signer{"retiring key": retiring, "incoming key": incoming} {
		t.Run(name, func(t *testing.T) {
			if err := verifier.Verify(entry, s.Sign(entry)); err != nil {
				t.Errorf("Verify = %v, want nil -- both keys in trusted_keys must be accepted", err)
			}
		})
	}

	// Removing a key from the list is what actually retires it. After that
	// the entry it signed is refused, which is the operator's cue to
	// re-sign -- not something that fails quietly.
	narrowed := newVerifier(t, incoming)
	if err := narrowed.Verify(entry, retiring.Sign(entry)); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify with the retired key removed = %v, want ErrInvalidSignature", err)
	}
}

// TestVerify_WithNoTrustedKeysRefusesEverything covers the "trust nobody"
// configuration. It is reachable only with require_signed = false --
// config.Config.Validate refuses the other combination -- and in it a
// signature cannot mean anything, so it must not be treated as if it did.
func TestVerify_WithNoTrustedKeysRefusesEverything(t *testing.T) {
	s := newSigner(t)
	entry := irisEntry()
	verifier := newVerifier(t)

	if got := verifier.TrustedCount(); got != 0 {
		t.Fatalf("test setup: TrustedCount = %d, want 0", got)
	}
	if err := verifier.Verify(entry, s.Sign(entry)); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify with an empty trusted set = %v, want ErrInvalidSignature", err)
	}
}

func TestNewVerifier_RejectsAMalformedTrustAnchor(t *testing.T) {
	good := newSigner(t).PublicKey()

	tests := map[string][]ed25519.PublicKey{
		"nil key":       {nil},
		"truncated key": {good[:len(good)-1]},
		"good then bad": {good, make(ed25519.PublicKey, 8)},
	}

	for name, keys := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifier(keys); !errors.Is(err, ErrNoKey) {
				t.Errorf("NewVerifier = %v, want ErrNoKey -- a malformed trust anchor must not be silently dropped", err)
			}
		})
	}
}

// TestNewVerifier_CopiesTheTrustedSet: the caller's slice is configuration
// that has already been reviewed. A Verifier that aliased it could have its
// trust anchor changed after construction by anything holding the original.
func TestNewVerifier_CopiesTheTrustedSet(t *testing.T) {
	trusted := newSigner(t)
	attacker := newSigner(t)

	keys := []ed25519.PublicKey{trusted.PublicKey()}
	v, err := NewVerifier(keys)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	keys[0] = attacker.PublicKey()

	entry := irisEntry()
	if err := v.Verify(entry, trusted.Sign(entry)); err != nil {
		t.Errorf("the originally trusted key stopped verifying after the caller's slice was mutated: %v", err)
	}
	if err := v.Verify(entry, attacker.Sign(entry)); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("mutating the caller's slice changed whom the Verifier trusts: %v", err)
	}
}

func TestVerifier_Trusts(t *testing.T) {
	known := newSigner(t)
	unknown := newSigner(t)
	v := newVerifier(t, known)

	if !v.Trusts(known.PublicKey()) {
		t.Error("Trusts(configured key) = false, want true")
	}
	if v.Trusts(unknown.PublicKey()) {
		t.Error("Trusts(unconfigured key) = true, want false")
	}
	if v.Trusts(nil) {
		t.Error("Trusts(nil) = true, want false")
	}
}

// TestCanonicalIgnoresTimestamps pins the other exclusion: an unrelated
// write bumps UpdatedAt, and a signature must survive it.
func TestCanonicalIgnoresTimestamps(t *testing.T) {
	entry := irisEntry()

	s := newSigner(t)
	sig := s.Sign(entry)

	touched := irisEntry()
	touched.UpdatedAt = entry.UpdatedAt.Add(72 * time.Hour)
	touched.CreatedAt = entry.CreatedAt.Add(-time.Second)

	if !bytes.Equal(Canonical(entry), Canonical(touched)) {
		t.Error("canonical bytes changed when only CreatedAt/UpdatedAt moved; timestamps must be excluded")
	}
	if err := newVerifier(t, s).Verify(touched, sig); err != nil {
		t.Errorf("Verify after timestamp bump = %v, want nil", err)
	}
}

func TestCanonicalIsIndependentOfEnvVarNameOrder(t *testing.T) {
	entry := irisEntry()
	reordered := irisEntry()
	slices.Reverse(reordered.EnvVarNames)

	if slices.Equal(entry.EnvVarNames, reordered.EnvVarNames) {
		t.Fatal("test setup: reordered entry has the same env var order as the original")
	}
	if !bytes.Equal(Canonical(entry), Canonical(reordered)) {
		t.Error("canonical bytes changed when EnvVarNames were merely reordered; names must be sorted before hashing")
	}
}

func TestCanonicalChangesWhenAnEnvVarNameIsAdded(t *testing.T) {
	entry := irisEntry()
	extended := irisEntry()
	extended.EnvVarNames = append(extended.EnvVarNames, "CASEMGMT_DEBUG_TOKEN")

	if bytes.Equal(Canonical(entry), Canonical(extended)) {
		t.Error("canonical bytes unchanged after adding an env var name; a new variable is a real change to what the upstream is handed")
	}
}

func TestCanonicalDoesNotMutateItsInput(t *testing.T) {
	entry := irisEntry()
	entry.EnvVarNames = []string{"Z_LAST", "A_FIRST"}
	original := slices.Clone(entry.EnvVarNames)

	Canonical(entry)

	if !slices.Equal(entry.EnvVarNames, original) {
		t.Errorf("Canonical reordered the caller's EnvVarNames: got %v, want %v", entry.EnvVarNames, original)
	}
}

// TestCanonicalEncodingIsUnambiguous constructs the collisions a naive
// concatenation would produce. Each pair differs only in where a field
// boundary falls; under "just glue the strings together" every pair hashes
// identically, which would let a signature obtained for one entry
// authenticate the other.
func TestCanonicalEncodingIsUnambiguous(t *testing.T) {
	base := func() registry.UpstreamServer {
		return registry.UpstreamServer{
			Name:      "svc",
			Transport: registry.TransportStdio,
			Command:   "x",
		}
	}

	withCmdArgs := func(cmd string, args ...string) registry.UpstreamServer {
		s := base()
		s.Command = cmd
		s.Args = args
		return s
	}

	tests := []struct {
		name string
		a, b registry.UpstreamServer
	}{
		{
			// Boundary moved between Command and the first Arg:
			// naive concat is "dockerrun" both ways.
			name: "command/arg boundary",
			a:    withCmdArgs("docker", "run"),
			b:    withCmdArgs("dockerrun"),
		},
		{
			// Boundary moved between two Args: naive concat is
			// "docker" + "runiris" both ways.
			name: "arg/arg boundary",
			a:    withCmdArgs("docker", "run", "casemgmt"),
			b:    withCmdArgs("docker", "runiris"),
		},
		{
			// Boundary moved between the last Arg and the first env var
			// name -- the one that matters most, because it lets an
			// attacker smuggle an extra environment variable in as part
			// of an argument (or vice versa).
			name: "arg/envvarname boundary",
			a: func() registry.UpstreamServer {
				s := withCmdArgs("docker", "run")
				s.EnvVarNames = []string{"API_KEY"}
				return s
			}(),
			b: withCmdArgs("docker", "runAPI_KEY"),
		},
		{
			// Boundary moved between two env var names.
			name: "envvarname/envvarname boundary",
			a: func() registry.UpstreamServer {
				s := base()
				s.EnvVarNames = []string{"AAA", "BBB"}
				return s
			}(),
			b: func() registry.UpstreamServer {
				s := base()
				s.EnvVarNames = []string{"AAABBB"}
				return s
			}(),
		},
		{
			// An empty trailing arg must not be invisible.
			name: "empty trailing arg",
			a:    withCmdArgs("docker", "run"),
			b:    withCmdArgs("docker", "run", ""),
		},
		{
			// Boundary moved between Name and Transport/Command.
			name: "name/command boundary",
			a: func() registry.UpstreamServer {
				s := withCmdArgs("docker")
				s.Name = "casemgmt"
				return s
			}(),
			b: func() registry.UpstreamServer {
				s := withCmdArgs("sdocker")
				s.Name = "iri"
				return s
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bytes.Equal(Canonical(tt.a), Canonical(tt.b)) {
				t.Errorf("two distinct entries produced identical canonical bytes:\n a = %+v\n b = %+v", tt.a, tt.b)
			}
		})
	}
}

func TestSignThenVerify_Succeeds(t *testing.T) {
	entry := irisEntry()
	s := newSigner(t)

	sig := s.Sign(entry)

	if len(sig.Bytes) != ed25519.SignatureSize {
		t.Errorf("signature is %d bytes, want %d", len(sig.Bytes), ed25519.SignatureSize)
	}
	if !sig.PublicKey.Equal(s.PublicKey()) {
		t.Error("signature carries a public key that is not the signer's")
	}
	if err := newVerifier(t, s).Verify(entry, sig); err != nil {
		t.Errorf("Verify = %v, want nil", err)
	}
}

// TestVerify_DetectsTampering covers the three mutations ADR-0003's threat
// model cares about: a swapped binary, swapped arguments, and a smuggled
// environment variable.
func TestVerify_DetectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(registry.UpstreamServer) registry.UpstreamServer
	}{
		{
			name: "command replaced",
			tamper: func(s registry.UpstreamServer) registry.UpstreamServer {
				s.Command = "/tmp/evil"
				return s
			},
		},
		{
			name: "args replaced",
			tamper: func(s registry.UpstreamServer) registry.UpstreamServer {
				s.Args = []string{"run", "--rm", "-i", "attacker/casemgmt-mcp:latest"}
				return s
			},
		},
		{
			name: "env var name added",
			tamper: func(s registry.UpstreamServer) registry.UpstreamServer {
				s.EnvVarNames = append(slices.Clone(s.EnvVarNames), "THREATINTEL_VIRUSTOTAL_API_KEY")
				return s
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := irisEntry()
			s := newSigner(t)
			sig := s.Sign(entry)

			err := newVerifier(t, s).Verify(tt.tamper(entry), sig)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("Verify(tampered) = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

// TestVerify_RejectsSignatureFromAnotherKey covers the mismatch inside one
// signature row: the bytes were made by key A, the row claims key B. Both
// keys are trusted here, so what is being tested is Ed25519 itself and not
// the trust anchor -- the row must not be accepted just because the key it
// names happens to be in trusted_keys.
func TestVerify_RejectsSignatureFromAnotherKey(t *testing.T) {
	entry := irisEntry()
	keyA := newSigner(t)
	keyB := newSigner(t)
	verifier := newVerifier(t, keyA, keyB)

	sig := keyA.Sign(entry)

	// A's signature bytes over a *different* entry, presented under B's
	// name. Neither trusted key verifies these bytes over this entry.
	other := irisEntry()
	other.Command = "/usr/bin/podman"
	forged := Signature{Bytes: keyA.Sign(other).Bytes, PublicKey: keyB.PublicKey()}

	if err := verifier.Verify(entry, forged); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify(signature over another entry, claimed as key B) = %v, want ErrInvalidSignature", err)
	}
	// And key B's own signature over the same entry must differ from A's,
	// so the two are not silently interchangeable.
	if bytes.Equal(sig.Bytes, keyB.Sign(entry).Bytes) {
		t.Error("two different keys produced identical signature bytes")
	}
}

func TestVerify_RejectsMalformedSignature(t *testing.T) {
	entry := irisEntry()
	s := newSigner(t)
	valid := s.Sign(entry)

	tests := map[string]Signature{
		"zero value":       {},
		"no public key":    {Bytes: valid.Bytes},
		"no signature":     {PublicKey: valid.PublicKey},
		"truncated sig":    {Bytes: valid.Bytes[:len(valid.Bytes)-1], PublicKey: valid.PublicKey},
		"truncated pubkey": {Bytes: valid.Bytes, PublicKey: valid.PublicKey[:len(valid.PublicKey)-1]},
	}

	verifier := newVerifier(t, s)
	for name, sig := range tests {
		t.Run(name, func(t *testing.T) {
			if err := verifier.Verify(entry, sig); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("Verify = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestNewSigner_RejectsMissingOrMalformedKey(t *testing.T) {
	tests := map[string]ed25519.PrivateKey{
		"nil key":       nil,
		"truncated key": make(ed25519.PrivateKey, ed25519.PrivateKeySize-1),
	}

	for name, key := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSigner(key); !errors.Is(err, ErrNoKey) {
				t.Errorf("NewSigner = %v, want ErrNoKey", err)
			}
		})
	}
}

func TestLoadKey_RoundTripsAWrittenKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")

	want, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := WriteKey(path, want); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("WriteKey created the key file with mode %04o, want 0600", perm)
	}

	got, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !got.Equal(want) {
		t.Error("LoadKey returned a different key than WriteKey wrote")
	}

	// A key that survived the round trip must still produce verifiable
	// signatures -- the point of the file, not just of the bytes.
	s, err := NewSigner(got)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	entry := irisEntry()
	if err := newVerifier(t, s).Verify(entry, s.Sign(entry)); err != nil {
		t.Errorf("Verify with loaded key = %v, want nil", err)
	}
}

func TestWriteKey_RefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := WriteKey(path, key); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	other, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := WriteKey(path, other); err == nil {
		t.Fatal("WriteKey overwrote an existing key file, want an error")
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !loaded.Equal(key) {
		t.Error("the original key was replaced despite WriteKey reporting an error")
	}
}

func TestLoadKey_RefusesGroupOrWorldReadableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signing.key")

			key, err := GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if err := WriteKey(path, key); err != nil {
				t.Fatalf("WriteKey: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("Chmod: %v", err)
			}

			_, err = LoadKey(path)
			if !errors.Is(err, ErrNoKey) {
				t.Fatalf("LoadKey(mode %04o) = %v, want ErrNoKey", mode.Perm(), err)
			}
			// The operator has to be able to tell *why* it was refused.
			if !strings.Contains(err.Error(), "group- or world-readable") {
				t.Errorf("LoadKey error does not name the problem: %v", err)
			}
		})
	}
}

func TestLoadKey_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.key")

	if _, err := LoadKey(path); !errors.Is(err, ErrNoKey) {
		t.Errorf("LoadKey(missing) = %v, want ErrNoKey", err)
	}
}

func TestLoadKey_RejectsNonPEMContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")

	if err := os.WriteFile(path, []byte("not a pem block at all\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadKey(path); !errors.Is(err, ErrNoKey) {
		t.Errorf("LoadKey(non-PEM) = %v, want ErrNoKey", err)
	}
}

// TestKeyMaterialNeverAppearsInErrors guards the rule that no error path
// out of this package may quote the private key.
func TestKeyMaterialNeverAppearsInErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := WriteKey(path, key); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Every failing path we can provoke against a real key file.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	_, permErr := LoadKey(path)

	corrupt := filepath.Join(dir, "corrupt.key")
	if err := os.WriteFile(corrupt, append(raw[:len(raw)/2], []byte("\n-----END PRIVATE KEY-----\n")...), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, parseErr := LoadKey(corrupt)

	_, noKeyErr := NewSigner(key[:10])

	for _, err := range []error{permErr, parseErr, noKeyErr} {
		if err == nil {
			t.Fatal("expected an error on every provoked failure path")
		}
		msg := err.Error()
		if strings.Contains(msg, string(key)) {
			t.Errorf("error leaks raw private key bytes: %v", err)
		}
		if bytes.Contains([]byte(msg), key.Seed()) {
			t.Errorf("error leaks the private key seed: %v", err)
		}
	}
}
