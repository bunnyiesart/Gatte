package sopsage_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
)

func TestProviderResolve(t *testing.T) {
	secretsFile, ageKeyFile := newFixture(t, map[string]string{
		"THREATINTEL_VT_KEY": "vt-abc123-topsecret",
		"CASEMGMT_TOKEN":     "casemgmt-xyz789-topsecret",
	})

	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := p.Resolve(context.Background(), "THREATINTEL_VT_KEY")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Value() != "vt-abc123-topsecret" {
		t.Errorf("Value() = %q, want %q", got.Value(), "vt-abc123-topsecret")
	}
}

func TestProviderResolveNotFound(t *testing.T) {
	secretsFile, ageKeyFile := newFixture(t, map[string]string{"A": "b"})

	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.Resolve(context.Background(), "MISSING")
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Resolve error = %v, want ErrNotFound", err)
	}
}

// TestNewRejectsWrongAgeIdentity confirms decryption genuinely depends on
// holding the matching age private key -- not, say, on the file merely
// looking like valid sops JSON.
func TestNewRejectsWrongAgeIdentity(t *testing.T) {
	secretsFile, _ := newFixture(t, map[string]string{"A": "b"})
	_, wrongKeyFile := newFixture(t, map[string]string{"unused": "unused"}) // a different keypair entirely

	_, err := sopsage.New(context.Background(), secretsFile, wrongKeyFile)
	if err == nil {
		t.Fatal("New with the wrong age identity: expected an error, got nil")
	}
}

// TestNewErrorDoesNotLeakOnMalformedPlaintext confirms that when the
// decrypted document doesn't parse as a flat string map, the returned
// error is a fixed message -- not one that echoes fragments of the
// decrypted plaintext back into whatever logs or reporting tool
// eventually prints the error (encoding/json's own error type does
// exactly that, which is why New deliberately does not %w-wrap it -- see
// provider.go).
func TestNewErrorDoesNotLeakOnMalformedPlaintext(t *testing.T) {
	// A JSON object, since sops itself refuses to encrypt anything else
	// as a top-level document -- but with a nested value where this
	// adapter's contract requires a flat object of string values.
	// The marker is in the KEY as well as the value, and that is the whole
	// difference between this test and the one it replaces.
	//
	// The old fixture put the marker only in a nested VALUE. encoding/json's
	// UnmarshalTypeError names the offending FIELD and the Go type -- never
	// the data -- so %w-wrapping it, the exact mutation this test's own
	// comment says it guards against, would not have echoed the marker and
	// the test would have passed. It could only ever catch a much cruder
	// leak (the whole plaintext interpolated), while claiming to catch the
	// subtle one.
	//
	// With the marker in the key, wrapping the json error DOES surface it,
	// so the test now fails for the mutation it was written for.
	secretsFile, ageKeyFile := newFixtureRaw(t, `{"s3cr3t":{"leaked":"s3cr3t"}}`)

	_, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err == nil {
		t.Fatal("New with malformed plaintext: expected an error, got nil")
	}
	if got := err.Error(); containsFold(got, "s3cr3t") {
		t.Fatalf("LEAK: New's error message echoes decrypted content: %q", got)
	}
}

// TestNewRefusesAgeIdentityReadableByOthers pins GAB-26: the age identity
// decrypts every backend credential the gateway holds, and until now
// nothing checked its permissions -- while signer.LoadKey enforced exactly
// this for the *signing* key, which is the less dangerous of the two.
//
// A group- or world-readable age identity means any local account can
// decrypt the vault and read every production API key: precisely the
// outcome this project was built to prevent, since the reason it exists is
// credentials sitting readable on analyst laptops.
//
// Written against the pre-fix code first, where every mode below was
// accepted, so the refusal is evidence rather than decoration.
func TestNewRefusesAgeIdentityReadableByOthers(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o666, 0o777} {
		t.Run(fmt.Sprintf("mode_%04o", mode), func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "age.key")
			if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-PLACEHOLDER\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Written 0600 then chmodded, because WriteFile's mode is
			// masked by the process umask and would otherwise silently
			// produce a stricter file than the case under test.
			if err := os.Chmod(keyPath, mode); err != nil {
				t.Fatal(err)
			}
			secretsPath := filepath.Join(dir, "secrets.json")
			if err := os.WriteFile(secretsPath, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := sopsage.New(context.Background(), secretsPath, keyPath)
			if err == nil {
				t.Fatalf("New accepted an age identity with mode %04o; it must be refused", mode)
			}
			// The message has to tell an operator what to type. A refusal
			// they cannot act on gets worked around, not fixed.
			if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("refusal does not name the fix: %v", err)
			}
		})
	}

	t.Run("owner_only_is_accepted", func(t *testing.T) {
		// The control: without it, a New() that rejected everything --
		// including a correct key -- would pass every case above.
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "age.key")
		if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-PLACEHOLDER\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatal(err)
		}
		secretsPath := filepath.Join(dir, "secrets.json")
		if err := os.WriteFile(secretsPath, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := sopsage.New(context.Background(), secretsPath, keyPath)
		if err != nil && strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("a correctly-permissioned key was refused by the permission check: %v", err)
		}
	})
}

// TestDecryptErrorDoesNotCarrySopsStderr pins a guarantee provider.go
// states twice and nothing tested: sops's stderr is discarded rather than
// wired into the returned error.
//
// The reason is in New's doc comment -- sops's diagnostics can echo
// fragments of the file it was decrypting -- and the mutation that breaks
// it is one line: point cmd.Stderr at a buffer and interpolate it. Both
// halves of the guarantee (the discard, and the error staying quiet)
// survived the whole suite untested until now.
//
// The failure is provoked with an age identity that cannot decrypt this
// file, which is the ordinary way sops fails loudly.
func TestDecryptErrorDoesNotCarrySopsStderr(t *testing.T) {
	secretsFile, _ := newFixture(t, map[string]string{"CASEMGMT_API_TOKEN": "tok-fake-do-not-echo-me"})
	// A DIFFERENT identity: valid in form, wrong for this file.
	_, wrongKeyFile := newFixture(t, map[string]string{"OTHER": "x"})

	_, err := sopsage.New(context.Background(), secretsFile, wrongKeyFile)
	if err == nil {
		t.Fatal("decrypting with the wrong identity succeeded; this test is not exercising a failure")
	}

	msg := err.Error()
	// Non-vacuity: the error must actually be sops failing, or the
	// assertions below hold trivially.
	if !containsFold(msg, "sops") {
		t.Fatalf("the error is not a sops failure, so this proves nothing: %q", msg)
	}
	for _, forbidden := range []string{"tok-fake-do-not-echo-me", "CASEMGMT_API_TOKEN", "age1", "AGE-SECRET-KEY"} {
		if containsFold(msg, forbidden) {
			t.Errorf("LEAK: the decrypt error carries %q: %q", forbidden, msg)
		}
	}
}
