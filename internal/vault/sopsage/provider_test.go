package sopsage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// ---------------------------------------------------------------------------
// Rotation (ADR-0023)
// ---------------------------------------------------------------------------

// reEncrypt replaces the encrypted file in place with a new document, the
// way `sops secrets.json` does for an operator rotating a credential.
func reEncrypt(t *testing.T, secretsFile, ageKeyFile string, secrets map[string]string) {
	t.Helper()

	// The recipient is recoverable from the identity file: age-keygen wrote
	// the public key into it as a comment, and sops needs the recipient,
	// not the identity, to encrypt.
	identity, err := os.ReadFile(ageKeyFile)
	if err != nil {
		t.Fatalf("read age identity: %v", err)
	}
	var recipient string
	for _, line := range strings.Split(string(identity), "\n") {
		if _, after, ok := strings.Cut(line, "# public key: "); ok {
			recipient = strings.TrimSpace(after)
		}
	}
	if recipient == "" {
		t.Fatalf("no recipient in %s; the fixture's shape changed", ageKeyFile)
	}

	plainJSON, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("marshal rotated secrets: %v", err)
	}
	dir := t.TempDir()
	plainFile := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(plainFile, plainJSON, 0o600); err != nil {
		t.Fatalf("write rotated plaintext: %v", err)
	}

	var encrypted, stderr bytes.Buffer
	cmd := exec.Command("sops", "--encrypt", "--age", recipient,
		"--input-type", "json", "--output-type", "json", plainFile)
	cmd.Stdout = &encrypted
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sops --encrypt: %v: %s", err, stderr.String())
	}
	if err := os.WriteFile(secretsFile, encrypted.Bytes(), 0o600); err != nil {
		t.Fatalf("rewrite encrypted fixture: %v", err)
	}
}

// TestResolveSeesARotationAfterTheFileChanges is the one that makes
// GAB-20's drift detection able to fire at all.
//
// Until ADR-0023 the Provider decrypted once and answered from a frozen
// map, so gateway.CredentialDrift -- which compares a digest taken at dial
// time against what Resolve returns now -- compared a value against itself.
// The control ran every tick, was documented in three places as working,
// and could not report a rotation. This test is the shape of that whole
// defect in six lines.
func TestResolveSeesARotationAfterTheFileChanges(t *testing.T) {
	const before, after = "vt-key-before-rotation", "vt-key-AFTER-rotation"

	secretsFile, ageKeyFile := newFixture(t, map[string]string{"VT_API_KEY": before})
	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := p.Resolve(context.Background(), "VT_API_KEY")
	if err != nil {
		t.Fatalf("Resolve before rotation: %v", err)
	}
	if got.Value() != before {
		t.Fatalf("Resolve = %q, want %q", got.Value(), before)
	}

	reEncrypt(t, secretsFile, ageKeyFile, map[string]string{"VT_API_KEY": after})

	got, err = p.Resolve(context.Background(), "VT_API_KEY")
	if err != nil {
		t.Fatalf("Resolve after rotation: %v", err)
	}
	if got.Value() != after {
		t.Errorf("Resolve = %q, want %q -- a rotation the operator performed is invisible, which is what made the drift warning inert", got.Value(), after)
	}
}

// TestResolveKeepsTheOldValueWhenTheFileGoesUnreadable is ADR-0023 item 2,
// and it is the same rule ADR-0013 sets for the quarantine: failing to
// measure is not evidence that something changed. A vault file that cannot
// be read for a moment must not stop the fleet from dialing.
func TestResolveKeepsTheOldValueWhenTheFileGoesUnreadable(t *testing.T) {
	const value = "vt-key-that-must-survive"

	secretsFile, ageKeyFile := newFixture(t, map[string]string{"VT_API_KEY": value})
	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.Resolve(context.Background(), "VT_API_KEY"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Gone, mid-incident.
	if err := os.Remove(secretsFile); err != nil {
		t.Fatalf("remove secrets file: %v", err)
	}

	got, err := p.Resolve(context.Background(), "VT_API_KEY")
	if err != nil {
		t.Fatalf("Resolve with the file gone = %v, want the previous value: an unreadable vault must not fail every dial", err)
	}
	if got.Value() != value {
		t.Errorf("Resolve = %q, want %q", got.Value(), value)
	}

	// And a file that is present but no longer decryptable is the same
	// case: a rotation caught half-written decrypts to garbage.
	if err := os.WriteFile(secretsFile, []byte("not sops output at all"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	got, err = p.Resolve(context.Background(), "VT_API_KEY")
	if err != nil {
		t.Fatalf("Resolve with an undecryptable file = %v, want the previous value", err)
	}
	if got.Value() != value {
		t.Errorf("Resolve = %q, want %q", got.Value(), value)
	}
}

// TestResolveDoesNotReDecryptWhenNothingChanged pins the cost side of
// ADR-0023 -- and, in the same assertion, the blind spot item 3 declares.
//
// The file is rewritten with a DIFFERENT value and then its modification
// time and size are restored, which is exactly the shape the stamp cannot
// see. The Provider must answer with the old value: proof that it did not
// re-run sops, because if it had it would have the new one.
//
// Read the failure of this test carefully if it ever comes: "it returned
// the new value" does not mean the vault got better, it means the cheap
// change-detection was replaced by something that reads the file every
// time, which is the option ADR-0023 rejected.
func TestResolveDoesNotReDecryptWhenNothingChanged(t *testing.T) {
	const before, after = "aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb" // same length

	secretsFile, ageKeyFile := newFixture(t, map[string]string{"VT_API_KEY": before})
	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := p.Resolve(context.Background(), "VT_API_KEY"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	info, err := os.Stat(secretsFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	reEncrypt(t, secretsFile, ageKeyFile, map[string]string{"VT_API_KEY": after})
	rotated, err := os.Stat(secretsFile)
	if err != nil {
		t.Fatalf("stat after rotation: %v", err)
	}
	if rotated.Size() != info.Size() {
		t.Skipf("the re-encrypted file changed size (%d -> %d), so the stamp legitimately sees it; this test needs a same-size rewrite",
			info.Size(), rotated.Size())
	}
	if err := os.Chtimes(secretsFile, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("restore mtime: %v", err)
	}

	got, err := p.Resolve(context.Background(), "VT_API_KEY")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Value() != before {
		t.Errorf("Resolve = %q, want %q -- the file's stamp did not move, so nothing should have been re-decrypted", got.Value(), before)
	}
}

// TestReloadFailureReachesTheHandler is the signal that did not exist
// between 15 and 16 Sep 2026 while three comments and an ADR said it did.
//
// The property is not "an error is returned" -- Resolve deliberately keeps
// answering from the last good copy, because a briefly unreadable file must
// not stop the fleet from dialing. The property is that somebody is TOLD:
// a gateway serving credentials it can no longer confirm, with a drift
// warning that is inert until the file comes back, is exactly the silent
// state ADR-0023 exists to end.
func TestReloadFailureReachesTheHandler(t *testing.T) {
	const value = "vt-key-under-test"

	secretsFile, ageKeyFile := newFixture(t, map[string]string{"VT_API_KEY": value})

	var mu sync.Mutex
	var reports []string
	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile,
		sopsage.WithReloadErrorHandler(func(err error) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, err.Error())
		}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	said := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(reports)
	}

	// Healthy: nothing to say.
	if _, err := p.Resolve(context.Background(), "VT_API_KEY"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := said(); len(got) != 0 {
		t.Fatalf("the handler was called %d times on a healthy vault: %v", len(got), got)
	}

	// The file goes away mid-incident.
	if err := os.Remove(secretsFile); err != nil {
		t.Fatalf("remove secrets file: %v", err)
	}
	for range 5 {
		if _, err := p.Resolve(context.Background(), "VT_API_KEY"); err != nil {
			t.Fatalf("Resolve while unreadable: %v", err)
		}
	}

	got := said()
	if len(got) != 1 {
		t.Fatalf("the handler was called %d times across five Resolves, want exactly 1: it is edge-triggered so one incident is one line, and a silent failure is the defect this test exists for.\n%v", len(got), got)
	}
	if !strings.Contains(got[0], secretsFile) {
		t.Errorf("the report does not name the file: %q", got[0])
	}
	if strings.Contains(got[0], value) {
		t.Errorf("LEAK: the report carries the secret: %q", got[0])
	}

	// And the recovery is said too, once.
	reEncrypt(t, secretsFile, ageKeyFile, map[string]string{"VT_API_KEY": value})
	for range 3 {
		if _, err := p.Resolve(context.Background(), "VT_API_KEY"); err != nil {
			t.Fatalf("Resolve after recovery: %v", err)
		}
	}
	if got := said(); len(got) != 2 {
		t.Errorf("the handler was called %d times in total, want 2 (one failure, one recovery): %v", len(got), got)
	}
}
