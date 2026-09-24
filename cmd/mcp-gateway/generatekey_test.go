package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/signer"
)

// TestSignGenerateKey_WritesOwnerOnlyKeyAndPrintsItsPublicHalf covers
// runGenerateKey end to end (it had 0% statement coverage): the key file is
// created owner-only, it loads back as a signer key, and the trusted_keys
// line printed for the operator is that key's public half -- not some other
// key, which would make the pasted anchor trust nothing it signs.
func TestSignGenerateKey_WritesOwnerOnlyKeyAndPrintsItsPublicHalf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	var stdout, stderr bytes.Buffer

	if code := cmdSign([]string{"-generate-key", "-out", path}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr.String())
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("key file mode %v is readable by group/other", perm)
	}

	key, err := signer.LoadKey(path)
	if err != nil {
		t.Fatalf("written key does not load: %v", err)
	}
	want := trustedKeyLine(key.Public().(ed25519.PublicKey))
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("stdout does not print the written key's public half %q:\n%s", want, stdout.String())
	}
}

// TestSignGenerateKey_NeverClobbersAnExistingKey pins the rotation safety the
// command documents: an existing file at -out is left byte-for-byte intact
// and the command fails, because overwriting a signing key invalidates every
// signature it made.
func TestSignGenerateKey_NeverClobbersAnExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	orig := []byte("pre-existing key material")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	if code := cmdSign([]string{"-generate-key", "-out", path}, &stdout, &stderr); code != exitCannotRun {
		t.Fatalf("exit %d, want %d (exitCannotRun); stdout:\n%s", code, exitCannotRun, stdout.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("existing key file was modified: %q", got)
	}
	if !strings.Contains(stderr.String(), "left untouched") {
		t.Fatalf("stderr does not tell the operator the key was left untouched:\n%s", stderr.String())
	}
}
