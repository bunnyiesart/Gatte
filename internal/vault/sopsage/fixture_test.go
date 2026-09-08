package sopsage_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireBinary skips the test if name is not found on PATH. sops and
// age/age-keygen are external runtime prerequisites of the sopsage
// adapter (design/adr/0005-shell-out-to-sops-cli.md), not Go module
// dependencies, so a dev machine or CI image without them should skip
// these tests rather than fail the build.
func requireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found on PATH (required by design/adr/0005): %v", name, err)
	}
}

// newFixture generates a fresh, disposable age keypair and a
// sops-encrypted JSON secrets file for secrets, entirely inside
// t.TempDir(). Nothing produced here is committed to the repository --
// each test run mints its own throwaway key, so there is no key material
// in Git history for anyone to mistake for something real.
func newFixture(t *testing.T, secrets map[string]string) (secretsFile, ageKeyFile string) {
	t.Helper()
	plainJSON, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("marshal fixture secrets: %v", err)
	}
	return newFixtureRaw(t, string(plainJSON))
}

// newFixtureRaw is newFixture's counterpart for tests that need control
// over the plaintext's raw bytes (e.g. deliberately malformed JSON)
// rather than a map[string]string of secrets. Both generate a fresh
// age keypair and hand the plaintext to the real `sops --encrypt`, so
// the fixture a test decrypts is byte-for-byte what production `sops`
// would produce, not a hand-rolled approximation of its format.
func newFixtureRaw(t *testing.T, plaintext string) (secretsFile, ageKeyFile string) {
	t.Helper()
	requireBinary(t, "age-keygen")
	requireBinary(t, "sops")

	dir := t.TempDir()
	ageKeyFile, recipient := generateAgeKey(t, dir)

	plainFile := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(plainFile, []byte(plaintext), 0o600); err != nil {
		t.Fatalf("write plaintext fixture: %v", err)
	}

	var encrypted, encryptStderr bytes.Buffer
	encrypt := exec.Command("sops",
		"--encrypt",
		"--age", recipient,
		"--input-type", "json",
		"--output-type", "json",
		plainFile,
	)
	encrypt.Stdout = &encrypted
	encrypt.Stderr = &encryptStderr
	if err := encrypt.Run(); err != nil {
		t.Fatalf("sops --encrypt: %v: %s", err, encryptStderr.String())
	}

	secretsFile = filepath.Join(dir, "secrets.enc.json")
	if err := os.WriteFile(secretsFile, encrypted.Bytes(), 0o600); err != nil {
		t.Fatalf("write encrypted fixture: %v", err)
	}
	return secretsFile, ageKeyFile
}

// generateAgeKey runs age-keygen into dir and returns the identity file
// path plus the recipient ("age1...") public key it printed to stderr.
func generateAgeKey(t *testing.T, dir string) (ageKeyFile, recipient string) {
	t.Helper()
	ageKeyFile = filepath.Join(dir, "key.txt")

	var keygenStderr bytes.Buffer
	keygen := exec.Command("age-keygen", "-o", ageKeyFile)
	keygen.Stderr = &keygenStderr
	if err := keygen.Run(); err != nil {
		t.Fatalf("age-keygen: %v: %s", err, keygenStderr.String())
	}
	return ageKeyFile, parseRecipient(t, keygenStderr.String())
}

// parseRecipient extracts the "age1..." public key age-keygen prints to
// stderr (its documented output format: a "Public key: age1..." line).
func parseRecipient(t *testing.T, keygenStderr string) string {
	t.Helper()
	for _, line := range strings.Split(keygenStderr, "\n") {
		const prefix = "Public key: "
		if idx := strings.Index(line, prefix); idx != -1 {
			return strings.TrimSpace(line[idx+len(prefix):])
		}
	}
	t.Fatalf("could not find \"Public key: \" line in age-keygen output: %q", keygenStderr)
	return ""
}

// containsFold reports whether s contains substr, ignoring case.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
