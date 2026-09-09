package sopsage_test

import (
	"context"
	"errors"
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
	secretsFile, ageKeyFile := newFixtureRaw(t, `{"NESTED":{"leaked":"s3cr3t"}}`)

	_, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err == nil {
		t.Fatal("New with malformed plaintext: expected an error, got nil")
	}
	if got := err.Error(); containsFold(got, "s3cr3t") {
		t.Fatalf("LEAK: New's error message echoes decrypted content: %q", got)
	}
}
