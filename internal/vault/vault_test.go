package vault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/vault"
)

// fakeProvider is a minimal in-memory vault.Provider used to test the
// contract against something that isn't the real sopsage adapter.
type fakeProvider map[string]string

func (f fakeProvider) Resolve(_ context.Context, name string) (vault.Secret, error) {
	v, ok := f[name]
	if !ok {
		return vault.Secret{}, vault.ErrNotFound
	}
	return vault.NewSecret(v), nil
}

func TestProviderResolve(t *testing.T) {
	p := fakeProvider{"THREATINTEL_VT_KEY": "vt-abc123"}

	got, err := p.Resolve(context.Background(), "THREATINTEL_VT_KEY")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Value() != "vt-abc123" {
		t.Errorf("Value() = %q, want %q", got.Value(), "vt-abc123")
	}
}

func TestProviderResolveNotFound(t *testing.T) {
	p := fakeProvider{}

	_, err := p.Resolve(context.Background(), "MISSING")
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Resolve error = %v, want ErrNotFound", err)
	}
}
