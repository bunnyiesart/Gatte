package sqlite_test

import (
	"context"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

// TestRepository_RemoteEntry_RoundTrip: a remote entry's URL, auth
// descriptor and remote kind -- every signed field -- come back as stored.
func TestRepository_RemoteEntry_RoundTrip(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()
	in := registry.UpstreamServer{
		Name:        "vendor",
		Transport:   registry.TransportRemote,
		URL:         "https://mcp.vendor.example/mcp",
		AuthKind:    registry.AuthHeader,
		AuthName:    "X-Api-Key",
		EnvVarNames: []string{"VENDOR_KEY"},
		RemoteKind:  registry.RemoteStreamable,
	}
	if err := repo.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := repo.Get(ctx, "vendor")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Transport != in.Transport || got.URL != in.URL || got.AuthKind != in.AuthKind ||
		got.AuthName != in.AuthName || got.RemoteKind != in.RemoteKind || len(got.EnvVarNames) != 1 {
		t.Errorf("round trip = %+v, want %+v", got, in)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("entry read back does not validate: %v", err)
	}
}
