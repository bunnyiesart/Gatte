package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

func casemgmtEntry() registry.UpstreamServer {
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

func newSigner(t *testing.T) *signer.Signer {
	t.Helper()

	key, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := signer.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestMigrate_IsIdempotent(t *testing.T) {
	db := newTestDB(t) // already migrated once

	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("third Migrate: %v", err)
	}
}

func TestPutThenGet_PreservesBytesExactly(t *testing.T) {
	db := newTestDB(t)
	st := New(db)
	ctx := context.Background()

	entry := casemgmtEntry()
	want := newSigner(t).Sign(entry)

	if err := st.Put(ctx, entry.Name, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := st.Get(ctx, entry.Name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Bytes, want.Bytes) {
		t.Errorf("signature bytes changed in storage:\n got %x\nwant %x", got.Bytes, want.Bytes)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) {
		t.Errorf("public key bytes changed in storage:\n got %x\nwant %x", got.PublicKey, want.PublicKey)
	}

	// The round trip is only worth anything if what comes back still
	// verifies -- that, not byte equality, is what the boot-time check
	// will actually do with it.
	if err := signer.Verify(entry, got); err != nil {
		t.Errorf("Verify(stored signature) = %v, want nil", err)
	}
}

func TestGet_UnknownNameReturnsErrNotFound(t *testing.T) {
	db := newTestDB(t)
	st := New(db)

	if _, err := st.Get(context.Background(), "no-such-entry"); !errors.Is(err, signer.ErrNotFound) {
		t.Errorf("Get(unknown) = %v, want signer.ErrNotFound", err)
	}
}

func TestPut_ReplacesAnExistingSignature(t *testing.T) {
	db := newTestDB(t)
	st := New(db)
	ctx := context.Background()

	entry := casemgmtEntry()
	first := newSigner(t).Sign(entry)
	if err := st.Put(ctx, entry.Name, first); err != nil {
		t.Fatalf("Put (first): %v", err)
	}

	// Re-signing with a rotated signing key must land on the same row,
	// not fail on the primary key and leave the old signature in place.
	second := newSigner(t).Sign(entry)
	if err := st.Put(ctx, entry.Name, second); err != nil {
		t.Fatalf("Put (second): %v", err)
	}

	got, err := st.Get(ctx, entry.Name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Bytes, second.Bytes) || !bytes.Equal(got.PublicKey, second.PublicKey) {
		t.Error("Get returned the superseded signature after a second Put")
	}

	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM entry_signatures").Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 1 {
		t.Errorf("entry_signatures has %d rows after two Puts for one name, want 1", n)
	}
}

func TestPut_RejectsMalformedSignature(t *testing.T) {
	db := newTestDB(t)
	st := New(db)
	ctx := context.Background()

	valid := newSigner(t).Sign(casemgmtEntry())

	tests := map[string]signer.Signature{
		"zero value":       {},
		"no public key":    {Bytes: valid.Bytes},
		"no signature":     {PublicKey: valid.PublicKey},
		"truncated sig":    {Bytes: valid.Bytes[:ed25519.SignatureSize-1], PublicKey: valid.PublicKey},
		"truncated pubkey": {Bytes: valid.Bytes, PublicKey: valid.PublicKey[:ed25519.PublicKeySize-1]},
	}

	for name, sig := range tests {
		t.Run(name, func(t *testing.T) {
			if err := st.Put(ctx, "casemgmt", sig); !errors.Is(err, signer.ErrInvalidSignature) {
				t.Errorf("Put(malformed) = %v, want signer.ErrInvalidSignature", err)
			}
			if _, err := st.Get(ctx, "casemgmt"); !errors.Is(err, signer.ErrNotFound) {
				t.Errorf("a rejected Put stored a row anyway: Get = %v, want signer.ErrNotFound", err)
			}
		})
	}
}

func TestDelete_RemovesThenReportsNotFound(t *testing.T) {
	db := newTestDB(t)
	st := New(db)
	ctx := context.Background()

	entry := casemgmtEntry()
	if err := st.Put(ctx, entry.Name, newSigner(t).Sign(entry)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := st.Delete(ctx, entry.Name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get(ctx, entry.Name); !errors.Is(err, signer.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want signer.ErrNotFound", err)
	}
	if err := st.Delete(ctx, entry.Name); !errors.Is(err, signer.ErrNotFound) {
		t.Errorf("second Delete = %v, want signer.ErrNotFound", err)
	}
}

func TestDelete_UnknownNameReturnsErrNotFound(t *testing.T) {
	db := newTestDB(t)
	st := New(db)

	if err := st.Delete(context.Background(), "no-such-entry"); !errors.Is(err, signer.ErrNotFound) {
		t.Errorf("Delete(unknown) = %v, want signer.ErrNotFound", err)
	}
}

// TestSignaturesAreKeyedPerEntry confirms two entries do not share a row --
// the table is keyed by entry name, per ADR-0006 item 2.
func TestSignaturesAreKeyedPerEntry(t *testing.T) {
	db := newTestDB(t)
	st := New(db)
	ctx := context.Background()

	s := newSigner(t)

	casemgmt := casemgmtEntry()
	threatintel := casemgmtEntry()
	threatintel.Name = "threatintel"
	threatintel.Args = []string{"run", "--rm", "-i", "threatintel-mcp:latest"}
	threatintel.EnvVarNames = []string{"THREATINTEL_SHODAN_API_KEY", "THREATINTEL_VIRUSTOTAL_API_KEY"}

	if err := st.Put(ctx, casemgmt.Name, s.Sign(casemgmt)); err != nil {
		t.Fatalf("Put casemgmt: %v", err)
	}
	if err := st.Put(ctx, threatintel.Name, s.Sign(threatintel)); err != nil {
		t.Fatalf("Put threatintel: %v", err)
	}

	gotIris, err := st.Get(ctx, casemgmt.Name)
	if err != nil {
		t.Fatalf("Get casemgmt: %v", err)
	}
	gotSwiss, err := st.Get(ctx, threatintel.Name)
	if err != nil {
		t.Fatalf("Get threatintel: %v", err)
	}

	if err := signer.Verify(casemgmt, gotIris); err != nil {
		t.Errorf("Verify casemgmt = %v, want nil", err)
	}
	if err := signer.Verify(threatintel, gotSwiss); err != nil {
		t.Errorf("Verify threatintel = %v, want nil", err)
	}
	// threatintel's signature must not authenticate casemgmt, even though the same
	// key produced both.
	if err := signer.Verify(casemgmt, gotSwiss); !errors.Is(err, signer.ErrInvalidSignature) {
		t.Errorf("threatintel's signature verified against casemgmt: %v, want ErrInvalidSignature", err)
	}
}
