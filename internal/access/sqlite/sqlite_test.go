package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate is not idempotent: %v", err)
	}
	return New(db)
}

var placedAt = time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)

func TestBlocklist_BlockUnblockRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if blocked, err := s.Blocked(ctx, "sub-analyst-1"); err != nil || blocked {
		t.Fatalf("Blocked before any block = %v, %v; want false, nil", blocked, err)
	}

	placed, err := s.Block(ctx, access.Block{Subject: "sub-analyst-1", Reason: "laptop lost", By: "operator1", At: placedAt})
	if err != nil || !placed {
		t.Fatalf("Block = %v, %v; want true, nil", placed, err)
	}
	if blocked, err := s.Blocked(ctx, "sub-analyst-1"); err != nil || !blocked {
		t.Fatalf("Blocked after Block = %v, %v; want true, nil", blocked, err)
	}
	// Exact match only: a block is on one subject, not a prefix.
	if blocked, _ := s.Blocked(ctx, "sub-analyst-10"); blocked {
		t.Fatal("a block on sub-analyst-1 also blocked sub-analyst-10")
	}

	// A second block keeps the first one's author and time.
	placed, err = s.Block(ctx, access.Block{Subject: "sub-analyst-1", By: "operator2", At: placedAt.Add(time.Hour)})
	if err != nil || placed {
		t.Fatalf("second Block = %v, %v; want false, nil", placed, err)
	}
	list, err := s.Blocks(ctx)
	if err != nil {
		t.Fatalf("Blocks: %v", err)
	}
	if len(list) != 1 || list[0].By != "operator1" || !list[0].At.Equal(placedAt) || list[0].Reason != "laptop lost" {
		t.Fatalf("Blocks = %+v; want the first block, unchanged", list)
	}

	lifted, err := s.Unblock(ctx, "sub-analyst-1")
	if err != nil || !lifted {
		t.Fatalf("Unblock = %v, %v; want true, nil", lifted, err)
	}
	if blocked, _ := s.Blocked(ctx, "sub-analyst-1"); blocked {
		t.Fatal("still blocked after Unblock")
	}
	if lifted, err := s.Unblock(ctx, "sub-analyst-1"); err != nil || lifted {
		t.Fatalf("second Unblock = %v, %v; want false, nil", lifted, err)
	}
}

func TestBlocklist_RefusesAMalformedBlock(t *testing.T) {
	s := newStore(t)
	for name, b := range map[string]access.Block{
		"empty subject":    {Subject: "", By: "operator1", At: placedAt},
		"padded subject":   {Subject: "sub-analyst-1 ", By: "operator1", At: placedAt},
		"control in sub":   {Subject: "sub\x1b[2J", By: "operator1", At: placedAt},
		"control reason":   {Subject: "sub-analyst-1", Reason: "a\nb", By: "operator1", At: placedAt},
		"nobody placed it": {Subject: "sub-analyst-1", At: placedAt},
		"no time":          {Subject: "sub-analyst-1", By: "operator1"},
	} {
		if _, err := s.Block(context.Background(), b); !errors.Is(err, access.ErrInvalidBlock) {
			t.Errorf("%s: Block err = %v, want ErrInvalidBlock", name, err)
		}
	}
	if list, _ := s.Blocks(context.Background()); len(list) != 0 {
		t.Fatalf("a refused block was stored: %+v", list)
	}
}

// TestBlocklist_UnreadableTableIsUnavailableNotUnblocked is the fail-closed
// half: an unmigrated database must answer "unknown", never "not blocked".
func TestBlocklist_UnreadableTableIsUnavailableNotUnblocked(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	blocked, err := New(db).Blocked(context.Background(), "sub-analyst-1")
	if !errors.Is(err, access.ErrBlocklistUnavailable) {
		t.Fatalf("Blocked on a missing table = %v, %v; want ErrBlocklistUnavailable", blocked, err)
	}
}
