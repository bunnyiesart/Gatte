package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// clock is a settable "now" for the store.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// TestUntil_TheBlockEndsAtTheInstantStatedAndIsListedAsExpired is
// design/adr/0046 item 3: Blocked, the admission check, stops refusing at
// Until -- not at the next sweep -- and the row stays visible until it is
// removed.
func TestUntil_TheBlockEndsAtTheInstantStatedAndIsListedAsExpired(t *testing.T) {
	c := &clock{t: placedAt}
	s := newStore(t).WithClock(c.now)
	ctx := context.Background()
	end := placedAt.Add(2 * time.Hour)

	placed, err := s.Block(ctx, access.Block{Subject: "sub-1", By: "op", At: placedAt, Until: end})
	if err != nil || !placed {
		t.Fatalf("Block = %v, %v", placed, err)
	}
	c.t = end.Add(-time.Nanosecond)
	if b, err := s.Blocked(ctx, "sub-1"); err != nil || !b {
		t.Fatalf("one nanosecond before the end: Blocked = %v, %v; want true", b, err)
	}
	if exp, _ := s.Expired(ctx); len(exp) != 0 {
		t.Fatalf("expired before the end: %+v", exp)
	}
	c.t = end
	if b, err := s.Blocked(ctx, "sub-1"); err != nil || b {
		t.Fatalf("at the end: Blocked = %v, %v; want false", b, err)
	}
	list, err := s.Blocks(ctx)
	if err != nil || len(list) != 1 || !list[0].Until.Equal(end) || list[0].ActiveAt(c.t) {
		t.Fatalf("Blocks after the end = %+v, %v; want the row, with its end, inactive", list, err)
	}
	exp, err := s.Expired(ctx)
	if err != nil || len(exp) != 1 || exp[0].Subject != "sub-1" {
		t.Fatalf("Expired = %+v, %v", exp, err)
	}
}

// TestUntil_AnExpiredBlockIsReplacedAndAnActiveOneIsNot: blocking again
// after the end places a new block; blocking during it changes nothing.
func TestUntil_AnExpiredBlockIsReplacedAndAnActiveOneIsNot(t *testing.T) {
	c := &clock{t: placedAt}
	s := newStore(t).WithClock(c.now)
	ctx := context.Background()
	end := placedAt.Add(time.Hour)
	if _, err := s.Block(ctx, access.Block{Subject: "sub-1", By: "first", At: placedAt, Until: end}); err != nil {
		t.Fatal(err)
	}
	c.t = placedAt.Add(30 * time.Minute)
	if placed, err := s.Block(ctx, access.Block{Subject: "sub-1", By: "second", At: c.t}); err != nil || placed {
		t.Fatalf("Block during an active block = %v, %v; want false", placed, err)
	}
	c.t = end.Add(time.Minute)
	if placed, err := s.Block(ctx, access.Block{Subject: "sub-1", By: "third", At: c.t}); err != nil || !placed {
		t.Fatalf("Block after the end = %v, %v; want true", placed, err)
	}
	list, _ := s.Blocks(ctx)
	if len(list) != 1 || list[0].By != "third" || !list[0].Until.IsZero() {
		t.Fatalf("after re-blocking: %+v; want third's block, with no end", list)
	}
	if b, _ := s.Blocked(ctx, "sub-1"); !b {
		t.Fatal("the new block does not block")
	}
}

// TestUntil_RemoveExpiredRemovesOnlyTheRowItWasGiven: a sweep that read an
// expired block must not delete the block an operator placed since.
func TestUntil_RemoveExpiredRemovesOnlyTheRowItWasGiven(t *testing.T) {
	c := &clock{t: placedAt}
	s := newStore(t).WithClock(c.now)
	ctx := context.Background()
	end := placedAt.Add(time.Hour)
	if _, err := s.Block(ctx, access.Block{Subject: "sub-1", By: "op", At: placedAt, Until: end}); err != nil {
		t.Fatal(err)
	}
	c.t = end.Add(time.Second)
	exp, _ := s.Expired(ctx)
	if len(exp) != 1 {
		t.Fatalf("expired %+v", exp)
	}
	// Meanwhile, somebody blocks again.
	if placed, _ := s.Block(ctx, access.Block{Subject: "sub-1", By: "op2", At: c.t}); !placed {
		t.Fatal("re-block not placed")
	}
	if removed, err := s.RemoveExpired(ctx, "sub-1", exp[0].Until); err != nil || removed {
		t.Fatalf("RemoveExpired of a replaced block = %v, %v; want false", removed, err)
	}
	if b, _ := s.Blocked(ctx, "sub-1"); !b {
		t.Fatal("the sweep lifted a block placed after it read the expired one")
	}
	if _, err := s.RemoveExpired(ctx, "sub-1", time.Time{}); err == nil {
		t.Fatal("RemoveExpired with no end must refuse: such a block never expires")
	}
}

// TestUntil_AnEndThatDoesNotParseKeepsTheSubjectBlocked is fail-closed.
func TestUntil_AnEndThatDoesNotParseKeepsTheSubjectBlocked(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.db.Exec(`INSERT INTO blocked_subjects (subject, reason, blocked_by, blocked_at, blocked_until) VALUES ('sub-1', '', 'op', ?, 'tomorrow')`,
		placedAt.Format(timeLayout)); err != nil {
		t.Fatal(err)
	}
	if b, err := s.Blocked(ctx, "sub-1"); err != nil || !b {
		t.Fatalf("Blocked with an unreadable end = %v, %v; want true, nil", b, err)
	}
}

// TestUntil_ABlockMayNotEndBeforeItBegins is the validation.
func TestUntil_ABlockMayNotEndBeforeItBegins(t *testing.T) {
	s := newStore(t)
	if _, err := s.Block(context.Background(), access.Block{Subject: "sub-1", By: "op", At: placedAt, Until: placedAt}); err == nil {
		t.Fatal("a block ending when it is placed was stored")
	}
}

// TestUntil_MigrationKeepsOldRowsAsBlocksWithNoEnd: a database written
// before the column existed.
func TestUntil_MigrationKeepsOldRowsAsBlocksWithNoEnd(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE blocked_subjects (subject TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', blocked_by TEXT NOT NULL, blocked_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO blocked_subjects VALUES ('sub-old', '', 'op', ?)`, placedAt.Format(timeLayout)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	checkOld(t, db)
}

func checkOld(t *testing.T, db *sql.DB) {
	t.Helper()
	s := New(db)
	if b, err := s.Blocked(context.Background(), "sub-old"); err != nil || !b {
		t.Fatalf("an old block after migration: Blocked = %v, %v", b, err)
	}
	list, err := s.Blocks(context.Background())
	if err != nil || len(list) != 1 || !list[0].Until.IsZero() {
		t.Fatalf("Blocks = %+v, %v", list, err)
	}
}
