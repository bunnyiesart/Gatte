package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
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

func countRows(t *testing.T, db *sql.DB) int {
	t.Helper()

	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_records").Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func TestRecordThenList_RoundTrips(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	ctx := context.Background()

	want := audit.Record{
		AnalystIdentity: "alice",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 8, 10, 30, 45, 123456789, time.FixedZone("BRT", -3*3600)),
		Outcome:         audit.OutcomeAllowed,
		Reason:          "",
	}

	if err := r.Record(ctx, want); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List returned %d records, want 1: %+v", len(got), got)
	}

	gotRec := got[0]
	if gotRec.AnalystIdentity != want.AnalystIdentity {
		t.Errorf("AnalystIdentity = %q, want %q", gotRec.AnalystIdentity, want.AnalystIdentity)
	}
	if gotRec.Tool != want.Tool {
		t.Errorf("Tool = %q, want %q", gotRec.Tool, want.Tool)
	}
	if gotRec.TargetUpstream != want.TargetUpstream {
		t.Errorf("TargetUpstream = %q, want %q", gotRec.TargetUpstream, want.TargetUpstream)
	}
	if !gotRec.Timestamp.Equal(want.Timestamp) {
		t.Errorf("Timestamp = %v, want %v (same instant)", gotRec.Timestamp, want.Timestamp)
	}
}

func TestRecord_InvalidRecordRejectedAndNotStored(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	ctx := context.Background()

	invalid := audit.Record{
		AnalystIdentity: "alice",
		Tool:            "", // invalid: empty
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Now(),
		Outcome:         audit.OutcomeAllowed,
	}

	err := r.Record(ctx, invalid)
	if !errors.Is(err, audit.ErrInvalid) {
		t.Fatalf("Record(invalid) = %v, want audit.ErrInvalid", err)
	}

	if n := countRows(t, db); n != 0 {
		t.Fatalf("audit_records has %d rows after rejected Record, want 0", n)
	}
}

func TestList_EmptyReturnsEmptyNonNilSlice(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	ctx := context.Background()

	got, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil slice, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Fatalf("List returned %d records, want 0", len(got))
	}
}

func TestList_OrdersChronologicallyRegardlessOfInsertionOrder(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	ctx := context.Background()

	base := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	ten := audit.Record{AnalystIdentity: "alice", Tool: "t", TargetUpstream: "casemgmt", Timestamp: base.Add(10 * time.Hour), Outcome: audit.OutcomeAllowed}
	nine := audit.Record{AnalystIdentity: "bob", Tool: "t", TargetUpstream: "casemgmt", Timestamp: base.Add(9 * time.Hour), Outcome: audit.OutcomeDenied, Reason: "forbidden"}
	eleven := audit.Record{AnalystIdentity: "carol", Tool: "t", TargetUpstream: "casemgmt", Timestamp: base.Add(11 * time.Hour), Outcome: audit.OutcomeFailed}

	// Insert out of chronological order: 10:00, 09:00, 11:00.
	for _, rec := range []audit.Record{ten, nine, eleven} {
		if err := r.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	got, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d records, want 3", len(got))
	}

	wantOrder := []audit.Record{nine, ten, eleven}
	for i, w := range wantOrder {
		if !got[i].Timestamp.Equal(w.Timestamp) {
			t.Errorf("record %d: Timestamp = %v, want %v", i, got[i].Timestamp, w.Timestamp)
		}
		if got[i].AnalystIdentity != w.AnalystIdentity {
			t.Errorf("record %d: AnalystIdentity = %q, want %q", i, got[i].AnalystIdentity, w.AnalystIdentity)
		}
	}
}
