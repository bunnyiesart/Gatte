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
		SourceAddress:   "198.51.100.23",
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
	if gotRec.SourceAddress != want.SourceAddress {
		t.Errorf("SourceAddress = %q, want %q", gotRec.SourceAddress, want.SourceAddress)
	}
}

// legacySchema is the audit_records table exactly as a gateway deployed
// before design/adr/0012 created it: outcome and reason are there (they
// were themselves retrofitted, and that retrofit is the precedent this
// one follows), source_address is not.
//
// It is spelled out here rather than derived from Migrate on purpose: a
// migration test that builds "the old schema" by calling the current
// migration code proves nothing about the database on the live host.
const legacySchema = `
CREATE TABLE audit_records (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	analyst_identity TEXT NOT NULL,
	tool             TEXT NOT NULL,
	target_upstream  TEXT NOT NULL,
	timestamp        TEXT NOT NULL,
	outcome          TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT ''
);`

// TestMigrate_AddsSourceAddressToADatabaseThatPredatesIt is the
// compatibility half of design/adr/0012 item 3. There is a live gateway
// running against a database created before this column existed, and
// CREATE TABLE IF NOT EXISTS is a no-op against it -- so without the
// ALTER TABLE the new column would exist only in fresh installs, and the
// running one would fail every write with "no such column".
//
// Both directions are asserted, because only one of them fails loudly:
// the rows already on disk must still read back (with an empty address,
// which honestly says "written before the gateway recorded one"), and a
// record written *after* the migration must round-trip its address.
func TestMigrate_AddsSourceAddressToADatabaseThatPredatesIt(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("creating the pre-0012 table: %v", err)
	}
	const legacyRow = `
INSERT INTO audit_records (analyst_identity, tool, target_upstream, timestamp, outcome, reason)
VALUES ('alice', 'casemgmt.list_cases', 'casemgmt', '2026-09-01T09:00:00Z', 'allowed', '')`
	if _, err := db.Exec(legacyRow); err != nil {
		t.Fatalf("seeding the pre-0012 row: %v", err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate against a pre-0012 database: %v", err)
	}
	// Idempotent: startup runs it every time, and the second run must not
	// trip over the column the first one added.
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	r := New(db)
	ctx := context.Background()
	fresh := audit.Record{
		AnalystIdentity: "bob",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC),
		Outcome:         audit.OutcomeAllowed,
		SourceAddress:   "203.0.113.7",
	}
	if err := r.Record(ctx, fresh); err != nil {
		t.Fatalf("Record after migrating a pre-0012 database: %v", err)
	}

	got, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d records, want 2 (the legacy row and the new one): %+v", len(got), got)
	}
	if got[0].AnalystIdentity != "alice" {
		t.Fatalf("first record is %q, want the legacy row 'alice'", got[0].AnalystIdentity)
	}
	if got[0].SourceAddress != "" {
		t.Errorf("legacy row SourceAddress = %q, want \"\" -- a row written before the column must not claim an address",
			got[0].SourceAddress)
	}
	if got[1].SourceAddress != fresh.SourceAddress {
		t.Errorf("migrated-in-place row SourceAddress = %q, want %q", got[1].SourceAddress, fresh.SourceAddress)
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
