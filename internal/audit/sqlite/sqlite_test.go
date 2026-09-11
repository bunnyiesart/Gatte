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

// newTestFileDB is newTestDB on a real file. It exists for the one test
// that needs genuine concurrency: store.Open pins ":memory:" to a single
// connection, so two goroutines racing against it would be serialised by
// the pool and the test would pass without ever exercising the lock it
// claims to.
func newTestFileDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := store.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// record writes n well-formed records a second apart, so timestamp order
// and insertion order agree and a test that breaks one is not accidentally
// also breaking the other.
func recordN(t *testing.T, r *Recorder, n int) {
	t.Helper()

	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	for i := range n {
		rec := audit.Record{
			AnalystIdentity: "ana",
			Tool:            "casemgmt.list_cases",
			TargetUpstream:  "casemgmt",
			Timestamp:       base.Add(time.Duration(i) * time.Second),
			Outcome:         audit.OutcomeAllowed,
		}
		if err := r.Record(context.Background(), rec); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
}

// TestVerifyChain_IntactAfterOrdinaryWrites is the control the other
// tests in this file need: without it, one that reports a break proves
// only that VerifyChain can say "broken", not that it says so for the
// right reason.
func TestVerifyChain_IntactAfterOrdinaryWrites(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 5)

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() {
		t.Fatalf("chain reported broken at position %d on a trail nobody touched: %+v",
			check.FirstBreak.Position, check.FirstBreak)
	}
	if check.Count != 5 {
		t.Errorf("Count = %d, want 5", check.Count)
	}
	if check.Head == audit.GenesisHash {
		t.Error("Head is the genesis value after five records -- nothing to anchor externally")
	}
	if check.RetroactivelyChained != 0 {
		t.Errorf("RetroactivelyChained = %d, want 0: every row here was hashed when written",
			check.RetroactivelyChained)
	}
}

// TestVerifyChain_EditedRowInTheMiddleIsReported is GAB-36's first
// premise: an attacker with write access to the database file rewrites a
// record, and the trail has to say so.
func TestVerifyChain_EditedRowInTheMiddleIsReported(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 5)

	// Straight SQL, deliberately: this is the attacker's tool, not the
	// Recorder's. Going through Record would be testing the wrong thing.
	if _, err := db.Exec(`UPDATE audit_records SET analyst_identity = 'someone-else' WHERE id = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if check.Intact() {
		t.Fatal("an edited record verified -- the chain detects nothing")
	}
	if got := check.FirstBreak.Position; got != 3 {
		t.Errorf("break reported at position %d, want 3", got)
	}
	if check.FirstBreak.Record.AnalystIdentity != "someone-else" {
		t.Errorf("break carries %q, want the row as it now reads on disk",
			check.FirstBreak.Record.AnalystIdentity)
	}
	if check.FirstBreak.Want == check.FirstBreak.Got {
		t.Error("Want and Got are equal on a reported break -- the report says nothing")
	}
}

// TestVerifyChain_DeletedRowInTheMiddleIsReported is the other half. An
// edit is caught by a record's own hash; a deletion is caught only by the
// next record's link no longer pointing at its predecessor.
func TestVerifyChain_DeletedRowInTheMiddleIsReported(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 5)

	if _, err := db.Exec(`DELETE FROM audit_records WHERE id = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if check.Intact() {
		t.Fatal("a deleted record left an intact chain -- removal is undetectable")
	}
	// Position 3 is now the record that used to be fourth: the first one
	// whose stored prev_hash names a row that is no longer there.
	if got := check.FirstBreak.Position; got != 3 {
		t.Errorf("break reported at position %d, want 3", got)
	}
	if check.Count != 4 {
		t.Errorf("Count = %d, want 4", check.Count)
	}
}

// TestVerifyChain_TruncatedTailStillVerifies pins the limit ADR-0015 item
// 6 declares, as a test rather than a footnote. Cutting records off the
// END leaves a shorter chain that is internally perfect, and nothing in
// this package can tell. If someone later makes this test fail by
// "fixing" it, they have either found a way to detect truncation from the
// inside -- worth an ADR -- or, far more likely, made the chain reject
// something it should accept.
func TestVerifyChain_TruncatedTailStillVerifies(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 5)

	before, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain before: %v", err)
	}

	if _, err := db.Exec(`DELETE FROM audit_records WHERE id > 3`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	after, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after: %v", err)
	}
	if !after.Intact() {
		t.Fatal("truncation was reported as a break -- that is not what this detects, " +
			"and claiming it would be the overstatement ADR-0015 exists to avoid")
	}
	if after.Count != 3 {
		t.Errorf("Count = %d, want 3", after.Count)
	}
	// The ONLY thing that catches this is the head having been recorded
	// somewhere else beforehand.
	if before.Head == after.Head {
		t.Error("head unchanged after truncation -- then an external anchor would not catch it either, " +
			"and the mitigation ADR-0015 offers is empty")
	}
}

// TestVerifyChain_ConcurrentWritesProduceAnIntactChain covers ADR-0015
// item 3. Without the serialised read-head-and-append, two writers read
// the same head, both link to it, and verification reports a break on a
// database nobody attacked -- a false alarm in the one component whose
// value is being believed.
func TestVerifyChain_ConcurrentWritesProduceAnIntactChain(t *testing.T) {
	db := newTestFileDB(t)
	r := New(db)

	const writers, each = 4, 10
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	errs := make(chan error, writers*each)
	done := make(chan struct{})
	for w := range writers {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := range each {
				errs <- r.Record(context.Background(), audit.Record{
					AnalystIdentity: "ana",
					Tool:            "casemgmt.list_cases",
					TargetUpstream:  "casemgmt",
					Timestamp:       base.Add(time.Duration(w*each+i) * time.Millisecond),
					Outcome:         audit.OutcomeAllowed,
				})
			}
		}(w)
	}
	for range writers {
		<-done
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Record: %v", err)
		}
	}

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() {
		t.Fatalf("concurrent writes forked the chain: break at position %d", check.FirstBreak.Position)
	}
	if check.Count != writers*each {
		t.Errorf("Count = %d, want %d -- a write was lost", check.Count, writers*each)
	}
}

// TestMigrate_BackfillsExistingRowsAndRecordsTheBoundary covers ADR-0015
// item 4, including the part that matters most: the boundary is reported,
// so an intact result cannot be read as "these rows are authentic" for
// the rows that were hashed after the fact.
func TestMigrate_BackfillsExistingRowsAndRecordsTheBoundary(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// A database as it looked before this ADR: the table without the
	// chain columns, carrying rows.
	if _, err := db.Exec(`
CREATE TABLE audit_records (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	analyst_identity TEXT NOT NULL,
	tool             TEXT NOT NULL,
	target_upstream  TEXT NOT NULL,
	timestamp        TEXT NOT NULL,
	outcome          TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT '',
	source_address   TEXT NOT NULL DEFAULT ''
);
INSERT INTO audit_records (analyst_identity, tool, target_upstream, timestamp, outcome)
VALUES ('ana', 'casemgmt.list_cases', 'casemgmt', '2026-09-10T12:00:00Z', 'allowed'),
       ('bea', 'logsearch.search', 'logsearch', '2026-09-10T12:00:01Z', 'denied');
`); err != nil {
		t.Fatalf("seed pre-chain database: %v", err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	r := New(db)

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() {
		t.Fatalf("backfilled rows do not verify: break at position %d", check.FirstBreak.Position)
	}
	if check.RetroactivelyChained != 2 {
		t.Errorf("RetroactivelyChained = %d, want 2 -- an intact result that hides how much of it "+
			"was hashed after the fact is the overstatement this field exists to prevent",
			check.RetroactivelyChained)
	}

	// A record written after the migration extends the same chain and is
	// NOT counted as retroactive.
	recordN(t, r, 1)
	check, err = r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after append: %v", err)
	}
	if !check.Intact() {
		t.Fatal("appending to a backfilled chain broke it")
	}
	if check.Count != 3 || check.RetroactivelyChained != 2 {
		t.Errorf("Count = %d, RetroactivelyChained = %d; want 3 and 2",
			check.Count, check.RetroactivelyChained)
	}

	// Migrate again: the backfill must not re-run and move the boundary.
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	check, err = r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after second Migrate: %v", err)
	}
	if check.RetroactivelyChained != 2 {
		t.Errorf("a second Migrate moved the boundary to %d rows; it must run once",
			check.RetroactivelyChained)
	}
}

// TestVerifyChain_EmptyTrailIsIntact: an empty trail is not a broken one,
// and its head is the genesis value rather than something an operator
// might anchor by mistake.
func TestVerifyChain_EmptyTrailIsIntact(t *testing.T) {
	r := New(newTestDB(t))

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() || check.Count != 0 || check.Head != audit.GenesisHash {
		t.Errorf("empty trail: Intact=%v Count=%d Head=%q; want true, 0, %q",
			check.Intact(), check.Count, check.Head, audit.GenesisHash)
	}
}
