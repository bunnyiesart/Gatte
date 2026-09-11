package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// rechain rewrites prev_hash and hash for every row in audit_records, in
// id order, using this project's own exported audit.ChainHash.
//
// It is a dozen lines of ordinary SQL plus one exported function, which is
// the entire point of the tests below: re-chaining is not an exotic
// capability, it is available to anyone who can write the database file --
// the actor ADR-0015 names. Nothing here is privileged, and nothing here
// is secret, because the chain is an unkeyed hash stored in the table it
// authenticates.
func rechain(t *testing.T, db *sql.DB) {
	t.Helper()

	rows, err := db.Query(`
SELECT id, analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address
FROM audit_records ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("rechain: query: %v", err)
	}
	type row struct {
		id  int64
		rec audit.Record
	}
	var all []row
	for rows.Next() {
		var rr row
		var ts, outcome string
		if err := rows.Scan(&rr.id, &rr.rec.AnalystIdentity, &rr.rec.Tool, &rr.rec.TargetUpstream,
			&ts, &outcome, &rr.rec.Reason, &rr.rec.SourceAddress); err != nil {
			rows.Close()
			t.Fatalf("rechain: scan: %v", err)
		}
		rr.rec.Timestamp, err = time.Parse(timeLayout, ts)
		if err != nil {
			rows.Close()
			t.Fatalf("rechain: parse timestamp: %v", err)
		}
		rr.rec.Outcome = audit.Outcome(outcome)
		all = append(all, rr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("rechain: query: %v", err)
	}

	prev := audit.GenesisHash
	for _, rr := range all {
		h := audit.ChainHash(prev, rr.rec)
		if _, err := db.Exec(`UPDATE audit_records SET prev_hash = ?, hash = ? WHERE id = ?`, prev, h, rr.id); err != nil {
			t.Fatalf("rechain: update id %d: %v", rr.id, err)
		}
		prev = h
	}
}

// TestVerifyChain_RechainedMiddleEditVerifiesClean pins the boundary of
// what the chain detects, the way TestVerifyChain_TruncatedTailStillVerifies
// pins the tail: as a test, not as a footnote somebody may or may not read.
//
// The chain catches an edit made WITHOUT recomputing the hashes that
// follow it -- the first half of this test, which is also the control
// proving the tamper is real and reachable by this test. It does not catch
// the same edit followed by a forward re-chain, and the only residue is
// the head. Both halves are asserted here because the doc comments, the
// help text and ADR-0015 now say exactly this, and a sentence asserting a
// property is worth what the test under it is worth.
//
// If this test ever fails, nobody "fixed" verification by accident: either
// the chain acquired a key or an anchor the named actor cannot reach
// (which is an ADR, not a patch), or -- far more likely -- VerifyChain
// started rejecting something it should accept.
func TestVerifyChain_RechainedMiddleEditVerifiesClean(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 5)

	before, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain before: %v", err)
	}
	if !before.Intact() {
		t.Fatalf("test setup: an untouched trail already reports a break at %d", before.FirstBreak.Position)
	}

	// Straight SQL: the attacker's tool, not the Recorder's.
	if _, err := db.Exec(`UPDATE audit_records SET analyst_identity = 'somebody-else' WHERE id = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	// Control. Without this half, an "intact" result after the re-chain
	// would prove only that the UPDATE did nothing.
	naive, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after edit: %v", err)
	}
	if naive.Intact() {
		t.Fatal("an edit with no re-chain verified: this test can no longer tell tampering from not, " +
			"so its second half proves nothing")
	}
	if naive.FirstBreak.Position != 3 {
		t.Errorf("control break at position %d, want 3", naive.FirstBreak.Position)
	}

	rechain(t, db)

	after, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after re-chain: %v", err)
	}
	if !after.Intact() {
		t.Fatalf("re-chained edit was reported as a break at position %d -- if this is a real "+
			"detection, say so in ADR-0015 and in the help text, because both now say it is not",
			after.FirstBreak.Position)
	}
	if after.Count != 5 {
		t.Errorf("Count = %d, want 5: the edit changed a field, not the number of rows", after.Count)
	}

	// The record now says something it never said, and the trail agrees.
	records, err := r.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var edited bool
	for _, rec := range records {
		if rec.AnalystIdentity == "somebody-else" {
			edited = true
		}
	}
	if !edited {
		t.Fatal("test setup: the edited identity is not in the trail")
	}

	// The single residue, and therefore the single control: the head.
	// This is the SAME signal tail truncation leaves, which is why there
	// is no "middle detected, tail open" split to claim.
	if after.Head == before.Head {
		t.Error("head unchanged after a re-chained edit -- then -expect-head would not catch it either, " +
			"and nothing in this system detects tampering at all")
	}
}

// TestVerifyChain_RechainedMiddleDeleteVerifiesClean is the deletion half.
// A deletion is caught only by the next record's link no longer naming its
// predecessor, so re-chaining forward removes that evidence too, and the
// trail comes back one record shorter and perfectly consistent.
func TestVerifyChain_RechainedMiddleDeleteVerifiesClean(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 5)

	before, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain before: %v", err)
	}

	if _, err := db.Exec(`DELETE FROM audit_records WHERE id = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	naive, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after delete: %v", err)
	}
	if naive.Intact() {
		t.Fatal("a deletion with no re-chain verified: the control half of this test is dead")
	}

	rechain(t, db)

	after, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after re-chain: %v", err)
	}
	if !after.Intact() {
		t.Fatalf("re-chained deletion was reported as a break at position %d", after.FirstBreak.Position)
	}
	if after.Count != 4 {
		t.Errorf("Count = %d, want 4: a record was removed", after.Count)
	}
	if after.Head == before.Head {
		t.Error("head unchanged after a re-chained deletion -- then nothing detects it")
	}
}
