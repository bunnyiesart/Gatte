package sqlite

import (
	"context"
	"database/sql"
	"strings"
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

// TestMigrate_DeletingChainMetaDoesNotResignATamperedTrail is the cheaper
// attack on the same weakness rechain_test.go's other cases describe, and
// it needs no hashing at all.
//
// backfillChain used the presence of the audit_chain_meta row as its only
// "already done" guard. Delete that one row -- the same write access the
// whole ADR is about -- and the next start re-chained EVERY row from
// scratch over whatever the table currently held. The attacker edits a
// record, drops one row from a second table, restarts the gateway, and the
// gateway itself computes and stores a valid chain over the edited trail.
// The retroactive-boundary disclosure, which exists so an intact result
// cannot be read as "authentic since written", was overwritten in the same
// motion.
//
// The fix is that a row which already carries a hash is never re-hashed.
// Backfill is for rows that predate the chain, and only those.
func TestMigrate_DeletingChainMetaDoesNotResignATamperedTrail(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 4)

	before, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain before: %v", err)
	}
	if !before.Intact() {
		t.Fatal("the trail did not verify before tampering")
	}

	// The attack: edit a record, then remove the one row that says the
	// backfill already ran.
	if _, err := db.Exec(`UPDATE audit_records SET analyst_identity = 'someone-else' WHERE id = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM audit_chain_meta`); err != nil {
		t.Fatalf("delete chain meta: %v", err)
	}

	// Restart: Migrate runs on every start and is where the backfill lives.
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate after tampering: %v", err)
	}

	after, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after: %v", err)
	}
	if after.Intact() {
		t.Fatal("the gateway re-signed a tampered trail: an edited record verifies clean after a " +
			"restart, and the attacker computed no hashes to achieve it")
	}
	if after.FirstBreak.Position != 2 {
		t.Errorf("break reported at %d, want 2 (the edited row)", after.FirstBreak.Position)
	}
	// The head is deliberately NOT asserted to move here, and the reason
	// is worth stating because getting it wrong is how the original ADR
	// overclaimed.
	//
	// This attacker edited a row and did not re-chain. The stored hashes
	// are untouched, so the head is unchanged -- and that costs nothing,
	// because detection comes from the break above, which is exactly what
	// an unrewritten chain is for. The head is the signal for the OTHER
	// attack, the one that does re-chain; that case is
	// TestVerifyChain_RechainedMiddleEditVerifiesClean, where the break
	// disappears and the moved head is all that is left.
	//
	// Two attacks, two different signals. Requiring both from one of them
	// would be asserting a property this design does not have.
	if before.Head != after.Head {
		t.Errorf("the stored head moved (%s -> %s) without anything re-chaining; "+
			"the backfill has rewritten hashes it must never touch",
			before.Head[:12], after.Head[:12])
	}
}

// TestVerifyChain_AnUnreadableTimestampIsABreakNotAnError: one damaged row
// must not make the whole trail unreadable.
//
// Returning an error for a timestamp that will not parse handed an attacker
// a cheaper move than re-chaining anything: corrupt a single character in
// one row and `audit -verify` answers with a parse error instead of with
// the trail, so nothing else in it gets checked or shown. A damaged row is
// exactly what this function exists to report.
func TestVerifyChain_AnUnreadableTimestampIsABreakNotAnError(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	recordN(t, r, 4)

	if _, err := db.Exec(`UPDATE audit_records SET timestamp = 'not-a-timestamp' WHERE id = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain returned an error instead of reporting the damaged row: %v", err)
	}
	if check.Intact() {
		t.Fatal("a row with an unreadable timestamp verified clean")
	}
	if check.FirstBreak.Position != 2 {
		t.Errorf("break at position %d, want 2", check.FirstBreak.Position)
	}
	if !strings.Contains(check.FirstBreak.Want, "unreadable") {
		t.Errorf("the break does not say the row is unreadable: %q", check.FirstBreak.Want)
	}
}
