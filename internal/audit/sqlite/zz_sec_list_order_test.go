package sqlite

// List ordering, ported from the internal tree's security pass of 24 Sep
// 2026. `mcp-gateway audit -limit N` takes the newest N from the END of
// List, so a misordering decides which rows an operator is shown during an
// incident. The hash chain is not involved: it is built and verified in id
// order, and these tests check that it still verifies.

import (
	"context"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

func secRec(tool string, ts time.Time) audit.Record {
	return audit.Record{
		AnalystIdentity: "sub-analyst-1",
		Tool:            tool,
		TargetUpstream:  "casemgmt",
		Timestamp:       ts,
		Outcome:         audit.OutcomeAllowed,
	}
}

func secAssertOrder(t *testing.T, got []audit.Record, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("List returned %d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Tool != want[i] {
			var order []string
			for _, r := range got {
				order = append(order, r.Tool+"@"+r.Timestamp.Format(time.RFC3339Nano))
			}
			t.Fatalf("List is not chronological: position %d is %q, want %q; full order %v", i, got[i].Tool, want[i], order)
		}
	}
}

func secAssertChainIntact(t *testing.T, r *Recorder) {
	t.Helper()
	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if check.FirstBreak != nil {
		t.Fatalf("chain broken at %d: %+v", check.FirstBreak.Position, check.FirstBreak)
	}
}

// TestSecList_SubSecondUTCTimestampsStayChronological: RFC3339Nano drops
// trailing zeros, so the on-disk TEXT for a whole second ("...:00Z") sorted
// AFTER the text for the same second plus a fraction ("...:00.5Z") because
// '.' < 'Z'. Rows are inserted in true chronological order; List must keep
// it.
func TestSecList_SubSecondUTCTimestampsStayChronological(t *testing.T) {
	rec := New(newTestDB(t))
	ctx := context.Background()

	base := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC)
	for _, r := range []audit.Record{
		secRec("t0-whole-second", base),
		secRec("t1-plus-500ms", base.Add(500*time.Millisecond)),
		secRec("t2-plus-550ms", base.Add(550*time.Millisecond)),
		secRec("t3-plus-1s", base.Add(time.Second)),
	} {
		if err := rec.Record(ctx, r); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got, err := rec.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	secAssertOrder(t, got, "t0-whole-second", "t1-plus-500ms", "t2-plus-550ms", "t3-plus-1s")
	secAssertChainIntact(t, rec)
}

// TestSecList_MixedOffsetsStayChronological: the same instant ordering
// must hold when the process clock's offset changes between writes (TZ
// change on the host, DST, a restart with a different TZ). Row "earlier"
// is 13:00Z; row "later" is 12:00-03:00 = 15:00Z, so the textual and
// chronological orders disagree.
func TestSecList_MixedOffsetsStayChronological(t *testing.T) {
	rec := New(newTestDB(t))
	ctx := context.Background()

	brt := time.FixedZone("BRT", -3*3600)
	earlier := time.Date(2026, 9, 24, 13, 0, 0, 0, time.UTC)
	later := time.Date(2026, 9, 24, 12, 0, 0, 0, brt)
	if !later.After(earlier) {
		t.Fatal("fixture is wrong")
	}
	for _, r := range []audit.Record{secRec("earlier", earlier), secRec("later", later)} {
		if err := rec.Record(ctx, r); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	got, err := rec.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	secAssertOrder(t, got, "earlier", "later")
	secAssertChainIntact(t, rec)
}

// TestSecList_EqualInstantsKeepInsertionOrder: the sort is stable over rows
// read in id order, so id still breaks ties -- the same tie-break the SQL
// ORDER BY used to apply, and the order the chain was built in.
func TestSecList_EqualInstantsKeepInsertionOrder(t *testing.T) {
	rec := New(newTestDB(t))
	ctx := context.Background()
	ts := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC)
	for _, name := range []string{"first", "second", "third"} {
		if err := rec.Record(ctx, secRec(name, ts)); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := rec.Record(ctx, secRec("before-all", ts.Add(-time.Minute))); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, err := rec.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	secAssertOrder(t, got, "before-all", "first", "second", "third")
	secAssertChainIntact(t, rec)
}
