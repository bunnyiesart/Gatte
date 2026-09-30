package sqlite

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// pageFromChainOrder is the reference: the page computed the way the
// management API did before it paged in the database.
func pageFromChainOrder(t *testing.T, r *Recorder, q audit.TrailQuery) ([]audit.PositionedRecord, bool) {
	t.Helper()
	all, err := r.ChainOrder(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := []audit.PositionedRecord{}
	for i := len(all) - 1; i >= 0; i-- {
		pos, rec := i+1, all[i]
		if q.Before > 0 && pos >= q.Before || !q.Since.IsZero() && rec.Timestamp.Before(q.Since) ||
			q.Subject != "" && rec.AnalystIdentity != q.Subject || q.Outcome != "" && string(rec.Outcome) != q.Outcome ||
			q.Source != "" && rec.SourceAddress != q.Source ||
			q.Tool != "" && rec.Tool != q.Tool || q.Server != "" && rec.TargetUpstream != q.Server ||
			!q.Until.IsZero() && !rec.Timestamp.Before(q.Until) {
			continue
		}
		if len(out) == q.Limit {
			return out, true
		}
		out = append(out, audit.PositionedRecord{Position: pos, Record: rec})
	}
	return out, false
}

// TestPage_MatchesTheChainPositionsWithAndWithoutAGap: on an intact trail
// and on one with a deleted row, every page carries the positions
// VerifyChain would name.
func TestPage_MatchesTheChainPositionsWithAndWithoutAGap(t *testing.T) {
	db := newTestDB(t)
	r := New(db)
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 12; i++ {
		who := []string{"ana", "bruno", "(operator:alice)"}[i%3]
		out := audit.OutcomeAllowed
		if i%4 == 0 {
			out = audit.OutcomeDenied
		}
		server := []string{"casemgmt", "logsearch"}[i%2]
		tool := server + []string{".list_cases", ".search"}[(i/2)%2]
		if err := r.Record(context.Background(), audit.Record{AnalystIdentity: who, Tool: tool, TargetUpstream: server,
			Timestamp: base.Add(time.Duration(i) * time.Minute), Outcome: out, SourceAddress: fmt.Sprintf("192.0.2.%d", i%2)}); err != nil {
			t.Fatal(err)
		}
	}
	queries := []audit.TrailQuery{
		{Limit: 5}, {Limit: 3, Before: 7}, {Limit: 50, Subject: "ana"}, {Limit: 2, Outcome: "denied"},
		{Limit: 4, Source: "192.0.2.1", Before: 11}, {Limit: 50, Since: base.Add(6 * time.Minute)}, {Limit: 1, Subject: "nobody"},
		// design/adr/0046: tool, server and the exclusive until bound.
		{Limit: 50, Tool: "logsearch.search"}, {Limit: 2, Server: "casemgmt", Before: 10},
		{Limit: 50, Until: base.Add(4 * time.Minute)}, {Limit: 50, Since: base.Add(2 * time.Minute), Until: base.Add(8 * time.Minute), Server: "logsearch"},
		{Limit: 50, Tool: "casemgmt.list_cases", Subject: "ana"},
	}
	check := func(label string) {
		for _, q := range queries {
			got, more, err := r.Page(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			want, wantMore := pageFromChainOrder(t, r, q)
			if fmt.Sprint(got) != fmt.Sprint(want) || more != wantMore {
				t.Errorf("%s: %+v:\n got %v more=%v\nwant %v more=%v", label, q, got, more, want, wantMore)
			}
		}
	}
	check("intact")
	if _, err := db.Exec(`DELETE FROM audit_records WHERE id = 5`); err != nil {
		t.Fatal(err)
	}
	check("with a deleted row")
}

// TestAnalysts_AggregatesPeopleOnly: operator and gateway rows are not
// people; the name is the newest non-empty one, the last call the newest
// row's.
func TestAnalysts_AggregatesPeopleOnly(t *testing.T) {
	r := New(newTestDB(t))
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i, rec := range []audit.Record{
		{AnalystIdentity: "ana", AnalystName: "Ana"},
		{AnalystIdentity: "(operator:alice)"},
		{AnalystIdentity: "ana", AnalystName: "Ana Lyst"},
		{AnalystIdentity: "bruno"},
		{AnalystIdentity: "ana"},
		{AnalystIdentity: "(gateway)"},
	} {
		rec.Tool, rec.TargetUpstream, rec.Outcome, rec.Timestamp = "casemgmt.list_cases", "casemgmt", audit.OutcomeAllowed, base.Add(time.Duration(i)*time.Minute)
		if err := r.Record(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.Analysts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]audit.AnalystSeen{}
	for _, a := range got {
		by[a.Identity] = a
	}
	if len(got) != 2 || by["ana"].Calls != 3 || by["ana"].Name != "Ana Lyst" || !by["ana"].LastCall.Equal(base.Add(4*time.Minute)) ||
		by["bruno"].Calls != 1 || by["bruno"].Name != "" {
		t.Fatalf("analysts %+v", got)
	}
}

// TestPage_UntilIsExclusiveAndSinceInclusive: adjacent windows neither
// share nor lose the record on their boundary.
func TestPage_UntilIsExclusiveAndSinceInclusive(t *testing.T) {
	r := New(newTestDB(t))
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	if err := r.Record(context.Background(), audit.Record{AnalystIdentity: "ana", Tool: "casemgmt.list_cases", TargetUpstream: "casemgmt", Timestamp: at, Outcome: audit.OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	before, _, _ := r.Page(context.Background(), audit.TrailQuery{Limit: 10, Until: at})
	after, _, _ := r.Page(context.Background(), audit.TrailQuery{Limit: 10, Since: at})
	if len(before) != 0 || len(after) != 1 {
		t.Fatalf("until=at gave %d, since=at gave %d; want 0 and 1", len(before), len(after))
	}
}
