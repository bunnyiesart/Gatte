package sqlite

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quota"
)

// TestSpentBy_AnswersOnlyTheNamedAnalystsCurrentCounters is the self-read
// port of design/adr/0042 item 3: one analyst, the windows the charges
// name, and nothing of anybody else.
func TestSpentBy_AnswersOnlyTheNamedAnalystsCurrentCounters(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	vt := charge("virustotal", 100, dayStart)
	sh := charge("shodan", 100, dayStart)
	for range 3 {
		if err := s.Reserve(ctx, reservation("sub-alice", vt)); err != nil {
			t.Fatal(err)
		}
	}
	for range 7 {
		if err := s.Reserve(ctx, reservation("sub-bob", vt, sh)); err != nil {
			t.Fatal(err)
		}
	}
	// Yesterday's counter for alice is not today's.
	if err := s.Reserve(ctx, reservation("sub-alice", charge("shodan", 100, dayStart.Add(-24*time.Hour)))); err != nil {
		t.Fatal(err)
	}

	got, err := s.SpentBy(ctx, "sub-alice", []quota.Charge{vt, sh})
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{3, 0}; !slices.Equal(got, want) {
		t.Errorf("alice's own counters = %v, want %v (bob's 7 must not show, nor yesterday's shodan)", got, want)
	}
	if got, _ := s.SpentBy(ctx, "sub-nobody", []quota.Charge{vt}); !slices.Equal(got, []int{0}) {
		t.Errorf("an analyst with no row = %v, want [0]", got)
	}
}

type failingSelf struct{}

func (failingSelf) SpentBy(context.Context, string, []quota.Charge) ([]int, error) {
	return nil, errors.New("disk on fire")
}

// TestGateStanding_NamesOnlyBudgetsTheCallersToolsSpend: gatte.status must
// never name an account the caller's tool list does not lead to, and a
// read failure is "unknown", never a refusal.
func TestGateStanding_NamesOnlyBudgetsTheCallersToolsSpend(t *testing.T) {
	s, _ := newTestStore(t)
	plan, err := quota.NewPlan([]quota.Provider{
		{Name: "virustotal", Upstream: "threatintel", Limit: 50, Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip", "threatintel.lookup_hash"}},
		{Name: "shodan", Upstream: "threatintel", Limit: 20, Window: time.Hour, Tools: []string{"threatintel.lookup_ip"}},
		{Name: "secret-budget", Upstream: "threatintel", Limit: 5, Window: time.Hour, Tools: []string{"threatintel.private"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := quota.NewGate(plan, s)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 14, 10, 30, 0, 0, time.UTC)
	ctx := context.Background()
	for range 4 {
		if err := g.Admit(ctx, "sub-alice", "threatintel.lookup_hash", now); err != nil {
			t.Fatal(err)
		}
	}

	// Without the self reader: policy only, use unknown.
	st, err := g.Standing(ctx, "sub-alice", []string{"threatintel.lookup_hash"}, now)
	if err != nil || len(st) != 1 || st[0].Provider != "virustotal" || st[0].Used != -1 {
		t.Fatalf("standing without a self reader = %+v, %v; want virustotal with Used -1", st, err)
	}

	self := g.WithSelf(s)
	st, err = self.Standing(ctx, "sub-alice", []string{"threatintel.lookup_ip", "threatintel.lookup_hash"}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []quota.Standing{
		{Provider: "shodan", Limit: 20, Window: time.Hour, Used: 0, ResetsAt: time.Date(2026, 9, 14, 11, 0, 0, 0, time.UTC)},
		{Provider: "virustotal", Limit: 50, Window: 24 * time.Hour, Used: 4, ResetsAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)},
	}
	if !slices.Equal(st, want) {
		t.Errorf("standing = %+v\nwant       %+v", st, want)
	}

	if st, _ := self.Standing(ctx, "sub-alice", []string{"casemgmt.list_cases"}, now); len(st) != 0 {
		t.Errorf("a caller whose tools spend no budget sees %+v, want nothing", st)
	}

	broken := g.WithSelf(failingSelf{})
	st, err = broken.Standing(ctx, "sub-alice", []string{"threatintel.lookup_hash"}, now)
	if err == nil || len(st) != 1 || st[0].Used != -1 {
		t.Errorf("an unreadable counter = %+v, %v; want the budget with Used -1 and the error for the log", st, err)
	}
	// Admit is untouched by the self reader.
	if err := self.Admit(ctx, "sub-alice", "threatintel.lookup_hash", now); err != nil {
		t.Errorf("Admit through the copy: %v", err)
	}
}

// TestExhausted_IsTypedAndKeepsItsText: the refusal the analyst reads is
// built from the typed fields; the operator's log text is what it was.
func TestExhausted_IsTypedAndKeepsItsText(t *testing.T) {
	err := quota.Exhausted(charge("virustotal", 100, dayStart))
	var ee *quota.ExhaustedError
	if !errors.As(err, &ee) || !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("Exhausted = %T %v, want an *ExhaustedError wrapping ErrExhausted", err, err)
	}
	if ee.Provider != "virustotal" || ee.Limit != 100 || ee.Window != 24*time.Hour || !ee.ResetsAt.Equal(nextDayStart) {
		t.Errorf("fields = %+v", *ee)
	}
	const want = `quota: exhausted: "virustotal" allows 100 call(s) per analyst per 24h0m0s, and this window is spent; it resets at 2026-09-15T00:00:00Z`
	if err.Error() != want {
		t.Errorf("text = %q, want %q", err.Error(), want)
	}
}
