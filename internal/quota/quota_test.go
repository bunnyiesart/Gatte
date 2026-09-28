package quota

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Times are constants, never time.Now(). The window boundary is an input
// to the decision under test, so a test that read the clock would be
// testing a different window every time it ran -- and could only exercise
// a rollover by waiting for midnight.
var (
	// noonUTC sits in the middle of the 24h window starting at
	// 2026-09-14T00:00:00Z.
	noonUTC = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	// dayStart and nextDayStart are that window's boundaries.
	dayStart     = time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	nextDayStart = time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
)

func virustotal(limit int) Provider {
	return Provider{
		Name:     "virustotal",
		Upstream: "threatintel",
		Limit:    limit,
		Window:   24 * time.Hour,
		Tools:    []string{"threatintel.virustotal", "threatintel.lookup_ip"},
	}
}

func abusech(limit int) Provider {
	return Provider{
		Name:     "abusech",
		Upstream: "threatintel",
		Limit:    limit,
		Window:   24 * time.Hour,
		Tools:    []string{"threatintel.malwarebazaar", "threatintel.lookup_hash"},
	}
}

func mustPlan(t *testing.T, providers ...Provider) *Plan {
	t.Helper()
	p, err := NewPlan(providers, nil)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	return p
}

// fakeStore is a domain-side stand-in for an adapter. It records what it
// was asked to reserve and answers with whatever the test told it to,
// which is how the fail-closed rule can be exercised against error classes
// a real SQLite store would only produce under a broken disk.
type fakeStore struct {
	mu   sync.Mutex
	got  []Reservation
	err  error
	used map[string]int
}

func (f *fakeStore) Reserve(_ context.Context, r Reservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, r)
	if f.err != nil {
		return f.err
	}
	if f.used == nil {
		f.used = map[string]int{}
	}
	// Enough counting to be a believable healthy store: debit every charge,
	// refuse the whole reservation if any of them no longer fits, and undo
	// what was debited so a refusal costs nothing.
	debited := make([]string, 0, len(r.Charges))
	for _, c := range r.Charges {
		key := r.Analyst + "\x00" + c.Provider + "\x00" + c.WindowStart.Format(time.RFC3339Nano)
		f.used[key]++
		debited = append(debited, key)
		if !c.Fits(f.used[key]) {
			for _, k := range debited {
				f.used[k]--
			}
			return Exhausted(c)
		}
	}
	return nil
}

func (f *fakeStore) calls() []Reservation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.got)
}

var _ Store = (*fakeStore)(nil)

// -----------------------------------------------------------------------
// Fail closed. This is the first test in the file on purpose.
// -----------------------------------------------------------------------

// TestAdmit_EveryStoreFailureRefusesTheCall is the ADR-0004 class test,
// applied to the counter: a quota whose counter cannot be reached must
// refuse, never pass.
//
// It is the test this component exists to pass. Every other control in
// this system fails closed when the state governing its decision is
// missing -- an unreadable registry serves nothing (ADR-0004), verifyEntry
// refuses to judge integrity without the signature store, admit treats a
// route with no quarantine entry as unapproved. A quota that became a free
// pass when its counter broke would be the single inverse, and the attack
// on the team's VirusTotal budget would reduce to breaking the counter.
//
// Read failures and write failures are asserted together and identically,
// because ADR-0030 decision 6 refuses to distinguish them: whoever wants
// free quota has no preference between the two, so if a failed write could
// pass, the attack is to make the write fail.
//
// The positive control is in the same test, and is not optional: without
// it, an Admit that refused unconditionally -- or a Gate wired to nothing
// -- would pass every case above and prove nothing.
func TestAdmit_EveryStoreFailureRefusesTheCall(t *testing.T) {
	ctx := context.Background()
	plan := mustPlan(t, virustotal(10))

	failures := []struct {
		name string
		err  error
	}{
		{"counter could not be read", errors.New("quota/sqlite: reserve \"virustotal\": select: disk I/O error")},
		{"counter could not be written", errors.New("quota/sqlite: reserve: commit: database or disk is full")},
		{"table is missing entirely", errors.New("quota/sqlite: reserve \"virustotal\": no such table: quota_counters")},
		{"database is locked by another writer", errors.New("quota/sqlite: reserve: database is locked")},
		{"context deadline while reserving", context.DeadlineExceeded},
		{"context cancelled while reserving", context.Canceled},
		{"adapter rejected the reservation", fmt.Errorf("%w: reservation with no charges", ErrInvalidReservation)},
		{"an error class nobody has anticipated", errors.New("something new and unclassified")},
	}

	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{err: tc.err}
			gate, err := NewGate(plan, store)
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}

			err = gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC)
			if err == nil {
				t.Fatal("Admit returned nil: a call whose quota could not be established was allowed through")
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("Admit error = %v, want it to wrap ErrUnavailable so the gateway records \"quota unavailable\"", err)
			}
			if errors.Is(err, ErrExhausted) {
				t.Errorf("Admit error = %v, wrapped ErrExhausted: a broken counter is not an exhausted one, and the two are recorded differently", err)
			}
			// The underlying cause survives for the operator's log; the
			// classification is for the decision.
			if !errors.Is(err, tc.err) {
				t.Errorf("Admit error = %v, lost the underlying cause %v", err, tc.err)
			}
		})
	}

	// Positive control, same plan, same gate shape, healthy store.
	t.Run("positive control: the same call passes on a healthy store", func(t *testing.T) {
		gate, err := NewGate(plan, &fakeStore{})
		if err != nil {
			t.Fatalf("NewGate: %v", err)
		}
		if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC); err != nil {
			t.Fatalf("Admit on a healthy store = %v, want nil; the failure cases above would prove nothing if this gate refused everything", err)
		}
	})
}

// TestAdmit_AnEmptyPlanJudgesNothing pins the promise the empty plan makes
// to an installation with no [quota] section: the gate is wired, consulted
// on every dispatch, and has no opinion about any call -- not even about a
// call it could not attribute, which TestAdmit_RefusesWhenTheCallCannotBeAttributed
// refuses the moment one account is declared. The request path's other
// controls refuse such a call on their own, as they did before this gate
// existed; the gate must not change which of them does.
func TestAdmit_AnEmptyPlanJudgesNothing(t *testing.T) {
	store := &fakeStore{}
	gate, err := NewGate(mustPlan(t), store)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	for _, tc := range []struct {
		name, analyst, tool string
		now                 time.Time
	}{
		{"ordinary call", "analyst-a", "threatintel.lookup_ip", noonUTC},
		{"no analyst", "", "threatintel.lookup_ip", noonUTC},
		{"no tool", "analyst-a", "", noonUTC},
		{"zero clock reading", "analyst-a", "threatintel.lookup_ip", time.Time{}},
	} {
		if err := gate.Admit(context.Background(), tc.analyst, tc.tool, tc.now); err != nil {
			t.Errorf("%s: Admit over an empty plan = %v, want nil", tc.name, err)
		}
	}
	if n := len(store.calls()); n != 0 {
		t.Errorf("an empty plan reached the store %d time(s), want 0", n)
	}
}

// TestAdmit_RefusesWhenTheCallCannotBeAttributed covers the inputs that
// mean the gateway lost track of who is calling or when. Each is a refusal
// rather than a pass, and each is refused before the plan is consulted --
// a call nobody can be billed for is a call no limit can hold.
func TestAdmit_RefusesWhenTheCallCannotBeAttributed(t *testing.T) {
	ctx := context.Background()
	// A plan that charges nothing for this tool, so the only thing that can
	// produce a refusal is the check under test.
	plan := mustPlan(t, virustotal(10))

	cases := []struct {
		name    string
		analyst string
		tool    string
		now     time.Time
	}{
		{"no analyst", "", "threatintel.decode", noonUTC},
		{"whitespace analyst", "   ", "threatintel.decode", noonUTC},
		{"no tool", "analyst-a", "", noonUTC},
		{"zero clock reading", "analyst-a", "threatintel.decode", time.Time{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{}
			gate, err := NewGate(plan, store)
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}

			err = gate.Admit(ctx, tc.analyst, tc.tool, tc.now)
			if err == nil {
				t.Fatal("Admit returned nil for a call it cannot attribute")
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("Admit error = %v, want ErrUnavailable", err)
			}
			if len(store.calls()) != 0 {
				t.Errorf("the store was asked to reserve %d time(s) for a call that was never attributable", len(store.calls()))
			}
		})
	}

	// Positive control: the same free tool, with everything in place.
	gate, err := NewGate(plan, &fakeStore{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	if err := gate.Admit(ctx, "analyst-a", "threatintel.decode", noonUTC); err != nil {
		t.Fatalf("Admit(valid call to an uncharged tool) = %v, want nil", err)
	}
}

// TestNewGate_RefusesToBeWiredToNothing pins the other half of fail
// closed: the control must not be able to switch itself off because a
// dependency was left nil. An installation that declares no account says
// so with an empty Plan, which is a plan that charges nothing -- not a
// missing one.
func TestNewGate_RefusesToBeWiredToNothing(t *testing.T) {
	if _, err := NewGate(nil, &fakeStore{}); err == nil {
		t.Error("NewGate(nil plan) succeeded; a nil plan would make every call free")
	}
	if _, err := NewGate(mustPlan(t, virustotal(10)), nil); err == nil {
		t.Error("NewGate(nil store) succeeded; a nil store has nowhere to count and would make every call free")
	}

	// The legitimate "no quota declared" wiring, which must work.
	empty, err := NewPlan(nil, nil)
	if err != nil {
		t.Fatalf("NewPlan(nil): %v", err)
	}
	gate, err := NewGate(empty, &fakeStore{})
	if err != nil {
		t.Fatalf("NewGate(empty plan) = %v, want a usable gate", err)
	}
	if err := gate.Admit(context.Background(), "analyst-a", "casemgmt.list_cases", noonUTC); err != nil {
		t.Errorf("Admit under an empty plan = %v, want nil", err)
	}
}

// -----------------------------------------------------------------------
// Exhaustion
// -----------------------------------------------------------------------

// TestAdmit_ExhaustionIsItsOwnClassAndSaysWhatHappened pins what the
// gateway needs in order to record "quota exhausted" rather than "quota
// unavailable", and what the analyst reads at 03h.
//
// ADR-0030 decision 7 makes this refusal explicit rather than opaque, on
// the same line ErrForbidden already draws: what leaks is the operator's
// own published limit, not the SOC's security posture.
func TestAdmit_ExhaustionIsItsOwnClassAndSaysWhatHappened(t *testing.T) {
	ctx := context.Background()
	gate, err := NewGate(mustPlan(t, virustotal(2)), &fakeStore{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	for i := 1; i <= 2; i++ {
		if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC); err != nil {
			t.Fatalf("Admit call %d = %v, want nil while under the limit", i, err)
		}
	}

	err = gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC)
	if err == nil {
		t.Fatal("the third call passed against a limit of two")
	}
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("Admit error = %v, want ErrExhausted", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Errorf("Admit error = %v, also wrapped ErrUnavailable: exhausted and unavailable are recorded as different reasons and must not collapse", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "virustotal") {
		t.Errorf("refusal %q does not name the exhausted account", msg)
	}
	if !strings.Contains(msg, nextDayStart.Format(time.RFC3339)) {
		t.Errorf("refusal %q does not say when the window resets (%s)", msg, nextDayStart.Format(time.RFC3339))
	}
}

// TestExhaustion_NamesNoAnalyst is the counter-as-side-channel rule. A
// refusal is read by the analyst who triggered it and copied into an
// operator-facing audit reason; neither needs a name, and a message that
// carried one would be a component whose output describes people's
// investigative activity.
func TestExhaustion_NamesNoAnalyst(t *testing.T) {
	ctx := context.Background()
	gate, err := NewGate(mustPlan(t, virustotal(1)), &fakeStore{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	const analyst = "0f3c-analyst-a-subject"
	if err := gate.Admit(ctx, analyst, "threatintel.lookup_ip", noonUTC); err != nil {
		t.Fatalf("first Admit: %v", err)
	}
	err = gate.Admit(ctx, analyst, "threatintel.lookup_ip", noonUTC)
	if err == nil {
		t.Fatal("second Admit passed against a limit of one")
	}
	if strings.Contains(err.Error(), analyst) {
		t.Errorf("refusal %q names the analyst; no message this package produces should", err)
	}
}

// TestAdmit_OneAnalystsSpendingDoesNotMoveAnothers is the other half of
// the same property, and the reason the counter is keyed per analyst
// rather than pooled. A pooled ceiling would let the first analyst in a
// loop exhaust everybody -- the defect this component exists to remove --
// and would also turn the shared balance into a channel: analyst B could
// infer that somebody else had been busy.
func TestAdmit_OneAnalystsSpendingDoesNotMoveAnothers(t *testing.T) {
	ctx := context.Background()
	gate, err := NewGate(mustPlan(t, virustotal(2)), &fakeStore{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	for i := 1; i <= 2; i++ {
		if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC); err != nil {
			t.Fatalf("analyst-a call %d: %v", i, err)
		}
	}
	if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC); !errors.Is(err, ErrExhausted) {
		t.Fatalf("analyst-a third call = %v, want ErrExhausted", err)
	}

	for i := 1; i <= 2; i++ {
		if err := gate.Admit(ctx, "analyst-b", "threatintel.lookup_ip", noonUTC); err != nil {
			t.Fatalf("analyst-b call %d = %v, want nil: analyst-a's spending must not touch analyst-b's balance", i, err)
		}
	}
}

// TestAdmit_AnUndeclaredToolNeverReachesTheStore covers the ordinary case
// and pins that it is cheap: 16 of the 28 tools `threatintel` serves consume no
// third-party account, and every tool of casemgmt, logsearch and docsearch has
// no external budget to protect at all.
func TestAdmit_AnUndeclaredToolNeverReachesTheStore(t *testing.T) {
	store := &fakeStore{err: errors.New("the store must not be consulted for an uncharged tool")}
	gate, err := NewGate(mustPlan(t, virustotal(10), abusech(10)), store)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	for _, tool := range []string{"threatintel.decode", "threatintel.lookup_cve", "casemgmt.list_cases", "logsearch.search_absolute"} {
		if err := gate.Admit(context.Background(), "analyst-a", tool, noonUTC); err != nil {
			t.Errorf("Admit(%q) = %v, want nil: no declared account names it", tool, err)
		}
	}
	if len(store.calls()) != 0 {
		t.Errorf("the store was consulted %d time(s) for tools no account charges", len(store.calls()))
	}
}

// TestAdmit_ChargesEveryAccountOneCallTouches is the fan-out case that
// forces the counted unit to be the account. One lookup_ip spends several
// accounts at once, and the reservation covering all of them in one value
// is what makes the all-or-nothing rule expressible at the port.
func TestAdmit_ChargesEveryAccountOneCallTouches(t *testing.T) {
	store := &fakeStore{}
	plan := mustPlan(t,
		Provider{Name: "virustotal", Upstream: "threatintel", Limit: 5, Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip"}},
		Provider{Name: "shodan", Upstream: "threatintel", Limit: 5, Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip"}},
		Provider{Name: "abuseipdb", Upstream: "threatintel", Limit: 5, Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip"}},
	)
	gate, err := NewGate(plan, store)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	if err := gate.Admit(context.Background(), "analyst-a", "threatintel.lookup_ip", noonUTC); err != nil {
		t.Fatalf("Admit: %v", err)
	}

	calls := store.calls()
	if len(calls) != 1 {
		t.Fatalf("the store was asked to reserve %d times, want exactly 1: one call is one all-or-nothing reservation", len(calls))
	}
	var names []string
	for _, c := range calls[0].Charges {
		names = append(names, c.Provider)
	}
	want := []string{"abuseipdb", "shodan", "virustotal"}
	if !slices.Equal(names, want) {
		t.Errorf("charges = %v, want %v (every account the call touches, sorted by name)", names, want)
	}
}

// -----------------------------------------------------------------------
// The window, without a clock
// -----------------------------------------------------------------------

func TestWindowStart_TruncatesInUTC(t *testing.T) {
	day := Provider{Name: "p", Upstream: "threatintel", Limit: 1, Window: 24 * time.Hour, Tools: []string{"t"}}
	hour := Provider{Name: "p", Upstream: "threatintel", Limit: 1, Window: time.Hour, Tools: []string{"t"}}

	cases := []struct {
		name string
		p    Provider
		now  time.Time
		want time.Time
	}{
		{"midday lands on the day's start", day, noonUTC, dayStart},
		{"the instant the window opens is its own start", day, dayStart, dayStart},
		{"the last nanosecond before rollover is still the old window", day, nextDayStart.Add(-time.Nanosecond), dayStart},
		{"the first instant after rollover is the new window", day, nextDayStart, nextDayStart},
		{"an hourly window truncates to the hour", hour, noonUTC.Add(37 * time.Minute), noonUTC},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.p.WindowStart(tc.now)
			if !got.Equal(tc.want) {
				t.Errorf("WindowStart(%s) = %s, want %s", tc.now.Format(time.RFC3339Nano), got.Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
			}
			if _, offset := got.Zone(); offset != 0 {
				t.Errorf("WindowStart returned %s, which carries offset %d: the window start is stored as text and must have exactly one spelling", got, offset)
			}
		})
	}
}

// TestWindowStart_IsTheSameWindowWhateverOffsetTheClockCarries is the
// reason WindowStart calls .UTC() at all. Truncate already works on
// absolute time, so the *instant* never depended on the location -- but
// the result is stored, and stored as text. A gateway whose clock returns
// local time would key the window as "2026-09-13T21:00:00-03:00" while the
// same window in UTC spells itself "2026-09-14T00:00:00Z": two keys, two
// counters, twice the allowance, and nothing visibly wrong.
func TestWindowStart_IsTheSameWindowWhateverOffsetTheClockCarries(t *testing.T) {
	p := virustotal(10)

	saoPaulo := time.FixedZone("-03", -3*60*60)
	// The same instant as noonUTC, spelled in an offset.
	local := noonUTC.In(saoPaulo)

	fromUTC := p.WindowStart(noonUTC)
	fromLocal := p.WindowStart(local)

	if !fromUTC.Equal(fromLocal) {
		t.Fatalf("WindowStart differs by the clock's offset: %s vs %s", fromUTC.Format(time.RFC3339Nano), fromLocal.Format(time.RFC3339Nano))
	}
	if fromUTC.Format(time.RFC3339Nano) != fromLocal.Format(time.RFC3339Nano) {
		t.Errorf("the two window starts are the same instant but spell themselves differently: %q vs %q; they are stored as text, so that is two counters",
			fromUTC.Format(time.RFC3339Nano), fromLocal.Format(time.RFC3339Nano))
	}
}

// TestCharges_RollOverWithoutTouchingTheClock exercises the rollover the
// component's usefulness depends on, using two constants instead of a
// wall clock.
func TestCharges_RollOverWithoutTouchingTheClock(t *testing.T) {
	plan := mustPlan(t, virustotal(10))

	inside := plan.Charges("threatintel.lookup_ip", noonUTC)
	stillInside := plan.Charges("threatintel.lookup_ip", nextDayStart.Add(-time.Nanosecond))
	after := plan.Charges("threatintel.lookup_ip", nextDayStart)

	if len(inside) != 1 || len(stillInside) != 1 || len(after) != 1 {
		t.Fatalf("Charges returned %d/%d/%d charges, want 1 each", len(inside), len(stillInside), len(after))
	}
	if !inside[0].WindowStart.Equal(stillInside[0].WindowStart) {
		t.Errorf("two instants inside one window produced different window starts: %s vs %s",
			inside[0].WindowStart.Format(time.RFC3339Nano), stillInside[0].WindowStart.Format(time.RFC3339Nano))
	}
	if after[0].WindowStart.Equal(inside[0].WindowStart) {
		t.Error("the instant after the rollover kept the previous window's start: the allowance would never reset")
	}
	if !after[0].WindowStart.Equal(nextDayStart) {
		t.Errorf("window start after rollover = %s, want %s", after[0].WindowStart.Format(time.RFC3339Nano), nextDayStart.Format(time.RFC3339Nano))
	}
	if !inside[0].WindowEnd.Equal(nextDayStart) {
		t.Errorf("window end = %s, want %s: a refusal has to be able to say when the allowance returns",
			inside[0].WindowEnd.Format(time.RFC3339Nano), nextDayStart.Format(time.RFC3339Nano))
	}
	if got := inside[0].Window(); got != 24*time.Hour {
		t.Errorf("Charge.Window() = %s, want 24h", got)
	}
}

// TestAdmit_AllowanceReturnsWithTheNextWindow is the rollover seen from
// the request path: exhausted in one window, served in the next, with no
// clock and no sleep.
func TestAdmit_AllowanceReturnsWithTheNextWindow(t *testing.T) {
	ctx := context.Background()
	gate, err := NewGate(mustPlan(t, virustotal(1)), &fakeStore{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", noonUTC); !errors.Is(err, ErrExhausted) {
		t.Fatalf("second call in the same window = %v, want ErrExhausted", err)
	}
	if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", nextDayStart); err != nil {
		t.Errorf("first call of the next window = %v, want nil: a fixed window resets at its boundary", err)
	}
}

// -----------------------------------------------------------------------
// Policy validation: a limit nobody set is not a limit of infinity
// -----------------------------------------------------------------------

func TestProvider_Validate(t *testing.T) {
	valid := virustotal(120)

	cases := []struct {
		name   string
		mutate func(*Provider)
		want   string
	}{
		{"absent limit", func(p *Provider) { p.Limit = 0 }, "limit 0"},
		{"negative limit", func(p *Provider) { p.Limit = -1 }, "limit -1"},
		{"absent window", func(p *Provider) { p.Window = 0 }, "window 0s"},
		{"negative window", func(p *Provider) { p.Window = -time.Hour }, "window -1h0m0s"},
		{"empty name", func(p *Provider) { p.Name = "" }, "empty name"},
		{"name with whitespace", func(p *Provider) { p.Name = "virustotal " }, "whitespace"},
		{"no upstream", func(p *Provider) { p.Upstream = "" }, "no upstream"},
		{"no tools", func(p *Provider) { p.Tools = nil }, "lists no tools"},
		{"empty tool name", func(p *Provider) { p.Tools = []string{"threatintel.lookup_ip", " "} }, "empty tool name"},
		{"tool listed twice", func(p *Provider) { p.Tools = []string{"threatintel.lookup_ip", "threatintel.lookup_ip"} }, "twice"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			p.Tools = slices.Clone(valid.Tools)
			tc.mutate(&p)

			err := p.Validate()
			if err == nil {
				t.Fatal("Validate returned nil")
			}
			if !errors.Is(err, ErrInvalidProvider) {
				t.Errorf("error = %v, want it to wrap ErrInvalidProvider", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.want)
			}
		})
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid provider) = %v, want nil; the cases above would prove nothing if everything were refused", err)
	}
}

// TestProvider_ValidateSaysRaiseTheLimitRatherThanRemoveIt pins the
// wording, not just the refusal. The precedent is quarantine's
// refresh_interval = 0, which is refused with a message telling the
// operator to raise the interval: a control switched off for a minute and
// left off must not be expressible without the file admitting it. A zero
// limit read as "unlimited" would be exactly that, and ADR-0030's own
// example uses limit = 0 as a marker meaning "nobody has measured this
// yet", which must not start a gateway.
func TestProvider_ValidateSaysRaiseTheLimitRatherThanRemoveIt(t *testing.T) {
	p := virustotal(0)
	err := p.Validate()
	if err == nil {
		t.Fatal("a provider with limit 0 validated")
	}
	msg := err.Error()
	if !strings.Contains(msg, "greater than zero") || !strings.Contains(msg, "do not remove it") {
		t.Errorf("message = %q, want it to tell the operator to raise the limit rather than read 0 as no limit", msg)
	}
}

func TestNewPlan_RefusesDuplicateAccounts(t *testing.T) {
	// Two blocks, one account. This is the abuse.ch counting mistake in
	// another shape: the counter is keyed by name, so these two limits are
	// two budgets against one third-party allowance.
	_, err := NewPlan([]Provider{virustotal(100), virustotal(50)}, nil)
	if err == nil {
		t.Fatal("NewPlan accepted two providers named \"virustotal\"")
	}
	if !errors.Is(err, ErrInvalidProvider) {
		t.Errorf("error = %v, want it to wrap ErrInvalidProvider", err)
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error = %q, want it to say the provider is duplicated", err.Error())
	}
}

func TestNewPlan_RefusesAnInvalidProvider(t *testing.T) {
	if _, err := NewPlan([]Provider{virustotal(10), abusech(0)}, nil); !errors.Is(err, ErrInvalidProvider) {
		t.Errorf("NewPlan with an unlimited account = %v, want ErrInvalidProvider", err)
	}
}

// TestPlan_IsImmutable is the access.Policy lesson applied here: Tools is
// a slice, so a plan that stored the caller's Provider verbatim would
// share a backing array with whoever built it, and Providers() would hand
// that same array to anyone who asked. Both aliasings were real bugs in
// access.Policy, caught by exactly this test.
func TestPlan_IsImmutable(t *testing.T) {
	declared := []Provider{{
		Name:     "virustotal",
		Upstream: "threatintel",
		Limit:    10,
		Window:   24 * time.Hour,
		Tools:    []string{"threatintel.lookup_ip"},
	}}
	plan := mustPlan(t, declared...)

	// Mutate what the caller still holds.
	declared[0].Tools[0] = "threatintel.decode"
	declared[0].Limit = 1_000_000

	if got := plan.Charges("threatintel.lookup_ip", noonUTC); len(got) != 1 {
		t.Fatalf("mutating the caller's slice changed what the plan charges: Charges(\"threatintel.lookup_ip\") = %v", got)
	} else if got[0].Limit != 10 {
		t.Errorf("limit = %d, want 10: mutating the caller's Provider changed the live plan", got[0].Limit)
	}

	// Mutate what Providers() handed back.
	out := plan.Providers()
	if len(out) != 1 {
		t.Fatalf("Providers() returned %d entries, want 1", len(out))
	}
	out[0].Tools[0] = "threatintel.decode"
	if got := plan.Charges("threatintel.lookup_ip", noonUTC); len(got) != 1 {
		t.Error("mutating the slice Providers() returned changed what the plan charges")
	}
}

// -----------------------------------------------------------------------
// Charge and Reservation contracts
// -----------------------------------------------------------------------

func TestCharge_ZeroValueGrantsNothing(t *testing.T) {
	var c Charge
	if c.Fits(1) {
		t.Error("the zero Charge admitted a first call: a limit nobody set is not a limit of infinity")
	}
}

func TestCharge_Fits(t *testing.T) {
	c := Charge{Provider: "virustotal", Limit: 2, WindowStart: dayStart, WindowEnd: nextDayStart}
	for _, used := range []int{1, 2} {
		if !c.Fits(used) {
			t.Errorf("Fits(%d) = false against a limit of 2", used)
		}
	}
	if c.Fits(3) {
		t.Error("Fits(3) = true against a limit of 2")
	}
}

// TestCharge_ValidateRefusesAWindowStartThatIsNotInUTC guards the one way
// a correct-looking Charge silently doubles an allowance: the window start
// is the counter's key and is stored as text, so the same instant in two
// offsets is two counters.
func TestCharge_ValidateRefusesAWindowStartThatIsNotInUTC(t *testing.T) {
	saoPaulo := time.FixedZone("-03", -3*60*60)
	c := Charge{
		Provider:    "virustotal",
		Limit:       10,
		WindowStart: dayStart.In(saoPaulo),
		WindowEnd:   nextDayStart,
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("a charge whose window start carries an offset validated")
	}
	if !strings.Contains(err.Error(), "not in UTC") {
		t.Errorf("error = %q, want it to name the offset as the problem", err.Error())
	}

	// Positive control: the same charge, in UTC.
	c.WindowStart = dayStart
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(UTC charge) = %v, want nil", err)
	}
}

func TestReservation_Validate(t *testing.T) {
	good := Charge{Provider: "virustotal", Limit: 10, WindowStart: dayStart, WindowEnd: nextDayStart}

	cases := []struct {
		name string
		r    Reservation
		want string
	}{
		{"no analyst", Reservation{Charges: []Charge{good}}, "no analyst identity"},
		{"no charges", Reservation{Analyst: "analyst-a"}, "no charges"},
		{
			"the same account twice",
			Reservation{Analyst: "analyst-a", Charges: []Charge{good, good}},
			"charged twice",
		},
		{
			"an invalid charge",
			Reservation{Analyst: "analyst-a", Charges: []Charge{{Provider: "virustotal", Limit: 0, WindowStart: dayStart, WindowEnd: nextDayStart}}},
			"want greater than zero",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.Validate()
			if err == nil {
				t.Fatal("Validate returned nil")
			}
			if !errors.Is(err, ErrInvalidReservation) {
				t.Errorf("error = %v, want it to wrap ErrInvalidReservation", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.want)
			}
		})
	}

	valid := Reservation{Analyst: "analyst-a", Charges: []Charge{good}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid reservation) = %v, want nil", err)
	}
}

// -----------------------------------------------------------------------
// Structural guarantees: no secret, no way to read a counter
// -----------------------------------------------------------------------

// TestStore_PortCannotReadOrLowerACounter turns two doc comments into
// something the test suite enforces.
//
// A read method would make the counter a side channel: it is a record of
// which accounts an analyst has been querying, and one analyst
// enumerating another's investigative activity is not a capability this
// gateway should hand out. A method that lowered a counter would be the
// `quota reset` ADR-0030 decision 8 refuses -- returning 120 units to one
// analyst does not create 120 lookups at VirusTotal, it takes them from
// the rest of the team with no diff and no review.
//
// Neither can be added by accident: this test names the entire method set.
func TestStore_PortCannotReadOrLowerACounter(t *testing.T) {
	typ := reflect.TypeOf((*Store)(nil)).Elem()
	if typ.Kind() != reflect.Interface {
		t.Fatalf("quota.Store is a %s, want an interface", typ.Kind())
	}

	var methods []string
	for i := range typ.NumMethod() {
		methods = append(methods, typ.Method(i).Name)
	}
	want := []string{"Reserve"}
	if !slices.Equal(methods, want) {
		t.Errorf("quota.Store has methods %v, want exactly %v.\n"+
			"A method that reads a counter makes it a channel for learning what another analyst looked up; "+
			"a method that lowers one is the quota reset ADR-0030 decision 8 refuses. "+
			"If a new method is genuinely needed, that is an ADR amendment, not a test update.",
			methods, want)
	}
}

// TestQuotaValuesCarryNoCredentialField is the reflection guard
// access.Identity already has, applied to every value this package
// defines. The risk is not today's code; it is the future change that
// stashes a key on a Provider "so the quota can ask the provider how much
// is left". That field is how a third-party API key ends up in an error
// message, a log line or a SQLite row -- and this package's whole storage
// layer is a table an operator reads by hand.
func TestQuotaValuesCarryNoCredentialField(t *testing.T) {
	forbidden := []string{"token", "secret", "password", "credential", "bearer", "jwt", "assertion", "apikey", "key"}

	types := []reflect.Type{
		reflect.TypeOf(Provider{}),
		reflect.TypeOf(Charge{}),
		reflect.TypeOf(Reservation{}),
		reflect.TypeOf(Usage{}),
	}
	for _, typ := range types {
		if typ.NumField() == 0 {
			t.Fatalf("%s has no fields; this test would pass vacuously", typ.Name())
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			lower := strings.ToLower(field.Name)
			for _, bad := range forbidden {
				if strings.Contains(lower, bad) {
					t.Errorf("quota.%s has field %q, whose name contains %q: no value in this package may hold a credential. "+
						"An account's key reaches its upstream as a name in the registry entry's EnvVarNames, resolved by the Credential Vault at spawn time.",
						typ.Name(), field.Name, bad)
				}
			}
		}
	}

	// The detector must actually detect, or the loop above rots into a
	// no-op the day somebody "simplifies" the matching.
	type canary struct {
		Name        string
		ProviderKey string
		BearerToken string
	}
	found := 0
	ct := reflect.TypeOf(canary{})
	for i := range ct.NumField() {
		lower := strings.ToLower(ct.Field(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				found++
				break
			}
		}
	}
	if found != 2 {
		t.Errorf("the credential-name detector flagged %d of 2 canary fields; the check above is not actually checking", found)
	}
}

// -----------------------------------------------------------------------
// Concurrency at the domain boundary
// -----------------------------------------------------------------------

// TestAdmit_DelegatesEveryDecisionToTheStoreUnderConcurrency pins that the
// Gate adds no caching, no short-circuit and no serialisation of its own:
// every chargeable call reaches the Store, which is where the atomic
// reserve lives. If the Gate ever tried to answer from memory, two
// concurrent callers could both be told yes while only one debit landed --
// and the store-side test proving N-1 of N callers are refused would still
// pass, because it never sees the calls the Gate answered itself.
//
// Run with -race for the second half of the property: Plan is read
// concurrently by every request and must never be written.
func TestAdmit_DelegatesEveryDecisionToTheStoreUnderConcurrency(t *testing.T) {
	const callers = 32

	store := &fakeStore{}
	gate, err := NewGate(mustPlan(t, virustotal(callers)), store)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			if err := gate.Admit(context.Background(), "analyst-a", "threatintel.lookup_ip", noonUTC); err != nil {
				t.Errorf("Admit under the limit = %v, want nil", err)
			}
		}()
	}
	wg.Wait()

	if got := len(store.calls()); got != callers {
		t.Errorf("the store saw %d reservations for %d chargeable calls: the Gate answered %d of them itself",
			got, callers, callers-got)
	}
}

// TestReaderIsASeparatePortFromStore is the structural half of the
// separation the two port declarations argue for: the request path holds
// Store and cannot read a counter, the Operator Console holds Reader and
// cannot debit one.
//
// The counter is a record of which accounts an analyst has been querying
// -- which is to say, a summary of what they are investigating -- so
// "how much has X spent" must not be answerable from anything a tool call
// can reach. Reading is a real operator need, and the way to serve it
// without serving it to the request path is for the two capabilities to
// live on interfaces neither of which is assignable to the other.
//
// A single interface with both methods would satisfy every other test in
// this file and quietly undo that, which is why this one is written in
// terms of assignability rather than in terms of method names alone.
func TestReaderIsASeparatePortFromStore(t *testing.T) {
	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	readerType := reflect.TypeOf((*Reader)(nil)).Elem()

	var methods []string
	for i := range readerType.NumMethod() {
		methods = append(methods, readerType.Method(i).Name)
	}
	if want := []string{"Usage"}; !slices.Equal(methods, want) {
		t.Errorf("quota.Reader has methods %v, want exactly %v. In particular it must never gain a way to LOWER a counter: "+
			"returning units to one analyst does not create requests at the provider, it takes them from the rest of the team.",
			methods, want)
	}

	if storeType.Implements(readerType) {
		t.Error("quota.Store satisfies quota.Reader, so whoever can debit can also read: " +
			"the Gateway holds a Store, and a Gateway that can read counters puts one analyst's investigative activity " +
			"one call away from another analyst's tool call")
	}
	if readerType.Implements(storeType) {
		t.Error("quota.Reader satisfies quota.Store, so the Operator Console could spend an analyst's allowance by reading it")
	}

	// The canary: two interfaces that genuinely do nest must be seen to
	// nest, or the assertions above pass for the wrong reason.
	type reserverAndReader interface {
		Store
		Reader
	}
	both := reflect.TypeOf((*reserverAndReader)(nil)).Elem()
	if !both.Implements(storeType) || !both.Implements(readerType) {
		t.Fatal("reflect.Implements is not detecting interface embedding, so this test proves nothing")
	}
}

// TestNewPlan_FreeToolsAreDeclaredNotAssumed pins the whole reason the free
// list exists: "this tool spends nothing" and "nobody mentioned this tool"
// have to be different states, because for a tool of an upstream whose
// third-party budget is being protected only the first one is safe.
func TestNewPlan_FreeToolsAreDeclaredNotAssumed(t *testing.T) {
	charged := Provider{
		Name: "virustotal", Upstream: "threatintel", Limit: 10,
		Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip"},
	}

	t.Run("a declared free tool is declared, an unmentioned one is not", func(t *testing.T) {
		p, err := NewPlan([]Provider{charged}, []string{"threatintel.decode"})
		if err != nil {
			t.Fatalf("NewPlan: %v", err)
		}
		for tool, want := range map[string]bool{
			"threatintel.lookup_ip": true,  // charged
			"threatintel.decode":    true,  // declared free
			"threatintel.enrich":    false, // nobody said anything
		} {
			if got := p.IsDeclared(tool); got != want {
				t.Errorf("IsDeclared(%q) = %v, want %v", tool, got, want)
			}
		}
	})

	t.Run("a free tool changes nothing about what anything costs", func(t *testing.T) {
		p, err := NewPlan([]Provider{charged}, []string{"threatintel.decode"})
		if err != nil {
			t.Fatalf("NewPlan: %v", err)
		}
		if charges := p.Charges("threatintel.decode", noonUTC); len(charges) != 0 {
			t.Errorf("a tool declared free costs %+v, want nothing", charges)
		}
		// Positive control: the charged tool still charges.
		if charges := p.Charges("threatintel.lookup_ip", noonUTC); len(charges) != 1 {
			t.Fatalf("the charged tool costs %d charge(s), want 1", len(charges))
		}
	})

	t.Run("charged and free at once is refused, not reconciled", func(t *testing.T) {
		// Letting the charge silently win would leave a file saying one
		// thing and a gateway doing another, which is the shape of every
		// finding this component exists to prevent.
		_, err := NewPlan([]Provider{charged}, []string{"threatintel.lookup_ip"})
		if !errors.Is(err, ErrInvalidProvider) {
			t.Fatalf("NewPlan = %v, want ErrInvalidProvider", err)
		}
		if !strings.Contains(err.Error(), "threatintel.lookup_ip") {
			t.Errorf("the error does not name the contradicting tool: %v", err)
		}
	})

	t.Run("an empty or duplicated entry is refused", func(t *testing.T) {
		if _, err := NewPlan(nil, []string{"  "}); !errors.Is(err, ErrInvalidProvider) {
			t.Errorf("NewPlan with a blank free tool = %v, want ErrInvalidProvider", err)
		}
		if _, err := NewPlan(nil, []string{"threatintel.decode", "threatintel.decode"}); !errors.Is(err, ErrInvalidProvider) {
			t.Errorf("NewPlan with a duplicate free tool = %v, want ErrInvalidProvider", err)
		}
		// Positive control.
		if _, err := NewPlan(nil, []string{"threatintel.decode", "threatintel.lookup_cve"}); err != nil {
			t.Errorf("NewPlan with two distinct free tools = %v, want nil", err)
		}
	})

	t.Run("FreeTools returns a sorted copy", func(t *testing.T) {
		p, err := NewPlan(nil, []string{"threatintel.decode", "threatintel.lookup_cve"})
		if err != nil {
			t.Fatalf("NewPlan: %v", err)
		}
		got := p.FreeTools()
		if !slices.Equal(got, []string{"threatintel.decode", "threatintel.lookup_cve"}) {
			t.Fatalf("FreeTools() = %v, want sorted", got)
		}
		got[0] = "mutated"
		if again := p.FreeTools(); again[0] == "mutated" {
			t.Error("a caller mutating the returned slice rewrote the plan")
		}
	})
}
