package gateway

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// ------------------------------------------------- per-analyst quota
//
// design/adr/0030-quota-por-analista.md, Compliance
// items 1, 2 and 4. The component's own behaviour -- windows, atomicity,
// concurrency, what a counter does when the store breaks -- is tested in
// internal/quota and internal/quota/sqlite. What is tested HERE is the
// only thing those cannot see: where the gate sits in Dispatch, and what
// the trail says when it fires.

// scriptedQuotaStore is a quota.Store that answers with whatever the test
// tells it to, and records what it was asked.
//
// Two reasons it is a fake rather than the real SQLite store. First, the
// failure cases: "the counter could not be read" and "the counter could
// not be written" are the whole of ADR-0030 decision 6, and the real
// adapter offers no honest way to force them from here (the adapter's own
// tests force them properly, with a revoked table and a closed handle).
// Second, "the quota was never consulted" is an assertion about a call
// that did NOT happen, which only a recording double can answer.
type scriptedQuotaStore struct {
	mu   sync.Mutex
	err  error
	seen []quota.Reservation
}

func (s *scriptedQuotaStore) Reserve(_ context.Context, r quota.Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, r)
	return s.err
}

func (s *scriptedQuotaStore) reservations() []quota.Reservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

// virustotalOn is a declared account charging one tool of one upstream.
// Named after the real one because the numbers a reader carries away from
// a test should not look like recommendations for production: the limits
// here are two and three.
func virustotalOn(upstream, tool string, limit int) quota.Provider {
	return quota.Provider{
		Name:     "virustotal",
		Upstream: upstream,
		Limit:    limit,
		Window:   24 * time.Hour,
		Tools:    []string{tool},
	}
}

// rowsFor returns the audit records for one tool, in the order written.
func rowsFor(rows []audit.Record, tool string) []audit.Record {
	var out []audit.Record
	for _, r := range rows {
		if r.Tool == tool {
			out = append(out, r)
		}
	}
	return out
}

// TestDispatch_QuotaExhaustedDeniesBeforeTheAllowedRow is ADR-0030's
// Compliance item 1, from both sides.
//
// The allowed row means "this call was dispatched" (ADR-0012 §1), so a
// refusal that landed after one would leave the trail asserting something
// that did not happen -- and the trail is the only attribution this system
// has, since the backend sees a service account and not an analyst. So:
// the refused call must produce a denied row carrying exactly the reason
// an operator will grep for, no allowed row of its own, and no call to the
// backend.
//
// The two calls before it are the positive control, in the same test on
// purpose: a gate that refused everything would satisfy every assertion
// below about the third call.
func TestDispatch_QuotaExhaustedDeniesBeforeTheAllowedRow(t *testing.T) {
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 2)},
	}, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	for i := range 2 {
		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil); err != nil {
			t.Fatalf("call %d of an allowance of 2 = %v, want nil", i+1, err)
		}
	}

	_, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil)
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("the call over the limit = %v, want one wrapping quota.ErrExhausted", err)
	}
	// Explicit, because the alternative was seriously considered and
	// rejected: an exhausted quota must NOT masquerade as a missing tool.
	// What it discloses is the operator's own published limit and the
	// caller's own consumption of it, never which tools exist.
	if errors.Is(err, ErrUnknownTool) {
		t.Errorf("a spent allowance was reported as an unknown tool: %v", err)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 2 {
		t.Errorf("the backend was called %d times, want 2: the refused call must not have left the process", len(calls))
	}

	rows := rowsFor(h.auditRows(), "casemgmt.list_cases")
	if len(rows) != 3 {
		t.Fatalf("audit rows = %d, want 3 (two allowed, one denied)", len(rows))
	}
	for i, r := range rows[:2] {
		if r.Outcome != audit.OutcomeAllowed {
			t.Errorf("row %d outcome = %q, want %q", i, r.Outcome, audit.OutcomeAllowed)
		}
	}
	last := rows[2]
	if last.Outcome != audit.OutcomeDenied {
		t.Errorf("the refused call recorded outcome %q, want %q -- no new Outcome value is invented for a quota refusal", last.Outcome, audit.OutcomeDenied)
	}
	if last.Reason != reasonQuotaExhausted {
		t.Errorf("the refused call recorded reason %q, want exactly %q", last.Reason, reasonQuotaExhausted)
	}
	if last.AnalystIdentity != analyst.Subject {
		t.Errorf("the refused call was attributed to %q, want %q (Subject, never Name)", last.AnalystIdentity, analyst.Subject)
	}
	if last.TargetUpstream != "casemgmt" {
		t.Errorf("the refused call named upstream %q, want %q", last.TargetUpstream, "casemgmt")
	}

	// A refused call spends nothing: the reservation is all or nothing.
	if used := h.used("virustotal"); used != 2 {
		t.Errorf("counter = %d after two allowed calls and one refusal, want 2", used)
	}
}

// TestDispatch_QuotaRunsAfterQuarantineSoRefusalsStayOpaque is ADR-0030's
// Compliance item 1 second half, and the reason the gate is where it is
// rather than one line higher.
//
// ADR-0007 rule 3 bought an opacity: a tool under quarantine must be
// indistinguishable from a tool that does not exist, because a caller able
// to tell them apart can read the SOC's security posture tool by tool from
// outside. A quota check placed before the quarantine would answer "you
// are over your limit" for a quarantined tool -- which confirms the tool
// exists, through the newest code path rather than the hardened one.
//
// The store is scripted to refuse everything, so the assertion is sharp in
// both directions: while the tool is quarantined the answer is
// ErrUnknownTool and the store was never asked; once it is approved the
// same call reaches the store and is refused by it.
func TestDispatch_QuotaRunsAfterQuarantineSoRefusalsStayOpaque(t *testing.T) {
	spent := &scriptedQuotaStore{err: quota.Exhausted(quota.Charge{
		Provider:    "virustotal",
		Limit:       1,
		WindowStart: fixedAt.Truncate(24 * time.Hour),
		WindowEnd:   fixedAt.Truncate(24 * time.Hour).Add(24 * time.Hour),
	})}
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 1)},
		store:     spent,
	}, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	// Deliberately NOT approved: the tool is pending in quarantine.

	_, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("a quarantined tool over its limit = %v, want ErrUnknownTool", err)
	}
	if errors.Is(err, quota.ErrExhausted) {
		t.Error("a quarantined tool answered with the quota's error, which tells the caller the tool exists")
	}
	if n := len(spent.reservations()); n != 0 {
		t.Errorf("the quota was consulted %d time(s) for a quarantined tool, want 0: the gate belongs after admit", n)
	}
	if rows := rowsFor(h.auditRows(), "casemgmt.list_cases"); len(rows) != 1 || rows[0].Reason != "quarantined" {
		t.Errorf("audit rows = %+v, want exactly one with reason %q", rows, "quarantined")
	}

	// Positive control: approve the tool and the very same call now
	// reaches the quota and is refused by it. Without this half, a gate
	// that was never wired at all would pass everything above.
	h.approve("casemgmt", "list_cases")
	_, err = h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil)
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("after approval = %v, want one wrapping quota.ErrExhausted", err)
	}
	if n := len(spent.reservations()); n != 1 {
		t.Errorf("the quota was consulted %d time(s) after approval, want 1", n)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
		t.Errorf("the backend was called %d times, want 0", len(calls))
	}
}

// TestDispatch_EveryQuotaStoreFailureRefusesTheCall is ADR-0030's
// Compliance item 2: fail closed, in both directions, with a positive
// control in the same test.
//
// The direction matters more than the coverage. Every other control in
// this system refuses when the state that governs it cannot be read --
// ADR-0004 for the registry, verifyEntry for signatures, admit for
// quarantine -- and a quota that turned into a free pass when its counter
// broke would be the single control here with the inverse behaviour.
// Anyone who wanted the team's VirusTotal budget would then only have to
// break the counter.
//
// Read failures and write failures are in one table on purpose: they must
// be indistinguishable in effect. If a failed write could pass, the attack
// would simply be to make writes fail.
func TestDispatch_EveryQuotaStoreFailureRefusesTheCall(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{"counter cannot be read", errors.New("disk I/O error")},
		{"counter cannot be written", errors.New("attempt to write a readonly database")},
		{"counter is locked by another writer", errors.New("database is locked")},
		{"context deadline while reserving", context.DeadlineExceeded},
		{"a failure class nobody anticipated", errors.New("some brand new adapter error")},
	}

	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			broken := &scriptedQuotaStore{err: tc.err}
			h := newQuotaHarness(t, quotaSetup{
				providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 5)},
				store:     broken,
			}, "casemgmt.list_cases")
			h.register("casemgmt")
			h.serve("casemgmt", def("list_cases", "list cases"))
			h.mustConnect()
			h.approve("casemgmt", "list_cases")

			_, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil)
			if err == nil {
				t.Fatal("Dispatch returned nil with a broken counter: a quota that cannot count must not be a free pass")
			}
			if !errors.Is(err, quota.ErrUnavailable) {
				t.Errorf("Dispatch error = %v, want one wrapping quota.ErrUnavailable", err)
			}
			if errors.Is(err, quota.ErrExhausted) {
				t.Error("a broken counter was reported as a spent allowance: an operator would go and raise a limit that is fine")
			}
			if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
				t.Errorf("the backend was called %d times with an unusable counter, want 0", len(calls))
			}

			rows := rowsFor(h.auditRows(), "casemgmt.list_cases")
			if len(rows) != 1 {
				t.Fatalf("audit rows = %d, want exactly 1 (the denial)", len(rows))
			}
			if rows[0].Outcome != audit.OutcomeDenied || rows[0].Reason != reasonQuotaUnavailable {
				t.Errorf("recorded (%q, %q), want (%q, %q)",
					rows[0].Outcome, rows[0].Reason, audit.OutcomeDenied, reasonQuotaUnavailable)
			}
		})
	}

	// The positive control, run against the same plan and the same tool:
	// a healthy counter lets the call through. Without it every assertion
	// above would also pass on a gateway that refused every call for an
	// unrelated reason.
	t.Run("positive control: a healthy counter admits the call", func(t *testing.T) {
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 5)},
		}, "casemgmt.list_cases")
		h.register("casemgmt")
		h.serve("casemgmt", def("list_cases", "list cases"))
		h.mustConnect()
		h.approve("casemgmt", "list_cases")

		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil); err != nil {
			t.Fatalf("Dispatch with a healthy counter = %v, want nil", err)
		}
		if used := h.used("virustotal"); used != 1 {
			t.Errorf("counter = %d, want 1", used)
		}
	})
}

// TestDispatch_ACallThatFailsAtTheBackendStillSpentQuota pins the cost
// ADR-0030 decision 5 accepted in writing, so that nobody "fixes" it later
// without meeting the argument.
//
// The debit is taken before the call and is never given back. A debit
// taken on the answer would leave free exactly the case the control exists
// for -- the loop whose calls never return -- and this gateway cannot
// learn whether the third party charged anyway, because the fan-out
// happens inside the upstream's process. Over-counting protects the
// budget; under-counting burns it.
func TestDispatch_ACallThatFailsAtTheBackendStillSpentQuota(t *testing.T) {
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 5)},
	}, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.dialer.upstream("casemgmt").callErr = errors.New("connection reset")

	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil); err == nil {
		t.Fatal("Dispatch of a call the backend broke returned nil")
	}
	if used := h.used("virustotal"); used != 1 {
		t.Errorf("counter = %d after a call that failed at the backend, want 1: the debit precedes the call and is never reversed", used)
	}

	rows := rowsFor(h.auditRows(), "casemgmt.list_cases")
	if len(rows) != 2 {
		t.Fatalf("audit rows = %d, want 2 (allowed, then failed)", len(rows))
	}
	if rows[0].Outcome != audit.OutcomeAllowed || rows[1].Outcome != audit.OutcomeFailed {
		t.Errorf("outcomes = (%q, %q), want (%q, %q)", rows[0].Outcome, rows[1].Outcome, audit.OutcomeAllowed, audit.OutcomeFailed)
	}
}

// TestDispatch_AnUnchargedToolNeverTouchesTheCounter is the ordinary case,
// and it is worth an assertion because it is most of the fleet: many of a
// threat-intel backend's tools spend no third-party account, and casemgmt,
// logsearch and docsearch have no external budget at all. A gateway that wrote a
// counter row per call would be paying for a control that is not
// protecting anything, on the request path, forever.
func TestDispatch_AnUnchargedToolNeverTouchesTheCounter(t *testing.T) {
	watched := &scriptedQuotaStore{}
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 5)},
		// Declared free, not merely unmentioned, and the distinction is the
		// point of UndeclaredQuotaTools: `casemgmt` is a budgeted upstream
		// here, so a tool of it that nobody costed would be withheld from
		// the routing table. Saying "spends nothing" is how the free case
		// is said now, and the gateway refuses to route the silent version.
		freeTools: []string{"casemgmt.get_case"},
		store:     watched,
	}, "casemgmt.list_cases", "casemgmt.get_case")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"), def("get_case", "get one case"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "get_case")

	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.get_case", nil); err != nil {
		t.Fatalf("Dispatch of an uncharged tool = %v, want nil", err)
	}
	if n := len(watched.reservations()); n != 0 {
		t.Errorf("the counter was written %d time(s) for a tool no account declares, want 0", n)
	}

	// Positive control: the charged tool, same gateway, does reach it.
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil); err != nil {
		t.Fatalf("Dispatch of a charged tool = %v, want nil", err)
	}
	if n := len(watched.reservations()); n != 1 {
		t.Fatalf("the counter was written %d time(s) for a charged tool, want 1", n)
	}
	got := watched.reservations()[0]
	if got.Analyst != analyst.Subject {
		t.Errorf("reservation attributed to %q, want %q", got.Analyst, analyst.Subject)
	}
	if len(got.Charges) != 1 || got.Charges[0].Provider != "virustotal" {
		t.Errorf("reservation charges = %+v, want exactly one against %q", got.Charges, "virustotal")
	}
}

// TestConnect_RefusesToServeWhenAQuotaAccountNamesNoRegisteredUpstream is
// ADR-0030 decision 4's cross-check, the one Config.Validate cannot make
// because no database is open when the file is parsed.
//
// An operator believes a third party's budget is protected and it is not.
// Unlike a backend that will not dial, that cannot come right on its own --
// it is two files on disk disagreeing -- so this is one of exactly two
// fatal Connect failures, and nothing is served until it is fixed.
//
// The internal tree also refused an upstream whose credential mode was not
// "shared". This gateway has no credential mode -- every entry shares its
// credential -- so there is no second clause to test.
func TestConnect_RefusesToServeWhenAQuotaAccountNamesNoRegisteredUpstream(t *testing.T) {
	t.Run("the named upstream is not registered", func(t *testing.T) {
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
		}, "casemgmt.list_cases")
		h.register("casemgmt") // threatintel is not registered.
		h.serve("casemgmt", def("list_cases", "list cases"))

		err := h.connect()
		if !errors.Is(err, ErrQuotaMisconfigured) {
			t.Fatalf("Connect = %v, want one wrapping ErrQuotaMisconfigured", err)
		}
		if h.dialer.wasDialed("casemgmt") {
			t.Error("a backend was dialed even though the quota policy does not match the registry")
		}
		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil); !errors.Is(err, ErrUnknownTool) {
			t.Errorf("Dispatch after a refused Connect = %v, want ErrUnknownTool: nothing may be served", err)
		}
	})

	t.Run("positive control: the registry agrees", func(t *testing.T) {
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 5)},
		}, "casemgmt.list_cases")
		h.register("casemgmt")
		h.serve("casemgmt", def("list_cases", "list cases"))

		if err := h.connect(); err != nil {
			t.Fatalf("Connect with a matching registry = %v, want nil", err)
		}
		if !h.dialer.wasDialed("casemgmt") {
			t.Error("the matching upstream was not dialed")
		}
	})
}

// TestConnect_WithholdsAToolOfABudgetedUpstreamThatNobodyCosted is the
// other half of the cross-check above, and it is the half that can actually
// hurt.
//
// The direction already covered -- "this account names an upstream that is
// not registered" -- is a limit that governs nothing, and it announces
// itself the first time anybody calls the tool. This direction is silent:
// everything dials, the routing table serves, `quota list` exits 0, the
// counter moves for the tools that were listed, and the account is spent
// through the tools that were not until the provider starts answering 429
// inside the backend's process, where the gateway cannot see it.
//
// Measured before this check existed: an account declared over
// `threatintel.virustotal` alone admitted 5000 calls to five other tools that
// spend the same VirusTotal account, with the Store consulted zero times.
//
// The response is to withhold the tool, not to refuse to start. See
// ErrQuotaUndeclaredTool for why the two quota failures differ.
func TestConnect_WithholdsAToolOfABudgetedUpstreamThatNobodyCosted(t *testing.T) {
	t.Run("the undeclared tool is not routed and the rest still is", func(t *testing.T) {
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
		}, "threatintel.lookup_ip", "threatintel.enrich")
		h.register("threatintel")
		h.serve("threatintel", def("lookup_ip", "look up an ip"), def("enrich", "enrich an indicator"))

		err := h.connect()
		if !errors.Is(err, ErrQuotaUndeclaredTool) {
			t.Fatalf("Connect = %v, want one wrapping ErrQuotaUndeclaredTool", err)
		}
		if errors.Is(err, ErrQuotaMisconfigured) {
			t.Error("the undeclared tool was reported as the FATAL quota failure; " +
				"that class stops the whole gateway and this one must not")
		}
		if !strings.Contains(err.Error(), "threatintel.enrich") {
			t.Errorf("the error does not name the undeclared tool: %v", err)
		}

		h.approve("threatintel", "enrich")
		h.approve("threatintel", "lookup_ip")

		// The hole, closed: the uncounted call cannot be made at all.
		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.enrich", nil); !errors.Is(err, ErrUnknownTool) {
			t.Errorf("Dispatch of the undeclared tool = %v, want ErrUnknownTool", err)
		}
		// And the outage, avoided: the declared tool of the same upstream
		// is still served.
		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.lookup_ip", nil); err != nil {
			t.Errorf("Dispatch of the declared tool = %v, want nil: withholding one tool may not cost the others", err)
		}
	})

	t.Run("declaring it free is how the operator says it costs nothing", func(t *testing.T) {
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
			freeTools: []string{"threatintel.enrich"},
		}, "threatintel.lookup_ip", "threatintel.enrich")
		h.register("threatintel")
		h.serve("threatintel", def("lookup_ip", "look up an ip"), def("enrich", "enrich an indicator"))

		if err := h.connect(); err != nil {
			t.Fatalf("Connect with every served tool declared = %v, want nil", err)
		}
		h.approve("threatintel", "enrich")
		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.enrich", nil); err != nil {
			t.Errorf("Dispatch of a tool declared free = %v, want nil", err)
		}
	})

	t.Run("an upstream no account names needs no declaration", func(t *testing.T) {
		// casemgmt, logsearch and docsearch carry one service credential each
		// against internal systems. Requiring a line per tool there would
		// be paperwork with no control behind it, and this asserts the
		// check knows the difference.
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
		}, "threatintel.lookup_ip", "casemgmt.list_cases", "casemgmt.get_case")
		h.register("threatintel")
		h.register("casemgmt")
		h.serve("threatintel", def("lookup_ip", "look up an ip"))
		h.serve("casemgmt", def("list_cases", "list cases"), def("get_case", "get one case"))

		if err := h.connect(); err != nil {
			t.Fatalf("Connect = %v, want nil: casemgmt is not budgeted, so its tools need no line", err)
		}
	})
}

// TestConnect_RefusesASecondEntryCarryingABudgetedCredential covers the
// path that needs no attacker: a `threatintel-v2` somebody stood up to try a new
// image, a rename that half-happened, a canary. Two entries, one key, one
// counter -- and the traffic through the second one is free forever while
// `upstream list` and `quota list` both report everything is fine.
func TestConnect_RefusesASecondEntryCarryingABudgetedCredential(t *testing.T) {
	sharedKey := "THREATINTEL_VIRUSTOTAL_API_KEY"
	entry := func(name string) registry.UpstreamServer {
		return registry.UpstreamServer{
			Name:        name,
			Transport:   registry.TransportStdio,
			Command:     "/usr/bin/threatintel",
			EnvVarNames: []string{sharedKey},
		}
	}

	t.Run("an unbudgeted twin holding the same key stops the gateway", func(t *testing.T) {
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
		}, "threatintel.lookup_ip")
		h.reg.entries = append(h.reg.entries, entry("threatintel"), entry("threatintel2"))

		err := h.connect()
		if !errors.Is(err, ErrQuotaMisconfigured) {
			t.Fatalf("Connect = %v, want one wrapping ErrQuotaMisconfigured", err)
		}
		for _, want := range []string{"threatintel2", sharedKey} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error does not mention %q, so it does not say what to fix: %v", want, err)
			}
		}
	})

	t.Run("positive control: a twin with its own credential is fine", func(t *testing.T) {
		other := entry("threatintel2")
		other.EnvVarNames = []string{"THREATINTEL2_OWN_KEY"}
		h := newQuotaHarness(t, quotaSetup{
			providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
			freeTools: []string{"threatintel2.lookup_ip"},
		}, "threatintel.lookup_ip", "threatintel2.lookup_ip")
		h.reg.entries = append(h.reg.entries, entry("threatintel"), other)
		h.vault.values[sharedKey] = "value-for-threatintel"
		h.vault.values["THREATINTEL2_OWN_KEY"] = "value-for-threatintel2"
		h.serve("threatintel", def("lookup_ip", "look up an ip"))
		h.serve("threatintel2", def("lookup_ip", "look up an ip"))

		if err := h.connect(); err != nil {
			t.Fatalf("Connect = %v, want nil: the second entry holds a different credential", err)
		}
	})
}
