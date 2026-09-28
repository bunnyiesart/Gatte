package gateway

// The per-analyst quota under ADR-0020's periodic reconciliation.
//
// The internal tree ran CheckQuotaCoverage and the undeclared-tool check at
// Connect and Refresh only, which was complete there because Connect was
// the only way a backend got dialled. Here Reconcile dials too -- an
// upstream registered with the gateway up is serving within one interval --
// so a registry that changes after boot would reach the routing table past
// the only check that looked at it. These tests pin the rule
// design/adr/0030-quota-por-analista.md adds for that path: while the plan
// and the registry disagree the fleet cannot grow, a live entry spending a
// budgeted credential uncounted is closed, and whatever Reconcile does
// bring up reaches the table through Refresh, which withholds a tool nobody
// costed exactly as Connect does.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// vtKey is the environment variable holding the budgeted account's key in
// these fixtures. A name, never a value: the registry stores names.
const vtKey = "THREATINTEL_VIRUSTOTAL_API_KEY"

// newThreatintelQuotaHarness is a gateway whose plan budgets one
// VirusTotal account on `threatintel`, charged by threatintel.lookup_ip,
// booted with `threatintel` (carrying vtKey) and `casemgmt` registered and
// approved -- the state a real boot has to be in, since Connect refuses to
// serve a plan naming an unregistered upstream.
func newThreatintelQuotaHarness(t *testing.T, allowed ...string) *harness {
	t.Helper()
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)},
	}, allowed...)
	h.vault.values[vtKey] = "vt-value-for-tests"
	h.register("threatintel", vtKey)
	h.register("casemgmt")
	h.serve("threatintel", def("lookup_ip", "look up an ip"))
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")
	h.approve("casemgmt", "list_cases")
	return h
}

// TestReconcile_ABudgetedUpstreamRegisteredAfterBootIsCheckedBeforeItIsServed
// is the path the internal tree did not have: the budgeted upstream goes
// away and comes back while the gateway runs, and comes back serving a tool
// nobody costed.
//
// While it is absent the plan names an unregistered upstream, which at boot
// would have stopped the process. Here it freezes the fleet: an upstream
// registered in that window is NOT brought up, because bringing it up would
// be serving it past the check Connect makes. Once the budgeted upstream is
// back the two agree, the held-back upstream is dialled, and the returning
// backend's new tool is withheld from the routing table by the same
// function that withholds it at boot -- while its declared tool is served
// and charged.
func TestReconcile_ABudgetedUpstreamRegisteredAfterBootIsCheckedBeforeItIsServed(t *testing.T) {
	h := newThreatintelQuotaHarness(t,
		"threatintel.lookup_ip", "threatintel.enrich", "casemgmt.list_cases", "logsearch.search")

	// The operator deregisters the budgeted backend, and registers an
	// unrelated one in the same minute.
	h.deregister("threatintel")
	h.register("logsearch")
	h.serve("logsearch", def("search", "search the logs"))

	err := h.reconcile()
	if !errors.Is(err, ErrQuotaMisconfigured) {
		t.Fatalf("Reconcile with the budgeted upstream gone = %v, want one wrapping ErrQuotaMisconfigured", err)
	}
	if !strings.Contains(err.Error(), "threatintel") {
		t.Errorf("the error does not name the upstream the account points at: %v", err)
	}
	if h.dialer.wasDialed("logsearch") {
		t.Error("an upstream registered while the quota plan and the registry disagree was brought up: " +
			"that is serving it past the check Connect makes at boot")
	}
	if n := h.dialer.upstream("threatintel").closeCount(); n != 1 {
		t.Errorf("the deregistered upstream was closed %d time(s), want 1: a freeze stops the fleet growing, not shrinking", n)
	}
	// Everything that was already serving keeps serving.
	if err := h.refresh(); err != nil {
		t.Fatalf("Refresh during the freeze = %v, want nil", err)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err != nil {
		t.Errorf("an upstream connected before the disagreement stopped serving: %v", err)
	}

	// The budgeted backend comes back, now also advertising `enrich`, which
	// spends the same account through its fan-out and which nobody added
	// to the plan.
	h.register("threatintel", vtKey)
	h.serve("threatintel", def("lookup_ip", "look up an ip"), def("enrich", "enrich an indicator"))
	h.mustReconcile()
	if !h.dialer.wasDialed("logsearch") {
		t.Error("the held-back upstream was not brought up once the plan and the registry agreed again")
	}
	if n := h.dialCount("threatintel"); n != 2 {
		t.Errorf("threatintel dialled %d time(s), want 2 (boot, then its return)", n)
	}

	// The Refresh on the same tick is the round that first sees `enrich`.
	// It is withheld already, while still pending: the operator hears about
	// the missing declaration before anybody approves the tool.
	for _, round := range []string{"while enrich is pending", "after enrich is approved"} {
		err = h.refresh()
		if !errors.Is(err, ErrQuotaUndeclaredTool) {
			t.Fatalf("Refresh %s = %v, want one wrapping ErrQuotaUndeclaredTool", round, err)
		}
		if !strings.Contains(err.Error(), "threatintel.enrich") {
			t.Errorf("Refresh %s: the error does not name the withheld tool: %v", round, err)
		}
		// Approving a tool of a budgeted upstream is a budget decision,
		// and approval alone must not route it.
		h.approve("threatintel", "enrich")
		h.approve("logsearch", "search")
	}

	got := h.listNames(analyst)
	want := []string{"casemgmt.list_cases", "logsearch.search", "threatintel.lookup_ip"}
	if !slices.Equal(got, want) {
		t.Fatalf("ListTools = %v, want %v -- the uncosted tool must not be routed and nothing else may be lost", got, want)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.enrich", json.RawMessage(`{}`)); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch of the withheld tool = %v, want ErrUnknownTool", err)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.lookup_ip", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Dispatch of the declared tool of the returned upstream = %v, want nil", err)
	}
	if used := h.used("virustotal"); used != 1 {
		t.Errorf("counter = %d after one call to the charged tool of an upstream Reconcile brought up, want 1", used)
	}
}

// TestReconcile_DoesNotBringUpAnUnbudgetedEntryCarryingABudgetedCredential
// is ADR-0030 decision 12 on the path that makes it urgent here. The
// internal tree met a `threatintel-canary` holding the budgeted key only at
// the next restart, where Connect refused to start. This gateway would
// dial it within one interval and serve every one of its calls uncounted,
// so the same function has to run on every round.
func TestReconcile_DoesNotBringUpAnUnbudgetedEntryCarryingABudgetedCredential(t *testing.T) {
	h := newThreatintelQuotaHarness(t,
		"threatintel.lookup_ip", "casemgmt.list_cases", "threatintel-canary.lookup_ip")

	h.register("threatintel-canary", vtKey)
	h.serve("threatintel-canary", def("lookup_ip", "look up an ip"))

	err := h.reconcile()
	if !errors.Is(err, ErrQuotaMisconfigured) {
		t.Fatalf("Reconcile with an unbudgeted twin of the budgeted credential = %v, want one wrapping ErrQuotaMisconfigured", err)
	}
	for _, want := range []string{"threatintel-canary", vtKey} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so it does not say what to fix: %v", want, err)
		}
	}
	if h.dialer.wasDialed("threatintel-canary") {
		t.Fatal("the twin was dialled: every call through it would spend the budgeted account uncounted")
	}
	if err := h.refresh(); err != nil {
		t.Fatalf("Refresh = %v", err)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel-canary.lookup_ip", json.RawMessage(`{}`)); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch through the twin = %v, want ErrUnknownTool", err)
	}
	// The budgeted upstream itself, and everything else, keeps serving.
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.lookup_ip", json.RawMessage(`{}`)); err != nil {
		t.Errorf("the budgeted upstream stopped serving because a twin appeared: %v", err)
	}

	// Positive control: the twin stops carrying that credential, and the
	// next round brings it up. Without this half, a Reconcile that never
	// dialled anything new would pass every assertion above.
	h.reregister("threatintel-canary", func(e *registry.UpstreamServer) {
		e.EnvVarNames = []string{"CANARY_OWN_KEY"}
	})
	h.vault.values["CANARY_OWN_KEY"] = "canary-value-for-tests"
	if err := h.reconcile(); err != nil {
		t.Fatalf("Reconcile once the twin holds its own credential = %v, want nil", err)
	}
	if !h.dialer.wasDialed("threatintel-canary") {
		t.Error("the twin was not brought up once it stopped sharing the budgeted credential")
	}
}

// TestReconcile_ClosesALiveEntryThatStartsSharingABudgetedCredential covers
// the one case where the freeze alone is not enough: an entry that was
// served legitimately and becomes an uncounted holder of a budgeted key
// because the BUDGETED entry was re-registered to declare it. Nothing new
// is dialled, and the live holder is closed -- it is the connection
// spending the account without a counter.
func TestReconcile_ClosesALiveEntryThatStartsSharingABudgetedCredential(t *testing.T) {
	h := newThreatintelQuotaHarness(t, "threatintel.lookup_ip", "casemgmt.list_cases", "enrichment.lookup")
	h.vault.values["SHARED_VT_KEY"] = "shared-value-for-tests"
	h.register("enrichment", "SHARED_VT_KEY")
	h.serve("enrichment", def("lookup", "look something up"))
	h.tick()
	h.approve("enrichment", "lookup")
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "enrichment.lookup", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("precondition: the unbudgeted entry serves while nothing budgeted shares its key: %v", err)
	}

	// The budgeted entry now declares enrichment's variable too.
	h.reregister("threatintel", func(e *registry.UpstreamServer) {
		e.EnvVarNames = []string{vtKey, "SHARED_VT_KEY"}
	})

	err := h.reconcile()
	if !errors.Is(err, ErrQuotaMisconfigured) {
		t.Fatalf("Reconcile = %v, want one wrapping ErrQuotaMisconfigured", err)
	}
	if n := h.dialer.upstream("enrichment").closeCount(); n != 1 {
		t.Errorf("the unbudgeted holder of the budgeted key was closed %d time(s), want 1", n)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "enrichment.lookup", json.RawMessage(`{}`)); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch through the uncounted holder = %v, want ErrUnknownTool", err)
	}
	// Frozen: the changed budgeted entry was closed like any changed entry
	// and is not re-dialled while the disagreement stands.
	if n := h.dialCount("threatintel"); n != 1 {
		t.Errorf("threatintel dialled %d time(s), want 1: nothing is brought up while the plan and the registry disagree", n)
	}
}

// TestDispatch_UnauditableCallStillSpentQuota pins the cost ADR-0030
// decision 6 (CORREÇÃO) accepts in writing: the reservation is taken
// before the audit record, and a record that then cannot be written
// refuses the call without giving the unit back. The call is refused and
// never reaches the backend -- "audit before dispatch" is unchanged -- and
// the over-count is the conservative direction.
func TestDispatch_UnauditableCallStillSpentQuota(t *testing.T) {
	unwritable := errors.New("audit store is read-only")
	h := newQuotaHarness(t, quotaSetup{providers: []quota.Provider{{
		Name:     "virustotal",
		Upstream: "casemgmt",
		Limit:    5,
		Window:   24 * time.Hour,
		Tools:    []string{"casemgmt.list_cases"},
	}}}, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.gw.audit = unwritableRecorder{err: unwritable}

	_, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`))
	if !errors.Is(err, unwritable) {
		t.Fatalf("Dispatch error = %v, want one wrapping the recorder's failure", err)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
		t.Fatalf("an unauditable call reached the upstream: %+v", calls)
	}
	if used := h.used("virustotal"); used != 1 {
		t.Errorf("counter for virustotal = %d, want 1: the reservation is taken before the record and is never reversed", used)
	}
}

// unwritableRecorder is an Audit Trail that refuses every write.
type unwritableRecorder struct{ err error }

func (r unwritableRecorder) Record(context.Context, audit.Record) error { return r.err }
func (r unwritableRecorder) List(context.Context) ([]audit.Record, error) {
	return nil, r.err
}
