package gateway

// Tests of design/adr/0044: a running gateway takes a new role policy and
// quota plan, and re-dials one backend, without a restart.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasql "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func mustPolicy(t *testing.T, tools ...string) *access.Policy {
	t.Helper()
	p, err := access.NewPolicy([]access.Role{{Name: "n1-triage", Tools: tools}}, map[string]string{"soc-n1": "n1-triage"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustGate(t *testing.T, providers []quota.Provider, free []string) *quota.Gate {
	t.Helper()
	plan, err := quota.NewPlan(providers, free)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quotasql.Migrate(db); err != nil {
		t.Fatal(err)
	}
	g, err := quota.NewGate(plan, quotasql.New(db))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestApplyPolicy_ANewRoleTakesEffectOnTheNextCallWithoutARestart: the
// defect is that [[role]] changes needed a restart of every analyst's
// session.
func TestApplyPolicy_ANewRoleTakesEffectOnTheNextCallWithoutARestart(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"), def("close_case", "close"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "close_case")

	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.list_cases"}) {
		t.Fatalf("precondition: ListTools = %v", got)
	}
	if _, err := h.dispatch("casemgmt.close_case"); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("precondition: close_case = %v, want forbidden", err)
	}

	if err := h.gw.ApplyPolicy(context.Background(), mustPolicy(t, "casemgmt.close_case"), mustGate(t, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.close_case"}) {
		t.Fatalf("ListTools after the reload = %v, want only close_case", got)
	}
	if _, err := h.dispatch("casemgmt.close_case"); err != nil {
		t.Fatalf("close_case after the reload: %v", err)
	}
	if _, err := h.dispatch("casemgmt.list_cases"); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("list_cases after the reload = %v, want forbidden", err)
	}
	if h.gw.Policy() == nil || !slices.Equal(h.gw.RoutedTools(), []string{"casemgmt.close_case", "casemgmt.list_cases"}) {
		t.Fatalf("RoutedTools = %v", h.gw.RoutedTools())
	}
}

// TestApplyPolicy_RefusesAQuotaPlanTheRegistryDisagreesWith: a reload must
// not put the gateway where the same file would have been refused at boot.
func TestApplyPolicy_RefusesAQuotaPlanTheRegistryDisagreesWith(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	before := h.gw.Policy()

	bad := mustGate(t, []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)}, nil)
	err := h.gw.ApplyPolicy(context.Background(), mustPolicy(t), bad)
	if !errors.Is(err, ErrQuotaMisconfigured) {
		t.Fatalf("ApplyPolicy with an account on an unregistered upstream = %v, want ErrQuotaMisconfigured", err)
	}
	if h.gw.Policy() != before || len(h.gw.QuotaPlan().Providers()) != 0 {
		t.Fatal("a refused reload changed the policy or the plan in force")
	}
	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.list_cases"}) {
		t.Fatalf("ListTools after a refused reload = %v", got)
	}

	h.reg.fail(errors.New("disk gone"))
	if err := h.gw.ApplyPolicy(context.Background(), mustPolicy(t), mustGate(t, nil, nil)); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("ApplyPolicy with the registry unreadable = %v, want ErrRegistryUnavailable", err)
	}
	if h.gw.Policy() != before {
		t.Fatal("a reload refused for an unreadable registry changed the policy")
	}
}

// TestApplyPolicy_WithholdsANewlyBudgetedBackendsUndeclaredToolsAtOnce:
// between the reload and the next Refresh no tool of a backend that just
// became budgeted may be served uncounted.
func TestApplyPolicy_WithholdsANewlyBudgetedBackendsUndeclaredToolsAtOnce(t *testing.T) {
	h := newHarness(t, "threatintel.lookup_ip", "threatintel.decode")
	h.register("threatintel")
	h.serve("threatintel", def("lookup_ip", "ip"), def("decode", "decode"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")
	h.approve("threatintel", "decode")

	gate := mustGate(t, []quota.Provider{virustotalOn("threatintel", "threatintel.lookup_ip", 5)}, nil)
	if err := h.gw.ApplyPolicy(context.Background(), h.gw.Policy(), gate); err != nil {
		t.Fatal(err)
	}
	if got := h.listNames(analyst); !slices.Equal(got, []string{"threatintel.lookup_ip"}) {
		t.Fatalf("ListTools = %v, want decode withheld at once: no account charges it and it is not free", got)
	}
	if _, err := h.dispatch("threatintel.decode"); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("decode = %v, want unknown tool", err)
	}
}

// TestApplyPolicy_ListToolsReadsOnePolicy: ListTools reads the pointer
// once, so a listing is never half one policy.
func TestApplyPolicy_ListToolsReadsOnePolicy(t *testing.T) {
	h := newHarness(t, "casemgmt.a", "casemgmt.b")
	h.register("casemgmt")
	h.serve("casemgmt", def("a", "a"), def("b", "b"))
	h.mustConnect()
	h.approve("casemgmt", "a")
	h.approve("casemgmt", "b")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			p := mustPolicy(t, "casemgmt.a", "casemgmt.b")
			if i%2 == 1 {
				p = mustPolicy(t)
			}
			_ = h.gw.ApplyPolicy(context.Background(), p, mustGate(t, nil, nil))
		}
	}()
	for i := 0; i < 200; i++ {
		if got := h.listNames(analyst); len(got) == 1 {
			t.Fatalf("ListTools = %v: half of one policy", got)
		}
	}
	<-done
}

// TestRedial_DropsAndReDialsOneBackendWithTheCurrentCredential is the
// rotation case: a credential changed in the vault reaches the backend
// without a restart, and the other backends are not touched.
func TestRedial_DropsAndReDialsOneBackendWithTheCurrentCredential(t *testing.T) {
	h := newHarness(t, "threatintel.lookup_ip", "casemgmt.list_cases")
	h.vault.values["VT_API_KEY"] = "old-value"
	h.register("threatintel", "VT_API_KEY")
	h.register("casemgmt")
	h.serve("threatintel", def("lookup_ip", "ip"))
	h.serve("casemgmt", def("list_cases", "list"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")
	h.approve("casemgmt", "list_cases")

	h.vault.mu.Lock()
	h.vault.values["VT_API_KEY"] = "new-value"
	h.vault.mu.Unlock()
	if drift := h.gw.CredentialDrift(context.Background()); len(drift) != 1 {
		t.Fatalf("precondition: drift = %+v, want the rotated credential", drift)
	}

	connected, err := h.gw.Redial(context.Background(), "threatintel")
	if err != nil || !connected {
		t.Fatalf("Redial = %v, %v", connected, err)
	}
	if live, cause, _ := h.gw.BackendState("threatintel"); live || cause != health.CauseRedial {
		t.Fatalf("right after Redial: live %v cause %q, want not live, redial", live, cause)
	}
	var ue *UnavailableError
	if _, err := h.dispatch("threatintel.lookup_ip"); !errors.As(err, &ue) || ue.State != StateReconnecting {
		t.Fatalf("a call between the redial and the round = %v, want reconnecting", err)
	}

	casemgmtDials := h.dialCount("casemgmt")
	h.mustReconcile()
	if live, cause, _ := h.gw.BackendState("threatintel"); live || cause != health.CauseNotListed {
		t.Fatalf("after the re-dial and before a listing: live %v cause %q, want not_listed", live, cause)
	}
	if err := h.refresh(); err != nil {
		t.Fatal(err)
	}

	if got := h.dialer.envSeen["threatintel"]["VT_API_KEY"]; got != "new-value" {
		t.Fatalf("the re-dialled backend got %q, want the current vault value", got)
	}
	if n := h.dialCount("threatintel"); n != 2 {
		t.Fatalf("threatintel dialled %d times, want 2 (boot and the redial)", n)
	}
	if h.dialCount("casemgmt") != casemgmtDials {
		t.Fatal("a redial of threatintel re-dialled casemgmt too")
	}
	if drift := h.gw.CredentialDrift(context.Background()); len(drift) != 0 {
		t.Fatalf("drift after the redial = %+v", drift)
	}
	if live, _, _ := h.gw.BackendState("threatintel"); !live {
		t.Fatal("threatintel is not live after the round that followed the redial")
	}
	if _, err := h.dispatch("threatintel.lookup_ip"); err != nil {
		t.Fatalf("a call after the redial: %v", err)
	}
	var down, up bool
	for _, r := range h.healthRows() {
		if r.TargetUpstream != "threatintel" {
			continue
		}
		if r.Outcome == audit.OutcomeDenied && strings.HasSuffix(r.Reason, string(health.CauseRedial)) {
			down = true
		}
		if down && r.Outcome == audit.OutcomeAllowed {
			up = true
		}
	}
	if !down || !up {
		t.Fatalf("health rows = %+v, want a denied (redial) row and the allowed row after it", h.healthRows())
	}
}

// TestRedial_RefusesWhatItCannotBringBack: an unknown name, and a backend
// while dials are held back, which would be closed and never re-dialled.
func TestRedial_RefusesWhatItCannotBringBack(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"))
	h.mustConnect()
	h.mustReconcile()

	if _, err := h.gw.Redial(context.Background(), "nosuch"); !errors.Is(err, ErrNotServable) {
		t.Fatalf("Redial(nosuch) = %v, want ErrNotServable", err)
	}
	h.gw.mu.Lock()
	h.gw.heldBack = true
	h.gw.mu.Unlock()
	if _, err := h.gw.Redial(context.Background(), "casemgmt"); !errors.Is(err, ErrQuotaMisconfigured) {
		t.Fatalf("Redial while held back = %v, want ErrQuotaMisconfigured", err)
	}
	if live, _, _ := h.gw.BackendState("casemgmt"); !live {
		t.Fatal("a refused redial took the backend down")
	}
}

// TestRedial_OfAServableBackendThatIsDownMarksNothing: it is dialled by
// the next round anyway.
func TestRedial_OfAServableBackendThatIsDownMarksNothing(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.dialer.dialErr["casemgmt"] = errors.New("refused")
	_ = h.connect()
	_ = h.reconcile()
	connected, err := h.gw.Redial(context.Background(), "casemgmt")
	if err != nil || connected {
		t.Fatalf("Redial of a down backend = %v, %v; want false, nil", connected, err)
	}
	delete(h.dialer.dialErr, "casemgmt")
	h.serve("casemgmt", def("list_cases", "list"))
	h.tick()
	if live, _, _ := h.gw.BackendState("casemgmt"); !live {
		t.Fatal("not live after the next round")
	}
}
