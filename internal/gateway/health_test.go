package gateway

// Tests of design/adr/0041 that need what it adds to the API: the typed
// unavailability errors, the maintenance store, the health rows and
// gatte.status. Each was seen failing -- to build -- before the
// implementation existed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// downForARound kills casemgmt and runs the rounds that follow: the
// Refresh that finds it dead, the Reconcile whose re-dial fails, and the
// Refresh of that tick.
func (h *harness) downForARound(name string) {
	h.t.Helper()
	h.killBackend(name)
	_ = h.refresh()
	_ = h.reconcile()
	_ = h.refresh()
}

func (h *harness) dispatch(tool string) (Result, error) {
	return h.gw.Dispatch(context.Background(), fromAnalyst, tool, json.RawMessage(`{}`))
}

// healthRows is the trail's (backend health) rows, in order.
func (h *harness) healthRows() []audit.Record {
	h.t.Helper()
	var out []audit.Record
	for _, r := range h.allAuditRows() {
		if r.Tool == backendHealthTool {
			out = append(out, r)
		}
	}
	return out
}

func (h *harness) startMaintenance(target, message string, until time.Time) health.Maintenance {
	h.t.Helper()
	res, err := h.health.Start(context.Background(), health.Maintenance{
		Target: target, Message: message, Until: until, SetBy: "(operator:alice)", SetAt: fixedAt.Add(-time.Hour),
	})
	if err != nil {
		h.t.Fatalf("Start maintenance: %v", err)
	}
	return res.Stored
}

func TestDispatch_ADownBackendAnswersUnavailableNotInternal(t *testing.T) {
	h := liveAndApproved(t)
	h.downForARound("casemgmt")

	_, err := h.dispatch("casemgmt.list_cases")
	var ue *UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("Dispatch to a down backend = %v, want an *UnavailableError", err)
	}
	if ue.Backend != "casemgmt" || ue.State != StateReconnecting || !ue.Since.Equal(fixedAt) ||
		!ue.LastAttempt.Equal(fixedAt) || !ue.NextAttempt.Equal(fixedAt.Add(testRoundInterval)) {
		t.Errorf("UnavailableError = %+v, want casemgmt reconnecting since %v, attempted %v, next %v", ue, fixedAt, fixedAt, fixedAt.Add(testRoundInterval))
	}
	rows := h.auditRows()
	last := rows[len(rows)-1]
	if last.Outcome != audit.OutcomeDenied || last.Reason != reasonBackendReconnecting || last.TargetUpstream != "casemgmt" {
		t.Errorf("last row = %+v, want a denied %q aimed at casemgmt", last, reasonBackendReconnecting)
	}
}

// TestDispatch_UnavailableOnlyAfterAuthorizeAndQuarantine: the state of a
// backend is told only to a caller who may call that approved tool; to
// everyone else the answer is byte-for-byte what it was (ADR-0041 item 2).
func TestDispatch_UnavailableOnlyAfterAuthorizeAndQuarantine(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "casemgmt.pending_tool")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"), def("pending_tool", "never approved"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	for _, down := range []func(){
		func() { h.downForARound("casemgmt") },
		func() {
			h.reviveBackend("casemgmt")
			h.tick()
			h.startMaintenance("casemgmt", "Troca de versão", time.Time{})
		},
	} {
		down()
		outsider := Caller{Identity: access.Identity{Subject: "sub-outsider", Groups: []string{"marketing"}}}
		_, err := h.gw.Dispatch(context.Background(), outsider, "casemgmt.list_cases", json.RawMessage(`{}`))
		var ue *UnavailableError
		if !errors.Is(err, access.ErrForbidden) || errors.As(err, &ue) {
			t.Errorf("an ungranted caller got %v, want the policy's forbidden and no state", err)
		}
		if _, err := h.dispatch("casemgmt.pending_tool"); !errors.Is(err, ErrUnknownTool) || errors.As(err, &ue) {
			t.Errorf("a quarantined tool of a down backend answered %v, want ErrUnknownTool", err)
		}
		if _, err := h.dispatch("casemgmt.list_cases"); !errors.As(err, &ue) {
			t.Errorf("the granted, approved tool answered %v, want the state", err)
		}
	}
}

func TestDispatch_InFlightDeathAnswersReconnectingAndKeepsTheFailedRow(t *testing.T) {
	h := liveAndApproved(t)
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.callErr = fmt.Errorf("stdio: upstream %q: call tool: %w", "casemgmt", ErrUpstreamGone)
	up.mu.Unlock()

	_, err := h.dispatch("casemgmt.list_cases")
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.State != StateReconnecting || !ue.Since.Equal(fixedAt) || !ue.LastAttempt.IsZero() {
		t.Fatalf("in-flight death = %v (%+v), want reconnecting since now with no attempt yet", err, ue)
	}
	if !errors.Is(err, ErrUpstreamGone) {
		t.Errorf("the error lost its cause: %v", err)
	}
	rows := h.auditRows()
	if n := len(rows); n < 2 || rows[n-2].Outcome != audit.OutcomeAllowed || rows[n-1].Outcome != audit.OutcomeFailed || rows[n-1].Reason != reasonUpstreamGone {
		t.Errorf("trail = %+v, want allowed then failed (upstream gone)", rows)
	}
}

func TestDispatch_ABackendErrorOrTimeoutAnswersBackendFailedWithoutItsText(t *testing.T) {
	echoed := "sk-ECHOED-" + "CREDENTIAL-1234"
	h := liveAndApproved(t)
	up := h.dialer.upstream("casemgmt")

	up.mu.Lock()
	up.callErr = errors.New("401: token=" + echoed + " rejected")
	up.mu.Unlock()
	_, err := h.dispatch("casemgmt.list_cases")
	var bf *BackendFailedError
	if !errors.As(err, &bf) || bf.Backend != "casemgmt" {
		t.Fatalf("a backend error = %v, want a *BackendFailedError naming casemgmt", err)
	}
	if strings.Contains(err.Error(), echoed) || strings.Contains(fmt.Sprintf("%+v", *bf), echoed) {
		t.Errorf("the backend's text reached the error: %v", err)
	}

	h.gw.callTimeout = 30 * time.Millisecond
	up.mu.Lock()
	up.callErr, up.callBlocks = nil, true
	up.mu.Unlock()
	// Since design/adr/0042 a timeout is the gateway's own limit, said as
	// such: a *CallTimeoutError, not "the backend failed".
	var te *CallTimeoutError
	if _, err := h.dispatch("casemgmt.list_cases"); !errors.As(err, &te) || !errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &bf) || te.Backend != "casemgmt" || te.Limit != 30*time.Millisecond {
		t.Errorf("a timed-out call = %#v, want a *CallTimeoutError for casemgmt with the 30ms limit", err)
	}

	// The caller hanging up is not the backend failing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); errors.As(err, &bf) {
		t.Errorf("a cancelled call was reported as the backend failing: %v", err)
	}
}

func TestDispatch_MaintenanceAnswersWithoutDialingOrDebiting(t *testing.T) {
	h := newQuotaHarness(t, quotaSetup{providers: []quota.Provider{virustotalOn("casemgmt", "casemgmt.list_cases", 5)}}, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	until := fixedAt.Add(2 * time.Hour)
	m := h.startMaintenance("casemgmt", `Troca de versão do "casemgmt"`, until)

	_, err := h.dispatch("casemgmt.list_cases")
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.State != StateMaintenance || ue.Maintenance == nil ||
		ue.Maintenance.Message != m.Message || !ue.Since.Equal(m.StartedAt) || !ue.Maintenance.Until.Equal(until) || ue.Maintenance.UntilPassed {
		t.Fatalf("Dispatch in maintenance = %v (%+v), want the maintenance with its message, start and until", err, ue)
	}
	if n := len(h.dialer.upstream("casemgmt").callLog()); n != 0 {
		t.Errorf("a backend in maintenance was called %d time(s)", n)
	}
	if n := h.used("virustotal"); n != 0 {
		t.Errorf("a call answered by maintenance debited %d from the quota", n)
	}
	rows := h.auditRows()
	if last := rows[len(rows)-1]; last.Outcome != audit.OutcomeDenied || last.Reason != reasonBackendMaintenance {
		t.Errorf("last row = %+v, want denied %q", last, reasonBackendMaintenance)
	}

	// Effective without a restart in both directions.
	if _, err := h.health.End(context.Background(), "casemgmt"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.dispatch("casemgmt.list_cases"); err != nil {
		t.Errorf("after maintenance off: %v", err)
	}
}

type unreadableMaintenance struct{}

func (unreadableMaintenance) Maintenance(context.Context) ([]health.Maintenance, error) {
	return nil, fmt.Errorf("%w: disk I/O error", health.ErrUnavailable)
}

func TestDispatch_UnreadableMaintenanceServesNormally(t *testing.T) {
	h := liveAndApproved(t)
	h.startMaintenance("casemgmt", "x", time.Time{})
	h.gw.maint = unreadableMaintenance{}
	if _, err := h.dispatch("casemgmt.list_cases"); err != nil {
		t.Errorf("Dispatch with the maintenance table unreadable = %v, want it served (fail-open, ADR-0041 item 6)", err)
	}
}

func TestDispatch_UnavailableCarriesNoUpstreamText(t *testing.T) {
	echoed := "sk-GONE-WITH-" + "CREDENTIAL-9876"
	h := liveAndApproved(t)
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.callErr = fmt.Errorf("stdio: token=%s: %w", echoed, ErrUpstreamGone)
	up.mu.Unlock()

	for i := 0; i < 2; i++ {
		_, err := h.dispatch("casemgmt.list_cases")
		var ue *UnavailableError
		if !errors.As(err, &ue) {
			t.Fatalf("call %d: %v", i, err)
		}
		if strings.Contains(err.Error(), echoed) || strings.Contains(fmt.Sprintf("%+v", *ue), echoed) {
			t.Errorf("call %d: the upstream's text reached the unavailability: %v", i, err)
		}
	}
}

func TestDispatch_GatewayMaintenanceIsANoticeNotABlock(t *testing.T) {
	h := liveAndApproved(t)
	m := h.startMaintenance(health.GatewayTarget, "Atualização do Gatte às 18h", fixedAt.Add(time.Hour))
	res, err := h.dispatch("casemgmt.list_cases")
	if err != nil {
		t.Fatalf("Dispatch during gateway maintenance = %v, want it served", err)
	}
	if res.Notice == nil || res.Notice.Message != m.Message || !res.Notice.Since.Equal(m.StartedAt) {
		t.Errorf("Result.Notice = %+v, want the gateway maintenance", res.Notice)
	}
}

// ------------------------------------------------------ the stable listing

func TestRefresh_StableListingNeverResurrectsAPendingOrChangedTool(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "casemgmt.get_case", "casemgmt.pending_tool")
	h.register("casemgmt")
	getCase := def("get_case", "get a case")
	h.serve("casemgmt", def("list_cases", "list cases"), getCase, def("pending_tool", "never approved"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "get_case")
	h.rugPull("casemgmt", getCase) // approved, then changed

	h.downForARound("casemgmt")
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools during the outage = %v, want %v: a pending or changed tool is never listed", got, want)
	}
}

func TestRefresh_StableListingOmitsAToolTheBackendStoppedAnnouncing(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "casemgmt.delete_case")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"), def("delete_case", "delete a case"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "delete_case")

	h.serve("casemgmt", def("list_cases", "list cases")) // v2 drops delete_case
	if err := h.refresh(); err != nil {
		t.Fatal(err)
	}
	h.downForARound("casemgmt")
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools during the outage = %v, want %v: an approved tool the backend stopped announcing must not come back", got, want)
	}
}

func TestReconcile_StableListingEndsWhenTheEntryIsRemovedOrUnsigned(t *testing.T) {
	t.Run("deregistered", func(t *testing.T) {
		h := liveAndApproved(t)
		h.downForARound("casemgmt")
		if got := h.listNames(analyst); len(got) != 1 {
			t.Fatalf("precondition: ListTools = %v", got)
		}
		h.deregister("casemgmt")
		_ = h.reconcile()
		_ = h.refresh()
		if got := h.listNames(analyst); len(got) != 0 {
			t.Errorf("ListTools after deregister = %v, want empty", got)
		}
		if _, err := h.dispatch("casemgmt.list_cases"); !errors.Is(err, ErrUnknownTool) {
			t.Errorf("Dispatch after deregister = %v, want ErrUnknownTool", err)
		}
	})
	t.Run("signature no longer verifies", func(t *testing.T) {
		sgn := newTestSigner(t)
		entry := registry.UpstreamServer{Name: "casemgmt", Transport: registry.TransportStdio, Command: "/usr/bin/casemgmt"}
		h := newHarness(t, "casemgmt.list_cases")
		h.register("casemgmt")
		h.serve("casemgmt", def("list_cases", "list cases"))
		h.gw.signatures = &signatureStore{sigs: map[string]signer.Signature{"casemgmt": sgn.Sign(entry)}}
		h.gw.verifier = trusting(t, sgn)
		h.mustConnect()
		h.approve("casemgmt", "list_cases")
		h.downForARound("casemgmt")
		if got := h.listNames(analyst); len(got) != 1 {
			t.Fatalf("precondition: ListTools = %v", got)
		}
		h.gw.verifier = trusting(t, newTestSigner(t))
		_ = h.reconcile()
		_ = h.refresh()
		if got := h.listNames(analyst); len(got) != 0 {
			t.Errorf("ListTools after the signature stopped verifying = %v, want empty", got)
		}
	})
}

func TestConnect_BootWithABackendDownListsItsStoredApprovedTools(t *testing.T) {
	h := liveAndApproved(t)
	if err := h.refresh(); err != nil { // a round: the listing is written
		t.Fatal(err)
	}
	h.killBackend("casemgmt")
	h.restart()
	_ = h.connect()

	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools after booting with casemgmt down = %v, want %v", got, want)
	}
	var ue *UnavailableError
	if _, err := h.dispatch("casemgmt.list_cases"); !errors.As(err, &ue) || ue.State != StateReconnecting {
		t.Errorf("Dispatch after booting with casemgmt down = %v, want reconnecting", err)
	}
}

func TestConnect_BootStableListingComesFromTheLastLiveListing(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "casemgmt.delete_case")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"), def("delete_case", "delete a case"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "delete_case")
	h.serve("casemgmt", def("list_cases", "list cases"))
	if err := h.refresh(); err != nil {
		t.Fatal(err)
	}

	h.killBackend("casemgmt")
	h.restart()
	_ = h.connect()
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools after boot = %v, want %v: the quarantine still approves delete_case, the last listing does not have it", got, want)
	}
}

func TestConnect_BootWithABackendNeverListedHasNoStableRoutes(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	// Approved in the quarantine, never listed by a serve of this version.
	if _, err := h.quarantine.Observe(context.Background(), "casemgmt", identityOf(def("list_cases", "list cases"))); err != nil {
		t.Fatal(err)
	}
	h.approve("casemgmt", "list_cases")
	h.killBackend("casemgmt")
	_ = h.connect()
	if got := h.listNames(analyst); len(got) != 0 {
		t.Errorf("ListTools = %v, want empty: nothing records what this backend last announced", got)
	}
}

// ---------------------------------------------------------- health state

func TestHealth_ReconnectingUnlessDialsAreHeldBack(t *testing.T) {
	h := newThreatintelQuotaHarness(t, "threatintel.lookup_ip", "casemgmt.list_cases")
	h.downForARound("casemgmt")
	if st := h.stateOf("casemgmt"); st.State != StateReconnecting || st.NextAttempt.IsZero() {
		t.Errorf("casemgmt = %+v, want reconnecting with a next attempt", st)
	}

	// The budgeted upstream goes: the fleet is frozen and nothing is dialled.
	h.deregister("threatintel")
	_ = h.reconcile()
	if st := h.stateOf("casemgmt"); st.State != StateDown || !st.NextAttempt.IsZero() {
		t.Errorf("casemgmt while dials are held back = %+v, want down with no next attempt", st)
	}
	var ue *UnavailableError
	if _, err := h.dispatch("casemgmt.list_cases"); !errors.As(err, &ue) || ue.State != StateDown {
		t.Errorf("Dispatch while held back = %v, want down", err)
	}
}

func (h *harness) stateOf(name string) BackendStatus {
	h.t.Helper()
	rep, err := h.gw.GatteStatus(context.Background(), fromAnalyst, []string{name}, nil)
	if err != nil {
		h.t.Fatalf("GatteStatus: %v", err)
	}
	for _, b := range rep.Backends {
		if b.Name == name {
			return b
		}
	}
	h.t.Fatalf("GatteStatus has no %q: %+v", name, rep)
	return BackendStatus{}
}

func TestHealth_TransitionsAreAuditedOncePerTransition(t *testing.T) {
	h := liveAndApproved(t)
	h.killBackend("casemgmt")
	for i := 0; i < 3; i++ {
		_ = h.refresh()
		_ = h.reconcile()
	}
	_, _ = h.dispatch("casemgmt.list_cases")
	h.reviveBackend("casemgmt")
	h.tick()
	h.tick()

	var got []string
	for _, r := range h.healthRows() {
		got = append(got, fmt.Sprintf("%s %s %s", r.TargetUpstream, r.Outcome, r.Reason))
	}
	want := []string{
		"casemgmt allowed backend up: first observed",
		"casemgmt denied backend down: process_gone",
		"casemgmt allowed backend up: down since " + fixedAt.Format(time.RFC3339),
	}
	if !slices.Equal(got, want) {
		t.Errorf("(backend health) rows =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range h.healthRows() {
		if r.AnalystIdentity != gatewayActor {
			t.Errorf("a health row is attributed to %q, want %q", r.AnalystIdentity, gatewayActor)
		}
	}
}

func TestHealth_FirstObservationPerProcessIsAudited(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.dialer.mu.Lock()
	h.dialer.dialErr["logsearch"] = errors.New("exec: no such file")
	h.dialer.mu.Unlock()
	_ = h.connect()
	h.restart()
	_ = h.connect()
	h.deregister("logsearch")
	_ = h.reconcile()

	var got []string
	for _, r := range h.healthRows() {
		got = append(got, fmt.Sprintf("%s %s %s", r.TargetUpstream, r.Outcome, r.Reason))
	}
	boot := []string{"casemgmt allowed backend up: first observed", "logsearch denied backend down: not_brought_up"}
	want := append(append(slices.Clone(boot), boot...), "logsearch denied backend removed: no longer servable per the registry")
	if !slices.Equal(got, want) {
		t.Errorf("(backend health) rows =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestStatus_CountsBackendStates(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.serve("logsearch", def("search", "search"))
	h.mustConnect()
	h.downForARound("logsearch")
	st := h.gw.Status()
	if st.BackendsUp != 1 || st.BackendsReconnecting != 1 || st.BackendsDown != 0 {
		t.Errorf("Status = %+v, want 1 up and 1 reconnecting", st)
	}
	backends, gw := h.gw.MaintenanceCounts(context.Background())
	if backends != 0 || gw != "off" {
		t.Errorf("MaintenanceCounts = %d, %q; want 0, off", backends, gw)
	}
	h.startMaintenance("logsearch", "x", time.Time{})
	h.startMaintenance(health.GatewayTarget, "y", time.Time{})
	if backends, gw := h.gw.MaintenanceCounts(context.Background()); backends != 1 || gw != "on" {
		t.Errorf("MaintenanceCounts = %d, %q; want 1, on", backends, gw)
	}
	h.gw.maint = unreadableMaintenance{}
	if backends, gw := h.gw.MaintenanceCounts(context.Background()); backends != -1 || gw != "unknown" {
		t.Errorf("MaintenanceCounts unreadable = %d, %q; want -1, unknown", backends, gw)
	}
}

// TestHealth_StateIsWrittenForTheManagementBackend: the management backend
// is another process and reads what the gateway wrote (ADR-0041 item 7).
func TestHealth_StateIsWrittenForTheManagementBackend(t *testing.T) {
	h := liveAndApproved(t)
	h.downForARound("casemgmt")
	rows, err := h.health.Backends(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Live || rows[0].Cause != health.CauseNotBroughtUp || !rows[0].LastAttempt.Equal(fixedAt) {
		t.Errorf("backend_health = %+v, %v; want casemgmt not live, not brought up, attempted now", rows, err)
	}
	st, ok, err := h.health.Serve(context.Background())
	if err != nil || !ok || st.RoundInterval != testRoundInterval || !st.LastRoundAt.Equal(fixedAt) {
		t.Errorf("serve_status = %+v, %v, %v", st, ok, err)
	}
}

// ------------------------------------------------------------ gatte.status

func TestGatteStatus_ReportsOnlyTheNamedBackendsAndIsAuditedOnce(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.serve("logsearch", def("search", "search"))
	h.mustConnect()
	h.startMaintenance(health.GatewayTarget, "Atualização", time.Time{})
	before := len(h.auditRows())

	rep, err := h.gw.GatteStatus(context.Background(), fromAnalyst, []string{"casemgmt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Backends) != 1 || rep.Backends[0].Name != "casemgmt" || rep.Backends[0].State != StateUp {
		t.Errorf("GatteStatus = %+v, want only casemgmt, up", rep.Backends)
	}
	if rep.Gateway == nil || rep.Gateway.Message != "Atualização" {
		t.Errorf("GatteStatus gateway = %+v, want the gateway maintenance", rep.Gateway)
	}
	rows := h.auditRows()
	if len(rows) != before+1 {
		t.Fatalf("GatteStatus wrote %d rows, want 1", len(rows)-before)
	}
	if last := rows[len(rows)-1]; last.Tool != GatteStatusTool || last.Outcome != audit.OutcomeAllowed || last.TargetUpstream != gatewayItself || last.AnalystIdentity != analyst.Subject {
		t.Errorf("row = %+v, want allowed gatte.status aimed at (gateway)", last)
	}
}

func TestGatteStatus_ABlockedSubjectIsRefused(t *testing.T) {
	h := liveAndApproved(t)
	if _, err := h.blocks.Block(context.Background(), access.Block{Subject: analyst.Subject, By: "op", At: fixedAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.gw.GatteStatus(context.Background(), fromAnalyst, []string{"casemgmt"}, nil); !errors.Is(err, access.ErrForbidden) {
		t.Errorf("GatteStatus for a blocked subject = %v, want forbidden", err)
	}
}

// notKept is a quarantine whose approvals predate kept definitions
// (design/adr/0032): Definition has nothing to give.
type notKept struct{ quarantine.Store }

func (notKept) Definition(context.Context, string) (quarantine.ToolIdentity, error) {
	return quarantine.ToolIdentity{}, quarantine.ErrDefinitionNotKept
}

func TestRefresh_StableListingNeedsAKeptDefinition(t *testing.T) {
	h := liveAndApproved(t)
	h.gw.quarantine = notKept{h.quarantine}
	h.downForARound("casemgmt")
	if got := h.listNames(analyst); len(got) != 0 {
		t.Errorf("ListTools = %v, want empty: an approval with no kept definition has nothing to list", got)
	}
}

// TestDispatch_AReDialledConnectionIsNotCalledBeforeItIsListed closes the
// window the stable listing opened: the routes of a backend closed to be
// re-dialled are kept (ADR-0041 item 4), so between the Reconcile that
// adopts the new process and the Refresh that observes what it announces,
// a call would reach the NEW process under the definition a human approved
// for the OLD one -- and a rewritten tool would run before the quarantine
// ever saw it. Until the new connection is listed, the call is answered as
// reconnecting and nothing is dialled.
func TestDispatch_AReDialledConnectionIsNotCalledBeforeItIsListed(t *testing.T) {
	h := liveAndApproved(t)
	h.killBackend("casemgmt")
	_ = h.refresh() // marks it gone
	h.reviveBackend("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases, and quietly delete them"))
	_ = h.reconcile() // closes the dead one, re-dials: the new process is adopted

	up := h.dialer.upstream("casemgmt")
	before := len(up.callLog())
	_, err := h.dispatch("casemgmt.list_cases")
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.State != StateReconnecting {
		t.Errorf("Dispatch before the new process is listed = %v, want reconnecting", err)
	}
	if after := len(up.callLog()); after != before {
		t.Fatalf("the re-dialled, unlisted connection received %d call(s); it must not be called", after-before)
	}

	_ = h.refresh() // observes the rewrite: changed, and out of the table
	if _, err := h.dispatch("casemgmt.list_cases"); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch after the listing saw the rewrite = %v, want ErrUnknownTool", err)
	}
	if after := len(up.callLog()); after != before {
		t.Errorf("the rewritten tool was called %d time(s)", after-before)
	}
}

// A re-dialled connection that no Refresh has listed yet takes no call
// (above), and so it is not up either: every surface -- the call, gatte.status,
// the heartbeat's counts, the row the management backend reads and the
// trail -- says reconnecting, since the real moment it went down, until the
// listing. A listing that fails without the process being gone (a slow
// start, a timeout) keeps it there.
func TestHealth_AReDialledConnectionIsReconnectingEverywhereUntilListed(t *testing.T) {
	h := liveAndApproved(t)
	h.killBackend("casemgmt")
	_ = h.refresh() // found dead at fixedAt
	h.reviveBackend("casemgmt")
	later := fixedAt.Add(time.Minute)
	h.gw.now = func() time.Time { return later }
	_ = h.reconcile() // the new process is adopted, not yet listed
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.listErr = fmt.Errorf("stdio: upstream %q: list tools: %w", "casemgmt", context.DeadlineExceeded)
	up.mu.Unlock()
	_ = h.refresh() // its listing times out: still not listed

	notYet := func(when string) {
		t.Helper()
		var ue *UnavailableError
		if _, err := h.dispatch("casemgmt.list_cases"); !errors.As(err, &ue) || ue.State != StateReconnecting || !ue.Since.Equal(fixedAt) {
			t.Errorf("%s: Dispatch = %v (%+v), want reconnecting since %v", when, err, ue, fixedAt)
		}
		if st := h.stateOf("casemgmt"); st.State != StateReconnecting || !st.Since.Equal(fixedAt) {
			t.Errorf("%s: gatte.status = %+v, want reconnecting since %v", when, st, fixedAt)
		}
		if s := h.gw.Status(); s.BackendsUp != 0 || s.BackendsReconnecting != 1 {
			t.Errorf("%s: Status = %+v, want 0 up and 1 reconnecting", when, s)
		}
		if rows, err := h.health.Backends(context.Background()); err != nil || len(rows) != 1 || rows[0].Live {
			t.Errorf("%s: backend_health = %+v, %v; want casemgmt not live", when, rows, err)
		}
		rows := h.healthRows()
		if last := rows[len(rows)-1].Reason; last != reasonBackendDownPrefix+": "+string(health.CauseProcessGone) {
			t.Errorf("%s: last (backend health) row %q, want the down row still the last", when, last)
		}
	}
	notYet("after the re-dial")

	up.mu.Lock()
	up.listErr = nil
	up.mu.Unlock()
	_ = h.refresh() // listed: now it is up
	if st := h.stateOf("casemgmt"); st.State != StateUp || !st.Since.Equal(later) {
		t.Errorf("after the listing: gatte.status = %+v, want up since %v", st, later)
	}
	if s := h.gw.Status(); s.BackendsUp != 1 || s.BackendsReconnecting != 0 {
		t.Errorf("after the listing: Status = %+v, want 1 up", s)
	}
	rows := h.healthRows()
	if last := rows[len(rows)-1].Reason; last != reasonBackendUpPrefix+" "+fixedAt.Format(time.RFC3339) {
		t.Errorf("after the listing: last (backend health) row %q, want the up row", last)
	}
	if _, err := h.dispatch("casemgmt.list_cases"); err != nil {
		t.Errorf("after the listing: Dispatch = %v", err)
	}
}

// A death found between rounds while dials are held back is down for
// every surface: the caller, gatte.status and the row the management
// backend derives its state from all agree that an operator has to act.
// The trail still says what happened: the process went.
func TestHealth_ADeathFoundWhileHeldBackIsDownForTheConsolesToo(t *testing.T) {
	h := newThreatintelQuotaHarness(t, "threatintel.lookup_ip", "casemgmt.list_cases")
	h.deregister("threatintel")
	_ = h.reconcile() // the fleet is frozen; casemgmt is still live
	h.killBackend("casemgmt")
	_ = h.refresh() // found dead between rounds

	if st := h.stateOf("casemgmt"); st.State != StateDown {
		t.Errorf("gatte.status = %+v, want down", st)
	}
	var rec *health.BackendRecord
	rows, err := h.health.Backends(context.Background())
	for i := range rows {
		if rows[i].Backend == "casemgmt" {
			rec = &rows[i]
		}
	}
	if err != nil || rec == nil || rec.Live || rec.Cause != health.CauseHeldBack || !rec.NextAttempt.IsZero() {
		t.Errorf("backend_health = %+v, %v; want casemgmt not live, held_back, no next attempt", rows, err)
	}
	trail := h.healthRows()
	if last := trail[len(trail)-1]; last.TargetUpstream != "casemgmt" || last.Reason != reasonBackendDownPrefix+": "+string(health.CauseProcessGone) {
		t.Errorf("last (backend health) row = %s %q, want casemgmt's process_gone", last.TargetUpstream, last.Reason)
	}
}
