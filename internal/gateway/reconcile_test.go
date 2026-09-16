package gateway

// Tests for Gateway.Reconcile -- the half of ADR-0004 that did not exist
// until ADR-0020.
//
// The property under test throughout is not "the registry is re-read". It
// is the pair of claims that made the incremental design worth its extra
// state: a change in the registry reaches the serving fleet within one
// round, AND a backend the registry still describes the same way is not
// touched. Either one alone is cheaper to build and worth less -- the
// first alone is `Connect` on a ticker, which respawns every subprocess
// every interval, and the second alone is what the gateway already did.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// ------------------------------------------------------------- helpers

func (h *harness) reconcile() error {
	return h.gw.Reconcile(context.Background())
}

func (h *harness) mustReconcile() {
	h.t.Helper()
	if err := h.reconcile(); err != nil {
		h.t.Fatalf("Reconcile: %v", err)
	}
}

// tick is what cmd/mcp-gateway's loop does on one interval, in the order
// it does it: settle which backends are connected, then ask the connected
// ones what they advertise. Tests use it wherever the assertion is about
// what an analyst can reach, because Reconcile alone deliberately leaves a
// newly connected upstream serving nothing (ADR-0020 item 2).
func (h *harness) tick() {
	h.t.Helper()
	h.mustReconcile()
	if err := h.refresh(); err != nil {
		h.t.Fatalf("Refresh: %v", err)
	}
}

// deregister removes an entry from the fake registry, the way
// `mcp-gateway upstream deregister` removes it from the real one.
func (h *harness) deregister(name string) {
	h.t.Helper()
	h.reg.mu.Lock()
	defer h.reg.mu.Unlock()
	h.reg.entries = slices.DeleteFunc(h.reg.entries, func(e registry.UpstreamServer) bool {
		return e.Name == name
	})
}

// reregister replaces a registered entry with a mutated copy of itself,
// which is what re-registering under the same name does.
func (h *harness) reregister(name string, mutate func(*registry.UpstreamServer)) {
	h.t.Helper()
	h.reg.mu.Lock()
	defer h.reg.mu.Unlock()
	for i := range h.reg.entries {
		if h.reg.entries[i].Name != name {
			continue
		}
		entry := h.reg.entries[i]
		mutate(&entry)
		if err := entry.Validate(); err != nil {
			h.t.Fatalf("mutated entry %q is not a valid registry entry: %v", name, err)
		}
		h.reg.entries[i] = entry
		return
	}
	h.t.Fatalf("reregister(%q): no such entry", name)
}

func (h *harness) dialCount(name string) int {
	h.t.Helper()
	h.dialer.mu.Lock()
	defer h.dialer.mu.Unlock()
	return h.dialer.dials[name]
}

// ------------------------------------------------------------- the fleet

// TestReconcile_PicksUpAnUpstreamRegisteredAfterBoot is the defect this
// whole ADR starts from: `upstream register` used to change nothing until
// somebody restarted the process.
func TestReconcile_PicksUpAnUpstreamRegisteredAfterBoot(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Fatalf("precondition: ListTools = %v, want %v", got, want)
	}

	// The operator registers a second backend with the gateway up.
	h.register("logsearch")
	h.serve("logsearch", def("search", "search the logs"))

	h.tick()
	h.approve("logsearch", "search")

	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases", "logsearch.search"}; !slices.Equal(got, want) {
		t.Fatalf("ListTools = %v, want %v -- a backend registered after boot must be reachable without a restart", got, want)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "logsearch.search", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Dispatch to the newly registered upstream: %v", err)
	}
}

// TestReconcile_DropsADeregisteredUpstreamAndItsRoutes asserts the routes
// go in the same round as the connection, not at the next Refresh:
// ListTools reads the table alone, so a route left behind advertises a
// backend that is already closed.
func TestReconcile_DropsADeregisteredUpstreamAndItsRoutes(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.serve("logsearch", def("search", "search the logs"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("logsearch", "search")

	if got := h.listNames(analyst); len(got) != 2 {
		t.Fatalf("precondition: ListTools = %v, want both tools", got)
	}

	h.deregister("logsearch")
	h.mustReconcile()

	if n := h.dialer.upstream("logsearch").closeCount(); n != 1 {
		t.Errorf("deregistered upstream closed %d times, want 1", n)
	}
	// Asserted before any Refresh runs.
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- a deregistered backend's routes must go with its connection", got, want)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "logsearch.search", nil); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch to the deregistered upstream = %v, want ErrUnknownTool", err)
	}
	// The one that was not touched is still the same connection.
	if n := h.dialCount("casemgmt"); n != 1 {
		t.Errorf("casemgmt dialed %d times, want 1: removing one upstream must not rebuild the others", n)
	}
}

// TestReconcile_LeavesAnUnchangedUpstreamConnected is the assertion that
// separates this from calling Connect on a ticker. Without it, every test
// above would still pass against an implementation that tears the fleet
// down and rebuilds it every round -- cutting in-flight analyst calls and
// respawning every subprocess, which is what ADR-0020 Option B was
// rejected for.
func TestReconcile_LeavesAnUnchangedUpstreamConnected(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	before := h.dialer.upstream("casemgmt")
	for range 3 {
		h.tick()
	}

	if n := h.dialCount("casemgmt"); n != 1 {
		t.Errorf("casemgmt dialed %d times over three rounds, want 1: an unchanged entry must not be re-dialed", n)
	}
	if n := before.closeCount(); n != 0 {
		t.Errorf("casemgmt closed %d times over three rounds, want 0: an unchanged entry must not be torn down", n)
	}
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- rounds that change nothing must not change what is served", got, want)
	}
}

// TestReconcile_RedialsWhenTheEntrySpecChanges: the live process is
// executing a command the operator has replaced, so it is closed -- before
// the new one is dialed, and whether or not the new one comes up.
func TestReconcile_RedialsWhenTheEntrySpecChanges(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()

	h.reregister("casemgmt", func(e *registry.UpstreamServer) {
		e.Command = "/usr/local/bin/casemgmt-v2"
		e.Args = []string{"-strict"}
	})
	h.mustReconcile()

	if n := h.dialCount("casemgmt"); n != 2 {
		t.Errorf("casemgmt dialed %d times, want 2: a changed entry must be re-dialed", n)
	}
	if n := h.dialer.upstream("casemgmt").closeCount(); n != 1 {
		t.Errorf("the superseded connection was closed %d times, want 1", n)
	}
	h.dialer.mu.Lock()
	spec := h.dialer.specs["casemgmt"]
	closedAtDial := slices.Clone(h.dialer.closedAtDial["casemgmt"])
	h.dialer.mu.Unlock()
	if spec.Command != "/usr/local/bin/casemgmt-v2" || !slices.Equal(spec.Args, []string{"-strict"}) {
		t.Errorf("spec = %+v, want the re-dial to use the NEW entry", spec)
	}
	// The ORDER, not just the counts. Asserting only "dialed twice, closed
	// once" passes just as well when Reconcile dials first and closes
	// after -- measured, by moving the retire call below the dial loop and
	// watching this test stay green. That ordering leaves the superseded
	// process serving for the length of a dial, which is the stale-decision
	// window ADR-0004 rejected.
	if len(closedAtDial) != 2 {
		t.Fatalf("closedAtDial = %v, want one entry per dial", closedAtDial)
	}
	if closedAtDial[0] != 0 || closedAtDial[1] != 1 {
		t.Errorf("closedAtDial = %v, want [0 1]: the superseded connection must be closed BEFORE the replacement is dialled", closedAtDial)
	}
}

// TestReconcile_ChangedEntryIsClosedEvenIfTheRedialFails is the other half
// of the sentence above -- "whether or not the new one comes up". A live
// process running a specification the operator has replaced is not a
// fallback to keep when the replacement will not start; it is the thing
// being replaced.
func TestReconcile_ChangedEntryIsClosedEvenIfTheRedialFails(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if got := h.listNames(analyst); len(got) != 1 {
		t.Fatalf("precondition: ListTools = %v, want the tool served", got)
	}

	h.reregister("casemgmt", func(e *registry.UpstreamServer) {
		e.Command = "/usr/local/bin/casemgmt-v2"
	})
	h.dialer.mu.Lock()
	h.dialer.dialErr["casemgmt"] = errors.New("exec: no such file")
	h.dialer.mu.Unlock()

	if err := h.reconcile(); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrUpstreamUnavailable", err)
	}
	if n := h.dialer.upstream("casemgmt").closeCount(); n != 1 {
		t.Errorf("the superseded connection was closed %d times, want 1 even though the replacement would not dial", n)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Errorf("ListTools = %v, want empty: the replaced process must not keep serving", got)
	}
}

// TestReconcile_ClosesAnUpstreamWhoseSignatureStopsVerifying is the
// security half of this ADR, and the one the original ADR-0004 never
// named: until now, verification ran once per process, so revoking a trust
// anchor or catching a tampered entry took a restart to act on.
func TestReconcile_ClosesAnUpstreamWhoseSignatureStopsVerifying(t *testing.T) {
	sgn := newTestSigner(t)
	entry := registry.UpstreamServer{
		Name:      "casemgmt",
		Transport: registry.TransportStdio,
		Command:   "/usr/bin/casemgmt",
	}

	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.gw.signatures = &signatureStore{sigs: map[string]signer.Signature{"casemgmt": sgn.Sign(entry)}}
	h.gw.verifier = trusting(t, sgn)
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if got := h.listNames(analyst); len(got) != 1 {
		t.Fatalf("precondition: ListTools = %v, want the signed entry served", got)
	}

	// The operator drops the signing key from signer.trusted_keys: the
	// stored signature is now vouched for by nothing.
	h.gw.verifier = trusting(t, newTestSigner(t))

	err := h.reconcile()
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrUpstreamUnavailable", err)
	}
	if n := h.dialer.upstream("casemgmt").closeCount(); n != 1 {
		t.Errorf("upstream closed %d times, want 1: an entry that stopped verifying must not stay connected", n)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Errorf("ListTools = %v, want empty once the signature no longer verifies", got)
	}
}

// TestReconcile_RetriesAnUpstreamThatFailedToDial: the same rule that
// picks up a new registration picks up a backend that was down at boot.
// One rule, three cases -- see ADR-0020 item 1.
func TestReconcile_RetriesAnUpstreamThatFailedToDial(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.dialer.mu.Lock()
	h.dialer.dialErr["casemgmt"] = errors.New("exec: no such file")
	h.dialer.mu.Unlock()

	if err := h.connect(); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Connect error = %v, want one wrapping ErrUpstreamUnavailable", err)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Fatalf("precondition: ListTools = %v, want empty while the backend will not dial", got)
	}

	// The backend comes back.
	h.dialer.mu.Lock()
	delete(h.dialer.dialErr, "casemgmt")
	h.dialer.mu.Unlock()

	h.tick()
	h.approve("casemgmt", "list_cases")

	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- a backend that failed at boot must come back without a restart", got, want)
	}
}

// TestReconcile_CredentialRotationAloneDoesNotRedial pins the boundary in
// ADR-0020 item 6. Reconnecting on a rotated credential is GAB-20's
// deliberately unbuilt half; if this test ever fails, that decision was
// reversed by accident rather than by an ADR.
func TestReconcile_CredentialRotationAloneDoesNotRedial(t *testing.T) {
	h := newHarness(t, "threatintel.lookup_ip")
	h.register("threatintel", "VT_API_KEY")
	h.serve("threatintel", def("lookup_ip", "look an address up"))
	h.vault.values["VT_API_KEY"] = "sk-old"
	h.mustConnect()

	h.vault.mu.Lock()
	h.vault.values["VT_API_KEY"] = "sk-rotated"
	h.vault.mu.Unlock()

	h.mustReconcile()

	if n := h.dialCount("threatintel"); n != 1 {
		t.Errorf("threatintel dialed %d times, want 1: a rotated credential must not silently re-dial a backend", n)
	}
	if n := h.dialer.upstream("threatintel").closeCount(); n != 0 {
		t.Errorf("threatintel closed %d times, want 0", n)
	}
	// And the divergence is still reported, which is the half that IS
	// built: reconciliation must not have quietly made drift undetectable
	// by overwriting the digests.
	drift := h.gw.CredentialDrift(context.Background())
	if len(drift) != 1 || drift[0].Upstream != "threatintel" || drift[0].VarName != "VT_API_KEY" {
		t.Errorf("CredentialDrift = %+v, want the rotation on threatintel/VT_API_KEY still reported", drift)
	}
}

// --------------------------------------------------------- suspension

// TestReconcile_RegistryFailureSuspendsWithoutClosingConnections is the
// difference between this and Connect's fail-closed path, and the reason
// a retry is cheaper than a restart: nothing is served, and no subprocess
// is killed over a disk hiccup (ADR-0020 item 3).
func TestReconcile_RegistryFailureSuspendsWithoutClosingConnections(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	h.reg.fail(errors.New("disk I/O error"))
	err := h.reconcile()
	if !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrRegistryUnavailable", err)
	}

	if n := h.dialer.upstream("casemgmt").closeCount(); n != 0 {
		t.Errorf("upstream closed %d times, want 0: suspension must not reap the fleet", n)
	}
	if defs, err := h.gw.ListTools(context.Background(), analyst); !errors.Is(err, ErrRegistryUnavailable) {
		t.Errorf("ListTools error = %v (%d tools), want ErrRegistryUnavailable: nothing may be served from a table nothing vouches for", err, len(defs))
	}

	// A Refresh landing during the suspension must not put the table back:
	// it builds from live connections, which are exactly what the registry
	// can no longer confirm.
	if err := h.refresh(); err != nil {
		t.Fatalf("Refresh during suspension: %v", err)
	}
	if _, err := h.gw.ListTools(context.Background(), analyst); !errors.Is(err, ErrRegistryUnavailable) {
		t.Errorf("ListTools after a Refresh during suspension = %v, want ErrRegistryUnavailable", err)
	}
	// Asserted on the TABLE and not only through ListTools, because the
	// suspension gate in ListTools answers ErrRegistryUnavailable whether
	// or not the table was repopulated -- so the assertion above passes
	// with swapRoutes's guard deleted, which is a test that defends
	// nothing. Measured by deleting that guard and watching it stay green.
	if n := len(h.gw.snapshot()); n != 0 {
		t.Errorf("the routing table holds %d routes after a Refresh during suspension, want 0: a table nothing vouches for must not be installed", n)
	}
}

// TestReconcile_SignatureStoreUnreadableKeepsTheFleet separates the two
// failures verifyEntry can report. A signature that does not verify is
// positive evidence that an entry was altered and takes the upstream out
// of service. A signature store that cannot be READ is the absence of a
// measurement -- and it is the same SQLite file the registry lives in, so
// treating the two alike means the disk hiccup ADR-0020 promises to
// survive would close every connection instead.
func TestReconcile_SignatureStoreUnreadableKeepsTheFleet(t *testing.T) {
	sgn := newTestSigner(t)
	entry := registry.UpstreamServer{
		Name:      "casemgmt",
		Transport: registry.TransportStdio,
		Command:   "/usr/bin/casemgmt",
	}

	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	store := &signatureStore{sigs: map[string]signer.Signature{"casemgmt": sgn.Sign(entry)}}
	h.gw.signatures = store
	h.gw.verifier = trusting(t, sgn)
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if got := h.listNames(analyst); len(got) != 1 {
		t.Fatalf("precondition: ListTools = %v, want the signed entry served", got)
	}

	// The database the signature store and the registry share goes
	// unreadable for a moment -- SQLITE_BUSY, a slow disk, a deadline.
	store.err = errors.New("database is locked")

	err := h.reconcile()
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrUpstreamUnavailable", err)
	}
	if n := h.dialer.upstream("casemgmt").closeCount(); n != 0 {
		t.Errorf("upstream closed %d times, want 0: an unreadable signature store is not evidence that anything changed", n)
	}
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- failing to measure must not unroute the fleet", got, want)
	}

	// And it recovers without a re-dial once the store answers again.
	store.err = nil
	h.tick()
	if n := h.dialCount("casemgmt"); n != 1 {
		t.Errorf("casemgmt dialed %d times, want 1: nothing was ever torn down", n)
	}
}

// TestReconcile_RecoveryDoesNotAnswerUnknownToolInTheGap: between the
// registry coming back and the table being rebuilt, the fleet is confirmed
// but routes nothing. Answering "unknown tool" there -- and auditing it as
// such -- is the confusion ADR-0020 item 4 exists to prevent, and it is
// what lifting the suspension on the successful READ produced.
func TestReconcile_RecoveryDoesNotAnswerUnknownToolInTheGap(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	h.reg.fail(errors.New("disk I/O error"))
	if err := h.reconcile(); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrRegistryUnavailable", err)
	}

	// The registry comes back. This is the state between Reconcile and the
	// Refresh that follows it on the same tick.
	h.reg.fail(nil)
	h.mustReconcile()

	if _, err := h.gw.ListTools(context.Background(), analyst); !errors.Is(err, ErrRegistryUnavailable) {
		t.Errorf("ListTools in the recovery gap = %v, want ErrRegistryUnavailable: the fleet is confirmed but not yet served", err)
	}
	_, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil)
	if errors.Is(err, ErrUnknownTool) {
		t.Error("a tool that exists was reported as unknown in the recovery gap")
	}
	if !errors.Is(err, ErrRegistryUnavailable) {
		t.Errorf("Dispatch in the recovery gap = %v, want ErrRegistryUnavailable", err)
	}
	if rows := h.auditRows(); rows[len(rows)-1].Reason != reasonRegistryUnavailable {
		t.Errorf("audit reason = %q, want %q -- the trail must not record a tool that exists as unknown",
			rows[len(rows)-1].Reason, reasonRegistryUnavailable)
	}

	// And the Refresh that follows ends the suspension by installing a
	// table, which is the only thing that should end it.
	if err := h.refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools after the refresh = %v, want %v", got, want)
	}
}

// TestReconcile_SuspendedGatewayServesNothingAndSaysWhy: the caller is
// told the fleet cannot be confirmed, and the trail records that reason
// rather than "unknown tool" -- the two send an operator down different
// paths during an incident (ADR-0020 item 4).
func TestReconcile_SuspendedGatewayServesNothingAndSaysWhy(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	h.reg.fail(errors.New("disk I/O error"))
	if err := h.reconcile(); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrRegistryUnavailable", err)
	}

	_, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", nil)
	if !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("Dispatch = %v, want ErrRegistryUnavailable", err)
	}
	if errors.Is(err, ErrUnknownTool) {
		t.Error("a suspended fleet must not be reported as a missing tool")
	}

	rows := h.auditRows()
	last := rows[len(rows)-1]
	if last.Outcome != audit.OutcomeDenied || last.Reason != reasonRegistryUnavailable {
		t.Errorf("audit row = {%s, %q}, want {%s, %q}", last.Outcome, last.Reason, audit.OutcomeDenied, reasonRegistryUnavailable)
	}
	if last.Tool != "casemgmt.list_cases" {
		t.Errorf("audit row tool = %q, want the tool that was refused", last.Tool)
	}
}

// TestReconcile_RecoversAfterTheRegistryComesBack is the retry actually
// retrying. Without this, suspension is just a slower outage.
func TestReconcile_RecoversAfterTheRegistryComesBack(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	h.reg.fail(errors.New("disk I/O error"))
	if err := h.reconcile(); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrRegistryUnavailable", err)
	}

	h.reg.fail(nil)
	h.tick()

	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Fatalf("ListTools = %v, want %v once the registry can be read again", got, want)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err != nil {
		t.Errorf("Dispatch after recovery: %v", err)
	}
	// Recovery reused the connection it kept.
	if n := h.dialCount("casemgmt"); n != 1 {
		t.Errorf("casemgmt dialed %d times, want 1: recovery must not respawn a backend that never went away", n)
	}
	// And the approval an operator gave before the outage still stands --
	// the quarantine was never re-observed as new.
	if n := h.dialer.upstream("casemgmt").closeCount(); n != 0 {
		t.Errorf("casemgmt closed %d times across the outage, want 0", n)
	}
}

// TestReconcile_ClosedGatewayIsNotRevived: a round racing shutdown must
// not dial anything back up, or Close's reaping silently leaks a
// subprocess per upstream.
func TestReconcile_ClosedGatewayIsNotRevived(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()

	if err := h.gw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.reconcile(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Reconcile after Close = %v, want ErrClosed", err)
	}
	if n := h.dialCount("casemgmt"); n != 1 {
		t.Errorf("casemgmt dialed %d times, want 1: a closed gateway must not re-dial", n)
	}
}

// ------------------------------------------------------------- status

// TestStatus_CountsWhatTheTrailRecords pins the claim ADR-0021 makes about
// these numbers: they are audit records written, by outcome, and not an
// approximation of "calls" kept in parallel with the thing it approximates.
//
// The trail itself is the check. A counter incremented somewhere other
// than the one place records are written would drift from it, and drifting
// is exactly what makes a gauge worse than no gauge -- an operator would
// read the heartbeat and believe it.
func TestStatus_CountsWhatTheTrailRecords(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"), def("delete_case", "delete a case"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	ctx := context.Background()
	// One allowed.
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	// Two denied: one outside the role, one that does not exist.
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.delete_case", nil); err == nil {
		t.Fatal("a tool outside the role was dispatched")
	}
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.nosuchtool", nil); err == nil {
		t.Fatal("an unknown tool was dispatched")
	}
	// One failure: the allowed tool, with the upstream refusing. That
	// writes an allowed record AND a failed one, which is the counting
	// subtlety worth pinning rather than explaining.
	h.dialer.upstream("casemgmt").mu.Lock()
	h.dialer.upstream("casemgmt").callErr = errors.New("backend exploded")
	h.dialer.upstream("casemgmt").mu.Unlock()
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err == nil {
		t.Fatal("the failing upstream returned no error")
	}

	got := h.gw.Status()

	// Counted against the rows themselves, not against hand-written
	// expectations: if the gateway ever writes a row without counting it,
	// or counts without writing, these disagree.
	var allowed, denied, failed uint64
	for _, row := range h.auditRows() {
		switch row.Outcome {
		case audit.OutcomeAllowed:
			allowed++
		case audit.OutcomeDenied:
			denied++
		case audit.OutcomeFailed:
			failed++
		}
	}
	if got.Allowed != allowed || got.Denied != denied || got.Failed != failed {
		t.Errorf("Status counters = {%d allowed, %d denied, %d failed}, trail holds {%d, %d, %d}",
			got.Allowed, got.Denied, got.Failed, allowed, denied, failed)
	}
	if got.Allowed != 2 || got.Failed != 1 {
		t.Errorf("Status = %+v; want 2 allowed and 1 failed -- a failed call writes BOTH, which is why allowed counts attempts", got)
	}
	if got.Upstreams != 1 || got.Tools != 2 {
		t.Errorf("Status = %+v, want 1 upstream and 2 routed tools", got)
	}
	if got.Suspended {
		t.Error("Status reports suspended on a gateway whose registry reads fine")
	}
}

// TestStatus_ReportsSuspension: the field exists so that "up and serving
// nobody" is visible in a heartbeat instead of only in the log of the
// minute it started.
func TestStatus_ReportsSuspension(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()

	h.reg.fail(errors.New("disk I/O error"))
	if err := h.reconcile(); !errors.Is(err, ErrRegistryUnavailable) {
		t.Fatalf("Reconcile error = %v, want one wrapping ErrRegistryUnavailable", err)
	}

	got := h.gw.Status()
	if !got.Suspended {
		t.Error("Status.Suspended is false while the fleet is suspended")
	}
	if got.Upstreams != 1 {
		t.Errorf("Status.Upstreams = %d, want 1: suspension keeps the connections", got.Upstreams)
	}
	if got.Tools != 0 {
		t.Errorf("Status.Tools = %d, want 0: a suspended fleet routes nothing", got.Tools)
	}
}

// -------------------------------------------------------- liveness

// TestReconcile_DeadUpstreamIsClosedAndRedialled is ADR-0024's central
// claim. Until it, "connected" meant "this Gateway holds an Upstream", and
// a backend whose process had exited stayed in the live set forever: the
// registry entry had not changed, so Reconcile left it alone, and every
// analyst call to it failed until somebody restarted the whole gateway --
// taking the other three backends down with it.
func TestReconcile_DeadUpstreamIsClosedAndRedialled(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if got := h.listNames(analyst); len(got) != 1 {
		t.Fatalf("precondition: ListTools = %v, want the tool served", got)
	}

	// The subprocess exits. What the adapter reports from then on is
	// ErrUpstreamGone, and the next Refresh is where the gateway meets it.
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.listErr = fmt.Errorf("stdio: upstream %q: list tools: %w", "casemgmt", ErrUpstreamGone)
	up.mu.Unlock()

	if err := h.refresh(); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Refresh error = %v, want one wrapping ErrUpstreamUnavailable", err)
	}
	if n := up.closeCount(); n != 0 {
		t.Errorf("Refresh closed the connection %d times; closing is Reconcile's job (ADR-0020 item 2)", n)
	}

	// The backend comes back healthy on the next dial.
	up.mu.Lock()
	up.listErr = nil
	up.mu.Unlock()

	h.mustReconcile()

	if n := up.closeCount(); n != 1 {
		t.Errorf("the dead connection was closed %d times, want 1", n)
	}
	if n := h.dialCount("casemgmt"); n != 2 {
		t.Errorf("casemgmt dialed %d times, want 2: a dead backend the registry still names must be re-dialled", n)
	}

	if err := h.refresh(); err != nil {
		t.Fatalf("Refresh after the re-dial: %v", err)
	}
	if got, want := h.listNames(analyst), []string{"casemgmt.list_cases"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- the replacement must serve without an operator restarting anything", got, want)
	}
}

// TestReconcile_AnUpstreamThatMerelyFailedToListIsNotRespawned is the other
// half, and the one that keeps this from being a respawn machine. ADR-0013
// says it in one line: failing to measure is not evidence that something
// changed. A backend under load that misses a tools/list is not a dead one,
// and treating it as dead would turn a busy afternoon into a fleet-wide
// respawn.
func TestReconcile_AnUpstreamThatMerelyFailedToListIsNotRespawned(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	up := h.dialer.upstream("casemgmt")
	for _, err := range []error{
		context.DeadlineExceeded,
		errors.New("connection reset by peer"),
		fmt.Errorf("stdio: upstream %q: list tools: %w", "casemgmt", context.Canceled),
	} {
		up.mu.Lock()
		up.listErr = err
		up.mu.Unlock()

		if refreshErr := h.refresh(); refreshErr == nil {
			t.Fatalf("Refresh with listErr=%v returned no error", err)
		}
		h.mustReconcile()

		if n := up.closeCount(); n != 0 {
			t.Fatalf("a listing failure of %v closed the connection; only ErrUpstreamGone may", err)
		}
		if n := h.dialCount("casemgmt"); n != 1 {
			t.Fatalf("a listing failure of %v caused a re-dial; only ErrUpstreamGone may", err)
		}
	}
}

// TestReconcile_DeathIsAnchoredToTheConnectionNotTheName: a marker written
// about one connection must never close its replacement.
//
// # What this test actually proves, which is not what it first claimed
//
// Two mechanisms protect this property, and only the first fires here:
// retire deletes the marker when it closes the connection, so by the time
// a replacement exists there is nothing left to consume. The identity
// comparison inside takeGone is the SECOND, and it is unreachable through
// the public API for exactly that reason -- measured, by keying the marker
// by name alone and watching this test stay green.
//
// So this is the end-to-end assertion (the replacement survives), and
// TestTakeGone_IgnoresAMarkerForAReplacedConnection below is the unit-level
// one that holds the backstop up. Keeping both is deliberate: the day
// somebody drops the delete from retire -- a one-line edit, in a function
// whose job is cleanup -- the backstop is what stops a healthy process
// being killed, and nothing else would catch it.
func TestReconcile_DeathIsAnchoredToTheConnectionNotTheName(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.dialer.mu.Lock()
	h.dialer.freshPerDial = true
	h.dialer.mu.Unlock()

	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()

	first := h.dialer.generation("casemgmt", 0)
	if first == nil {
		t.Fatal("no first generation was dialled")
	}

	// Generation 0 dies.
	first.mu.Lock()
	first.listErr = fmt.Errorf("list tools: %w", ErrUpstreamGone)
	first.mu.Unlock()
	if err := h.refresh(); err == nil {
		t.Fatal("Refresh returned no error for a dead upstream")
	}

	// Before the next round, the operator also changes the entry -- so this
	// round closes and re-dials for the SPEC change, and generation 1 is a
	// different object that nobody has said anything about.
	h.reregister("casemgmt", func(e *registry.UpstreamServer) { e.Command = "/usr/local/bin/casemgmt-v2" })
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustReconcile()

	second := h.dialer.generation("casemgmt", 1)
	if second == nil {
		t.Fatal("the replacement was never dialled")
	}
	if second == first {
		t.Fatal("the fake handed back the same object; freshPerDial is not in effect and this test proves nothing")
	}
	if n := h.dialCount("casemgmt"); n != 2 {
		t.Fatalf("casemgmt dialed %d times, want 2", n)
	}

	// The round that must do nothing at all. A marker keyed by name alone
	// would close `second` here -- a healthy process, on the strength of an
	// observation about its predecessor.
	h.mustReconcile()

	if n := second.closeCount(); n != 0 {
		t.Errorf("the replacement was closed %d times: a death marker about the PREVIOUS connection killed it", n)
	}
	if n := h.dialCount("casemgmt"); n != 2 {
		t.Errorf("casemgmt dialed %d times, want 2: nothing should have been re-dialled", n)
	}
	if n := first.closeCount(); n != 1 {
		t.Errorf("the dead generation was closed %d times, want 1", n)
	}
}

// TestDispatch_ADeadUpstreamIsAuditedAsGone: the trail has to separate "the
// backend answered badly" from "the backend is not running", because they
// send an operator to different places.
func TestDispatch_ADeadUpstreamIsAuditedAsGone(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.callErr = fmt.Errorf("stdio: upstream %q: call tool: %w", "casemgmt", ErrUpstreamGone)
	up.mu.Unlock()

	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err == nil {
		t.Fatal("Dispatch to a dead upstream returned no error")
	}

	rows := h.auditRows()
	last := rows[len(rows)-1]
	if last.Outcome != audit.OutcomeFailed || last.Reason != reasonUpstreamGone {
		t.Errorf("audit row = {%s, %q}, want {%s, %q}", last.Outcome, last.Reason, audit.OutcomeFailed, reasonUpstreamGone)
	}

	// And the call taught the gateway something the tick had not seen yet.
	up.mu.Lock()
	up.callErr = nil
	up.mu.Unlock()
	h.mustReconcile()
	if n := h.dialCount("casemgmt"); n != 2 {
		t.Errorf("casemgmt dialed %d times, want 2: a death noticed by a CALL must be repaired too", n)
	}
}

// TestDispatch_AFailedCallThatIsNotDeathRepairsNothing is the negative of
// the test above, and it is the one that keeps the repair path from
// becoming a respawn path. Dispatch marks an upstream dead only for
// ErrUpstreamGone; every other call failure -- a timeout, a cancellation,
// a backend that simply errored -- must leave the connection alone.
func TestDispatch_AFailedCallThatIsNotDeathRepairsNothing(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	up := h.dialer.upstream("casemgmt")
	for _, callErr := range []error{
		context.DeadlineExceeded,
		context.Canceled,
		errors.New("backend refused the call"),
		fmt.Errorf("stdio: upstream %q: call tool: %w", "casemgmt", errors.New("broken pipe")),
	} {
		up.mu.Lock()
		up.callErr = callErr
		up.mu.Unlock()

		if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err == nil {
			t.Fatalf("Dispatch with callErr=%v returned no error", callErr)
		}
		h.mustReconcile()

		if n := up.closeCount(); n != 0 {
			t.Fatalf("a call failing with %v closed the connection; only ErrUpstreamGone may", callErr)
		}
		if n := h.dialCount("casemgmt"); n != 1 {
			t.Fatalf("a call failing with %v caused a re-dial; only ErrUpstreamGone may", callErr)
		}
	}
}

// TestTakeGone_IgnoresAMarkerForAReplacedConnection holds up the backstop
// the test above cannot reach.
//
// It builds the situation by hand because no sequence of Reconcile calls
// produces it today: retire clears the marker whenever it closes something,
// so a marker never meets a different live connection. That is an
// invariant of one line inside retire, not of the design -- this asserts
// what happens when that line is gone.
func TestTakeGone_IgnoresAMarkerForAReplacedConnection(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.dialer.mu.Lock()
	h.dialer.freshPerDial = true
	h.dialer.mu.Unlock()
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()

	first := h.dialer.generation("casemgmt", 0)
	h.gw.markGone("casemgmt", first)

	// The connection is replaced WITHOUT going through retire, which is the
	// only way to reach this state.
	second := &fakeUpstream{}
	h.gw.mu.Lock()
	h.gw.conns["casemgmt"] = second
	h.gw.mu.Unlock()

	if h.gw.takeGone("casemgmt", second) {
		t.Error("a marker written about the previous connection was accepted for its replacement; a healthy process would be closed on the strength of an observation about a different one")
	}

	// And the marker is consumed either way, so it cannot resurface later.
	h.gw.mu.RLock()
	_, still := h.gw.gone["casemgmt"]
	h.gw.mu.RUnlock()
	if still {
		t.Error("the marker survived the read; a stale marker is the thing this design must not keep")
	}
}
