package gateway

// Behavioural tests of design/adr/0041 that need nothing the ADR adds to
// the API: they were written first and seen failing on the code before it,
// through Dispatch, ListTools, Refresh and Reconcile alone.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// killBackend makes the named upstream's process look gone to every call
// and listing, the way the stdio adapter reports a child that exited, and
// makes the next dial of it fail -- the backend stays down.
func (h *harness) killBackend(name string) {
	h.t.Helper()
	up := h.dialer.upstream(name)
	up.mu.Lock()
	up.listErr = fmt.Errorf("stdio: upstream %q: list tools: %w", name, ErrUpstreamGone)
	up.callErr = fmt.Errorf("stdio: upstream %q: call tool: %w", name, ErrUpstreamGone)
	up.mu.Unlock()
	h.dialer.mu.Lock()
	h.dialer.dialErr[name] = errors.New("exec: container exited")
	h.dialer.mu.Unlock()
}

// reviveBackend undoes killBackend.
func (h *harness) reviveBackend(name string) {
	h.t.Helper()
	up := h.dialer.upstream(name)
	up.mu.Lock()
	up.listErr, up.callErr = nil, nil
	up.mu.Unlock()
	h.dialer.mu.Lock()
	delete(h.dialer.dialErr, name)
	h.dialer.mu.Unlock()
}

// liveAndApproved is the fixture every test here starts from: casemgmt up,
// list_cases approved and listed for the analyst.
func liveAndApproved(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.list_cases"}) {
		t.Fatalf("precondition: ListTools = %v", got)
	}
	return h
}

// TestRefresh_ADeadBackendsApprovedToolsStayListed is ADR-0041 item 4: the
// model reads tools/list once per session, so pruning a dead backend's
// routes bought nothing but "unknown tool" for a tool it already had.
func TestRefresh_ADeadBackendsApprovedToolsStayListed(t *testing.T) {
	h := liveAndApproved(t)
	h.killBackend("casemgmt")

	_ = h.refresh()   // finds it dead
	_ = h.reconcile() // closes it; the re-dial fails
	_ = h.refresh()   // the round's listing, with the backend down

	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.list_cases"}) {
		t.Errorf("ListTools during the outage = %v, want the approved tool still listed", got)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch during the outage = %v: a tool the model already holds must not become unknown", err)
	}
}

// TestDispatch_AGoneMarkedConnectionIsNotCalled: once a connection is known
// dead, handing it another call only produces another failure.
func TestDispatch_AGoneMarkedConnectionIsNotCalled(t *testing.T) {
	h := liveAndApproved(t)
	h.killBackend("casemgmt")
	_ = h.refresh() // marks it gone; nothing is closed until Reconcile

	up := h.dialer.upstream("casemgmt")
	before := len(up.callLog())
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); err == nil {
		t.Fatal("Dispatch to a dead backend returned no error")
	}
	if after := len(up.callLog()); after != before {
		t.Errorf("the connection marked gone received %d call(s); it must not be called", after-before)
	}
}
