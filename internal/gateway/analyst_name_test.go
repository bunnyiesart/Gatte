package gateway

import (
	"errors"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
)

// Analyst name on the trail (design/adr/0037-nome-do-analista-na-trilha.md).

// TestDispatch_EveryRowOfAnAuthenticatedCallCarriesTheName: allowed,
// denied, failed and panic rows all pass through one builder, and each of
// them names the analyst next to the subject.
func TestDispatch_EveryRowOfAnAuthenticatedCallCarriesTheName(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.serve("logsearch", def("search", "search"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("logsearch", "search")

	ctx := t.Context()
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.list_cases", nil); err != nil {
		t.Fatalf("allowed call: %v", err)
	}
	// Denied: a tool the role does not grant.
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "docsearch.search", nil); err == nil {
		t.Fatal("a call to an unknown tool was not refused")
	}
	// Failed: the upstream errors.
	up := h.dialer.upstream("logsearch")
	up.mu.Lock()
	up.callErr = errors.New("backend down")
	up.mu.Unlock()
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "logsearch.search", nil); err == nil {
		t.Fatal("a failing upstream call succeeded")
	}
	// Panicked: recordPanic writes the row itself.
	cm := h.dialer.upstream("casemgmt")
	cm.mu.Lock()
	cm.panicWith = "adapter bug"
	cm.mu.Unlock()
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.list_cases", nil); !errors.Is(err, ErrInternal) {
		t.Fatalf("panicking call = %v, want ErrInternal", err)
	}

	rows := h.auditRows()
	seen := map[audit.Outcome]int{}
	for _, r := range rows {
		if r.AnalystIdentity != analyst.Subject {
			t.Errorf("row %+v is not attributed to the subject", r)
		}
		if r.AnalystName != analyst.Name {
			t.Errorf("row %s/%s has AnalystName %q, want %q", r.Tool, r.Outcome, r.AnalystName, analyst.Name)
		}
		seen[r.Outcome]++
	}
	if seen[audit.OutcomeAllowed] < 2 || seen[audit.OutcomeDenied] < 1 || seen[audit.OutcomeFailed] < 2 {
		t.Fatalf("the test did not reach every outcome: %v in %+v", seen, rows)
	}
}

// TestDispatch_ANameThatSaysNothingIsNotRecorded: a display name that is
// empty, or that is the subject itself (displayName's fallback), is left
// out rather than duplicated.
func TestDispatch_ANameThatSaysNothingIsNotRecorded(t *testing.T) {
	for _, name := range []string{"", analyst.Subject, "   "} {
		h := newHarness(t, "casemgmt.list_cases")
		h.register("casemgmt")
		h.serve("casemgmt", def("list_cases", "list cases"))
		h.mustConnect()
		h.approve("casemgmt", "list_cases")

		c := fromAnalyst
		c.Identity = access.Identity{Subject: analyst.Subject, Name: name, Groups: analyst.Groups}
		if _, err := h.gw.Dispatch(t.Context(), c, "casemgmt.list_cases", nil); err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		for _, r := range h.auditRows() {
			if r.AnalystName != "" {
				t.Errorf("Name %q produced AnalystName %q, want empty", name, r.AnalystName)
			}
		}
	}
}

// TestRowsNobodyAuthenticatedForCarryNoName: an unauthenticated request
// and the gateway's own events have no analyst to name.
func TestRowsNobodyAuthenticatedForCarryNoName(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect() // writes a first-seen (gateway) row per tool

	h.gw.RecordAuthFailure(t.Context(), "203.0.113.9")

	var events, unauth int
	for _, r := range h.allAuditRows() {
		switch r.AnalystIdentity {
		case gatewayActor:
			events++
		case unauthenticatedIdentity:
			unauth++
		}
		if r.AnalystName != "" {
			t.Errorf("row by %q carries AnalystName %q", r.AnalystIdentity, r.AnalystName)
		}
	}
	if events == 0 || unauth == 0 {
		t.Fatalf("the test did not produce both kinds of row: %d events, %d unauthenticated", events, unauth)
	}
}
