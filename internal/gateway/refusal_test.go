package gateway

// design/adr/0042 item 2 and 3, at the Dispatch and gatte.status seam:
// each refusal a caller can act on comes back typed, carrying only the
// gateway's state and the operator's declared policy, and gatte.status
// reports the caller's own standing and nobody else's.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/quota"
)

func TestDispatch_AnOversizedResultIsTypedWithTheCeilingOnly(t *testing.T) {
	const limit = 512
	h := newLimitedHarness(t, limit, "logsearch.search_keyword")
	h.register("logsearch")
	h.serve("logsearch", def("search_keyword", "keyword search"))
	h.mustConnect()
	h.approve("logsearch", "search_keyword")
	h.respond("logsearch", Result{Content: contentOfSize(t, limit+1)})

	_, err := h.gw.Dispatch(t.Context(), fromAnalyst, "logsearch.search_keyword", nil)
	var tl *ResultTooLargeError
	if !errors.As(err, &tl) || !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("Dispatch = %v, want a *ResultTooLargeError wrapping ErrResultTooLarge", err)
	}
	if tl.Tool != "logsearch.search_keyword" || tl.Limit != limit {
		t.Errorf("fields = %+v, want the tool called and the %d-byte ceiling", *tl, limit)
	}
	// The trail keeps its reason.
	rows := rowsFor(h.auditRows(), "logsearch.search_keyword")
	if last := rows[len(rows)-1]; last.Reason != reasonResultTooLarge {
		t.Errorf("trail reason = %q, want %q", last.Reason, reasonResultTooLarge)
	}
}

func TestDispatch_AnExhaustedQuotaIsTypedWithPolicyAndReset(t *testing.T) {
	const tool = "casemgmt.list_cases"
	h := newQuotaHarness(t, quotaSetup{providers: []quota.Provider{virustotalOn("casemgmt", tool, 1)}}, tool)
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if _, err := h.gw.Dispatch(t.Context(), fromAnalyst, tool, nil); err != nil {
		t.Fatal(err)
	}
	_, err := h.gw.Dispatch(t.Context(), fromAnalyst, tool, nil)
	var qe *QuotaExhaustedError
	if !errors.As(err, &qe) || !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("Dispatch = %v, want a *QuotaExhaustedError wrapping quota.ErrExhausted", err)
	}
	want := quota.ExhaustedError{Provider: "virustotal", Limit: 1, Window: 24 * time.Hour,
		ResetsAt: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
	if *qe.Budget != want {
		t.Errorf("budget = %+v, want %+v", *qe.Budget, want)
	}
}

func TestDispatch_AConcurrencyRefusalCarriesTheLimit(t *testing.T) {
	const tool = "casemgmt.list_cases"
	h := liveAndApproved(t)
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.waitForCtx = true
	up.mu.Unlock()

	n := DefaultMaxConcurrentCallsPerAnalyst
	hold, release := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { _, _ = h.gw.Dispatch(hold, fromAnalyst, tool, nil) })
	}
	t.Cleanup(func() { release(); wg.Wait() })
	waitUntil(t, func() bool { return len(up.callLog()) == n })

	_, err := h.gw.Dispatch(t.Context(), fromAnalyst, tool, nil)
	var cl *ConcurrencyLimitedError
	if !errors.As(err, &cl) || !errors.Is(err, ErrConcurrencyLimited) || cl.Limit != n {
		t.Fatalf("Dispatch = %v, want a *ConcurrencyLimitedError with limit %d", err, n)
	}
}

// TestGatteStatus_YouIsTheCallersOwnStandingOnly: the name and roles are
// the caller's own; the budgets are the ones their served tools spend,
// with their own use -- another analyst's spending never shows, and a
// budget none of their tools spends is not named.
func TestGatteStatus_YouIsTheCallersOwnStandingOnly(t *testing.T) {
	const tool = "casemgmt.list_cases"
	h := newQuotaHarness(t, quotaSetup{providers: []quota.Provider{
		virustotalOn("casemgmt", tool, 10),
		{Name: "hidden-budget", Upstream: "casemgmt", Limit: 3, Window: time.Hour, Tools: []string{"casemgmt.other"}},
	}, freeTools: []string{}}, tool, "casemgmt.other")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"), def("other", "other"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "other")

	other := Caller{Identity: access.Identity{Subject: "sub-analyst-2", Name: "Outra", Groups: []string{"soc-n1"}}, SourceAddress: analystSource}
	for range 2 {
		if _, err := h.gw.Dispatch(t.Context(), fromAnalyst, tool, nil); err != nil {
			t.Fatal(err)
		}
	}
	for range 5 {
		if _, err := h.gw.Dispatch(t.Context(), other, tool, nil); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := h.gw.GatteStatus(context.Background(), fromAnalyst, []string{"casemgmt"}, []string{tool})
	if err != nil {
		t.Fatal(err)
	}
	you := rep.You
	if you.Name != "Ana Lyst" || fmt.Sprint(you.Roles) != "[n1-triage]" {
		t.Errorf("you = %+v, want the caller's own name and role", you)
	}
	if len(you.Budgets) != 1 {
		t.Fatalf("budgets = %+v, want only virustotal: hidden-budget is spent by no tool the caller was served", you.Budgets)
	}
	b := you.Budgets[0]
	if b.Provider != "virustotal" || b.Used != 2 || b.Limit != 10 || !b.ResetsAt.Equal(time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("budget = %+v, want virustotal 2/10 resetting at midnight (the other analyst's 5 must not count)", b)
	}
	if strings.Contains(fmt.Sprintf("%+v", rep), "sub-analyst") {
		t.Errorf("a subject reached the report: %+v", rep)
	}
}
