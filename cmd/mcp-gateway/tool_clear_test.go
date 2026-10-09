package main

import (
	"context"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// `tool clear` and the approval of a sensitive tool (design/adr/0048
// Decisão 5), against the real store, like every console test.

var submitReport = quarantine.ToolIdentity{
	Name:        "submit_report",
	Description: "Submit a report to the vendor.",
	InputSchema: []byte(`{"type":"object","properties":{}}`),
}

// mustObserveSensitive is mustObserve for an operation that can act.
func mustObserveSensitive(t *testing.T, e opTestEnv, server string, id quarantine.ToolIdentity) quarantine.Tool {
	t.Helper()
	tool, err := e.tools().Observe(context.Background(), server, id, quarantine.ClassSensitive)
	if err != nil {
		t.Fatalf("observing %s.%s: %v", server, id.Name, err)
	}
	return tool.Tool
}

// TestRunToolApprove_ASensitiveToolIsApprovedNotServedAndNotABug: the
// post-approval guard used to call this state a bug and exit 1.
func TestRunToolApprove_ASensitiveToolIsApprovedNotServedAndNotABug(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserveSensitive(t, e, "reporting", submitReport)

	requireExit(t, runToolApproveReviewed(e.opEnv, "reporting", "submit_report"), exitOK, "approve sensitive")
	got := e.stdoutText()
	for _, want := range []string{
		"Approved reporting.submit_report",
		"SENSITIVE",
		"NOT served",
		"non_read = true",
		"mcp-gateway tool clear reporting submit_report",
	} {
		requireContains(t, got, want, "approve sensitive")
	}
	if e.err.Len() != 0 {
		t.Errorf("stderr is not empty:\n%s", e.stderrText())
	}
	after, err := e.tools().Get(context.Background(), "reporting", "submit_report")
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != quarantine.StatusApproved || after.Usable() {
		t.Errorf("after approval: %+v, want approved and held", after)
	}

	// `tool list` names it, with the command to run.
	e.out.Reset()
	requireExit(t, runToolList(e.opEnv, "", false), exitOK, "tool list")
	requireContains(t, e.stdoutText(), "1 SENSITIVE tool is approved and not yet cleared", "tool list")
	requireContains(t, e.stdoutText(), "mcp-gateway tool clear reporting submit_report", "tool list")
}

func TestRunToolClear_RefusesWithOnlyAWildcardGrant(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Roles = []config.Role{{Name: "ir-act", Grants: map[string][]string{"reporting": {"*"}}, NonRead: true}}
	mustObserveSensitive(t, e, "reporting", submitReport)
	mustApprove(t, e, "reporting", "submit_report")

	requireExit(t, runToolClear(e.opEnv, "reporting", "submit_report"), exitProblem, "clear wildcard")
	got := e.stderrText()
	for _, want := range []string{"NOT cleared", `role "ir-act"`, "wildcard", `"reporting.submit_report"`, "non_read = true"} {
		requireContains(t, got, want, "clear wildcard")
	}
	after, _ := e.tools().Get(context.Background(), "reporting", "submit_report")
	if after.Usable() {
		t.Errorf("a refused clearance made the tool usable: %+v", after)
	}
}

func TestRunToolClear_RefusesAnExplicitNameOnAReadRole(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Roles = []config.Role{{Name: "tier1", Tools: []string{"reporting.submit_report"}}}
	mustObserveSensitive(t, e, "reporting", submitReport)
	mustApprove(t, e, "reporting", "submit_report")

	requireExit(t, runToolClear(e.opEnv, "reporting", "submit_report"), exitProblem, "clear read role")
	requireContains(t, e.stderrText(), `role "tier1"`, "clear read role")
	requireContains(t, e.stderrText(), "not marked non_read", "clear read role")
}

func TestRunToolClear_AcceptsAnExplicitNameOnANonReadRole(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}},
		{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true},
	}
	mustObserveSensitive(t, e, "reporting", submitReport)
	mustApprove(t, e, "reporting", "submit_report")

	requireExit(t, runToolClear(e.opEnv, "reporting", "submit_report"), exitOK, "tool clear")
	got := e.stdoutText()
	for _, want := range []string{
		"Clearing reporting.submit_report makes it callable by every analyst in this role",
		"ir-act",
		"Cleared reporting.submit_report",
		"served from the next call on",
	} {
		requireContains(t, got, want, "tool clear")
	}
	after, err := e.tools().Get(context.Background(), "reporting", "submit_report")
	if err != nil {
		t.Fatal(err)
	}
	if !after.Usable() || after.SensitiveClearedHash != after.ApprovedHash {
		t.Errorf("after clearing: %+v, want usable at the approved fingerprint", after)
	}

	// Idempotent, like revoke on a pending tool.
	e.out.Reset()
	requireExit(t, runToolClear(e.opEnv, "reporting", "submit_report"), exitOK, "tool clear again")
	requireContains(t, e.stdoutText(), "was already cleared", "tool clear again")
}

func TestRunToolClear_SafeAndUnapprovedAndUnobservedAreProblems(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Roles = []config.Role{{Name: "ir-act", Tools: []string{"casemgmt.list_cases", "reporting.submit_report"}, NonRead: true}}

	mustObserve(t, e, "casemgmt", irisListCases)
	mustApprove(t, e, "casemgmt", "list_cases")
	requireExit(t, runToolClear(e.opEnv, "casemgmt", "list_cases"), exitProblem, "clear safe")
	requireContains(t, e.stderrText(), "not a sensitive tool", "clear safe")

	e.err.Reset()
	mustObserveSensitive(t, e, "reporting", submitReport)
	requireExit(t, runToolClear(e.opEnv, "reporting", "submit_report"), exitProblem, "clear pending")
	requireContains(t, e.stderrText(), "not approved", "clear pending")
	requireContains(t, e.stderrText(), "mcp-gateway tool approve -fingerprint SHA256 reporting submit_report", "clear pending")

	e.err.Reset()
	requireExit(t, runToolClear(e.opEnv, "reporting", "ghost"), exitProblem, "clear unobserved")
	requireContains(t, e.stderrText(), "no quarantine entry", "clear unobserved")
}

// TestRunToolApproveSet_ASensitiveToolIsHeldAndNotABug is the batch path
// at the console (design/adr/0048 Decisão 5, "o caminho de LOTE"): the
// table marks the sensitive tool as held, the safe one is served, the
// held one does not trip the "still NOT usable -- this is a bug" guard, the
// service's sensitive_uncleared warning names the command, and the store
// agrees that approving a set cleared nothing.
func TestRunToolApproveSet_ASensitiveToolIsHeldAndNotABug(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}},
		{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true},
	}
	mustObserveSensitive(t, e, "reporting", submitReport)
	mustObserve(t, e, "reporting", quarantine.ToolIdentity{Name: "list_reports", Description: "List reports."})

	requireExit(t, runToolReview(e.opEnv, "reporting"), exitOK, "tool review")
	review := e.stdoutText()
	manifest := printedManifest(t, review)
	// The review already says which tool the approval will not serve, and
	// for a sensitive tool names only the non_read role, not the wildcard.
	requireContains(t, review, "submit_report", "review")
	requireContains(t, review, "SENSITIVE", "review")
	requireContains(t, review, "ir-act", "review")
	if strings.Contains(review, `A "*" grant is why this matters`) {
		// list_reports IS under the wildcard, so the notice is right to
		// appear for it; what must not happen is the notice being the only
		// thing said about submit_report. Checked by the line itself:
		for _, line := range strings.Split(review, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "submit_report") && strings.Contains(line, "ir,") {
				t.Errorf("the review lists the wildcard role as reaching the sensitive tool: %q", line)
			}
		}
	}

	e.out.Reset()
	requireExit(t, runToolApproveSet(e.opEnv, "reporting", manifest), exitOK, "approve set with a sensitive tool")
	got := e.stdoutText()
	for _, want := range []string{
		"Approved 2 tools of reporting",
		"(sensitive: NOT served until cleared)",
		"approving a set never clears",
		"tool clear reporting TOOL",
		"submit_report",
	} {
		requireContains(t, got, want, "approve set")
	}
	if strings.Contains(got, "This is a bug") {
		t.Errorf("the held sensitive tool was reported as a bug:\n%s", got)
	}
	if e.err.Len() != 0 {
		t.Errorf("stderr is not empty:\n%s", e.stderrText())
	}

	ctx := context.Background()
	held, err := e.tools().Get(ctx, "reporting", "submit_report")
	if err != nil {
		t.Fatal(err)
	}
	if held.Status != quarantine.StatusApproved || held.SensitiveClearedHash != "" || held.Usable() {
		t.Errorf("submit_report after the set: %+v, want approved, not cleared, not usable", held)
	}
	if safe, _ := e.tools().Get(ctx, "reporting", "list_reports"); !safe.Usable() {
		t.Errorf("list_reports after the set: %+v, want usable", safe)
	}
}

// TestRunToolApprove_ReapprovingAHeldSensitiveToolIsANoOp pins the two
// read-first branches of runToolApproveFingerprint for a tool approved as
// advertised and held: the same fingerprint is nothing to do (exit 0, the
// clear command repeated, no new row), and another fingerprint is refused
// as already approved -- before ADR-0048 this state fell into "drift" and
// was re-approved.
func TestRunToolApprove_ReapprovingAHeldSensitiveToolIsANoOp(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserveSensitive(t, e, "reporting", submitReport)
	requireExit(t, runToolApproveReviewed(e.opEnv, "reporting", "submit_report"), exitOK, "first approval")
	ctx := context.Background()
	rows, err := e.auditTrail().List(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows after the first approval: %d, %v; want 1", len(rows), err)
	}

	e.out.Reset()
	e.err.Reset()
	requireExit(t, runToolApproveReviewed(e.opEnv, "reporting", "submit_report"), exitOK, "approve again")
	requireContains(t, e.stdoutText(), "Nothing to do", "approve again")
	requireContains(t, e.stdoutText(), "mcp-gateway tool clear reporting submit_report", "approve again")
	if strings.Contains(e.stdoutText(), "Re-approved") {
		t.Errorf("a held sensitive tool was re-approved as drift:\n%s", e.stdoutText())
	}
	if rows, _ := e.auditTrail().List(ctx); len(rows) != 1 {
		t.Errorf("the no-op approval wrote a row: %d rows", len(rows))
	}

	e.out.Reset()
	e.err.Reset()
	requireExit(t, runToolApproveFingerprint(e.opEnv, "reporting", "submit_report", "deadbeef"), exitProblem, "approve another fingerprint")
	requireContains(t, e.stderrText(), "already approved at", "approve another fingerprint")
	if after, _ := e.tools().Get(ctx, "reporting", "submit_report"); after.Usable() || after.Status != quarantine.StatusApproved {
		t.Errorf("after the refused re-approval: %+v", after)
	}
}

// TestRunToolApprove_GrantCoverageOfASensitiveToolIsHonest: the block
// printed before the transition. Under a wildcard-only role it must not
// say "makes it callable by every analyst", nor print the wildcard notice
// -- the gateway refuses that role, and approval is not the last human act
// -- and with a non_read role naming it, that role is the one printed.
func TestRunToolApprove_GrantCoverageOfASensitiveToolIsHonest(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Roles = []config.Role{{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}}}
	mustObserveSensitive(t, e, "reporting", submitReport)
	requireExit(t, runToolApproveReviewed(e.opEnv, "reporting", "submit_report"), exitOK, "approve under a wildcard")
	got := e.stdoutText()
	requireContains(t, got, "no [[role]] with non_read = true names it", "approve under a wildcard")
	for _, bad := range []string{"makes it callable by every analyst", `A "*" grant is why this matters`, "ONLY remaining human act"} {
		if strings.Contains(got, bad) {
			t.Errorf("approving a sensitive tool under a wildcard printed %q:\n%s", bad, got)
		}
	}

	e2 := newOpTestEnv(t)
	e2.cfg.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}},
		{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true},
	}
	mustObserveSensitive(t, e2, "reporting", submitReport)
	requireExit(t, runToolApproveReviewed(e2.opEnv, "reporting", "submit_report"), exitOK, "approve with a non_read role")
	got = e2.stdoutText()
	requireContains(t, got, "Once cleared, it is callable", "approve with a non_read role")
	requireContains(t, got, "ir-act", "approve with a non_read role")
	if strings.Contains(got, `A "*" grant is why this matters`) {
		t.Errorf("the wildcard notice was printed for a sensitive tool:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ir ") || strings.TrimSpace(line) == "ir" {
			t.Errorf("the wildcard role is listed as reaching the sensitive tool: %q", line)
		}
	}
}
