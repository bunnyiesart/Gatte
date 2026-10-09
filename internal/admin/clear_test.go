package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The approval/clearance edge of design/adr/0048 Decisão 5: a sensitive
// tool is approved like any other and NOT served until cleared; clearing
// refuses unless a role marked non_read names the tool in `tools`; the
// batch path approves and never clears; and "approved but not usable" is
// no longer reported as a bug for a sensitive tool.

var submitReport = quarantine.ToolIdentity{Name: "submit_report", Description: "Submit a report.", InputSchema: []byte(`{"type":"object"}`)}

// observeAs is harness.observe with the class in the test's hands.
func (h *harness) observeAs(t *testing.T, server string, id quarantine.ToolIdentity, class quarantine.Class) quarantine.Tool {
	t.Helper()
	o, err := h.tools.Observe(context.Background(), server, id, class)
	if err != nil {
		t.Fatal(err)
	}
	return o.Tool
}

// approvedSensitive is a harness with reporting.submit_report observed as
// sensitive and approved at its fingerprint, through the service.
func approvedSensitive(t *testing.T) (*harness, adminapi.ApproveResult) {
	t.Helper()
	h := newHarness(t)
	obs := h.observeAs(t, "reporting", submitReport, quarantine.ClassSensitive)
	res, err := h.svc.ApproveTool(context.Background(), alice, adminapi.ApproveRequest{Server: "reporting", Tool: "submit_report", Fingerprint: obs.ObservedHash})
	if err != nil {
		t.Fatalf("approving a sensitive tool: %v", err)
	}
	return h, res
}

// TestApprove_ASensitiveToolIsApprovedAndHeldNotABug inverts the guard
// that used to answer `internal` here: approved, usable false, the row
// written, and the operator told what remains.
func TestApprove_ASensitiveToolIsApprovedAndHeldNotABug(t *testing.T) {
	h, res := approvedSensitive(t)
	if !res.Changed || !res.Recorded || res.Audit == nil || res.Tool.Status != adminapi.StatusApproved {
		t.Fatalf("approve result %+v", res)
	}
	if res.Tool.Usable || res.Tool.Class != adminapi.ClassSensitive || res.Tool.SensitiveClearedHash != "" {
		t.Fatalf("tool %+v, want approved, sensitive, not cleared, not usable", res.Tool)
	}
	if !res.HasWarning(adminapi.WarnSensitiveUncleared) {
		t.Errorf("warnings %+v lack sensitive_uncleared", res.Warnings)
	}
	joined := strings.Join(res.Messages, "\n")
	if !strings.Contains(joined, "sensitive") || !strings.Contains(joined, "tool clear reporting submit_report") {
		t.Errorf("messages %q do not say approved; sensitive: run tool clear", joined)
	}
	rows := h.rows(t)
	if len(rows) != 1 || rows[0].Tool != admin.ToolApprove || !strings.Contains(rows[0].Reason, "sensitive; not served until cleared") {
		t.Fatalf("rows %+v, want one (tool approve) row saying the tool is held", rows)
	}

	// Approving again at the same definition is a no-op that says the
	// same thing, not a re-approval and not a bug.
	again, err := h.svc.ApproveTool(context.Background(), alice, adminapi.ApproveRequest{Server: "reporting", Tool: "submit_report", Fingerprint: res.Tool.ApprovedHash})
	if err != nil || again.Changed || again.Recorded || !again.HasWarning(adminapi.WarnSensitiveUncleared) {
		t.Fatalf("repeating the approval: %+v, %v; want changed=false with the clear hint", again, err)
	}
	if n := len(h.rows(t)); n != 1 {
		t.Errorf("the repeated approval wrote a row: %d rows", n)
	}
}

func TestClear_RefusesWithOnlyAWildcardGrant(t *testing.T) {
	h, _ := approvedSensitive(t)
	// Both roles of the harness cover reporting through a wildcard, one
	// of them marked non_read: a wildcard never reaches a sensitive tool,
	// whatever the marking.
	h.cfg.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}},
		{Name: "ir-act", Grants: map[string][]string{"reporting": {"*"}}, NonRead: true},
	}
	_, err := h.svc.ClearTool(context.Background(), alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"})
	requireCode(t, err, adminapi.CodeNoNonReadGrant)
	var ae *adminapi.Error
	if !asAdminError(err, &ae) {
		t.Fatal("not an adminapi error")
	}
	for _, want := range []string{`role "ir"`, `role "ir-act"`, "wildcard", "non_read", `"reporting.submit_report"`, "tools = [...]"} {
		if !strings.Contains(ae.Message, want) {
			t.Errorf("refusal does not say %q: %s", want, ae.Message)
		}
	}
	if _, ok := ae.Details["callable_by"]; !ok {
		t.Errorf("refusal carries no details.callable_by: %+v", ae.Details)
	}
	if got, _ := h.tools.Get(context.Background(), "reporting", "submit_report"); got.Usable() || got.SensitiveClearedHash != "" {
		t.Fatal("a refused clearance cleared the tool")
	}
	if n := len(h.rows(t)); n != 1 {
		t.Errorf("a refused clearance wrote a row: %d rows (1 is the approval)", n)
	}
}

func TestClear_RefusesAnExplicitNameOnARoleThatIsNotNonRead(t *testing.T) {
	h, _ := approvedSensitive(t)
	h.cfg.Roles = []config.Role{{Name: "tier1", Tools: []string{"reporting.submit_report"}}}
	_, err := h.svc.ClearTool(context.Background(), alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"})
	requireCode(t, err, adminapi.CodeNoNonReadGrant)
	var ae *adminapi.Error
	asAdminError(err, &ae)
	if !strings.Contains(ae.Message, `role "tier1"`) || !strings.Contains(ae.Message, "not marked non_read") {
		t.Errorf("refusal does not name the role and the missing marking: %s", ae.Message)
	}
	if got, _ := h.tools.Get(context.Background(), "reporting", "submit_report"); got.Usable() {
		t.Fatal("a refused clearance cleared the tool")
	}
}

func TestClear_AcceptsAnExplicitNameOnANonReadRoleAndWritesARow(t *testing.T) {
	h, _ := approvedSensitive(t)
	h.cfg.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}},
		{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true},
	}
	ctx := context.Background()
	res, err := h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || !res.Recorded || res.Audit == nil || res.Audit.Tool != admin.ToolClear {
		t.Fatalf("clear result %+v", res)
	}
	if !res.Tool.Usable || res.Tool.SensitiveClearedHash != res.Tool.ApprovedHash || res.Tool.SensitiveClearedHash == "" {
		t.Fatalf("tool %+v, want usable, cleared at the approved fingerprint", res.Tool)
	}
	if len(res.ClearedBy) != 1 || res.ClearedBy[0].Role != "ir-act" || !res.ClearedBy[0].NonRead || res.ClearedBy[0].Wildcard {
		t.Errorf("cleared_by %+v, want only the non_read role naming the tool", res.ClearedBy)
	}
	got, _ := h.tools.Get(ctx, "reporting", "submit_report")
	if !got.Usable() {
		t.Fatalf("the store does not agree the tool is usable: %+v", got)
	}
	rows := h.rows(t)
	if len(rows) != 2 || rows[1].Tool != admin.ToolClear || rows[1].AnalystIdentity != "(operator:alice)" ||
		!strings.Contains(rows[1].Reason, got.ApprovedHash) || !strings.Contains(rows[1].Reason, "[api]") {
		t.Fatalf("rows %+v, want (tool approve) then (tool clear) naming the operator, the fingerprint and the front", rows)
	}

	again, err := h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"})
	if err != nil || again.Changed || again.Recorded {
		t.Fatalf("repeating the clear: %+v, %v; want changed=false, nothing recorded", again, err)
	}
}

func TestClear_RefusesASafeToolAndAnUnapprovedOne(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.cfg.Roles = []config.Role{{Name: "ir-act", Tools: []string{"casemgmt.list_cases", "reporting.submit_report"}, NonRead: true}}

	obs := h.observe(t, "casemgmt", listCases)
	if _, err := h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: obs.ObservedHash}); err != nil {
		t.Fatal(err)
	}
	_, err := h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "casemgmt", Tool: "list_cases"})
	requireCode(t, err, adminapi.CodeNotSensitive)

	h.observeAs(t, "reporting", submitReport, quarantine.ClassSensitive)
	_, err = h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"})
	requireCode(t, err, adminapi.CodeNotApproved)

	_, err = h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "reporting", Tool: "ghost"})
	requireCode(t, err, adminapi.CodeNotFound)

	if n := len(h.rows(t)); n != 1 {
		t.Errorf("refused clearances wrote rows: %d rows (1 is the approval)", n)
	}
}

// TestApproveToolSet_ApprovesSensitiveToolsAndClearsNone is the batch path
// treated explicitly: the set is approved as one act, the sensitive tool
// of it is approved and held, nothing is cleared, and nothing is a bug.
func TestApproveToolSet_ApprovesSensitiveToolsAndClearsNone(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.cfg.Roles = []config.Role{{Name: "ir-act", Tools: []string{"reporting.submit_report", "reporting.list_reports"}, NonRead: true}}
	h.observeAs(t, "reporting", submitReport, quarantine.ClassSensitive)
	h.observeAs(t, "reporting", quarantine.ToolIdentity{Name: "list_reports", Description: "List reports."}, quarantine.ClassSafe)

	rs, err := h.svc.ReviewToolSet(ctx, "reporting")
	if err != nil || !rs.Approvable || len(rs.Tools) != 2 {
		t.Fatalf("review set %+v, %v", rs, err)
	}
	res, err := h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "reporting", Manifest: rs.Manifest})
	if err != nil {
		t.Fatalf("approving a set with a sensitive tool: %v", err)
	}
	if !res.Changed || !res.Recorded || len(res.Approved) != 2 || len(res.Rows) != 2 {
		t.Fatalf("result %+v", res)
	}
	if !res.HasWarning(adminapi.WarnSensitiveUncleared) {
		t.Errorf("warnings %+v lack sensitive_uncleared", res.Warnings)
	}
	for _, a := range res.Approved {
		switch a.Tool.Tool {
		case "submit_report":
			if a.Tool.Usable || a.Tool.Status != adminapi.StatusApproved || a.Tool.Class != adminapi.ClassSensitive {
				t.Errorf("the sensitive tool after the batch: %+v, want approved and not usable", a.Tool)
			}
		case "list_reports":
			if !a.Tool.Usable {
				t.Errorf("the safe tool after the batch: %+v, want usable", a.Tool)
			}
		}
	}
	got, _ := h.tools.Get(ctx, "reporting", "submit_report")
	if got.Usable() || got.SensitiveClearedHash != "" || got.Status != quarantine.StatusApproved {
		t.Fatalf("the batch cleared, or did not approve, the sensitive tool: %+v", got)
	}
	joined := strings.Join(res.Messages, "\n")
	if !strings.Contains(joined, "approving a set never clears") || !strings.Contains(joined, "submit_report") {
		t.Errorf("messages %q do not say the sensitive tool is held and why", joined)
	}

	// Clearing it afterwards is the separate decision, and it works.
	cl, err := h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"})
	if err != nil || !cl.Changed || !cl.Tool.Usable {
		t.Fatalf("clearing after the batch: %+v, %v", cl, err)
	}
}

// TestClear_IsWithdrawnWithTheApproval: a definition change after a
// clearance holds the tool again, and re-approving does not re-clear.
func TestClear_IsWithdrawnWithTheApproval(t *testing.T) {
	h, _ := approvedSensitive(t)
	h.cfg.Roles = []config.Role{{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true}}
	ctx := context.Background()
	if _, err := h.svc.ClearTool(ctx, alice, adminapi.ToolRef{Server: "reporting", Tool: "submit_report"}); err != nil {
		t.Fatal(err)
	}
	moved := submitReport
	moved.Description = "Submit a report. Also mail it out."
	changed := h.observeAs(t, "reporting", moved, quarantine.ClassSensitive)
	if changed.Usable() || changed.Status != quarantine.StatusChanged {
		t.Fatalf("after a change: %+v, want changed and not usable", changed)
	}
	res, err := h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "reporting", Tool: "submit_report", Fingerprint: changed.ObservedHash})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tool.Usable || !res.HasWarning(adminapi.WarnSensitiveUncleared) {
		t.Fatalf("re-approving a changed sensitive tool served it without a new clearance: %+v", res)
	}
}

// asAdminError is errors.As for *adminapi.Error, kept local so the tests
// above read as one sentence.
func asAdminError(err error, target **adminapi.Error) bool {
	ae, ok := err.(*adminapi.Error)
	if ok {
		*target = ae
	}
	return ok
}

// TestApprove_ASensitiveToolCoveredOnlyByAWildcardGetsNoWildcardWarning:
// callable_by is ReachableBy. The wildcard covers the tool by name and the
// gateway refuses it anyway, so the approval must not say "the only human
// act between it and every analyst in role ir" -- neither statement is
// true -- and callable_by must not list a role that cannot reach it.
func TestApprove_ASensitiveToolCoveredOnlyByAWildcardGetsNoWildcardWarning(t *testing.T) {
	h := newHarness(t)
	h.cfg.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}},
		{Name: "ir-act", Grants: map[string][]string{"reporting": {"*"}}, NonRead: true},
		{Name: "tier1", Tools: []string{"reporting.submit_report"}},
	}
	obs := h.observeAs(t, "reporting", submitReport, quarantine.ClassSensitive)

	rv, err := h.svc.ReviewTool(context.Background(), "reporting", "submit_report")
	if err != nil || len(rv.CallableBy) != 0 {
		t.Fatalf("review callable_by = %+v, %v; want empty: no role reaches a sensitive tool through a wildcard or without the marking", rv.CallableBy, err)
	}

	res, err := h.svc.ApproveTool(context.Background(), alice, adminapi.ApproveRequest{Server: "reporting", Tool: "submit_report", Fingerprint: obs.ObservedHash})
	if err != nil || !res.Changed {
		t.Fatalf("approve: %+v, %v", res, err)
	}
	if res.HasWarning(adminapi.WarnWildcardGrant) {
		t.Errorf("warnings %+v carry wildcard_grant for a sensitive tool the wildcard never reaches", res.Warnings)
	}
	if len(res.CallableBy) != 0 {
		t.Errorf("callable_by = %+v, want empty", res.CallableBy)
	}
	if !res.HasWarning(adminapi.WarnNoRoleGrants) || !res.HasWarning(adminapi.WarnSensitiveUncleared) {
		t.Errorf("warnings %+v, want no_role_grants (worded for non_read) and sensitive_uncleared", res.Warnings)
	}
	for _, w := range res.Warnings {
		if w.Code == adminapi.WarnNoRoleGrants && !strings.Contains(w.Message, "non_read") {
			t.Errorf("no_role_grants for a sensitive tool does not say what is missing: %s", w.Message)
		}
	}

	// With a non_read role naming it, callable_by is exactly that role.
	h.cfg.Roles = append(h.cfg.Roles, config.Role{Name: "dfir", Tools: []string{"reporting.submit_report"}, NonRead: true})
	rv, err = h.svc.ReviewTool(context.Background(), "reporting", "submit_report")
	if err != nil || len(rv.CallableBy) != 1 || rv.CallableBy[0].Role != "dfir" || !rv.CallableBy[0].NonRead || rv.CallableBy[0].Wildcard {
		t.Fatalf("review callable_by = %+v, %v; want only the non_read role naming it", rv.CallableBy, err)
	}
}

// TestApproveToolSet_WildcardWarningComesOnlyFromSafeTools: the batch
// picks its wildcard role among the items a wildcard reaches. A set of one
// sensitive tool under a wildcard gets no wildcard_grant; a set with a safe
// tool beside it does, for the safe tool, and the sensitive item's
// callable_by stays honest.
func TestApproveToolSet_WildcardWarningComesOnlyFromSafeTools(t *testing.T) {
	ctx := context.Background()
	approveSet := func(t *testing.T, h *harness) adminapi.ApproveSetResult {
		t.Helper()
		rs, err := h.svc.ReviewToolSet(ctx, "reporting")
		if err != nil || !rs.Approvable {
			t.Fatalf("review set %+v, %v", rs, err)
		}
		res, err := h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "reporting", Manifest: rs.Manifest})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	h := newHarness(t)
	h.cfg.Roles = []config.Role{{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}}}
	h.observeAs(t, "reporting", submitReport, quarantine.ClassSensitive)
	res := approveSet(t, h)
	if res.HasWarning(adminapi.WarnWildcardGrant) {
		t.Errorf("a set of one sensitive tool under a wildcard raised wildcard_grant: %+v", res.Warnings)
	}
	if !res.HasWarning(adminapi.WarnNoRoleGrants) || len(res.Approved) != 1 || len(res.Approved[0].CallableBy) != 0 {
		t.Errorf("result %+v, want no_role_grants and an empty callable_by for the sensitive item", res)
	}

	h2 := newHarness(t)
	h2.cfg.Roles = []config.Role{{Name: "ir", Grants: map[string][]string{"reporting": {"*"}}}}
	h2.observeAs(t, "reporting", submitReport, quarantine.ClassSensitive)
	h2.observeAs(t, "reporting", quarantine.ToolIdentity{Name: "list_reports", Description: "List reports."}, quarantine.ClassSafe)
	res = approveSet(t, h2)
	if !res.HasWarning(adminapi.WarnWildcardGrant) {
		t.Errorf("the safe tool of the set is under a wildcard and no wildcard_grant was raised: %+v", res.Warnings)
	}
	for _, a := range res.Approved {
		switch a.Tool.Tool {
		case "submit_report":
			if len(a.CallableBy) != 0 {
				t.Errorf("sensitive item callable_by = %+v, want empty", a.CallableBy)
			}
		case "list_reports":
			if len(a.CallableBy) != 1 || !a.CallableBy[0].Wildcard {
				t.Errorf("safe item callable_by = %+v, want the wildcard role", a.CallableBy)
			}
		}
	}
}
