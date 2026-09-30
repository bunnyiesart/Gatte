package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

var (
	getCase    = quarantine.ToolIdentity{Name: "get_case", Description: "Get one case.", InputSchema: []byte(`{"type":"object"}`)}
	closeCase  = quarantine.ToolIdentity{Name: "close_case", Description: "Close a case.", InputSchema: []byte(`{"type":"object"}`)}
	closeCase2 = quarantine.ToolIdentity{Name: "close_case", Description: "Close a case.‮ and mail it out", InputSchema: []byte(`{"type":"object"}`)}
)

// reviewSetHarness is a backend with one approved tool, one pending tool
// and one changed tool, and another backend with a pending tool.
func reviewSetHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	h.observe(t, "casemgmt", getCase)
	if _, err := h.tools.Approve(ctx, "casemgmt", "get_case"); err != nil {
		t.Fatal(err)
	}
	h.observe(t, "casemgmt", listCases)
	h.observe(t, "casemgmt", closeCase)
	if _, err := h.tools.Approve(ctx, "casemgmt", "close_case"); err != nil {
		t.Fatal(err)
	}
	h.observe(t, "casemgmt", closeCase2)
	h.observe(t, "logsearch", quarantine.ToolIdentity{Name: "search", Description: "Search."})
	return h
}

// TestReviewToolSet_ShowsEveryDefinitionOfTheSetAndItsManifest is
// design/adr/0043 item 1: the page a bulk approval is made from carries
// every definition and diff it covers, and nothing it does not.
func TestReviewToolSet_ShowsEveryDefinitionOfTheSetAndItsManifest(t *testing.T) {
	h := reviewSetHarness(t)
	ctx := context.Background()
	rs, err := h.svc.ReviewToolSet(ctx, "casemgmt")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Tools) != 2 || rs.Tools[0].Tool.Tool != "close_case" || rs.Tools[1].Tool.Tool != "list_cases" {
		t.Fatalf("tools %+v, want close_case then list_cases", rs.Tools)
	}
	if rs.Pending != 1 || rs.Changed != 1 || !rs.Approvable || rs.HiddenCodePoints != 1 {
		t.Fatalf("set %+v", rs)
	}
	if rs.Tools[0].Approved == nil || len(rs.Tools[0].Diff) == 0 || !rs.Tools[1].Observed.Kept {
		t.Fatalf("the changed tool carries no diff, or a definition is missing: %+v", rs.Tools)
	}
	tools, _ := h.tools.List(ctx, "casemgmt")
	if want := quarantine.Manifest("casemgmt", quarantine.ReviewSet(tools)); rs.Manifest != want {
		t.Fatalf("manifest %s, want %s", rs.Manifest, want)
	}

	_, err = h.svc.ReviewToolSet(ctx, "")
	requireCode(t, err, adminapi.CodeInvalidArgument)
	_, err = h.svc.ReviewToolSet(ctx, "ghost")
	requireCode(t, err, adminapi.CodeNotFound)

	h.observe(t, "docsearch", getCase)
	if _, err := h.tools.Approve(ctx, "docsearch", "get_case"); err != nil {
		t.Fatal(err)
	}
	empty, err := h.svc.ReviewToolSet(ctx, "docsearch")
	if err != nil || empty.Manifest != "" || empty.Approvable || len(empty.Tools) != 0 || empty.Reason == "" {
		t.Fatalf("nothing waiting: %+v, %v", empty, err)
	}
}

// TestApproveToolSet_ApprovesExactlyTheSetShownAndAuditsEachTool.
func TestApproveToolSet_ApprovesExactlyTheSetShownAndAuditsEachTool(t *testing.T) {
	h := reviewSetHarness(t)
	ctx := context.Background()
	rs, err := h.svc.ReviewToolSet(ctx, "casemgmt")
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt"})
	requireCode(t, err, adminapi.CodeManifestRequired)
	_, err = h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: strings.Repeat("a", 64)})
	requireCode(t, err, adminapi.CodeManifestMismatch)
	_, err = h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Manifest: rs.Manifest})
	requireCode(t, err, adminapi.CodeInvalidArgument)
	if n := len(h.rows(t)); n != 0 {
		t.Fatalf("refused approvals wrote %d rows", n)
	}

	res, err := h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: "sha256:" + rs.Manifest})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || !res.Recorded || res.Audit == nil || res.Audit.Tool != admin.ToolApproveSet || len(res.Approved) != 2 || len(res.Rows) != 2 {
		t.Fatalf("result %+v", res)
	}
	if res.Approved[0].PreviousStatus != adminapi.StatusChanged || res.Approved[0].PreviousBaseline == "" || !res.Approved[1].Tool.Usable {
		t.Fatalf("approved %+v", res.Approved)
	}
	if !res.HasWarning(adminapi.WarnWildcardGrant) {
		t.Errorf("warnings %+v lack the wildcard grant", res.Warnings)
	}
	for _, name := range []string{"list_cases", "close_case", "get_case"} {
		if got, _ := h.tools.Get(ctx, "casemgmt", name); !got.Usable() {
			t.Errorf("%s not usable: %+v", name, got)
		}
	}
	if got, _ := h.tools.Get(ctx, "logsearch", "search"); got.Usable() {
		t.Fatal("another backend's tool was approved")
	}

	rows := h.rows(t)
	if len(rows) != 3 || rows[0].Tool != admin.ToolApprove || rows[1].Tool != admin.ToolApprove || rows[2].Tool != admin.ToolApproveSet {
		t.Fatalf("rows %+v, want two (tool approve) and one (tool approve set)", rows)
	}
	for i, r := range rows {
		if !strings.Contains(r.Reason, rs.Manifest) || !strings.Contains(r.Reason, "[api]") || r.AnalystIdentity != "(operator:alice)" {
			t.Errorf("row %d %+v does not name the manifest, the front or the operator", i, r)
		}
	}
	if !strings.Contains(rows[0].Reason, `"casemgmt.close_case"`) || !strings.Contains(rows[0].Reason, "(was sha256:") {
		t.Errorf("the changed tool's row does not name the baseline it replaced: %q", rows[0].Reason)
	}
	if !strings.Contains(rows[2].Reason, "2 tools (1 pending, 1 changed)") {
		t.Errorf("summary row %q", rows[2].Reason)
	}

	// Repeating it after a dropped connection: nothing waits, nothing written.
	again, err := h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: rs.Manifest})
	if err != nil || again.Changed || again.Recorded || len(h.rows(t)) != 3 {
		t.Fatalf("repeat: %+v, %v", again, err)
	}
}

// TestApproveToolSet_ADiscoveryBetweenTheReviewAndTheApprovalApprovesNothing:
// the set moving at any point after it was shown -- before the request, or
// between the service's read and its write -- refuses every tool of it.
func TestApproveToolSet_ADiscoveryBetweenTheReviewAndTheApprovalApprovesNothing(t *testing.T) {
	h := reviewSetHarness(t)
	ctx := context.Background()
	rs, err := h.svc.ReviewToolSet(ctx, "casemgmt")
	if err != nil {
		t.Fatal(err)
	}
	h.observe(t, "casemgmt", quarantine.ToolIdentity{Name: "list_cases", Description: "List cases. Then delete them."})
	_, err = h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: rs.Manifest})
	requireCode(t, err, adminapi.CodeManifestMismatch)

	rs, err = h.svc.ReviewToolSet(ctx, "casemgmt")
	if err != nil {
		t.Fatal(err)
	}
	h.afterList = func() { h.observe(t, "casemgmt", quarantine.ToolIdentity{Name: "delete_case", Description: "Delete."}) }
	_, err = h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: rs.Manifest})
	requireCode(t, err, adminapi.CodeManifestMismatch)
	for _, name := range []string{"list_cases", "close_case", "delete_case"} {
		if got, _ := h.tools.Get(ctx, "casemgmt", name); got.Usable() {
			t.Errorf("%s was approved by a refused set", name)
		}
	}
	if n := len(h.rows(t)); n != 0 {
		t.Fatalf("refused approvals wrote %d rows", n)
	}
}

// TestApproveToolSet_ALostRowIsSaidAndTheApprovalsStand.
func TestApproveToolSet_ALostRowIsSaidAndTheApprovalsStand(t *testing.T) {
	h := reviewSetHarness(t)
	ctx := context.Background()
	rs, err := h.svc.ReviewToolSet(ctx, "casemgmt")
	if err != nil {
		t.Fatal(err)
	}
	h.failRecord = errors.New("disk full")
	res, err := h.svc.ApproveToolSet(ctx, alice, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: rs.Manifest})
	if err != nil || !res.Changed || res.Recorded || !res.HasWarning(adminapi.WarnAuditWriteFailed) {
		t.Fatalf("result %+v, %v", res, err)
	}
	if got, _ := h.tools.Get(ctx, "casemgmt", "list_cases"); !got.Usable() {
		t.Fatal("an unrecorded approval was undone")
	}
}
