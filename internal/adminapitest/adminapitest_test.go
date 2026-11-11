package adminapitest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// TestFakeServesEveryOperation calls every client method against the fake and
// fails on any transport or decoding error, so the fake stays in step with the
// client's view of the contract.
func TestFakeServesEveryOperation(t *testing.T) {
	c := adminapitest.Start(t)
	ctx := context.Background()
	op, acc := c.Operator, c.Accounts

	check := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	check("whoAmI", first(op.WhoAmI(ctx)))
	check("overview", first(op.Overview(ctx)))
	check("listTools", first(op.ListTools(ctx, "", "")))
	check("reviewTool", first(op.ReviewTool(ctx, "logsearch", "search_absolute")))
	check("reviewToolSet", first(op.ReviewToolSet(ctx, "casemgmt")))
	check("listBlocks", first(op.ListBlocks(ctx)))
	check("listAudit", first(op.ListAudit(ctx, adminapi.AuditQuery{})))
	check("verifyAudit", first(op.VerifyAudit(ctx, adminapi.VerifyRequest{})))
	check("listUpstreams", first(op.ListUpstreams(ctx)))
	check("getUpstream", first(op.GetUpstream(ctx, "casemgmt")))
	check("listSecrets", first(op.ListSecrets(ctx)))
	check("getRoles", first(op.GetRoles(ctx)))
	check("listMaintenance", first(op.ListMaintenance(ctx)))
	check("quotaUsage", first(op.QuotaUsage(ctx, adminapi.QuotaQuery{})))
	check("people", first(op.People(ctx)))
	check("peopleRoles", first(op.PeopleRoles(ctx)))
	check("connect", first(op.Connect(ctx, "ana.lima")))
	_, _, err := op.ConnectScript(ctx, adminapi.OSMacOS, "ana.lima")
	check("connectScript", err)
	check("assignableGroups", first(acc.AssignableGroups(ctx)))
	check("listAccounts", first(acc.ListAccounts(ctx)))
	check("getAccount", first(acc.GetAccount(ctx, "ana.lima")))
	check("checkAccount", first(acc.CheckAccount(ctx, adminapi.AccountDraft{DisplayName: "New Hire"})))
}

// TestApproveIsLive: approving a pending tool at its observed fingerprint moves
// it to approved and usable, and a later list reflects it.
func TestApproveIsLive(t *testing.T) {
	c := adminapitest.Start(t)
	ctx := context.Background()
	rv, err := c.Operator.ReviewTool(ctx, "logsearch", "search_absolute")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Tool.Status != adminapi.StatusPending {
		t.Fatalf("seed tool status = %q, want pending", rv.Tool.Status)
	}
	res, err := c.Operator.ApproveTool(ctx, adminapi.ApproveRequest{Server: "logsearch", Tool: "search_absolute", Fingerprint: rv.Tool.ObservedHash})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Tool.Status != adminapi.StatusApproved || !res.Tool.Usable {
		t.Fatalf("approve = %+v, want approved and usable", res.Tool)
	}
	list, err := c.Operator.ListTools(ctx, "logsearch", "approved")
	if err != nil {
		t.Fatal(err)
	}
	if !containsTool(list.Tools, "search_absolute") {
		t.Fatal("approved tool is not in the approved list after approval")
	}
}

// TestApproveWrongFingerprintIsRefused covers an error state the frontends must
// render: the definition moved since it was shown.
func TestApproveWrongFingerprintIsRefused(t *testing.T) {
	c := adminapitest.Start(t)
	_, err := c.Operator.ApproveTool(context.Background(), adminapi.ApproveRequest{
		Server: "logsearch", Tool: "search_absolute", Fingerprint: "sha256:stale"})
	var ae *adminapi.Error
	if !errors.As(err, &ae) || ae.Code != adminapi.CodeFingerprintMismatch {
		t.Fatalf("approve with a stale fingerprint: err = %v, want fingerprint_mismatch", err)
	}
}

// TestUnknownAccountIs404 covers the not-found error state.
func TestUnknownAccountIs404(t *testing.T) {
	c := adminapitest.Start(t)
	_, err := c.Accounts.GetAccount(context.Background(), "nobody")
	var ae *adminapi.Error
	if !errors.As(err, &ae) || ae.Code != adminapi.CodeNotFound {
		t.Fatalf("get unknown account: err = %v, want not_found", err)
	}
}

// TestAccountLifecycleIsLive: add, read back, then delete.
func TestAccountLifecycleIsLive(t *testing.T) {
	c := adminapitest.Start(t)
	ctx := context.Background()
	add, err := c.Accounts.AddAccount(ctx, adminapi.NewAccount{Username: "carla.nova", DisplayName: "Carla Nova", Groups: []string{"soc-tier1"}})
	if err != nil {
		t.Fatal(err)
	}
	if add.OneTimePassword == "" {
		t.Fatal("add account returned no one-time password")
	}
	got, err := c.Accounts.GetAccount(ctx, "carla.nova")
	if err != nil {
		t.Fatalf("account not found after add: %v", err)
	}
	if got.Username != "carla.nova" {
		t.Fatalf("got %q", got.Username)
	}
	if _, err := c.Accounts.DeleteAccount(ctx, "carla.nova"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Accounts.GetAccount(ctx, "carla.nova"); err == nil {
		t.Fatal("account still present after delete")
	}
}

// TestRegisterRemoteIsLive: a remote register lists the entry with its URL
// and remote kind (streamable by default), and the fake refuses a keyed
// descriptor with no key, as the backend does.
func TestRegisterRemoteIsLive(t *testing.T) {
	c := adminapitest.Start(t)
	ctx := context.Background()
	res, err := c.Operator.RegisterUpstream(ctx, adminapi.RegisterUpstreamRequest{Name: "vendor", Transport: adminapi.UpstreamTransportRemote,
		URL: "https://mcp.vendor.example/mcp", AuthKind: "bearer", KeyName: "VENDOR_TOKEN"})
	if err != nil || res.Transport != "remote" || res.RemoteKind != adminapi.RemoteKindStreamable || res.Auth.Secret != "VENDOR_TOKEN" {
		t.Fatalf("register = %+v, %v", res, err)
	}
	d, err := c.Operator.GetUpstream(ctx, "vendor")
	if err != nil || d.Transport != "remote" || d.URL != "https://mcp.vendor.example/mcp" || d.Auth == nil || d.Auth.Kind != "bearer" {
		t.Fatalf("detail = %+v, %v", d, err)
	}
	_, err = c.Operator.RegisterUpstream(ctx, adminapi.RegisterUpstreamRequest{Name: "nokey", Transport: adminapi.UpstreamTransportRemote,
		URL: "https://mcp.vendor.example/mcp", AuthKind: "header", AuthName: "X-Api-Key"})
	if !adminapi.IsCode(err, adminapi.CodeInvalidArgument) {
		t.Fatalf("a keyed descriptor with no key: %v", err)
	}

	// What the backend refuses, the fake refuses, by field.
	ok := adminapi.RegisterUpstreamRequest{Name: "bad", Transport: adminapi.UpstreamTransportRemote, URL: "https://mcp.vendor.example/mcp",
		AuthKind: "header", AuthName: "X-Api-Key", KeyName: "VENDOR_TOKEN"}
	for _, tc := range []struct {
		what, field string
		edit        func(*adminapi.RegisterUpstreamRequest)
	}{
		{"a key on a keyless entry", "key_name", func(r *adminapi.RegisterUpstreamRequest) { r.AuthKind, r.AuthName = "none", "" }},
		{"a key, no auth kind", "key_name", func(r *adminapi.RegisterUpstreamRequest) { r.AuthKind, r.AuthName = "", "" }},
		{"query auth", "auth_kind", func(r *adminapi.RegisterUpstreamRequest) { r.AuthKind = "query" }},
		{"bearer with a name", "auth_name", func(r *adminapi.RegisterUpstreamRequest) { r.AuthKind = "bearer" }},
		{"header with no name", "auth_name", func(r *adminapi.RegisterUpstreamRequest) { r.AuthName = "" }},
		{"a header line", "auth_name", func(r *adminapi.RegisterUpstreamRequest) { r.AuthName = "Authorization: Bearer x" }},
		{"sse", "remote_kind", func(r *adminapi.RegisterUpstreamRequest) { r.RemoteKind = "sse" }},
		{"userinfo", "url", func(r *adminapi.RegisterUpstreamRequest) { r.URL = "https://u:p@mcp.vendor.example/mcp" }},
		{"a query", "url", func(r *adminapi.RegisterUpstreamRequest) { r.URL = "https://mcp.vendor.example/mcp?k=v" }},
		{"a fragment", "url", func(r *adminapi.RegisterUpstreamRequest) { r.URL = "https://mcp.vendor.example/mcp#x" }},
		{"an image", "image", func(r *adminapi.RegisterUpstreamRequest) { r.Image = "x@sha256:0" }},
	} {
		req := ok
		tc.edit(&req)
		_, err := c.Operator.RegisterUpstream(ctx, req)
		var ae *adminapi.Error
		if !errors.As(err, &ae) || ae.Code != adminapi.CodeInvalidArgument || ae.Details["field"] != tc.field {
			t.Errorf("%s: %v, want invalid_argument on %s", tc.what, err, tc.field)
		}
	}
	if _, err := c.Operator.GetUpstream(ctx, "bad"); !adminapi.IsCode(err, adminapi.CodeNotFound) {
		t.Fatalf("a refused register left an entry: %v", err)
	}
	open, err := c.Operator.RegisterUpstream(ctx, adminapi.RegisterUpstreamRequest{Name: "open", Transport: adminapi.UpstreamTransportRemote,
		URL: "https://mcp.open.example/mcp", AuthKind: "none"})
	if err != nil || open.Auth != (adminapi.UpstreamAuth{Kind: "none"}) || len(open.EnvVarNames) != 0 {
		t.Fatalf("keyless = %+v, %v", open, err)
	}
}

func first[T any](v T, err error) error { return err }

func containsTool(ts []adminapi.Tool, tool string) bool {
	for _, t := range ts {
		if t.Tool == tool {
			return true
		}
	}
	return false
}
