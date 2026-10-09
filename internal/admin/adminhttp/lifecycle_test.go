package adminhttp_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// TestOffboard_TheAccountsSocketAsksTheKernelWhetherThePeerIsAnOperator is
// design/adr/0046 item 2: the operator group is read from the peer's
// credentials, never from the request.
func TestOffboard_TheAccountsSocketAsksTheKernelWhetherThePeerIsAnOperator(t *testing.T) {
	b := newBackend(t)
	// Root is an operator whatever its groups, so this half runs only as
	// another user.
	if os.Geteuid() != 0 {
		other := uint32(1<<31 - 7)
		sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: b.svc, OperatorGID: &other})
		status, code, body := call(t, sock, "POST", "/v1/accounts/ana/offboard", `{"subject":"sub-ana"}`, nil)
		if status != 403 || code != adminapi.CodeForbiddenPeer {
			t.Fatalf("offboard with a subject by a peer outside the operator group: %d %s", status, body)
		}
	}
	mine := uint32(os.Getegid())
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: b.svc, OperatorGID: &mine})
	status, _, body := call(t, sock, "POST", "/v1/accounts/ana/offboard", `{"subject":"sub-ana","reason":"left"}`, map[string]string{adminapi.FrontHeader: "ui"})
	var res adminapi.OffboardResult
	if status != 200 || json.Unmarshal(body, &res) != nil || !res.Blocked || !res.Disabled || len(res.Rows) != 3 {
		t.Fatalf("offboard by a peer in the operator group: %d %s", status, body)
	}
	status, code, _ := call(t, sock, "POST", "/v1/accounts/ana/offboard", `{"subject":"sub-ana","groups":[]}`, nil)
	if status != 400 || code != adminapi.CodeBadRequest {
		t.Fatalf("offboard with an unknown field: %d %s", status, code)
	}
}

// TestDeleteAccount_IsServedOnTheAccountsSocketOnly.
func TestDeleteAccount_IsServedOnTheAccountsSocketOnly(t *testing.T) {
	b := newBackend(t)
	op, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	if status, code, _ := call(t, op, "DELETE", "/v1/accounts/ana", "", nil); status != 404 || code != adminapi.CodeWrongSocket {
		t.Fatalf("delete on the operator socket: %d %s", status, code)
	}
	acc, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: b.svc})
	if status, _, body := call(t, acc, "DELETE", "/v1/accounts/ana", "", nil); status != 200 || !strings.Contains(string(body), `"(account delete)"`) {
		t.Fatalf("delete: %d %s", status, body)
	}
	if status, code, _ := call(t, acc, "DELETE", "/v1/accounts/ana", "", nil); status != 404 || code != adminapi.CodeNotFound {
		t.Fatalf("second delete: %d %s", status, code)
	}
}

// TestAudit_UntilIsParsedLikeSince and the whoami features of 1.4.0.
func TestAudit_UntilIsParsedLikeSince(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	if status, code, _ := call(t, sock, "GET", "/v1/audit?until=yesterday", "", nil); status != 400 || code != adminapi.CodeBadRequest {
		t.Fatalf("until=yesterday: %d %s", status, code)
	}
	if status, _, body := call(t, sock, "GET", "/v1/audit?until=2026-09-30T00:00:00Z&tool=casemgmt.list_cases&server=casemgmt", "", nil); status != 200 {
		t.Fatalf("filtered audit: %d %s", status, body)
	}
	_, _, body := call(t, sock, "GET", "/v1/whoami", "", nil)
	var me adminapi.WhoAmI
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{adminapi.FeatureAuditFilters, adminapi.FeatureBlockUntil, adminapi.FeatureAccountDelete, adminapi.FeatureOffboard, adminapi.FeatureToolClear} {
		found := false
		for _, g := range me.Features {
			found = found || g == f
		}
		if !found {
			t.Errorf("whoami does not list feature %s: %v", f, me.Features)
		}
	}
	// 1.5.0 since design/adr/0048 (feature tool_clear); the whoami
	// features of 1.4.0 are still listed above.
	if me.ContractVersion != "1.5.0" {
		t.Errorf("contract version %s", me.ContractVersion)
	}
}
