package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
)

// TestASensitiveRefusalIsTheForbiddenClassOnTheWire pins design/adr/0048
// Decisão 5 at the last hop: the class gate's refusal (a cleared sensitive
// tool reached only through a wildcard) and a plain policy denial (a tool
// outside the role) are the SAME class, and classify + the two writers put
// byte-identical answers on the wire for both -- carrying none of
// "sensitive", "non_read" or "clear". Both errors are the real ones from
// gateway.Dispatch, not hand-built. The guard this is: a `case
// errors.Is(err, gateway.ErrSensitiveNotGranted)` added to classify ahead
// of ErrForbidden, for a "more helpful" message, would reopen on the wire
// the clearance oracle TestDispatch_AReadRoleLearnsNothingAboutClearance
// closes in the domain.
func TestASensitiveRefusalIsTheForbiddenClassOnTheWire(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A sensitive operation joins casemgmt; approved and cleared through
	// the quarantine's own transitions.
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.defs = append(up.defs, gateway.ToolDef{Name: "close_case", Description: "Close a case.", InputSchema: json.RawMessage(objSchema), SecurityClass: quarantine.ClassSensitive})
	up.mu.Unlock()
	if err := h.gw.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	q := quarantinesql.New(h.db)
	if _, err := q.Approve(ctx, "casemgmt", "close_case"); err != nil {
		t.Fatal(err)
	}
	if got, err := q.Clear(ctx, "casemgmt", "close_case"); err != nil || !got.Usable() {
		t.Fatalf("Clear: %+v, %v", got, err)
	}

	// The analyst's role: a wildcard on casemgmt, nothing on logsearch.
	policy, err := access.NewPolicy(
		[]access.Role{{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}}},
		map[string]string{"soc-n1": "n1-triage"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.gw.ApplyPolicy(ctx, policy, noQuota(t)); err != nil {
		t.Fatal(err)
	}

	c := gateway.Caller{Identity: analyst, SourceAddress: "127.0.0.1:1"}
	_, sensitiveErr := h.gw.Dispatch(ctx, c, "casemgmt.close_case", nil)
	_, outsideErr := h.gw.Dispatch(ctx, c, toolSearch, nil)
	if !errors.Is(sensitiveErr, gateway.ErrSensitiveNotGranted) || !errors.Is(sensitiveErr, access.ErrForbidden) {
		t.Fatalf("precondition: Dispatch(close_case) = %v, want the class gate's refusal", sensitiveErr)
	}
	if !errors.Is(outsideErr, access.ErrForbidden) || errors.Is(outsideErr, gateway.ErrSensitiveNotGranted) {
		t.Fatalf("precondition: Dispatch(search) = %v, want a plain policy denial", outsideErr)
	}

	onTheWire := func(err error, tool string) (int, string) {
		t.Helper()
		class := classify(err)
		if class != classForbidden {
			t.Fatalf("classify(%v) = %v, want classForbidden", err, class)
		}
		rec := httptest.NewRecorder()
		writeGeneric(rec, class)
		wire := jsonRPCError(class, tool).Error()
		return rec.Code, rec.Body.String() + "|" + strings.ReplaceAll(wire, tool, "<TOOL>")
	}
	sensitiveStatus, sensitiveWire := onTheWire(sensitiveErr, "casemgmt.close_case")
	outsideStatus, outsideWire := onTheWire(outsideErr, toolSearch)
	if sensitiveStatus != outsideStatus || sensitiveWire != outsideWire {
		t.Errorf("the class gate's refusal and a policy denial are distinguishable on the wire:\n  sensitive: %d %q\n  outside:   %d %q",
			sensitiveStatus, sensitiveWire, outsideStatus, outsideWire)
	}
	assertNoLeak(t, sensitiveWire)
	for _, word := range []string{"sensitive", "non_read", "non-read", "clear"} {
		if strings.Contains(strings.ToLower(sensitiveWire), word) {
			t.Errorf("the wire answer says %q: %s", word, sensitiveWire)
		}
	}

	// And the trail, not the caller, carries the distinct reason.
	want := map[string]string{"casemgmt.close_case": "sensitive tool requires an explicit grant in a non-read role", toolSearch: "forbidden"}
	for tool, reason := range want {
		rows := h.denialsFor(tool)
		if len(rows) != 1 || rows[0].Reason != reason {
			t.Errorf("denials for %s = %+v, want one row with reason %q", tool, rows, reason)
		}
	}
}
