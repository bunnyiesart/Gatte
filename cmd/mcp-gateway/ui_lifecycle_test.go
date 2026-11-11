//go:build !nofront

package main

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// design/adr/0046 on the Gatte web console, with the offboard subject typed
// (design/adr/0061 §3).

// TestUI_OffboardBlocksDisablesAndListsWhatIsLeft, and Delete.
func TestUI_OffboardBlocksDisablesAndListsWhatIsLeft(t *testing.T) {
	e, s, cookie, path := newPeopleTest(t, true)
	if err := e.auditTrail().Record(context.Background(), audit.Record{AnalystIdentity: "sub-ana", AnalystName: "Ana", Tool: "casemgmt.list_cases",
		TargetUpstream: "casemgmt", Timestamp: time.Now().UTC(), Outcome: audit.OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	page := uiDo(s, "GET", "/people/account?u=ana", nil, cookie, nil).Body.String()
	if !strings.Contains(page, "/people/offboard") || !strings.Contains(page, `name="subject"`) || !strings.Contains(page, "/people/delete") {
		t.Fatalf("the account page has no offboard or delete:\n%s", page)
	}
	// The subject is typed: the page reads no audit data to offer one, and
	// nothing comes pre-selected (design/adr/0046, 0061).
	if strings.Contains(page, "sub-ana") || strings.Contains(page, "<select name=\"subject\"") {
		t.Fatalf("the offboard form offers a subject from the audit trail:\n%s", page)
	}
	w := uiDo(s, "POST", "/people/offboard", url.Values{"username": {"ana"}, "subject": {"sub-ana"}, "reason": {"left"}, "csrf": {s.csrf}}, cookie, samePost)
	body := w.Body.String()
	if !strings.Contains(body, "Still to do by hand") || !strings.Contains(body, "identity provider") {
		t.Fatalf("offboard result:\n%s", body)
	}
	if b, _ := e.blocks().Blocked(context.Background(), "sub-ana"); !b {
		t.Fatal("not blocked")
	}
	if f, _ := os.ReadFile(path); !strings.Contains(string(f), "disabled: true") {
		t.Fatalf("not disabled:\n%s", f)
	}
	w = uiDo(s, "POST", "/people/delete", url.Values{"username": {"ana"}, "csrf": {s.csrf}}, cookie, samePost)
	if f, _ := os.ReadFile(path); !strings.Contains(string(f), "ana:") || !strings.Contains(w.Body.String(), "tick the confirmation") {
		t.Fatal("deleted without the confirmation")
	}
	uiDo(s, "POST", "/people/delete", url.Values{"username": {"ana"}, "confirm": {"yes"}, "csrf": {s.csrf}}, cookie, samePost)
	if f, _ := os.ReadFile(path); strings.Contains(string(f), "ana:") {
		t.Fatalf("not deleted:\n%s", f)
	}
	rows, _ := e.auditTrail().List(context.Background())
	var tools []string
	for _, r := range rows {
		tools = append(tools, r.Tool)
	}
	if got := strings.Join(tools, ","); got != "casemgmt.list_cases,(access block),(account disable),(account offboard),(account delete)" {
		t.Fatalf("rows %s", got)
	}
}
