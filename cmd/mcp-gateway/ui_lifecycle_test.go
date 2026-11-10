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

// design/adr/0046 on the Gatte web console.

// TestUI_AccessBlockWithAnEnd.
func TestUI_AccessBlockWithAnEnd(t *testing.T) {
	_, s, cookie := newUITest(t)
	page := uiDo(s, "GET", "/users", nil, cookie, nil).Body.String()
	if !strings.Contains(page, `name="until"`) {
		t.Fatal("the Blocklist section has no end field")
	}
	w := uiDo(s, "POST", "/access/block", url.Values{"subject": {"sub-ana"}, "until": {"8h"}, "csrf": {s.csrf}}, cookie, samePost)
	if !strings.Contains(w.Body.String(), "ends by itself") {
		t.Fatalf("block with an end:\n%s", w.Body.String())
	}
	if page := uiDo(s, "GET", "/users", nil, cookie, nil).Body.String(); !strings.Contains(page, "ends 20") {
		t.Fatalf("the list does not show the end:\n%s", page)
	}
	w = uiDo(s, "POST", "/access/block", url.Values{"subject": {"sub-bruno"}, "until": {"soon"}, "csrf": {s.csrf}}, cookie, samePost)
	if !strings.Contains(w.Body.String(), "duration such as 8h") {
		t.Fatalf("an unreadable end:\n%s", w.Body.String())
	}
}

// TestUI_OffboardBlocksDisablesAndListsWhatIsLeft, and Delete.
func TestUI_OffboardBlocksDisablesAndListsWhatIsLeft(t *testing.T) {
	e, s, cookie, path := newPeopleTest(t, true)
	if err := e.auditTrail().Record(context.Background(), audit.Record{AnalystIdentity: "sub-ana", AnalystName: "Ana", Tool: "casemgmt.list_cases",
		TargetUpstream: "casemgmt", Timestamp: time.Now().UTC(), Outcome: audit.OutcomeAllowed}); err != nil {
		t.Fatal(err)
	}
	page := uiDo(s, "GET", "/people/account?u=ana", nil, cookie, nil).Body.String()
	if !strings.Contains(page, "/people/offboard") || !strings.Contains(page, `value="sub-ana"`) || !strings.Contains(page, "/people/delete") {
		t.Fatalf("the account page has no offboard or delete:\n%s", page)
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
