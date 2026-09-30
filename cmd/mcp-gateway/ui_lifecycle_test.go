//go:build !nofront

package main

import (
	"context"
	"encoding/csv"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// design/adr/0046 on the Gatte web console.

func seedUITrail(t *testing.T, e opTestEnv) time.Time {
	t.Helper()
	base := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	for i, rec := range []audit.Record{
		{AnalystIdentity: "sub-ana", Tool: "casemgmt.list_cases", TargetUpstream: "casemgmt", Outcome: audit.OutcomeAllowed},
		{AnalystIdentity: "sub-ana", Tool: "logsearch.search", TargetUpstream: "logsearch", Outcome: audit.OutcomeAllowed},
		{AnalystIdentity: "sub-bruno", Tool: "=HYPERLINK(\"http://x.test\")", TargetUpstream: "casemgmt", Outcome: audit.OutcomeDenied, Reason: "@probe\u202e"},
	} {
		rec.Timestamp = base.Add(time.Duration(i) * time.Hour)
		if err := e.auditTrail().Record(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

// TestUI_AuditFiltersByToolServerAndTimeAndPagesBack: every filter is the
// API's, and "Older records" walks back with before.
func TestUI_AuditFiltersByToolServerAndTimeAndPagesBack(t *testing.T) {
	e, s, cookie := newUITest(t)
	seedUITrail(t, e)
	body := uiDo(s, "GET", "/audit?server=logsearch", nil, cookie, nil).Body.String()
	if !strings.Contains(body, ">logsearch.search<") || strings.Contains(body, ">casemgmt.list_cases<") {
		t.Fatalf("server filter:\n%s", body)
	}
	body = uiDo(s, "GET", "/audit?tool=casemgmt.list_cases&since=2026-09-30&until=2026-09-30+09:00", nil, cookie, nil).Body.String()
	if !strings.Contains(body, ">casemgmt.list_cases<") || strings.Contains(body, ">logsearch.search<") {
		t.Fatalf("tool and window:\n%s", body)
	}
	body = uiDo(s, "GET", "/audit?since=yesterday", nil, cookie, nil).Body.String()
	if !strings.Contains(body, "From") || !strings.Contains(body, "use 2026-09-30") {
		t.Fatalf("an unreadable time is not refused:\n%s", body)
	}
	body = uiDo(s, "GET", "/audit?limit=1", nil, cookie, nil).Body.String()
	if !strings.Contains(body, "Older records") || !strings.Contains(body, "before=3") {
		t.Fatalf("no link to older records:\n%s", body)
	}
	body = uiDo(s, "GET", "/audit?limit=1&before=3", nil, cookie, nil).Body.String()
	if !strings.Contains(body, ">logsearch.search<") || strings.Contains(body, "HYPERLINK") || !strings.Contains(body, "Newest") {
		t.Fatalf("the older page:\n%s", body)
	}
}

// TestUI_AuditDownloadsAreTheFilteredRowsCSVGuarded: the CSV cell of a
// formula starts with an apostrophe and a hidden character is visible;
// the JSON Lines carry the raw values.
func TestUI_AuditDownloadsAreTheFilteredRowsCSVGuarded(t *testing.T) {
	e, s, cookie := newUITest(t)
	seedUITrail(t, e)
	w := uiDo(s, "GET", "/audit/export?format=csv&outcome=denied", nil, cookie, nil)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv: %d %v", w.Code, w.Header())
	}
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv rows %v, %v\n%s", rows, err, w.Body.String())
	}
	if rows[0][4] != "tool" || rows[1][4] != `'=HYPERLINK("http://x.test")` || rows[1][7] != `'@probe\u{202E}` {
		t.Fatalf("csv row %q", rows[1])
	}
	w = uiDo(s, "GET", "/audit/export?format=jsonl&subject=sub-ana", nil, cookie, nil)
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if w.Code != 200 || len(lines) != 2 || !strings.Contains(lines[0], `"logsearch.search"`) {
		t.Fatalf("jsonl: %d\n%s", w.Code, w.Body.String())
	}
	if w := uiDo(s, "GET", "/audit/export?format=xlsx", nil, cookie, nil); w.Code != 400 {
		t.Fatalf("format xlsx: %d", w.Code)
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatal("the download loosened the CSP")
	}
}

// TestUI_AccessBlockWithAnEnd.
func TestUI_AccessBlockWithAnEnd(t *testing.T) {
	_, s, cookie := newUITest(t)
	page := uiDo(s, "GET", "/access", nil, cookie, nil).Body.String()
	if !strings.Contains(page, `name="until"`) {
		t.Fatal("the Access page has no end field")
	}
	w := uiDo(s, "POST", "/access/block", url.Values{"subject": {"sub-ana"}, "until": {"8h"}, "csrf": {s.csrf}}, cookie, samePost)
	if !strings.Contains(w.Body.String(), "ends by itself") {
		t.Fatalf("block with an end:\n%s", w.Body.String())
	}
	if page := uiDo(s, "GET", "/access", nil, cookie, nil).Body.String(); !strings.Contains(page, "ends 20") {
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
