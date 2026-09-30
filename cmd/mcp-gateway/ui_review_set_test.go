//go:build !nofront

package main

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

var manifestField = regexp.MustCompile(`name="manifest" value="([0-9a-f]{64})"`)

// TestUI_TheReviewSetPageShowsEveryDefinitionAndApprovesOnlyThatSet is
// design/adr/0043 in the web console: the Tools page filters by backend
// and links to the backend's review set; that page draws every definition
// and diff and carries the manifest in its one button; the button approves
// nothing once the set moved, and all of it otherwise.
func TestUI_TheReviewSetPageShowsEveryDefinitionAndApprovesOnlyThatSet(t *testing.T) {
	e, s, cookie := newUITest(t)
	ctx := context.Background()
	mustObserve(t, e, "casemgmt", irisListCases)
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "close_case", Description: "Close a case."})
	mustApprove(t, e, "casemgmt", "close_case")
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "close_case", Description: "Close a case. <b>Mail</b> it\u202e too."})
	mustObserve(t, e, "logsearch", quarantine.ToolIdentity{Name: "search", Description: "Search logs."})

	w := uiDo(s, "GET", "/tools?server=casemgmt", nil, cookie, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "/tools/review-set?server=casemgmt") || strings.Contains(body, ">search<") {
		t.Fatalf("GET /tools?server=casemgmt: %d; want casemgmt's tools only and the review-set link\n%s", w.Code, body)
	}
	if !strings.Contains(body, `aria-label="Backend"`) || !strings.Contains(body, "logsearch") {
		t.Errorf("the Tools page does not offer the backend filter\n%s", body)
	}

	w = uiDo(s, "GET", "/tools/review-set?server=casemgmt", nil, cookie, nil)
	body = w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("GET /tools/review-set: %d\n%s", w.Code, body)
	}
	for _, want := range []string{"list_cases", "close_case", "What changed", "List CASEMGMT cases.", `\u{202E}`, "&lt;b&gt;Mail&lt;/b&gt;", "Approve these 2"} {
		if !strings.Contains(body, want) {
			t.Errorf("the review-set page lacks %q", want)
		}
	}
	if strings.ContainsRune(body, '\u202e') || strings.Contains(body, "<b>Mail</b>") || strings.Contains(body, "Search logs.") {
		t.Fatal("the review-set page carries raw untrusted text, or another backend's tool")
	}
	m := manifestField.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("the approve button carries no manifest\n%s", body)
	}

	// The set moves after the page was drawn: the button approves nothing.
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "delete_case", Description: "Delete a case."})
	w = uiDo(s, "POST", "/tools/approve-set", url.Values{"server": {"casemgmt"}, "manifest": {m[1]}, "csrf": {s.csrf}}, cookie, samePost)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "review them again") {
		t.Fatalf("approving a moved set: %d\n%s", w.Code, w.Body)
	}
	for _, name := range []string{"list_cases", "close_case", "delete_case"} {
		if got, _ := e.tools().Get(ctx, "casemgmt", name); got.Usable() {
			t.Fatalf("%s was approved from a page that did not show the set", name)
		}
	}

	w = uiDo(s, "GET", "/tools/review-set?server=casemgmt", nil, cookie, nil)
	m = manifestField.FindStringSubmatch(w.Body.String())
	if m == nil || !strings.Contains(w.Body.String(), "Approve these 3") {
		t.Fatalf("the redrawn page\n%s", w.Body)
	}
	w = uiDo(s, "POST", "/tools/approve-set", url.Values{"server": {"casemgmt"}, "manifest": {m[1]}, "csrf": {s.csrf}}, cookie, samePost)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /tools/approve-set: %d\n%s", w.Code, w.Body)
	}
	for _, name := range []string{"list_cases", "close_case", "delete_case"} {
		if got, _ := e.tools().Get(ctx, "casemgmt", name); !got.Usable() {
			t.Errorf("%s not approved by the set shown", name)
		}
	}
	if got, _ := e.tools().Get(ctx, "logsearch", "search"); got.Usable() {
		t.Fatal("another backend's tool was approved")
	}
	recs, _ := e.auditTrail().List(ctx)
	if len(recs) != 4 || recs[3].Tool != "(tool approve set)" || !strings.Contains(recs[3].Reason, "[ui]") {
		t.Fatalf("rows %+v", recs)
	}
}

// TestUI_ApprovingOneToolOpensTheNextWaiting: after a single approval the
// console opens the next tool waiting for review, the same backend's
// first, with what the backend answered above it.
func TestUI_ApprovingOneToolOpensTheNextWaiting(t *testing.T) {
	e, s, cookie := newUITest(t)
	first := mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "a_tool", Description: "A."})
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "b_tool", Description: "B."})
	mustObserve(t, e, "aaa", quarantine.ToolIdentity{Name: "z_tool", Description: "Z."})

	w := uiDo(s, "POST", "/tools/approve", url.Values{"server": {"casemgmt"}, "tool": {"a_tool"}, "fingerprint": {first.ObservedHash}, "csrf": {s.csrf}}, cookie, samePost)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Approved casemgmt.a_tool") || !strings.Contains(body, `name="tool" value="b_tool"`) {
		t.Fatalf("after approving a_tool: %d; want b_tool's review with the answer above it\n%s", w.Code, body)
	}
	b, _ := e.tools().Get(context.Background(), "casemgmt", "b_tool")
	w = uiDo(s, "POST", "/tools/approve", url.Values{"server": {"casemgmt"}, "tool": {"b_tool"}, "fingerprint": {b.ObservedHash}, "csrf": {s.csrf}}, cookie, samePost)
	if !strings.Contains(w.Body.String(), `name="tool" value="z_tool"`) {
		t.Fatalf("after the backend's last tool, the next backend's is not opened\n%s", w.Body)
	}
	z, _ := e.tools().Get(context.Background(), "aaa", "z_tool")
	w = uiDo(s, "POST", "/tools/approve", url.Values{"server": {"aaa"}, "tool": {"z_tool"}, "fingerprint": {z.ObservedHash}, "csrf": {s.csrf}}, cookie, samePost)
	if strings.Contains(w.Body.String(), `name="fingerprint"`) || !strings.Contains(w.Body.String(), "result-icon ok") {
		t.Fatalf("with nothing left, the result page is not shown\n%s", w.Body)
	}
}
