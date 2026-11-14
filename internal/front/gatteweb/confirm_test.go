package gatteweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// get drives one GET through the real console routes and returns the response.
func get(t *testing.T, f *Front, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.routes().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

// A consequential one-click action is now a link to a confirm page, not a form
// that posts on the first click: the review page links Revoke and Clear with GET
// and carries no POST form of its own for an approved tool.
func TestToolPage_RevokeAndClearAreConfirmLinks(t *testing.T) {
	f := testFront(t)

	safe := get(t, f, "/servers/casemgmt/tools/get_case").Body.String()
	if !strings.Contains(safe, `href="/servers/casemgmt/tools/get_case/revoke"`) {
		t.Errorf("the approved tool page does not link Revoke to its confirm page:\n%s", safe)
	}
	if strings.Contains(safe, `method="post"`) {
		t.Errorf("the approved tool page still posts an action on the first click:\n%s", safe)
	}

	sensitive := get(t, f, "/servers/casemgmt/tools/create_case").Body.String()
	if !strings.Contains(sensitive, `href="/servers/casemgmt/tools/create_case/clear"`) {
		t.Errorf("the sensitive tool page does not link Clear to its confirm page:\n%s", sensitive)
	}
}

// Revoke's confirm page is a GET interstitial: one sentence, a Cancel back to the
// tool, and a single POST form, carrying the form token, to the same revoke
// action.
func TestRevokeConfirm_IsAGetInterstitialThatPostsRevoke(t *testing.T) {
	f := testFront(t)
	w := get(t, f, "/servers/casemgmt/tools/get_case/revoke")
	if w.Code != http.StatusOK {
		t.Fatalf("GET the revoke confirm: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	for _, want := range []string{
		"Revoke casemgmt.get_case",
		`action="/servers/casemgmt/tools/get_case/revoke"`,
		`method="post"`,
		`name="csrf"`,
		">Revoke approval<",
		">Cancel<",
		`href="/servers/casemgmt/tools/get_case"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the revoke confirm page is missing %q:\n%s", want, s)
		}
	}
}

// Clear's confirm page posts the clear action and reaches it only on a console
// that may clear.
func TestClearConfirm_PostsClear(t *testing.T) {
	f := testFront(t)
	w := get(t, f, "/servers/casemgmt/tools/create_case/clear")
	if w.Code != http.StatusOK {
		t.Fatalf("GET the clear confirm: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	for _, want := range []string{
		"Clear casemgmt.create_case",
		`action="/servers/casemgmt/tools/create_case/clear"`,
		">Clear for serving<",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the clear confirm page is missing %q:\n%s", want, s)
		}
	}
}

// The account page links Disable and Offboard to their confirm pages instead of
// posting on the first click.
func TestAccountPage_DisableAndOffboardAreConfirmLinks(t *testing.T) {
	f := testFront(t)
	s := get(t, f, "/people/account?u=ana.lima").Body.String()
	for _, want := range []string{
		`href="/people/disable?u=ana.lima"`,
		`href="/people/offboard?u=ana.lima"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the account page is missing confirm link %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, `action="/people/disable"`) || strings.Contains(s, `action="/people/offboard"`) {
		t.Errorf("the account page still posts disable or offboard on the first click:\n%s", s)
	}
}

// Disable's confirm page posts disable with the username carried through.
func TestDisableConfirm_PostsDisableWithUsername(t *testing.T) {
	f := testFront(t)
	w := get(t, f, "/people/disable?u=ana.lima")
	if w.Code != http.StatusOK {
		t.Fatalf("GET the disable confirm: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	for _, want := range []string{
		"Disable ana.lima",
		`action="/people/disable"`,
		`name="username" value="ana.lima"`,
		">Disable<",
		">Cancel<",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the disable confirm page is missing %q:\n%s", want, s)
		}
	}
}

// Offboard's confirm page carries the subject and reason inputs and says loudly
// that an empty gateway ID blocks nobody.
func TestOffboardConfirm_WarnsEmptySubjectBlocksNothing(t *testing.T) {
	f := testFront(t)
	w := get(t, f, "/people/offboard?u=ana.lima")
	if w.Code != http.StatusOK {
		t.Fatalf("GET the offboard confirm: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	for _, want := range []string{
		"Offboard ana.lima",
		`action="/people/offboard"`,
		`name="username" value="ana.lima"`,
		`name="subject"`,
		`name="reason"`,
		"nothing is blocked",
		`class="notice danger"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the offboard confirm page is missing %q:\n%s", want, s)
		}
	}
}

// The confirm pages for account actions exist only with the accounts socket: a
// console started without it answers 404, as the actions themselves do.
func TestAccountConfirms_NeedTheAccountsSocket(t *testing.T) {
	c := adminapitest.Start(t)
	kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("frontkit: %v", err)
	}
	t.Cleanup(func() { _ = kit.Close() })
	f, err := New(Options{Operator: c.Operator, Kit: kit}) // no Accounts
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, path := range []string{"/people/disable?u=ana.lima", "/people/offboard?u=ana.lima"} {
		if w := get(t, f, path); w.Code != http.StatusNotFound {
			t.Errorf("GET %s without the accounts socket = %d, want 404", path, w.Code)
		}
	}
}
