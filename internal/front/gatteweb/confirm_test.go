package gatteweb

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
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

// postForm drives one form POST through the real console routes.
func postForm(t *testing.T, f *Front, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.routes().ServeHTTP(w, r)
	return w
}

// Offboard and Delete gate their POST on the same feature as the page that
// offers them: a backend without the feature gets a 404 from both, and the
// account is left as it was. With the feature, the POST goes through.
func TestAccountActions_GateThePostOnTheirFeature(t *testing.T) {
	for _, tc := range []struct {
		feature, get, post string
		form               url.Values
	}{
		{adminapi.FeatureOffboard, "/people/offboard?u=ana.lima", "/people/offboard",
			url.Values{"username": {"ana.lima"}, "subject": {"sub-ana"}, "reason": {"left"}}},
		{adminapi.FeatureAccountDelete, "", "/people/delete",
			url.Values{"username": {"ana.lima"}, "confirm": {"yes"}}},
	} {
		t.Run(tc.feature+" off", func(t *testing.T) {
			f, c := testFrontOn(t)
			c.Server.DropFeature(tc.feature)
			if tc.get != "" {
				if w := get(t, f, tc.get); w.Code != http.StatusNotFound {
					t.Errorf("GET %s without %s = %d, want 404", tc.get, tc.feature, w.Code)
				}
			}
			if w := postForm(t, f, tc.post, tc.form); w.Code != http.StatusNotFound {
				t.Errorf("POST %s without %s = %d, want 404", tc.post, tc.feature, w.Code)
			}
			a, err := c.Accounts.GetAccount(t.Context(), "ana.lima")
			if err != nil || a.Disabled {
				t.Errorf("ana.lima after a refused POST %s: %+v, %v; want present and enabled", tc.post, a, err)
			}
			if bl, err := c.Operator.ListBlocks(t.Context()); err != nil || slices.ContainsFunc(bl.Blocks, func(b adminapi.Block) bool { return b.Subject == "sub-ana" }) {
				t.Errorf("a refused POST %s blocked sub-ana (%v)", tc.post, err)
			}
		})
		t.Run(tc.feature+" on", func(t *testing.T) {
			f, c := testFrontOn(t)
			if w := postForm(t, f, tc.post, tc.form); w.Code != http.StatusOK {
				t.Fatalf("POST %s with %s = %d\n%s", tc.post, tc.feature, w.Code, w.Body)
			}
			a, err := c.Accounts.GetAccount(t.Context(), "ana.lima")
			if tc.feature == adminapi.FeatureOffboard && (err != nil || !a.Disabled) {
				t.Errorf("ana.lima after offboard: %+v, %v; want disabled", a, err)
			}
			if tc.feature == adminapi.FeatureAccountDelete && err == nil {
				t.Errorf("ana.lima still exists after delete")
			}
		})
	}
}

// frontWithBrokenWhoAmI is a console whose accounts socket fails whoami and
// counts every other call it is sent; the operator socket and the state behind
// both are the seeded fake's.
func frontWithBrokenWhoAmI(t *testing.T) (*Front, *adminapitest.Clients, *atomic.Int32) {
	t.Helper()
	c := adminapitest.Start(t)
	var calls atomic.Int32
	dir, err := os.MkdirTemp("", "gwb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "acc.sock"))
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/whoami" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		calls.Add(1)
		c.Server.ServeHTTP(w, r)
	})}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("frontkit: %v", err)
	}
	t.Cleanup(func() { _ = kit.Close() })
	f, err := New(Options{Operator: c.Operator, Accounts: adminapi.New(ln.Addr().String(), adminapi.WithFront("ui")), Kit: kit})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, c, &calls
}

// When the accounts socket cannot be asked whether it offers offboard or
// delete, the console says so on the result page instead of a bare 404, and
// sends nothing else to the backend.
func TestAccountActions_AnUnreachableAccountsSocketIsShownNotA404(t *testing.T) {
	f, c, calls := frontWithBrokenWhoAmI(t)
	for _, tc := range []struct {
		method, path string
		form         url.Values
	}{
		{"GET", "/people/offboard?u=ana.lima", nil},
		{"POST", "/people/offboard", url.Values{"username": {"ana.lima"}, "subject": {"sub-ana"}, "reason": {"left"}}},
		{"POST", "/people/delete", url.Values{"username": {"ana.lima"}, "confirm": {"yes"}}},
	} {
		var w *httptest.ResponseRecorder
		if tc.method == "GET" {
			w = get(t, f, tc.path)
		} else {
			w = postForm(t, f, tc.path, tc.form)
		}
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "result-icon danger") ||
			!strings.Contains(body, "Nothing was done: the accounts socket could not be reached.") {
			t.Errorf("%s %s with whoami failing = %d, want the error result:\n%s", tc.method, tc.path, w.Code, body)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the accounts socket was sent %d calls besides whoami, want 0", n)
	}
	a, err := c.Accounts.GetAccount(t.Context(), "ana.lima")
	if err != nil || a.Disabled {
		t.Errorf("ana.lima after the refused actions: %+v, %v; want present and enabled", a, err)
	}
}
