package gatteweb

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// testFront builds a console wired to the seeded fake, for rendering checks.
func testFront(t *testing.T) *Front {
	t.Helper()
	f, _ := testFrontOn(t)
	return f
}

// testFrontOn is testFront that also hands back the fake, to check what the
// console asked of it.
func testFrontOn(t *testing.T) (*Front, *adminapitest.Clients) {
	t.Helper()
	c := adminapitest.Start(t)
	kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("frontkit: %v", err)
	}
	t.Cleanup(func() { _ = kit.Close() })
	f, err := New(Options{Operator: c.Operator, Accounts: c.Accounts, Kit: kit})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, c
}

// TestRolesSections_MakeNoAuditRead: both Roles sections draw roles and
// groups from GET /v1/people/roles and never call GET /v1/people, the read
// that makes the gateway read the audit trail (design/adr/0061 §3).
func TestRolesSections_MakeNoAuditRead(t *testing.T) {
	f, c := testFrontOn(t)
	r := httptest.NewRequest("GET", "/users", nil)
	panel, err := f.rolesPanelFragment(r)
	if err != nil {
		t.Fatalf("roles panel: %v", err)
	}
	view, err := f.rolesViewSection(r)
	if err != nil {
		t.Fatalf("roles view: %v", err)
	}
	for name, html := range map[string]string{"panel": string(panel), "view": string(view)} {
		for _, want := range []string{"tier1-analyst", "soc-tier1", "ir-lead", "soc-ir"} {
			if !strings.Contains(html, want) {
				t.Errorf("roles %s is missing %q", name, want)
			}
		}
	}
	if n := c.Server.PeopleReads(); n != 0 {
		t.Errorf("the Roles sections called GET /v1/people %d times; it reads the audit trail", n)
	}
}

// TestRolesPanel_ListsTheRoles renders the Roles section against the fake's
// seeded roles: one row per role, linking to its page, with its non_read
// state and groups. The edit form lives on the role page, not the list.
func TestRolesPanel_ListsTheRoles(t *testing.T) {
	f := testFront(t)
	html, err := f.rolesPanelFragment(httptest.NewRequest("GET", "/users", nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		"/users/roles/view?name=tier1-analyst", "/users/roles/view?name=ir-lead",
		"soc-tier1", "soc-ir", "non_read", ">On<", ">Off<",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered Roles section is missing %q", want)
		}
	}
	if strings.Contains(s, "/users/roles/edit") {
		t.Error("the role list carries the edit form; it belongs on the role page")
	}
}

// TestRolePage_ToolsAsCheckboxesByServer: a role's page lists every tool
// under its backend, as a checkbox, sensitive ones marked, with one form
// that grants or revokes the selection and the non_read switch.
func TestRolePage_ToolsAsCheckboxesByServer(t *testing.T) {
	f := testFront(t)
	w := httptest.NewRecorder()
	f.routes().ServeHTTP(w, httptest.NewRequest("GET", "/users/roles/view?name=ir-lead", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET the role page: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	for _, want := range []string{
		"<h2>casemgmt</h2>", `type="checkbox" name="tool" value="casemgmt.close_case"`, "Sensitive",
		"/users/roles/edit", `value="grant"`, "Grant selected", `value="revoke"`, "Revoke selected",
		"/users/roles/non-read", "Turn off",
		// The caption states the sensitive-tool path up front, before a refusal.
		"A sensitive tool is granted by ticking it and turning non_read on",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the role page is missing %q", want)
		}
	}
	w = httptest.NewRecorder()
	f.routes().ServeHTTP(w, httptest.NewRequest("GET", "/users/roles/view?name=nobody", nil))
	if !strings.Contains(w.Body.String(), "No such role") || strings.Contains(w.Body.String(), "Grant selected") {
		t.Errorf("an unknown role's page:\n%s", w.Body)
	}
}

// TestRolesPanel_SelfRegistersAtSlotTwenty checks the section is registered in
// the UsersSection registry at order 20, as the surface map assigns.
func TestRolesPanel_SelfRegistersAtSlotTwenty(t *testing.T) {
	var found *UsersSection
	for i := range usersGroups {
		if usersGroups[i].ID == "roles" {
			found = &usersGroups[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no UsersSection with ID \"roles\" is registered")
	}
	if found.Order != 20 {
		t.Errorf("roles section Order = %d, want 20", found.Order)
	}
	if found.Show == nil || found.Show(Capabilities{Manages: true, Root: false}) {
		t.Error("roles section must show only on the managing console with the accounts socket")
	}
	if !found.Show(Capabilities{Manages: true, Root: true}) {
		t.Error("roles section should show with Manages and Root")
	}
}

// TestRolesEdit_AWildcardGrantIsNoChangeAndRefusesARevoke: a tool a "*" grant
// already reaches needs no grant, and cannot be revoked one tool at a time;
// both are listed on the result page, the rest of the selection still goes.
func TestRolesEdit_AWildcardGrantIsNoChangeAndRefusesARevoke(t *testing.T) {
	f := testFront(t)
	post := func(op string, tools ...string) string {
		form := url.Values{"role": {"tier1-analyst"}, "op": {op}, "tool": tools}
		r := httptest.NewRequest("POST", "/users/roles/edit", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		f.routes().ServeHTTP(w, r)
		return w.Body.String()
	}
	got := post("grant", "logsearch.search_relative", "threatintel.lookup_ip")
	if !strings.Contains(got, "<h2>No change</h2>") || !strings.Contains(got, "logsearch.search_relative (granted by *)") ||
		!strings.Contains(got, "<h2>Granted</h2>") || strings.Contains(got, "<h2>Refused</h2>") {
		t.Errorf("a grant over a wildcard:\n%s", got)
	}
	got = post("revoke", "logsearch.search_relative")
	if !strings.Contains(got, "<h2>Refused</h2>") || !strings.Contains(got, "Nothing written.") {
		t.Errorf("a revoke under a wildcard:\n%s", got)
	}
}
