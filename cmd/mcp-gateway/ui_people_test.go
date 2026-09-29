package main

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
)

const peopleUsersFixture = `users:
  ana:
    displayname: "Ana"
    PWKEY: "LAB_HASH"
    email: ana@example.org
    groups: [blue-ir]
`

// newPeopleTest is a logged-in console whose configuration has two roles,
// with -manage-users switched on over a temporary Authelia users file when
// manage is true.
func newPeopleTest(t *testing.T, manage bool) (opTestEnv, *uiServer, *http.Cookie, string) {
	t.Helper()
	e, s, cookie := newUITest(t)
	e.cfg.Roles = []config.Role{
		{Name: "ir-lead", Tools: []string{"casemgmt.create_case"}},
		{Name: "tier1-analyst", Grants: map[string][]string{"logsearch": {"search_relative"}}},
	}
	e.cfg.GroupToRole = map[string]string{"blue-ir": "ir-lead", "blue-tier1": "tier1-analyst"}
	path := filepath.Join(t.TempDir(), "users_database.yml")
	hash, err := idp.HashPassword("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.NewReplacer("LAB_HASH", hash, "PWKEY", "pass"+"word").Replace(peopleUsersFixture)), 0o600); err != nil {
		t.Fatal(err)
	}
	if manage {
		s.enableAccounts(autheliafile.New(path))
	}
	return e, s, cookie, path
}

func samePost(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8090") }

func TestUI_PeopleShowsRolesTheirGroupsAndWhoWasSeen(t *testing.T) {
	e, s, cookie, _ := newPeopleTest(t, false)
	for _, rec := range []audit.Record{
		{AnalystIdentity: "95f757fe-0c7b-4272", Tool: "logsearch.search_relative", TargetUpstream: "logsearch", Outcome: audit.OutcomeAllowed},
		{AnalystIdentity: "(gateway)", Tool: "x.y", TargetUpstream: "x", Outcome: audit.OutcomeDenied, Reason: "first seen"},
	} {
		rec.Timestamp = time.Now().UTC()
		if err := e.auditTrail().Record(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	body := uiDo(s, "GET", "/people", nil, cookie, nil).Body.String()
	for _, want := range []string{"ir-lead", "blue-ir", "tier1-analyst", "logsearch.search_relative", "casemgmt.create_case", "95f757fe-0c7b-4272", "sudo mcp-gateway ui -manage-users"} {
		if !strings.Contains(body, want) {
			t.Errorf("People page lacks %q", want)
		}
	}
	if strings.Contains(body, "(gateway)") {
		t.Error("the gateway's own rows are listed as a person")
	}
}

func TestUI_AccountEditingDoesNotExistWithoutManageUsers(t *testing.T) {
	_, s, cookie, path := newPeopleTest(t, false)
	before, _ := os.ReadFile(path)
	for _, target := range []string{"/people/add", "/people/groups", "/people/disable", "/people/enable", "/people/reset"} {
		w := uiDo(s, "POST", target, url.Values{"username": {"ana"}, "displayname": {"X"}, "group": {"blue-ir"}, "csrf": {s.csrf}}, cookie, samePost)
		if w.Code != http.StatusNotFound {
			t.Errorf("POST %s without -manage-users: %d, want 404", target, w.Code)
		}
	}
	if w := uiDo(s, "GET", "/people/account?u=ana", nil, cookie, nil); w.Code != http.StatusNotFound {
		t.Errorf("GET /people/account without -manage-users: %d, want 404", w.Code)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("the users file changed without -manage-users")
	}
}

func TestUI_AddingAPersonWritesTheIdPShowsThePasswordOnceAndAuditsWithoutIt(t *testing.T) {
	e, s, cookie, path := newPeopleTest(t, true)
	w := uiDo(s, "POST", "/people/add", url.Values{
		"username": {"carla"}, "displayname": {"Carla Lima"}, "email": {"carla@example.org"},
		"group": {"blue-tier1"}, "csrf": {s.csrf},
	}, cookie, samePost)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "result-icon ok") {
		t.Fatalf("POST /people/add: %d\n%s", w.Code, body)
	}
	i := strings.Index(body, `class="secret-value">`)
	if i < 0 {
		t.Fatal("the result page shows no one-time password")
	}
	pw := body[i+len(`class="secret-value">`):]
	pw = pw[:strings.Index(pw, "<")]
	if len(pw) < 20 {
		t.Fatalf("one-time password %q is too short", pw)
	}
	file, _ := os.ReadFile(path)
	if !strings.Contains(string(file), "carla:") || !strings.Contains(string(file), "$argon2id$") || strings.Contains(string(file), pw) {
		t.Fatalf("users file after add:\n%s", file)
	}
	recs, _ := e.auditTrail().List(context.Background())
	var found bool
	for _, r := range recs {
		if strings.Contains(r.Reason, pw) || strings.Contains(r.Tool, pw) {
			t.Fatal("the one-time password reached the audit trail")
		}
		if r.Tool == accountAddTool && r.AnalystIdentity == "(operator:ana.ops)" && strings.Contains(r.Reason, `"carla"`) && strings.Contains(r.Reason, "blue-tier1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no (account add) operator row for carla: %+v", recs)
	}
}

func TestUI_AGroupThatMapsToNoRoleIsNeverAssigned(t *testing.T) {
	_, s, cookie, path := newPeopleTest(t, true)
	before, _ := os.ReadFile(path)
	for target, form := range map[string]url.Values{
		"/people/add":    {"username": {"dave"}, "displayname": {"Dave"}, "group": {"admins"}, "csrf": {s.csrf}},
		"/people/groups": {"username": {"ana"}, "group": {"blue-ir", "admins"}, "csrf": {s.csrf}},
	} {
		w := uiDo(s, "POST", target, form, cookie, samePost)
		if !strings.Contains(w.Body.String(), "maps to no role") {
			t.Errorf("POST %s with an unmapped group was not refused:\n%s", target, w.Body)
		}
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("an unmapped group changed the users file")
	}
}

func TestUI_GroupsDisableEnableAndResetChangeTheAccount(t *testing.T) {
	_, s, cookie, path := newPeopleTest(t, true)
	dir := autheliafile.New(path)
	uiDo(s, "POST", "/people/groups", url.Values{"username": {"ana"}, "group": {"blue-ir", "blue-tier1"}, "csrf": {s.csrf}}, cookie, samePost)
	uiDo(s, "POST", "/people/disable", url.Values{"username": {"ana"}, "csrf": {s.csrf}}, cookie, samePost)
	accts, _ := dir.Accounts()
	if strings.Join(accts[0].Groups, ",") != "blue-ir,blue-tier1" || !accts[0].Disabled {
		t.Fatalf("ana after groups+disable = %+v", accts[0])
	}
	uiDo(s, "POST", "/people/enable", url.Values{"username": {"ana"}, "csrf": {s.csrf}}, cookie, samePost)
	before, _ := os.ReadFile(path)
	w := uiDo(s, "POST", "/people/reset", url.Values{"username": {"ana"}, "csrf": {s.csrf}}, cookie, samePost)
	if !strings.Contains(w.Body.String(), `class="secret-value"`) {
		t.Fatal("reset shows no one-time password")
	}
	after, _ := os.ReadFile(path)
	if bytes.Equal(before, after) {
		t.Fatal("reset did not change the stored hash")
	}
	if accts, _ = dir.Accounts(); accts[0].Disabled {
		t.Fatal("enable left ana disabled")
	}
	if w := uiDo(s, "GET", "/people/account?u=ana", nil, cookie, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Reset password") {
		t.Fatalf("account page: %d", w.Code)
	}
}

func TestUI_ManageUsersRefusesAConsoleThatIsNotRoot(t *testing.T) {
	orig := uiGeteuid
	uiGeteuid = func() int { return 1000 }
	t.Cleanup(func() { uiGeteuid = orig })
	e, s, _, path := newPeopleTest(t, false)
	e.cfg.IdP.UsersFile = path
	var stderr bytes.Buffer
	if _, ok := uiEnableManage(s, e.opEnv, &stderr); ok || s.accounts != nil {
		t.Fatal("-manage-users was enabled in a process that is not root")
	}
	if !strings.Contains(stderr.String(), "runs only as root") {
		t.Fatalf("refusal does not say why: %s", stderr.String())
	}
}

func TestUI_PeopleAndAuditShowTheNameNextToTheSubject(t *testing.T) {
	e, s, cookie, _ := newPeopleTest(t, false)
	rec := audit.Record{AnalystIdentity: "95f757fe-0c7b-4272", AnalystName: "Ana Souza", Tool: "logsearch.search_relative",
		TargetUpstream: "logsearch", Outcome: audit.OutcomeAllowed, Timestamp: time.Now().UTC()}
	if err := e.auditTrail().Record(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"/people", "/audit"} {
		body := uiDo(s, "GET", page, nil, cookie, nil).Body.String()
		if !strings.Contains(body, "Ana Souza") || !strings.Contains(body, "95f757fe-0c7b-4272") {
			t.Errorf("GET %s does not show the name next to the subject", page)
		}
	}
}
