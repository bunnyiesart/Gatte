package gattetui

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// start runs the fake and returns the front's model on it, with the
// accounts socket when root is set, already past its first read.
func start(t *testing.T, root bool) (*app, *adminapitest.Clients) {
	t.Helper()
	c := adminapitest.Start(t)
	o := Options{Operator: adminapi.New(c.Socket, adminapi.WithFront(FrontName))}
	if root {
		o.Accounts = adminapi.New(c.Socket, adminapi.WithFront(FrontName))
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	a := m.(*app)
	a.width, a.height = 140, 300
	settle(a, a.Init())
	return a, c
}

func press(a *app, keys ...string) {
	for _, k := range keys {
		settle(a, func() tea.Msg { return keyMsg(k) })
	}
}

func open(a *app, p *page) { settle(a, push(p)) }

// cursorTo moves the cursor down to the first selectable row containing s.
func cursorTo(t *testing.T, a *app, s string) {
	t.Helper()
	p := a.top()
	for i := range p.rows {
		if p.selectable(i) && strings.Contains(p.rows[i].text, s) {
			p.cursor = i
			return
		}
	}
	t.Fatalf("no selectable row with %q in:\n%s", s, a.View())
}

func mustShow(t *testing.T, a *app, want ...string) {
	t.Helper()
	v := a.View()
	for _, w := range want {
		if !strings.Contains(v, w) {
			t.Errorf("the screen does not show %q:\n%s", w, v)
		}
	}
}

func toolStatus(t *testing.T, c *adminapitest.Clients, server, tool string) string {
	t.Helper()
	l, err := c.Operator.ListTools(context.Background(), server, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range l.Tools {
		if x.Tool == tool {
			return x.Status
		}
	}
	return ""
}

func TestRegistriesHoldTheTwoTabsAndTheirParts(t *testing.T) {
	ids := func(n int, id func(int) string) []string {
		var out []string
		for i := range n {
			out = append(out, id(i))
		}
		return out
	}
	s, d, u := orderedScreens(), orderedDetailPanels(), orderedUsersSections()
	for _, c := range []struct {
		got, want []string
	}{
		{ids(len(s), func(i int) string { return s[i].ID }), []string{"servers", "users"}},
		{ids(len(d), func(i int) string { return d[i].ID }), []string{"tools", "secrets", "maintenance"}},
		{ids(len(u), func(i int) string { return u[i].ID }), []string{"people", "roles"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("registry order %v, want %v", c.got, c.want)
		}
	}
}

func TestEveryCallCarriesTheTUIFrontTag(t *testing.T) {
	a, _ := start(t, true)
	if a.env.me.Front != FrontName {
		t.Fatalf("the backend saw front %q, want %q", a.env.me.Front, FrontName)
	}
}

func mustNotShow(t *testing.T, a *app, absent ...string) {
	t.Helper()
	v := a.View()
	for _, s := range absent {
		if strings.Contains(v, s) {
			t.Errorf("the screen shows %q:\n%s", s, v)
		}
	}
}

func TestServersListShowsHealthAndConfigApprovalButNoReviewMarker(t *testing.T) {
	a, _ := start(t, true)
	mustShow(t, a, "MCP Servers / APIs", "threatintel", "Down", "In maintenance", "CONFIG", "Config approved", "[ R Reload config ]", "[ V Vault ]")
	// Pending tools are shown in each backend's tools panel, not on the list.
	mustNotShow(t, a, "NEEDS REVIEW", "Tool waits for review", "Tool definition changed")
}

// TestServersListFlagsOnlyAChangedTool: a backend with a tool changed since
// approval is flagged on the list; one with pending tools only is not.
func TestServersListFlagsOnlyAChangedTool(t *testing.T) {
	a, _ := start(t, false)
	row := func(name string) string {
		for _, r := range a.top().rows {
			if strings.HasPrefix(r.text, name+" ") {
				return r.text
			}
		}
		t.Fatalf("no row for %s:\n%s", name, a.View())
		return ""
	}
	if !strings.Contains(row("docsearch"), "tool changed since approved") {
		t.Errorf("docsearch has a changed tool and is not flagged: %q", row("docsearch"))
	}
	for _, pendingOnly := range []string{"logsearch", "threatintel", "casemgmt"} {
		if strings.Contains(row(pendingOnly), "changed") {
			t.Errorf("%s has no changed tool and is flagged: %q", pendingOnly, row(pendingOnly))
		}
	}
}

func TestConfigTextUsesTheApprovalWords(t *testing.T) {
	for sig, want := range map[string]string{"yes": "Config approved", "INVALID": "Changed since approved", "no": "Config not approved", "": "Config not approved"} {
		if got := configText(sig); got != want {
			t.Errorf("configText(%q) = %q, want %q", sig, got, want)
		}
	}
}

func TestApproveSendsTheFingerprintShownAndNoMeansNothing(t *testing.T) {
	a, c := start(t, false)
	open(a, toolPage("logsearch", "search_absolute"))
	mustShow(t, a, "sha256:logsearch-search_absolute", "[ enter Actions ]")

	press(a, "enter")
	mustShow(t, a, "a  Approve tool")
	press(a, "a", "n")
	mustShow(t, a, "Cancelled. Nothing was sent.")
	if got := toolStatus(t, c, "logsearch", "search_absolute"); got != adminapi.StatusPending {
		t.Fatalf("after answering no the tool is %q, want pending", got)
	}

	press(a, "enter", "a")
	mustShow(t, a, "Approve tool logsearch.search_absolute at fingerprint sha256:logsearch-search_absolute?")
	press(a, "y")
	if got := toolStatus(t, c, "logsearch", "search_absolute"); got != adminapi.StatusApproved {
		t.Fatalf("after approving the tool is %q, want approved", got)
	}
	mustShow(t, a, "Approved logsearch.search_absolute.")
	press(a, "enter")
	mustShow(t, a, "v  Revoke")
	mustNotShow(t, a, "Approve tool")
}

// TestToolMenuFromThePanel: a tool's actions open as one menu on its row;
// approving is not in it (the definition is not on screen), and esc closes
// it without sending anything.
func TestToolMenuFromThePanel(t *testing.T) {
	a, c := start(t, false)
	open(a, serverPage("casemgmt"))
	cursorTo(t, a, "get_case")
	press(a, "enter")
	mustShow(t, a, "casemgmt.get_case", "r  Review", "v  Revoke", "[ esc Cancel ]")
	mustNotShow(t, a, "Approve tool")

	press(a, "esc")
	if a.menu != nil {
		t.Fatal("esc left the menu open")
	}
	if got := toolStatus(t, c, "casemgmt", "get_case"); got != adminapi.StatusApproved {
		t.Fatalf("closing the menu changed the tool: %q", got)
	}

	press(a, "enter", "down", "enter")
	mustShow(t, a, "Revoke casemgmt.get_case?")
	press(a, "y")
	if got := toolStatus(t, c, "casemgmt", "get_case"); got != adminapi.StatusPending {
		t.Fatalf("after revoking from the menu the tool is %q, want pending", got)
	}

	cursorTo(t, a, "get_case")
	press(a, "enter", "r")
	if got := a.top().title; got != "get_case" {
		t.Fatalf("Review opened %q, want the tool's review page", got)
	}
}

// TestReviewPageMenuWithoutADefinitionOffersNoApproval: a review page that
// could not draw the definition offers neither approval nor a review of
// itself.
func TestReviewPageMenuWithoutADefinitionOffersNoApproval(t *testing.T) {
	a, _ := start(t, false)
	pending := adminapi.Tool{Server: "logsearch", Tool: "x", Status: adminapi.StatusPending, ObservedHash: "sha256:x"}
	if items := toolActions(a.env, pending, true, false); len(items) != 0 {
		t.Fatalf("a review page without the definition offers %+v", items)
	}
	if items := toolActions(a.env, pending, true, true); len(items) != 1 || items[0].label != "Approve tool" {
		t.Fatalf("a review page with the definition offers %+v, want Approve tool", items)
	}
}

func TestHeaderStaysOneLineOnANarrowTerminal(t *testing.T) {
	a, _ := start(t, true)
	a.width = 30
	if h := a.header(); strings.Contains(h, "\n") || lipgloss.Width(h) != 30 {
		t.Fatalf("the header is %d wide or wraps: %q", lipgloss.Width(h), h)
	}
}

func TestRemoveForwardsTheTypedNameAndTheBackendDecides(t *testing.T) {
	a, c := start(t, false)
	open(a, serverPage("casemgmt"))
	press(a, "X", "casemgm", "enter")
	mustShow(t, a, "Refused: confirm must repeat the name")
	if l, _ := c.Operator.ListUpstreams(context.Background()); len(l.Upstreams) != 4 {
		t.Fatalf("a wrong name removed a backend: %d left", len(l.Upstreams))
	}

	press(a, "X", "casemgmt", "enter")
	l, _ := c.Operator.ListUpstreams(context.Background())
	if slices.ContainsFunc(l.Upstreams, func(u adminapi.Upstream) bool { return u.Name == "casemgmt" }) {
		t.Fatal("casemgmt is still registered after the name was typed")
	}
	if a.top().title != "MCP Servers / APIs" {
		t.Errorf("after removing the page is %q, want the list", a.top().title)
	}
	mustShow(t, a, "Removed casemgmt.")
}

func TestSecretValueIsNeverDrawn(t *testing.T) {
	a, c := start(t, true)
	open(a, serverPage("threatintel"))
	cursorTo(t, a, "SHODAN_KEY")
	const value = "s3cr3t-value-123"
	press(a, "s", value)
	if v := a.View(); strings.Contains(v, value) || !strings.Contains(v, strings.Repeat("*", len(value))) {
		t.Fatalf("the hidden prompt draws the value, or no mask:\n%s", v)
	}
	press(a, "enter")
	if v := a.View(); strings.Contains(v, value) {
		t.Fatalf("the value is on screen after it was sent:\n%s", v)
	}
	mustShow(t, a, "Wrote SHODAN_KEY to the vault.", "until it reconnects")
	list, _ := c.Accounts.ListSecrets(context.Background())
	if i := slices.IndexFunc(list.Secrets, func(s adminapi.Secret) bool { return s.Name == "SHODAN_KEY" }); i < 0 || !list.Secrets[i].InVault {
		t.Fatal("SHODAN_KEY is not in the vault after it was set")
	}
}

func TestOneTimePasswordIsShownOnceThenWiped(t *testing.T) {
	a, _ := start(t, true)
	settle(a, a.switchTab(1))
	open(a, accountPage("ana.lima"))
	press(a, "p", "y")
	mustShow(t, a, "fake-otp-reset-ana.lima", "Shown once")
	press(a, "j")
	if v := a.View(); strings.Contains(v, "fake-otp") {
		t.Fatalf("the one-time password is still on screen after a key:\n%s", v)
	}
	if a.result != nil {
		t.Fatal("the result holding the password was kept")
	}
}

func TestAddAPersonChecksThenCreates(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	cursorTo(t, a, "+ Add a person")
	press(a, "enter", "Carla Dias", "enter", "carla.dias", "enter", "enter")
	mustShow(t, a, "Groups for carla.dias")
	press(a, "soc-tier1", "enter", "y")
	mustShow(t, a, "Added carla.dias.", "One-time password for carla.dias")
	acct, err := c.Accounts.GetAccount(context.Background(), "carla.dias")
	if err != nil || !slices.Equal(acct.Groups, []string{"soc-tier1"}) {
		t.Fatalf("account after add: %+v, %v", acct, err)
	}
}

func TestRoleWriteIsSurgicalThenAsksToReload(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	before, _ := c.Accounts.GetRoles(context.Background())
	open(a, rolePage("tier1-analyst"))
	cursorTo(t, a, "casemgmt.get_case")
	press(a, "v", "y")
	after, _ := c.Accounts.GetRoles(context.Background())
	if strings.Contains(after.Text, `"get_case"`) {
		t.Fatalf("get_case is still granted:\n%s", after.Text)
	}
	for _, keep := range []string{"# SOC roles. Keep the approver note", "# triage; read-only. reviewed 2026-10 by alice.ops", "# all read-only log search"} {
		if !strings.Contains(after.Text, keep) {
			t.Errorf("the write lost %q (the file must never be regenerated):\n%s", keep, after.Text)
		}
	}
	if before.Text == after.Text {
		t.Fatal("nothing was written")
	}
	mustShow(t, a, "Revoked 1 for tier1-analyst.", "NOT applied yet", "Reload the configuration now to apply it?")
	press(a, "y")
	mustShow(t, a, "The reload (request 1) was applied.")
}

func TestSensitiveGrantNeedsNonReadAndWritesNothing(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	before, _ := c.Accounts.GetRoles(context.Background())
	open(a, rolePage("tier1-analyst"))
	cursorTo(t, a, "casemgmt.close_case")
	press(a, "g", "y")
	mustShow(t, a, "Not granted: casemgmt.close_case is sensitive; select it, then n to turn non_read on with it.")
	mustShow(t, a, "Refused 1 for tier1-analyst.")
	mustNotShow(t, a, "Granted", "already set")
	if after, _ := c.Accounts.GetRoles(context.Background()); after.Text != before.Text {
		t.Fatalf("a refused grant changed the roles file:\n%s", after.Text)
	}
}

// TestRoleGrantsTheSelectedToolsInOneWrite: the safe tools are granted on
// one copy of the file, the sensitive one is refused, and non_read is left
// alone.
func TestRoleGrantsTheSelectedToolsInOneWrite(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	open(a, rolePage("tier1-analyst"))
	cursorTo(t, a, "docsearch.find_document")
	press(a, "space")
	cursorTo(t, a, "threatintel.lookup_ip")
	press(a, "space")
	cursorTo(t, a, "casemgmt.close_case")
	press(a, "space")
	mustShow(t, a, "[x] casemgmt.close_case", "[x] docsearch.find_document", "[ ] casemgmt.get_case")
	before, _ := c.Accounts.GetRoles(context.Background())
	press(a, "g")
	mustShow(t, a, "Grant 3 tool(s) for tier1-analyst?")
	press(a, "y")
	mustShow(t, a, "Granted 2, refused 1 for tier1-analyst.",
		"Granted: docsearch.find_document, threatintel.lookup_ip", "Not granted: casemgmt.close_case is sensitive")
	want, _ := frontkit.GrantSafeTool(before.Text, "tier1-analyst", "docsearch", "find_document")
	want, _ = frontkit.GrantSafeTool(want, "tier1-analyst", "threatintel", "lookup_ip")
	if after, _ := c.Accounts.GetRoles(context.Background()); after.Text != want {
		t.Fatalf("roles file after the grant:\n%s\nwant:\n%s", after.Text, want)
	}
	mustShow(t, a, "Reload the configuration now to apply it?")
	press(a, "n")
	mustNotShow(t, a, "[x]")
}

// TestRoleGrantCountsANoOpApartFromARefusal: a tool already granted is
// "already set", not refused, and nothing is written.
func TestRoleGrantCountsANoOpApartFromARefusal(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	before, _ := c.Accounts.GetRoles(context.Background())
	open(a, rolePage("tier1-analyst"))
	cursorTo(t, a, "casemgmt.get_case")
	press(a, "space")
	cursorTo(t, a, "casemgmt.close_case")
	press(a, "space", "g", "y")
	mustShow(t, a, "Already set 1, refused 1 for tier1-analyst.", "Already granted: casemgmt.get_case")
	if after, _ := c.Accounts.GetRoles(context.Background()); after.Text != before.Text {
		t.Fatalf("a grant with nothing to change wrote the roles file:\n%s", after.Text)
	}
}

// TestNonReadGoesOnWithTheSelectedSensitiveTools: the backend refuses
// non_read on a role with no tools, so it goes on with the selected
// sensitive tools in one write, and without one it is refused locally.
func TestNonReadGoesOnWithTheSelectedSensitiveTools(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	before, _ := c.Accounts.GetRoles(context.Background())
	open(a, rolePage("tier1-analyst"))
	press(a, "n")
	mustShow(t, a, "non_read needs at least one sensitive tool: select it, then n.")
	if after, _ := c.Accounts.GetRoles(context.Background()); after.Text != before.Text {
		t.Fatalf("a refused non_read changed the roles file:\n%s", after.Text)
	}
	cursorTo(t, a, "casemgmt.close_case")
	press(a, "space")
	cursorTo(t, a, "docsearch.find_document")
	press(a, "space", "n")
	mustShow(t, a, "Turn non_read on for tier1-analyst and give it: casemgmt.close_case?")
	press(a, "y")
	mustShow(t, a, "non_read is on for tier1-analyst; gave it casemgmt.close_case.")
	after, _ := c.Accounts.GetRoles(context.Background())
	roles, _, _ := strings.Cut(after.Text, "[[preset]]") // presets may name any tool
	if !strings.Contains(roles, "non_read = true") || !strings.Contains(roles, `"casemgmt.close_case"`) || strings.Contains(roles, "find_document") {
		t.Fatalf("roles file after non_read on:\n%s", after.Text)
	}
	press(a, "n") // no reload
	mustShow(t, a, "[ n Turn non_read off ]")
	mustNotShow(t, a, "[x]")
	press(a, "n", "y")
	mustShow(t, a, "non_read is off for tier1-analyst.")
}

// TestSelectionSurvivesACancelAndARefusal: only a write empties it.
func TestSelectionSurvivesACancelAndARefusal(t *testing.T) {
	a, _ := start(t, true)
	settle(a, a.switchTab(1))
	open(a, rolePage("tier1-analyst"))
	cursorTo(t, a, "casemgmt.close_case")
	press(a, "space", "g", "n")
	mustShow(t, a, "Cancelled.", "[x] casemgmt.close_case")
	press(a, "g", "y")
	mustShow(t, a, "Refused 1 for tier1-analyst.", "[x] casemgmt.close_case")
}

func TestHelpOpensOnQuestionMarkAndEscCloses(t *testing.T) {
	a, _ := start(t, true)
	open(a, serverPage("casemgmt"))
	press(a, "?")
	mustShow(t, a, "mcp-gateway reload", "Config approved", "non_read", "docs/how-to/change-roles-and-quota.md")
	press(a, "?")
	if n := len(a.stacks[a.active]); n != 3 {
		t.Fatalf("? on the help screen stacked another: %d pages", n)
	}
	press(a, "esc")
	mustNotShow(t, a, "docs/command-guide.md")
	if a.top().help {
		t.Fatal("esc did not close the help screen")
	}
}

func TestWithoutTheAccountsSocketRootActionsAreAbsent(t *testing.T) {
	a, _ := start(t, false)
	open(a, serverPage("casemgmt"))
	mustNotShow(t, a, "Approve configuration", "Secrets  names only")
	mustShow(t, a, "[ C Reconnect ]", "[ X Remove ]", "Maintenance")
	settle(a, a.switchTab(1))
	mustShow(t, a, "Read-only: editing needs console_manages", "sudo mcp-gateway tui -manage-users")
}

// TestUsersShowsOnlyPeopleAndRoles: no blocklist and no view of the audit
// trail on the Users tab (design/adr/0061 §3, §4), even when the gateway
// has seen and blocked subjects.
func TestUsersShowsOnlyPeopleAndRoles(t *testing.T) {
	for _, root := range []bool{true, false} {
		a, c := start(t, root)
		if _, err := c.Operator.BlockSubject(context.Background(), adminapi.BlockRequest{Subject: "sub-eve", Reason: "phished"}); err != nil {
			t.Fatal(err)
		}
		settle(a, a.switchTab(1))
		mustShow(t, a, "People", "Roles")
		mustNotShow(t, a, "Blocklist", "Block", "block", "sub-eve", "Seen by the gateway", "calls, last")
		mustShow(t, a, "tier1-analyst", "soc-tier1", "ir-lead", "soc-ir")
		if n := c.Server.PeopleReads(); n != 0 {
			t.Errorf("root=%v: the Users tab called GET /v1/people %d times; it reads the audit trail", root, n)
		}
	}
}

func TestUntrustedTextCannotDriveTheTerminal(t *testing.T) {
	a, c := start(t, false)
	hostile := "evil\x1b[2J\u202eburied\x07"
	if _, err := c.Operator.StartMaintenance(context.Background(), adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: "casemgmt", Message: hostile}); err != nil {
		t.Fatal(err)
	}
	open(a, serverPage("casemgmt"))
	v := a.View()
	if strings.Contains(v, "\x1b[2J") || strings.Contains(v, "\u202e") || strings.Contains(v, "\x07") {
		t.Fatalf("a control sequence from the API reached the screen:\n%q", v)
	}
	mustShow(t, a, `evil\u{001B}[2J`, `buried\u{0007}`)
}

func TestMaintenanceStartsAndEnds(t *testing.T) {
	a, c := start(t, false)
	open(a, serverPage("casemgmt"))
	cursorTo(t, a, "Not in maintenance")
	press(a, "m", "patching", "enter", "2h", "enter")
	l, _ := c.Operator.ListMaintenance(context.Background())
	i := slices.IndexFunc(l.Upstreams, func(u adminapi.UpstreamMaintenance) bool { return u.Upstream == "casemgmt" })
	if i < 0 || l.Upstreams[i].Message != "patching" || l.Upstreams[i].Until == nil {
		t.Fatalf("maintenance after start: %+v", l.Upstreams)
	}
	cursorTo(t, a, "In maintenance")
	press(a, "e", "y")
	l, _ = c.Operator.ListMaintenance(context.Background())
	if slices.ContainsFunc(l.Upstreams, func(u adminapi.UpstreamMaintenance) bool { return u.Upstream == "casemgmt" }) {
		t.Fatal("casemgmt is still in maintenance after it was ended")
	}
}

func TestUntilOf(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"2h", "2026-11-10T14:00:00Z", true},
		{"2026-11-11T08:30", "2026-11-11T08:30:00Z", true},
		{"2026-11-11 08:30", "2026-11-11T08:30:00Z", true},
		{"tomorrow", "", false},
		{"-2h", "", false},
	} {
		got, ok := untilOf(c.in, now)
		s := ""
		if got != nil {
			s = got.Format(time.RFC3339)
		}
		if ok != c.ok || s != c.want {
			t.Errorf("untilOf(%q) = %q, %t; want %q, %t", c.in, s, ok, c.want, c.ok)
		}
	}
}

func TestGalleryDrawsEveryState(t *testing.T) {
	c := adminapitest.Start(t)
	var b bytes.Buffer
	o := Options{Operator: adminapi.New(c.Socket, adminapi.WithFront(FrontName)), Accounts: adminapi.New(c.Socket, adminapi.WithFront(FrontName))}
	if err := Gallery(&b, o); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(b.String(), "\n==== "); n < 20 {
		t.Fatalf("the gallery drew %d states:\n%s", n, b.String())
	}
	for _, want := range []string{"fake-otp-reset-ana.lima", "Reload the configuration now", "[x] casemgmt.get_case", "mcp-gateway tui", "docs/command-guide.md", "no backend \"no-such-backend\"", "**************", "tool changed since approved",
		"What kind of backend?", "Not kept:", "Not registered: image", "Registered vendor", "need podman on the gateway's host"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the gallery lacks %q", want)
		}
	}
	if strings.Contains(b.String(), "not-a-real-key") {
		t.Error("the gallery drew a secret value typed into the hidden prompt")
	}
	// The old labels and the removed views are gone from every screen
	// (design/adr/0061 §2-§4).
	for _, old := range []string{"Redial", "redial", "Deregister", "deregister", "Signed", "Not signed", "Signature invalid",
		"ttest", "Tool safety", "Blocklist", "Seen by", "NEEDS REVIEW", "Tool waits for review"} {
		if strings.Contains(b.String(), old) {
			t.Errorf("the gallery still shows %q", old)
		}
	}
}

// slowReader hands over its keys after a pause, so the program draws its
// first frame before it reads them.
type slowReader struct {
	keys string
	done bool
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.done {
		select {} // a terminal that stays open
	}
	time.Sleep(300 * time.Millisecond)
	r.done = true
	return copy(p, r.keys), nil
}

// TestProgramRunsAndQuits runs the real Bubble Tea loop, not the test
// driver: it starts on the fake, draws, and quits on q.
func TestProgramRunsAndQuits(t *testing.T) {
	c := adminapitest.Start(t)
	m, err := New(Options{Operator: adminapi.New(c.Socket, adminapi.WithFront(FrontName))})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(&slowReader{keys: "q"}), tea.WithOutput(&out), tea.WithoutSignalHandler())
	if _, err := p.Run(); err != nil {
		t.Fatalf("the program did not quit on q: %v", err)
	}
	if !strings.Contains(out.String(), "MCP Servers / APIs") {
		t.Fatalf("the program drew no screen:\n%q", out.String())
	}
}

var _ io.Reader = (*slowReader)(nil)

func TestAnOlderReadDoesNotOverwriteANewerOne(t *testing.T) {
	a, _ := start(t, false)
	p := a.top()
	a.Update(loadedMsg{id: p.id, seq: p.seq - 1, c: content{rows: []row{textRow("stale rows")}}})
	if v := a.View(); strings.Contains(v, "stale rows") {
		t.Fatalf("an older read was drawn over the newer one:\n%s", v)
	}
}

func TestBackLeavesThePageTheActionStartedFrom(t *testing.T) {
	a, _ := start(t, true)
	open(a, serverPage("casemgmt"))
	a.origin = a.top().id
	settle(a, a.switchTab(1))
	open(a, accountPage("ana.lima"))
	settle(a, func() tea.Msg { return resultMsg{result{ok: true, summary: "done", back: true}} })
	if got := a.top().title; got != "ana.lima" {
		t.Errorf("the Users tab lost its page: top is %q", got)
	}
	if got := a.stacks[0][len(a.stacks[0])-1].title; got != "MCP Servers / APIs" {
		t.Errorf("the Servers tab still shows %q, want the list", got)
	}
}

func TestOneTimePasswordIsWipedEvenUnderAPrompt(t *testing.T) {
	a, _ := start(t, true)
	next := confirm("Next?", func() tea.Cmd { return nil })
	settle(a, func() tea.Msg {
		return resultMsg{result{ok: true, summary: "done", secret: "otp-123", label: "pw", next: next}}
	})
	mustShow(t, a, "otp-123", "Next?")
	press(a, "x")
	if v := a.View(); strings.Contains(v, "otp-123") {
		t.Fatalf("the password stayed on screen under a prompt:\n%s", v)
	}
}
