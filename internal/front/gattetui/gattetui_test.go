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

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
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
		{ids(len(u), func(i int) string { return u[i].ID }), []string{"people", "roles", "blocklist"}},
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

func TestServersListShowsHealthAndWhatNeedsReview(t *testing.T) {
	a, _ := start(t, true)
	mustShow(t, a, "MCP Servers / APIs", "threatintel", "Down", "In maintenance", "Tool waits for review", "R reload config", "V vault")
}

func TestApproveSendsTheFingerprintShownAndNoMeansNothing(t *testing.T) {
	a, c := start(t, false)
	open(a, toolPage("logsearch", "search_absolute"))
	mustShow(t, a, "sha256:logsearch-search_absolute", "a approve")

	press(a, "a", "n")
	mustShow(t, a, "Cancelled. Nothing was sent.")
	if got := toolStatus(t, c, "logsearch", "search_absolute"); got != adminapi.StatusPending {
		t.Fatalf("after answering no the tool is %q, want pending", got)
	}

	press(a, "a")
	mustShow(t, a, "at fingerprint sha256:logsearch-search_absolute?")
	press(a, "y")
	if got := toolStatus(t, c, "logsearch", "search_absolute"); got != adminapi.StatusApproved {
		t.Fatalf("after approving the tool is %q, want approved", got)
	}
	mustShow(t, a, "Approved logsearch.search_absolute.", "v revoke")
}

func TestDeregisterForwardsTheTypedNameAndTheBackendDecides(t *testing.T) {
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
		t.Errorf("after deregistering the page is %q, want the list", a.top().title)
	}
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
	mustShow(t, a, "Wrote SHODAN_KEY to the vault.", "redialled")
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
	press(a, "enter", "y")
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
	mustShow(t, a, "NOT applied yet", "Reload the configuration now to apply it?")
	press(a, "y")
	mustShow(t, a, "The reload (request 1) was applied.")
}

func TestSensitiveGrantNeedsNonReadAndWritesNothing(t *testing.T) {
	a, c := start(t, true)
	settle(a, a.switchTab(1))
	before, _ := c.Accounts.GetRoles(context.Background())
	open(a, rolePage("tier1-analyst"))
	cursorTo(t, a, "casemgmt.close_case")
	press(a, "enter", "y")
	mustShow(t, a, "Not granted: casemgmt.close_case is a sensitive tool")
	if after, _ := c.Accounts.GetRoles(context.Background()); after.Text != before.Text {
		t.Fatalf("a refused grant changed the roles file:\n%s", after.Text)
	}
}

func TestWithoutTheAccountsSocketRootActionsAreAbsent(t *testing.T) {
	a, _ := start(t, false)
	open(a, serverPage("casemgmt"))
	v := a.View()
	for _, absent := range []string{"S sign", "S re-sign", "Secrets  names only"} {
		if strings.Contains(v, absent) {
			t.Errorf("without -manage-users the detail page offers %q:\n%s", absent, v)
		}
	}
	mustShow(t, a, "D redial", "X deregister", "Maintenance")
	settle(a, a.switchTab(1))
	mustShow(t, a, "Read-only: editing needs console_manages", "sudo mcp-gateway tui -manage-users", "+ Block a subject")
}

func TestUntrustedTextCannotDriveTheTerminal(t *testing.T) {
	a, c := start(t, false)
	hostile := "evil\x1b[2J\u202eburied"
	if _, err := c.Operator.BlockSubject(context.Background(), adminapi.BlockRequest{Subject: hostile, Reason: "x\x07"}); err != nil {
		t.Fatal(err)
	}
	settle(a, a.switchTab(1))
	v := a.View()
	if strings.Contains(v, "\x1b[2J") || strings.Contains(v, "\u202e") || strings.Contains(v, "\x07") {
		t.Fatalf("a control sequence from the API reached the screen:\n%q", v)
	}
	mustShow(t, a, `evil\u{001B}[2J`, `x\u{0007}`)
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

func TestBlockThenUnblock(t *testing.T) {
	a, c := start(t, false)
	settle(a, a.switchTab(1))
	cursorTo(t, a, "+ Block a subject")
	press(a, "enter", "sub-eve", "enter", "phished", "enter", "8h", "enter", "y")
	l, _ := c.Operator.ListBlocks(context.Background())
	i := slices.IndexFunc(l.Blocks, func(b adminapi.Block) bool { return b.Subject == "sub-eve" })
	if i < 0 || l.Blocks[i].Until == nil {
		t.Fatalf("blocks after block: %+v", l.Blocks)
	}
	cursorTo(t, a, "sub-eve")
	press(a, "u", "y")
	l, _ = c.Operator.ListBlocks(context.Background())
	if slices.ContainsFunc(l.Blocks, func(b adminapi.Block) bool { return b.Subject == "sub-eve" }) {
		t.Fatal("sub-eve is still blocked after unblock")
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
	for _, want := range []string{"fake-otp-reset-ana.lima", "Reload the configuration now", "no backend \"no-such-backend\"", "**************"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the gallery lacks %q", want)
		}
	}
	if strings.Contains(b.String(), "not-a-real-key") {
		t.Error("the gallery drew a secret value typed into the hidden prompt")
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
