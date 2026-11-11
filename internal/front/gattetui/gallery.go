package gattetui

import (
	"fmt"
	"io"
	"slices"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Gallery draws every screen and state of the front, one after another, as
// plain text: for reviewing the whole surface at once against the mock API
// (make preview-tui ARGS=-gallery). It drives the same model the program
// runs, with each API call made synchronously.
//
// It performs the actions it shows (a reconnect, a password reset, a
// register),
// so point it only at the in-memory fake.
func Gallery(w io.Writer, o Options) error {
	if o.Operator == nil {
		return fmt.Errorf("gattetui: an operator client is required")
	}
	readOnly := Options{Operator: o.Operator}
	shots := []struct {
		name  string
		o     Options
		users bool // on the Users tab
		page  func() *page
		keys  []string
	}{
		{"Servers: list with health, config approval and changed tools", o, false, nil, nil},
		{"Server detail: up, with tools, secrets and maintenance", o, false, func() *page { return serverPage("casemgmt") }, nil},
		{"Server detail: down, with a secret missing from the vault", o, false, func() *page { return serverPage("threatintel") }, nil},
		{"Server detail: in maintenance", o, false, func() *page { return serverPage("docsearch") }, nil},
		{"Tools panel: one tool's actions in a menu", o, false, func() *page { return serverPage("casemgmt") }, []string{"enter"}},
		{"Tool review: sensitive, approved and not cleared", o, false, func() *page { return toolPage("casemgmt", "create_case") }, nil},
		{"Tool review: its actions in a menu", o, false, func() *page { return toolPage("casemgmt", "create_case") }, []string{"enter"}},
		{"Tool review: changed since approval, with its diff", o, false, func() *page { return toolPage("docsearch", "find_document") }, nil},
		{"Tool review: approving asks about the fingerprint shown", o, false, func() *page { return toolPage("logsearch", "search_absolute") }, []string{"enter", "a"}},
		{"Review set: every waiting tool of one backend", o, false, func() *page { return reviewSetPage("logsearch") }, nil},
		{"Approve configuration: what it approves", o, false, func() *page { return serverPage("threatintel") }, []string{"A"}},
		{"Remove: the name must be typed again", o, false, func() *page { return serverPage("casemgmt") }, []string{"X", "casemgmt"}},
		{"Reconnect: the gateway's answer", o, false, func() *page { return serverPage("logsearch") }, []string{"C", "y"}},
		{"Secret value: typed hidden", o, false, func() *page { return serverPage("threatintel") }, []string{"down", "down", "s", "not-a-real-key"}},
		{"Vault: every name, never a value", o, false, vaultPage, nil},
		{"Users: people and roles", o, true, nil, nil},
		{"Account", o, true, func() *page { return accountPage("ana.lima") }, nil},
		{"Account: a one-time password, shown once", o, true, func() *page { return accountPage("ana.lima") }, []string{"p", "y"}},
		{"Role: what it reaches, tool by tool", o, true, func() *page { return rolePage("tier1-analyst") }, nil},
		{"Role: a surgical write, then the reload question", o, true, func() *page { return rolePage("tier1-analyst") }, []string{"enter", "y"}},
		{"Add a person: the first question", o, true, nil, []string{"enter"}},
		{"Read-only: Users without the accounts socket", readOnly, true, nil, nil},
		{"Read-only: server detail without the accounts socket", readOnly, false, func() *page { return serverPage("casemgmt") }, nil},
		{"Error: a backend that does not exist", o, false, func() *page { return serverPage("no-such-backend") }, nil},
		{"Cancelled: nothing is sent", o, false, func() *page { return serverPage("logsearch") }, []string{"C", "n"}},
		{"Add a backend: the three choices", o, false, nil, []string{"a"}},
		{"Add a REST API: the form", o, false, func() *page { return addFormPage("rest") }, nil},
		{"Add a REST API: the auth choices", o, false, func() *page { return addFormPage("rest") }, []string{"down", "down", "down", "enter"}},
		{"Add a remote MCP server: the form", o, false, func() *page { return addFormPage("remote") }, nil},
		{"Add a remote MCP server: a pasted credential is not kept", o, false, func() *page { return addFormPage("remote") },
			[]string{"down", "down", "down", "down", "down", "enter", "VENDOR_KEY=not-a-real-key", "enter"}},
		{"Add a container (oci): the form", o, false, func() *page { return addFormPage("oci") }, nil},
		{"Add a container (oci): refused by the API", o, false, func() *page { return addFormPage("oci") },
			[]string{"enter", "intel", "enter", "down", "enter", "ghcr.io/example/intel-mcp:latest", "enter", "S"}},
		{"Registered: a remote MCP server, configuration not approved yet", o, false, func() *page { return addFormPage("remote") },
			[]string{"enter", "vendor", "enter", "down", "enter", "https://mcp.example.com/mcp", "enter", "S"}},
		{"Registered: a REST API, its operations pending review", o, false, func() *page { return addFormPage("rest") },
			[]string{"enter", "inventory", "enter", "down", "enter", "https://api.example.com", "enter", "down", "enter", "https://api.example.com/openapi.json", "enter", "S"}},
		{"Registered: read-only, approving needs root", readOnly, false, func() *page { return addFormPage("oci") },
			[]string{"enter", "intel", "enter", "down", "enter", "ghcr.io/example/intel-mcp@sha256:0123", "enter", "S"}},
	}
	draw := func(name string, o Options, users bool, pg func() *page, keys []string, noOCI bool) error {
		m, err := New(o)
		if err != nil {
			return err
		}
		a := m.(*app)
		a.width, a.height = 110, 200
		settle(a, a.Init())
		if noOCI {
			a.env.me.Features = slices.DeleteFunc(slices.Clone(a.env.me.Features), func(f string) bool { return f == adminapi.FeatureOCIRegister })
		}
		if users {
			settle(a, a.switchTab(1))
		}
		if pg != nil {
			settle(a, push(pg()))
		}
		for _, k := range keys {
			settle(a, func() tea.Msg { return keyMsg(k) })
		}
		_, err = fmt.Fprintf(w, "\n==== %s ====\n%s", name, a.View())
		return err
	}
	for _, s := range shots {
		if err := draw(s.name, s.o, s.users, s.page, s.keys, false); err != nil {
			return err
		}
	}
	return draw("Add a backend: no podman, so no Container", o, false, nil, []string{"a"}, true)
}

// addFormPage is the form of one registered add kind.
func addFormPage(id string) *page {
	for _, k := range orderedAddKinds() {
		if k.ID == id {
			return formPage(k.Form())
		}
	}
	return newPage("No such kind", func(env) content { return content{} })
}

// settle runs cmd and everything it leads to, feeding each message back
// into the model, until nothing is left: the program's loop, synchronously.
func settle(a *app, cmd tea.Cmd) {
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		switch msg := c().(type) {
		case nil:
		case tea.BatchMsg:
			queue = append(queue, msg...)
		case tea.QuitMsg:
			return
		default:
			_, next := a.Update(msg)
			queue = append(queue, next)
		}
	}
}

// keyMsg is the key the program would read for k: a named key, or text.
func keyMsg(k string) tea.KeyMsg {
	switch k {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}
