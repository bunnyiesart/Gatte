package gattetui

import (
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// Gallery draws every screen and state of the front, one after another, as
// plain text: for reviewing the whole surface at once against the mock API
// (make preview-tui ARGS=-gallery). It drives the same model the program
// runs, with each API call made synchronously.
//
// It performs the actions it shows (a reconnect, a password reset),
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
	}
	for _, s := range shots {
		m, err := New(s.o)
		if err != nil {
			return err
		}
		a := m.(*app)
		a.width, a.height = 110, 200
		settle(a, a.Init())
		if s.users {
			settle(a, a.switchTab(1))
		}
		if s.page != nil {
			settle(a, push(s.page()))
		}
		for _, k := range s.keys {
			settle(a, func() tea.Msg { return keyMsg(k) })
		}
		if _, err := fmt.Fprintf(w, "\n==== %s ====\n%s", s.name, a.View()); err != nil {
			return err
		}
	}
	return nil
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
