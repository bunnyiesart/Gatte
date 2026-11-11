package gattetui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Every screen of the front is a page: a title, rows read from the API, and
// actions bound to keys, on a row or on the whole page. A tab is a stack of
// pages (list, then detail, then review); esc goes back down it.

// An action is one key on a row or a page. run is called on the update loop
// and returns the command that does the work (an API call, a prompt, a new
// page).
type action struct {
	key   string
	label string
	run   func() tea.Cmd
}

// A row is one drawn line. Only a row with actions can hold the cursor.
// check, when set, draws a checkbox before the text that an action toggles.
type row struct {
	text    string
	actions []action
	check   *bool
}

func textRow(s string) row { return row{text: s} }

// content is what a page's fill read: its rows, the page-level actions and
// the problems met on the way, shown above the rows.
type content struct {
	rows     []row
	actions  []action
	problems []string
}

type page struct {
	id    int
	title string
	// fill reads the page. It runs off the update loop, with a copy of env.
	fill func(e env) content
	content
	loaded bool
	// seq numbers the reads, so a slow read that answers after a newer one
	// is dropped rather than drawn over it.
	seq    int
	cursor int
	offset int
}

func newPage(title string, fill func(e env) content) *page {
	return &page{title: title, fill: fill}
}

func (p *page) selectable(i int) bool {
	return i >= 0 && i < len(p.rows) && len(p.rows[i].actions) > 0
}

// fixCursor keeps the cursor on a selectable row after the rows changed.
func (p *page) fixCursor() {
	if p.selectable(p.cursor) {
		return
	}
	for i := range p.rows {
		if p.selectable(i) {
			p.cursor = i
			return
		}
	}
	p.cursor = 0
}

func (p *page) move(delta int) {
	for i := p.cursor + delta; i >= 0 && i < len(p.rows); i += delta {
		if p.selectable(i) {
			p.cursor = i
			return
		}
	}
	if !p.selectable(p.cursor) {
		// A page of text only: the arrows scroll it.
		p.offset = max(0, min(p.offset+delta, len(p.rows)-1))
	}
}

// keys are the actions in force: the selected row's first, then the page's.
func (p *page) keys() []action {
	var out []action
	if p.selectable(p.cursor) {
		out = append(out, p.rows[p.cursor].actions...)
	}
	return append(out, p.actions...)
}

// ---- messages

type (
	meMsg struct {
		me  adminapi.WhoAmI
		err error
	}
	loadedMsg struct {
		id, seq int
		c       content
	}
	pushMsg   struct{ p *page }
	promptMsg struct{ p *prompt }
	menuMsg   struct{ m *menu }
	resultMsg struct{ r result }
)

// A menu is a small popup of actions that belong together, such as one
// tool's (design/adr/0061 §5). An item is chosen with the arrows and enter,
// or by its key; esc closes it and nothing is sent.
type menu struct {
	title  string
	items  []action
	cursor int
}

func openMenu(title string, items []action) tea.Cmd {
	if len(items) == 0 {
		return nil
	}
	m := &menu{title: title, items: items}
	return func() tea.Msg { return menuMsg{m} }
}

func push(p *page) tea.Cmd { return func() tea.Msg { return pushMsg{p} } }

// do runs fn off the update loop and shows what it returns.
func do(fn func() result) tea.Cmd { return func() tea.Msg { return resultMsg{fn()} } }

// ---- the application

type app struct {
	env    env
	meErr  error
	tabs   []Screen
	active int
	stacks [][]*page
	nextID int
	width  int
	height int
	prompt *prompt
	menu   *menu
	result *result
	// origin is the page the last action started from: the page a result
	// with back leaves, whichever tab is shown when it answers.
	origin int
}

func newApp(e env) *app {
	a := &app{env: e, tabs: orderedScreens(), width: 100, height: 30}
	for _, s := range a.tabs {
		a.stacks = append(a.stacks, []*page{a.adopt(s.Root())})
	}
	return a
}

func (a *app) adopt(p *page) *page {
	a.nextID++
	p.id = a.nextID
	return p
}

func (a *app) top() *page {
	if len(a.stacks) == 0 {
		return nil
	}
	s := a.stacks[a.active]
	return s[len(s)-1]
}

func (a *app) whoami() tea.Cmd {
	op := a.env.op
	return func() tea.Msg {
		me, err := op.WhoAmI(ctx())
		return meMsg{me, err}
	}
}

func (a *app) load(p *page) tea.Cmd {
	if p == nil {
		return nil
	}
	p.seq++
	e, id, seq, fill := a.env, p.id, p.seq, p.fill
	return func() tea.Msg { return loadedMsg{id, seq, fill(e)} }
}

// Init reads who the operator is first: what a page offers depends on the
// features the backend lists.
func (a *app) Init() tea.Cmd { return a.whoami() }

func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		return a, nil
	case meMsg:
		a.meErr = m.err
		if m.err == nil {
			a.env.me = m.me
		}
		return a, a.load(a.top())
	case loadedMsg:
		for _, s := range a.stacks {
			for _, p := range s {
				if p.id == m.id && p.seq == m.seq {
					p.content, p.loaded = m.c, true
					p.fixCursor()
				}
			}
		}
		return a, nil
	case pushMsg:
		p := a.adopt(m.p)
		a.stacks[a.active] = append(a.stacks[a.active], p)
		return a, a.load(p)
	case promptMsg:
		a.prompt = m.p
		return a, nil
	case menuMsg:
		a.menu = m.m
		return a, nil
	case resultMsg:
		r := m.r
		a.result = &r
		cmds := []tea.Cmd{r.next}
		tab := a.tabOf(a.origin)
		if r.back {
			cmds = append(cmds, a.leave(a.origin))
		}
		if r.open != nil && tab >= 0 {
			p := a.adopt(r.open)
			a.stacks[tab] = append(a.stacks[tab], p)
			if tab != a.active {
				cmds = append(cmds, a.load(p))
			}
		}
		// What is shown after an action is what the backend now says.
		return a, tea.Batch(append(cmds, a.load(a.top()))...)
	case tea.KeyMsg:
		return a, a.key(m)
	}
	return a, nil
}

// leave pops page id off its own tab when it is that tab's top; a tab not
// shown has the page under it read again.
func (a *app) leave(id int) tea.Cmd {
	for i, s := range a.stacks {
		if n := len(s); n > 1 && s[n-1].id == id {
			a.stacks[i] = s[:n-1]
			if i != a.active {
				return a.load(a.stacks[i][n-2])
			}
		}
	}
	return nil
}

// tabOf is the tab whose stack holds page id, or -1.
func (a *app) tabOf(id int) int {
	for i, s := range a.stacks {
		for _, p := range s {
			if p.id == id {
				return i
			}
		}
	}
	return -1
}

func (a *app) pop() {
	if s := a.stacks[a.active]; len(s) > 1 {
		a.stacks[a.active] = s[:len(s)-1]
	}
}

func (a *app) key(m tea.KeyMsg) tea.Cmd {
	k := m.String()
	if k == "ctrl+c" {
		return tea.Quit
	}
	if a.result != nil && a.result.secret != "" {
		// A one-time password is wiped by the first key, prompt or not; that
		// key does nothing else, so it cannot be lost to a page change unseen.
		a.result.secret = ""
		a.result = nil
		return nil
	}
	if a.prompt != nil {
		return a.promptKey(m)
	}
	a.result = nil
	if k == " " {
		k = "space"
	}
	if a.menu != nil {
		return a.menuKey(k)
	}
	p := a.top()
	switch k {
	case "q":
		return tea.Quit
	case "tab", "shift+tab":
		step := 1
		if k == "shift+tab" {
			step = len(a.tabs) - 1
		}
		return a.switchTab((a.active + step) % len(a.tabs))
	case "esc", "backspace", "left", "h":
		a.pop()
		return a.load(a.top())
	case "r":
		return a.whoami()
	case "?":
		if p.title == helpTitle {
			return nil
		}
		return push(helpPage())
	case "up", "k":
		p.move(-1)
		return nil
	case "down", "j":
		p.move(1)
		return nil
	}
	if len(k) == 1 && k[0] >= '1' && k[0] <= '9' {
		if i := int(k[0] - '1'); i < len(a.tabs) {
			return a.switchTab(i)
		}
	}
	for _, act := range p.keys() {
		if act.key == k {
			a.origin = p.id
			return act.run()
		}
	}
	return nil
}

func (a *app) switchTab(i int) tea.Cmd {
	a.active = i
	if p := a.top(); !p.loaded {
		return a.load(p)
	}
	return nil
}

func (a *app) promptKey(m tea.KeyMsg) tea.Cmd {
	p := a.prompt
	switch {
	case p.yesNo:
		a.prompt = nil
		if s := m.String(); s == "y" || s == "Y" {
			return p.done("y")
		}
		return cancelled()
	case m.Type == tea.KeyEnter:
		a.prompt = nil
		v := string(p.buf)
		p.wipe()
		return p.done(v)
	case m.Type == tea.KeyEsc:
		a.prompt = nil
		p.wipe()
		return cancelled()
	case m.Type == tea.KeyBackspace:
		if len(p.buf) > 0 {
			p.buf = p.buf[:len(p.buf)-1]
		}
	case m.Type == tea.KeyRunes || m.Type == tea.KeySpace:
		p.buf = append(p.buf, m.Runes...)
	}
	return nil
}

// menuKey drives an open menu; it holds every key until an item runs or it
// is closed.
func (a *app) menuKey(k string) tea.Cmd {
	m := a.menu
	switch k {
	case "esc", "q", "left", "h":
		a.menu = nil
		return nil
	case "up", "k":
		m.cursor = max(0, m.cursor-1)
		return nil
	case "down", "j":
		m.cursor = min(len(m.items)-1, m.cursor+1)
		return nil
	case "enter":
		a.menu = nil
		return m.items[m.cursor].run()
	}
	for _, it := range m.items {
		if it.key == k {
			a.menu = nil
			return it.run()
		}
	}
	return nil
}

func (m *menu) view() string {
	lines := []string{stBold.Render(m.title)}
	for i, it := range m.items {
		line := " " + it.key + "  " + it.label + " "
		if i == m.cursor {
			line = stMenuSel.Render(line)
		}
		lines = append(lines, line)
	}
	return bevel(true).Render(strings.Join(lines, "\n"))
}

func cancelled() tea.Cmd {
	return func() tea.Msg { return resultMsg{result{summary: "Cancelled. Nothing was sent."}} }
}

// ---- drawing
//
// The screen is a classic window: a grey title bar, the tabs as square
// buttons, the page in a sunken bevelled panel, then the result, the prompt
// or the open menu, and the buttons of the actions in force.

func (a *app) View() string {
	var b strings.Builder
	b.WriteString(a.header() + "\n")
	b.WriteString(a.tabBar() + "\n")
	p := a.top()
	if p == nil {
		return b.String()
	}
	b.WriteString(stBold.Render(a.crumbs()) + "\n")

	var foot []string
	if a.result != nil {
		foot = append(foot, a.result.lines()...)
	}
	if a.prompt != nil {
		foot = append(foot, a.prompt.view())
	}
	if a.menu != nil {
		foot = append(foot, strings.Split(a.menu.view(), "\n")...)
	}
	foot = append(foot, a.help(p)...)

	inner := max(10, a.width-4) // the panel's border and padding
	var body []string
	if a.meErr != nil {
		body = append(body, stBad.Render("The management API did not answer: "+vis(a.meErr.Error())))
	}
	for _, pr := range p.problems {
		body = append(body, stBad.Render(vis(pr)))
	}
	if !p.loaded {
		body = append(body, stDim.Render("Reading..."))
	}
	room := a.height - 5 - len(foot) - len(body)
	if room < 3 {
		room = 3
	}
	if p.selectable(p.cursor) {
		if p.cursor < p.offset {
			p.offset = p.cursor
		}
		if p.cursor >= p.offset+room {
			p.offset = p.cursor - room + 1
		}
	}
	p.offset = max(0, min(p.offset, len(p.rows)-1))
	for i := p.offset; i < len(p.rows) && i < p.offset+room; i++ {
		line := p.rows[i].text
		if c := p.rows[i].check; c != nil {
			box := "[ ] "
			if *c {
				box = "[x] "
			}
			line = box + line
		}
		if i == p.cursor && p.selectable(i) {
			line = stCursor.Render("> ") + line
		} else {
			line = "  " + line
		}
		body = append(body, line)
	}
	for i, l := range body {
		body[i] = lipgloss.NewStyle().MaxWidth(inner).Render(l)
	}
	b.WriteString(bevel(false).Width(inner+2).Render(strings.Join(body, "\n")) + "\n")
	for _, l := range foot {
		b.WriteString(a.fit(l) + "\n")
	}
	return b.String()
}

func (a *app) fit(s string) string { return lipgloss.NewStyle().MaxWidth(a.width).Render(s) }

func (a *app) header() string {
	who := a.env.me.Operator.Name
	if who == "" {
		who = a.env.me.Operator.Identity
	}
	// Holding the accounts socket is root's power, so it is marked in red.
	socket := stBar.Render("operator socket only")
	if a.env.acc != nil {
		socket = stBar.Foreground(lipgloss.Color("1")).Bold(true).Render("accounts socket open (root)")
	}
	line := stBar.Bold(true).Render(" Gatte") + stBar.Render("  |  operator "+vis(dash(who))+"  |  ") + socket
	// MaxWidth truncates; Width would wrap a long line onto a second row.
	line = lipgloss.NewStyle().MaxWidth(a.width).Render(line)
	return line + stBar.Render(strings.Repeat(" ", max(0, a.width-lipgloss.Width(line))))
}

func (a *app) tabBar() string {
	var out []string
	for i, s := range a.tabs {
		label := "[ " + string(rune('1'+i)) + " " + s.Title + " ]"
		if i == a.active {
			out = append(out, stTabOn.Render(label))
		} else {
			out = append(out, stTabOff.Render(label))
		}
	}
	return strings.Join(out, " ")
}

func (a *app) crumbs() string {
	var t []string
	for _, p := range a.stacks[a.active] {
		t = append(t, p.title)
	}
	return strings.Join(t, " > ")
}

// help is the row of buttons in force, wrapped to the screen's width, and
// the keys that work everywhere.
func (a *app) help(p *page) []string {
	switch {
	case a.prompt != nil && a.prompt.yesNo:
		return []string{button("y", "Yes") + "  " + stDim.Render("any other key: No, nothing is sent")}
	case a.prompt != nil:
		return []string{button("enter", "OK") + " " + button("esc", "Cancel")}
	case a.menu != nil:
		return []string{button("enter", "OK") + " " + button("esc", "Cancel") + "  " + stDim.Render("up/down choose")}
	}
	var lines []string
	line := ""
	for _, act := range p.keys() {
		bt := button(act.key, act.label)
		if line != "" && lipgloss.Width(line)+1+lipgloss.Width(bt) > a.width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += bt
	}
	if line != "" {
		lines = append(lines, line)
	}
	return append(lines, stDim.Render("tab switch  r refresh  ? help  esc back  q quit"))
}
