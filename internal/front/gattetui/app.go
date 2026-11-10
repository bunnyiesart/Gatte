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
type row struct {
	text    string
	actions []action
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
		id int
		c  content
	}
	pushMsg   struct{ p *page }
	promptMsg struct{ p *prompt }
	resultMsg struct{ r result }
)

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
	result *result
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
	e, id, fill := a.env, p.id, p.fill
	return func() tea.Msg { return loadedMsg{id, fill(e)} }
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
				if p.id == m.id {
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
	case resultMsg:
		r := m.r
		a.result = &r
		if r.back {
			a.pop()
		}
		// What is shown after an action is what the backend now says.
		return a, tea.Batch(a.load(a.top()), r.next)
	case tea.KeyMsg:
		return a, a.key(m)
	}
	return a, nil
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
	if a.prompt != nil {
		return a.promptKey(m)
	}
	if a.result != nil {
		held := a.result.secret != ""
		a.result.secret = ""
		a.result = nil
		if held {
			// A one-time password is wiped by the first key; that key does
			// nothing else, so it cannot be lost to a page change unseen.
			return nil
		}
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

func cancelled() tea.Cmd {
	return func() tea.Msg { return resultMsg{result{summary: "Cancelled. Nothing was sent."}} }
}

// ---- drawing

func (a *app) View() string {
	var b strings.Builder
	b.WriteString(a.header() + "\n")
	b.WriteString(a.tabBar() + "\n")
	p := a.top()
	if p == nil {
		return b.String()
	}
	b.WriteString(stTitle.Render(a.crumbs()) + "\n")

	var foot []string
	if a.result != nil {
		foot = append(foot, a.result.lines()...)
	}
	if a.prompt != nil {
		foot = append(foot, a.prompt.view())
	}
	foot = append(foot, a.help(p))

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
	room := a.height - 3 - len(foot) - len(body)
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
		if i == p.cursor && p.selectable(i) {
			line = stCursor.Render("> ") + line
		} else {
			line = "  " + line
		}
		body = append(body, line)
	}
	for _, l := range body {
		b.WriteString(a.fit(l) + "\n")
	}
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
	parts := []string{stBold.Render("Gatte"), "operator " + vis(dash(who))}
	if a.env.acc != nil {
		parts = append(parts, stWarn.Render("accounts socket open (root)"))
	} else {
		parts = append(parts, stDim.Render("operator socket only"))
	}
	return strings.Join(parts, "  ")
}

func (a *app) tabBar() string {
	var out []string
	for i, s := range a.tabs {
		label := " " + string(rune('1'+i)) + " " + s.Title + " "
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

func (a *app) help(p *page) string {
	switch {
	case a.prompt != nil && a.prompt.yesNo:
		return stKey.Render("y") + " yes  " + stDim.Render("any other key: no, nothing is sent")
	case a.prompt != nil:
		return stKey.Render("enter") + " send  " + stKey.Render("esc") + " cancel"
	}
	var parts []string
	for _, act := range p.keys() {
		parts = append(parts, stKey.Render(act.key)+" "+act.label)
	}
	parts = append(parts, stDim.Render("tab switch  r refresh  esc back  q quit"))
	return strings.Join(parts, "  ")
}
