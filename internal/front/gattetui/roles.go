package gattetui

// Roles, a section of the Users tab (design/adr/0051, 0054). With the
// managing console and the accounts socket it is the role x tool view with
// surgical grant and revoke; otherwise it is read-only, from what the
// operator socket reports.
//
// A write is never a regenerated file: it splices the one entry it changes
// (frontkit.GrantSafeTool and the rest, the web console's rules), so the
// approver comments of design/adr/0009 survive byte for byte, and PutRoles
// validates it before keeping it. Writing does not apply: the front asks
// whether to reload right after.

import (
	"fmt"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

func init() {
	registerUsersSection(UsersSection{ID: "roles", Order: 20, Rows: rolesSection})
}

var roleCols = []int{18, 14, 22}

// roleSectionRows are extra rows at the top of the Roles list, such as a
// "New role" action. Each is drawn only when the roles file is editable.
var roleSectionRows []func(e env) row

func rolesSection(e env) ([]row, error) {
	editable := managesAndRoot(e.caps())
	var notes []row
	var blocks []frontkit.RoleBlock
	if editable {
		rt, rerr := e.acc.GetRoles(ctx())
		if rerr != nil {
			notes = append(notes, textRow(stBad.Render("The roles file could not be read: "+vis(errText(rerr)))))
			editable = false
		} else {
			blocks = frontkit.ParseRoles(rt.Text)
			notes = append(notes, textRow(stDim.Render(vis(rt.Path)+"  "+vis(rt.SHA256))))
		}
	} else {
		notes = append(notes, textRow(stDim.Render("Read-only: editing needs console_manages and -manage-users.")))
	}
	rows := append([]row{heading("Roles")}, notes...)
	if editable {
		for _, r := range roleSectionRows {
			rows = append(rows, r(e))
		}
	}
	p, err := e.op.PeopleRoles(ctx())
	if err != nil {
		return append(rows, textRow(stBad.Render("The roles could not be read: "+vis(errText(err))))), nil
	}
	rows = append(rows, textRow(stDim.Render(cols(roleCols, "ROLE", "NON_READ", "GROUPS", "TOOLS"))))
	for _, r := range p.Roles {
		name := r.Name
		nonRead := "-"
		if b, ok := frontkit.FindRole(blocks, name); ok {
			nonRead = nonReadText(b.NonRead)
		}
		line := cols(roleCols, vis(r.Name), nonRead, vis(dash(strings.Join(r.Groups, ", "))), fmt.Sprint(len(r.Tools)))
		if !editable {
			rows = append(rows, textRow(line))
			continue
		}
		rows = append(rows, row{text: line, actions: []action{{key: "enter", label: "open", run: func() tea.Cmd { return push(rolePage(name)) }}}})
	}
	return rows, nil
}

func nonReadText(on bool) string {
	if on {
		return stWarn.Render("on")
	}
	return stDim.Render("off")
}

// ---- one role: every tool, whether the role reaches it, and a checkbox
// to grant or revoke several at once

func rolePage(role string) *page {
	sel := &selection{on: map[string]bool{}}
	return newPage(vis(role), func(e env) content { return fillRole(e, role, sel) })
}

// selection is a role page's checked tools, by name. It outlives a re-read
// of the page, so a cancel or a refusal keeps it; a write empties it. It is
// toggled on the update loop and read by fills off it, hence the lock.
type selection struct {
	mu sync.Mutex
	on map[string]bool
}

func (s *selection) toggle(ns string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.on[ns] = !s.on[ns]
}

func (s *selection) has(ns string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.on[ns]
}

func (s *selection) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.on)
}

// pick is the selected tools of list, in list order; with none selected,
// the tool under the cursor.
func (s *selection) pick(list []adminapi.Tool, cursor string) []string {
	var out []string
	for _, t := range list {
		if ns := t.Server + "." + t.Tool; s.has(ns) {
			out = append(out, ns)
		}
	}
	if len(out) == 0 && cursor != "" {
		out = []string{cursor}
	}
	return out
}

func fillRole(e env, role string, sel *selection) content {
	var c content
	rt, err := e.acc.GetRoles(ctx())
	if err != nil {
		c.problems = append(c.problems, errText(err))
		return c
	}
	b, ok := frontkit.FindRole(frontkit.ParseRoles(rt.Text), role)
	if !ok {
		c.problems = append(c.problems, "No [[role]] named "+vis(role)+" in "+vis(rt.Path)+".")
		return c
	}
	tools, err := e.op.ListTools(ctx(), "", "")
	if err != nil {
		c.problems = append(c.problems, errText(err))
	}
	c.rows = append(c.rows, heading(vis(role)), textRow(cols([]int{14}, stDim.Render("non_read"), nonReadText(b.NonRead))), blank(),
		textRow(stDim.Render(cols([]int{40, 12}, "    TOOL", "CLASS", "REACHED"))))
	apply := func(op, cursor string) tea.Cmd {
		picked := sel.pick(tools.Tools, cursor)
		verb := strings.ToUpper(op[:1]) + op[1:]
		q := fmt.Sprintf("%s %d tool(s) for %s?", verb, len(picked), vis(role))
		if len(picked) == 1 {
			q = fmt.Sprintf("%s %s for %s?", verb, vis(picked[0]), vis(role))
		}
		return confirm(q, func() tea.Cmd {
			return do(func() result { return editGrants(e, role, picked, op, sel) })
		})
	}
	for _, t := range tools.Tools {
		cov := b.Cover(t.Server, t.Tool, t.Class == adminapi.ClassSensitive)
		reach := stDim.Render("no")
		switch cov.How {
		case "explicit", "grant", "non_read":
			reach = stOK.Render("yes") + stDim.Render("  "+cov.How)
		case "wildcard":
			reach = stOK.Render("yes") + stDim.Render(`  "*" over `+vis(t.Server))
		}
		ns := t.Server + "." + t.Tool
		c.rows = append(c.rows, row{
			text:    cols([]int{36, 12}, vis(ns), classText(t.Class), reach),
			checked: func() bool { return sel.has(ns) },
			actions: []action{
				{key: "space", label: "select", run: func() tea.Cmd { sel.toggle(ns); return nil }},
				{key: "g", label: "grant", run: func() tea.Cmd { return apply("grant", ns) }},
				{key: "v", label: "revoke", run: func() tea.Cmd { return apply("revoke", ns) }},
			},
		})
	}
	if b.NonRead {
		c.actions = append(c.actions, action{key: "n", label: "turn non_read off", run: func() tea.Cmd {
			return confirm("Turn non_read off for "+vis(role)+"?", func() tea.Cmd {
				return do(func() result { return setNonRead(e, role, false, nil, sel) })
			})
		}})
		return c
	}
	c.actions = append(c.actions, action{key: "n", label: "turn non_read on", run: func() tea.Cmd {
		// non_read is a security boundary (design/adr/0048): it is turned
		// on only here, never by a grant. The backend refuses it on a role
		// whose tools list is empty, so it goes on together with the
		// sensitive tools the operator selected, in one write.
		var give []string
		for _, t := range tools.Tools {
			if ns := t.Server + "." + t.Tool; t.Class == adminapi.ClassSensitive && sel.has(ns) {
				give = append(give, ns)
			}
		}
		if len(give) == 0 && len(b.Tools) == 0 {
			return do(func() result { return refused(needSensitive) })
		}
		q := "Turn non_read on for " + vis(role) + "?"
		if len(give) > 0 {
			q = "Turn non_read on for " + vis(role) + " and give it: " + vis(strings.Join(give, ", ")) + "?"
		}
		return confirm(q, func() tea.Cmd {
			return do(func() result { return setNonRead(e, role, true, give, sel) })
		})
	}})
	return c
}

const needSensitive = "non_read needs at least one sensitive tool: select it, then n."

// setNonRead turns non_read on or off for role; turning it on also names
// the sensitive tools in give, so the role is valid in the same write.
func setNonRead(e env, role string, on bool, give []string, sel *selection) result {
	cur, err := e.acc.GetRoles(ctx())
	if err != nil {
		return refused("The roles file could not be read: " + firstLine(errText(err)))
	}
	state := map[bool]string{true: "on", false: "off"}[on]
	text, st := frontkit.SetNonRead(cur.Text, role, on)
	switch st {
	case frontkit.SpliceNoRole:
		return refused("Nothing changed: no [[role]] named " + role + ".")
	case frontkit.SpliceAlready:
		if len(give) == 0 {
			return result{ok: true, summary: "non_read is already " + state + " for " + role + "."}
		}
	}
	for _, ns := range give {
		server, tool, _ := strings.Cut(ns, ".")
		next, st := frontkit.GrantSensitiveTool(text, role, server, tool)
		if st == frontkit.SpliceChanged {
			text = next
		}
	}
	done := "non_read is " + state + " for " + role + "."
	if len(give) > 0 {
		done = "non_read is on for " + role + "; gave it " + strings.Join(give, ", ") + "."
	}
	r := putRoles(e, text, done)
	if r.ok {
		sel.clear()
	}
	return r
}

// editGrants grants or revokes each tool for one role on one copy of the
// roles file, then writes it once. The class is read from the live list
// rather than from what was drawn, so a sensitive tool takes the sensitive
// path whatever the screen showed.
func editGrants(e env, role string, picked []string, op string, sel *selection) result {
	list, err := e.op.ListTools(ctx(), "", "")
	if err != nil {
		return refused("The tools could not be read: " + firstLine(errText(err)))
	}
	cur, err := e.acc.GetRoles(ctx())
	if err != nil {
		return refused("The roles file could not be read: " + firstLine(errText(err)))
	}
	text := cur.Text
	var done, already, notes []string
	for _, ns := range picked {
		var tool adminapi.Tool
		for _, t := range list.Tools {
			if t.Server+"."+t.Tool == ns {
				tool = t
			}
		}
		if tool.Tool == "" {
			notes = append(notes, "Not changed: no tool "+ns+" is known.")
			continue
		}
		var next string
		var st frontkit.SpliceStatus
		switch {
		case op == "revoke":
			next, st = frontkit.RevokeTool(text, role, tool.Server, tool.Tool)
		case tool.Class == adminapi.ClassSensitive:
			next, st = frontkit.GrantSensitiveTool(text, role, tool.Server, tool.Tool)
		default:
			next, st = frontkit.GrantSafeTool(text, role, tool.Server, tool.Tool)
		}
		switch st {
		case frontkit.SpliceChanged:
			text = next
			done = append(done, ns)
		case frontkit.SpliceAlready:
			already = append(already, ns)
		case frontkit.SpliceNoRole:
			return refused("Nothing changed: no [[role]] named " + role + ".")
		case frontkit.SpliceWildcard:
			notes = append(notes, "Not changed: "+ns+` is reached through "*" over `+tool.Server+"; edit that grant in the roles file.")
		case frontkit.SpliceNeedNonRead:
			notes = append(notes, "Not granted: "+ns+" is sensitive; select it, then n to turn non_read on with it.")
		}
	}
	verb := map[string]string{"grant": "Granted", "revoke": "Revoked"}[op]
	var out []string
	if len(done) > 0 {
		out = append(out, verb+": "+strings.Join(done, ", "))
	}
	if len(already) > 0 {
		out = append(out, map[string]string{"grant": "Already granted: ", "revoke": "Already not granted: "}[op]+strings.Join(already, ", "))
	}
	out = append(out, notes...)
	// The counts keep a refusal apart from a no-op: a refused tool is one
	// the operator still has to act on.
	var counts []string
	if len(done) > 0 {
		counts = append(counts, fmt.Sprintf("%s %d", strings.ToLower(verb), len(done)))
	}
	if len(already) > 0 {
		counts = append(counts, fmt.Sprintf("already set %d", len(already)))
	}
	if len(notes) > 0 {
		counts = append(counts, fmt.Sprintf("refused %d", len(notes)))
	}
	summary := strings.Join(counts, ", ") + " for " + role + "."
	summary = strings.ToUpper(summary[:1]) + summary[1:]
	if len(done) == 0 {
		return result{ok: len(notes) == 0, summary: summary, output: out}
	}
	r := putRoles(e, text, summary)
	r.output = append(out, r.output...)
	if r.ok {
		sel.clear()
	}
	return r
}

// putRoles stores the edited roles text. A write is not applied, so a
// successful one asks right away whether to reload.
func putRoles(e env, text, done string) result {
	res, err := e.acc.PutRoles(ctx(), text)
	r := fromAction(res.ActionResult, err, done)
	if err != nil {
		return r
	}
	r.output = append(r.output, "Written to the roles file and NOT applied yet.")
	if e.has(adminapi.FeatureServeControl) {
		r.next = confirm("Reload the configuration now to apply it?", func() tea.Cmd {
			return do(func() result { q, err := e.op.Reload(ctx()); return serveResult(e, q, err) })
		})
	} else {
		r.output = append(r.output, "Apply it with mcp-gateway reload.")
	}
	return r
}
