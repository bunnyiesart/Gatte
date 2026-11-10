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

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

func init() {
	registerUsersSection(UsersSection{ID: "roles", Order: 20, Rows: rolesSection})
}

var roleCols = []int{18, 10, 22}

func rolesSection(e env) ([]row, error) {
	editable := managesAndRoot(e.caps())
	var notes []row
	var blocks []frontkit.RoleBlock
	if editable {
		rt, rerr := e.acc.GetRoles(ctx())
		if rerr != nil {
			notes = append(notes, textRow(stBad.Render("The roles file could not be read, so nothing here can be edited: "+vis(errText(rerr)))))
			editable = false
		} else {
			blocks = frontkit.ParseRoles(rt.Text)
			notes = append(notes, textRow(stDim.Render(vis(rt.Path)+"  "+vis(rt.SHA256))))
		}
	} else {
		notes = append(notes, textRow(stDim.Render("Read-only: editing needs console_manages and -manage-users.")))
	}
	rows := append([]row{heading("Roles")}, notes...)
	p, err := e.op.People(ctx())
	if err != nil {
		return append(rows, textRow(stBad.Render("The roles could not be read: "+vis(errText(err))))), nil
	}
	for _, r := range p.Roles {
		name := r.Name
		marking := ""
		if b, ok := frontkit.FindRole(blocks, name); ok && b.NonRead {
			marking = stWarn.Render("non_read")
		}
		line := cols(roleCols, vis(r.Name), marking, vis(dash(strings.Join(r.Groups, ", "))), stDim.Render(vis(strings.Join(r.Tools, ", "))))
		if !editable {
			rows = append(rows, textRow(line))
			continue
		}
		rows = append(rows, row{text: line, actions: []action{{key: "enter", label: "edit grants", run: func() tea.Cmd { return push(rolePage(name)) }}}})
	}
	return rows, nil
}

// ---- one role: every tool, and whether the role reaches it

func rolePage(role string) *page {
	return newPage(vis(role), func(e env) content { return fillRole(e, role) })
}

func fillRole(e env, role string) content {
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
	marking := stDim.Render("read only: cannot hold a sensitive tool")
	if b.NonRead {
		marking = stWarn.Render("non_read: may hold the sensitive tools named on it")
	}
	c.rows = append(c.rows, heading(vis(role)), textRow(marking), blank(),
		textRow(stDim.Render(cols([]int{36, 12}, "TOOL", "CLASS", "REACHED"))))
	for _, t := range tools.Tools {
		sensitive := t.Class == adminapi.ClassSensitive
		cov := b.Cover(t.Server, t.Tool, sensitive)
		reach := stDim.Render("no")
		switch cov.How {
		case "explicit", "grant", "non_read":
			reach = stOK.Render("yes") + stDim.Render("  "+cov.How)
		case "wildcard":
			reach = stOK.Render("yes") + stDim.Render(`  through "*" over `+vis(t.Server))
		}
		server, tool := t.Server, t.Tool
		op := "grant"
		if cov.Covered {
			op = "revoke"
		}
		c.rows = append(c.rows, row{
			text: cols([]int{36, 12}, vis(server+"."+tool), classText(t.Class), reach),
			actions: []action{{key: "enter", label: op, run: func() tea.Cmd {
				return confirm(fmt.Sprintf("%s %s for %s in the roles file?", strings.ToUpper(op[:1])+op[1:], vis(server+"."+tool), vis(role)), func() tea.Cmd {
					return do(func() result { return editGrant(e, role, server, tool, op) })
				})
			}}},
		})
	}
	verb, on := "Mark", true
	if b.NonRead {
		verb, on = "Clear", false
	}
	c.actions = append(c.actions, action{key: "n", label: strings.ToLower(verb) + " non_read", run: func() tea.Cmd {
		// non_read is a security boundary (design/adr/0048): it is set on
		// its own, never as a side effect of a grant.
		return confirm(verb+" non_read on "+vis(role)+"?", func() tea.Cmd {
			return do(func() result {
				cur, err := e.acc.GetRoles(ctx())
				if err != nil {
					return refused("The roles file could not be read: " + firstLine(errText(err)))
				}
				text, st := frontkit.SetNonRead(cur.Text, role, on)
				done := "Role " + role + " is now marked non_read: it may hold sensitive tools named on it explicitly."
				if !on {
					done = "Role " + role + " is no longer marked non_read."
				}
				return writeRoles(e, st, text, done, spliceText{noRole: "Nothing changed: no [[role]] named " + role + ".", already: "Role " + role + " already has that marking."})
			})
		})
	}})
	return c
}

// editGrant grants or revokes one tool for one role. The class is read from
// the live list rather than from what was drawn, so a sensitive tool takes
// the sensitive path whatever the screen showed.
func editGrant(e env, role, server, tool, op string) result {
	list, err := e.op.ListTools(ctx(), server, "")
	if err != nil {
		return refused("The tools could not be read: " + firstLine(errText(err)))
	}
	sensitive, known := false, false
	for _, t := range list.Tools {
		if t.Server == server && t.Tool == tool {
			sensitive, known = t.Class == adminapi.ClassSensitive, true
		}
	}
	ns := server + "." + tool
	if !known {
		return refused("Nothing changed: no tool " + ns + " is known.")
	}
	cur, err := e.acc.GetRoles(ctx())
	if err != nil {
		return refused("The roles file could not be read: " + firstLine(errText(err)))
	}
	var text string
	var st frontkit.SpliceStatus
	done := "Role " + role + " may no longer call " + ns + "."
	switch {
	case op == "revoke":
		text, st = frontkit.RevokeTool(cur.Text, role, server, tool)
	case sensitive:
		text, st = frontkit.GrantSensitiveTool(cur.Text, role, server, tool)
		done = "Role " + role + " may call " + ns + " once you approve and clear it."
	default:
		text, st = frontkit.GrantSafeTool(cur.Text, role, server, tool)
		done = "Role " + role + " may call " + ns + " once you approve it."
	}
	word := "grants"
	if op == "revoke" {
		word = "does not grant"
	}
	return writeRoles(e, st, text, done, spliceText{
		noRole:  "Nothing changed: no [[role]] named " + role + ".",
		already: "No change: role " + role + " already " + word + " " + ns + ".",
		wildcard: "Not changed: " + ns + " is reached through a \"*\" grant over " + server +
			". Change the whole-backend grant in the roles file to change it one tool at a time.",
		needNonRead: "Not granted: " + ns + " is a sensitive tool, reachable only by a role marked non_read that names it. " +
			"Mark " + role + " non_read first (n). A sensitive tool also needs a clear before it is served.",
	})
}

type spliceText struct{ noRole, already, wildcard, needNonRead string }

// writeRoles stores a spliced text through PutRoles; a status other than
// changed is a message, with nothing written. A write is not applied, so a
// successful one asks right away whether to reload.
func writeRoles(e env, st frontkit.SpliceStatus, text, done string, m spliceText) result {
	switch st {
	case frontkit.SpliceNoRole:
		return refused(m.noRole)
	case frontkit.SpliceAlready:
		return result{ok: true, summary: m.already}
	case frontkit.SpliceWildcard:
		return refused(m.wildcard)
	case frontkit.SpliceNeedNonRead:
		return refused(m.needNonRead)
	}
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
