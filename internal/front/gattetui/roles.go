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
	return newPage(vis(role), func(e env) content { return fillRole(e, role) })
}

// toolCheck is one tool's checkbox on a role page. A read of the page makes
// new ones, so a write, which re-reads it, leaves nothing selected.
type toolCheck struct {
	ns string
	on *bool
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
	c.rows = append(c.rows, heading(vis(role)), textRow(cols([]int{14}, stDim.Render("non_read"), nonReadText(b.NonRead))), blank(),
		textRow(stDim.Render(cols([]int{40, 12}, "    TOOL", "CLASS", "REACHED"))))
	// apply is bound to a row so that, with nothing selected, it acts on
	// the tool under the cursor.
	var checks []toolCheck
	apply := func(op, ns string) tea.Cmd {
		var picked []string
		for _, c := range checks {
			if *c.on {
				picked = append(picked, c.ns)
			}
		}
		if len(picked) == 0 {
			picked = []string{ns}
		}
		q := fmt.Sprintf("%s %d tool(s) for %s?", strings.ToUpper(op[:1])+op[1:], len(picked), vis(role))
		if len(picked) == 1 {
			q = fmt.Sprintf("%s %s for %s?", strings.ToUpper(op[:1])+op[1:], vis(picked[0]), vis(role))
		}
		return confirm(q, func() tea.Cmd {
			return do(func() result { return editGrants(e, role, picked, op) })
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
		check := new(bool)
		checks = append(checks, toolCheck{ns, check})
		c.rows = append(c.rows, row{
			text:  cols([]int{36, 12}, vis(ns), classText(t.Class), reach),
			check: check,
			actions: []action{
				{key: "space", label: "select", run: func() tea.Cmd { *check = !*check; return nil }},
				{key: "g", label: "grant", run: func() tea.Cmd { return apply("grant", ns) }},
				{key: "v", label: "revoke", run: func() tea.Cmd { return apply("revoke", ns) }},
			},
		})
	}
	state, on := "on", true
	if b.NonRead {
		state, on = "off", false
	}
	c.actions = append(c.actions, action{key: "n", label: "turn non_read " + state, run: func() tea.Cmd {
		// non_read is a security boundary (design/adr/0048): it is set on
		// its own, never as a side effect of a grant.
		return confirm("Turn non_read "+state+" for "+vis(role)+"?", func() tea.Cmd {
			return do(func() result {
				cur, err := e.acc.GetRoles(ctx())
				if err != nil {
					return refused("The roles file could not be read: " + firstLine(errText(err)))
				}
				text, st := frontkit.SetNonRead(cur.Text, role, on)
				switch st {
				case frontkit.SpliceNoRole:
					return refused("Nothing changed: no [[role]] named " + role + ".")
				case frontkit.SpliceAlready:
					return result{ok: true, summary: "non_read is already " + state + " for " + role + "."}
				}
				return putRoles(e, text, "non_read is "+state+" for "+role+".")
			})
		})
	}})
	return c
}

// editGrants grants or revokes each tool for one role on one copy of the
// roles file, then writes it once. The class is read from the live list
// rather than from what was drawn, so a sensitive tool takes the sensitive
// path whatever the screen showed.
func editGrants(e env, role string, picked []string, op string) result {
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
			notes = append(notes, "Not granted: "+ns+" is sensitive; switch non_read on first (n).")
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
	if len(done) == 0 {
		r := result{ok: len(notes) == 0, summary: "Nothing changed."}
		if len(out) == 1 {
			r.summary, out = out[0], nil
		}
		r.output = out
		return r
	}
	summary := fmt.Sprintf("%s %d for %s.", verb, len(done), role)
	if len(notes) > 0 {
		summary = fmt.Sprintf("%s %d for %s, %d not changed.", verb, len(done), role, len(notes))
	}
	r := putRoles(e, text, summary)
	r.output = append(out, r.output...)
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
