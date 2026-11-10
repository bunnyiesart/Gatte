package gattetui

// Tools, the quarantine, as a panel of the server-detail page
// (design/adr/0051), and the per-tool review and the review of a whole set.
// Every gate is the backend's (design/adr/0047, 0048, 0040 §3, 0032): a tool
// stays pending until approved, an approval binds to the fingerprint the
// review showed, and a sensitive tool also needs a clear and a non_read role
// before it is served. So approving, revoking and clearing happen on the
// review page only, where the definition and its fingerprint are on screen.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func init() {
	registerDetailPanel(DetailPanel{ID: "tools", Order: 20, Rows: toolsPanel})
}

var toolCols = []int{24, 24}

func toolsPanel(e env, d adminapi.UpstreamDetail) ([]row, error) {
	waiting, sensitive := 0, 0
	for _, t := range d.Tools {
		if t.Status != adminapi.StatusApproved {
			waiting++
		}
		if t.Class == adminapi.ClassSensitive {
			sensitive++
		}
	}
	rows := []row{heading(fmt.Sprintf("Tools  %d, %d waiting for review, %d sensitive", len(d.Tools), waiting, sensitive))}
	if len(d.Tools) == 0 {
		return append(rows, textRow(stDim.Render("The gateway has seen no tool from this backend yet."))), nil
	}
	server := d.Name
	if waiting > 0 && e.has(adminapi.FeatureToolReviewSet) {
		rows = append(rows, row{
			text:    stWarn.Render(fmt.Sprintf("Review all waiting tools together (%d)", waiting)),
			actions: []action{{key: "enter", label: "review set", run: func() tea.Cmd { return push(reviewSetPage(server)) }}},
		})
	}
	for _, t := range d.Tools {
		tool := t.Tool
		note := classText(t.Class)
		if t.Class == adminapi.ClassSensitive && t.Status == adminapi.StatusApproved && !t.Usable {
			note += stWarn.Render("  not served until cleared")
		}
		rows = append(rows, row{
			text:    cols(toolCols, vis(t.Tool), toolStatusText(t), note),
			actions: []action{{key: "enter", label: "review", run: func() tea.Cmd { return push(toolPage(server, tool)) }}},
		})
	}
	return rows, nil
}

// ---- one tool's review

func toolPage(server, tool string) *page {
	return newPage(vis(tool), func(e env) content { return fillTool(e, server, tool) })
}

func fillTool(e env, server, tool string) content {
	var c content
	rv, err := e.op.ReviewTool(ctx(), server, tool)
	if err != nil {
		c.problems = append(c.problems, errText(err))
	}
	t := rv.Tool
	if t.Server == "" {
		return c
	}
	sensitive := t.Class == adminapi.ClassSensitive
	cleared := t.SensitiveClearedHash != "" && t.SensitiveClearedHash == t.ApprovedHash
	kv := func(k, v string) row { return textRow(cols([]int{14}, stDim.Render(k), v)) }
	c.rows = append(c.rows,
		heading(vis(t.Server+"."+t.Tool)),
		kv("Status", toolStatusText(t)),
		kv("Class", classText(t.Class)),
		kv("Fingerprint", vis(t.ObservedHash)),
		kv("Approved", vis(dash(t.ApprovedHash))))
	if sensitive {
		state := stWarn.Render("no: approval alone does not serve a sensitive tool")
		if cleared {
			state = stOK.Render("yes, at the approved fingerprint")
		}
		c.rows = append(c.rows, kv("Cleared", state))
	}
	c.rows = append(c.rows, callableRows(rv.CallableBy, sensitive)...)

	shown := err == nil && rv.Observed.Kept
	c.rows = append(c.rows, blank())
	if !shown {
		c.rows = append(c.rows, textRow(stBad.Render("The observed definition was not kept, so it cannot be shown and is not approved from here.")))
	} else {
		c.rows = append(c.rows, definitionRows(rv.Observed)...)
		if len(rv.Diff) > 0 {
			c.rows = append(append(c.rows, blank(), heading("Changes since the approved definition")), diffRows(rv.Diff)...)
		}
	}

	fp := t.ObservedHash
	if shown && t.Status != adminapi.StatusApproved {
		c.actions = append(c.actions, action{key: "a", label: "approve", run: func() tea.Cmd {
			// The fingerprint sent is the one this read showed; the backend
			// refuses it if the tool advertises another by now.
			return confirm("Approve "+vis(server+"."+tool)+" at fingerprint "+vis(fp)+"?", func() tea.Cmd {
				return do(func() result {
					res, err := e.op.ApproveTool(ctx(), adminapi.ApproveRequest{Server: server, Tool: tool, Fingerprint: fp})
					return fromAction(res.ActionResult, err, "Approved "+server+"."+tool+".")
				})
			})
		}})
	}
	if t.Status == adminapi.StatusApproved {
		c.actions = append(c.actions, action{key: "v", label: "revoke", run: func() tea.Cmd {
			return confirm("Revoke "+vis(server+"."+tool)+"? It returns to pending and is no longer served.", func() tea.Cmd {
				return do(func() result {
					res, err := e.op.RevokeTool(ctx(), adminapi.ToolRef{Server: server, Tool: tool})
					return fromAction(res.ActionResult, err, "Revoked "+server+"."+tool+".")
				})
			})
		}})
	}
	if sensitive && t.Status == adminapi.StatusApproved && !cleared && e.caps().Manages && e.has(adminapi.FeatureToolClear) {
		c.actions = append(c.actions, action{key: "c", label: "clear", run: func() tea.Cmd {
			return confirm("Clear "+vis(server+"."+tool)+" for serving at its approved fingerprint "+vis(t.ApprovedHash)+"?", func() tea.Cmd {
				return do(func() result {
					res, err := e.op.ClearTool(ctx(), adminapi.ToolRef{Server: server, Tool: tool})
					r := fromAction(res.ActionResult, err, "Cleared "+server+"."+tool+".")
					if err == nil && len(res.ClearedBy) > 0 {
						var roles []string
						for _, cb := range res.ClearedBy {
							roles = append(roles, cb.Role)
						}
						r.output = append(r.output, "Reached by: "+strings.Join(roles, ", "))
					}
					return r
				})
			})
		}})
	}
	return c
}

// callableRows are the roles that reach the tool once approved -- or, for a
// sensitive tool, once cleared: the backend already narrowed the list to
// what the gateway will serve (design/adr/0048).
func callableRows(cov []adminapi.RoleCoverage, sensitive bool) []row {
	if len(cov) == 0 {
		msg := "No role could call it once approved."
		if sensitive {
			msg = "No role could call it once cleared: only a role marked non_read that names it can."
		}
		return []row{textRow(cols([]int{14}, stDim.Render("Callable by"), stWarn.Render(msg)))}
	}
	var rows []row
	for i, c := range cov {
		label := ""
		if i == 0 {
			label = "Callable by"
		}
		how := vis(c.Role) + stDim.Render("  "+vis(c.How))
		if c.Wildcard {
			how += stWarn.Render("  through a wildcard")
		}
		if c.NonRead {
			how += stDim.Render("  non_read")
		}
		rows = append(rows, textRow(cols([]int{14}, stDim.Render(label), how)))
	}
	return rows
}

// definitionRows draws the definition's canonical form, the text the
// fingerprint covers, from the segments the backend computed from the raw
// bytes; a hidden code point is counted above it.
func definitionRows(d adminapi.Definition) []row {
	rows := []row{heading("Definition")}
	if d.HiddenCodePoints > 0 {
		rows = append(rows, textRow(stBad.Render(fmt.Sprintf("%d hidden code points in this definition, marked below.", d.HiddenCodePoints))))
	}
	for _, l := range d.Lines {
		rows = append(rows, segmentRows(strings.Repeat("  ", max(0, l.Depth)), l.Segments)...)
	}
	return rows
}

func diffRows(diff []adminapi.DiffLine) []row {
	var rows []row
	for _, d := range diff {
		indent := strings.Repeat("  ", max(0, d.Depth))
		switch d.Op {
		case adminapi.DiffGap:
			rows = append(rows, textRow(stDim.Render("...")))
		case adminapi.DiffAdd:
			rows = append(rows, textRow(stOK.Render("+ ")+indent+segments(d.Segments)))
		case adminapi.DiffDel:
			rows = append(rows, textRow(stBad.Render("- ")+indent+segments(d.Segments)))
		case adminapi.DiffContext:
			rows = append(rows, textRow("  "+indent+segments(d.Segments)))
		default:
			rows = append(rows, textRow(stWarn.Render("? ")+indent+segments(d.Segments)))
		}
	}
	return rows
}

// ---- a whole backend's review set (FeatureToolReviewSet, design/adr/0043)

func reviewSetPage(server string) *page {
	return newPage("Review set", func(e env) content { return fillReviewSet(e, server) })
}

func fillReviewSet(e env, server string) content {
	var c content
	rs, err := e.op.ReviewToolSet(ctx(), server)
	if err != nil {
		c.problems = append(c.problems, errText(err))
		return c
	}
	c.rows = append(c.rows, heading(fmt.Sprintf("%s: %d pending, %d changed", vis(server), rs.Pending, rs.Changed)))
	if rs.HiddenCodePoints > 0 {
		c.rows = append(c.rows, textRow(stBad.Render(fmt.Sprintf("%d hidden code points across these definitions, marked below.", rs.HiddenCodePoints))))
	}
	approvable := rs.Approvable
	for _, rv := range rs.Tools {
		c.rows = append(c.rows, blank(), heading(vis(rv.Tool.Tool)+"  "+toolStatusText(rv.Tool)+"  "+classText(rv.Tool.Class)),
			textRow(stDim.Render("fingerprint "+vis(rv.Tool.ObservedHash))))
		if !rv.Observed.Kept {
			// A definition the screen cannot draw is not approved from it.
			approvable = false
			c.rows = append(c.rows, textRow(stBad.Render("Not kept: cannot be shown.")))
			continue
		}
		for _, l := range rv.Observed.Lines {
			c.rows = append(c.rows, segmentRows("  "+strings.Repeat("  ", max(0, l.Depth)), l.Segments)...)
		}
	}
	if !approvable {
		if rs.Reason != "" {
			c.rows = append(c.rows, blank(), textRow(stWarn.Render("Not approvable as a set: "+vis(rs.Reason))))
		}
		return c
	}
	manifest := rs.Manifest
	n := len(rs.Tools)
	c.actions = append(c.actions, action{key: "A", label: "approve all", run: func() tea.Cmd {
		// The manifest names exactly the set shown; the backend approves all
		// of it or nothing.
		return confirm(fmt.Sprintf("Approve all %d tools of %s shown here (manifest %s)?", n, vis(server), vis(manifest)), func() tea.Cmd {
			return do(func() result {
				res, err := e.op.ApproveToolSet(ctx(), adminapi.ApproveSetRequest{Server: server, Manifest: manifest})
				r := fromAction(res.ActionResult, err, fmt.Sprintf("Approved %d tools of %s.", len(res.Approved), server))
				r.back = err == nil
				return r
			})
		})
	}})
	return c
}
