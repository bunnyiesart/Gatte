package gatteweb

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// This file is the Tools slice (design/adr/0051): the server-detail panel that
// lists a backend's tools, and the per-tool review and the approve / revoke /
// clear / review-set / approve-set actions, all scoped to one backend's own
// path. It holds no rule of its own: every decision — a tool stays pending
// until approved, approval binds to the fingerprint shown, a sensitive tool
// needs clear plus a non_read role — is the backend's (design/adr/0047/0048,
// 0040 §3, 0032). The pages render what the backend answers and confirm before
// sending.

// ---- the detail-page panel

// toolsPanelView is the per-server Tools panel: the backend's own tools, how
// many wait for review, and whether this console can offer the one-page review
// of the set (FeatureToolReviewSet). CanClear is whether the per-tool menu
// offers Clear (FeatureConsoleManages and FeatureToolClear).
type toolsPanelView struct {
	Base       string
	CSRF       string
	ServerPath string
	Tools      []toolRow
	Review     int
	Sensitive  int
	ReviewSet  bool
	CanClear   bool
}

// toolRow is one tool as the panel lists it. NotServed marks an approved
// sensitive tool that is not yet cleared, so the panel never implies approval
// alone makes a sensitive tool callable (design/adr/0048).
type toolRow struct {
	Name      string
	Status    string
	UpdatedAt time.Time
	Path      string
	Sensitive bool
	NotServed bool
}

// toolsPanel renders the Tools panel for one backend. It reads the backend's
// tools from the detail the shell already fetched (UpstreamDetail.Tools), so
// the panel costs no extra call. Each row's actions sit in a <details> menu
// (design/adr/0061 §5); Approve opens the review page, because an approval
// binds to the definition the operator was shown (design/adr/0040 §3).
func (f *Front) toolsPanel(r *http.Request, d adminapi.UpstreamDetail) (template.HTML, error) {
	me, _ := f.op.WhoAmI(r.Context())
	has := func(name string) bool { return slices.Contains(me.Features, name) }
	v := toolsPanelView{
		Base:       f.kit.Base(),
		CSRF:       f.kit.CSRFToken(),
		ServerPath: serverBack(d.Name),
		ReviewSet:  has(adminapi.FeatureToolReviewSet),
		CanClear:   has(adminapi.FeatureConsoleManages) && has(adminapi.FeatureToolClear),
	}
	for _, t := range d.Tools {
		row := toolRow{Name: t.Tool, Status: t.Status, UpdatedAt: t.UpdatedAt,
			Path: toolPath(t.Server, t.Tool), Sensitive: t.Class == adminapi.ClassSensitive}
		if t.Status != adminapi.StatusApproved {
			v.Review++
		}
		row.NotServed = row.Sensitive && t.Status == adminapi.StatusApproved && !t.Usable
		if row.Sensitive {
			v.Sensitive++
		}
		v.Tools = append(v.Tools, row)
	}
	var b bytes.Buffer
	if err := f.pages.ExecuteTemplate(&b, "tools_panel.html", v); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil // #nosec G203 -- the template's own escaped output
}

// toolPath is a tool's own path under its backend, each segment escaped so a
// name with a slash or a space still routes.
func toolPath(server, tool string) string {
	return serverBack(server) + "/tools/" + url.PathEscape(tool)
}

// ---- the per-tool review page

// toolReview is the review page's content, drawn from the segments the backend
// computed from the raw bytes (design/adr/0040 §3): the page never re-reads
// escaped text, where a literal \u{202E} and a real U+202E would look the same.
type toolReview struct {
	Server, Tool string
	Path         string
	ServerPath   string
	Status       string
	Usable       bool
	Fingerprint  string
	Approved     string
	Shown        bool
	Description  []reviewLine
	InputSchema  template.HTML
	OutputSchema template.HTML
	Hidden       int
	Diff         []reviewLine
	Output       string
	// Sensitive is the tool's class (design/adr/0048): approval is not enough
	// to serve it. Cleared says it is cleared at the approved fingerprint;
	// CanClear that this console offers the button (FeatureConsoleManages and
	// FeatureToolClear).
	Sensitive, Cleared, CanClear bool
	// Callable are the roles that can reach the tool once it is approved — or,
	// for a sensitive tool, once it is cleared: only roles marked non_read that
	// name it (design/adr/0048). Empty means no role could reach it.
	Callable []roleCoverage
}

// roleCoverage is one role that can call the tool, as RoleCoverage carries it.
type roleCoverage struct {
	Role     string
	How      string
	NonRead  bool
	Wildcard bool
}

// reviewLine is one drawn line of review text, classed for colour.
type reviewLine struct {
	Class string
	HTML  template.HTML
}

func (f *Front) serverToolReview(w http.ResponseWriter, r *http.Request) {
	f.showServerTool(w, r, r.PathValue("name"), r.PathValue("tool"), "")
}

// showServerTool renders the review page of server.tool, with notice above it
// when an action led here.
func (f *Front) showServerTool(w http.ResponseWriter, r *http.Request, server, tool, notice string) {
	rv, err := f.op.ReviewTool(r.Context(), server, tool)
	d := reviewOf(rv, err == nil)
	if d.Server == "" {
		// A tool the backend does not know: keep the path so the page can link
		// back and name what was asked for.
		d.Server, d.Tool, d.Path, d.ServerPath = server, tool, toolPath(server, tool), serverBack(server)
	}
	if d.Sensitive {
		d.CanClear = f.feature(r.Context(), adminapi.FeatureConsoleManages) && f.feature(r.Context(), adminapi.FeatureToolClear)
	}
	f.render(w, r, "server_tool", frontkit.VisibleText(server+"."+tool), page{Nav: "servers", Data: d, Notice: notice, Error: errText(err)})
}

// reviewOf is the page's view of one review. ok is whether the read succeeded;
// a failed one still shows what it carried.
func reviewOf(rv adminapi.ToolReview, ok bool) toolReview {
	var d toolReview
	if rv.Tool.Server != "" {
		// The fingerprint in the form is the one this read showed, and the
		// backend refuses the approval if the tool advertises another by the
		// time the form is sent.
		d = toolReview{Server: rv.Tool.Server, Tool: rv.Tool.Tool, Path: toolPath(rv.Tool.Server, rv.Tool.Tool), ServerPath: serverBack(rv.Tool.Server),
			Status: rv.Tool.Status, Usable: rv.Tool.Usable,
			Fingerprint: rv.Tool.ObservedHash, Approved: rv.Tool.ApprovedHash, Output: rv.ReviewText,
			Sensitive: rv.Tool.Class == adminapi.ClassSensitive,
			Cleared:   rv.Tool.SensitiveClearedHash != "" && rv.Tool.SensitiveClearedHash == rv.Tool.ApprovedHash}
		for _, c := range rv.CallableBy {
			d.Callable = append(d.Callable, roleCoverage{Role: c.Role, How: c.How, NonRead: c.NonRead, Wildcard: c.Wildcard})
		}
	}
	if ok && rv.Observed.Kept {
		d.Shown = true
		d.Hidden = rv.Observed.HiddenCodePoints
		if rv.Observed.Description != nil {
			for _, segs := range splitLines(rv.Observed.Description.Segments) {
				d.Description = append(d.Description, reviewLine{HTML: frontkit.DrawSegments(segs)})
			}
		}
		d.InputSchema = schemaBlock(rv.Observed.Lines, "input schema:")
		d.OutputSchema = schemaBlock(rv.Observed.Lines, "output schema:")
		d.Diff = diffLines(rv.Diff)
	}
	return d
}

func (f *Front) serverToolApprove(w http.ResponseWriter, r *http.Request) {
	server, tool, fp := r.PathValue("name"), r.PathValue("tool"), r.PostForm.Get("fingerprint")
	res, err := f.op.ApproveTool(r.Context(), adminapi.ApproveRequest{Server: server, Tool: tool, Fingerprint: fp})
	out := actionResult(res.ActionResult, err)
	if out.OK {
		// Open the next tool of this backend still waiting for review, so a
		// run of approvals stays on one backend.
		if next, ok := f.nextServerToReview(r, server, tool); ok {
			notice := out.Output + "\nNext waiting for review: " + next.Server + "." + next.Tool + "."
			f.showServerTool(w, r, next.Server, next.Tool, notice)
			return
		}
	}
	f.showResult(w, r, "servers", "Approve "+frontkit.VisibleText(server+"."+tool), serverBack(server), out)
}

// nextServerToReview is the first tool of the same backend waiting for review
// other than the one just approved.
func (f *Front) nextServerToReview(r *http.Request, server, tool string) (adminapi.Tool, bool) {
	list, err := f.op.ListTools(r.Context(), server, "review")
	if err != nil {
		return adminapi.Tool{}, false
	}
	for _, t := range list.Tools {
		if t.Server != server || t.Tool != tool {
			return t, true
		}
	}
	return adminapi.Tool{}, false
}

func (f *Front) serverToolRevoke(w http.ResponseWriter, r *http.Request) {
	server, tool := r.PathValue("name"), r.PathValue("tool")
	res, err := f.op.RevokeTool(r.Context(), adminapi.ToolRef{Server: server, Tool: tool})
	f.showResult(w, r, "servers", "Revoke "+frontkit.VisibleText(server+"."+tool), serverBack(server), actionResult(res.ActionResult, err))
}

// serverToolClear clears an approved sensitive tool for serving at its approved
// fingerprint (design/adr/0048). The backend requires a non_read role that
// names the tool and refuses otherwise; this console only forwards the request
// and, on success, names the roles that now reach it.
func (f *Front) serverToolClear(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureToolClear) {
		return
	}
	server, tool := r.PathValue("name"), r.PathValue("tool")
	res, err := f.op.ClearTool(r.Context(), adminapi.ToolRef{Server: server, Tool: tool})
	out := actionResult(res.ActionResult, err)
	if err == nil && len(res.ClearedBy) > 0 {
		var roles []string
		for _, c := range res.ClearedBy {
			roles = append(roles, c.Role)
		}
		out.Output = strings.TrimSpace(out.Output + "\nReached by: " + strings.Join(roles, ", "))
	}
	f.showResult(w, r, "servers", "Clear "+frontkit.VisibleText(server+"."+tool), toolPath(server, tool), out)
}

// ---- the review-set page (FeatureToolReviewSet)

// reviewSetData is one backend's review set as the page shows it: every
// definition, and the manifest the one button sends.
type reviewSetData struct {
	Server           string
	ServerPath       string
	Manifest         string
	Tools            []toolReview
	Pending, Changed int
	Hidden           int
	Approvable       bool
	Reason           string
}

func (f *Front) serverToolReviewSet(w http.ResponseWriter, r *http.Request) {
	server := r.PathValue("name")
	rs, err := f.op.ReviewToolSet(r.Context(), server)
	d := reviewSetData{Server: rs.Server, ServerPath: serverBack(server), Manifest: rs.Manifest,
		Pending: rs.Pending, Changed: rs.Changed, Hidden: rs.HiddenCodePoints, Reason: rs.Reason}
	if d.Server == "" {
		d.Server = server
	}
	if err == nil {
		d.Approvable = rs.Approvable
		for _, rv := range rs.Tools {
			t := reviewOf(rv, true)
			// A definition the page cannot draw is not approved from it.
			d.Approvable = d.Approvable && t.Shown
			d.Tools = append(d.Tools, t)
		}
	}
	f.render(w, r, "server_toolset", "Review "+frontkit.VisibleText(server), page{Nav: "servers", Data: d, Error: errText(err)})
}

func (f *Front) serverToolApproveSet(w http.ResponseWriter, r *http.Request) {
	server, manifest := r.PathValue("name"), r.PostForm.Get("manifest")
	res, err := f.op.ApproveToolSet(r.Context(), adminapi.ApproveSetRequest{Server: server, Manifest: manifest})
	f.showResult(w, r, "servers", "Approve the tools of "+frontkit.VisibleText(server), serverBack(server), actionResult(res.ActionResult, err))
}

// ---- drawing helpers (shared by the review page and the review-set page)

// splitLines cuts segments at each line feed, which the backend sends as a
// hidden U+000A: a description keeps its own line breaks.
func splitLines(segs []adminapi.Segment) [][]adminapi.Segment { return frontkit.SplitLines(segs) }

// plain is a line's text when it is all text, and false when it holds a hidden
// code point or a bad byte.
func plain(segs []adminapi.Segment) (string, bool) {
	var b strings.Builder
	for _, s := range segs {
		if s.Kind != adminapi.SegmentText {
			return "", false
		}
		b.WriteString(s.Text)
	}
	return b.String(), true
}

// schemaBlock is the schema under label in a definition's lines, as the review
// shows it: the backend's indented JSON, one drawn line each. Empty when the
// definition declares none.
func schemaBlock(lines []adminapi.ReviewLine, label string) template.HTML {
	var out []string
	in := false
	for _, l := range lines {
		if l.Depth == 0 {
			text, ok := plain(l.Segments)
			in = ok && text == label
			continue
		}
		if in {
			out = append(out, string(frontkit.DrawSegments(l.Segments)))
		}
	}
	return template.HTML(strings.Join(out, "\n")) // #nosec G203 -- each line is DrawSegments' escaped HTML
}

// diffLines draws the backend's hunks as `tool show` prints a diff: "+ " or
// "- " before a changed line, the definition's indentation, and an ellipsis
// where unchanged lines were left out.
func diffLines(diff []adminapi.DiffLine) []reviewLine {
	var out []reviewLine
	for _, d := range diff {
		mark, class := "  ", ""
		switch d.Op {
		case adminapi.DiffGap:
			out = append(out, reviewLine{Class: "gap", HTML: "…"})
			continue
		case adminapi.DiffAdd:
			mark, class = "+ ", "add"
		case adminapi.DiffDel:
			mark, class = "- ", "del"
		case adminapi.DiffContext:
		default:
			// An operation this front does not know is still shown, marked.
			mark, class = "? ", "warn"
		}
		prefix := template.HTMLEscapeString(mark + strings.Repeat("  ", max(0, d.Depth)))
		out = append(out, reviewLine{Class: class, HTML: template.HTML(prefix) + frontkit.DrawSegments(d.Segments)}) // #nosec G203 -- both parts escaped
	}
	return out
}
