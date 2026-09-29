package gatteweb

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// ---- overview

type overviewData struct {
	Attention           []adminapi.Attention
	Approved, Upstreams int
	Blocked             int
	Denied              []adminapi.AuditRecord
}

func (f *Front) overview(w http.ResponseWriter, r *http.Request) {
	ov, err := f.op.Overview(r.Context())
	d := overviewData{Attention: ov.Attention, Approved: ov.Counts.ApprovedUsable, Upstreams: ov.Counts.Upstreams,
		Blocked: ov.Counts.Blocked, Denied: ov.RecentDenied}
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	for _, p := range ov.Problems {
		errs = append(errs, p.Part+": "+p.Message)
	}
	f.render(w, "overview", "Overview", page{Data: d, Error: strings.Join(errs, "\n")})
}

// ---- tools

type toolsData struct {
	Show   string
	Tools  []adminapi.Tool
	Counts map[string]int
}

func (f *Front) toolsPage(w http.ResponseWriter, r *http.Request) {
	show := r.URL.Query().Get("show")
	if show != "review" && show != "approved" {
		show = ""
	}
	list, err := f.op.ListTools(r.Context(), "", show)
	d := toolsData{Show: show, Tools: list.Tools,
		Counts: map[string]int{"all": list.Counts.All, "review": list.Counts.Review, "approved": list.Counts.Approved}}
	f.render(w, "tools", "Tools", page{Data: d, Error: errText(err)})
}

// toolReview is the review page's content, drawn from the segments the
// backend computed from the raw bytes (design/adr/0040 §3): the page never
// re-reads escaped text, where a literal \u{202E} and a real U+202E would
// look the same.
type toolReview struct {
	Server, Tool string
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
}

// reviewLine is one drawn line of review text, classed for colour.
type reviewLine struct {
	Class string
	HTML  template.HTML
}

func (f *Front) toolShowPage(w http.ResponseWriter, r *http.Request) {
	server, tool := r.URL.Query().Get("server"), r.URL.Query().Get("tool")
	rv, err := f.op.ReviewTool(r.Context(), server, tool)
	var d toolReview
	if rv.Tool.Server != "" {
		// The fingerprint in the form is the one this read showed, and the
		// backend refuses the approval if the tool advertises another by
		// the time the form is sent.
		d = toolReview{Server: rv.Tool.Server, Tool: rv.Tool.Tool, Status: rv.Tool.Status, Usable: rv.Tool.Usable,
			Fingerprint: rv.Tool.ObservedHash, Approved: rv.Tool.ApprovedHash, Output: rv.ReviewText}
	}
	if err == nil && rv.Observed.Kept {
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
	f.render(w, "tool", frontkit.VisibleText(server+"."+tool), page{Nav: "tools", Data: d, Error: errText(err)})
}

// splitLines cuts segments at each line feed, which the backend sends as a
// hidden U+000A: a description keeps its own line breaks.
func splitLines(segs []adminapi.Segment) [][]adminapi.Segment {
	out := [][]adminapi.Segment{{}}
	for _, s := range segs {
		if s.Kind == adminapi.SegmentHidden && s.CodePoint == "U+000A" {
			out = append(out, []adminapi.Segment{})
			continue
		}
		out[len(out)-1] = append(out[len(out)-1], s)
	}
	return out
}

// plain is a line's text when it is all text, and false when it holds a
// hidden code point or a bad byte.
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

// schemaBlock is the schema under label in a definition's lines, as the
// review shows it: the backend's indented JSON, one drawn line each.
// Empty when the definition declares none.
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

// diffLines draws the backend's hunks as `tool show` prints a diff: "+ "
// or "- " before a changed line, the definition's indentation, and an
// ellipsis where unchanged lines were left out.
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

func (f *Front) toolApprove(w http.ResponseWriter, r *http.Request) {
	server, tool, fp := r.PostForm.Get("server"), r.PostForm.Get("tool"), r.PostForm.Get("fingerprint")
	res, err := f.op.ApproveTool(r.Context(), adminapi.ApproveRequest{Server: server, Tool: tool, Fingerprint: fp})
	f.showResult(w, "tools", "Approve "+frontkit.VisibleText(server+"."+tool), "/tools", actionResult(res.ActionResult, err))
}

func (f *Front) toolRevoke(w http.ResponseWriter, r *http.Request) {
	server, tool := r.PostForm.Get("server"), r.PostForm.Get("tool")
	res, err := f.op.RevokeTool(r.Context(), adminapi.ToolRef{Server: server, Tool: tool})
	f.showResult(w, "tools", "Revoke "+frontkit.VisibleText(server+"."+tool), "/tools", actionResult(res.ActionResult, err))
}

// ---- access

func (f *Front) accessPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.ListBlocks(r.Context())
	f.render(w, "access", "Access", page{Data: list.Blocks, Error: errText(err)})
}

func (f *Front) accessBlock(w http.ResponseWriter, r *http.Request)   { f.accessChange(w, r, true) }
func (f *Front) accessUnblock(w http.ResponseWriter, r *http.Request) { f.accessChange(w, r, false) }

// accessChange blocks or unblocks. The backend validates the subject and
// the reason, and tags the row [ui] from the client's front name.
func (f *Front) accessChange(w http.ResponseWriter, r *http.Request, block bool) {
	req := adminapi.BlockRequest{Subject: r.PostForm.Get("subject"), Reason: strings.TrimSpace(r.PostForm.Get("reason"))}
	verb := "Unblock"
	call := f.op.UnblockSubject
	if block {
		verb, call = "Block", f.op.BlockSubject
	}
	res, err := call(r.Context(), req)
	f.showResult(w, "access", verb+" "+frontkit.VisibleText(req.Subject), "/access", actionResult(res.ActionResult, err))
}

// ---- audit

type auditData struct {
	Records []adminapi.AuditRecord
	Subject string
	Outcome string
	Limit   int
}

func (f *Front) auditPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := auditData{Subject: q.Get("subject"), Outcome: q.Get("outcome"), Limit: auditLimit}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		d.Limit = min(n, maxAuditLimit)
	}
	switch d.Outcome {
	case adminapi.OutcomeAllowed, adminapi.OutcomeDenied, adminapi.OutcomeFailed:
	default:
		d.Outcome = ""
	}
	p, err := f.op.ListAudit(r.Context(), adminapi.AuditQuery{Limit: d.Limit, Subject: d.Subject, Outcome: d.Outcome})
	d.Records = p.Records
	f.render(w, "audit", "Audit trail", page{Data: d, Error: errText(err)})
}

func (f *Front) auditVerify(w http.ResponseWriter, r *http.Request) {
	res, err := f.op.VerifyAudit(r.Context(), adminapi.VerifyRequest{ExpectHead: strings.TrimSpace(r.PostForm.Get("expect_head"))})
	f.showResult(w, "audit", "Verify the audit chain", "/audit", verifyResult(res, err))
}

// verifyResult says whether the chain holds and, when a head was given,
// whether it is the one expected.
func verifyResult(v adminapi.VerifyResult, err error) result {
	if err != nil {
		text := errText(err)
		return result{Summary: firstLine(text), Output: text}
	}
	var out []string
	switch {
	case v.Empty:
		out = append(out, "The audit trail is empty.")
	case v.FirstBreak != nil:
		out = append(out, fmt.Sprintf("BROKEN at position %d of %d records.", v.FirstBreak.Position, v.Count))
	default:
		out = append(out, fmt.Sprintf("Intact: %d records.", v.Count))
	}
	out = append(out, "head sha256:"+v.Head)
	if v.RetroactivelyChained > 0 {
		out = append(out, fmt.Sprintf("%d records written before the chain existed were chained afterwards.", v.RetroactivelyChained))
	}
	if v.SIEM != nil {
		out = append(out, "SIEM copy: "+v.SIEM.Path)
	}
	out = append(out, v.Messages...)
	ok := v.Intact && (v.HeadMatches == nil || *v.HeadMatches)
	r := result{OK: ok, Summary: "Done.", Output: strings.Join(out, "\n")}
	if !ok {
		r.Summary = out[0]
		if v.Intact {
			r.Summary = "TRUNCATED OR REWRITTEN: the head does not match the expected value."
		}
	}
	return r
}

// ---- upstreams and quota (read-only: registering and signing stay in
// the terminal, because signing needs root's key)

func (f *Front) upstreamsPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.ListUpstreams(r.Context())
	f.render(w, "upstreams", "Backends", page{Data: list.Upstreams, Error: errText(err)})
}

func (f *Front) quotaPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.QuotaUsage(r.Context(), adminapi.QuotaQuery{})
	f.render(w, "quota", "Quota", page{Data: list.Usage, Error: errText(err)})
}
