package gatteweb

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// ---- overview

type overviewData struct {
	Attention           []adminapi.Attention
	Approved, Upstreams int
	Blocked             int
	Denied              []adminapi.AuditRecord
	// Health is what the backend answered with feature backend_health,
	// nil from an older backend or when it could not be read.
	Health *adminapi.Health
	// Reload is the Reload the configuration button: FeatureConsoleManages
	// and FeatureServeControl.
	Reload bool
}

func (f *Front) overview(w http.ResponseWriter, r *http.Request) {
	ov, err := f.op.Overview(r.Context())
	d := overviewData{Attention: ov.Attention, Approved: ov.Counts.ApprovedUsable, Upstreams: ov.Counts.Upstreams,
		Blocked: ov.Counts.Blocked, Denied: ov.RecentDenied, Health: ov.Health}
	if me, werr := f.op.WhoAmI(r.Context()); werr == nil {
		d.Reload = slices.Contains(me.Features, adminapi.FeatureConsoleManages) && slices.Contains(me.Features, adminapi.FeatureServeControl)
	}
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	for _, p := range ov.Problems {
		errs = append(errs, p.Part+": "+p.Message)
	}
	f.render(w, r, "overview", "Overview", page{Data: d, Error: strings.Join(errs, "\n")})
}

// ---- tools

type toolsData struct {
	Show string
	// Server is the backend the list is filtered to, "" for all.
	Server string
	Tools  []adminapi.Tool
	Counts map[string]int
	// Backends is every backend with a tool, and how many of its tools
	// wait for review.
	Backends []backendChip
	// ReviewSet is the backend serving feature tool_review_set.
	ReviewSet bool
}

type backendChip struct {
	Name   string
	Review int
}

func (f *Front) toolsPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	show, server := q.Get("show"), q.Get("server")
	if show != "review" && show != "approved" {
		show = ""
	}
	// The filter is the backend's (listTools takes server); the whole list
	// is read only to name the backends.
	all, err := f.op.ListTools(r.Context(), "", "")
	list := all
	if err == nil && (server != "" || show != "") {
		list, err = f.op.ListTools(r.Context(), server, show)
	}
	d := toolsData{Show: show, Server: server, Tools: list.Tools,
		Counts: map[string]int{"all": list.Counts.All, "review": list.Counts.Review, "approved": list.Counts.Approved}}
	for _, t := range all.Tools {
		if n := len(d.Backends); n == 0 || d.Backends[n-1].Name != t.Server {
			d.Backends = append(d.Backends, backendChip{Name: t.Server})
		}
		if t.Status != adminapi.StatusApproved {
			d.Backends[len(d.Backends)-1].Review++
		}
	}
	if me, werr := f.op.WhoAmI(r.Context()); werr == nil {
		d.ReviewSet = slices.Contains(me.Features, adminapi.FeatureToolReviewSet)
	}
	f.render(w, r, "tools", "Tools", page{Data: d, Error: errText(err)})
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
	// Sensitive is the tool's class (design/adr/0048): approval is not
	// enough to serve it. Cleared says it is cleared at the approved
	// fingerprint; CanClear that this console offers the button
	// (FeatureConsoleManages and FeatureToolClear).
	Sensitive, Cleared, CanClear bool
}

// reviewLine is one drawn line of review text, classed for colour.
type reviewLine struct {
	Class string
	HTML  template.HTML
}

func (f *Front) toolShowPage(w http.ResponseWriter, r *http.Request) {
	server, tool := r.URL.Query().Get("server"), r.URL.Query().Get("tool")
	f.showTool(w, r, server, tool, "")
}

// showTool renders the review page of server.tool, with notice above it
// when an action led here.
func (f *Front) showTool(w http.ResponseWriter, r *http.Request, server, tool, notice string) {
	rv, err := f.op.ReviewTool(r.Context(), server, tool)
	d := reviewOf(rv, err == nil)
	if d.Sensitive {
		d.CanClear = f.feature(r.Context(), adminapi.FeatureConsoleManages) && f.feature(r.Context(), adminapi.FeatureToolClear)
	}
	f.render(w, r, "tool", frontkit.VisibleText(server+"."+tool), page{Nav: "tools", Data: d, Notice: notice, Error: errText(err)})
}

// reviewOf is the page's view of one review. ok is whether the read
// succeeded; a failed one still shows what it carried.
func reviewOf(rv adminapi.ToolReview, ok bool) toolReview {
	var d toolReview
	if rv.Tool.Server != "" {
		// The fingerprint in the form is the one this read showed, and the
		// backend refuses the approval if the tool advertises another by
		// the time the form is sent.
		d = toolReview{Server: rv.Tool.Server, Tool: rv.Tool.Tool, Status: rv.Tool.Status, Usable: rv.Tool.Usable,
			Fingerprint: rv.Tool.ObservedHash, Approved: rv.Tool.ApprovedHash, Output: rv.ReviewText,
			Sensitive: rv.Tool.Class == adminapi.ClassSensitive,
			Cleared:   rv.Tool.SensitiveClearedHash != "" && rv.Tool.SensitiveClearedHash == rv.Tool.ApprovedHash}
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

// reviewSetData is one backend's review set as the page shows it: every
// definition, and the manifest the one button sends.
type reviewSetData struct {
	Server           string
	Manifest         string
	Tools            []toolReview
	Pending, Changed int
	Hidden           int
	Approvable       bool
	Reason           string
}

func (f *Front) reviewSetPage(w http.ResponseWriter, r *http.Request) {
	server := r.URL.Query().Get("server")
	rs, err := f.op.ReviewToolSet(r.Context(), server)
	d := reviewSetData{Server: rs.Server, Manifest: rs.Manifest, Pending: rs.Pending, Changed: rs.Changed,
		Hidden: rs.HiddenCodePoints, Reason: rs.Reason}
	if err == nil {
		d.Approvable = rs.Approvable
		for _, rv := range rs.Tools {
			t := reviewOf(rv, true)
			// A definition the page cannot draw is not approved from it.
			d.Approvable = d.Approvable && t.Shown
			d.Tools = append(d.Tools, t)
		}
	}
	f.render(w, r, "reviewset", "Review "+frontkit.VisibleText(server), page{Nav: "tools", Data: d, Error: errText(err)})
}

func (f *Front) toolApproveSet(w http.ResponseWriter, r *http.Request) {
	server, manifest := r.PostForm.Get("server"), r.PostForm.Get("manifest")
	res, err := f.op.ApproveToolSet(r.Context(), adminapi.ApproveSetRequest{Server: server, Manifest: manifest})
	f.showResult(w, r, "tools", "Approve the tools of "+frontkit.VisibleText(server), "/tools?server="+url.QueryEscape(server), actionResult(res.ActionResult, err))
}

// splitLines cuts segments at each line feed, which the backend sends as a
// hidden U+000A: a description keeps its own line breaks.
func splitLines(segs []adminapi.Segment) [][]adminapi.Segment { return frontkit.SplitLines(segs) }

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

// toolApprove approves one tool and, when that went through and was
// recorded, opens the next tool waiting for review -- of the same backend
// first -- with the backend's answer above it. A refusal, an unrecorded
// change or an empty queue is the result page, as for any action.
func (f *Front) toolApprove(w http.ResponseWriter, r *http.Request) {
	server, tool, fp := r.PostForm.Get("server"), r.PostForm.Get("tool"), r.PostForm.Get("fingerprint")
	res, err := f.op.ApproveTool(r.Context(), adminapi.ApproveRequest{Server: server, Tool: tool, Fingerprint: fp})
	out := actionResult(res.ActionResult, err)
	if out.OK {
		if next, ok := f.nextToReview(r, server, tool); ok {
			notice := out.Output + "\nNext waiting for review: " + next.Server + "." + next.Tool + "."
			f.showTool(w, r, next.Server, next.Tool, notice)
			return
		}
	}
	f.showResult(w, r, "tools", "Approve "+frontkit.VisibleText(server+"."+tool), "/tools", out)
}

// nextToReview is the first tool waiting for review other than the one
// just approved: the same backend's first, then any backend's.
func (f *Front) nextToReview(r *http.Request, server, tool string) (adminapi.Tool, bool) {
	for _, s := range []string{server, ""} {
		list, err := f.op.ListTools(r.Context(), s, "review")
		if err != nil {
			return adminapi.Tool{}, false
		}
		for _, t := range list.Tools {
			if t.Server != server || t.Tool != tool {
				return t, true
			}
		}
	}
	return adminapi.Tool{}, false
}

func (f *Front) toolRevoke(w http.ResponseWriter, r *http.Request) {
	server, tool := r.PostForm.Get("server"), r.PostForm.Get("tool")
	res, err := f.op.RevokeTool(r.Context(), adminapi.ToolRef{Server: server, Tool: tool})
	f.showResult(w, r, "tools", "Revoke "+frontkit.VisibleText(server+"."+tool), "/tools", actionResult(res.ActionResult, err))
}

// ---- access

// accessData is the Access page: the blocklist, and whether the backend
// takes an end for a block (feature block_until, design/adr/0046).
type accessData struct {
	Blocks []adminapi.Block
	Until  bool
}

func (f *Front) accessPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.ListBlocks(r.Context())
	d := accessData{Blocks: list.Blocks}
	if me, werr := f.op.WhoAmI(r.Context()); werr == nil {
		d.Until = slices.Contains(me.Features, adminapi.FeatureBlockUntil)
	}
	f.render(w, r, "access", "Access", page{Data: d, Error: errText(err)})
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
		if v := strings.TrimSpace(r.PostForm.Get("until")); v != "" {
			until, err := blockEnd(v, time.Now())
			if err != nil {
				f.showResult(w, r, "access", verb+" "+frontkit.VisibleText(req.Subject), "/access", result{Summary: err.Error(), Output: err.Error()})
				return
			}
			req.Until = &until
		}
	}
	res, err := call(r.Context(), req)
	f.showResult(w, r, "access", verb+" "+frontkit.VisibleText(req.Subject), "/access", actionResult(res.ActionResult, err))
}

// blockEnd reads the Access form's end: a duration from now ("8h") or a
// time as the audit filters take it. The backend refuses one that is not
// in the future.
func blockEnd(v string, now time.Time) (time.Time, error) {
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(d).UTC(), nil
	}
	t, err := formTime("Until", v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%v, or a duration such as 8h", err)
	}
	return t, nil
}

// ---- audit

func (f *Front) auditVerify(w http.ResponseWriter, r *http.Request) {
	res, err := f.op.VerifyAudit(r.Context(), adminapi.VerifyRequest{ExpectHead: strings.TrimSpace(r.PostForm.Get("expect_head"))})
	f.showResult(w, r, "audit", "Verify the audit chain", "/audit", verifyResult(res, err))
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

// ---- quota (read-only)

func (f *Front) quotaPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.QuotaUsage(r.Context(), adminapi.QuotaQuery{})
	f.render(w, r, "quota", "Quota", page{Data: list.Usage, Error: errText(err)})
}
