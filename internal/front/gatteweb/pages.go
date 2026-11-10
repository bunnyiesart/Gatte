package gatteweb

import (
	"fmt"
	"net/http"
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
