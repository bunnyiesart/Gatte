package gatteweb

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
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
