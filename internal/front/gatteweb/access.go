package gatteweb

// The Blocklist section of the Users tab (design/adr/0051): the subjects the
// gateway refuses, and the block/unblock actions, on the operator socket
// (design/adr/0031).
//
// Blocking a subject is not disabling an account (design/adr/0038): a block
// cuts off an already-issued token, so the gateway refuses the subject's next
// request whatever token they hold; disabling an account only stops new
// sign-ins, and lives in the People section. Both exist, distinctly.

import (
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// blocklistData is the Blocklist section: the blocked subjects, and whether
// the backend takes an end for a block (feature block_until, design/adr/0046).
type blocklistData struct {
	Base   string
	CSRF   string
	Blocks []adminapi.Block
	Until  bool
	// Error is a failed read of the blocklist, shown inline. The block and
	// unblock forms still render, so the control stays usable through a
	// transient read failure.
	Error string
}

// blocklistSection renders the Blocklist into the Users page. It reads what it
// needs itself; a failed read is shown inline and leaves the forms in place,
// rather than dropping the whole section and with it the way to block someone.
func (f *Front) blocklistSection(r *http.Request) (template.HTML, error) {
	d := blocklistData{Base: f.kit.Base(), CSRF: f.kit.CSRFToken()}
	if list, err := f.op.ListBlocks(r.Context()); err != nil {
		d.Error = errText(err)
	} else {
		d.Blocks = list.Blocks
	}
	if me, werr := f.op.WhoAmI(r.Context()); werr == nil {
		d.Until = slices.Contains(me.Features, adminapi.FeatureBlockUntil)
	}
	return f.renderFragment("section_access.html", d)
}

func (f *Front) accessBlock(w http.ResponseWriter, r *http.Request)   { f.accessChange(w, r, true) }
func (f *Front) accessUnblock(w http.ResponseWriter, r *http.Request) { f.accessChange(w, r, false) }

// accessChange blocks or unblocks. The backend validates the subject and the
// reason, and tags the row [ui] from the client's front name. The result page
// returns to the Users tab, where the Blocklist section lives.
func (f *Front) accessChange(w http.ResponseWriter, r *http.Request, block bool) {
	req := adminapi.BlockRequest{Subject: r.PostForm.Get("subject"), Reason: strings.TrimSpace(r.PostForm.Get("reason"))}
	verb := "Unblock"
	call := f.op.UnblockSubject
	if block {
		verb, call = "Block", f.op.BlockSubject
		if v := strings.TrimSpace(r.PostForm.Get("until")); v != "" {
			until, err := blockEnd(v, time.Now())
			if err != nil {
				f.showResult(w, r, "users", verb+" "+frontkit.VisibleText(req.Subject), "/users", result{Summary: err.Error(), Output: err.Error()})
				return
			}
			req.Until = &until
		}
	}
	res, err := call(r.Context(), req)
	f.showResult(w, r, "users", verb+" "+frontkit.VisibleText(req.Subject), "/users", actionResult(res.ActionResult, err))
}

// formTime reads a time field: RFC 3339, or a date or a date and minute
// taken as UTC, which the page says. Empty is no bound.
func formTime(label, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%s %q: use 2026-09-30, 2026-09-30 14:00 (UTC) or 2026-09-30T14:00:00Z", label, frontkit.VisibleText(v))
}

// blockEnd reads the block form's end: a duration from now ("8h") or a time
// (formTime). The backend refuses one that is not in the future.
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
