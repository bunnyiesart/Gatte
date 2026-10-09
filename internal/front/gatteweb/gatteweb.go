// Package gatteweb is the Gatte web front: the operator console as pages in
// a browser (design/adr/0036), as a client of the management API
// (design/adr/0040 §6).
//
// It holds no rule. Every list, every review and every action is a call of
// pkg/adminapi to `mcp-gateway admin`, over the operator socket and, for
// the account pages, the accounts socket; what a page shows after an
// action is what the backend answered. Approving only the fingerprint
// shown, the operator row of every change, the groups an account may get
// and the one-time password all live there, so a second front cannot
// forget one.
//
// What the front adds is the defence a page on loopback needs, and it
// takes all of it from pkg/frontkit: the loopback bind and Host check, the
// one-time login link and the session bound to the path and a cookie, the
// form token and Origin check on every POST, and the headers (no script,
// no framing, no caching). It serves through kit.Serve and nothing else,
// and imports nothing of Gatte but those two packages; a fitness test
// holds it to both (internal/fitness/front_test.go).
package gatteweb

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

//go:embed ui/*.html ui/*.css
var assets embed.FS

// FrontName is the [ui] tag the backend writes in this front's operator
// rows.
const FrontName = "ui"

// auditLimit is how many of the newest audit records the audit page shows
// when the operator asks for no other number, and maxAuditLimit the most
// it asks the backend for (which holds the same bound).
const (
	auditLimit    = 200
	maxAuditLimit = 5000
)

// Options is what a front is built from.
type Options struct {
	// Operator is a client of the operator socket. Required.
	Operator *adminapi.Client
	// Accounts is a client of the accounts socket, nil when the console
	// does not edit accounts: the account pages then do not exist (404).
	Accounts *adminapi.Client
	// Kit is the browser boundary the front serves through. Required.
	Kit *frontkit.Kit
}

// Front is the Gatte web console.
type Front struct {
	op    *adminapi.Client
	acc   *adminapi.Client
	kit   *frontkit.Kit
	pages *template.Template
	css   []byte
}

// New parses the pages and builds the front.
func New(o Options) (*Front, error) {
	if o.Operator == nil || o.Kit == nil {
		return nil, errors.New("gatteweb: an operator client and a frontkit.Kit are required")
	}
	pages, err := template.New("").Funcs(template.FuncMap{
		"vis":     frontkit.VisibleText,
		"vistext": visibleLines,
		"segs":    frontkit.DrawSegments,
		"time":    showTime,
		"short":   shortHash,
		"image":   shortImage,
		"imgname": imageName,
		"imgdig":  imageDigest,
		"dash":    dash,
		"initial": initial,
		"dict":    dict,
		"sub":     func(a, b int) int { return a - b },
		"state":   stateLabel,
		"since":   showTimePtr,
		"formend": formUntil,
	}).ParseFS(assets, "ui/*.html")
	if err != nil {
		return nil, fmt.Errorf("gatteweb: templates: %w", err)
	}
	css, err := assets.ReadFile("ui/app.css")
	if err != nil {
		return nil, err
	}
	return &Front{op: o.Operator, acc: o.Accounts, kit: o.Kit, pages: pages, css: css}, nil
}

// Serve serves the console through the kit until the kit is shut down.
func (f *Front) Serve() error { return f.kit.Serve(f.routes()) }

func (f *Front) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", f.overview)
	mux.HandleFunc("GET /tools", f.toolsPage)
	mux.HandleFunc("GET /tools/show", f.toolShowPage)
	mux.HandleFunc("POST /tools/approve", f.toolApprove)
	mux.HandleFunc("GET /tools/review-set", f.reviewSetPage)
	mux.HandleFunc("POST /tools/approve-set", f.toolApproveSet)
	mux.HandleFunc("POST /tools/revoke", f.toolRevoke)
	mux.HandleFunc("GET /access", f.accessPage)
	mux.HandleFunc("POST /access/block", f.accessBlock)
	mux.HandleFunc("POST /access/unblock", f.accessUnblock)
	mux.HandleFunc("GET /audit", f.auditPage)
	mux.HandleFunc("GET /audit/export", f.auditExport)
	mux.HandleFunc("POST /audit/verify", f.auditVerify)
	mux.HandleFunc("GET /people", f.peoplePage)
	mux.HandleFunc("GET /people/account", f.accountPage)
	mux.HandleFunc("GET /people/new", f.newPersonPage)
	mux.HandleFunc("GET /people/new/access", f.newPersonPage)
	mux.HandleFunc("GET /people/new/review", f.newPersonPage)
	mux.HandleFunc("GET /people/connect", f.connectPage)
	mux.HandleFunc("GET /people/connect/script", f.connectScript)
	mux.HandleFunc("POST /people/add", f.accountAdd)
	mux.HandleFunc("POST /people/groups", f.accountGroups)
	mux.HandleFunc("POST /people/disable", f.accountDisable)
	mux.HandleFunc("POST /people/enable", f.accountEnable)
	mux.HandleFunc("POST /people/reset", f.accountReset)
	mux.HandleFunc("POST /people/offboard", f.accountOffboard)
	mux.HandleFunc("POST /people/delete", f.accountDelete)
	mux.HandleFunc("GET /upstreams", f.upstreamsPage)
	mux.HandleFunc("POST /upstreams/maintenance/on", f.maintenanceOn)
	mux.HandleFunc("POST /upstreams/maintenance/off", f.maintenanceOff)
	mux.HandleFunc("GET /quota", f.quotaPage)
	// design/adr/0050: each answers 404 unless the backend lists
	// FeatureConsoleManages (and, for root's, the console has -manage-users).
	mux.HandleFunc("POST /upstreams/register", f.upstreamRegister)
	mux.HandleFunc("GET /upstreams/show", f.upstreamShowPage)
	mux.HandleFunc("POST /upstreams/sign", f.upstreamSign)
	mux.HandleFunc("POST /upstreams/redial", f.upstreamRedial)
	mux.HandleFunc("POST /upstreams/remove", f.upstreamRemove)
	mux.HandleFunc("POST /tools/clear", f.toolClear)
	mux.HandleFunc("POST /reload", f.reload)
	mux.HandleFunc("GET /serve-requests", f.serveRequestPage)
	mux.HandleFunc("GET /secrets", f.secretsPage)
	mux.HandleFunc("POST /secrets/set", f.secretSet)
	mux.HandleFunc("POST /secrets/delete", f.secretDelete)
	mux.HandleFunc("GET /roles", f.rolesPage)
	mux.HandleFunc("POST /roles", f.rolesApply)
	mux.HandleFunc("GET /app.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(f.css)
	})
	return mux
}

// page is what every template receives.
type page struct {
	Title string
	Nav   string
	Base  string
	CSRF  string
	// Manages is the backend listing FeatureConsoleManages
	// (design/adr/0050), and Root the console holding the accounts socket
	// (-manage-users): together they decide the navigation's Secrets and
	// Roles entries.
	Manages bool
	Root    bool
	// Notice is what the backend answered to the action that led here,
	// when the page shown next is not its result page.
	Notice string
	Error  string
	Data   any
}

// render executes the template named tmpl. p.Nav, when empty, is tmpl: the
// page highlights its own entry in the navigation.
func (f *Front) render(w http.ResponseWriter, r *http.Request, tmpl, title string, p page) {
	if p.Nav == "" {
		p.Nav = tmpl
	}
	p.Title, p.CSRF, p.Base = title, f.kit.CSRFToken(), f.kit.Base()
	p.Manages, p.Root = f.feature(r.Context(), adminapi.FeatureConsoleManages), f.acc != nil
	var b bytes.Buffer
	if err := f.pages.ExecuteTemplate(&b, tmpl+".html", p); err != nil {
		http.Error(w, "rendering: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}

// errText is what a page says about a failed call: the backend's own
// sentence for a refusal, and that it did not answer otherwise.
func errText(err error) string {
	if err == nil {
		return ""
	}
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae.Message
	}
	if errors.Is(err, adminapi.ErrImpostor) {
		return err.Error()
	}
	return "The management API did not answer: " + err.Error()
}

// result is the page after an action: one plain sentence saying what
// happened, and what the backend said, kept one click away.
type result struct {
	OK      bool
	Summary string
	Output  string
	Back    string
	// Secret is a one-time password to hand over, shown on this page only:
	// never logged, never kept, never in a URL.
	Secret    string
	SecretFor string
	// SecretName is the person's display name, for the handover heading.
	SecretName string
	// Connect, after adding a person or resetting their password, is how
	// they connect their computer.
	Connect *connectPanel
	// Remaining is what the operator still has to do by hand, as the
	// backend said it (an offboard, design/adr/0046).
	Remaining []string
	// Refresh, for a request to the gateway process still pending, is the
	// page that reads it again (no script refreshes anything).
	Refresh string
}

// actionResult is the result page of a state change. A change the trail
// could not record is shown as made and unrecorded: it is in force, and
// the operator has to know the trail lacks it.
func actionResult(res adminapi.ActionResult, err error) result {
	if err != nil {
		text := errText(err)
		return result{Summary: firstLine(text), Output: text}
	}
	var out []string
	out = append(out, res.Messages...)
	for _, w := range res.Warnings {
		out = append(out, w.Message)
	}
	r := result{OK: true, Summary: "Done.", Output: strings.Join(out, "\n")}
	if res.Changed && !res.Recorded {
		why := "the audit trail could not record it"
		for _, w := range res.Warnings {
			if w.Code == adminapi.WarnAuditWriteFailed {
				why += ": " + w.Message
			}
		}
		r.OK, r.Summary = false, "The change was made, but "+why
	}
	return r
}

func (r result) withBack(back string) result { r.Back = back; return r }

func (f *Front) showResult(w http.ResponseWriter, r *http.Request, nav, title, back string, res result) {
	f.render(w, r, "result", title, page{Nav: nav, Data: res.withBack(f.kit.Base() + back)})
}

func firstLine(text string) string {
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// visibleLines makes the hidden code points of a block of text visible,
// line by line: the line breaks are the block's own structure, and every
// other hidden code point inside a line is shown as \u{XXXX}.
func visibleLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = frontkit.VisibleText(l)
	}
	return strings.Join(lines, "\n")
}

const timeLayout = "2006-01-02 15:04:05Z"

func showTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(timeLayout)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// shortHash abbreviates a fingerprint for a caption; the full value is on
// the same page.
func shortHash(h string) string {
	const shown = 12
	if len(h) <= shown {
		return dash(h)
	}
	return h[:shown] + "..."
}

// shortImage is an image reference as a table shows it: the repository and
// the first 12 hex digits of a sha256 digest. The page puts the full
// reference in the cell's title.
func shortImage(ref string) string {
	name, digest, ok := strings.Cut(ref, "@sha256:")
	if !ok || len(digest) <= 12 {
		return ref
	}
	return name + "@sha256:" + digest[:12] + "…"
}

// imageName and imageDigest split what shortImage joins, so a narrow cell
// can put the repository and the digest on their own lines.
func imageName(ref string) string {
	name, _, _ := strings.Cut(shortImage(ref), "@")
	return name
}

func imageDigest(ref string) string {
	_, digest, ok := strings.Cut(shortImage(ref), "@")
	if !ok {
		return ""
	}
	return digest
}

// initial is the letter an account's avatar shows.
func initial(names ...string) string {
	for _, n := range names {
		for _, r := range strings.TrimSpace(n) {
			return strings.ToUpper(string(r))
		}
	}
	return "?"
}

// dict builds a map from key, value pairs, so a template can hand a
// partial more than one value.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict: odd number of arguments")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, errors.New("dict: keys must be strings")
		}
		m[k] = kv[i+1]
	}
	return m, nil
}
