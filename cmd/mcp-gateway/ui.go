// Operator Console -- "ui": the same console as a page in a browser, on
// loopback (design/adr/0036-console-web-local.md).
//
// Every action on the page is the CLI command of the same name, run in
// this process against the same opEnv: approve is runToolApproveFingerprint,
// block is runAccessBlock, and so on. The page adds no rule and skips none;
// what it shows after an action is what the command printed. That is the
// whole design: a second implementation of "approve" would be a second
// place for the fingerprint check to be forgotten.
//
// What the page must add is the defence a terminal never needed. A server
// on 127.0.0.1 is reachable from every website the operator has open: any
// origin can POST a form to it, and a hostname the attacker controls can
// be rebound to it. So, in the order a request meets them:
//
//   - the bind is loopback, refused otherwise (as serve's, ADR-0011);
//   - Host must name loopback, which defeats DNS rebinding;
//   - the printed /login?token=... link works once. It opens a session:
//     a random session id that every later URL carries as its first path
//     segment (/s/ID/...) and that an HttpOnly, SameSite=Strict cookie
//     carries too. Both must match, and the session ends after
//     uiSessionLifetime. The path matters because cookies are not
//     isolated by port: a page some other process serves on another
//     localhost port is "same site", and the browser hands it the cookie.
//     It never learns the path;
//   - every POST carries the per-run form token and, when the browser
//     sends an Origin, that Origin is this page's own;
//   - state changes only on POST, and no page carries a script
//     (Content-Security-Policy default-src 'none').

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

//go:embed ui/*.html ui/*.css
var uiAssets embed.FS

// uiCookieName carries the session id.
const uiCookieName = "gatte_ui"

// uiSessionLifetime is how long one login lasts. Long enough for a shift;
// after it, restart `mcp-gateway ui` for a new link.
const uiSessionLifetime = 12 * time.Hour

// uiMaxAuditLimit bounds the audit page. The whole trail is read for any
// limit (runAudit); what this bounds is one render holding mu.
const uiMaxAuditLimit = 5000

// uiDefaultListen is not serve's 8080, so both can run side by side.
const uiDefaultListen = "127.0.0.1:8090"

// uiAuditLimit is how many of the newest audit records the audit page
// shows when the operator asks for no other number.
const uiAuditLimit = 200

// uiMaxForm bounds a POST body. Every form here is a few short fields.
const uiMaxForm = 64 << 10

// uiServer is the web console. One per `mcp-gateway ui` process.
type uiServer struct {
	base     *opEnv
	operator string
	token    string
	csrf     string
	pages    *template.Template
	css      []byte
	now      func() time.Time

	// accounts is the IdP's account store, set only in the root
	// -manage-users mode (ui_people.go). Nil means the account pages are
	// read-only or absent.
	accounts idp.Directory
	// ownDB, when set, is the database path whose owner every action
	// restores (keepDBOwner): a root console must not leave root-owned
	// SQLite files the service cannot write.
	ownDB string

	// The one session the login link opens. sessMu guards the three.
	sessMu    sync.Mutex
	loginUsed bool
	session   string
	expires   time.Time

	// mu serialises the console commands. Each one writes to the opEnv's
	// stdout and stderr, which are per request here, but the commands were
	// written for a process that runs one of them; running them one at a
	// time keeps that true.
	mu sync.Mutex
}

// newUIServer checks listen and builds the console. token is the secret
// the operator's browser must present; operator is the name operator
// actions are attributed to (operatorName, as for the CLI).
func newUIServer(base *opEnv, listen, operator, token string) (*uiServer, error) {
	if !config.IsLoopbackAddr(listen) {
		return nil, fmt.Errorf("-listen %q is not a loopback address. The web console has the operator's powers and "+
			"terminates no TLS; it binds 127.0.0.1, ::1 or localhost only, and is reached from elsewhere through "+
			"ssh -L (design/adr/0036)", listen)
	}
	if _, port, err := net.SplitHostPort(listen); err != nil || port == "" {
		return nil, fmt.Errorf("-listen %q is not a host:port address", listen)
	}
	if len(token) < 32 {
		return nil, errors.New("ui: the access token is too short")
	}
	csrf, err := uiRandomToken()
	if err != nil {
		return nil, err
	}
	pages, err := template.New("").Funcs(template.FuncMap{
		"vis":     visible.Escape,
		"vistext": uiEscapeText,
		"time":    opTime,
		"short":   opShortHash,
		"dash":    opDash,
		"lines":   uiReviewLines,
		"initial": uiInitial,
	}).ParseFS(uiAssets, "ui/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: templates: %w", err)
	}
	css, err := uiAssets.ReadFile("ui/app.css")
	if err != nil {
		return nil, err
	}
	return &uiServer{base: base, operator: operator, token: token, csrf: csrf, pages: pages, css: css, now: time.Now}, nil
}

func uiRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ui: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Handler is the whole console: routes behind the checks every request
// passes.
func (s *uiServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /tools", s.toolsPage)
	mux.HandleFunc("GET /tools/show", s.toolShowPage)
	mux.HandleFunc("POST /tools/approve", s.toolApprove)
	mux.HandleFunc("POST /tools/revoke", s.toolRevoke)
	mux.HandleFunc("GET /access", s.accessPage)
	mux.HandleFunc("POST /access/block", s.accessBlock)
	mux.HandleFunc("POST /access/unblock", s.accessUnblock)
	mux.HandleFunc("GET /audit", s.auditPage)
	mux.HandleFunc("POST /audit/verify", s.auditVerify)
	mux.HandleFunc("GET /people", s.peoplePage)
	mux.HandleFunc("GET /people/account", s.accountPage)
	mux.HandleFunc("POST /people/add", s.accountAdd)
	mux.HandleFunc("POST /people/groups", s.accountGroups)
	mux.HandleFunc("POST /people/disable", s.accountDisable)
	mux.HandleFunc("POST /people/enable", s.accountEnable)
	mux.HandleFunc("POST /people/reset", s.accountReset)
	mux.HandleFunc("GET /upstreams", s.upstreamsPage)
	mux.HandleFunc("GET /quota", s.quotaPage)
	mux.HandleFunc("GET /app.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(s.css)
	})
	return s.guard(mux)
}

// guard applies, to every request, the checks in the file comment.
func (s *uiServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")

		if !uiLoopbackHost(r.Host) {
			http.Error(w, "forbidden: this console answers only on a loopback name (localhost, 127.0.0.1, ::1)", http.StatusForbidden)
			return
		}

		if r.URL.Path == "/login" {
			s.login(w, r)
			return
		}
		rest, ok := s.authenticate(r)
		if !ok {
			http.Error(w, "unauthorized: open the /login link `mcp-gateway ui` printed when it started. "+
				"It works once; for a new session, restart mcp-gateway ui", http.StatusUnauthorized)
			return
		}
		r.URL.Path = rest
		r.URL.RawPath = ""

		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, uiMaxForm)
			if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, "http://"+r.Host) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
			if err := r.ParseForm(); err != nil || !uiEqual(r.PostForm.Get("csrf"), s.csrf) {
				http.Error(w, "forbidden: missing or wrong form token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate checks the session in the path and in the cookie, and
// returns the path with the /s/ID prefix removed.
func (s *uiServer) authenticate(r *http.Request) (string, bool) {
	s.sessMu.Lock()
	sess, exp := s.session, s.expires
	s.sessMu.Unlock()
	if sess == "" || !s.now().Before(exp) {
		return "", false
	}
	prefix := "/s/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return "", false
	}
	id, rest, _ := strings.Cut(r.URL.Path[len(prefix):], "/")
	if !uiEqual(id, sess) {
		return "", false
	}
	c, err := r.Cookie(uiCookieName)
	if err != nil || !uiEqual(c.Value, sess) {
		return "", false
	}
	return "/" + rest, true
}

// base is the path prefix of every link in this session.
func (s *uiServer) basePath() string {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	return "/s/" + s.session
}

// login trades the printed token, once, for a session, then drops the
// token from the address bar. A second use is refused: the link can sit in
// browser history, scrollback or a terminal log.
func (s *uiServer) login(w http.ResponseWriter, r *http.Request) {
	s.sessMu.Lock()
	if r.Method != http.MethodGet || s.loginUsed || !uiEqual(r.URL.Query().Get("token"), s.token) {
		s.sessMu.Unlock()
		http.Error(w, "unauthorized: wrong, missing or already used login token. For a new session, restart mcp-gateway ui", http.StatusUnauthorized)
		return
	}
	sess, err := uiRandomToken()
	if err != nil {
		s.sessMu.Unlock()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.loginUsed, s.session, s.expires = true, sess, s.now().Add(uiSessionLifetime)
	s.sessMu.Unlock()
	// Not Secure: the page is plain http on loopback (TLS would need a
	// certificate for localhost), and not every browser sends a Secure
	// cookie to http://localhost. HttpOnly and SameSite=Strict are what
	// this cookie relies on; gosec's G124 flags the missing flag.
	http.SetCookie(w, &http.Cookie{
		Name: uiCookieName, Value: sess, Path: "/s/" + sess + "/",
		MaxAge:   int(uiSessionLifetime / time.Second),
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/s/"+sess+"/", http.StatusSeeOther)
}

// uiLoopbackHost reports whether a Host header names loopback. The port
// is not compared: an ssh -L tunnel may use any local port.
func uiLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func uiEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// uiRun runs one console command against a copy of the base opEnv whose
// output lands in buffers.
func (s *uiServer) uiRun(fn func(*opEnv) int) (stdout, stderr string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out, errb bytes.Buffer
	e := *s.base
	e.stdout, e.stderr = &out, &errb
	// Loaded for every action, as a CLI command loads it for every run:
	// this process may live for hours, and grants, signers and quota
	// budgets change in the file.
	if e.configPath != "" {
		cfg, ok := loadConfig(e.configPath, &errb)
		if !ok {
			return out.String(), errb.String(), exitCannotRun
		}
		e.cfg = cfg
	}
	code = fn(&e)
	if s.ownDB != "" {
		if err := keepDBOwner(s.ownDB); err != nil {
			fmt.Fprintf(&errb, "\n%v\n", err)
		}
	}
	return out.String(), errb.String(), code
}

// uiJSON runs a -json list command and decodes what it printed. The list
// commands exit 1 on an empty list, which is not an error here.
func uiJSON[T any](s *uiServer, fn func(*opEnv) int) (T, string) {
	var v T
	out, errText, code := s.uiRun(fn)
	if code == exitCannotRun || strings.TrimSpace(out) == "" {
		return v, strings.TrimSpace(errText)
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return v, "decoding the command's output: " + err.Error()
	}
	return v, strings.TrimSpace(errText)
}

// page is what every template receives.
type page struct {
	Title  string
	Nav    string
	Base   string
	CSRF   string
	Config string
	Error  string
	Data   any
}

// render executes the template named tmpl. p.Nav, when empty, is tmpl:
// the page highlights its own entry in the navigation.
func (s *uiServer) render(w http.ResponseWriter, tmpl, title string, p page) {
	if p.Nav == "" {
		p.Nav = tmpl
	}
	p.Title, p.CSRF, p.Config, p.Base = title, s.csrf, s.base.configPath, s.basePath()
	var b bytes.Buffer
	if err := s.pages.ExecuteTemplate(&b, tmpl+".html", p); err != nil {
		http.Error(w, "rendering: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b.Bytes())
}

// result is the page after an action: one plain sentence saying what
// happened, and what the command printed, kept one click away.
type result struct {
	OK      bool
	Summary string
	Output  string
	Back    string
	// Secret is a one-time password to hand over, shown on this page only:
	// never logged, never recorded, never stored in plain text.
	Secret    string
	SecretFor string
}

func uiResult(stdout, stderr string, code int) result {
	out := strings.TrimRight(stdout, "\n")
	if e := strings.TrimRight(stderr, "\n"); e != "" {
		if out != "" {
			out += "\n\n"
		}
		out += e
	}
	summary := "Done."
	if code != exitOK {
		// The command's own first line says why; the rest is one click away.
		summary = uiFirstLine(stderr)
		if summary == "" {
			summary = uiFirstLine(stdout)
		}
	}
	return result{OK: code == exitOK, Summary: summary, Output: out}
}

func (r result) withBack(back string) result { r.Back = back; return r }

func (s *uiServer) showResult(w http.ResponseWriter, nav, action, back, stdout, stderr string, code int) {
	s.render(w, "result", action, page{Nav: nav, Data: uiResult(stdout, stderr, code).withBack(s.basePath() + back)})
}

func uiFirstLine(text string) string {
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// ---- overview

type overviewData struct {
	Attention           []uiAttention
	Approved, Upstreams int
	Blocked             int
	Denied              []auditJSON
}

// uiAttention is one row of "Needs attention": something only an operator
// can resolve, with the page that resolves it.
type uiAttention struct {
	Kind   string // changed, pending, unsigned
	Title  string
	Detail string
	Server string
	Tool   string
}

type uiLever struct {
	N            int
	Server, Tool string
	Status       string
	Usable       bool
	ObservedHash string
	UpdatedAt    time.Time
}

func uiLevers(tools []toolJSON) []uiLever {
	out := make([]uiLever, len(tools))
	for i, t := range tools {
		out[i] = uiLever{N: i + 1, Server: t.Server, Tool: t.Tool, Status: t.Status, Usable: t.Usable,
			ObservedHash: t.ObservedHash, UpdatedAt: t.UpdatedAt}
	}
	return out
}

func (s *uiServer) overview(w http.ResponseWriter, r *http.Request) {
	var d overviewData
	var errs []string
	tools, e1 := uiJSON[[]toolJSON](s, func(e *opEnv) int { return runToolList(e, "", true) })
	var pending []uiAttention
	for _, t := range tools {
		switch quarantine.Status(t.Status) {
		case quarantine.StatusChanged:
			d.Attention = append(d.Attention, uiAttention{Kind: "changed", Title: t.Server + "." + t.Tool,
				Detail: "Changed since it was approved. Not served until reviewed.", Server: t.Server, Tool: t.Tool})
		case quarantine.StatusPending:
			pending = append(pending, uiAttention{Kind: "pending", Title: t.Server + "." + t.Tool,
				Detail: "New tool, waiting for review.", Server: t.Server, Tool: t.Tool})
		default:
			if t.Usable {
				d.Approved++
			}
		}
	}
	d.Attention = append(d.Attention, pending...)
	ups, e2 := uiJSON[[]upstreamJSON](s, func(e *opEnv) int { return runUpstreamList(e, true) })
	d.Upstreams = len(ups)
	for _, u := range ups {
		if u.Signature != "yes" {
			d.Attention = append(d.Attention, uiAttention{Kind: "unsigned", Title: u.Name,
				Detail: "Backend not signed, so none of its tools are served. Sign it in the terminal."})
		}
	}
	blocks, e3 := uiJSON[[]accessBlockJSON](s, func(e *opEnv) int { return runAccessList(e, true) })
	d.Blocked = len(blocks)
	denied, e4 := uiJSON[[]auditJSON](s, func(e *opEnv) int {
		return runAudit(e, auditFilter{Limit: 5, Outcome: audit.OutcomeDenied}, true)
	})
	d.Denied = denied
	for _, e := range []string{e1, e2, e3, e4} {
		if e != "" && !strings.HasPrefix(e, "No ") {
			errs = append(errs, e)
		}
	}
	s.render(w, "overview", "Overview", page{Data: d, Error: strings.Join(errs, "\n")})
}

// ---- tools

type toolsData struct {
	Show   string
	Tools  []uiLever
	Counts map[string]int
}

func (s *uiServer) toolsPage(w http.ResponseWriter, r *http.Request) {
	tools, errText := uiJSON[[]toolJSON](s, func(e *opEnv) int { return runToolList(e, "", true) })
	d := toolsData{Show: r.URL.Query().Get("show"), Counts: map[string]int{}}
	for _, t := range uiLevers(tools) {
		review := t.Status != string(quarantine.StatusApproved)
		if review {
			d.Counts["review"]++
		} else {
			d.Counts["approved"]++
		}
		if d.Show == "review" && !review || d.Show == "approved" && review {
			continue
		}
		d.Tools = append(d.Tools, t)
	}
	if d.Show != "review" && d.Show != "approved" {
		d.Show = ""
	}
	d.Counts["all"] = len(tools)
	s.render(w, "tools", "Tools", page{Data: d, Error: errText})
}

// toolReview is the review page's content, built from the stored
// definitions rather than from `tool show`'s text, which stays one click
// away as Output.
type toolReview struct {
	Server, Tool string
	Status       string
	Usable       bool
	Fingerprint  string
	Approved     string
	Shown        bool
	Description  []uiReviewLine
	InputSchema  string
	OutputSchema string
	Hidden       int
	Diff         []uiReviewLine
	Output       string
}

func (s *uiServer) toolShowPage(w http.ResponseWriter, r *http.Request) {
	server, tool := r.URL.Query().Get("server"), r.URL.Query().Get("tool")
	var rv toolReview
	_, errText, _ := s.uiRun(func(e *opEnv) int {
		t, code, ok := getForConsole(e, server, tool, "show")
		if !ok {
			return code
		}
		// The fingerprint in the form is the one this read showed, and
		// approve refuses if the tool advertises another by the time the
		// form is sent.
		rv = toolReview{Server: t.ServerName, Tool: t.ToolName, Status: string(t.Status), Usable: t.Usable(),
			Fingerprint: t.ObservedHash, Approved: t.ApprovedHash}
		var b bytes.Buffer
		rv.Shown = writeReview(e, &b, t)
		rv.Output = b.String()
		if !rv.Shown {
			return exitProblem
		}
		observed, err := e.tools().Definition(e.ctx(), t.ObservedHash)
		if err != nil {
			rv.Shown = false
			return exitProblem
		}
		obsLines, hidden := definitionLines(observed)
		rv.Hidden = hidden
		for _, l := range strings.Split(observed.Description, "\n") {
			rv.Description = append(rv.Description, uiReviewLine{Segs: uiSegments(visible.Escape(l))})
		}
		rv.InputSchema = uiSchema(observed.InputSchema)
		rv.OutputSchema = uiSchema(observed.OutputSchema)
		if t.ApprovedHash != "" && t.ApprovedHash != t.ObservedHash {
			if approved, err := e.tools().Definition(e.ctx(), t.ApprovedHash); err == nil {
				appLines, _ := definitionLines(approved)
				rv.Diff = uiDiffHunks(lineDiff(appLines, obsLines), 1)
			}
		}
		return exitOK
	})
	s.render(w, "tool", visible.Escape(server+"."+tool), page{Nav: "tools", Data: rv, Error: strings.TrimSpace(errText)})
}

// uiDiffHunks keeps the changed lines of a lineDiff and ctx unchanged
// lines around each, with a "gap" line where unchanged lines were left out:
// the review shows what changed, not the whole definition again.
func uiDiffHunks(diff []string, ctx int) []uiReviewLine {
	keep := make([]bool, len(diff))
	for i, l := range diff {
		if strings.HasPrefix(l, "+ ") || strings.HasPrefix(l, "- ") {
			for j := max(0, i-ctx); j <= min(len(diff)-1, i+ctx); j++ {
				keep[j] = true
			}
		}
	}
	var out []uiReviewLine
	gap := false
	for i, l := range diff {
		if !keep[i] {
			gap = true
			continue
		}
		if gap && len(out) > 0 {
			out = append(out, uiReviewLine{Class: "gap", Segs: []uiSeg{{Text: "…"}}})
		}
		gap = false
		c := ""
		switch {
		case strings.HasPrefix(l, "+ "):
			c = "add"
		case strings.HasPrefix(l, "- "):
			c = "del"
		}
		out = append(out, uiReviewLine{Class: c, Segs: uiSegments(l)})
	}
	// A label line ("input schema:") left as the last context line of a
	// hunk heads nothing; drop it.
	var trimmed []uiReviewLine
	for i, l := range out {
		last := i == len(out)-1 || out[i+1].Class == "gap"
		if last && l.Class == "" && len(l.Segs) == 1 && strings.HasSuffix(strings.TrimSpace(l.Segs[0].Text), ":") {
			continue
		}
		trimmed = append(trimmed, l)
	}
	if n := len(trimmed); n > 0 && trimmed[n-1].Class == "gap" {
		trimmed = trimmed[:n-1]
	}
	return trimmed
}

// uiSchema is a schema as the review shows it: indented JSON, every hidden
// code point escaped.
func uiSchema(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		return uiEscapeText(string(raw))
	}
	return uiEscapeText(b.String())
}

func (s *uiServer) toolApprove(w http.ResponseWriter, r *http.Request) {
	server, tool, fp := r.PostForm.Get("server"), r.PostForm.Get("tool"), r.PostForm.Get("fingerprint")
	out, errText, code := s.uiRun(func(e *opEnv) int { return runToolApproveFingerprint(e, server, tool, fp) })
	s.showResult(w, "tools", "Approve "+visible.Escape(server+"."+tool), "/tools", out, errText, code)
}

func (s *uiServer) toolRevoke(w http.ResponseWriter, r *http.Request) {
	server, tool := r.PostForm.Get("server"), r.PostForm.Get("tool")
	out, errText, code := s.uiRun(func(e *opEnv) int { return runToolRevoke(e, server, tool) })
	s.showResult(w, "tools", "Revoke "+visible.Escape(server+"."+tool), "/tools", out, errText, code)
}

// uiReviewLine is one line of `tool show` output, classed for colour, in
// segments: a hidden code point writeReview escaped as \u{XXXX} is its own
// segment, so the page can mark it as a thing and not as text.
type uiReviewLine struct {
	Class string
	Segs  []uiSeg
}

type uiSeg struct {
	Text   string
	Hidden bool
}

var uiEscapeMark = regexp.MustCompile(`\\(u\{[0-9A-F]{4,6}\}|x\{[0-9A-F]{2}\})`)

func uiSegments(l string) []uiSeg {
	var out []uiSeg
	last := 0
	for _, m := range uiEscapeMark.FindAllStringIndex(l, -1) {
		if m[0] > last {
			out = append(out, uiSeg{Text: l[last:m[0]]})
		}
		out = append(out, uiSeg{Text: l[m[0]:m[1]], Hidden: true})
		last = m[1]
	}
	if last < len(l) || len(out) == 0 {
		out = append(out, uiSeg{Text: l[last:]})
	}
	return out
}

// uiReviewLines classes the lines writeReview printed: its diff lines
// start with "+ " or "- " at column 0, block lines are indented, and its
// hidden code point warning starts with "WARNING".
func uiReviewLines(text string) []uiReviewLine {
	var out []uiReviewLine
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		c := ""
		switch {
		case strings.HasPrefix(l, "+ "):
			c = "add"
		case strings.HasPrefix(l, "- "):
			c = "del"
		case strings.HasPrefix(l, "WARNING"):
			c = "warn"
		case l != "" && l[0] != ' ':
			c = "head"
		}
		out = append(out, uiReviewLine{Class: c, Segs: uiSegments(l)})
	}
	return out
}

// ---- access

func (s *uiServer) accessPage(w http.ResponseWriter, r *http.Request) {
	blocks, errText := uiJSON[[]accessBlockJSON](s, func(e *opEnv) int { return runAccessList(e, true) })
	s.render(w, "access", "Access", page{Data: blocks, Error: errText})
}

func (s *uiServer) accessBlock(w http.ResponseWriter, r *http.Request)   { s.accessChange(w, r, true) }
func (s *uiServer) accessUnblock(w http.ResponseWriter, r *http.Request) { s.accessChange(w, r, false) }

// accessChange validates as the CLI's accessChange does, then runs the
// same command. The note says the action came from this page, because
// the operator row cannot otherwise tell a browser from a terminal.
func (s *uiServer) accessChange(w http.ResponseWriter, r *http.Request, block bool) {
	subject := r.PostForm.Get("subject")
	note := "[ui]"
	if reason := strings.TrimSpace(r.PostForm.Get("reason")); reason != "" {
		note += " " + reason
	}
	verb := "Unblock"
	if block {
		verb = "Block"
	}
	action := verb + " " + visible.Escape(subject)
	if err := access.ValidateSubject(subject); err != nil {
		s.showResult(w, "access", action, "/access", "", err.Error(), exitCannotRun)
		return
	}
	if err := access.ValidateBlock(access.Block{Subject: subject, Reason: note, By: "-", At: time.Now()}); err != nil {
		s.showResult(w, "access", action, "/access", "", err.Error(), exitCannotRun)
		return
	}
	out, errText, code := s.uiRun(func(e *opEnv) int {
		if block {
			return runAccessBlock(e, s.operator, subject, note)
		}
		return runAccessUnblock(e, s.operator, subject, note)
	})
	s.showResult(w, "access", action, "/access", out, errText, code)
}

// ---- audit

type auditData struct {
	Records []auditJSON
	Subject string
	Outcome string
	Limit   int
}

func (s *uiServer) auditPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := auditData{Subject: q.Get("subject"), Outcome: q.Get("outcome"), Limit: uiAuditLimit}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		d.Limit = min(n, uiMaxAuditLimit)
	}
	f := auditFilter{Limit: d.Limit, Subject: d.Subject}
	switch audit.Outcome(d.Outcome) {
	case audit.OutcomeAllowed, audit.OutcomeDenied, audit.OutcomeFailed:
		f.Outcome = audit.Outcome(d.Outcome)
	default:
		d.Outcome = ""
	}
	recs, errText := uiJSON[[]auditJSON](s, func(e *opEnv) int { return runAudit(e, f, true) })
	d.Records = recs
	s.render(w, "audit", "Audit trail", page{Data: d, Error: errText})
}

func (s *uiServer) auditVerify(w http.ResponseWriter, r *http.Request) {
	head := strings.TrimSpace(r.PostForm.Get("expect_head"))
	out, errText, code := s.uiRun(func(e *opEnv) int { return runAuditVerify(e, head) })
	s.showResult(w, "audit", "Verify the audit chain", "/audit", out, errText, code)
}

// ---- upstreams and quota (read-only: registering and signing stay in
// the terminal, because signing needs root's key)

func (s *uiServer) upstreamsPage(w http.ResponseWriter, r *http.Request) {
	ups, errText := uiJSON[[]upstreamJSON](s, func(e *opEnv) int { return runUpstreamList(e, true) })
	s.render(w, "upstreams", "Backends", page{Data: ups, Error: errText})
}

func (s *uiServer) quotaPage(w http.ResponseWriter, r *http.Request) {
	usage, errText := uiJSON[[]quotaUsageJSON](s, func(e *opEnv) int { return runQuotaUsage(e, quotaUsageFilter{}, true) })
	s.render(w, "quota", "Quota", page{Data: usage, Error: errText})
}

// ---- the command

func cmdUI(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("ui", stderr)
	listen := fs.String("listen", uiDefaultListen, "loopback address to serve the console on")
	manage := fs.Bool("manage-users", false, "also edit the identity provider's accounts ([idp] users_file); root only")
	if code, ok := opParse(fs, args, stdout, stderr, uiUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, uiUsage) {
		return exitCannotRun
	}
	operator, err := operatorName()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	token, err := uiRandomToken()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		s, err := newUIServer(e, *listen, operator, token)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitCannotRun
		}
		if *manage {
			if code, ok := uiEnableManage(s, e, stderr); !ok {
				return code
			}
		}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			fmt.Fprintf(stderr, "listen: %v\n", err)
			return exitCannotRun
		}
		srv := &http.Server{
			Handler:           s.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       2 * time.Minute,
		}
		ctx, stop := signalContext()
		defer stop()
		go func() {
			<-ctx.Done()
			shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shut)
		}()
		fmt.Fprintf(stdout, "Gatte web console for %s, acting as operator %q.\n\nOpen this link (it logs this browser in; keep it private):\n\n    http://%s/login?token=%s\n\nFrom another machine: ssh -L %s:%s HOST, then open the same link there.\nCtrl-C stops the console. The gateway itself keeps running.\n",
			e.configPath, operator, ln.Addr(), token, uiPort(ln.Addr()), ln.Addr())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "ui: %v\n", err)
			return exitCannotRun
		}
		return exitOK
	})
}

func uiPort(a net.Addr) string {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return "8090"
	}
	return p
}

func uiUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway ui [-config FILE] [-listen 127.0.0.1:8090]

Serves the operator console as a web page on loopback: the tool approval
queue with each definition's review and diff, the blocklist, the audit
trail and its verification, the registered backends and quota spend.

Every button runs the console command of the same name (tool approve,
access block, audit -verify, ...) in this process, with the same checks and
the same audit rows; the page shows what the command printed. Registering
and signing a backend stay in the terminal.

Run it as the service account, like the other console commands. It prints
a /login link carrying a random token; open it once and the browser keeps
a cookie for this run. -listen must be loopback. To use it from your own
machine, forward the port: ssh -L 8090:127.0.0.1:8090 HOST.
`)
}

// uiEscapeText escapes what a command printed, line by line: the lines
// are the command's own structure, and every hidden code point inside one
// is shown as \u{XXXX}. Most commands escape what they print; this makes
// the page not depend on every one of them doing it.
func uiEscapeText(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = visible.Escape(l)
	}
	return strings.Join(lines, "\n")
}

// uiGeteuid is os.Geteuid, a variable so the root check is testable from
// a test that is not root, and one that is.
var uiGeteuid = os.Geteuid

// uiEnableManage turns on account editing, refusing unless this process is
// root and the configuration names the IdP's users file
// (design/adr/0038). The service account must never be able to write the
// IdP's accounts; a console that runs as it has no such mode at all.
func uiEnableManage(s *uiServer, e *opEnv, stderr io.Writer) (int, bool) {
	if uiGeteuid() != 0 {
		fmt.Fprint(stderr, "-manage-users edits the identity provider's accounts, so it runs only as root:\n\n    sudo mcp-gateway ui -manage-users -config FILE\n\nThe service account is deliberately unable to create accounts: whoever runs code as the gateway\ncould otherwise give themselves any role (design/adr/0038).\n")
		return exitCannotRun, false
	}
	if e.cfg.IdP.UsersFile == "" {
		fmt.Fprint(stderr, "-manage-users needs [idp] users_file in the configuration file: the path of the identity\nprovider's users database (Authelia file backend).\n")
		return exitCannotRun, false
	}
	dir := autheliafile.New(e.cfg.IdP.UsersFile)
	if _, err := dir.Accounts(); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun, false
	}
	s.enableAccounts(dir)
	s.ownDB = e.cfg.Database
	if err := keepDBOwner(s.ownDB); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun, false
	}
	return exitOK, true
}

// uiInitial is the letter an account's avatar shows.
func uiInitial(names ...string) string {
	for _, n := range names {
		for _, r := range strings.TrimSpace(n) {
			return strings.ToUpper(string(r))
		}
	}
	return "?"
}
