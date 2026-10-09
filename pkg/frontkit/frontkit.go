// Package frontkit is the browser protection every Gatte web front serves
// through (design/adr/0036 §3, 0040 §5), as a library, so a front of
// another look -- the Gatte one, or a deployment's own -- gets them without
// reimplementing any.
//
// A page on 127.0.0.1 is reachable from every website the operator has
// open: any origin can POST a form to it, and a hostname an attacker
// controls can be rebound to it. So, in the order a request meets them:
//
//   - the bind is loopback, refused otherwise;
//   - Host must name loopback, which defeats DNS rebinding;
//   - the printed /login?token=... link works once. It opens a session:
//     a random id every later URL carries as its first path segment
//     (/s/ID/...) and an HttpOnly, SameSite=Strict cookie carries too. Both
//     must match. The path matters because cookies are not isolated by
//     port: a page another process serves on another localhost port is
//     "same site" and gets the cookie, but never learns the path;
//   - every POST carries the form token and, when the browser sends an
//     Origin, it is the page's own; the body is bounded, url-encoded or
//     multipart (a file upload) alike;
//   - every response says Content-Security-Policy default-src 'none',
//     X-Frame-Options DENY, nosniff, no-referrer and no-store.
//
// There is one way in: New binds, Serve serves. No handler is exported to
// be mounted elsewhere; serving by another path is not using frontkit.
package frontkit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// CookieName carries the session id.
const CookieName = "gatte_ui"

// DefaultSessionLifetime is how long one login lasts: a shift.
const DefaultSessionLifetime = 12 * time.Hour

// DefaultMaxBody bounds a POST body. Every form of a console is a few
// short fields; a front whose form uploads a document sets Config.MaxBody.
const DefaultMaxBody = 64 << 10

// CSP is the policy every response carries: no script, styles only from
// the page's own origin, forms only to it, no framing.
const CSP = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// Config configures a Kit.
type Config struct {
	// Listen is a loopback host:port ("127.0.0.1:8090", "[::1]:0",
	// "localhost:8090"). Anything else is refused.
	Listen string
	// SessionLifetime defaults to DefaultSessionLifetime.
	SessionLifetime time.Duration
	// MaxBody defaults to DefaultMaxBody.
	MaxBody int64
}

// Kit is one front's browser boundary: a loopback listener, the one-time
// login token, the session it opens and the form token.
type Kit struct {
	cfg   Config
	ln    net.Listener
	token string
	csrf  string
	now   func() time.Time
	srv   *http.Server

	sessMu    sync.Mutex
	loginUsed bool
	session   string
	expires   time.Time

	// inner is what Serve was given; tests set it directly.
	inner http.Handler
}

// New checks cfg, binds the listener and makes the login and form tokens.
func New(cfg Config) (*Kit, error) {
	if !isLoopbackAddr(cfg.Listen) {
		return nil, fmt.Errorf("frontkit: listen %q is not a loopback address. A console has the operator's powers and "+
			"terminates no TLS; it binds 127.0.0.1, ::1 or localhost only, and is reached from elsewhere through ssh -L", cfg.Listen)
	}
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = DefaultSessionLifetime
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("frontkit: %w", err)
	}
	// "localhost" resolves; hold what it resolved to to loopback as well.
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		_ = ln.Close()
		return nil, fmt.Errorf("frontkit: %q bound %s, which is not loopback", cfg.Listen, ln.Addr())
	}
	return &Kit{cfg: cfg, ln: ln, token: token, csrf: csrf, now: time.Now}, nil
}

// isLoopbackAddr reports whether host:port names loopback, with a port.
func isLoopbackAddr(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("frontkit: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Addr is the bound address.
func (k *Kit) Addr() net.Addr { return k.ln.Addr() }

// LoginURL is the one-time link that logs a browser in. Print it to the
// operator's terminal and nowhere else.
func (k *Kit) LoginURL() string {
	return "http://" + k.ln.Addr().String() + "/login?token=" + k.token
}

// CSRFToken is the form token every POST must carry as the field "csrf".
func (k *Kit) CSRFToken() string { return k.csrf }

// Base is the path prefix of every link in the session ("/s/ID"), empty
// before the login.
func (k *Kit) Base() string {
	k.sessMu.Lock()
	defer k.sessMu.Unlock()
	if k.session == "" {
		return ""
	}
	return "/s/" + k.session
}

// Serve serves h behind every check, until Shutdown or Close. h sees paths
// with the /s/ID prefix removed, and POST forms already parsed.
func (k *Kit) Serve(h http.Handler) error {
	k.sessMu.Lock()
	k.inner = h
	k.srv = &http.Server{
		Handler:           k.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	srv := k.srv
	k.sessMu.Unlock()
	if err := srv.Serve(k.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops Serve gracefully.
func (k *Kit) Shutdown(ctx context.Context) error {
	k.sessMu.Lock()
	srv := k.srv
	k.sessMu.Unlock()
	if srv == nil {
		return k.ln.Close()
	}
	return srv.Shutdown(ctx)
}

// Close stops Serve at once and releases the listener.
func (k *Kit) Close() error {
	k.sessMu.Lock()
	srv := k.srv
	k.sessMu.Unlock()
	if srv != nil {
		return srv.Close()
	}
	return k.ln.Close()
}

// handler applies, to every request, the checks in the package comment.
func (k *Kit) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")

		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden: this console answers only on a loopback name (localhost, 127.0.0.1, ::1)", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/login" {
			k.login(w, r)
			return
		}
		rest, ok := k.authenticate(r)
		if !ok {
			http.Error(w, "unauthorized: open the /login link the console printed when it started. "+
				"It works once; for a new session, start the console again", http.StatusUnauthorized)
			return
		}
		r.URL.Path = rest
		r.URL.RawPath = ""
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, k.cfg.MaxBody)
			if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, "http://"+r.Host) {
				http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
				return
			}
			if err := parseForm(r, k.cfg.MaxBody); err != nil {
				http.Error(w, "forbidden: the form could not be read (too large?)", http.StatusRequestEntityTooLarge)
				return
			}
			if r.MultipartForm != nil {
				defer func() { _ = r.MultipartForm.RemoveAll() }()
			}
			if !equal(r.PostForm.Get("csrf"), k.csrf) {
				http.Error(w, "forbidden: missing or wrong form token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		if k.inner == nil {
			http.NotFound(w, r)
			return
		}
		k.inner.ServeHTTP(w, r)
	})
}

// parseForm reads a POST body into r.PostForm: url-encoded, or
// multipart/form-data for a form that uploads a file. A multipart form is
// held in memory up to the body's own bound, which MaxBytesReader already
// enforces, so no part spills to a temporary file; its fields, the form
// token among them, land in r.PostForm like any other form's, and every
// check after this one reads them from there. A file part is in
// r.MultipartForm.File.
func parseForm(r *http.Request, maxBody int64) error {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.EqualFold(strings.TrimSpace(ct), "multipart/form-data") {
		return r.ParseMultipartForm(maxBody)
	}
	return r.ParseForm()
}

// authenticate checks the session in the path and in the cookie, and
// returns the path with the /s/ID prefix removed.
func (k *Kit) authenticate(r *http.Request) (string, bool) {
	k.sessMu.Lock()
	sess, exp := k.session, k.expires
	k.sessMu.Unlock()
	if sess == "" || !k.now().Before(exp) {
		return "", false
	}
	after, ok := strings.CutPrefix(r.URL.Path, "/s/")
	if !ok {
		return "", false
	}
	id, rest, _ := strings.Cut(after, "/")
	if !equal(id, sess) {
		return "", false
	}
	c, err := r.Cookie(CookieName)
	if err != nil || !equal(c.Value, sess) {
		return "", false
	}
	return "/" + rest, true
}

// login trades the printed token, once, for a session, then drops the
// token from the address bar. A second use is refused: the link can sit in
// browser history, scrollback or a terminal log.
func (k *Kit) login(w http.ResponseWriter, r *http.Request) {
	k.sessMu.Lock()
	if r.Method != http.MethodGet || k.loginUsed || !equal(r.URL.Query().Get("token"), k.token) {
		k.sessMu.Unlock()
		http.Error(w, "unauthorized: wrong, missing or already used login token. For a new session, start the console again", http.StatusUnauthorized)
		return
	}
	sess, err := randomToken()
	if err != nil {
		k.sessMu.Unlock()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	k.loginUsed, k.session, k.expires = true, sess, k.now().Add(k.cfg.SessionLifetime)
	k.sessMu.Unlock()
	// Not Secure: the page is plain http on loopback, and not every browser
	// sends a Secure cookie to http://localhost. HttpOnly and
	// SameSite=Strict are what this cookie relies on.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- see above
		Name: CookieName, Value: sess, Path: "/s/" + sess + "/",
		MaxAge:   int(k.cfg.SessionLifetime / time.Second),
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/s/"+sess+"/", http.StatusSeeOther)
}

// loopbackHost reports whether a Host header names loopback. The port is
// not compared: an ssh -L tunnel may use any local port.
func loopbackHost(hostport string) bool {
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

func equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VisibleText writes every code point a screen would not show as \u{XXXX}
// and every byte that is not UTF-8 as \x{XX}, for text the front has that
// did not come as segments. It does not escape HTML: a template does that.
func VisibleText(s string) string { return escapeVisible(s) }

// DrawSegments renders review segments as HTML: text escaped, a hidden
// code point as a marked \u{XXXX}, a bad byte as a marked \x{XX}, and a
// kind this front does not know drawn visibly as well.
func DrawSegments(segs []adminapi.Segment) template.HTML {
	var b strings.Builder
	for _, s := range segs {
		switch s.Kind {
		case adminapi.SegmentText:
			b.WriteString(html.EscapeString(escapeVisible(s.Text)))
		case adminapi.SegmentHidden:
			b.WriteString(`<mark class="hidden-cp" title="Hidden character">\u{` + html.EscapeString(strings.TrimPrefix(s.CodePoint, "U+")) + `}</mark>`)
		case adminapi.SegmentInvalidByte:
			b.WriteString(`<mark class="hidden-cp" title="Hidden character">\x{` + html.EscapeString(s.Byte) + `}</mark>`)
		case adminapi.SegmentNewline:
			b.WriteString("<br>")
		default:
			b.WriteString(`<mark class="hidden-cp" title="Hidden character">` + html.EscapeString(escapeVisible(s.Text+s.CodePoint+s.Byte)) + `</mark>`)
		}
	}
	return template.HTML(b.String()) // #nosec G203 -- every piece above is escaped
}

func escapeVisible(s string) string { return visible.Escape(s) }

// SplitLines cuts segments at newline segments, for a front that draws a
// multi-line field one line per element instead of with <br>.
func SplitLines(segs []adminapi.Segment) [][]adminapi.Segment {
	out := [][]adminapi.Segment{{}}
	for _, s := range segs {
		if s.Kind == adminapi.SegmentNewline {
			out = append(out, []adminapi.Segment{})
			continue
		}
		out[len(out)-1] = append(out[len(out)-1], s)
	}
	return out
}
