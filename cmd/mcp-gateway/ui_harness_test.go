//go:build !nofront

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/front/gatteweb"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// The web console is a client of the management API (design/adr/0040 §6).
// Its tests run it the way it runs: a real `mcp-gateway admin` backend
// over the test's database, on a temporary UNIX socket, and the front in
// front of it on a loopback port, reached over real HTTP.

// uiOperator is the name the test backends give the connecting peer, as
// the kernel's credentials would.
const uiOperator = "ana.ops"

// uiSocketDir is a directory for sockets: resolved, short enough for
// sun_path, and closed to group and others.
func uiSocketDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// uiServeBackend serves one management socket over e's database and
// configuration, and returns its path. The configuration is read again on
// every request: e.configPath when a test sets it, e.cfg otherwise.
func uiServeBackend(t *testing.T, e opTestEnv, socket string) string {
	t.Helper()
	loadCfg := func() (*config.Config, error) {
		if e.configPath != "" {
			return config.Load(e.configPath)
		}
		return e.cfg, nil
	}
	svc, err := newAdminService(e.db, loadCfg, io.Discard, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid())
	path := filepath.Join(uiSocketDir(t), socket+".sock")
	ln, err := adminhttp.Listen(path, adminhttp.SocketPolicy{Group: -1, Mode: 0o600, SelfUID: me, OwnDirOK: true,
		Trusted: func(uid uint32) bool { return uid == 0 || uid == me }})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := adminhttp.New(adminhttp.Options{Socket: socket, Service: svc, ServiceUID: 1 << 30,
		LookupUser: func(uint32) (string, error) { return uiOperator, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the management backend did not stop")
		}
	})
	return path
}

// uiHarness is a running console and the browser that talks to it.
type uiHarness struct {
	kit     *frontkit.Kit
	origin  string // http://127.0.0.1:PORT
	token   string // the login link's query
	csrf    string
	session string // /s/ID, once logged in
	opSock  string
	accSock string
}

// newUIFront starts the console over a backend of e. With manage, it also
// serves the accounts socket and opens it, as -manage-users does. The test
// dials the accounts socket with the operator client: the accounts client
// refuses a server that is not root, and this one is the test's user.
func newUIFront(t *testing.T, e opTestEnv, manage bool) *uiHarness {
	t.Helper()
	h := &uiHarness{opSock: uiServeBackend(t, e, adminapi.SocketOperator)}
	var acc *adminapi.Client
	if manage {
		h.accSock = uiServeBackend(t, e, adminapi.SocketAccounts)
		acc = adminapi.New(h.accSock, adminapi.WithFront("ui"))
	}
	kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	front, err := gatteweb.New(gatteweb.Options{Operator: adminapi.New(h.opSock, adminapi.WithFront("ui")), Accounts: acc, Kit: kit})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = front.Serve() }()
	t.Cleanup(func() { kit.Close() })
	h.kit, h.origin, h.csrf = kit, "http://"+kit.Addr().String(), kit.CSRFToken()
	u, err := url.Parse(kit.LoginURL())
	if err != nil {
		t.Fatal(err)
	}
	h.token = u.Query().Get("token")
	return h
}

// newUIServerOnly returns a console nobody has logged in to yet.
func newUIServerOnly(t *testing.T) (opTestEnv, *uiHarness) {
	t.Helper()
	e := newOpTestEnv(t)
	return e, newUIFront(t, e, false)
}

// uiLogin opens the session through /login the way a browser does, and
// returns the cookie that browser holds.
func uiLogin(t *testing.T, s *uiHarness) *http.Cookie {
	t.Helper()
	w := uiDo(s, "GET", "/login?token="+s.token, nil, nil, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: %d\n%s", w.Code, w.Body)
	}
	s.session = strings.TrimSuffix(w.Header().Get("Location"), "/")
	for _, c := range w.Result().Cookies() {
		if c.Name == frontkit.CookieName {
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

// newUITest returns a console over a real backend and database, logged
// in.
func newUITest(t *testing.T) (opTestEnv, *uiHarness, *http.Cookie) {
	t.Helper()
	e, s := newUIServerOnly(t)
	return e, s, uiLogin(t, s)
}

// uiDo sends one request as a browser on loopback would. A target that is
// not /login or already under /s/ is sent under the session's path, as
// every link on the page is.
func uiDo(s *uiHarness, method, target string, form url.Values, cookie *http.Cookie, mutate func(*http.Request)) *httptest.ResponseRecorder {
	if !strings.HasPrefix(target, "/login") && !strings.HasPrefix(target, "/s/") && s.session != "" {
		target = s.session + target
	}
	return uiRaw(s, method, target, form, cookie, mutate)
}

// uiRaw sends one request to exactly target.
func uiRaw(s *uiHarness, method, target string, form url.Values, cookie *http.Cookie, mutate func(*http.Request)) *httptest.ResponseRecorder {
	var body io.Reader = strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequest(method, s.origin+target, body)
	if err != nil {
		panic(err)
	}
	r.Host = "127.0.0.1:8090"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if mutate != nil {
		mutate(r)
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(r)
	w := httptest.NewRecorder()
	if err != nil {
		w.WriteHeader(599)
		_, _ = io.WriteString(w, err.Error())
		return w
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	return w
}

func samePost(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8090") }
