package frontkit

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// These are design/adr/0036's browser tests, moved from the Gatte web front
// into the library every web front serves through (design/adr/0040 §5).

// testKit is a kit bound on a free loopback port, with a handler that
// records whether it ran.
func testKit(t *testing.T) (*Kit, *bool) {
	t.Helper()
	k, err := New(Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	ran := false
	k.inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		_, _ = io.WriteString(w, "ok "+r.URL.Path)
	})
	return k, &ran
}

func do(k *Kit, method, target string, form url.Values, cookie *http.Cookie, mutate func(*http.Request)) *httptest.ResponseRecorder {
	var body io.Reader = strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8090"+target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	k.handler().ServeHTTP(w, r)
	return w
}

func login(t *testing.T, k *Kit) *http.Cookie {
	t.Helper()
	w := do(k, "GET", "/login?token="+k.token, nil, nil, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

func TestNew_RefusesANonLoopbackListen(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.10:8090", ":0", "gw.example.internal:8090"} {
		if k, err := New(Config{Listen: addr}); err == nil {
			k.Close()
			t.Errorf("New(%q) accepted a non-loopback listen address", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		k, err := New(Config{Listen: addr})
		if err != nil {
			if strings.Contains(err.Error(), "::1") {
				continue // a host with no IPv6 loopback
			}
			t.Errorf("New(%q): %v", addr, err)
			continue
		}
		k.Close()
	}
}

func TestLogin_TheLinkOpensOneSessionOnce(t *testing.T) {
	k, _ := testKit(t)
	if !strings.Contains(k.LoginURL(), "/login?token="+k.token) {
		t.Fatalf("LoginURL %q", k.LoginURL())
	}
	if w := do(k, "GET", "/s/x/", nil, nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("before any login: %d", w.Code)
	}
	if w := do(k, "GET", "/login?token=wrong", nil, nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", w.Code)
	}
	w := do(k, "GET", "/login?token="+k.token, nil, nil, nil)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/s/") || strings.Contains(loc, k.token) {
		t.Fatalf("login: %d %q", w.Code, loc)
	}
	set := w.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=" + loc, "Max-Age="} {
		if !strings.Contains(set, want) {
			t.Errorf("Set-Cookie %q lacks %q", set, want)
		}
	}
	if k.Base() != strings.TrimSuffix(loc, "/") {
		t.Errorf("Base() %q, want %q", k.Base(), strings.TrimSuffix(loc, "/"))
	}
	if w := do(k, "GET", "/login?token="+k.token, nil, nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("second use: %d", w.Code)
	}
}

func TestSession_TheCookieWithoutThePathIsNotEnough(t *testing.T) {
	k, ran := testKit(t)
	cookie := login(t, k)
	for _, target := range []string{"/", "/tools", "/s/" + strings.Repeat("0", 64) + "/", "/s/" + cookie.Value + "x/"} {
		if w := do(k, "GET", target, nil, cookie, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with the cookie and not the path: %d", target, w.Code)
		}
	}
	if w := do(k, "GET", k.Base()+"/", nil, nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("the path without the cookie: %d", w.Code)
	}
	w := do(k, "GET", k.Base()+"/tools", nil, cookie, nil)
	if w.Code != http.StatusOK || !*ran || w.Body.String() != "ok /tools" {
		t.Fatalf("path and cookie: %d %q", w.Code, w.Body)
	}
}

func TestSession_Ends(t *testing.T) {
	k, _ := testKit(t)
	cookie := login(t, k)
	k.now = func() time.Time { return time.Now().Add(DefaultSessionLifetime + time.Minute) }
	if w := do(k, "GET", k.Base()+"/", nil, cookie, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("after the lifetime: %d", w.Code)
	}
}

func TestHost_MustBeLoopback(t *testing.T) {
	k, _ := testKit(t)
	cookie := login(t, k)
	if w := do(k, "GET", k.Base()+"/", nil, cookie, func(r *http.Request) { r.Host = "attacker.example:8090" }); w.Code != http.StatusForbidden {
		t.Fatalf("Host attacker.example: %d", w.Code)
	}
	for _, host := range []string{"localhost:9000", "127.0.0.1:8090", "[::1]:8090", "LOCALHOST:8090"} {
		if w := do(k, "GET", k.Base()+"/", nil, cookie, func(r *http.Request) { r.Host = host }); w.Code != http.StatusOK {
			t.Errorf("Host %s: %d", host, w.Code)
		}
	}
}

func TestPost_NeedsTheFormTokenAndTheSameOrigin(t *testing.T) {
	k, ran := testKit(t)
	cookie := login(t, k)
	if w := do(k, "POST", k.Base()+"/x", url.Values{"a": {"b"}}, cookie, nil); w.Code != http.StatusForbidden || *ran {
		t.Fatalf("without the form token: %d ran=%v", w.Code, *ran)
	}
	if w := do(k, "POST", k.Base()+"/x", url.Values{"csrf": {k.CSRFToken()}}, cookie, func(r *http.Request) {
		r.Header.Set("Origin", "https://attacker.example")
	}); w.Code != http.StatusForbidden || *ran {
		t.Fatalf("from another origin: %d ran=%v", w.Code, *ran)
	}
	if w := do(k, "POST", k.Base()+"/x", url.Values{"csrf": {k.CSRFToken()}}, cookie, func(r *http.Request) {
		r.Host = "LOCALHOST:8090"
		r.Header.Set("Origin", "http://localhost:8090")
	}); w.Code != http.StatusOK || !*ran {
		t.Fatalf("same origin in another case: %d ran=%v", w.Code, *ran)
	}
}

func TestPost_BodyIsBounded(t *testing.T) {
	k, ran := testKit(t)
	cookie := login(t, k)
	form := url.Values{"csrf": {k.CSRFToken()}, "big": {strings.Repeat("a", DefaultMaxBody+1)}}
	if w := do(k, "POST", k.Base()+"/x", form, cookie, nil); w.Code == http.StatusOK || *ran {
		t.Fatalf("an oversized body: %d ran=%v", w.Code, *ran)
	}
}

// multipartBody is a multipart/form-data body with fields and one file.
func multipartBody(t *testing.T, fields map[string]string, file string) (io.Reader, string) {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("doc", "doc.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(fw, file)
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &b, mw.FormDataContentType()
}

// TestPost_AMultipartFormIsHeldToTheSameChecks: a form that uploads a file
// carries the form token as one of its parts, and is refused without it,
// from another origin, and over the bound, exactly as a url-encoded one.
func TestPost_AMultipartFormIsHeldToTheSameChecks(t *testing.T) {
	k, ran := testKit(t)
	var got string
	k.inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		f, _, err := r.FormFile("doc")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer f.Close()
		b, _ := io.ReadAll(f)
		got = r.PostForm.Get("name") + ":" + string(b)
	})
	cookie := login(t, k)
	send := func(fields map[string]string, file string, mutate func(*http.Request)) *httptest.ResponseRecorder {
		body, ct := multipartBody(t, fields, file)
		r := httptest.NewRequest("POST", "http://127.0.0.1:8090"+k.Base()+"/x", body)
		r.Header.Set("Content-Type", ct)
		r.AddCookie(cookie)
		if mutate != nil {
			mutate(r)
		}
		w := httptest.NewRecorder()
		k.handler().ServeHTTP(w, r)
		return w
	}
	if w := send(map[string]string{"name": "a"}, "{}", nil); w.Code != http.StatusForbidden || *ran {
		t.Fatalf("multipart without the form token: %d ran=%v", w.Code, *ran)
	}
	if w := send(map[string]string{"csrf": "wrong"}, "{}", nil); w.Code != http.StatusForbidden || *ran {
		t.Fatalf("multipart with a wrong form token: %d ran=%v", w.Code, *ran)
	}
	if w := send(map[string]string{"csrf": k.CSRFToken()}, "{}", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }); w.Code != http.StatusForbidden || *ran {
		t.Fatalf("multipart from another origin: %d ran=%v", w.Code, *ran)
	}
	if w := send(map[string]string{"csrf": k.CSRFToken()}, strings.Repeat("a", DefaultMaxBody+1), nil); w.Code == http.StatusOK || *ran {
		t.Fatalf("an oversized multipart body: %d ran=%v", w.Code, *ran)
	}
	if w := send(map[string]string{"csrf": k.CSRFToken(), "name": "api"}, `{"openapi":"3.0.0"}`, nil); w.Code != http.StatusOK || !*ran || got != `api:{"openapi":"3.0.0"}` {
		t.Fatalf("a multipart form with the token: %d ran=%v got=%q", w.Code, *ran, got)
	}
}

// TestHeaders_OnEveryResponse: a strict policy, no framing, no sniffing,
// no referrer, and no-store on every page including the refusals.
func TestHeaders_OnEveryResponse(t *testing.T) {
	k, _ := testKit(t)
	cookie := login(t, k)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"page":    do(k, "GET", k.Base()+"/", nil, cookie, nil),
		"refusal": do(k, "GET", "/nope", nil, nil, nil),
		"login":   do(k, "GET", "/login?token=x", nil, nil, nil),
	} {
		h := w.Header()
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: CSP %q", name, csp)
		}
		for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "X-Frame-Options": "DENY"} {
			if h.Get(k) != v {
				t.Errorf("%s: %s = %q, want %q", name, k, h.Get(k), v)
			}
		}
	}
}

func TestServe_IsTheWayIn(t *testing.T) {
	k, err := New(Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- k.Serve(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hi") }))
	}()
	resp, err := http.Get("http://" + k.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated GET through Serve: %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := k.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve after Shutdown: %v", err)
	}
}

func TestVisibleText_AndDrawSegments(t *testing.T) {
	if got := VisibleText("a\u202eb<x>"); got != `a\u{202E}b<x>` {
		t.Errorf("VisibleText = %q", got)
	}
	segs := []adminapi.Segment{
		{Kind: adminapi.SegmentText, Text: "<b>"},
		{Kind: adminapi.SegmentHidden, CodePoint: "U+202E"},
		{Kind: adminapi.SegmentInvalidByte, Byte: "FF"},
		{Kind: adminapi.SegmentText, Text: "tail\u200b"},
		{Kind: "from-a-newer-backend", Text: "<i>"},
	}
	got := string(DrawSegments(segs))
	for _, want := range []string{"&lt;b&gt;", `\u{202E}`, `\x{FF}`, `tail\u{200B}`, "&lt;i&gt;"} {
		if !strings.Contains(got, want) {
			t.Errorf("DrawSegments lacks %q:\n%s", want, got)
		}
	}
	if strings.ContainsAny(got, "\u202e\u200b") || strings.Contains(got, "<b>") || strings.Contains(got, "<i>") {
		t.Errorf("DrawSegments carries raw text:\n%s", got)
	}
}
