package resthttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// The credential discipline of ADR-0048 Decisão 7 and ADR-0047 §5, as
// tests that fail if anyone relaxes it: no error out of this package
// carries the live value in any rendering, and the upstream object holds
// no copy of it.

// leakySecret is chosen to need escaping in every rendering MaskCredentials
// knows: quote, backslash, newline, space, '+', '/', '&', '=' and a
// non-ASCII rune, so that a raw, %q, JSON or URL-encoded echo is each a
// different byte string. The newline makes it unsendable as a HEADER value
// (net/http refuses the request before any dial), so it serves the query
// kind and the synthetic tests; the header and bearer kinds use
// headerSecret.
const leakySecret = "sk/live+9f8e7d \"q\"\\&=ç\n-TAIL-7d41"

// headerSecret is leakySecret without the control byte: still a different
// byte string under %q, JSON and URL encoding (quote, backslash, space,
// '+', '/', '&', '=', non-ASCII), and a value net/http will put on the
// wire, so a call with it reaches the transport and fails THERE.
const headerSecret = "sk/live+9f8e7d \"q\"\\&=ç -TAIL-7d41"

// renderings is every spelling of secret that must be absent from a
// message, including the tail fragment that survives when an overlap splits
// the value.
func renderings(secret string) []string {
	q, a := strconv.Quote(secret), strconv.QuoteToASCII(secret)
	return []string{
		secret, q[1 : len(q)-1], a[1 : len(a)-1],
		url.QueryEscape(secret), url.PathEscape(secret),
		"-TAIL-7d41",
	}
}

func assertNoRendering(t *testing.T, what, text string, secret string) {
	t.Helper()
	for _, r := range renderings(secret) {
		if strings.Contains(text, r) {
			t.Errorf("LEAK in %s: rendering %q found in: %s", what, r, text)
		}
	}
}

// assertErrorIsClean checks every way an error reaches a reader: Error(),
// %v, %+v, %#v, %s and %q -- and that the *url.Error with the full URL is
// not reachable through errors.As.
func assertErrorIsClean(t *testing.T, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		assertNoRendering(t, verb, fmt.Sprintf(verb, err), secret)
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		t.Errorf("LEAK: *url.Error (which prints the full URL) is reachable through errors.As: %v", uerr)
	}
}

// TestSecCallErrorNeverCarriesTheCredential: for each auth kind, a call
// that fails AT THE TRANSPORT (connection refused) yields an error with no
// rendering of the secret. The query kind is the one ADR-0048 Decisão 7
// names -- the URL in *url.Error holds "?key=<secret>" -- and the test
// would fail without scrubCallError. The header and bearer kinds carry a
// secret net/http accepts as a field value, and the test checks the error
// is the connect failure, so the dial path is what is exercised and not an
// "invalid header field value" refusal that never left the client.
func TestSecCallErrorNeverCarriesTheCredential(t *testing.T) {
	for _, tc := range []struct{ kind, name, secret string }{
		{resthttp.AuthQuery, "key", leakySecret},
		{resthttp.AuthHeader, "X-API-Key", headerSecret},
		{resthttp.AuthBearer, "", headerSecret},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			v := &fakeVault{secrets: map[string]string{"API_KEY": tc.secret}}
			up := dialKeyed(t, newDialer(t, v), closedPort(t), tc.kind, tc.name, "API_KEY", tc.secret)
			_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4","query_maxAgeInDays":7}`))
			assertErrorIsClean(t, err, tc.secret)
			if !strings.Contains(err.Error(), "GET /check/{ip}") {
				t.Errorf("the error should name the method and path template: %v", err)
			}
			if !strings.Contains(err.Error(), "connect") {
				t.Errorf("the call must fail at the transport (connection refused), not before: %v", err)
			}
			if strings.Contains(err.Error(), "maxAgeInDays") || strings.Contains(err.Error(), "1.2.3.4") {
				t.Errorf("the filled path or query leaked into the error: %v", err)
			}
		})
	}

	// A secret net/http cannot put in a header: the client refuses the
	// request before dialling, and that refusal must be as clean as a
	// transport failure.
	t.Run("control byte in a header secret", func(t *testing.T) {
		v := &fakeVault{secrets: map[string]string{"API_KEY": leakySecret}}
		up := dialKeyed(t, newDialer(t, v), closedPort(t), resthttp.AuthHeader, "X-API-Key", "API_KEY", leakySecret)
		_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
		assertErrorIsClean(t, err, leakySecret)
		if !strings.Contains(err.Error(), "invalid header field value") {
			t.Errorf("want net/http's refusal of the field value, got %v", err)
		}
	})
}

// TestSecDialErrorNeverCarriesTheCredential: Dial masks the operation-set
// error with env (resthttp.go, scrubDialError). An operation set is
// operator-authored text that should not hold a secret, but ParsePath and
// Validate print paths and property names verbatim, so a set that does is
// the one case where that mask is the only barrier.
func TestSecDialErrorNeverCarriesTheCredential(t *testing.T) {
	for name, set := range map[string][]resthttp.Operation{
		"secret in a path": {{Name: "a", Method: "GET", Path: "/x/" + leakySecret, InputSchema: json.RawMessage(`{"type":"object"}`)}},
		"secret in a header name": {{Name: "a", Method: "GET", Path: "/x",
			InputSchema: json.RawMessage(`{"type":"object","properties":{` + strconv.Quote("header_"+leakySecret) + `:{"type":"string"}}}`)}},
		"secret in an operation name": {{Name: leakySecret, Method: "GET", Path: "/x", InputSchema: json.RawMessage(`{"type":"object"}`)}},
	} {
		t.Run(name, func(t *testing.T) {
			ops, err := resthttp.Encode(set)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			s := spec(t, "https://api.example.test/", resthttp.AuthHeader, "X-API-Key")
			s.Operations = ops
			_, err = newDialer(t, &fakeVault{}).Dial(context.Background(), s, map[string]string{"API_KEY": leakySecret})
			if !errors.Is(err, resthttp.ErrInvalidOperations) {
				t.Fatalf("want ErrInvalidOperations, got %v", err)
			}
			assertErrorIsClean(t, err, leakySecret)
		})
	}
}

// TestSecTLSFailureWithQueryCredentialIsClean: a TLS verification failure
// is a *url.Error too, produced after the URL (with the query credential)
// was built.
func TestSecTLSFailureWithQueryCredentialIsClean(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	v := &fakeVault{secrets: map[string]string{"API_KEY": leakySecret}}
	up := dialKeyed(t, newDialer(t, v), srv.URL, resthttp.AuthQuery, "key", "API_KEY", leakySecret)
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	assertErrorIsClean(t, err, leakySecret)
}

// TestSecRedirectRefusalWithQueryCredentialIsClean: the refused Location
// of a cross-host redirect, and the request URL that got there, both hold
// the credential when the kind is query.
func TestSecRedirectRefusalWithQueryCredentialIsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the whole query, credential included, into the Location.
		http.Redirect(w, r, "http://203.0.113.9/echo?"+r.URL.RawQuery, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	v := &fakeVault{secrets: map[string]string{"API_KEY": leakySecret}}
	up := dialKeyed(t, newDialer(t, v), srv.URL, resthttp.AuthQuery, "key", "API_KEY", leakySecret)
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("want ErrEgressRefused, got %v", err)
	}
	assertErrorIsClean(t, err, leakySecret)
}

// TestSecScrubCallErrorDirect exercises the redaction on synthetic errors:
// a *url.Error whose URL holds the secret, an inner error that echoes it in
// each rendering, an overlap with a shorter value, and errors.Is through the
// scrubbed result.
func TestSecScrubCallErrorDirect(t *testing.T) {
	op := resthttp.Operation{Method: "GET", Path: "/check/{ip}"}
	env := map[string]string{"API_KEY": leakySecret, "SHORT": "9f8e"}

	full := "http://h/check/1?key=" + url.QueryEscape(leakySecret)
	for _, inner := range []error{
		errors.New("dial tcp 127.0.0.1:1: connect: connection refused"),
		errors.New("server said: bad key " + leakySecret),
		errors.New("server said: " + strconv.Quote(leakySecret)),
		errors.New("server said: " + url.QueryEscape(leakySecret)),
		context.Canceled,
		context.DeadlineExceeded,
		fmt.Errorf("wrapped: %w", resthttp.ErrEgressRefused),
	} {
		uerr := &url.Error{Op: "Get", URL: full, Err: inner}
		got := resthttp.ScrubCallError(uerr, op, env)
		assertErrorIsClean(t, got, leakySecret)
		if !strings.HasPrefix(got.Error(), "GET /check/{ip}: ") {
			t.Errorf("URL not replaced by the template: %v", got)
		}
		if !errors.Is(got, inner) {
			t.Errorf("errors.Is lost for %v", inner)
		}
		if errors.Is(got, gateway.ErrUpstreamGone) {
			t.Errorf("never gone")
		}
	}

	// A non-url error is masked too, and loses nothing it should keep.
	got := resthttp.ScrubCallError(fmt.Errorf("read: %w: %s", context.DeadlineExceeded, leakySecret), op, env)
	assertErrorIsClean(t, got, leakySecret)
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("errors.Is lost on a non-url error")
	}
}

// TestSecUpstreamRetainsNoCredential walks every field reachable from the
// upstream -- its own, the client's, the transport's, and whatever the
// transport still points at -- after a dial and after a call that resolved
// the secret, and fails on any string or byte slice holding the value. Dial
// receives the value in env, and CallTool resolves it; neither may keep it
// (ADR-0047 §5: re-resolved per call, never persisted).
//
// With keep-alive on, an idle connection's write buffer kept the last
// request line (with "?key=<value>") reachable through client.Transport
// until the connection was reused or expired, and an earlier version of
// this test closed the client first -- which dropped the idle connection
// -- and so never saw it. Keep-alive is off (egress.go, newTransport); this
// is what proves it stays off: the walk waits for the exchange's goroutines
// to exit, which with keep-alive they would not do (the readLoop of an idle
// connection lives until the connection does), so a regression fails the
// wait before it could hide behind Close. Close is then called BEFORE the
// walk only as a synchronisation point -- it takes the transport's idle
// lock, which the exiting readLoop also took, and that is the
// happens-before the race detector needs between the readLoop's last map
// write (deleting the finished request) and this reflective read; with no
// idle connection it drops nothing. Each kind is walked, because each puts
// the value in a different line of the request.
func TestSecUpstreamRetainsNoCredential(t *testing.T) {
	for _, tc := range []struct{ kind, name, secret string }{
		{resthttp.AuthQuery, "key", leakySecret},
		{resthttp.AuthHeader, "X-API-Key", headerSecret},
		{resthttp.AuthBearer, "", headerSecret},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			srv, _ := recorder(t, 200, nil)
			v := &fakeVault{secrets: map[string]string{"API_KEY": tc.secret}}
			d := newDialer(t, v)
			up, err := d.Dial(context.Background(), spec(t, srv.URL, tc.kind, tc.name), map[string]string{"API_KEY": tc.secret})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = up.Close() })

			walk(t, "after Dial", reflect.ValueOf(up), tc.secret)
			baseline := runtime.NumGoroutine()
			if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`)); err != nil {
				t.Fatal(err)
			}
			waitForGoroutines(t, baseline)
			_ = up.Close()
			walk(t, "after CallTool", reflect.ValueOf(up), tc.secret)
			walk(t, "dialer", reflect.ValueOf(d), tc.secret)
		})
	}
}

// waitForGoroutines waits until the goroutine count is back to baseline:
// the transport's readLoop/writeLoop for the connection and the server's
// handler goroutine have all exited, which happens only when the
// connection was closed rather than kept idle.
func waitForGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines still running after the call (baseline %d): a connection was kept alive, and its buffers hold the last request", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// providerType is the one port whose implementation may hold the value:
// the walk does not descend into a vault.Provider, because the vault is
// where the secret lives by design. Everything else reachable from the
// upstream is checked.
var providerType = reflect.TypeOf((*vault.Provider)(nil)).Elem()

// walk is a bounded reflective traversal: strings and byte slices are
// checked, containers are descended, pointers are visited once.
func walk(t *testing.T, where string, root reflect.Value, secret string) {
	t.Helper()
	visited := map[uintptr]bool{}
	var visit func(v reflect.Value, path string, depth int)
	visit = func(v reflect.Value, path string, depth int) {
		if !v.IsValid() || depth > 16 {
			return
		}
		if v.Type().Implements(providerType) {
			return
		}
		switch v.Kind() {
		case reflect.String:
			assertNoRendering(t, where+" "+path, v.String(), secret)
		case reflect.Slice, reflect.Array:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				b := make([]byte, v.Len())
				for i := range b {
					b[i] = byte(v.Index(i).Uint())
				}
				assertNoRendering(t, where+" "+path, string(b), secret)
				return
			}
			if v.Kind() == reflect.Slice && v.Len() > 0 {
				if ptr := v.Pointer(); visited[ptr] {
					return
				} else {
					visited[ptr] = true
				}
			}
			for i := 0; i < v.Len(); i++ {
				visit(v.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1)
			}
		case reflect.Map:
			if v.IsNil() {
				return
			}
			if ptr := v.Pointer(); visited[ptr] {
				return
			} else {
				visited[ptr] = true
			}
			iter := v.MapRange()
			for iter.Next() {
				visit(iter.Key(), path+".key", depth+1)
				visit(iter.Value(), path+"[]", depth+1)
			}
		case reflect.Pointer:
			if v.IsNil() {
				return
			}
			if ptr := v.Pointer(); visited[ptr] {
				return
			} else {
				visited[ptr] = true
			}
			visit(v.Elem(), path, depth+1)
		case reflect.Interface:
			if !v.IsNil() {
				visit(v.Elem(), path, depth+1)
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				visit(v.Field(i), path+"."+v.Type().Field(i).Name, depth+1)
			}
		}
	}
	visit(root, "upstream", 0)
}
