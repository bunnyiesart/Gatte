package resthttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// These tests run the adapter against httptest servers. httptest listens on
// loopback, which the egress policy refuses, so every dialer here is given
// the test-only loopback allowance; the policy itself is pinned in
// egress_test.go.

// fakeVault is a vault.Provider over a map, counting resolutions so a test
// can prove the secret is re-resolved per call and never cached.
type fakeVault struct {
	secrets map[string]string
	calls   atomic.Int32
}

func (v *fakeVault) Resolve(_ context.Context, name string) (vault.Secret, error) {
	v.calls.Add(1)
	value, ok := v.secrets[name]
	if !ok {
		return vault.Secret{}, fmt.Errorf("%w: %q", vault.ErrNotFound, name)
	}
	return vault.NewSecret(value), nil
}

// ops is a small set: a GET with a parameter in every location and a POST
// with a body, under a header credential named X-API-Key unless a test
// says otherwise.
func ops(t *testing.T) []byte {
	t.Helper()
	set := []resthttp.Operation{
		{
			Name:        "check",
			Description: "Look an IP up",
			Method:      "GET",
			Path:        "/check/{ip}",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"path_ip":{"type":"string"},"query_maxAgeInDays":{"type":"integer"},"query_tags":{"type":"array","items":{"type":"string"}},"header_Accept":{"type":"string"},"cookie_session":{"type":"string"}},"required":["path_ip"]}`),
		},
		{
			Name:        "report",
			Description: "File a report",
			Method:      "POST",
			Path:        "/report",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"body":{"type":"object"},"query_dry":{"type":"boolean"}}}`),
		},
		{
			Name:        "ping",
			Method:      "HEAD",
			Path:        "/ping",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		},
	}
	b, err := resthttp.Encode(set)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func spec(t *testing.T, url, kind, name string) gateway.UpstreamSpec {
	t.Helper()
	return gateway.UpstreamSpec{Name: "api", Transport: resthttp.TransportHTTP, URL: url, AuthKind: kind, AuthName: name, Operations: ops(t)}
}

func newDialer(t *testing.T, v vault.Provider, opts ...resthttp.Option) *resthttp.Dialer {
	t.Helper()
	d := resthttp.New(v, opts...)
	resthttp.AllowLoopbackForTest(d)
	return d
}

func dialKeyless(t *testing.T, d *resthttp.Dialer, url string) gateway.Upstream {
	t.Helper()
	up, err := d.Dial(context.Background(), spec(t, url, resthttp.AuthNone, ""), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	return up
}

func dialKeyed(t *testing.T, d *resthttp.Dialer, url, kind, name, secretRef, secret string) gateway.Upstream {
	t.Helper()
	up, err := d.Dial(context.Background(), spec(t, url, kind, name), map[string]string{secretRef: secret})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	return up
}

// seen is what a recording handler captured of one request.
type seen struct {
	Method, Path, RawQuery string
	Header                 http.Header
	Body                   []byte
}

func recorder(t *testing.T, status int, respond func(w http.ResponseWriter)) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Method, s.Path, s.RawQuery, s.Header = r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Clone()
		s.Body, _ = io.ReadAll(r.Body)
		if respond != nil {
			respond(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

// decodeEnvelope unpacks the single text block of a Result.
func decodeEnvelope(t *testing.T, res gateway.Result) (status int, headers map[string][]string, body json.RawMessage, encoding string) {
	t.Helper()
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(res.Content, &blocks); err != nil {
		t.Fatalf("content is not a block array: %v (%s)", err, res.Content)
	}
	if len(blocks) != 1 || blocks[0].Type != "text" {
		t.Fatalf("want exactly one text block, got %s", res.Content)
	}
	var env struct {
		Status   int                 `json:"status"`
		Headers  map[string][]string `json:"headers"`
		Body     json.RawMessage     `json:"body"`
		Encoding string              `json:"encoding"`
	}
	if err := json.Unmarshal([]byte(blocks[0].Text), &env); err != nil {
		t.Fatalf("envelope: %v (%s)", err, blocks[0].Text)
	}
	return env.Status, env.Headers, env.Body, env.Encoding
}

func TestDial_RefusesWhatItMustRefuse(t *testing.T) {
	d := newDialer(t, &fakeVault{secrets: map[string]string{"KEY": "k"}})
	keyed := map[string]string{"KEY": "k"}

	cases := []struct {
		name string
		spec gateway.UpstreamSpec
		env  map[string]string
		want error
	}{
		{"stdio transport", gateway.UpstreamSpec{Name: "x", Transport: "stdio", Command: "/bin/true"}, nil, resthttp.ErrUnsupportedTransport},
		{"oci transport", gateway.UpstreamSpec{Name: "x", Transport: "oci"}, nil, resthttp.ErrUnsupportedTransport},
		{"empty url", spec(t, "", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"ftp scheme", spec(t, "ftp://h/", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"no host", spec(t, "https:///path", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"userinfo", spec(t, "https://user:pw@h/", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"query", spec(t, "https://h/?k=v", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"fragment", spec(t, "https://h/#f", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"base path with dot segment", spec(t, "https://h/a/../b", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"base path with template", spec(t, "https://h/{v}", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		// A base ending in "//" used to be trimmed to "/" (or "/api/") before
		// ParsePath saw it, and every request then began "//check": the "//"
		// ParsePath refuses in a template, smuggled in by the base.
		{"base path is //", spec(t, "https://h//", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"base path ends in //", spec(t, "https://h/api//", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"base path with // inside", spec(t, "https://h/api//v2", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		// A host that is already a forbidden literal fails at dial (and at
		// register, TestValidateBaseURL_RefusesAForbiddenLiteralHost), not on
		// the first call. This dialer allows loopback, so the metadata address
		// and a private one stand in.
		{"literal link-local host", spec(t, "http://169.254.169.254/latest", resthttp.AuthNone, ""), nil, resthttp.ErrEgressRefused},
		{"literal private host", spec(t, "https://10.0.0.1/", resthttp.AuthNone, ""), nil, resthttp.ErrInvalidURL},
		{"keyless with a secret", spec(t, "https://h/", resthttp.AuthNone, ""), keyed, resthttp.ErrAuthMismatch},
		{"keyed without a secret", spec(t, "https://h/", resthttp.AuthHeader, "X-API-Key"), nil, resthttp.ErrAuthMismatch},
		{"keyed with two secrets", spec(t, "https://h/", resthttp.AuthHeader, "X-API-Key"), map[string]string{"A": "1", "B": "2"}, resthttp.ErrAuthMismatch},
		{"bearer with a name", spec(t, "https://h/", resthttp.AuthBearer, "X"), keyed, resthttp.ErrInvalidOperations},
		{"bad operations", gateway.UpstreamSpec{Name: "x", Transport: "http", URL: "https://h/", Operations: []byte(`[{"name":"a","method":"GET","path":"evil","inputSchema":{"type":"object"}}]`)}, nil, resthttp.ErrInvalidOperations},
		{"empty operations", gateway.UpstreamSpec{Name: "x", Transport: "http", URL: "https://h/", Operations: []byte(`[]`)}, nil, resthttp.ErrInvalidOperations},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up, err := d.Dial(context.Background(), tc.spec, tc.env)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if up != nil {
				t.Errorf("a refused dial must return no upstream")
			}
		})
	}

	// A keyed entry through a dialer with no vault is refused at dial.
	noVault := newDialer(t, nil)
	if _, err := noVault.Dial(context.Background(), spec(t, "https://h/", resthttp.AuthHeader, "X-API-Key"), keyed); !errors.Is(err, resthttp.ErrNoVault) {
		t.Errorf("want ErrNoVault, got %v", err)
	}
	// A keyless entry through it is fine.
	if _, err := noVault.Dial(context.Background(), spec(t, "https://h/", resthttp.AuthNone, ""), nil); err != nil {
		t.Errorf("keyless without vault: %v", err)
	}
}

func TestParseBase_PinsSchemeHostPortAndFoldsTheBasePath(t *testing.T) {
	cases := []struct{ in, origin, path string }{
		{"https://api.example.com", "https://api.example.com:443", ""},
		{"https://api.example.com/", "https://api.example.com:443", ""},
		{"https://API.example.com:443/api/v2/", "https://api.example.com:443", "/api/v2"},
		{"http://api.example.com:8080/x", "http://api.example.com:8080", "/x"},
		{"http://[::1]:9/x", "http://[::1]:9", "/x"},
	}
	for _, tc := range cases {
		b, err := resthttp.ParseBase(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		origin, path := resthttp.BaseOrigin(b)
		if origin != tc.origin || path != tc.path {
			t.Errorf("%s: got origin %q path %q, want %q %q", tc.in, origin, path, tc.origin, tc.path)
		}
		if strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
			t.Errorf("%s: base path %q breaks parseBase's post-condition", tc.in, path)
		}
	}
}

// TestValidateBaseURL_RefusesAForbiddenLiteralHost: the console's seam
// applies the egress policy to a host that is already an address, so an
// entry the adapter would refuse on every call is refused at register/sign
// (ADR-0047 §2). A host NAME is not resolved and passes; a public literal
// passes.
func TestValidateBaseURL_RefusesAForbiddenLiteralHost(t *testing.T) {
	for _, raw := range []string{
		"http://169.254.169.254/latest", "http://127.0.0.1/", "https://10.0.0.1/v1",
		"http://[::1]:8080", "http://0.0.0.0/", "http://100.64.0.1/", "http://[::ffff:127.0.0.1]/",
	} {
		err := resthttp.ValidateBaseURL(raw)
		if !errors.Is(err, resthttp.ErrInvalidURL) || !errors.Is(err, resthttp.ErrEgressRefused) {
			t.Errorf("%s: want ErrInvalidURL wrapping ErrEgressRefused, got %v", raw, err)
		}
	}
	for _, raw := range []string{"https://api.example.com/v2", "http://203.0.113.10:8080/", "https://[2001:db8::1]/"} {
		if err := resthttp.ValidateBaseURL(raw); err != nil {
			t.Errorf("%s: want accepted, got %v", raw, err)
		}
	}
}

func TestListTools_ClassFollowsTheMethod(t *testing.T) {
	up := dialKeyless(t, newDialer(t, nil), "https://h/")
	defs, err := up.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]quarantine.Class{"check": quarantine.ClassSafe, "ping": quarantine.ClassSafe, "report": quarantine.ClassSensitive}
	if len(defs) != len(want) {
		t.Fatalf("got %d tools, want %d", len(defs), len(want))
	}
	for _, def := range defs {
		if def.SecurityClass != want[def.Name] {
			t.Errorf("%s: class %q, want %q", def.Name, def.SecurityClass, want[def.Name])
		}
		if len(def.InputSchema) == 0 {
			t.Errorf("%s: no input schema", def.Name)
		}
	}
}

func TestCallTool_GETPlacesEveryArgumentWhereItBelongs(t *testing.T) {
	srv, got := recorder(t, 200, nil)
	up := dialKeyless(t, newDialer(t, nil), srv.URL+"/api/v2/")

	args := `{"path_ip":"1.2.3.4 x","query_maxAgeInDays":90,"query_tags":["a","b c"],"header_Accept":"application/json","cookie_session":"abc123"}`
	res, err := up.CallTool(context.Background(), "check", []byte(args))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if got.Method != "GET" || got.Path != "/api/v2/check/1.2.3.4%20x" {
		t.Errorf("request line: %s %s", got.Method, got.Path)
	}
	if got.RawQuery != "maxAgeInDays=90&tags=a&tags=b+c" {
		t.Errorf("query: %s", got.RawQuery)
	}
	if got.Header.Get("Accept") != "application/json" || got.Header.Get("Cookie") != "session=abc123" {
		t.Errorf("headers: %v", got.Header)
	}
	if got.Header.Get("Authorization") != "" || strings.Contains(got.RawQuery, "key") {
		t.Errorf("keyless entry sent a credential: %v %s", got.Header, got.RawQuery)
	}
	if res.IsError {
		t.Errorf("200 is not an error")
	}
	status, headers, body, _ := decodeEnvelope(t, res)
	if status != 200 || headers["Content-Type"][0] != "application/json" || string(body) != `{"ok":true}` {
		t.Errorf("envelope: %d %v %s", status, headers, body)
	}
	if string(res.StructuredContent) != `{"ok":true}` {
		t.Errorf("structured content: %s", res.StructuredContent)
	}
}

func TestCallTool_POSTSendsTheBodyAsJSON(t *testing.T) {
	srv, got := recorder(t, 201, nil)
	up := dialKeyless(t, newDialer(t, nil), srv.URL)

	res, err := up.CallTool(context.Background(), "report", []byte(`{"body":{"ip":"1.2.3.4","categories":[1,2]},"query_dry":true}`))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if got.Method != "POST" || got.Path != "/report" || got.RawQuery != "dry=true" {
		t.Errorf("request line: %s %s?%s", got.Method, got.Path, got.RawQuery)
	}
	if got.Header.Get("Content-Type") != "application/json" || string(got.Body) != `{"ip":"1.2.3.4","categories":[1,2]}` {
		t.Errorf("body: %s %s", got.Header.Get("Content-Type"), got.Body)
	}
	if res.IsError {
		t.Errorf("201 is not an error")
	}
	// A POST without a body sends none and no Content-Type.
	if _, err := up.CallTool(context.Background(), "report", nil); err != nil {
		t.Fatal(err)
	}
	if len(got.Body) != 0 || got.Header.Get("Content-Type") != "" {
		t.Errorf("empty POST sent a body or content type: %q %q", got.Body, got.Header.Get("Content-Type"))
	}
}

func TestCallTool_InjectsTheCredentialWhereTheKindSaysAndNowhereElse(t *testing.T) {
	const secret = "sk-live-9f8e7d"
	v := &fakeVault{secrets: map[string]string{"API_KEY": secret}}
	for _, tc := range []struct{ kind, name string }{
		{resthttp.AuthBearer, ""},
		{resthttp.AuthHeader, "X-API-Key"},
		{resthttp.AuthQuery, "api_key"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			srv, got := recorder(t, 200, nil)
			up := dialKeyed(t, newDialer(t, v), srv.URL, tc.kind, tc.name, "API_KEY", secret)
			before := v.calls.Load()
			if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4","query_maxAgeInDays":1}`)); err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if v.calls.Load() != before+1 {
				t.Errorf("secret resolved %d times for one call", v.calls.Load()-before)
			}
			auth, apiKey, query := got.Header.Get("Authorization"), got.Header.Get("X-API-Key"), got.RawQuery
			switch tc.kind {
			case resthttp.AuthBearer:
				if auth != "Bearer "+secret || apiKey != "" || strings.Contains(query, secret) {
					t.Errorf("bearer: auth=%q apiKey=%q query=%q", auth, apiKey, query)
				}
			case resthttp.AuthHeader:
				if apiKey != secret || auth != "" || strings.Contains(query, secret) {
					t.Errorf("header: auth=%q apiKey=%q query=%q", auth, apiKey, query)
				}
			case resthttp.AuthQuery:
				if query != "api_key="+secret+"&maxAgeInDays=1" || auth != "" || apiKey != "" {
					t.Errorf("query: auth=%q apiKey=%q query=%q", auth, apiKey, query)
				}
			}
			// A second call resolves again: nothing was cached.
			if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4"}`)); err != nil {
				t.Fatal(err)
			}
			if v.calls.Load() != before+2 {
				t.Errorf("secret not re-resolved on the second call")
			}
		})
	}
}

func TestCallTool_CredentialProblemsAreRefusedBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)

	// The vault has no such secret.
	up := dialKeyed(t, newDialer(t, &fakeVault{secrets: map[string]string{}}), srv.URL, resthttp.AuthHeader, "X-API-Key", "MISSING", "x")
	if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`)); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("want vault.ErrNotFound, got %v", err)
	}
	// The vault resolves it to nothing.
	up = dialKeyed(t, newDialer(t, &fakeVault{secrets: map[string]string{"EMPTY": ""}}), srv.URL, resthttp.AuthHeader, "X-API-Key", "EMPTY", "x")
	if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`)); !errors.Is(err, resthttp.ErrNoCredential) {
		t.Errorf("want ErrNoCredential, got %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("%d request(s) reached the server without a credential", hits.Load())
	}
}

func TestCallTool_NonTwoXXIsAnErrorResultWithTheStatus(t *testing.T) {
	srv, _ := recorder(t, 0, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"detail":"no such ip"}`))
	})
	up := dialKeyless(t, newDialer(t, nil), srv.URL)
	res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4"}`))
	if err != nil {
		t.Fatalf("a 404 is a result, not an error: %v", err)
	}
	if !res.IsError {
		t.Errorf("404 must be IsError")
	}
	status, headers, body, _ := decodeEnvelope(t, res)
	if status != 404 || string(body) != `{"detail":"no such ip"}` {
		t.Errorf("envelope: %d %s", status, body)
	}
	if got := headers["Set-Cookie"]; len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Errorf("repeated headers must all be carried: %v", headers)
	}
	if res.StructuredContent != nil {
		t.Errorf("an error result carries no structured content: %s", res.StructuredContent)
	}
}

func TestCallTool_BodyShapes(t *testing.T) {
	t.Run("non-JSON text", func(t *testing.T) {
		srv, _ := recorder(t, 0, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello {not json"))
		})
		up := dialKeyless(t, newDialer(t, nil), srv.URL)
		res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _, body, enc := decodeEnvelope(t, res)
		if string(body) != `"hello {not json"` || enc != "" || res.StructuredContent != nil {
			t.Errorf("text body: %s enc=%q structured=%s", body, enc, res.StructuredContent)
		}
	})
	t.Run("JSON media type but invalid JSON falls back to text", func(t *testing.T) {
		srv, _ := recorder(t, 0, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{broken"))
		})
		up := dialKeyless(t, newDialer(t, nil), srv.URL)
		res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _, body, _ := decodeEnvelope(t, res)
		if string(body) != `"{broken"` || res.StructuredContent != nil {
			t.Errorf("body: %s structured=%s", body, res.StructuredContent)
		}
	})
	t.Run("binary is base64", func(t *testing.T) {
		srv, _ := recorder(t, 0, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte{0xff, 0xfe, 0x00, 'a'})
		})
		up := dialKeyless(t, newDialer(t, nil), srv.URL)
		res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _, body, enc := decodeEnvelope(t, res)
		if string(body) != `"//4AYQ=="` || enc != "base64" {
			t.Errorf("binary body: %s enc=%q", body, enc)
		}
	})
	t.Run("HEAD has an empty body", func(t *testing.T) {
		srv, got := recorder(t, 204, nil)
		up := dialKeyless(t, newDialer(t, nil), srv.URL)
		res, err := up.CallTool(context.Background(), "ping", nil)
		if err != nil {
			t.Fatal(err)
		}
		status, _, body, _ := decodeEnvelope(t, res)
		if got.Method != "HEAD" || status != 204 || string(body) != `""` || res.IsError {
			t.Errorf("HEAD: %s %d %s isError=%v", got.Method, status, body, res.IsError)
		}
	})
}

func TestCallTool_BodyOverTheCeilingIsRefusedNotTruncated(t *testing.T) {
	payload := strings.Repeat("x", 100)
	srv, _ := recorder(t, 0, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(payload))
	})
	up := dialKeyless(t, newDialer(t, nil, resthttp.WithMaxBodyBytes(99)), srv.URL)
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if !errors.Is(err, resthttp.ErrBodyTooLarge) {
		t.Fatalf("want ErrBodyTooLarge, got %v", err)
	}
	// Exactly at the ceiling is fine.
	up = dialKeyless(t, newDialer(t, nil, resthttp.WithMaxBodyBytes(100)), srv.URL)
	res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, body, _ := decodeEnvelope(t, res); string(body) != `"`+payload+`"` {
		t.Errorf("body at the ceiling: %s", body)
	}
}

func TestCallTool_RedirectToAnotherHostIsRefused(t *testing.T) {
	var bHits atomic.Int32
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { bHits.Add(1) }))
	t.Cleanup(b.Close)
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/elsewhere", http.StatusFound)
	}))
	t.Cleanup(a.Close)

	// A and B are both loopback, so only the port differs: the pin is on
	// scheme+host+port, and that is enough to refuse.
	up := dialKeyed(t, newDialer(t, &fakeVault{secrets: map[string]string{"K": "s3cret"}}), a.URL, resthttp.AuthHeader, "X-API-Key", "K", "s3cret")
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("want ErrEgressRefused, got %v", err)
	}
	if bHits.Load() != 0 {
		t.Errorf("the other host received %d request(s)", bHits.Load())
	}
	if strings.Contains(err.Error(), "/elsewhere") {
		t.Errorf("the refused Location's path leaked into the error: %v", err)
	}
}

func TestCallTool_SameOriginRedirectsAreFollowedUpToALimit(t *testing.T) {
	var hops atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		switch r.URL.Path {
		case "/check/1":
			http.Redirect(w, r, "/v2/check/1", http.StatusMovedPermanently)
		case "/v2/check/1":
			if r.Header.Get("X-API-Key") != "s3cret" {
				t.Errorf("credential lost on a same-origin redirect: %v", r.Header)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"moved":true}`))
		case "/report":
			// A loop: never resolves.
			http.Redirect(w, r, "/report", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	up := dialKeyed(t, newDialer(t, &fakeVault{secrets: map[string]string{"K": "s3cret"}}), srv.URL, resthttp.AuthHeader, "X-API-Key", "K", "s3cret")

	res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if err != nil {
		t.Fatalf("one same-origin hop must be followed: %v", err)
	}
	if status, _, body, _ := decodeEnvelope(t, res); status != 200 || string(body) != `{"moved":true}` {
		t.Errorf("after redirect: %d %s", status, body)
	}

	hops.Store(0)
	res, err = up.CallTool(context.Background(), "report", nil)
	if err != nil {
		t.Fatalf("past the limit the last 3xx is a result, not an error: %v", err)
	}
	status, headers, _, _ := decodeEnvelope(t, res)
	if !res.IsError || status != 307 || len(headers["Location"]) != 1 {
		t.Errorf("redirect past the limit: isError=%v status=%d headers=%v", res.IsError, status, headers)
	}
	// Pinned exactly: maxRedirects (3) is the number of requests a chain
	// may send, so two redirects are followed and the third 3xx is the
	// answer. A change to the arithmetic in checkRedirect shows up here.
	if hops.Load() != 3 {
		t.Errorf("sent %d requests in the loop, want exactly 3 (maxRedirects)", hops.Load())
	}
}

// TestCallTool_ArgumentsAreRefusedBeforeAnyRequest: an argument the
// operation cannot carry is answered as a Result{IsError} naming the fault
// -- not as an error, which the gateway would report as the backend's
// failure (ADR-0041 item 2; ADR-0048 Decisão 9, dated note) -- and costs
// neither a request nor a vault resolve. An unknown tool stays an error: it
// is a gateway/adapter disagreement, not a caller mistake.
func TestCallTool_ArgumentsAreRefusedBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	v := &fakeVault{secrets: map[string]string{"K": "s"}}
	up := dialKeyed(t, newDialer(t, v), srv.URL, resthttp.AuthHeader, "X-API-Key", "K", "s")

	refused := map[string]struct{ args, reason string }{
		"not an object":                   {`[1,2]`, "JSON object"},
		"undeclared key":                  {`{"path_ip":"1","foo":"bar"}`, `"foo" is not a declared property`},
		"undeclared query":                {`{"path_ip":"1","query_debug":"true"}`, `"query_debug" is not a declared property`},
		"the Authorization header":        {`{"path_ip":"1","header_authorization":"Bearer x"}`, "not a declared property"},
		"the credential's own header":     {`{"path_ip":"1","header_X-API-Key":"other"}`, "not a declared property"},
		"a body on a GET":                 {`{"path_ip":"1","body":{}}`, "not a declared property"},
		"missing path value":              {`{"query_maxAgeInDays":1}`, "has no path_ip argument"},
		"empty path value":                {`{"path_ip":""}`, "must not be empty"},
		"path value with a slash":         {`{"path_ip":"1/../../admin"}`, `must not contain "/"`},
		"dot-dot path value":              {`{"path_ip":".."}`, "dot segment"},
		"path value with CRLF":            {`{"path_ip":"1\r\nX: y"}`, "control byte"},
		"header value with CRLF":          {`{"path_ip":"1","header_Accept":"a\r\nX-Injected: y"}`, "control byte"},
		"cookie value with a semicolon":   {`{"path_ip":"1","cookie_session":"a;b"}`, "cookie-octet"},
		"object where a scalar is needed": {`{"path_ip":{"x":1}}`, "string, number or boolean"},
		"null path value":                 {`{"path_ip":null}`, "string, number or boolean"},
		"trailing data":                   {`{"path_ip":"1"} {}`, "trailing data"},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			res, err := up.CallTool(context.Background(), "check", []byte(tc.args))
			if err != nil {
				t.Fatalf("a refused argument is a result, not an error: %v", err)
			}
			if !res.IsError || res.StructuredContent != nil {
				t.Fatalf("want IsError with no structured content, got %+v", res)
			}
			text := textOf(t, res)
			if !strings.Contains(text, `tool "check"`) || !strings.Contains(text, tc.reason) {
				t.Errorf("the refusal must name the tool and the fault %q: %s", tc.reason, text)
			}
			if strings.Contains(text, "Bearer x") || strings.Contains(text, "other") || strings.Contains(text, "X-Injected") {
				t.Errorf("the refusal echoed an argument value: %s", text)
			}
		})
	}
	if _, err := up.CallTool(context.Background(), "nope", nil); !errors.Is(err, resthttp.ErrUnknownTool) {
		t.Errorf("unknown tool: want ErrUnknownTool, got %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("%d refused call(s) still reached the server", hits.Load())
	}
	if v.calls.Load() != 0 {
		t.Errorf("%d refused call(s) resolved the secret first", v.calls.Load())
	}
}

// textOf returns the text of a Result's single text block.
func textOf(t *testing.T, res gateway.Result) string {
	t.Helper()
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(res.Content, &blocks); err != nil || len(blocks) != 1 || blocks[0].Type != "text" {
		t.Fatalf("want exactly one text block, got %s (%v)", res.Content, err)
	}
	return blocks[0].Text
}

// TestCallTool_ClientTimeoutIsADeadlineNotDeath: WithHTTPClientTimeout is
// the backstop for a caller WITHOUT a deadline (the gateway always sets
// one). http.Client.Timeout reports as context.DeadlineExceeded through the
// redaction, so the gateway's dispatch reads it as a timeout, never as the
// upstream gone; cmd/mcp-gateway/dialer.go equalises it with call_timeout
// on that reading.
func TestCallTool_ClientTimeoutIsADeadlineNotDeath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	up := dialKeyless(t, newDialer(t, nil, resthttp.WithHTTPClientTimeout(50*time.Millisecond)), srv.URL)
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded through the scrubbed error, got %v", err)
	}
	if errors.Is(err, gateway.ErrUpstreamGone) || errors.Is(err, resthttp.ErrEgressRefused) {
		t.Errorf("a client timeout must read as a timeout only: %v", err)
	}
}

// TestCallTool_MasksTheValueItInjectedEvenAfterARotation: the server
// reflects the credential (header, Location-style header and body) and the
// vault rotates it DURING the exchange -- after the adapter resolved it,
// before anything downstream could re-resolve. The gateway's scrubResult
// would mask the new value and miss the old; the adapter masks with the
// one it injected (ADR-0047 §5, dated note), so the Result never carries
// it in any rendering.
func TestCallTool_MasksTheValueItInjectedEvenAfterARotation(t *testing.T) {
	const injected = "sk-live-9f8e7d/old+value"
	v := &fakeVault{secrets: map[string]string{"API_KEY": injected}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The rotation happens here: the request already carries `injected`.
		v.secrets["API_KEY"] = "sk-live-rotated"
		key := r.Header.Get("X-API-Key")
		w.Header().Set("X-Echo", key)
		w.Header().Set("Location", "/login?key="+url.QueryEscape(key))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_, _ = fmt.Fprintf(w, `{"error":"bad key","key":%q,"quoted":"%s"}`, key, strconv.Quote(key)[1:len(strconv.Quote(key))-1])
	}))
	t.Cleanup(srv.Close)
	up := dialKeyed(t, newDialer(t, v), srv.URL, resthttp.AuthHeader, "X-API-Key", "API_KEY", injected)

	res, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	for _, form := range []string{injected, url.QueryEscape(injected), url.PathEscape(injected), "9f8e7d/old"} {
		if strings.Contains(string(res.Content), form) {
			t.Errorf("the Result carries the injected value as %q: %s", form, res.Content)
		}
	}
	status, headers, _, _ := decodeEnvelope(t, res)
	if status != 401 || !res.IsError {
		t.Errorf("status %d isError=%v", status, res.IsError)
	}
	if headers["X-Echo"][0] == injected || !strings.Contains(headers["Location"][0], "key=") {
		t.Errorf("headers after masking: %v", headers)
	}
	// Keyless: nothing to mask, and the body passes through untouched.
	plain := dialKeyless(t, newDialer(t, nil), srv.URL)
	if _, err := plain.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`)); err != nil {
		t.Errorf("keyless call: %v", err)
	}
}

func TestCallTool_CancelledContextIsReportedAsSuchAndNeverAsGone(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	up := dialKeyed(t, newDialer(t, &fakeVault{secrets: map[string]string{"K": "s3cret"}}), srv.URL, resthttp.AuthQuery, "key", "K", "s3cret")

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := up.CallTool(ctx, "check", []byte(`{"path_ip":"1"}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if errors.Is(err, gateway.ErrUpstreamGone) {
		t.Errorf("a cancelled call must never read as the upstream gone")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = up.CallTool(ctx, "check", []byte(`{"path_ip":"1"}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
}

func TestCallTool_ConnectionRefusedIsAFailureNotDeath(t *testing.T) {
	up := dialKeyless(t, newDialer(t, nil), closedPort(t))
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if err == nil || errors.Is(err, gateway.ErrUpstreamGone) || errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("want a plain failure, got %v", err)
	}
	// After the failure the upstream is still usable: stateless.
	if _, err := up.ListTools(context.Background()); err != nil {
		t.Errorf("ListTools after a failed call: %v", err)
	}
}

func TestClose_IsIdempotentAndLeavesTheUpstreamUsable(t *testing.T) {
	srv, _ := recorder(t, 200, nil)
	up := dialKeyless(t, newDialer(t, nil), srv.URL)
	if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := up.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
}

func TestCallTool_DeclinesAnUnverifiableTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	up := dialKeyless(t, newDialer(t, nil), srv.URL)
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`))
	if err == nil {
		t.Fatal("a self-signed certificate must not verify")
	}
	if errors.Is(err, gateway.ErrUpstreamGone) {
		t.Errorf("a TLS failure must never read as gone")
	}
}

// closedPort returns an http URL to a loopback port nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr
}
