package httpapi

// Test doubles policy, stated once so the choices are reviewable rather
// than incidental. It follows internal/gateway/gateway_test.go's:
//
//   - The Gateway under the handler is the REAL *gateway.Gateway, over the
//     REAL SQLite-backed Tool Quarantine and Audit Trail. The property
//     these tests exist to check is "a caller sees exactly the tools their
//     identity is entitled to, and nothing else reaches them", and a mocked
//     Gateway would be a mock of precisely the filtering under test. Only
//     the Gateway's own outward ports -- Registry, Vault, Dialer, Upstream
//     -- are fakes, because each has to fail on command.
//
//   - access.TokenVerifier is a fake. A real OIDC round trip (JWKS,
//     signatures, audience, expiry) is already covered hermetically in
//     internal/access/oidc; repeating it here would test go-oidc again
//     instead of testing this handler's seam. What matters here is what the
//     handler does with a verifier's yes and with its no.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// ---------------------------------------------------------------- fakes

type fakeUpstream struct {
	mu      sync.Mutex
	defs    []gateway.ToolDef
	result  gateway.Result
	callErr error
	calls   []string
}

func (u *fakeUpstream) ListTools(context.Context) ([]gateway.ToolDef, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.defs), nil
}

func (u *fakeUpstream) CallTool(_ context.Context, tool string, _ json.RawMessage) (gateway.Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, tool)
	if u.callErr != nil {
		return gateway.Result{}, u.callErr
	}
	return u.result, nil
}

func (u *fakeUpstream) Close() error { return nil }

type fakeDialer struct {
	mu        sync.Mutex
	upstreams map[string]*fakeUpstream
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{upstreams: map[string]*fakeUpstream{}}
}

func (d *fakeDialer) Dial(_ context.Context, spec gateway.UpstreamSpec, _ map[string]string) (gateway.Upstream, error) {
	return d.upstream(spec.Name), nil
}

func (d *fakeDialer) upstream(name string) *fakeUpstream {
	d.mu.Lock()
	defer d.mu.Unlock()
	up, ok := d.upstreams[name]
	if !ok {
		up = &fakeUpstream{}
		d.upstreams[name] = up
	}
	return up
}

type fakeRegistry struct {
	mu      sync.Mutex
	entries []registry.UpstreamServer
}

func (r *fakeRegistry) List(context.Context) ([]registry.UpstreamServer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.entries), nil
}

func (r *fakeRegistry) Register(context.Context, registry.UpstreamServer) error {
	return errors.New("not used in these tests")
}

func (r *fakeRegistry) Get(context.Context, string) (registry.UpstreamServer, error) {
	return registry.UpstreamServer{}, registry.ErrNotFound
}

func (r *fakeRegistry) Deregister(context.Context, string) error { return registry.ErrNotFound }

// fakeVault resolves nothing, because no upstream in these tests names a
// credential. It exists so gateway.New has a non-nil port.
type fakeVault struct{}

func (fakeVault) Resolve(context.Context, string) (vault.Secret, error) {
	return vault.Secret{}, vault.ErrNotFound
}

// fakeVerifier is the authentication seam under test: a token is either in
// the table or it is not.
//
// Its rejection is uniform and wraps access.ErrUnauthenticated, matching
// the contract in access.TokenVerifier's doc comment and what
// oidc.Verifier really does. The deliberately juicy text is there so the
// leak tests have something real to catch if it ever reaches a client.
type fakeVerifier struct {
	tokens map[string]access.Identity
}

func (v fakeVerifier) Verify(_ context.Context, raw string) (access.Identity, error) {
	if id, ok := v.tokens[raw]; ok {
		return id, nil
	}
	return access.Identity{}, fmt.Errorf("%w: token could not be verified", access.ErrUnauthenticated)
}

var (
	_ gateway.Upstream     = (*fakeUpstream)(nil)
	_ gateway.Dialer       = (*fakeDialer)(nil)
	_ registry.Repository  = (*fakeRegistry)(nil)
	_ vault.Provider       = (*fakeVault)(nil)
	_ access.TokenVerifier = (*fakeVerifier)(nil)
)

// -------------------------------------------------------------- harness

// The fleet these tests serve. Two upstreams, four tools, arranged so that
// every gate has something on both sides of it:
//
//	casemgmt.list_cases     approved, in both roles
//	casemgmt.delete_case    approved, in dfir-lead only  -> the "not yours" case
//	casemgmt.pending_tool   in n1-triage, never approved -> the quarantine case
//	logsearch.search      approved, in n1-triage only
const (
	toolListCases   = "casemgmt.list_cases"
	toolDeleteCase  = "casemgmt.delete_case"
	toolPending     = "casemgmt.pending_tool"
	toolSearch      = "logsearch.search"
	toolNonexistent = "casemgmt.no_such_tool_anywhere"
)

const objSchema = `{"type":"object","properties":{"q":{"type":"string"}}}`

// Identities. The subjects are distinctive strings so a leak test can grep
// for them in a response body.
var (
	analyst   = access.Identity{Subject: "sub-analyst-CANARY-1", Name: "Ana Lyst", Groups: []string{"soc-n1"}}
	responder = access.Identity{Subject: "sub-dfir-CANARY-7", Name: "Dee Fir", Groups: []string{"soc-dfir"}}
	stranger  = access.Identity{Subject: "sub-nobody-CANARY-9", Name: "No Body", Groups: []string{"marketing"}}
)

const (
	tokenAnalyst   = "token-for-the-analyst"
	tokenResponder = "token-for-the-responder"
	tokenStranger  = "token-for-the-stranger"
)

type harness struct {
	t       *testing.T
	gw      *gateway.Gateway
	handler *Handler
	server  *httptest.Server
	db      *sql.DB
	dialer  *fakeDialer
	logs    *bytes.Buffer
}

// harnessOptions lets one test bend the wiring without every other test
// paying for the knob.
type harnessOptions struct {
	// wrapQuarantine decorates the real Tool Quarantine the Gateway is
	// given, so a test can make it misbehave in a way no real store would
	// on demand.
	wrapQuarantine func(quarantine.Store) quarantine.Store
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, harnessOptions{})
}

func newHarnessWith(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quarantinesql.Migrate(db); err != nil {
		t.Fatalf("quarantine migrate: %v", err)
	}
	if err := auditsql.Migrate(db); err != nil {
		t.Fatalf("audit migrate: %v", err)
	}
	q := quarantinesql.New(db)
	// served is what the Gateway consults; q is what the test approves
	// through, so setup always goes to the real store.
	var served quarantine.Store = q
	if opts.wrapQuarantine != nil {
		served = opts.wrapQuarantine(q)
	}

	policy, err := access.NewPolicy(
		[]access.Role{
			{Name: "n1-triage", Tools: []string{toolListCases, toolPending, toolSearch}},
			{Name: "dfir-lead", Tools: []string{toolListCases, toolDeleteCase}},
		},
		map[string]string{"soc-n1": "n1-triage", "soc-dfir": "dfir-lead"},
	)
	if err != nil {
		t.Fatalf("access.NewPolicy: %v", err)
	}

	reg := &fakeRegistry{}
	for _, name := range []string{"casemgmt", "logsearch"} {
		entry := registry.UpstreamServer{
			Name:      name,
			Transport: registry.TransportStdio,
			Command:   "/usr/bin/" + name,
		}
		if err := entry.Validate(); err != nil {
			t.Fatalf("test entry %q invalid: %v", name, err)
		}
		reg.entries = append(reg.entries, entry)
	}

	dialer := newFakeDialer()
	dialer.upstream("casemgmt").defs = []gateway.ToolDef{
		{Name: "list_cases", Description: "List CASEMGMT cases.", InputSchema: json.RawMessage(objSchema)},
		{Name: "delete_case", Description: "Delete an CASEMGMT case.", InputSchema: json.RawMessage(objSchema)},
		{Name: "pending_tool", Description: "Never approved.", InputSchema: json.RawMessage(objSchema)},
	}
	dialer.upstream("casemgmt").result = gateway.Result{Content: json.RawMessage(`[{"type":"text","text":"case 42"}]`)}
	dialer.upstream("logsearch").defs = []gateway.ToolDef{
		{Name: "search", Description: "Search Logsearch.", InputSchema: json.RawMessage(objSchema)},
	}
	dialer.upstream("logsearch").result = gateway.Result{Content: json.RawMessage(`[{"type":"text","text":"0 hits"}]`)}

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	gw, err := gateway.New(gateway.Config{
		Registry:   reg,
		Vault:      fakeVault{},
		Quarantine: served,
		Audit:      auditsql.New(db),
		Policy:     policy,
		Dialer:     dialer,
		Now:        func() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) },
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	if err := gw.Connect(context.Background()); err != nil {
		t.Fatalf("gateway.Connect: %v", err)
	}
	for _, pair := range [][2]string{{"casemgmt", "list_cases"}, {"casemgmt", "delete_case"}, {"logsearch", "search"}} {
		if _, err := q.Approve(context.Background(), pair[0], pair[1]); err != nil {
			t.Fatalf("Approve(%q, %q): %v", pair[0], pair[1], err)
		}
	}
	// casemgmt.pending_tool is deliberately left unapproved.

	handler, err := New(Config{
		Gateway: gw,
		Verifier: fakeVerifier{tokens: map[string]access.Identity{
			tokenAnalyst:   analyst,
			tokenResponder: responder,
			tokenStranger:  stranger,
		}},
		Policy:               policy,
		Resource:             "http://127.0.0.1/mcp",
		AuthorizationServers: []string{"https://auth.soc.internal/realms/soc"},
		ServerName:           "mcp-gateway-test",
		ServerVersion:        "0.0.1",
		Logger:               logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &harness{t: t, gw: gw, handler: handler, server: srv, db: db, dialer: dialer, logs: logs}
}

// endpoint is the MCP endpoint: any path that is not the metadata path.
func (h *harness) endpoint() string { return h.server.URL + "/mcp" }

// post sends one raw JSON-RPC request, so a test can look at the HTTP
// response the way an attacker would rather than through the SDK client.
// A token of "" sends no Authorization header at all.
func (h *harness) post(path, token, body string) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	res, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	h.t.Cleanup(func() { res.Body.Close() })
	return res
}

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}`

func body(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return string(b)
}

// authTransport injects the bearer credential the way a real MCP client
// would: in the header, on every request.
type authTransport struct {
	token string
	inner http.RoundTripper
}

func (t authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	if t.token != "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	inner := t.inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(clone)
}

// session opens a real MCP session over streamable HTTP as the holder of
// token.
func (h *harness) session(token string) *mcp.ClientSession {
	h.t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   h.endpoint(),
		HTTPClient: &http.Client{Transport: authTransport{token: token}},
		// Stateless servers answer GET with 405, so there is no standalone
		// SSE stream to establish.
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	if err != nil {
		h.t.Fatalf("connecting as %q: %v", token, err)
	}
	h.t.Cleanup(func() { cs.Close() })
	return cs
}

// toolNames lists what a session can see, sorted.
func (h *harness) toolNames(cs *mcp.ClientSession) []string {
	h.t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		h.t.Fatalf("tools/list: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// ------------------------------------------------------------ construction

func TestNewRequiresEveryPort(t *testing.T) {
	h := newHarness(t)
	base := func() Config {
		return Config{
			Gateway:              h.gw,
			Verifier:             fakeVerifier{},
			Policy:               &access.Policy{},
			Resource:             "https://gw.soc.internal/mcp",
			AuthorizationServers: []string{"https://auth.soc.internal"},
			Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
	}

	tests := map[string]func(*Config){
		"no gateway":               func(c *Config) { c.Gateway = nil },
		"no verifier":              func(c *Config) { c.Verifier = nil },
		"no policy":                func(c *Config) { c.Policy = nil },
		"no resource":              func(c *Config) { c.Resource = "  " },
		"no authorization servers": func(c *Config) { c.AuthorizationServers = nil },
		"relative resource":        func(c *Config) { c.Resource = "/mcp" },
		"resource with fragment":   func(c *Config) { c.Resource = "https://gw.soc.internal/mcp#x" },
		"resource with query":      func(c *Config) { c.Resource = "https://gw.soc.internal/mcp?a=b" },
		// An http:// resource identifier is an instruction to every client
		// that reads the metadata to put a bearer token on the wire in
		// cleartext. Refused unless explicitly overridden.
		"insecure resource":             func(c *Config) { c.Resource = "http://gw.soc.internal/mcp" },
		"insecure authorization server": func(c *Config) { c.AuthorizationServers = []string{"http://auth.soc.internal"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted a configuration it should have refused")
			}
		})
	}

	t.Run("loopback http is allowed", func(t *testing.T) {
		cfg := base()
		cfg.Resource = "http://127.0.0.1:8080/mcp"
		if _, err := New(cfg); err != nil {
			t.Fatalf("New refused a loopback resource: %v", err)
		}
	})
}

// ---------------------------------------------------------- authentication

// TestUnauthenticatedRequestsAreIndistinguishable is the 401 half of the
// leak property: every way of failing to present a credential produces the
// same status, the same body and the same challenge.
func TestUnauthenticatedRequestsAreIndistinguishable(t *testing.T) {
	h := newHarness(t)

	// Genuinely different failures: no credential at all, the wrong scheme,
	// no scheme, an empty token, a token that does not verify, a token that
	// verifies for nobody.
	cases := map[string]string{
		"no authorization header": "",
		"basic scheme":            "Basic dXNlcjpwYXNz",
		"bare token, no scheme":   tokenAnalyst,
		"bearer with no token":    "Bearer",
		"bearer with empty token": "Bearer ",
		"unknown token":           "Bearer not-a-real-token",
		"token with whitespace":   "Bearer " + tokenAnalyst + " extra",
		"negotiate scheme":        "Negotiate YIIB",
	}

	var seenBody, seenChallenge string
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			res := h.post("/mcp", header, initializeBody)
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", res.StatusCode)
			}
			challenge := res.Header.Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "Bearer") {
				t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge", challenge)
			}
			if !strings.Contains(challenge, "resource_metadata=") {
				t.Fatalf("WWW-Authenticate = %q, want an RFC 9728 resource_metadata parameter", challenge)
			}
			got := body(t, res)
			if seenBody == "" {
				seenBody, seenChallenge = got, challenge
				return
			}
			if got != seenBody {
				t.Errorf("401 body differs by cause:\n  %q\n  %q\nthat difference is an oracle", seenBody, got)
			}
			if challenge != seenChallenge {
				t.Errorf("401 challenge differs by cause:\n  %q\n  %q", seenChallenge, challenge)
			}
		})
	}

	// And the body says nothing at all beyond the class.
	assertNoLeak(t, seenBody)
}

// TestTwoAuthorizationHeadersAreRefused: two credentials in one request is
// ambiguous, and picking one is how a request gets past a proxy that
// inspected the other.
func TestTwoAuthorizationHeadersAreRefused(t *testing.T) {
	h := newHarness(t)

	req, err := http.NewRequest(http.MethodPost, h.endpoint(), strings.NewReader(initializeBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Add("Authorization", "Bearer "+tokenAnalyst)
	req.Header.Add("Authorization", "Bearer not-a-real-token")

	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for two Authorization headers", res.StatusCode)
	}
}

// TestSchemeIsCaseInsensitive documents the RFC 7235 section 2.1 choice:
// the auth-scheme is case-insensitive, so `bearer` and `BEARER` are
// accepted. Rejecting them buys no security -- the token still has to
// verify -- and costs interoperability.
func TestSchemeIsCaseInsensitive(t *testing.T) {
	h := newHarness(t)

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run(scheme, func(t *testing.T) {
			res := h.post("/mcp", scheme+" "+tokenAnalyst, initializeBody)
			if res.StatusCode == http.StatusUnauthorized {
				t.Fatalf("scheme %q was refused; RFC 7235 makes the scheme case-insensitive", scheme)
			}
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", res.StatusCode)
			}
		})
	}
}

// TestTokenInQueryParameterIsIgnored is the RFC 6750 / ADR-0008 MUST:
// "aceitar credencial apenas em Authorization: Bearer, nunca em parametro
// de URL". A valid token in the query string is not a fallback -- it is
// not read at all, and the request is refused exactly as if no credential
// had been sent.
func TestTokenInQueryParameterIsIgnored(t *testing.T) {
	h := newHarness(t)

	for _, param := range []string{"access_token", "token", "bearer_token", "api_key"} {
		t.Run(param, func(t *testing.T) {
			res := h.post("/mcp?"+param+"="+tokenAnalyst, "", initializeBody)
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: a credential in the URL must never authenticate", res.StatusCode)
			}
		})
	}

	// It is ignored even alongside a header that would have worked, and the
	// fact that one was offered is recorded for the operator -- a token in
	// a URL has probably already been written to every access log between
	// the analyst and here, and should be revoked.
	if !strings.Contains(h.logs.String(), "credential offered in query string") {
		t.Error("a credential in the query string was not logged as an incident")
	}
	// ...but never its value.
	if strings.Contains(h.logs.String(), tokenAnalyst) {
		t.Error("the log contains a bearer token; it must never be written anywhere")
	}
}

// ------------------------------------------------------- per-identity view

func TestToolsListIsScopedToTheCaller(t *testing.T) {
	h := newHarness(t)

	tests := map[string]struct {
		token string
		want  []string
	}{
		// n1-triage holds pending_tool too, but Tool Quarantine has never
		// approved it, so it is invisible: both gates have to pass.
		"analyst":   {tokenAnalyst, []string{toolSearch, toolListCases}},
		"responder": {tokenResponder, []string{toolDeleteCase, toolListCases}},
		// An authenticated caller with no mapped role is entitled to
		// nothing, and gets a working session with nothing in it -- not an
		// error, and certainly not everything.
		"stranger": {tokenStranger, []string{}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			want := slices.Clone(tc.want)
			slices.Sort(want)
			got := h.toolNames(h.session(tc.token))
			if !slices.Equal(got, want) {
				t.Fatalf("tools/list = %v, want %v", got, want)
			}
		})
	}
}

// TestTwoIdentitiesOneEndpoint: the same address serves different fleets to
// different people, with no session involved in deciding which.
func TestTwoIdentitiesGetDifferentToolsFromTheSameEndpoint(t *testing.T) {
	h := newHarness(t)

	n1 := h.toolNames(h.session(tokenAnalyst))
	dfir := h.toolNames(h.session(tokenResponder))

	if slices.Equal(n1, dfir) {
		t.Fatalf("both roles saw the same tools (%v); per-identity filtering is not happening", n1)
	}
	if slices.Contains(n1, toolDeleteCase) {
		t.Errorf("n1-triage can see %q, which belongs to dfir-lead", toolDeleteCase)
	}
	if slices.Contains(dfir, toolSearch) {
		t.Errorf("dfir-lead can see %q, which belongs to n1-triage", toolSearch)
	}
}

// TestToolOutsideRoleIsAbsentAndUncallable is the property that makes the
// filtering worth anything: not being listed is not the same as not being
// callable, so both are checked.
//
// It also checks the shape of the refusal. A tool the caller may not use is
// never registered on their server, so the SDK answers it the same way it
// answers a name that exists nowhere in the fleet -- which means a caller
// cannot use call-by-name to discover which tools exist but are not theirs.
func TestToolOutsideRoleIsAbsentAndUncallable(t *testing.T) {
	h := newHarness(t)
	cs := h.session(tokenAnalyst)

	if names := h.toolNames(cs); slices.Contains(names, toolDeleteCase) {
		t.Fatalf("%q appears in the analyst's tools/list: %v", toolDeleteCase, names)
	}

	// A fresh session per call: the SDK answers an unknown-tool JSON-RPC
	// error with HTTP 400 (SEP-2575), which tears the client connection
	// down, so reusing one session would compare the first error against
	// itself.
	callErr := func(name string) string {
		t.Helper()
		_, err := h.session(tokenAnalyst).CallTool(context.Background(), &mcp.CallToolParams{
			Name:      name,
			Arguments: json.RawMessage(`{}`),
		})
		if err == nil {
			t.Fatalf("calling %q as the analyst succeeded; it must not", name)
		}
		return err.Error()
	}

	forbidden := callErr(toolDeleteCase) // exists, belongs to another role
	quarantined := callErr(toolPending)  // in the caller's role, not approved
	absent := callErr(toolNonexistent)   // never existed anywhere

	assertNoLeak(t, forbidden)
	assertNoLeak(t, quarantined)

	// The three are the same class of answer: "no such tool for you". A
	// caller able to tell them apart could map the fleet and read the SOC's
	// quarantine posture from outside.
	normalize := func(s, name string) string { return strings.ReplaceAll(s, name, "<TOOL>") }
	a := normalize(forbidden, toolDeleteCase)
	b := normalize(quarantined, toolPending)
	c := normalize(absent, toolNonexistent)
	if a != b || b != c {
		t.Errorf("a forbidden tool, a quarantined tool and a nonexistent tool are distinguishable:\n"+
			"  forbidden:   %q\n  quarantined: %q\n  nonexistent: %q", a, b, c)
	}

	// And no upstream was ever reached.
	h.dialer.upstream("casemgmt").mu.Lock()
	calls := slices.Clone(h.dialer.upstream("casemgmt").calls)
	h.dialer.upstream("casemgmt").mu.Unlock()
	if len(calls) != 0 {
		t.Errorf("refused calls still reached the upstream: %v", calls)
	}
}

// rugPullOnCall reports one tool usable the first time it is asked about
// after arming, and changed every time after -- an upstream rewriting a
// tool in the instant between a client's listing and its call.
type rugPullOnCall struct {
	quarantine.Store

	mu     sync.Mutex
	armed  bool
	seen   int
	server string
	tool   string
}

func (q *rugPullOnCall) arm() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.armed, q.seen = true, 0
}

func (q *rugPullOnCall) Get(ctx context.Context, server, tool string) (quarantine.Tool, error) {
	got, err := q.Store.Get(ctx, server, tool)
	if err != nil || server != q.server || tool != q.tool {
		return got, err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.armed {
		return got, err
	}
	q.seen++
	if q.seen > 1 {
		got.Status = quarantine.StatusChanged
	}
	return got, err
}

// TestDispatchRechecksQuarantineWithinOneRequest exercises the redundancy
// this handler deliberately keeps.
//
// Registering only the caller's tools already makes an unentitled tool
// unlistable and uncallable, so it would be easy to argue that the
// gateway.Dispatch call in each handler need not re-authorize or re-check
// quarantine. It does, and this is why: the tool list was true when it was
// built, and the call arrives afterwards -- even within a single HTTP
// request. Here the tool passes the listing gate and fails the call-time
// one, and the client is told nothing except that there is no such tool.
func TestDispatchRechecksQuarantineWithinOneRequest(t *testing.T) {
	var rug *rugPullOnCall
	h := newHarnessWith(t, harnessOptions{
		wrapQuarantine: func(s quarantine.Store) quarantine.Store {
			rug = &rugPullOnCall{Store: s, server: "casemgmt", tool: "list_cases"}
			return rug
		},
	})
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + toolListCases + `","arguments":{}}}`

	// One request carries both the listing and the dispatch: the stateless
	// handler synthesizes the session state, so a bare tools/call POST is a
	// complete interaction. Unarmed, it works -- which is what makes the
	// armed run below evidence of the call-time gate and not of some other
	// difference.
	if before := body(t, h.post("/mcp", "Bearer "+tokenAnalyst, call)); !strings.Contains(before, "case 42") {
		t.Fatalf("the call did not succeed before the rug pull: %q", before)
	}

	rug.arm()

	res := h.post("/mcp", "Bearer "+tokenAnalyst, call)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the failure travels as a JSON-RPC error)", res.StatusCode)
	}
	got := body(t, res)

	if !strings.Contains(got, `unknown tool`) {
		t.Fatalf("body = %q, want the opaque unknown-tool answer", got)
	}
	assertNoLeak(t, got)
	if strings.Contains(got, "changed") || strings.Contains(got, "approv") {
		t.Errorf("body = %q reveals the tool's quarantine state", got)
	}

	// The refused call never reached the upstream: only the first,
	// pre-rug-pull one did.
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.calls) != 1 {
		t.Errorf("upstream calls = %v, want only the one made before the rug pull", up.calls)
	}
}

// TestAllowedToolDispatches proves the happy path actually goes through
// gateway.Dispatch to the backend and comes back intact.
func TestAllowedToolDispatches(t *testing.T) {
	h := newHarness(t)
	cs := h.session(tokenAnalyst)

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      toolListCases,
		Arguments: json.RawMessage(`{"q":"open"}`),
	})
	if err != nil {
		t.Fatalf("calling %q: %v", toolListCases, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("content = %#v, want one block", res.Content)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "case 42" {
		t.Fatalf("content = %#v, want the upstream's text verbatim", res.Content[0])
	}

	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	defer up.mu.Unlock()
	if !slices.Equal(up.calls, []string{"list_cases"}) {
		t.Fatalf("upstream saw %v, want the un-namespaced name once", up.calls)
	}

	// The call is in the audit trail, attributed to the subject the token
	// attested -- which is the whole reason this gateway exists.
	records, err := auditsql.New(h.db).List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	found := slices.ContainsFunc(records, func(r audit.Record) bool {
		return r.AnalystIdentity == analyst.Subject && r.Tool == toolListCases && r.Outcome == audit.OutcomeAllowed
	})
	if !found {
		t.Fatalf("no allowed audit record for %s calling %s; got %+v", analyst.Subject, toolListCases, records)
	}
}

// --------------------------------------------------------------- leakage

// forbiddenSubstrings are things that must never appear in anything a
// client receives: the subject claims, internal error vocabulary, upstream
// identifiers, and the Go error text of the components underneath.
var forbiddenSubstrings = []string{
	"CANARY",
	"sub-analyst", "sub-dfir", "sub-nobody",
	"may not call",
	"quarantin", "Quarantin",
	"access:", "gateway:", "httpapi:",
	"sql:", "database", "goroutine",
	"10.0.0.", "connection refused",
}

func assertNoLeak(t *testing.T, s string) {
	t.Helper()
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(s, bad) {
			t.Errorf("a client-facing message contains %q, which is internal detail:\n%s", bad, s)
		}
	}
}

// TestDifferentInternalFailuresLookIdentical is the core leak test.
//
// It feeds genuinely different real internal errors -- built by the actual
// components, not hand-written strings -- through the one function that
// decides what a client is told, and asserts that within a status class the
// answers are byte-identical and carry none of the detail.
func TestDifferentInternalFailuresLookIdentical(t *testing.T) {
	policy, err := access.NewPolicy(
		[]access.Role{{Name: "n1-triage", Tools: []string{toolListCases}}},
		map[string]string{"soc-n1": "n1-triage"},
	)
	if err != nil {
		t.Fatalf("access.NewPolicy: %v", err)
	}

	// Real errors, from the real components, each carrying detail that is
	// correct for the audit trail and wrong on the wire.
	forbiddenA := policy.Authorize(analyst, toolDeleteCase)
	forbiddenB := policy.Authorize(responder, toolSearch)
	if forbiddenA == nil || forbiddenB == nil {
		t.Fatal("expected the policy to forbid these calls")
	}

	failures := []struct {
		name  string
		err   error
		class failureClass
	}{
		{"policy refusal naming one subject", forbiddenA, classForbidden},
		{"policy refusal naming another", forbiddenB, classForbidden},

		{"unknown tool", gateway.ErrUnknownTool, classUnknownTool},
		{"quarantined tool", fmt.Errorf("%w: casemgmt.pending_tool -> casemgmt.pending_tool", gateway.ErrToolQuarantined), classUnknownTool},

		{"verifier rejection", fmt.Errorf("%w: token could not be verified", access.ErrUnauthenticated), classUnauthenticated},

		{"quarantine store down", fmt.Errorf("%w: casemgmt.list_cases: %w", gateway.ErrQuarantineUnavailable, sql.ErrConnDone), classInternal},
		{"registry down", fmt.Errorf("%w: %w", gateway.ErrRegistryUnavailable, sql.ErrConnDone), classInternal},
		{"gateway closed", gateway.ErrClosed, classInternal},
		{"upstream transport failure", errors.New(`gateway: call "casemgmt.list_cases": dial tcp 10.0.0.5:9200: connection refused`), classInternal},
		{"nothing recognisable at all", errors.New("boom: /etc/mcp-gateway/secrets.yaml: permission denied"), classInternal},
	}

	byClass := map[failureClass][]string{}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			got := classify(f.err)
			if got != f.class {
				t.Fatalf("classify() = %v, want %v", got, f.class)
			}

			// What an HTTP-level failure of this class puts on the wire.
			rec := httptest.NewRecorder()
			writeGeneric(rec, got)
			if rec.Code != f.class.status() {
				t.Fatalf("status = %d, want %d", rec.Code, f.class.status())
			}
			httpBody := rec.Body.String()

			// What a tool-call failure of this class puts on the wire. The
			// tool name is the caller's own input, so it is normalized out
			// before comparison.
			wire := jsonRPCError(got, toolDeleteCase).Error()
			wire = strings.ReplaceAll(wire, toolDeleteCase, "<TOOL>")

			assertNoLeak(t, httpBody)
			assertNoLeak(t, wire)
			byClass[got] = append(byClass[got], httpBody+"|"+wire)
		})
	}

	for class, seen := range byClass {
		for i := 1; i < len(seen); i++ {
			if seen[i] != seen[0] {
				t.Errorf("class %v is not opaque: two different internal failures produced\n  %q\nand\n  %q",
					class, seen[0], seen[i])
			}
		}
	}

	// Sanity: the classes really are distinct, so this test is not passing
	// because everything collapsed to one answer.
	if len(byClass) < 4 {
		t.Fatalf("expected at least four distinct classes exercised, got %d", len(byClass))
	}
}

// TestBrokenQuarantineIsAGenericFiveHundred exercises the internal-error
// class end to end, over HTTP, with a real failure: the store the Tool
// Quarantine lives in goes away.
//
// gateway.ListTools fails the whole call rather than returning a short list
// -- an empty tool list and a broken approval store must not look the same
// -- and this asserts that distinction survives the last hop, without the
// SQLite driver's error text going with it.
func TestBrokenQuarantineIsAGenericFiveHundred(t *testing.T) {
	h := newHarness(t)

	// It works before.
	if res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody); res.StatusCode != http.StatusOK {
		t.Fatalf("status before the failure = %d, want 200", res.StatusCode)
	}

	if err := h.db.Close(); err != nil {
		t.Fatalf("closing the store: %v", err)
	}

	res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when Tool Quarantine cannot be read", res.StatusCode)
	}
	got := body(t, res)
	assertNoLeak(t, got)
	if strings.Contains(got, "sqlite") || strings.Contains(got, "closed") {
		t.Errorf("500 body carries the driver's error text: %q", got)
	}

	// The operator, unlike the client, is told exactly what happened.
	if !strings.Contains(h.logs.String(), "quarantine") {
		t.Error("the real cause did not reach the log")
	}
}

// ------------------------------------------------------- getServer safety

// TestGetServerWithoutIdentityServesNothing checks the unreachable path.
// ServeHTTP always installs a verified identity before delegating; if that
// ever stops being true, the answer must be an empty server and never a
// permissive one.
func TestGetServerWithoutIdentityServesNothing(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	srv := h.handler.getServer(req)
	if srv == nil {
		t.Fatal("getServer returned nil; the SDK answers that with a 400 and no diagnosis")
	}

	// Talk to it: the only honest way to assert "no tools" is to ask it.
	clientT, serverT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	defer ss.Close()

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "1"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	defer cs.Close()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(res.Tools) != 0 {
		t.Fatalf("a server built with no identity exposed %d tools; it must expose none", len(res.Tools))
	}
}

// TestToolWithUnusableSchemaIsSkipped: mcp.Server.AddTool panics on an
// input schema that is not a JSON object, and the schema is
// upstream-controlled. A malformed backend must cost that one tool, not the
// process.
func TestToolWithUnusableSchemaIsSkipped(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req = req.WithContext(context.WithValue(req.Context(), callerContextKey{}, &caller{
		identity: analyst,
		tools: []gateway.ToolDef{
			{Name: toolListCases, Description: "fine", InputSchema: json.RawMessage(objSchema)},
			{Name: "casemgmt.no_schema", Description: "nil schema"},
			{Name: "casemgmt.array_schema", Description: "not an object", InputSchema: json.RawMessage(`["nope"]`)},
			{Name: "casemgmt.string_type", Description: "wrong type", InputSchema: json.RawMessage(`{"type":"string"}`)},
			{Name: "casemgmt.not_json", Description: "not even JSON", InputSchema: json.RawMessage(`{`)},
		},
	}))

	var srv *mcp.Server
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("getServer panicked on an upstream-controlled schema: %v", r)
			}
		}()
		srv = h.handler.getServer(req)
	}()

	clientT, serverT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "1"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	defer cs.Close()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != toolListCases {
		names := make([]string, 0, len(res.Tools))
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		t.Fatalf("tools = %v, want only the one with a usable schema", names)
	}
}

// ----------------------------------------------------------- statelessness

// TestNoSessionIdIsEverSet is the ADR-0008 MUST: a session identifier must
// never be able to stand in for authentication. The strongest form of that
// is not issuing one.
func TestNoSessionIdIsEverSet(t *testing.T) {
	h := newHarness(t)

	res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if id := res.Header.Get("Mcp-Session-Id"); id != "" {
		t.Fatalf("the server issued Mcp-Session-Id = %q; in stateless mode there is no session, and a session id must never authenticate", id)
	}

	// And presenting one gains nothing: it is not read, so the request is
	// still refused without a token.
	req, err := http.NewRequest(http.MethodPost, h.endpoint(), strings.NewReader(initializeBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", "borrowed-session-id")
	got, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a session id must not authenticate", got.StatusCode)
	}
}

// ---------------------------------------------------------------- RFC 9728

func TestProtectedResourceMetadata(t *testing.T) {
	h := newHarness(t)

	// Both the bare well-known path and the RFC 9728 section 3.1 location
	// for a resource that carries a path.
	for _, path := range []string{MetadataPath, MetadataPath + "/mcp"} {
		t.Run(path, func(t *testing.T) {
			// No Authorization header: discovery metadata tells a client
			// with no token where to get one, so requiring a token would be
			// circular.
			res, err := h.server.Client().Get(h.server.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 without authentication", res.StatusCode)
			}
			if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}

			var doc struct {
				Resource               string   `json:"resource"`
				AuthorizationServers   []string `json:"authorization_servers"`
				BearerMethodsSupported []string `json:"bearer_methods_supported"`
			}
			if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
				t.Fatalf("body is not valid JSON: %v", err)
			}
			if doc.Resource != "http://127.0.0.1/mcp" {
				t.Errorf("resource = %q, want the configured resource identifier", doc.Resource)
			}
			if !slices.Equal(doc.AuthorizationServers, []string{"https://auth.soc.internal/realms/soc"}) {
				t.Errorf("authorization_servers = %v", doc.AuthorizationServers)
			}
			// The document itself says the credential goes in the header.
			if !slices.Equal(doc.BearerMethodsSupported, []string{"header"}) {
				t.Errorf("bearer_methods_supported = %v, want [header] only", doc.BearerMethodsSupported)
			}
		})
	}

	t.Run("challenge points at the document", func(t *testing.T) {
		res := h.post("/mcp", "", initializeBody)
		challenge := res.Header.Get("WWW-Authenticate")
		want := `resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource/mcp"`
		if !strings.Contains(challenge, want) {
			t.Fatalf("WWW-Authenticate = %q, want it to contain %s", challenge, want)
		}
		// No error parameter: it would classify the failure.
		if strings.Contains(challenge, "error=") {
			t.Errorf("WWW-Authenticate = %q carries an error parameter, which is an oracle", challenge)
		}
	})

	t.Run("only GET and HEAD", func(t *testing.T) {
		res := h.post(MetadataPath, "", "{}")
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", res.StatusCode)
		}
		if allow := res.Header.Get("Allow"); allow == "" {
			t.Error("a 405 must carry Allow (RFC 9110 section 15.5.6)")
		}
	})
}

// TestUnknownPathsAreAuthenticated: a path this handler does not recognise
// must not become an unauthenticated hole.
func TestUnknownPathsRequireAuthentication(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/", "/mcp", "/anything", "/.well-known/openid-configuration"} {
		res := h.post(path, "", initializeBody)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s = %d, want 401", path, res.StatusCode)
		}
	}
}

// ------------------------------------------------------------ conversions

func TestToCallToolResult(t *testing.T) {
	t.Run("empty content becomes an empty array, never null", func(t *testing.T) {
		out, err := toCallToolResult(gateway.Result{})
		if err != nil {
			t.Fatalf("toCallToolResult: %v", err)
		}
		if out.Content == nil {
			t.Fatal("Content is nil; clients treat content as an array")
		}
		if len(out.Content) != 0 {
			t.Fatalf("Content = %#v, want empty", out.Content)
		}
	})

	t.Run("tool-level errors survive", func(t *testing.T) {
		out, err := toCallToolResult(gateway.Result{
			Content: json.RawMessage(`[{"type":"text","text":"nope"}]`),
			IsError: true,
		})
		if err != nil {
			t.Fatalf("toCallToolResult: %v", err)
		}
		if !out.IsError {
			t.Error("IsError was dropped; a tool that refused must still look like it refused")
		}
	})

	t.Run("malformed upstream content is refused, not forwarded", func(t *testing.T) {
		if _, err := toCallToolResult(gateway.Result{Content: json.RawMessage(`{not json`)}); err == nil {
			t.Fatal("invalid JSON from an upstream was accepted")
		}
	})
}

// ------------------------------------------------- auditing refused probes

// auditRows reads the whole trail the Gateway under this harness writes to.
func (h *harness) auditRows() []audit.Record {
	h.t.Helper()
	rows, err := auditsql.New(h.db).List(context.Background())
	if err != nil {
		h.t.Fatalf("audit List: %v", err)
	}
	return rows
}

// denialsFor returns the denied rows naming one tool.
func (h *harness) denialsFor(tool string) []audit.Record {
	h.t.Helper()
	var out []audit.Record
	for _, r := range h.auditRows() {
		if r.Tool == tool && r.Outcome == audit.OutcomeDenied {
			out = append(out, r)
		}
	}
	return out
}

// rawCall POSTs one tools/call as the analyst and returns the status and
// body exactly as they went over the wire, so two refusals can be compared
// byte for byte rather than through the SDK client's error formatting.
func (h *harness) rawCall(name string) (int, string) {
	h.t.Helper()
	req := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
	res := h.post("/mcp", "Bearer "+tokenAnalyst, req)
	return res.StatusCode, body(h.t, res)
}

// TestUnservedToolCallIsAuditedAndStillOpaque is ISSUE-16 in one place.
//
// Registering only the caller's own tools means a call naming anything
// else is answered by the SDK, never by gateway.Dispatch -- and Dispatch is
// the only writer of denials, so probing used to be free and invisible.
// Both halves are asserted together on purpose: the record has to exist,
// and the caller has to learn nothing from the fact that it does. Either
// one alone would pass while the feature was broken.
func TestUnservedToolCallIsAuditedAndStillOpaque(t *testing.T) {
	h := newHarness(t)

	// A real tool that belongs to another role, and a name that exists
	// nowhere in the fleet. To the analyst these must be the same event.
	outOfRoleStatus, outOfRoleBody := h.rawCall(toolDeleteCase)
	absentStatus, absentBody := h.rawCall(toolNonexistent)

	if outOfRoleStatus != absentStatus {
		t.Errorf("status: out-of-role = %d, nonexistent = %d; the two are distinguishable",
			outOfRoleStatus, absentStatus)
	}
	// The tool name is echoed because the caller supplied it; everything
	// else must match exactly.
	normalize := func(s, name string) string { return strings.ReplaceAll(s, name, "<TOOL>") }
	if a, b := normalize(outOfRoleBody, toolDeleteCase), normalize(absentBody, toolNonexistent); a != b {
		t.Errorf("an out-of-role tool and a nonexistent one are distinguishable:\n"+
			"  out-of-role: %q\n  nonexistent: %q", a, b)
	}
	assertNoLeak(t, outOfRoleBody)
	assertNoLeak(t, absentBody)

	// And yet both are on the trail, attributed and reasoned.
	for _, tool := range []string{toolDeleteCase, toolNonexistent} {
		rows := h.denialsFor(tool)
		if len(rows) != 1 {
			t.Fatalf("denial rows for %q = %d, want exactly 1: %+v", tool, len(rows), rows)
		}
		if rows[0].AnalystIdentity != analyst.Subject {
			t.Errorf("denial for %q attributed to %q, want %q", tool, rows[0].AnalystIdentity, analyst.Subject)
		}
		if rows[0].Reason == "" {
			t.Errorf("denial for %q carries no Reason; the operator cannot tell why it was blocked", tool)
		}
	}

	// Nothing reached a backend.
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.calls) != 0 {
		t.Errorf("a refused probe reached the upstream: %v", up.calls)
	}
}

// TestFabricatedToolNamesAreAudited: guessing at names the fleet does not
// have is the same signal as naming a real tool somebody else owns, so it
// is recorded the same way -- including for a name that does not even split
// into upstream and tool.
func TestFabricatedToolNamesAreAudited(t *testing.T) {
	h := newHarness(t)

	fabrications := []string{
		"casemgmt.totally_made_up", // plausible upstream, invented tool
		"ghost.list_everything",    // invented upstream too
		"notnamespaced",            // not even a namespaced name
	}
	for _, name := range fabrications {
		if status, got := h.rawCall(name); got == "" {
			t.Fatalf("calling %q produced no response (status %d)", name, status)
		}
	}

	for _, name := range fabrications {
		rows := h.denialsFor(name)
		if len(rows) != 1 {
			t.Errorf("denial rows for the fabricated name %q = %d, want exactly 1: %+v", name, len(rows), rows)
			continue
		}
		if rows[0].AnalystIdentity != analyst.Subject {
			t.Errorf("denial for %q attributed to %q, want %q", name, rows[0].AnalystIdentity, analyst.Subject)
		}
		if rows[0].TargetUpstream == "" {
			t.Errorf("denial for %q names no target upstream; audit.Record.Validate would have rejected it", name)
		}
	}
}

// TestServedToolIsAuditedExactlyOnce guards the other side of the new
// interception: a tool the caller *is* served must not be recorded twice,
// once by the middleware and once by gateway.Dispatch. A trail that
// double-counts is a trail an operator cannot count from.
func TestServedToolIsAuditedExactlyOnce(t *testing.T) {
	h := newHarness(t)

	// Allowed, and quarantined-but-in-role: the first goes through
	// Dispatch, the second is filtered out of the caller's listing and so
	// takes the new path. Each must produce exactly one row.
	if _, err := h.session(tokenAnalyst).CallTool(context.Background(), &mcp.CallToolParams{
		Name:      toolListCases,
		Arguments: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("calling %q: %v", toolListCases, err)
	}
	h.rawCall(toolPending)

	counts := map[string]int{}
	for _, r := range h.auditRows() {
		counts[r.Tool]++
	}
	if counts[toolListCases] != 1 {
		t.Errorf("audit rows for the allowed call = %d, want 1", counts[toolListCases])
	}
	if counts[toolPending] != 1 {
		t.Errorf("audit rows for the unapproved-but-in-role call = %d, want 1", counts[toolPending])
	}
}

// TestListingIsNotAudited pins the scope of the new middleware: it records
// tools/call and nothing else. A tools/list is not a refusal and must not
// land on the trail as one.
func TestListingIsNotAudited(t *testing.T) {
	h := newHarness(t)
	h.toolNames(h.session(tokenAnalyst))

	if rows := h.auditRows(); len(rows) != 0 {
		t.Errorf("listing tools wrote %d audit rows, want 0: %+v", len(rows), rows)
	}
}
