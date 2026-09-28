package httpapi

// Security tests for Gatte's one client-facing endpoint (public repo).
// They reuse the harness in httpapi_test.go (real Gateway, real SQLite
// quarantine + audit, fake verifier) and add attack shapes it does not
// already exercise: Authorization header smuggling variants, metadata-path
// lookalikes, a whitespace-only subject, malformed/hostile JSON-RPC bodies,
// namespace confusion in tools/call, and bearer token passthrough/leakage.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// secUpstreamCalls snapshots which tools reached the fake upstream.
func secUpstreamCalls(h *harness, name string) []string {
	up := h.dialer.upstream(name)
	up.mu.Lock()
	defer up.mu.Unlock()
	return slices.Clone(up.calls)
}

// TestSecAuthorizationHeaderVariantsAreRefused sends a valid token in every
// shape that is NOT exactly one `Authorization: Bearer <b64token>` header,
// and requires a 401 with the same body as "no header at all".
func TestSecAuthorizationHeaderVariantsAreRefused(t *testing.T) {
	h := newHarness(t)
	baseline := h.post("/mcp", "", initializeBody)
	wantBody := body(t, baseline)
	if baseline.StatusCode != http.StatusUnauthorized {
		t.Fatalf("baseline without header = %d, want 401", baseline.StatusCode)
	}

	headerCases := map[string]string{
		"bare token, no scheme":        tokenAnalyst,
		"Basic scheme":                 "Basic " + tokenAnalyst,
		"Bearer with no token":         "Bearer",
		"Bearer with only spaces":      "Bearer    ",
		"token with trailing garbage":  "Bearer " + tokenAnalyst + " extra",
		"tab between scheme and token": "Bearer\t" + tokenAnalyst,
		"scheme prefix only":           "Bear " + tokenAnalyst,
		"scheme with suffix":           "Bearerx " + tokenAnalyst,
		"token plus comma second cred": "Bearer " + tokenAnalyst + ",Bearer " + tokenResponder,
		"token with leading quote":     `Bearer "` + tokenAnalyst + `"`,
	}
	for name, value := range headerCases {
		t.Run(name, func(t *testing.T) {
			res := h.post("/mcp", value, initializeBody)
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("Authorization %q = %d, want 401", value, res.StatusCode)
			}
			if got := body(t, res); got != wantBody {
				t.Errorf("401 body differs from the no-header 401 (oracle):\n got %q\nwant %q", got, wantBody)
			}
		})
	}

	// Alternative carriers must not be read at all.
	for _, carrier := range []struct{ header, value string }{
		{"Cookie", "access_token=" + tokenAnalyst},
		{"X-Api-Key", tokenAnalyst},
		{"X-Access-Token", tokenAnalyst},
		{"Proxy-Authorization", "Bearer " + tokenAnalyst},
		{"X-Forwarded-Authorization", "Bearer " + tokenAnalyst},
	} {
		t.Run("carrier "+carrier.header, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, h.endpoint(), strings.NewReader(initializeBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set(carrier.header, carrier.value)
			res, err := h.server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("credential in %s authenticated the request: %d", carrier.header, res.StatusCode)
			}
		})
	}

	// A form body carrying the token (RFC 6750 2.2) is not read either.
	req, _ := http.NewRequest(http.MethodPost, h.endpoint(), strings.NewReader("access_token="+tokenAnalyst))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("form-body access_token authenticated the request: %d", res.StatusCode)
	}

	if calls := secUpstreamCalls(h, "casemgmt"); len(calls) != 0 {
		t.Errorf("an unauthenticated request reached the upstream: %v", calls)
	}
}

// TestSecMetadataLookalikePathsRequireAuthentication: only the exact
// metadata paths are public. A lookalike path (trailing slash, dot segment,
// case change, encoded char, suffix) must fall into the authenticated
// branch, and a non-GET on the real path must never reach the MCP handler.
func TestSecMetadataLookalikePathsRequireAuthentication(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		MetadataPath + "/",
		MetadataPath + "/../../mcp",
		MetadataPath + "x",
		MetadataPath + "/mcp/extra",
		"/.well-known/OAUTH-protected-resource",
		"/.well-known/oauth-protected-resource%2F",
		"//.well-known/oauth-protected-resource",
		"/.well-known/./oauth-protected-resource",
	} {
		res := h.post(path, "", initializeBody)
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("POST %s without a token = %d, want 401", path, res.StatusCode)
		}
	}

	// The real metadata path answers POST with 405, never with MCP.
	for _, path := range []string{MetadataPath, MetadataPath + "/mcp"} {
		res := h.post(path, "", initializeBody)
		b := body(t, res)
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, res.StatusCode)
		}
		if strings.Contains(b, "jsonrpc") || strings.Contains(b, "serverInfo") {
			t.Errorf("POST %s reached the MCP handler unauthenticated: %s", path, b)
		}
	}
}

// secSubjectVerifier authenticates one token as an identity with an
// attacker-shaped subject.
type secSubjectVerifier struct{ subject string }

func (v secSubjectVerifier) Verify(context.Context, string) (access.Identity, error) {
	return access.Identity{Subject: v.subject, Groups: []string{"soc-dfir"}}, nil
}

// TestSecBlankSubjectIsRefused: a verifier that returns a whitespace-only
// subject (a broken IdP mapping) must not produce a working session with
// audit rows attributed to nobody.
func TestSecBlankSubjectIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, subject := range []string{"", " ", "\t", "\n", " \t \n "} {
		handler, err := New(Config{
			Gateway:              h.gw,
			Verifier:             secSubjectVerifier{subject: subject},
			Policy:               h.handler.policy,
			Resource:             "http://127.0.0.1/mcp",
			AuthorizationServers: []string{"https://auth.example.internal/realms/soc"},
			Logger:               h.handler.log,
		})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+toolDeleteCase+`","arguments":{}}}`))
		req.Header.Set("Authorization", "Bearer anything")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("subject %q: status %d, want 401", subject, rec.Code)
		}
	}
	if calls := secUpstreamCalls(h, "casemgmt"); len(calls) != 0 {
		t.Errorf("a blank-subject identity reached the upstream: %v", calls)
	}
}

// TestSecMalformedJSONRPCIsHandledWithoutCrashOrDispatch throws hostile
// bodies at the authenticated endpoint. None may produce a 5xx, leak
// internal detail, or reach the upstream with a tool the caller may not use.
func TestSecMalformedJSONRPCIsHandledWithoutCrashOrDispatch(t *testing.T) {
	h := newHarness(t)
	del := toolDeleteCase // outside the analyst's role
	bodies := map[string]string{
		"empty":                   ``,
		"not json":                `this is not json`,
		"truncated":               `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":`,
		"json null":               `null`,
		"json number":             `42`,
		"json string":             `"tools/call"`,
		"empty object":            `{}`,
		"empty array":             `[]`,
		"wrong jsonrpc version":   `{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"` + del + `","arguments":{}}}`,
		"missing jsonrpc":         `{"id":1,"method":"tools/call","params":{"name":"` + del + `","arguments":{}}}`,
		"method is a number":      `{"jsonrpc":"2.0","id":1,"method":7}`,
		"params is a string":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"` + del + `"}`,
		"name is an object":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":{"x":"` + del + `"}}}`,
		"name is an array":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["` + del + `"]}}`,
		"arguments is an array":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolListCases + `","arguments":[1,2]}}`,
		"id is an object":         `{"jsonrpc":"2.0","id":{"a":1},"method":"tools/call","params":{"name":"` + del + `","arguments":{}}}`,
		"huge id":                 `{"jsonrpc":"2.0","id":1e999,"method":"tools/call","params":{"name":"` + del + `","arguments":{}}}`,
		"notification tools/call": `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + del + `","arguments":{}}}`,
		"batch with forbidden":    `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + del + `","arguments":{}}}]`,
		"batch mixed":             `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolListCases + `","arguments":{}}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + del + `","arguments":{}}}]`,
		"duplicate name keys":     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolListCases + `","name":"` + del + `","arguments":{}}}`,
		"nul byte in name":        `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + del + `\u0000","arguments":{}}}`,
		"deeply nested args":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolListCases + `","arguments":{"q":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}}}`,
		"invalid utf8":            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"\xff\xfe\",\"arguments\":{}}}",
		"unknown method":          `{"jsonrpc":"2.0","id":1,"method":"admin/approve","params":{"server":"casemgmt","tool":"pending_tool"}}`,
		"resources/read":          `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}`,
		"sampling from client":    `{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}`,
		"large junk body":         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolListCases + `","arguments":{"q":"` + strings.Repeat("A", 2<<20) + `"}}}`,
	}
	for name, b := range bodies {
		t.Run(name, func(t *testing.T) {
			res := h.post("/mcp", "Bearer "+tokenAnalyst, b)
			got := body(t, res)
			if res.StatusCode >= 500 {
				t.Errorf("status %d for %s: %s", res.StatusCode, name, secTrim(got))
			}
			assertNoLeak(t, got)
			if strings.Contains(got, "goroutine ") || strings.Contains(got, "panic") {
				t.Errorf("response looks like a panic trace: %s", secTrim(got))
			}
		})
	}
	for _, c := range secUpstreamCalls(h, "casemgmt") {
		if c != "list_cases" {
			t.Errorf("malformed traffic reached casemgmt.%s, which the analyst may not call", c)
		}
	}
	if slices.Contains(secUpstreamCalls(h, "casemgmt"), "pending_tool") {
		t.Error("an unapproved tool was dispatched")
	}
	// The server is still healthy afterwards.
	cs := h.session(tokenAnalyst)
	if names := h.toolNames(cs); !slices.Contains(names, toolListCases) {
		t.Errorf("after the hostile bodies the analyst's session lists %v", names)
	}
}

// TestSecNamespaceConfusionNeverReachesAnUnauthorizedTool: variants of a
// tool name the analyst may not call must not dispatch it.
func TestSecNamespaceConfusionNeverReachesAnUnauthorizedTool(t *testing.T) {
	h := newHarness(t)
	variants := []string{
		toolDeleteCase,
		"CASEMGMT.delete_case",
		"casemgmt.DELETE_CASE",
		" casemgmt.delete_case",
		"casemgmt.delete_case ",
		"casemgmt..delete_case",
		"casemgmt/delete_case",
		"casemgmt:delete_case",
		"delete_case",
		".delete_case",
		"casemgmt.delete_case\\u0000",
		"casemgmt\\u2024delete_case", // one dot leader
		"casemgmt\\uff0edelete_case", // fullwidth full stop
		"casemgmt.list_cases/../delete_case",
		"logsearch.casemgmt.delete_case",
		toolPending,
		"casemgmt.*",
		"*",
	}
	for _, name := range variants {
		status, b := h.rawCall(name)
		if status >= 500 {
			t.Errorf("%q: status %d", name, status)
		}
		if strings.Contains(b, "case 42") {
			t.Errorf("%q returned the upstream's result: %s", name, secTrim(b))
		}
	}
	for _, c := range secUpstreamCalls(h, "casemgmt") {
		t.Errorf("a confused name reached casemgmt.%s", c)
	}
	for _, c := range secUpstreamCalls(h, "logsearch") {
		t.Errorf("a confused name reached logsearch.%s", c)
	}
}

// ---------------------------------------------------- token passthrough

type secRecordedCall struct {
	tool string
	args string
}

type secRecordingUpstream struct {
	mu    sync.Mutex
	calls []secRecordedCall
}

func (u *secRecordingUpstream) ListTools(context.Context) ([]gateway.ToolDef, error) {
	return []gateway.ToolDef{{Name: "echo", Description: "Echo.", InputSchema: json.RawMessage(objSchema)}}, nil
}

func (u *secRecordingUpstream) CallTool(_ context.Context, tool string, args json.RawMessage) (gateway.Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, secRecordedCall{tool: tool, args: string(args)})
	return gateway.Result{Content: json.RawMessage(`[{"type":"text","text":"ok"}]`)}, nil
}

func (u *secRecordingUpstream) Close() error { return nil }

type secRecordingDialer struct {
	mu   sync.Mutex
	up   *secRecordingUpstream
	envs []map[string]string
	spec []gateway.UpstreamSpec
}

func (d *secRecordingDialer) Dial(_ context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.envs = append(d.envs, env)
	d.spec = append(d.spec, spec)
	return d.up, nil
}

// TestSecBearerTokenIsNeverPassedThrough is the MCP "token passthrough"
// anti-pattern check: the analyst's bearer token must never reach the
// upstream (in the args it is sent, the env it is spawned with, or its
// argv), nor the operational log or the audit trail. A distinctive token is
// used so any copy of it anywhere is unambiguous.
func TestSecBearerTokenIsNeverPassedThrough(t *testing.T) {
	const token = "eyJCANARY.PASSTHROUGH.fake-9f3a1c"
	const badToken = "eyJCANARY.REJECTED.tok-77aa"

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quarantinesql.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := auditsql.Migrate(db); err != nil {
		t.Fatal(err)
	}
	q := quarantinesql.New(db)
	policy, err := access.NewPolicy(
		[]access.Role{{Name: "r", Tools: []string{"echoer.echo"}}},
		map[string]string{"g": "r"},
	)
	if err != nil {
		t.Fatal(err)
	}
	entry := registry.UpstreamServer{Name: "echoer", Transport: registry.TransportStdio, Command: "/usr/bin/echoer"}
	reg := &fakeRegistry{entries: []registry.UpstreamServer{entry}}
	dialer := &secRecordingDialer{up: &secRecordingUpstream{}}

	logs := &secSyncBuffer{}
	logger := secLogger(logs)
	gw, err := gateway.New(gateway.Config{
		Registry: reg, Vault: fakeVault{}, Quarantine: q, Audit: auditsql.New(db),
		Policy: policy, Dialer: dialer, Logger: logger, Quota: noQuota(t), Blocklist: noBlocks{},
		Now: func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	if err := gw.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Approve(context.Background(), "echoer", "echo"); err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{
		Gateway:              gw,
		Verifier:             fakeVerifier{tokens: map[string]access.Identity{token: {Subject: "sub-pass", Groups: []string{"g"}}}},
		Policy:               policy,
		Resource:             "http://127.0.0.1/mcp",
		AuthorizationServers: []string{"https://auth.example.internal/realms/soc"},
		Logger:               logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	do := func(auth, target, b string) int {
		req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echoer.echo","arguments":{"q":"hello"}}}`
	if code := do("Bearer "+token, "/mcp", call); code != http.StatusOK {
		t.Fatalf("authorized call = %d", code)
	}
	_ = do("Bearer "+badToken, "/mcp", call)
	_ = do("Bearer "+token, "/mcp?access_token="+token, call)
	_ = do("", "/mcp?access_token="+badToken, call)

	dialer.up.mu.Lock()
	calls := slices.Clone(dialer.up.calls)
	dialer.up.mu.Unlock()
	if len(calls) == 0 {
		t.Fatal("the authorized call never reached the upstream; the test proves nothing")
	}
	for _, c := range calls {
		if strings.Contains(c.args, "CANARY") {
			t.Errorf("bearer token reached the upstream in tool arguments: %s", c.args)
		}
		if c.args != `{"q":"hello"}` {
			t.Errorf("the gateway altered the arguments sent upstream: %s", c.args)
		}
	}
	dialer.mu.Lock()
	for _, env := range dialer.envs {
		for k, v := range env {
			if strings.Contains(k+v, "CANARY") {
				t.Errorf("bearer token reached the upstream environment: %s", k)
			}
		}
	}
	for _, s := range dialer.spec {
		if strings.Contains(fmt.Sprint(s), "CANARY") {
			t.Errorf("bearer token reached the upstream spec/argv: %v", s)
		}
	}
	dialer.mu.Unlock()

	if l := logs.String(); strings.Contains(l, "CANARY") {
		t.Errorf("a bearer token was written to the operational log:\n%s", l)
	}
	rows, err := auditsql.New(db).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no audit rows written; the audit half of this test proves nothing")
	}
	for _, r := range rows {
		if strings.Contains(fmt.Sprintf("%+v", r), "CANARY") {
			t.Errorf("a bearer token was written to the audit trail: %+v", r)
		}
	}
}

func secTrim(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

// ------------------------------------------------------------- helpers

type secSyncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *secSyncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *secSyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func secLogger(w *secSyncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestSecOversizedRequestBodyIsRefused: an authenticated caller cannot make
// the gateway buffer an unbounded body (the SDK's 4 MiB default is in
// force, because New does not set MaxRequestBodyBytes negative), and the
// oversized call never reaches the upstream.
func TestSecOversizedRequestBodyIsRefused(t *testing.T) {
	h := newHarness(t)
	b := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolListCases +
		`","arguments":{"q":"` + strings.Repeat("A", 5<<20) + `"}}}`
	res := h.post("/mcp", "Bearer "+tokenAnalyst, b)
	got := body(t, res)
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("5 MiB body = %d, want 413: %s", res.StatusCode, secTrim(got))
	}
	if calls := secUpstreamCalls(h, "casemgmt"); len(calls) != 0 {
		t.Errorf("an oversized call was dispatched: %v", calls)
	}
}

// TestSecBearerTokenMustBeAB64token: bearerToken's doc says the credential
// is an RFC 6750 b64token (ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" /
// "/" then "="*). A value outside that grammar -- here a JWS in JSON
// serialisation, which internal/access/oidc then VERIFIES (see
// internal/access/oidc/zz_sec_public_gatte_test.go) -- must not be handed
// to the verifier.
func TestSecBearerTokenMustBeAB64token(t *testing.T) {
	jsonJWS := `{"payload":"eyJzdWIiOiJ4In0","protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"k"},"signature":"c2ln"}`
	var accepted []string
	for _, tok := range []string{jsonJWS, `a"b`, `tok;en`, "tok\x00en", "tok,en", `tok\en`} {
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer "+tok)
		if _, ok := bearerToken(hdr); ok {
			accepted = append(accepted, tok)
		}
	}
	if len(accepted) > 0 {
		t.Errorf("bearerToken accepted %d non-b64token credential(s): %q", len(accepted), accepted)
	}
	// And the grammar must not refuse what it allows: a compact JWT, the
	// full alphabet, trailing padding.
	for _, tok := range []string{"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.fake", "Az09-._~+/", "abc==", "x"} {
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer "+tok)
		if got, ok := bearerToken(hdr); !ok || got != tok {
			t.Errorf("bearerToken refused the b64token %q", tok)
		}
	}
	for _, tok := range []string{"=", "==abc", "ab=c"} {
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer "+tok)
		if _, ok := bearerToken(hdr); ok {
			t.Errorf("bearerToken accepted %q, whose '=' is not trailing padding", tok)
		}
	}
}
