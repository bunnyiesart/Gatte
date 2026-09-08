// Package e2e holds the end-to-end checkpoint WORKFLOW.md's Phase 5
// names as the moment this build has to prove the thing it exists for.
//
// Every other test in this repository checks one component against its
// own contract. This one wires the real ones together -- real SQLite
// store, real Upstream Registry, real Tool Quarantine, real Audit Trail,
// real Access Control policy, the real stdio dialer spawning real
// subprocesses, and the real HTTP surface -- and puts a real MCP client
// in front of it over real HTTP.
//
// The property under test is the one every rejected candidate failed some
// version of: a credential injected into an upstream must reach that
// upstream intact and must never appear anywhere the client can see.
// WORKFLOW.md is explicit that failing this is a stop-the-line finding,
// not a bug to file.
//
// The Credential Vault is the one component represented by a simple
// in-memory Provider rather than the real sops+age adapter. That is
// deliberate: the vault's own no-leak property is proven against real
// sops encryption in internal/vault/sopsage/leak_test.go, and making this
// checkpoint depend on the sops binary would mean the project's headline
// test silently skips on any machine without it -- the exact silent-skip
// trap `make test` now prints a banner about. Each test proves what it is
// responsible for; this one is responsible for the gateway.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/httpapi"
	gwstdio "github.com/bunnyiesart/Gatte/internal/gateway/stdio"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/bunnyiesart/Gatte/lab/mockutil"
)

// upstreams are the four lab mocks, shaped like the team's real backends.
var upstreams = []string{"casemgmt", "logsearch", "docsearch", "threatintel"}

// mockBinaries maps upstream name to a compiled binary path, built once.
var mockBinaries = map[string]string{}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e2e-mocks-")
	if err != nil {
		panic(err)
	}
	for _, name := range upstreams {
		bin := filepath.Join(dir, name)
		out, err := exec.Command("go", "build", "-o", bin, "../../lab/servers/"+name).CombinedOutput()
		if err != nil {
			panic("build " + name + ": " + err.Error() + "\n" + string(out))
		}
		mockBinaries[name] = bin
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// memVault is a vault.Provider serving values held in memory. See the
// package doc for why the real sops adapter is not used here.
type memVault struct{ secrets map[string]string }

func (v memVault) Resolve(_ context.Context, name string) (vault.Secret, error) {
	val, ok := v.secrets[name]
	if !ok {
		return vault.Secret{}, vault.ErrNotFound
	}
	return vault.NewSecret(val), nil
}

// staticVerifier stands in for the OIDC adapter. The real one is
// exercised against a real JWKS in internal/access/oidc; here the
// question is what the gateway does with a verified identity, so tokens
// map straight to identities.
type staticVerifier struct{ byToken map[string]access.Identity }

func (v staticVerifier) Verify(_ context.Context, raw string) (access.Identity, error) {
	id, ok := v.byToken[raw]
	if !ok {
		return access.Identity{}, access.ErrUnauthenticated
	}
	return id, nil
}

// wireTap records every byte of every HTTP request and response body the
// client exchanges with the gateway. This is the leak detector: whatever
// the client could possibly have observed passes through here first.
type wireTap struct {
	rt   http.RoundTripper
	seen *bytes.Buffer
}

func (w *wireTap) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		w.seen.Write(body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	// Headers are part of what a client sees too -- a credential echoed
	// into a response header would be just as much of a leak as one in a
	// body.
	for k, vs := range req.Header {
		w.seen.WriteString(k)
		for _, v := range vs {
			w.seen.WriteString(v)
		}
	}

	resp, err := w.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	for k, vs := range resp.Header {
		w.seen.WriteString(k)
		for _, v := range vs {
			w.seen.WriteString(v)
		}
	}
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		w.seen.Write(body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp, nil
}

type stack struct {
	t       *testing.T
	gw      *gateway.Gateway
	server  *httptest.Server
	tap     *wireTap
	secrets map[string]string // upstream name -> its injected secret
	audit   audit.Recorder
	quar    quarantine.Store
	logs    *bytes.Buffer
}

// newStack builds the whole system: four registered upstreams, each with
// its own distinct secret, fronted by the real HTTP surface.
func newStack(t *testing.T, policy *access.Policy, tokens map[string]access.Identity) *stack {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := registrysqlite.Migrate(db); err != nil {
		t.Fatalf("migrate registry: %v", err)
	}
	if err := auditsqlite.Migrate(db); err != nil {
		t.Fatalf("migrate audit: %v", err)
	}
	if err := quarantinesqlite.Migrate(db); err != nil {
		t.Fatalf("migrate quarantine: %v", err)
	}

	reg := registrysqlite.New(db)
	aud := auditsqlite.New(db)
	quar := quarantinesqlite.New(db)

	// One secret, shared by all four upstreams, and not by choice.
	//
	// The registry couples the vault key to the destination environment
	// variable name: resolveEnv does env[name] = vault.Resolve(name), so a
	// variable can only ever carry the value stored under its own name.
	// Every lab mock reads MOCK_SECRET, so under the current design all
	// four necessarily receive the same value.
	//
	// DEVELOPMENT-LOG.md 7 says to reuse ToolHive's
	// "--secret NAME,target=TARGET" shape as the reference design, which
	// separates the two; that separation was not carried into
	// registry.UpstreamServer. Tracked separately.
	//
	// What this costs the checkpoint: it cannot prove each backend got
	// *its own* secret rather than a neighbour's. What it does not cost:
	// the leak property, which is what this test exists for -- a real
	// credential is still injected, and it must still be invisible.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	shared := "e2e-shared-" + hex.EncodeToString(buf)

	secrets := map[string]string{}
	vaultValues := map[string]string{
		"MOCK_SECRET": shared,
		"MOCK_EXPECT": shared,
	}
	for _, name := range upstreams {
		secrets[name] = shared
		if err := reg.Register(context.Background(), registry.UpstreamServer{
			Name:      name,
			Transport: registry.TransportStdio,
			Command:   mockBinaries[name],
			// The names only. The values live in the vault and are
			// resolved at dial time.
			EnvVarNames: []string{"MOCK_SECRET", "MOCK_EXPECT"},
		}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	gw, err := gateway.New(gateway.Config{
		Registry:   reg,
		Vault:      memVault{secrets: vaultValues},
		Quarantine: quar,
		Audit:      aud,
		Policy:     policy,
		Dialer:     gwstdio.New(),
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	if err := gw.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Approve everything the mocks advertise, so the checkpoint exercises
	// the serving path rather than the quarantine path (which has its own
	// tests).
	tools, err := quar.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list quarantine: %v", err)
	}
	for _, tool := range tools {
		if _, err := quar.Approve(context.Background(), tool.ServerName, tool.ToolName); err != nil {
			t.Fatalf("approve %s/%s: %v", tool.ServerName, tool.ToolName, err)
		}
	}

	h, err := httpapi.New(httpapi.Config{
		Gateway:                   gw,
		Verifier:                  staticVerifier{byToken: tokens},
		Policy:                    policy,
		Resource:                  "http://127.0.0.1/mcp",
		AuthorizationServers:      []string{"http://127.0.0.1/idp"},
		AllowInsecureResourceURLs: true,
		Logger:                    logger,
	})
	if err != nil {
		t.Fatalf("httpapi.New: %v", err)
	}

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &stack{
		t: t, gw: gw, server: srv,
		tap:     &wireTap{rt: http.DefaultTransport, seen: &bytes.Buffer{}},
		secrets: secrets, audit: aud, quar: quar, logs: logs,
	}
}

// connect returns a live MCP client session over HTTP, with every byte
// tapped for the leak check.
func (s *stack) connect(token string) *mcp.ClientSession {
	s.t.Helper()

	httpClient := &http.Client{Transport: s.tap}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   s.server.URL,
		HTTPClient: httpClient,
	}
	// The bearer token rides on the request, which is the only place the
	// gateway will look for it.
	transport.HTTPClient.Transport = &authTap{tap: s.tap, token: token}

	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "v0"}, nil)
	sess, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		s.t.Fatalf("connect over HTTP: %v", err)
	}
	s.t.Cleanup(func() { sess.Close() })
	return sess
}

// authTap adds the bearer credential and still records everything.
type authTap struct {
	tap   *wireTap
	token string
}

func (a *authTap) RoundTrip(req *http.Request) (*http.Response, error) {
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	return a.tap.RoundTrip(req)
}

// assertNoSecretLeaked is the decisive assertion.
func (s *stack) assertNoSecretLeaked() {
	s.t.Helper()
	seen := s.tap.seen.String()
	for name, secret := range s.secrets {
		if strings.Contains(seen, secret) {
			s.t.Fatalf("LEAK: %s's injected credential appeared in the client-facing HTTP traffic", name)
		}
	}
	// The operator log is allowed to be detailed, but never that detailed.
	logs := s.logs.String()
	for name, secret := range s.secrets {
		if strings.Contains(logs, secret) {
			s.t.Fatalf("LEAK: %s's injected credential appeared in the gateway's own logs", name)
		}
	}
}

// TestCheckpoint_CredentialInjectionAndNoLeak is the Phase 5 checkpoint.
//
// It is the same question every external candidate was asked, and five of
// six failed: with the client holding no service credential of its own,
// does a call reach a backend that received the right secret, and does
// that secret stay invisible to the client?
func TestCheckpoint_CredentialInjectionAndNoLeak(t *testing.T) {
	// A role holding every mock's credcheck tool.
	var tools []string
	for _, name := range upstreams {
		tools = append(tools, gateway.Namespaced(name, name+"_credcheck"))
	}
	policy, err := access.NewPolicy(
		[]access.Role{{Name: "dfir-lead", Tools: tools}},
		map[string]string{"soc-dfir": "dfir-lead"},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	lead := access.Identity{Subject: "sub-lead", Name: "DFIR Lead", Groups: []string{"soc-dfir"}}
	s := newStack(t, policy, map[string]access.Identity{"lead-token": lead})

	sess := s.connect("lead-token")

	// The client sees exactly the four credcheck tools -- and note what it
	// did NOT have to hold: any backend credential of its own.
	listed, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(listed.Tools) != len(upstreams) {
		var names []string
		for _, tl := range listed.Tools {
			names = append(names, tl.Name)
		}
		t.Fatalf("tools/list returned %d tools %v, want %d", len(listed.Tools), names, len(upstreams))
	}

	// Every backend must report that it received the exact secret the
	// vault holds for it -- which proves injection reached the right
	// process, not merely that something was injected.
	for _, name := range upstreams {
		toolName := gateway.Namespaced(name, name+"_credcheck")
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: toolName})
		if err != nil {
			t.Fatalf("call %s: %v", toolName, err)
		}
		if res.IsError {
			t.Fatalf("%s reported an error result", toolName)
		}
		text, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("%s returned %T, want TextContent", toolName, res.Content[0])
		}
		var got mockutil.CredCheckResult
		if err := json.Unmarshal([]byte(text.Text), &got); err != nil {
			t.Fatalf("%s result did not parse: %v", toolName, err)
		}
		if !got.ReceivedExpectedSecret {
			t.Errorf("%s did not receive its expected secret -- injection is broken", name)
		}
		if got.Fingerprint == "" {
			t.Errorf("%s reported no fingerprint", name)
		}
	}

	// The decisive check.
	s.assertNoSecretLeaked()

	// And the calls are attributable, which is the other half of why this
	// gateway exists.
	rows, err := s.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(rows) != len(upstreams) {
		t.Fatalf("audit rows = %d, want %d (one per call)", len(rows), len(upstreams))
	}
	for _, r := range rows {
		if r.AnalystIdentity != lead.Subject {
			t.Errorf("audit row attributed to %q, want %q", r.AnalystIdentity, lead.Subject)
		}
		if r.Outcome != audit.OutcomeAllowed {
			t.Errorf("audit row for %q recorded %q, want %q", r.Tool, r.Outcome, audit.OutcomeAllowed)
		}
	}
}

// TestCheckpoint_UnauthenticatedClientGetsNothing is the failure five of
// six external candidates had in their documented quickstart: an
// unauthenticated caller reaching tools, or worse, credentials.
func TestCheckpoint_UnauthenticatedClientGetsNothing(t *testing.T) {
	policy, err := access.NewPolicy(
		[]access.Role{{Name: "dfir-lead", Tools: []string{"casemgmt.casemgmt_credcheck"}}},
		map[string]string{"soc-dfir": "dfir-lead"},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	s := newStack(t, policy, map[string]access.Identity{"good": {Subject: "sub-1", Groups: []string{"soc-dfir"}}})

	for _, tc := range []struct{ name, header string }{
		{"no credential", ""},
		{"garbage bearer", "Bearer not-a-real-token"},
		{"wrong scheme", "Basic Zm9vOmJhcg=="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, s.server.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401; body: %s", resp.StatusCode, body)
			}
			for name, secret := range s.secrets {
				if strings.Contains(string(body), secret) {
					t.Fatalf("LEAK: %s's credential in an unauthenticated response", name)
				}
			}
			if strings.Contains(string(body), "casemgmt") {
				t.Errorf("an unauthenticated response named a backend: %s", body)
			}
		})
	}
}

// TestCheckpoint_RoleLimitsWhatIsReachable proves the per-analyst tool
// view that no tested candidate offered: two analysts, one endpoint,
// different tools, enforced rather than advisory.
func TestCheckpoint_RoleLimitsWhatIsReachable(t *testing.T) {
	policy, err := access.NewPolicy(
		[]access.Role{
			{Name: "n1-triage", Tools: []string{"threatintel.threatintel_credcheck"}},
			{Name: "dfir-lead", Tools: []string{"threatintel.threatintel_credcheck", "casemgmt.casemgmt_credcheck"}},
		},
		map[string]string{"soc-n1": "n1-triage", "soc-dfir": "dfir-lead"},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	s := newStack(t, policy, map[string]access.Identity{
		"n1-token":   {Subject: "sub-n1", Groups: []string{"soc-n1"}},
		"lead-token": {Subject: "sub-lead", Groups: []string{"soc-dfir"}},
	})

	n1 := s.connect("n1-token")
	n1Tools, err := n1.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("n1 tools/list: %v", err)
	}
	if len(n1Tools.Tools) != 1 || n1Tools.Tools[0].Name != "threatintel.threatintel_credcheck" {
		t.Errorf("n1 saw %+v, want only threatintel.threatintel_credcheck", n1Tools.Tools)
	}

	// The tool n1 cannot see must also be one n1 cannot call by name.
	if _, err := n1.CallTool(context.Background(), &mcp.CallToolParams{Name: "casemgmt.casemgmt_credcheck"}); err == nil {
		t.Error("n1 called a tool outside its role")
	}

	lead := s.connect("lead-token")
	leadTools, err := lead.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("lead tools/list: %v", err)
	}
	if len(leadTools.Tools) != 2 {
		t.Errorf("lead saw %d tools, want 2", len(leadTools.Tools))
	}

	s.assertNoSecretLeaked()

	// KNOWN GAP, asserted as it actually behaves rather than as it should.
	//
	// n1's out-of-role call above is correctly refused -- but it is NOT
	// audited, and it should be. httpapi registers only the caller's own
	// tools on their session, so a call naming anything else is rejected
	// by the SDK before it ever reaches gateway.Dispatch, and Dispatch is
	// what writes denials to the trail.
	//
	// Two features that are each correct alone: per-identity filtering
	// (so a caller cannot enumerate what they may not use) and denial
	// auditing (so a SOC can see who probed for what). Composed, the first
	// silently disables the second, and a token probing tool names leaves
	// no record at all.
	//
	// This test pins today's behaviour so the gap is visible and so
	// fixing it will fail here loudly, rather than leaving a green suite
	// that implies auditing works when it does not.
	rows, err := s.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	var denied int
	for _, r := range rows {
		if r.Outcome == audit.OutcomeDenied {
			denied++
		}
	}
	if denied != 0 {
		t.Fatalf("denied rows = %d; if this is now non-zero the known gap has been fixed -- "+
			"update this test to assert the denial is attributed to sub-n1", denied)
	}
}
