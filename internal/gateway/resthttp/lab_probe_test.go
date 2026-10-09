package resthttp_test

// TestLabProbeREST is the lab's REST probe (lab/README.md, "The REST probe"):
// the end-to-end proof, over the real components, of what ADR-0047 and
// ADR-0048 claim an `upstream register -transport http` entry gives the
// team. `make lab-probe-rest` runs it; `make lab-probe` is its stdio
// sibling (lab/probe).
//
// # Why this is a test in internal/gateway/resthttp and not a binary in lab/
//
// The adapter refuses loopback by design (egress.go refuseAddr, ADR-0048
// Decisão 6), and the only thing that lets httptest's listener through is
// AllowLoopbackForTest in export_test.go -- which exists in this package's
// test binary and nowhere else, on purpose, so that a production build has
// exactly one egress policy. A probe binary under lab/ could not reach that
// hook without a seam outside _test.go, which is the seam this project
// decided not to have. An external test package (resthttp_test) in this
// directory can: it links against the same test binary as export_test.go,
// and it can import the rest of the system (gateway, httpapi, the SQLite
// adapters, the signer) because none of them imports resthttp. So the probe
// lives here, next to the one policy exception it needs, and the lab keeps
// its mock (lab/servers/restmock) where the other mocks are.
//
// # What it proves, in order
//
//  1. The mock received the credential (credcheck): GET /check/{ip} answers
//     with the credcheck of the X-API-Key it got, and the fingerprint is the
//     one of the value THIS test put in the vault -- so the key was injected
//     server-side, from the vault, into the right header, on a request the
//     analyst's client never held a key for.
//  2. The secret appears in no byte returned to the client and in no line of
//     the gateway's own log (the bytes.Contains discipline of
//     lab/probe/main.go:216), nor on the mock's stdout.
//  3. A credential the API reflects in a Location, a Set-Cookie and a JSON
//     body (GET /echo) comes back masked in all three.
//  4. The sensitive operation (POST /report) is refused for a read role --
//     even one that names it -- and for an acting role until the tool is
//     cleared, with the mock seeing no request; after `tool clear` the
//     non-read role that names it is served.
//
// Along the way it also exercises the two decisions a lab run would
// otherwise leave untested: the document is fetched through the adapter's
// own guarded client (FetchDocument), and the entry is signed under
// canonical/v3-http and served with RequireSigned, so a tampered operation
// set would stop the upstream, not reroute it (ADR-0048 Decisão 2).
//
// What it does not do: run `dialTimeRefusal`/`ValidateBaseURL`, which would
// refuse a loopback -url at a real register prompt. The console's own tests
// cover that refusal (cmd/mcp-gateway/upstream_http_test.go); here the
// destination is loopback by necessity, and the rest of the register flow
// (FetchDocument, Ingest, registry.Validate via Register, sign) is the real
// one.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/access"
	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/httpapi"
	"github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/signer"
	signersqlite "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// The names the probe is written against. upstreamName is the registry
// entry; secretRef is the vault key the entry names in EnvVarNames and the
// gateway resolves on every call.
const (
	upstreamName = "restmock"
	secretRef    = "RESTMOCK_KEY"
	basePath     = "/api/v1"
	// redactedMarker is the gateway's placeholder (internal/gateway
	// endpoint.go `redacted`). Asserted literally: the probe's claim is not
	// only that the secret is gone but that a reader can see where it was.
	redactedMarker = "[redacted]"
)

// mockEvent is one stdout line of lab/servers/restmock (requestEvent there).
type mockEvent struct {
	Event       string `json:"event"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Received    bool   `json:"received_expected_secret"`
	Fingerprint string `json:"fingerprint"`
	Authorized  bool   `json:"authorized"`
}

// restmock is the running mock: its URL and everything it wrote to stdout.
type restmock struct {
	url string
	mu  sync.Mutex
	out []string
}

// lines is a snapshot of the mock's stdout so far.
func (m *restmock) lines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.out)
}

// requests returns the request events the mock logged, parsed.
func (m *restmock) requests(t *testing.T) []mockEvent {
	t.Helper()
	var out []mockEvent
	for _, line := range m.lines() {
		var ev mockEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("restmock stdout line is not JSON: %q: %v", line, err)
		}
		if ev.Event == "request" {
			out = append(out, ev)
		}
	}
	return out
}

// buildRestmock compiles lab/servers/restmock once for this test, the way
// internal/e2e and lab/probe build their fixtures: a real binary, a real
// process, so the credential crosses a real process boundary.
func buildRestmock(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "restmock")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/bunnyiesart/Gatte/lab/servers/restmock").CombinedOutput()
	if err != nil {
		t.Fatalf("build restmock: %v\n%s", err, out)
	}
	return bin
}

// startRestmock spawns the mock with secret as the key it demands (and as
// the credcheck baseline), on a loopback port the kernel picks, and reads
// its stdout until it says where it listens.
func startRestmock(t *testing.T, bin, secret string) *restmock {
	t.Helper()
	cmd := exec.Command(bin, "-listen", "127.0.0.1:0")
	// Built, not inherited: the mock gets the two variables every lab mock
	// reads and nothing else of this process's environment except PATH.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "MOCK_SECRET=" + secret, "MOCK_EXPECT=" + secret}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start restmock: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	m := &restmock{}
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			m.mu.Lock()
			m.out = append(m.out, line)
			m.mu.Unlock()
			var ev mockEvent
			if json.Unmarshal([]byte(line), &ev) == nil && ev.Event == "listening" {
				ready <- ev.URL
			}
		}
	}()
	select {
	case m.url = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("restmock did not report its address within 10 s")
	}
	return m
}

// memVault is the in-memory vault.Provider the e2e checkpoint uses, for the
// same reason it gives: the vault's own property is proven against real
// sops elsewhere, and this probe is responsible for the gateway.
type memVault struct{ secrets map[string]string }

func (v memVault) Resolve(_ context.Context, name string) (vault.Secret, error) {
	val, ok := v.secrets[name]
	if !ok {
		return vault.Secret{}, vault.ErrNotFound
	}
	return vault.NewSecret(val), nil
}

// staticVerifier maps bearer tokens straight to identities, as the e2e
// checkpoint does; OIDC is proven in internal/access/oidc.
type staticVerifier struct{ byToken map[string]access.Identity }

func (v staticVerifier) Verify(_ context.Context, raw string) (access.Identity, error) {
	id, ok := v.byToken[raw]
	if !ok {
		return access.Identity{}, access.ErrUnauthenticated
	}
	return id, nil
}

// tapBuffer is a bytes.Buffer shared by every session's wireTap, so one
// leak check covers everything every client saw.
type tapBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *tapBuffer) add(parts ...[]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range parts {
		b.buf.Write(p)
	}
}

func (b *tapBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.buf.Bytes())
}

// wireTap records every byte of every request and response the analyst's
// client exchanges with the gateway -- bodies and headers both -- which is
// the whole of what the client could have observed. The leak check reads
// it. token is the bearer token the gateway authenticates, added here so
// the client itself never holds one either.
type wireTap struct {
	rt    http.RoundTripper
	token string
	seen  *tapBuffer
}

// headerBytes flattens a header set for the tap.
func headerBytes(h http.Header) []byte {
	var b bytes.Buffer
	for k, vs := range h {
		b.WriteString(k)
		for _, v := range vs {
			b.WriteString(v)
		}
	}
	return b.Bytes()
}

func (w *wireTap) RoundTrip(req *http.Request) (*http.Response, error) {
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}
	w.seen.add(headerBytes(req.Header))
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		w.seen.add(body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	resp, err := w.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	w.seen.add(headerBytes(resp.Header), body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// envelope is the adapter's response envelope (resthttp.go `envelope`), as
// the analyst sees it inside the text block.
type envelope struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    json.RawMessage     `json:"body"`
}

// resultText is the one text block a REST tool result carries.
func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("result has no content: %+v", res)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("result content is %T, want TextContent", res.Content[0])
	}
	return text.Text
}

func TestLabProbeREST(t *testing.T) {
	ctx := context.Background()
	logf := func(format string, args ...any) { t.Logf("probe: "+format, args...) }

	// A fresh, unpredictable key: the leak check is only meaningful for a
	// value that cannot appear in unrelated output by coincidence.
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	secret := "restprobe-" + hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(secret))
	wantFingerprint := hex.EncodeToString(sum[:])[:8]

	mock := startRestmock(t, buildRestmock(t), secret)
	logf("restmock up at %s (a real subprocess; the key is only in its environment)", mock.url)

	// --- register: fetch the document through the adapter's guarded client,
	// ingest it, and let the auth descriptor be derived from the document.
	fetcher := resthttp.New(nil, resthttp.WithHTTPClientTimeout(10*time.Second))
	resthttp.AllowLoopbackForTest(fetcher)
	doc, err := fetcher.FetchDocument(ctx, mock.url+"/openapi.json", 0)
	if err != nil {
		t.Fatalf("FetchDocument: %v", err)
	}
	res, err := resthttp.Ingest(doc, resthttp.IngestOptions{BaseURL: mock.url})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if !res.AuthDerived || res.AuthKind != resthttp.AuthHeader || res.AuthName != "X-API-Key" {
		t.Fatalf("auth = %q %q derived=%v, want header X-API-Key derived from the document's one apiKey scheme", res.AuthKind, res.AuthName, res.AuthDerived)
	}
	if res.BasePath != basePath || res.BaseURL != mock.url+basePath {
		t.Fatalf("BasePath = %q, BaseURL = %q; want %q folded into %s (ADR-0047 §6)", res.BasePath, res.BaseURL, basePath, mock.url)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "restmock.invalid") }) {
		t.Errorf("no warning about the document's host being ignored; warnings = %q", res.Warnings)
	}
	var names []string
	for _, op := range res.Ops {
		names = append(names, op.Name)
	}
	if want := []string{"check_ip", "echo", "report"}; !slices.Equal(names, want) {
		t.Fatalf("tools = %v, want %v", names, want)
	}
	if got := resthttp.ClassOf(res.Ops[2].Method); got != quarantine.ClassSensitive {
		t.Fatalf("report is %q, want sensitive: a POST is a sensitive tool (ADR-0048 Decisão 5)", got)
	}
	// The parameter locations survive as namespaced properties.
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(res.Ops[0].InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"path_ip", "query_verbose", "header_X-Request-Id"} {
		if _, ok := schema.Properties[p]; !ok {
			t.Errorf("check_ip has no property %q; properties = %v", p, schema.Properties)
		}
	}
	if !slices.Contains(schema.Required, "path_ip") {
		t.Errorf("check_ip does not require path_ip; required = %v", schema.Required)
	}
	logf("ingested %d tools from the fetched document; auth %s %s (derived); base path %s folded", len(res.Ops), res.AuthKind, res.AuthName, res.BasePath)

	// --- the stack: real SQLite, real registry, real signer, real
	// quarantine, real trail, the real adapter, the real HTTP surface.
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for name, migrate := range map[string]func(*sql.DB) error{
		"registry": registrysqlite.Migrate, "audit": auditsqlite.Migrate, "quarantine": quarantinesqlite.Migrate,
		"blocklist": accesssqlite.Migrate, "quota": quotasqlite.Migrate, "signatures": signersqlite.Migrate,
	} {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate %s: %v", name, err)
		}
	}
	reg := registrysqlite.New(db)
	aud := auditsqlite.New(db)
	quar := quarantinesqlite.New(db)
	sigs := signersqlite.New(db)

	entry := registry.UpstreamServer{
		Name:        upstreamName,
		Transport:   registry.TransportHTTP,
		URL:         res.BaseURL,
		AuthKind:    registry.AuthKind(res.AuthKind),
		AuthName:    res.AuthName,
		EnvVarNames: []string{secretRef},
		Operations:  res.Operations,
	}
	if err := reg.Register(ctx, entry); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Sign under canonical/v3-http and serve with RequireSigned: the
	// operation set is covered (ADR-0048 Decisão 2), and the probe shows it
	// by changing one byte of it.
	key, err := signer.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sg, err := signer.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	sig := sg.Sign(entry)
	if err := sigs.Put(ctx, upstreamName, sig); err != nil {
		t.Fatal(err)
	}
	verifier, err := signer.NewVerifier([]ed25519.PublicKey{sg.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(entry, sig); err != nil {
		t.Fatalf("the signature does not verify on the entry it was made for: %v", err)
	}
	tampered := entry
	tampered.Operations = bytes.Replace(entry.Operations, []byte(`"/echo"`), []byte(`"/exfil"`), 1)
	if bytes.Equal(tampered.Operations, entry.Operations) {
		t.Fatal("precondition: the tamper did not change the operation set")
	}
	if err := verifier.Verify(tampered, sig); err == nil {
		t.Fatal("a signature over the operation set verified after the set changed: the v3-http digest is not covering it")
	}
	logf("entry signed (canonical/v3-http); the same signature refuses a set with one path changed")

	policy, err := access.NewPolicy(
		[]access.Role{
			// A read role that NAMES the sensitive tool: the gate must refuse
			// it anyway (ADR-0048 Decisão 5).
			{Name: "n1-triage", Tools: []string{
				gateway.Namespaced(upstreamName, "check_ip"),
				gateway.Namespaced(upstreamName, "echo"),
				gateway.Namespaced(upstreamName, "report"),
			}},
			{Name: "dfir-responder", NonRead: true, Tools: []string{gateway.Namespaced(upstreamName, "report")}},
		},
		map[string]string{"soc-n1": "n1-triage", "soc-dfir": "dfir-responder"},
	)
	if err != nil {
		t.Fatal(err)
	}
	reader := access.Identity{Subject: "sub-reader", Name: "Ana Lyst", Groups: []string{"soc-n1"}}
	actor := access.Identity{Subject: "sub-actor", Name: "Dee Fir", Groups: []string{"soc-dfir"}}

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	plan, err := quota.NewPlan(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := quota.NewGate(plan, quotasqlite.New(db))
	if err != nil {
		t.Fatal(err)
	}

	dialer := resthttp.New(memVault{secrets: map[string]string{secretRef: secret}}, resthttp.WithHTTPClientTimeout(10*time.Second))
	resthttp.AllowLoopbackForTest(dialer)

	gw, err := gateway.New(gateway.Config{
		Registry:      reg,
		Vault:         memVault{secrets: map[string]string{secretRef: secret}},
		Quarantine:    quar,
		Audit:         aud,
		Policy:        policy,
		Blocklist:     accesssqlite.New(db),
		Quota:         gate,
		Dialer:        dialer,
		Signatures:    sigs,
		Verifier:      verifier,
		RequireSigned: true,
		Logger:        logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gw.Close() })
	if err := gw.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Approve the three tools; clear none. Approval is the first operator
	// decision; for the sensitive one it is not the last.
	tools, err := quar.List(ctx, upstreamName)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 3 {
		t.Fatalf("quarantine holds %d tools for %s, want 3", len(tools), upstreamName)
	}
	for _, tool := range tools {
		if _, err := quar.Approve(ctx, tool.ServerName, tool.ToolName); err != nil {
			t.Fatalf("approve %s: %v", tool.ToolName, err)
		}
	}
	logf("gateway up with RequireSigned; 3 tools observed and approved, none cleared")

	h, err := httpapi.New(httpapi.Config{
		Gateway:                   gw,
		Verifier:                  staticVerifier{byToken: map[string]access.Identity{"reader-token": reader, "actor-token": actor}},
		Policy:                    policy,
		Resource:                  "http://127.0.0.1/mcp",
		AuthorizationServers:      []string{"http://127.0.0.1/idp"},
		AllowInsecureResourceURLs: true,
		Logger:                    logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	seen := &tapBuffer{}
	connect := func(token string) *mcp.ClientSession {
		t.Helper()
		tap := &wireTap{rt: http.DefaultTransport, token: token, seen: seen}
		transport := &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: tap}}
		client := mcp.NewClient(&mcp.Implementation{Name: "lab-probe-rest", Version: "v0"}, nil)
		sess, err := client.Connect(ctx, transport, nil)
		if err != nil {
			t.Fatalf("connect as %s: %v", token, err)
		}
		t.Cleanup(func() { sess.Close() })
		return sess
	}
	tapBytes := seen.bytes

	// --- (1) the credential reached the backend, from the vault, in the
	// header the document named, on a call whose client held no key.
	readerSess := connect("reader-token")
	listed, err := readerSess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var listedNames []string
	for _, tl := range listed.Tools {
		listedNames = append(listedNames, tl.Name)
	}
	if slices.Contains(listedNames, gateway.Namespaced(upstreamName, "report")) {
		t.Errorf("the read role is listed the sensitive tool it cannot call: %v", listedNames)
	}
	for _, want := range []string{gateway.Namespaced(upstreamName, "check_ip"), gateway.Namespaced(upstreamName, "echo")} {
		if !slices.Contains(listedNames, want) {
			t.Errorf("tools/list for the read role lacks %s: %v", want, listedNames)
		}
	}

	checkRes, err := readerSess.CallTool(ctx, &mcp.CallToolParams{
		Name:      gateway.Namespaced(upstreamName, "check_ip"),
		Arguments: map[string]any{"path_ip": "192.0.2.7", "query_verbose": true, "header_X-Request-Id": "probe-1"},
	})
	if err != nil {
		t.Fatalf("call check_ip: %v", err)
	}
	checkText := resultText(t, checkRes)
	if checkRes.IsError {
		t.Fatalf("check_ip answered an error result: %s", checkText)
	}
	var checkEnv envelope
	if err := json.Unmarshal([]byte(checkText), &checkEnv); err != nil {
		t.Fatalf("check_ip result is not the adapter's envelope: %v\n%s", err, checkText)
	}
	var checkBody struct {
		IP        string `json:"ip"`
		Verbose   bool   `json:"verbose"`
		RequestID string `json:"request_id"`
		Credcheck struct {
			Received    bool   `json:"received_expected_secret"`
			Fingerprint string `json:"fingerprint"`
		} `json:"credcheck"`
	}
	if err := json.Unmarshal(checkEnv.Body, &checkBody); err != nil {
		t.Fatalf("check_ip body: %v", err)
	}
	if checkEnv.Status != http.StatusOK || checkBody.IP != "192.0.2.7" || !checkBody.Verbose || checkBody.RequestID != "probe-1" {
		t.Errorf("check_ip: status %d body %+v; the three parameters did not land in path, query and header", checkEnv.Status, checkBody)
	}
	if !checkBody.Credcheck.Received {
		t.Errorf("the mock did not receive its expected key -- injection is broken")
	}
	if checkBody.Credcheck.Fingerprint != wantFingerprint {
		t.Errorf("the mock received a key with fingerprint %q, want %q: not the value the vault holds", checkBody.Credcheck.Fingerprint, wantFingerprint)
	}
	logf("(1) credcheck: received_expected_secret=%v fingerprint=%s (vault value %s) -- injected server-side into %s",
		checkBody.Credcheck.Received, checkBody.Credcheck.Fingerprint, wantFingerprint, res.AuthName)

	// --- (3) the reflected credential comes back masked, three ways.
	echoRes, err := readerSess.CallTool(ctx, &mcp.CallToolParams{Name: gateway.Namespaced(upstreamName, "echo")})
	if err != nil {
		t.Fatalf("call echo: %v", err)
	}
	echoText := resultText(t, echoRes)
	var echoEnv envelope
	if err := json.Unmarshal([]byte(echoText), &echoEnv); err != nil {
		t.Fatalf("echo result is not the adapter's envelope: %v\n%s", err, echoText)
	}
	if echoEnv.Status != http.StatusFound || !echoRes.IsError {
		t.Errorf("echo: status %d isError=%v, want the last 302 handed back as an error result", echoEnv.Status, echoRes.IsError)
	}
	for _, header := range []string{"Location", "Set-Cookie"} {
		vals := echoEnv.Headers[header]
		if len(vals) == 0 {
			t.Errorf("echo: the envelope carries no %s header, so the reflection was dropped rather than masked", header)
			continue
		}
		if !strings.Contains(vals[0], redactedMarker) {
			t.Errorf("echo: %s = %q, want the credential masked as %s", header, vals[0], redactedMarker)
		}
	}
	var echoBody struct {
		Echo string `json:"echo"`
	}
	if err := json.Unmarshal(echoEnv.Body, &echoBody); err != nil {
		t.Fatalf("echo body: %v", err)
	}
	if !strings.Contains(echoBody.Echo, redactedMarker) {
		t.Errorf("echo: body.echo = %q, want %s", echoBody.Echo, redactedMarker)
	}
	logf("(3) reflected credential: Location=%q Set-Cookie=%q body.echo=%q", echoEnv.Headers["Location"], echoEnv.Headers["Set-Cookie"], echoBody.Echo)

	// --- (4) the sensitive tool: refused to the read role that names it,
	// refused to the acting role until cleared, served after.
	reportArgs := map[string]any{"body": map[string]any{"kind": "ip", "ip": "192.0.2.7"}}
	reportName := gateway.Namespaced(upstreamName, "report")
	refused := func(sess *mcp.ClientSession, who string) {
		t.Helper()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: reportName, Arguments: reportArgs})
		if err == nil && (res == nil || !res.IsError) {
			t.Fatalf("%s: report was SERVED: %+v", who, res)
		}
		if res != nil && strings.Contains(resultText(t, res), `"accepted"`) {
			t.Fatalf("%s: report reached the backend: %s", who, resultText(t, res))
		}
	}
	postsSeen := func() int {
		n := 0
		for _, ev := range mock.requests(t) {
			if ev.Method == http.MethodPost {
				n++
			}
		}
		return n
	}
	refused(readerSess, "read role naming the tool")
	actorSess := connect("actor-token")
	refused(actorSess, "non-read role before clear")
	if n := postsSeen(); n != 0 {
		t.Fatalf("the mock saw %d POST(s) before any clearance; a refused call must not reach the backend", n)
	}
	logf("(4a) POST /report refused for the read role and for the non-read role before clearance; the mock saw no POST")

	if _, err := quar.Clear(ctx, upstreamName, "report"); err != nil {
		t.Fatalf("clear report: %v", err)
	}
	if _, err := quar.Clear(ctx, upstreamName, "check_ip"); !errors.Is(err, quarantine.ErrNotSensitive) {
		t.Errorf("clearing a safe tool = %v, want ErrNotSensitive", err)
	}
	// The listing is per session; reconnect so the SDK registers what the
	// cleared gate now serves.
	actorSess = connect("actor-token")
	served, err := actorSess.CallTool(ctx, &mcp.CallToolParams{Name: reportName, Arguments: reportArgs})
	if err != nil {
		t.Fatalf("non-read role after clear: %v", err)
	}
	servedText := resultText(t, served)
	var servedEnv envelope
	if err := json.Unmarshal([]byte(servedText), &servedEnv); err != nil {
		t.Fatalf("report result is not the adapter's envelope: %v\n%s", err, servedText)
	}
	if served.IsError || servedEnv.Status != http.StatusCreated || !strings.Contains(string(servedEnv.Body), `"accepted":true`) {
		t.Fatalf("non-read role after clear: status %d isError=%v body %s; want 201 accepted", servedEnv.Status, served.IsError, servedEnv.Body)
	}
	refused(connect("reader-token"), "read role after clear")
	if n := postsSeen(); n != 1 {
		t.Fatalf("the mock saw %d POST(s), want exactly 1 (the cleared, non-read call)", n)
	}
	logf("(4b) after `tool clear`: served to the non-read role that names it (201), still refused to the read role; the mock saw exactly one POST")

	// --- (2) the decisive check, last so it covers everything above.
	if bytes.Contains(tapBytes(), []byte(secret)) {
		t.Fatal("LEAK: the secret appeared in the client-facing HTTP traffic")
	}
	if bytes.Contains(logs.Bytes(), []byte(secret)) {
		t.Fatal("LEAK: the secret appeared in the gateway's own log")
	}
	for _, line := range mock.lines() {
		if strings.Contains(line, secret) {
			t.Fatalf("LEAK: the mock's stdout quotes the key: %s", line)
		}
	}
	for _, ev := range mock.requests(t) {
		if !ev.Authorized || !ev.Received || ev.Fingerprint != wantFingerprint {
			t.Errorf("the mock logged a request without the expected key: %+v", ev)
		}
	}
	logf("(2) %d bytes of client-facing traffic, %d bytes of gateway log and %d mock stdout lines: the secret is in none of them",
		len(tapBytes()), logs.Len(), len(mock.lines()))

	// And the trail says who did what, including the refusals.
	rows, err := aud.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var denials, allowed int
	for _, r := range rows {
		if r.AnalystIdentity == "(gateway)" {
			continue
		}
		switch r.Outcome {
		case audit.OutcomeDenied:
			denials++
		case audit.OutcomeAllowed:
			allowed++
		}
		if strings.Contains(r.Reason, secret) {
			t.Fatalf("LEAK: the secret appeared in an audit row")
		}
	}
	if denials < 3 || allowed < 3 {
		t.Errorf("trail: %d denials and %d allowed rows, want at least 3 and 3 (three refusals of report; check_ip, echo and the served report)", denials, allowed)
	}
	logf("trail: %d allowed, %d denied", allowed, denials)
}
