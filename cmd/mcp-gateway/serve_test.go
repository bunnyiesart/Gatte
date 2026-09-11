package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/httpapi"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/signer"
	signersqlite "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// ---------------------------------------------------------------------------
// Fixtures
//
// buildServer wires the *real* adapters, so exercising it needs a real
// sops-encrypted secrets file and a real OIDC discovery document. The
// first needs `sops` and `age-keygen` on PATH; per
// design/adr/0005-shell-out-to-sops-cli.md those are runtime prerequisites
// of the gateway host rather than Go dependencies, so a machine without
// them skips -- loudly -- instead of making this package untestable. The
// same convention internal/vault/sopsage's tests use.
// ---------------------------------------------------------------------------

// serveRequireBinary skips the test if name is not on PATH.
func serveRequireBinary(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found on PATH (required by design/adr/0005 to build a real vault fixture): %v", name, err)
	}
}

// newServeVaultFixture mints a throwaway age keypair and a sops-encrypted JSON
// secrets file holding secrets, entirely inside t.TempDir(). Nothing it
// produces is ever committed: each run generates its own key.
func newServeVaultFixture(t *testing.T, secrets map[string]string) (secretsFile, ageKeyFile string) {
	t.Helper()
	serveRequireBinary(t, "age-keygen")
	serveRequireBinary(t, "sops")

	dir := t.TempDir()
	ageKeyFile = filepath.Join(dir, "age.key")

	var keygenErr bytes.Buffer
	keygen := exec.Command("age-keygen", "-o", ageKeyFile)
	keygen.Stderr = &keygenErr
	if err := keygen.Run(); err != nil {
		t.Fatalf("age-keygen: %v: %s", err, keygenErr.String())
	}
	recipient := parseAgeRecipient(t, keygenErr.String())

	plaintext, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("marshal fixture secrets: %v", err)
	}
	plainFile := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(plainFile, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext fixture: %v", err)
	}

	var encrypted, encryptErr bytes.Buffer
	encrypt := exec.Command("sops",
		"--encrypt", "--age", recipient,
		"--input-type", "json", "--output-type", "json",
		plainFile,
	)
	encrypt.Stdout = &encrypted
	encrypt.Stderr = &encryptErr
	if err := encrypt.Run(); err != nil {
		t.Fatalf("sops --encrypt: %v: %s", err, encryptErr.String())
	}

	secretsFile = filepath.Join(dir, "secrets.enc.json")
	if err := os.WriteFile(secretsFile, encrypted.Bytes(), 0o600); err != nil {
		t.Fatalf("write encrypted fixture: %v", err)
	}
	return secretsFile, ageKeyFile
}

func parseAgeRecipient(t *testing.T, keygenStderr string) string {
	t.Helper()
	for _, line := range strings.Split(keygenStderr, "\n") {
		const prefix = "Public key: "
		if idx := strings.Index(line, prefix); idx != -1 {
			return strings.TrimSpace(line[idx+len(prefix):])
		}
	}
	t.Fatalf("no %q line in age-keygen output: %q", "Public key: ", keygenStderr)
	return ""
}

// newServeIssuer serves the minimum OIDC discovery document oidc.New needs, on
// a loopback address. It mints no tokens: every test here is about what
// the gateway does with a request that carries none.
func newServeIssuer(t *testing.T) string {
	t.Helper()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"keys":[]}`)
	})
	return srv.URL
}

// serveFixture is one complete, valid deployment on disk.
type serveFixture struct {
	configPath string
	dbPath     string
	cfg        *config.Config
}

// newServeFixture writes a valid configuration file plus its vault and issuer,
// and returns the loaded config so a test can adjust it in memory. tweak,
// when non-nil, edits the TOML body before it is written.
func newServeFixture(t *testing.T, tweak func(*strings.Builder)) serveFixture {
	t.Helper()

	secretsFile, ageKeyFile := newServeVaultFixture(t, map[string]string{"MOCK_SECRET": "not-a-real-secret"})
	issuer := newServeIssuer(t)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gateway.db")

	var body strings.Builder
	fmt.Fprintf(&body, "listen = %q\n", "127.0.0.1:0")
	fmt.Fprintf(&body, "database = %q\n", dbPath)
	fmt.Fprintf(&body, "[oidc]\nissuer = %q\naudience = %q\n", issuer, "http://127.0.0.1/mcp")
	fmt.Fprintf(&body, "[vault]\nsecrets_file = %q\nage_key_file = %q\n", secretsFile, ageKeyFile)
	fmt.Fprintf(&body, "[signer]\nrequire_signed = false\n")
	fmt.Fprintf(&body, "[[role]]\nname = %q\ntools = [%q]\n", "n1-triage", "casemgmt.list_cases")
	fmt.Fprintf(&body, "[group_to_role]\n%q = %q\n", "soc-n1", "n1-triage")
	if tweak != nil {
		tweak(&body)
	}

	configPath := filepath.Join(dir, "mcp-gateway.toml")
	if err := os.WriteFile(configPath, []byte(body.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("the fixture config does not load: %v", err)
	}
	return serveFixture{configPath: configPath, dbPath: dbPath, cfg: cfg}
}

// serveTestLogger returns a logger and the buffer it writes to, so a test can
// assert on what an operator would see.
func serveTestLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// ---------------------------------------------------------------------------
// Configuration failures: nothing is built, and the operator is told why.
// ---------------------------------------------------------------------------

func TestCmdServe_MissingConfigFileCannotRun(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nowhere.toml")
	var stdout, stderr bytes.Buffer

	if code := cmdServe([]string{"-config", missing}, &stdout, &stderr); code != exitCannotRun {
		t.Errorf("exit code = %d, want %d (exitCannotRun)", code, exitCannotRun)
	}

	msg := stderr.String()
	if !strings.Contains(msg, missing) {
		t.Errorf("the error does not name the file it could not read; an operator with a shipped example, a staging file and a live one cannot act on that:\n%s", msg)
	}
	if !strings.Contains(msg, "config.example.toml") {
		t.Errorf("a missing config should point at the shipped example:\n%s", msg)
	}
	if stdout.Len() != 0 {
		t.Errorf("a failure wrote to stdout: %q", stdout.String())
	}
}

func TestCmdServe_InvalidConfigCannotRun(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{
			name: "missing required fields",
			body: "listen = \"127.0.0.1:0\"\n",
			want: "database",
		},
		{
			name: "misspelled security setting",
			body: "database = \"x.db\"\n[oidc]\nissuer = \"https://idp.example\"\naudience = \"https://gw.example/mcp\"\n" +
				"[vault]\nsecrets_file = \"s\"\nage_key_file = \"k\"\n[signer]\nrequire_signd = true\n",
			want: "unknown key",
		},
		{
			name: "not TOML at all",
			body: "this is not toml\n",
			want: "parsing",
		},
		{
			// ADR-0010 item 3, at the surface the operator actually
			// touches. require_signed defaults to true, so this body is
			// every pre-ADR-0010 configuration in the world: it used to
			// start and serve, and it now refuses, in front of whoever
			// just edited the file rather than in front of whoever is on
			// call three weeks later.
			name: "signatures required with nothing to verify against",
			body: "database = \"x.db\"\n[oidc]\nissuer = \"https://idp.example\"\naudience = \"https://gw.example/mcp\"\n" +
				"[vault]\nsecrets_file = \"s\"\nage_key_file = \"k\"\n[signer]\nrequire_signed = true\n",
			want: "trusted_keys",
		},
		{
			name: "a trusted key that is not a key",
			body: "database = \"x.db\"\n[oidc]\nissuer = \"https://idp.example\"\naudience = \"https://gw.example/mcp\"\n" +
				"[vault]\nsecrets_file = \"s\"\nage_key_file = \"k\"\n[signer]\ntrusted_keys = [\"obviously-not-base64!\"]\n",
			want: "signer.trusted_keys[0]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			var stdout, stderr bytes.Buffer
			if code := cmdServe([]string{"-config", path}, &stdout, &stderr); code != exitCannotRun {
				t.Errorf("exit code = %d, want %d (exitCannotRun)", code, exitCannotRun)
			}
			if got := stderr.String(); !strings.Contains(got, tc.want) {
				t.Errorf("stderr does not mention %q:\n%s", tc.want, got)
			}
		})
	}
}

func TestCmdServe_UnexpectedArgumentCannotRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cmdServe([]string{"suddenly-a-positional"}, &stdout, &stderr); code != exitCannotRun {
		t.Errorf("exit code = %d, want %d (exitCannotRun)", code, exitCannotRun)
	}
	if !strings.Contains(stderr.String(), "suddenly-a-positional") {
		t.Errorf("stderr does not name the argument it refused:\n%s", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// The wiring itself.
// ---------------------------------------------------------------------------

// TestBuildServer_AuthSeamIsWired is the proof that the composition root
// actually connected the authentication seam: a request carrying no
// credential is refused at the HTTP boundary, before anything is listed or
// dispatched. A handler wired without a Verifier could not produce this,
// and httpapi.New refuses to construct without one.
func TestBuildServer_AuthSeamIsWired(t *testing.T) {
	fx := newServeFixture(t, nil)
	logger, logs := serveTestLogger()

	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	stack.server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}
	// RFC 9728 section 5.1: the challenge has to tell a client where to go
	// for a token, which is only true if the metadata was wired too.
	if challenge := rec.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, "resource_metadata") {
		t.Errorf("WWW-Authenticate = %q, want a resource_metadata parameter", challenge)
	}
	if strings.Contains(logs.String(), "not-a-real-secret") {
		t.Error("LEAK: a vault value reached the startup log")
	}
}

// TestBuildServer_MetadataIsServedUnauthenticated pins the other half of
// that seam: the RFC 9728 discovery document is public, because a client
// with no token has to be able to find out where to get one.
func TestBuildServer_MetadataIsServedUnauthenticated(t *testing.T) {
	fx := newServeFixture(t, nil)
	logger, _ := serveTestLogger()

	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	rec := httptest.NewRecorder()
	stack.server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, httpapi.MetadataPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	// The resource identifier must be the configured OIDC audience: if the
	// two ever drift, a token minted for this gateway is rejected while one
	// minted for whatever the metadata advertises is accepted.
	if doc.Resource != fx.cfg.OIDC.Audience {
		t.Errorf("metadata resource = %q, want the configured oidc.audience %q", doc.Resource, fx.cfg.OIDC.Audience)
	}
	if len(doc.AuthorizationServers) == 0 || doc.AuthorizationServers[0] != fx.cfg.OIDC.Issuer {
		t.Errorf("metadata authorization_servers = %v, want [%q]", doc.AuthorizationServers, fx.cfg.OIDC.Issuer)
	}
}

// TestBuildServer_UnreadableRegistryIsFatal is the fail-closed half of
// ADR-0004. The registry table is replaced with one the adapter's SELECT
// cannot read, so Connect returns ErrRegistryUnavailable: nothing can be
// routed, and a process that listened anyway would serve an empty tool
// list to every analyst with no indication that anything is wrong.
func TestBuildServer_UnreadableRegistryIsFatal(t *testing.T) {
	fx := newServeFixture(t, nil)

	db, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// CREATE TABLE IF NOT EXISTS makes the migration a no-op over this,
	// so the table exists and every query against it fails.
	if _, err := db.Exec(`CREATE TABLE upstream_servers (name TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("plant a broken registry table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	logger, _ := serveTestLogger()
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err == nil {
		stack.close()
		t.Fatal("buildServer succeeded with an unreadable registry; it must refuse to start")
	}
	if stack != nil {
		t.Error("buildServer returned both an error and a stack; the caller has no way to know it must clean up")
	}
	if !errors.Is(err, gateway.ErrRegistryUnavailable) {
		t.Errorf("error = %v, want one wrapping gateway.ErrRegistryUnavailable", err)
	}
}

// TestBuildServer_OneUnavailableUpstreamIsNotFatal is the other side of
// that coin, and the distinction gateway.ErrUpstreamUnavailable exists to
// draw: a backend that will not come up must not take the whole SOC's
// gateway offline. It is loud, named, and counted -- and the process
// serves.
func TestBuildServer_OneUnavailableUpstreamIsNotFatal(t *testing.T) {
	fx := newServeFixture(t, nil)

	db, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := registrysqlite.Migrate(db); err != nil {
		t.Fatalf("migrate registry: %v", err)
	}
	if err := registrysqlite.New(db).Register(context.Background(), registry.UpstreamServer{
		Name:        "brokenbackend",
		Transport:   registry.TransportStdio,
		Command:     filepath.Join(t.TempDir(), "no-such-binary"),
		EnvVarNames: []string{"MOCK_SECRET"},
	}); err != nil {
		t.Fatalf("register upstream: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	logger, logs := serveTestLogger()
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer refused to start because one upstream is down; it must serve the rest: %v", err)
	}
	defer stack.close()

	if got, want := stack.summary.UpstreamsRegistered, 1; got != want {
		t.Errorf("summary.UpstreamsRegistered = %d, want %d", got, want)
	}
	if got := stack.summary.UpstreamsFailed; len(got) != 1 || got[0] != "brokenbackend" {
		t.Errorf("summary.UpstreamsFailed = %v, want [brokenbackend]", got)
	}

	// And it is loud: the summary names the backend that did not come up.
	stack.summary.log(logger)
	if !strings.Contains(logs.String(), "brokenbackend") {
		t.Errorf("the startup log does not name the upstream that failed:\n%s", logs.String())
	}

	// Still serving: the auth seam answers, which means the handler is
	// live even with the fleet degraded.
	rec := httptest.NewRecorder()
	stack.server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 from a degraded but serving gateway", rec.Code)
	}
}

// TestBuildServer_TrustAnchorIsWired is ADR-0010 at the composition root:
// the whole point of the change is that the *serving* process refuses an
// entry vouched for only by a key nobody put in the configuration file.
//
// The unit tests prove signer.Verifier refuses it. This proves the trust
// anchor actually reaches the gateway -- that buildServer reads
// signer.trusted_keys, builds a Verifier from it, and hands it over. A
// Verifier that is correct but not wired is the same as no Verifier.
func TestBuildServer_TrustAnchorIsWired(t *testing.T) {
	// A key the configuration will name, and one it will not. Only the
	// second one ever signs anything here: the attacker's whole advantage
	// was that generating a key is free.
	attacker, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	attackerSigner, err := signer.NewSigner(attacker)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	trustedKey := writeSigningKey(t, 0o600)

	fx := newServeFixture(t, func(body *strings.Builder) {
		// Replace the fixture's permissive signer block. require_signed is
		// on, and the only key named is one the attacker does not hold.
		s := body.String()
		body.Reset()
		body.WriteString(strings.Replace(s,
			"[signer]\nrequire_signed = false\n",
			"[signer]\nrequire_signed = true\ntrusted_keys = [\""+trustedKeyFor(t, trustedKey)+"\"]\n", 1))
	})

	entry := registry.UpstreamServer{
		Name:        "casemgmt",
		Transport:   registry.TransportStdio,
		Command:     filepath.Join(t.TempDir(), "no-such-binary"),
		EnvVarNames: []string{"MOCK_SECRET"},
	}

	db, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := registrysqlite.Migrate(db); err != nil {
		t.Fatalf("migrate registry: %v", err)
	}
	if err := signersqlite.Migrate(db); err != nil {
		t.Fatalf("migrate signatures: %v", err)
	}
	if err := registrysqlite.New(db).Register(context.Background(), entry); err != nil {
		t.Fatalf("register upstream: %v", err)
	}
	// The forgery: the entry is signed, self-consistently, by a key the
	// gateway was never told to trust. Before ADR-0010 this was accepted
	// and the command below would have been spawned.
	if err := signersqlite.New(db).Put(context.Background(), entry.Name, attackerSigner.Sign(entry)); err != nil {
		t.Fatalf("store forged signature: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	logger, logs := serveTestLogger()
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	if got := stack.summary.UpstreamsFailed; len(got) != 1 || got[0] != "casemgmt" {
		t.Fatalf("summary.UpstreamsFailed = %v, want [casemgmt] -- an entry signed by an untrusted key must not be served", got)
	}
	if !strings.Contains(logs.String(), "trusted_keys") {
		t.Errorf("the log does not say the signing key is untrusted, so an operator cannot tell this apart from a broken backend:\n%s", logs.String())
	}
	if got := stack.summary.TrustedKeys; got != 1 {
		t.Errorf("summary.TrustedKeys = %d, want 1 -- the size of the trusted set belongs in the startup log", got)
	}
}

// TestServeStack_RunShutsDownCleanly exercises the signal path without a
// signal: run serves on the bound listener until its context is cancelled,
// then drains and returns exitOK.
func TestServeStack_RunShutsDownCleanly(t *testing.T) {
	fx := newServeFixture(t, nil)
	logger, _ := serveTestLogger()

	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	ctx, cancel := context.WithCancel(context.Background())
	codes := make(chan int, 1)
	go func() { codes <- stack.run(ctx, logger) }()

	// Wait until it is really accepting, so the shutdown below is a
	// shutdown and not a race with startup.
	url := "http://" + stack.listener.Addr().String() + httpapi.MetadataPath
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("server never accepted a connection: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case code := <-codes:
		if code != exitOK {
			t.Errorf("run returned %d after a clean shutdown, want %d (exitOK)", code, exitOK)
		}
	case <-time.After(shutdownTimeout + 10*time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}
}

// ---------------------------------------------------------------------------
// The startup summary. These need no vault, so they never skip.
// ---------------------------------------------------------------------------

// TestStartupSummary_RequireSignedIsVisible pins ADR-0006's declared debt
// to the log: an operator must be able to see whether unsigned registry
// entries are being accepted without opening the configuration file.
func TestStartupSummary_RequireSignedIsVisible(t *testing.T) {
	for _, tc := range []struct {
		requireSigned bool
		wantLevel     string
		wantText      string
	}{
		{false, "WARN", "require_signed=false"},
		{true, "INFO", "require_signed=true"},
	} {
		t.Run(fmt.Sprintf("require_signed=%t", tc.requireSigned), func(t *testing.T) {
			logger, logs := serveTestLogger()
			startupSummary{
				Addr:          "127.0.0.1:8080",
				Loopback:      true,
				RequireSigned: tc.requireSigned,
			}.log(logger)

			out := logs.String()
			if !strings.Contains(out, tc.wantText) {
				t.Errorf("startup log does not state %q:\n%s", tc.wantText, out)
			}
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, tc.wantText) && strings.Contains(line, "ADR-0006") {
					if !strings.Contains(line, tc.wantLevel) {
						t.Errorf("the require_signed line is not %s:\n%s", tc.wantLevel, line)
					}
				}
			}
		})
	}
}

// TestStartupSummary_RoleReachIsVisible is the boot-time half of GAB-30
// item 3. A role whose tool names match nothing the gateway serves is not
// an error anywhere -- the policy is well-formed, it just authorizes a set
// of names no upstream advertises -- so without this line the first report
// is an analyst being denied mid-incident.
//
// A role that grants nothing *on purpose* (the "onboarding" role in
// config.example.toml) must not be warned about: it is a documented,
// legitimate shape, and warning about it is how a warning stops being read.
func TestStartupSummary_RoleReachIsVisible(t *testing.T) {
	logger, logs := serveTestLogger()
	startupSummary{
		Addr:            "127.0.0.1:8080",
		Loopback:        true,
		RequireSigned:   true,
		ToolsDiscovered: 4,
		ToolsServable:   4,
		Roles: []roleReach{
			{Name: "n1-triage", Granted: 3, Observed: 3},
			{Name: "typo-squad", Granted: 2, Observed: 0},
			{Name: "onboarding", Granted: 0, Observed: 0},
		},
	}.log(logger)

	out := logs.String()
	for _, want := range []string{"n1-triage", "typo-squad", "onboarding"} {
		if !strings.Contains(out, want) {
			t.Errorf("the startup log does not state role %q's reach:\n%s", want, out)
		}
	}

	var warned string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN") && strings.Contains(line, "typo-squad") {
			warned = line
		}
	}
	if warned == "" {
		t.Errorf("a role granting 2 tools that match nothing observed was not warned about:\n%s", out)
	}
	if strings.Contains(warned, "onboarding") {
		t.Errorf("a role that deliberately grants nothing was reported as broken:\n%s", warned)
	}
}

// TestRoleReaches checks the arithmetic against what the gateway actually
// advertises: namespaced names, matched exactly, because that is how
// access.Role.Allows matches them.
func TestRoleReaches(t *testing.T) {
	observed := map[string]bool{
		"casemgmt.list_cases":   true,
		"casemgmt.get_case":     true,
		"threatintel.lookup_ip": true,
	}
	roles := []config.Role{
		{Name: "n1-triage", Tools: []string{"casemgmt.list_cases", "threatintel.lookup_ip"}},
		// The GAB-30 shape: legal config, well-formed policy, grants nothing.
		{Name: "un-namespaced", Tools: []string{"list_cases"}},
		{Name: "half", Tools: []string{"casemgmt.get_case", "logsearch.search_relative"}},
		{Name: "onboarding"},
	}

	want := []roleReach{
		{Name: "n1-triage", Granted: 2, Observed: 2},
		{Name: "un-namespaced", Granted: 1, Observed: 0},
		{Name: "half", Granted: 2, Observed: 1},
		{Name: "onboarding", Granted: 0, Observed: 0},
	}
	if got := roleReaches(roles, observed); !reflect.DeepEqual(got, want) {
		t.Errorf("roleReaches = %+v, want %+v", got, want)
	}
}

// TestStartupSummary_NonLoopbackIsWarned: a non-loopback bind is the
// operator's decision, but it must never be an invisible one.
func TestStartupSummary_NonLoopbackIsWarned(t *testing.T) {
	logger, logs := serveTestLogger()
	startupSummary{Addr: "0.0.0.0:8080", Loopback: false}.log(logger)

	out := logs.String()
	if !strings.Contains(out, "0.0.0.0:8080") {
		t.Errorf("the startup log does not state the listen address:\n%s", out)
	}
	if !strings.Contains(out, "NON-LOOPBACK") {
		t.Errorf("a non-loopback bind was not warned about:\n%s", out)
	}
}

func TestFailedUpstreams(t *testing.T) {
	entries := []registry.UpstreamServer{{Name: "casemgmt"}, {Name: "logsearch"}, {Name: "threatintel"}}

	if got := failedUpstreams(entries, nil); got != nil {
		t.Errorf("failedUpstreams(_, nil) = %v, want nil", got)
	}

	// The shape gateway.Connect really produces: a joined error whose
	// elements each name their entry with %q.
	err := errors.Join(
		fmt.Errorf("%w: %q: dial: no such file", gateway.ErrUpstreamUnavailable, "casemgmt"),
		fmt.Errorf("%w: %q: resolve credential %q: not found", gateway.ErrUpstreamUnavailable, "threatintel", "TOKEN"),
	)
	got := failedUpstreams(entries, err)
	if len(got) != 2 || got[0] != "casemgmt" || got[1] != "threatintel" {
		t.Errorf("failedUpstreams = %v, want [casemgmt threatintel]", got)
	}
}

// TestBuildServer_RefusesANonLoopbackBind keeps ADR-0011 item 1 pinned at
// the composition root after the predicate itself moved into
// internal/config (where the rule now lives, is applied by Validate, and
// has its own table of cases).
//
// What is asserted here is different from what is asserted there, and both
// are needed: that buildServer applies the rule *before* it acquires
// anything. A process that opened the database, decrypted the vault and
// spawned every upstream subprocess only to then refuse to listen has done
// a great deal of work on behalf of a configuration it was always going to
// reject -- and, more to the point, has already put every backend
// credential into a child process.
func TestBuildServer_RefusesANonLoopbackBind(t *testing.T) {
	cfg := &config.Config{
		Listen: "0.0.0.0:8080",
		// Deliberately nothing else. If the bind check runs first, as it
		// must, none of the missing pieces is ever reached.
	}
	logger, _ := serveTestLogger()

	stack, err := buildServer(context.Background(), cfg, logger)
	if err == nil {
		t.Fatal("buildServer accepted a non-loopback bind")
	}
	if stack != nil {
		t.Error("buildServer returned both an error and a stack; the caller has no way to know it must clean up")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the refusal does not say what is wrong with the address: %v", err)
	}
}

// TestBuildServer_ResultCeilingIsWired is a wiring test in the same family
// as TestBuildServer_RefreshIntervalIsWired and for the same reason: a
// setting an operator writes and the process ignores is worse than no
// setting, because the file reads as though it applied. Here it would read
// as though results were bounded.
func TestBuildServer_ResultCeilingIsWired(t *testing.T) {
	tests := []struct {
		name  string
		tweak func(*strings.Builder)
		want  int64
	}{
		{
			name:  "silent file gets the documented default",
			tweak: nil,
			want:  gateway.DefaultMaxResultBytes,
		},
		{
			name:  "configured value is used",
			tweak: func(b *strings.Builder) { fmt.Fprintf(b, "[response]\nmax_bytes = %d\n", 65536) },
			want:  65536,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newServeFixture(t, tc.tweak)
			logger, logs := serveTestLogger()

			stack, err := buildServer(context.Background(), fx.cfg, logger)
			if err != nil {
				t.Fatalf("buildServer: %v", err)
			}
			defer stack.close()

			if stack.maxResultBytes != tc.want {
				t.Errorf("maxResultBytes = %d, want %d", stack.maxResultBytes, tc.want)
			}
			// And an operator can read the number in effect out of the
			// startup log. A refused oversized result looks like a broken
			// backend from the analyst's side, and the first thing whoever
			// is paged needs is the limit it hit.
			if !strings.Contains(logs.String(), fmt.Sprintf("max_result_bytes=%d", tc.want)) {
				t.Errorf("the startup log does not state the result ceiling in effect:\n%s", logs.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Periodic re-observation (ADR-0013 / GAB-23)
// ---------------------------------------------------------------------------

// TestBuildServer_RefreshIntervalIsWired: the configured interval has to
// reach the loop that uses it. This is a wiring test in the same family as
// TestBuildServer_TrustAnchorIsWired -- a setting an operator writes and
// the process ignores is worse than no setting, because the file reads as
// though it applied.
func TestBuildServer_RefreshIntervalIsWired(t *testing.T) {
	tests := []struct {
		name  string
		tweak func(*strings.Builder)
		want  time.Duration
	}{
		{
			name:  "silent file gets the documented default",
			tweak: nil,
			want:  config.DefaultRefreshInterval,
		},
		{
			name:  "configured value is used",
			tweak: func(b *strings.Builder) { fmt.Fprintf(b, "[quarantine]\nrefresh_interval = %q\n", "45m") },
			want:  45 * time.Minute,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newServeFixture(t, tc.tweak)
			logger, _ := serveTestLogger()

			stack, err := buildServer(context.Background(), fx.cfg, logger)
			if err != nil {
				t.Fatalf("buildServer: %v", err)
			}
			defer stack.close()

			if stack.refreshEvery != tc.want {
				t.Errorf("refreshEvery = %v, want %v", stack.refreshEvery, tc.want)
			}
		})
	}
}

// TestServeStack_RefreshLoopTicks is the "somebody actually calls it" half
// of GAB-23, and it matters more than it looks: the defect being fixed was
// never that re-observation was wrong, it was that the only code path to it
// ran once at boot and nothing else ever reached it. A Refresh method with
// no caller would reproduce that exactly.
//
// The proof does not need an upstream. gateway.Refresh returns ErrClosed on
// a closed Gateway and the loop stops on that, so a loop that returns from
// a closed gateway without its context being cancelled is a loop that
// ticked and called Refresh. A loop that never calls Refresh hangs here and
// the test times out.
func TestServeStack_RefreshLoopTicks(t *testing.T) {
	fx := newServeFixture(t, nil)
	logger, logs := serveTestLogger()

	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	// Set directly rather than through the config file: config.Validate
	// refuses anything under a second, deliberately, and this test needs a
	// tick inside a test's patience.
	stack.refreshEvery = 10 * time.Millisecond
	if err := stack.gateway.Close(); err != nil {
		t.Fatalf("closing the gateway: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		stack.refreshLoop(context.Background(), logger)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh loop never called Refresh -- nothing re-observes the upstreams, which is GAB-23 all over again")
	}

	// And an operator can see that it is running at all, with the interval
	// they chose. The window in which a poisoned tool is still served IS
	// that interval, so it belongs in the log rather than only in the file.
	if !strings.Contains(logs.String(), "re-observing upstream tool definitions periodically") {
		t.Errorf("the startup log does not say that periodic re-observation is on:\n%s", logs.String())
	}
}

// TestServeStack_RefreshLoopStopsWhenCancelled: run's caller closes the
// database on the way out, so a loop still writing observations after that
// would surface as a confusing error during shutdown.
func TestServeStack_RefreshLoopStopsWhenCancelled(t *testing.T) {
	fx := newServeFixture(t, nil)
	logger, _ := serveTestLogger()

	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	// Long enough that a tick cannot be what ends the loop: only the
	// cancellation can.
	stack.refreshEvery = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		stack.refreshLoop(ctx, logger)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh loop outlived its context")
	}
}
