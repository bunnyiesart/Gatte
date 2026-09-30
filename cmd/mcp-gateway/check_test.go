package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func TestSvcAccountPermits(t *testing.T) {
	svc := svcAccount{Name: "mcpgw", UID: 998, groups: map[uint32]bool{998: true, 50: true}}
	tests := []struct {
		name        string
		f           fileFacts
		read, write bool
	}{
		{"owner rw", fileFacts{998, 0, 0o600}, true, true},
		{"owner r only", fileFacts{998, 0, 0o400}, true, false},
		{"root's 0600", fileFacts{0, 0, 0o600}, false, false},
		{"root, its group, 0640", fileFacts{0, 998, 0o640}, true, false},
		{"root, its group, 0660", fileFacts{0, 998, 0o660}, true, true},
		{"root, other group, 0640", fileFacts{0, 7, 0o640}, false, false},
		{"world-readable", fileFacts{0, 0, 0o644}, true, false},
		{"world-writable", fileFacts{0, 0, 0o666}, true, true},
		// The owner's bits apply to the owner even when the group's are
		// wider, as the kernel does.
		{"owner 0070", fileFacts{998, 998, 0o070}, false, false},
	}
	for _, tt := range tests {
		if got := svc.canRead(tt.f); got != tt.read {
			t.Errorf("%s: canRead = %v, want %v", tt.name, got, tt.read)
		}
		if got := svc.canWrite(tt.f); got != tt.write {
			t.Errorf("%s: canWrite = %v, want %v", tt.name, got, tt.write)
		}
	}
	root := svcAccount{UID: 0}
	if !root.canRead(fileFacts{0, 0, 0}) {
		t.Error("root reads everything")
	}
}

func TestJudgeSigningKey(t *testing.T) {
	svc := &svcAccount{Name: "mcpgw", UID: 998, Group: "mcpgw", groups: map[uint32]bool{998: true}}
	tests := []struct {
		name string
		f    fileFacts
		svc  *svcAccount
		want checkStatus
		fix  string
	}{
		{"root 0600", fileFacts{0, 0, 0o600}, svc, checkPass, ""},
		{"owned by the service account", fileFacts{998, 998, 0o600}, svc, checkFail, "chown root:root"},
		{"root 0640", fileFacts{0, 998, 0o640}, svc, checkFail, "chmod 0600"},
		{"root 0604", fileFacts{0, 0, 0o604}, svc, checkFail, "chmod 0600"},
		{"serve runs as root", fileFacts{0, 0, 0o600}, &svcAccount{Name: "root", UID: 0}, checkFail, ""},
		{"no account known, root 0600", fileFacts{0, 0, 0o600}, nil, checkPass, ""},
	}
	for _, tt := range tests {
		st, detail, fix := judgeSigningKey(tt.f, tt.svc, "/k/signing.key")
		if st != tt.want || !strings.Contains(fix, tt.fix) {
			t.Errorf("%s: %s %q fix %q; want %s with fix containing %q", tt.name, st, detail, fix, tt.want, tt.fix)
		}
	}
}

func TestJudgeAgeKey(t *testing.T) {
	svc := &svcAccount{Name: "mcpgw", UID: 998, Group: "mcpgw", groups: map[uint32]bool{998: true}}
	tests := []struct {
		name string
		f    fileFacts
		want checkStatus
		fix  string
	}{
		{"service account's 0600", fileFacts{998, 998, 0o600}, checkPass, ""},
		{"root's 0600: serve cannot decrypt", fileFacts{0, 0, 0o600}, checkFail, "chown mcpgw:mcpgw"},
		{"0640: the vault refuses it", fileFacts{998, 998, 0o640}, checkFail, "chmod 0600"},
	}
	for _, tt := range tests {
		st, _, fix := judgeAgeKey(tt.f, svc, "/k/age.key")
		if st != tt.want || !strings.Contains(fix, tt.fix) {
			t.Errorf("%s: %s fix %q; want %s with fix containing %q", tt.name, st, fix, tt.want, tt.fix)
		}
	}
}

// checkFixture is a deployment on disk owned by the user running the
// test, with a real vault, one signed stdio entry and a trail.
type checkFixture struct {
	fileEnv
	configPath string
}

func newCheckFixture(t *testing.T, extra string) checkFixture {
	t.Helper()
	secrets, ageKey := newServeVaultFixture(t, map[string]string{"CASEMGMT_URL": "https://casemgmt.example.org", "CASEMGMT_API_KEY": "fixture-value"})
	e := newFileEnv(t)
	e.cfg.Vault = config.Vault{SecretsFile: secrets, AgeKeyFile: ageKey}

	var b strings.Builder
	fmt.Fprintf(&b, "listen = %q\ndatabase = %q\n", "127.0.0.1:0", e.cfg.Database)
	fmt.Fprintf(&b, "[oidc]\nissuer = %q\naudience = %q\n", "https://idp.example.org", "https://gatte.example.org/mcp")
	fmt.Fprintf(&b, "[vault]\nsecrets_file = %q\nage_key_file = %q\n", secrets, ageKey)
	b.WriteString(signerSection(t, e.cfg.Signer.KeyFile))
	b.WriteString("[upstreams]\nallow_credentialed_stdio = true\n")
	b.WriteString(extra)
	p := filepath.Join(e.dir, "config.toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	e.db.Close()
	return checkFixture{fileEnv: e, configPath: p}
}

// fixtureChecker is a checker over fx that sees every file as owned by a
// made-up service account, uid 4242, with the file's real mode: the
// results then do not depend on who runs the test, root included.
func fixtureChecker(t *testing.T, fx checkFixture) *checker {
	t.Helper()
	c := newChecker(fx.configPath, false)
	c.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Uid: "4242", Gid: "4242", Username: name}, nil
	}
	c.stat = func(p string) (fileFacts, error) {
		fi, err := os.Stat(p)
		if err != nil {
			return fileFacts{}, err
		}
		return fileFacts{uid: 4242, gid: 4242, mode: fi.Mode()}, nil
	}
	return c
}

// runFixture runs c and returns its report as check -json prints it.
func runFixture(t *testing.T, c *checker) (checkReport, int) {
	t.Helper()
	var out, errBuf bytes.Buffer
	if code := c.run(context.Background(), "svc-test", &errBuf); code != exitOK {
		t.Fatalf("check could not run: %d\n%s", code, errBuf.String())
	}
	code := c.report(&out, &errBuf, true)
	var rep checkReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("check -json: %v\n%s", err, out.String())
	}
	return rep, code
}

func runCheckJSON(t *testing.T, args ...string) (checkReport, int, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(append([]string{"check", "-json"}, args...), &out, &errBuf)
	var rep checkReport
	if code != exitCannotRun {
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("check -json: %v\n%s\n%s", err, out.String(), errBuf.String())
		}
	}
	return rep, code, errBuf.String()
}

func resultOf(t *testing.T, rep checkReport, name string) checkResult {
	t.Helper()
	for _, r := range rep.Checks {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no %q check in the report: %+v", name, rep.Checks)
	return checkResult{}
}

func TestCheck_ADeploymentOwnedByTheServiceAccount(t *testing.T) {
	fx := newCheckFixture(t, "")
	dbBefore, _, _ := fileSHA256(fx.cfg.Database)

	rep, code := runFixture(t, fixtureChecker(t, fx))
	if code != exitProblem {
		t.Fatalf("check = %d, want %d (the signing key is not root's)", code, exitProblem)
	}
	for name, want := range map[string]checkStatus{
		"configuration":       checkPass,
		"service account":     checkPass,
		"configuration file":  checkFail, // the service account owns and can write it
		"signing key":         checkFail, // not root's
		"age key":             checkPass,
		"vault file":          checkWarn,
		"sops":                checkPass,
		"database schema":     checkPass,
		"audit trail":         checkPass,
		"registry signatures": checkPass,
		"vault contents":      checkPass,
		"oci backends":        checkSkip,
		"identity provider":   checkSkip,
	} {
		if got := resultOf(t, rep, name); got.Status != want {
			t.Errorf("%s: %s (%s), want %s", name, got.Status, got.Detail, want)
		}
	}
	for _, r := range rep.Checks {
		if (r.Status == checkFail || r.Status == checkWarn) && r.Fix == "" {
			t.Errorf("%s is %s with no fix: %s", r.Name, r.Status, r.Detail)
		}
		if strings.Contains(r.Detail, "fixture-value") {
			t.Fatalf("a credential value reached the report: %s", r.Name)
		}
	}
	if rep.Failed != 2 || rep.ServiceAccount == nil || rep.ServiceAccount.Name != "svc-test" {
		t.Errorf("failed = %d, account %+v; want 2, svc-test", rep.Failed, rep.ServiceAccount)
	}

	// Read-only: the database file is byte for byte what it was, and no
	// -wal appeared that the service account would then not own.
	if after, _, _ := fileSHA256(fx.cfg.Database); after != dbBefore {
		t.Error("check changed the database")
	}
	if fi, err := os.Stat(fx.cfg.Database + "-wal"); err == nil && fi.Size() > 0 {
		t.Error("check wrote to the database's WAL")
	}
}

func TestCheck_HumanOutputNamesEachFix(t *testing.T) {
	fx := newCheckFixture(t, "")
	c := fixtureChecker(t, fx)
	var out, errBuf bytes.Buffer
	if code := c.run(context.Background(), "svc-test", &errBuf); code != exitOK {
		t.Fatal(code)
	}
	if code := c.report(&out, &errBuf, false); code != exitProblem {
		t.Fatalf("check = %d\n%s", code, errBuf.String())
	}
	text := out.String()
	for _, want := range []string{"FAIL  signing key", "fix: sudo chown root:root", "PASS  sops", "2 failed", "Not checked: ACLs"} {
		if !strings.Contains(text, want) {
			t.Errorf("check's output does not say %q:\n%s", want, text)
		}
	}
}

func TestCheck_ACredentialTheVaultDoesNotHoldFails(t *testing.T) {
	fx := newCheckFixture(t, "")
	db, err := openStore(fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := &opEnv{cfg: fx.cfg, db: db, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	entry := stdioEntry("docsearch")
	entry.EnvVarNames = []string{"DOCSEARCH_TOKEN"}
	if err := e.upstreams().Register(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	db.Close()

	rep, code := runFixture(t, fixtureChecker(t, fx))
	if code != exitProblem {
		t.Fatalf("check = %d", code)
	}
	vc := resultOf(t, rep, "vault contents")
	if vc.Status != checkFail || !strings.Contains(vc.Detail, "docsearch: DOCSEARCH_TOKEN") {
		t.Errorf("vault contents: %s %s", vc.Status, vc.Detail)
	}
	// And that entry is unsigned while require_signed is on.
	rs := resultOf(t, rep, "registry signatures")
	if rs.Status != checkFail || !strings.Contains(rs.Detail, "unsigned (docsearch)") {
		t.Errorf("registry signatures: %s %s", rs.Status, rs.Detail)
	}
}

func TestCheck_ANewerSchemaFails(t *testing.T) {
	fx := newCheckFixture(t, "")
	raw, err := store.Open(fx.cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", store.SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	rep, code := runFixture(t, fixtureChecker(t, fx))
	if code != exitProblem {
		t.Fatalf("check = %d", code)
	}
	if r := resultOf(t, rep, "database schema"); r.Status != checkFail || !strings.Contains(r.Fix, "docs/upgrade.md") {
		t.Errorf("database schema: %+v", r)
	}
}

func TestCheck_AConfigThatDoesNotLoadIsAFailure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte("listen = \"0.0.0.0:80\"\nnot_a_key = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, code, _ := runCheckJSON(t, "-config", p)
	if code != exitProblem {
		t.Fatalf("check on a broken config = %d, want %d", code, exitProblem)
	}
	if r := resultOf(t, rep, "configuration"); r.Status != checkFail || r.Fix == "" {
		t.Errorf("configuration: %+v", r)
	}
}

func TestCheck_AnUnknownUserCannotRun(t *testing.T) {
	fx := newCheckFixture(t, "")
	_, code, stderr := runCheckJSON(t, "-config", fx.configPath, "-user", "no-such-account-qol-ops")
	if code != exitCannotRun || !strings.Contains(stderr, "no-such-account-qol-ops") {
		t.Fatalf("check -user unknown = %d\n%s", code, stderr)
	}
}

// A root-owned -wal beside the service account's database is the failure
// README step 4 warns about: serve cannot open it.
func TestCheck_ARootOwnedWALIsCaught(t *testing.T) {
	fx := newCheckFixture(t, "")
	c := fixtureChecker(t, fx)
	owned := c.stat
	c.stat = func(p string) (fileFacts, error) {
		if strings.HasSuffix(p, "-wal") {
			return fileFacts{0, 0, 0o644}, nil
		}
		return owned(p)
	}
	rep, _ := runFixture(t, c)
	got := resultOf(t, rep, "database")
	if got.Status != checkFail || !strings.Contains(got.Detail, "-wal") || !strings.Contains(got.Fix, "chown svc-test") {
		t.Errorf("database: %+v", got)
	}
}

// Through the command, as an operator runs it: the flags reach the
// checker and the exit code is the report's.
func TestCmdCheck_EndToEnd(t *testing.T) {
	fx := newCheckFixture(t, "")
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	rep, code, stderr := runCheckJSON(t, "-config", fx.configPath, "-user", u.Username)
	// The fixture's signing key is the test user's, never root's, so the
	// signing key fails whoever runs this.
	if code != exitProblem {
		t.Fatalf("check = %d\n%s", code, stderr)
	}
	if r := resultOf(t, rep, "signing key"); r.Status != checkFail {
		t.Errorf("signing key: %+v", r)
	}
}

func TestCheck_OCIBackendsNeedPodmanAndSubordinateIDs(t *testing.T) {
	dir := t.TempDir()
	subuid, subgid := filepath.Join(dir, "subuid"), filepath.Join(dir, "subgid")
	svc := &svcAccount{Name: "mcpgw", UID: 998, Group: "mcpgw"}
	oci := []registry.UpstreamServer{{Name: "threatintel", Transport: registry.TransportOCI}}
	newC := func(podman bool) *checker {
		c := &checker{svc: svc, goos: "linux", subidFiles: [2]string{subuid, subgid}}
		c.lookPath = func(string) (string, error) {
			if podman {
				return "/usr/bin/podman", nil
			}
			return "", fs.ErrNotExist
		}
		return c
	}

	c := newC(false)
	c.checkOCI(oci)
	if r := c.results[0]; r.Status != checkFail || !strings.Contains(r.Detail, "podman") {
		t.Errorf("without podman: %+v", r)
	}

	_ = os.WriteFile(subuid, []byte("other:100000:65536\nmcpgw:165536:1000\n"), 0o644)
	_ = os.WriteFile(subgid, []byte("998:100000:65536\n"), 0o644)
	c = newC(true)
	c.checkOCI(oci)
	if r := c.results[0]; r.Status != checkFail || !strings.Contains(r.Detail, subuid) || strings.Contains(r.Detail, subgid) {
		t.Errorf("a range of 1000 in subuid, a uid-keyed one in subgid: %+v", r)
	}

	_ = os.WriteFile(subuid, []byte("mcpgw:100000:65536\n"), 0o644)
	c = newC(true)
	c.checkOCI(oci)
	if r := c.results[0]; r.Status != checkPass {
		t.Errorf("with both ranges: %+v", r)
	}

	c = newC(true)
	c.checkOCI(nil)
	if r := c.results[0]; r.Status != checkSkip {
		t.Errorf("no oci entry: %+v", r)
	}
}

func TestCheck_OnlineReadsTheDiscoveryDocument(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/good/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/other/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://elsewhere.example.org", "jwks_uri": srv.URL + "/jwks"})
	})

	for _, tt := range []struct {
		path string
		want checkStatus
	}{{"/good", checkPass}, {"/other", checkFail}, {"/missing", checkFail}} {
		issuer = srv.URL + tt.path
		c := &checker{online: true, httpClient: srv.Client(), cfg: &config.Config{OIDC: config.OIDC{Issuer: issuer}}}
		c.checkIdP(context.Background())
		if r := c.results[0]; r.Status != tt.want {
			t.Errorf("%s: %+v, want %s", tt.path, r, tt.want)
		}
	}

	c := &checker{cfg: &config.Config{OIDC: config.OIDC{Issuer: srv.URL}}}
	c.checkIdP(context.Background())
	if r := c.results[0]; r.Status != checkSkip || !strings.Contains(r.Detail, "-online") {
		t.Errorf("offline: %+v", r)
	}
}

// TestCheckSigningKey_ADirectoryTheServiceAccountWritesFails: a key that
// is root's and 0600 is still replaceable by whoever writes its directory.
func TestCheckSigningKey_ADirectoryTheServiceAccountWritesFails(t *testing.T) {
	svc := &svcAccount{Name: "mcpgw", UID: 998, Group: "mcpgw", groups: map[uint32]bool{998: true}}
	for _, tt := range []struct {
		name string
		dir  fileFacts
		want checkStatus
	}{
		{"root's 0700 directory", fileFacts{0, 0, 0o700 | fs.ModeDir}, checkPass},
		{"root's directory, group mcpgw writable", fileFacts{0, 998, 0o770 | fs.ModeDir}, checkFail},
		{"the service account's directory", fileFacts{998, 998, 0o700 | fs.ModeDir}, checkFail},
	} {
		c := newChecker("", false)
		c.cfg = &config.Config{Signer: config.Signer{KeyFile: "/k/signing.key"}}
		c.svc = svc
		c.stat = func(p string) (fileFacts, error) {
			if p == "/k" {
				return tt.dir, nil
			}
			return fileFacts{0, 0, 0o600}, nil
		}
		c.checkSigningKey()
		if len(c.results) != 1 || c.results[0].Status != tt.want {
			t.Errorf("%s: results %+v, want one %s", tt.name, c.results, tt.want)
			continue
		}
		if tt.want == checkFail && !strings.Contains(c.results[0].Fix, "chown root:root") {
			t.Errorf("%s: fix %q does not say how", tt.name, c.results[0].Fix)
		}
	}
}
