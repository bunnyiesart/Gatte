package admin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
)

// gatte-status, the command the connect script installs on an analyst's
// machine for the case nothing in-band can help with: Gatte itself not
// answering (design/adr/0041 item 8a).

// The `claude mcp get` outputs of Claude Code 2.1.285 the script reads
// (design/adr/0041, Contexto item 8). Only the Status: and Issue: lines
// matter; the rest is there so the parser is shown the real shape.
const (
	claudeGetConnected = `gatte:
  Scope: User config (available in all your projects)
  Status: ✔ Connected
  Type: http
  URL: https://mcp.example.internal/mcp

To remove this server, run: claude mcp remove "gatte" -s user
`
	claudeGetNeedsAuth = `gatte:
  Scope: User config (available in all your projects)
  Status: Needs authentication
  Type: http
  URL: https://mcp.example.internal/mcp
`
	claudeGetFailed503 = `gatte:
  Scope: User config (available in all your projects)
  Status: ✘ Failed to connect
  Issue: HTTP 503: Error POSTing to endpoint: Gatte is temporarily unable to serve tools. This is not a problem with your request; retry in a few minutes or tell the user.
  Type: http
  URL: https://mcp.example.internal/mcp
`
	claudeGetFailedOther = `gatte:
  Scope: User config (available in all your projects)
  Status: ✘ Failed to connect
  Issue: Dynamic Client Registration rejected (HTTP 404)
`
)

func statusInfo(base string) admin.ConnectInfo {
	return admin.ConnectInfo{Ready: true, URL: base + "/mcp", MetaURL: base + "/.well-known/oauth-protected-resource",
		ClientID: "claude-code", Port: 47823, Server: "gatte", Date: "2026-09-29"}
}

// gatteStub answers like serve: the metadata with 200, an MCP POST without
// a token with 401 and the resource_metadata challenge.
func gatteStub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/oauth-protected-resource":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"resource":"x"}`)
		case r.URL.Path == "/mcp" && r.Method == http.MethodPost:
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://mcp.example.internal/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	})
}

type statusRun struct {
	code int
	out  string
	args string
}

// runStatus renders gatte-status for info and runs it in a throwaway HOME
// with a stand-in claude that prints fixture (none: no claude at all).
func runStatus(t *testing.T, info admin.ConnectInfo, fixture string, flags ...string) statusRun {
	t.Helper()
	text, name, err := admin.RenderStatusScript(info, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if name != "gatte-status" {
		t.Fatalf("sh status script named %q", name)
	}
	dir := t.TempDir()
	home, bin := filepath.Join(dir, "home"), filepath.Join(dir, "bin")
	for _, d := range []string{filepath.Join(home, ".config", "gatte"), bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if info.CAPEM != "" {
		if err := os.WriteFile(filepath.Join(home, ".config", "gatte", "ca.pem"), []byte(info.CAPEM), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"curl", "grep", "sed", "tr", "cut", "head", "mktemp", "rm", "cat", "printf"} {
		if p, err := exec.LookPath(tool); err == nil {
			_ = os.Symlink(p, filepath.Join(bin, tool))
		}
	}
	log := filepath.Join(dir, "claude.log")
	if fixture != "" {
		fx := filepath.Join(dir, "fixture.txt")
		if err := os.WriteFile(fx, []byte(fixture), 0o600); err != nil {
			t.Fatal(err)
		}
		fake := strings.ReplaceAll(strings.ReplaceAll(fakeClaude, "@LOG@", log), "@FIXTURE@", fx)
		if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(dir, name)
	if err := os.WriteFile(script, []byte(text), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", append([]string{script}, flags...)...)
	// Run from a checkout, as an analyst does: its project settings and
	// hooks must not be what Claude Code loads for the script.
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd.Dir = repo
	// Only bin: no claude on the PATH unless the test put one there.
	cmd.Env = []string{"HOME=" + home, "PATH=" + bin}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(log)
	realRepo, _ := filepath.EvalSymlinks(repo)
	for _, line := range strings.Split(string(args), "\n") {
		if strings.HasPrefix(line, "cwd="+repo+" ") || strings.HasPrefix(line, "cwd="+realRepo+" ") {
			t.Errorf("claude ran in the analyst's current directory: %q", line)
		}
	}
	return statusRun{code: code, out: string(out), args: string(args)}
}

// fakeClaude stands in for Claude Code 2.1.285. It logs where it ran and
// with what, prints the fixture for "mcp get", and parses -p the way the
// real one does: --allowedTools takes every argument after it that is not
// an option, so a prompt placed after it is read as a tool name and -p has
// no prompt.
const fakeClaude = `#!/bin/sh
echo "cwd=$(pwd) $*" >> '@LOG@'
if [ "$1" = mcp ]; then
  cat '@FIXTURE@'
  exit 0
fi
prompt=
while [ $# -gt 0 ]; do
  case "$1" in
    --allowedTools|--allowed-tools)
      shift
      while [ $# -gt 0 ]; do
        case "$1" in -*) break ;; esac
        shift
      done ;;
    --setting-sources) shift 2 ;;
    -*) shift ;;
    *) prompt=$1; shift ;;
  esac
done
if [ -z "$prompt" ]; then
  echo 'Error: Input must be provided either through stdin or as a prompt argument when using --print' >&2
  exit 1
fi
echo 'casemgmt: up since 2026-09-29T08:00:03Z.'
exit 0
`

func TestStatusScript_TellsUnreachableFromNeedsLoginFromUp(t *testing.T) {
	up := httptest.NewServer(gatteStub())
	defer up.Close()
	// A port where nothing listens: the host answers with a reset.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	ln.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "Gatte em manutenção\x1b[31m até 15h")
	}))
	defer proxy.Close()
	notGatte := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer notGatte.Close()

	for _, tc := range []struct {
		name    string
		base    string
		fixture string
		code    int
		says    []string
		never   []string
	}{
		{"up and signed in", up.URL, claudeGetConnected, 0, []string{"/mcp", "reconnect"}, nil},
		{"up, login expired", up.URL, claudeGetNeedsAuth, 4, []string{"/mcp", "authenticate", "signing in again will not help"}, nil},
		{"up, not serving tools", up.URL, claudeGetFailed503, 3, []string{"Gatte is temporarily unable to serve tools"}, nil},
		{"up, unexpected failure", up.URL, claudeGetFailedOther, 5, []string{"Dynamic Client Registration rejected"}, nil},
		{"up, no Claude Code", up.URL, "", 4, []string{"connect-gatte"}, nil},
		{"nothing listens", closed, claudeGetConnected, 3, []string{"operator"}, []string{"VPN"}},
		{"name does not resolve", "http://gatte.invalid", claudeGetConnected, 1, []string{"VPN"}, nil},
		{"proxy answers 503", proxy.URL, claudeGetConnected, 3, []string{"Gatte em manutenção"}, []string{"\x1b"}},
		{"something else at the MCP URL", notGatte.URL, claudeGetConnected, 5, []string{"not Gatte"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runStatus(t, statusInfo(tc.base), tc.fixture)
			if r.code != tc.code {
				t.Fatalf("exit %d, want %d\n%s", r.code, tc.code, r.out)
			}
			for _, s := range tc.says {
				if !strings.Contains(r.out, s) {
					t.Errorf("output lacks %q:\n%s", s, r.out)
				}
			}
			for _, s := range tc.never {
				if strings.Contains(r.out, s) {
					t.Errorf("output has %q:\n%s", s, r.out)
				}
			}
		})
	}
}

// With the team's CA the check is TLS against that CA and nothing else: a
// server whose certificate another CA issued is a TLS problem (exit 2).
func TestStatusScript_ChecksTLSAgainstTheTeamCA(t *testing.T) {
	srv := httptest.NewTLSServer(gatteStub())
	defer srv.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	info := statusInfo(srv.URL)
	info.CAPEM = caPEM
	if r := runStatus(t, info, claudeGetConnected); r.code != 0 {
		t.Fatalf("with the right CA: exit %d\n%s", r.code, r.out)
	}
	// Every httptest server shares one certificate, so "another CA" is a
	// team CA that did not issue the server's.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Other Lab CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	info.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if r := runStatus(t, info, claudeGetConnected); r.code != 2 || !strings.Contains(r.out, "connect-gatte") {
		t.Fatalf("with another CA: exit %d, want 2\n%s", r.code, r.out)
	}
}

// -backends asks Claude Code to call gatte.status under the name the
// client exposes it as, and says the answer is the model's.
func TestStatusScript_BackendsCallsGatteStatusAsTheClientNamesIt(t *testing.T) {
	up := httptest.NewServer(gatteStub())
	defer up.Close()
	r := runStatus(t, statusInfo(up.URL), claudeGetConnected, "-backends")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.out)
	}
	if !strings.Contains(r.args, "--allowedTools mcp__gatte__gatte_status") || !strings.Contains(r.out, "casemgmt: up") || !strings.Contains(r.out, "model") {
		t.Fatalf("claude called with %q; output:\n%s", r.args, r.out)
	}
	// Only the analyst's own settings: no project's permissions or hooks.
	if !strings.Contains(r.args, "--setting-sources user") {
		t.Errorf("claude -p called with %q, want --setting-sources user", r.args)
	}
}

// Without -backends the check does not look at the backends, so a pass
// must not read as "everything is fine": it says Gatte itself is fine and
// how to see the backends.
func TestStatusScript_APassWithoutBackendsPointsToThem(t *testing.T) {
	up := httptest.NewServer(gatteStub())
	defer up.Close()
	r := runStatus(t, statusInfo(up.URL), claudeGetConnected)
	if r.code != 0 || !strings.Contains(r.out, "gatte-status -backends") || !strings.Contains(r.out, "gatte.status") {
		t.Fatalf("exit %d; the pass does not point to the backends:\n%s", r.code, r.out)
	}
	text, _, _ := admin.RenderStatusScript(statusInfo(up.URL), "linux")
	if strings.Contains(text, "0 all good") {
		t.Error("the header still calls exit 0 \"all good\" although backends are not checked")
	}
}

// The PowerShell version, which cannot run here: Claude Code is called
// from a directory of the script's own, never under
// $ErrorActionPreference = 'Stop' (Windows PowerShell 5.1 turns a native
// command's stderr into a terminating error there), and -p gets its
// prompt before the list option.
func TestStatusScript_PowerShellCallsClaudeSafely(t *testing.T) {
	ps, _, err := admin.RenderStatusScript(statusInfo("https://mcp.example.internal"), "windows")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(ps, "\r\n")
	pref, pushed, calls := "", false, 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "$ErrorActionPreference = ") {
			pref = strings.TrimPrefix(trimmed, "$ErrorActionPreference = ")
		}
		if strings.HasPrefix(trimmed, "Push-Location") {
			pushed = true
		}
		if strings.HasPrefix(trimmed, "Pop-Location") {
			pushed = false
		}
		if !strings.Contains(line, "& claude") {
			continue
		}
		calls++
		if pref != "'Continue'" {
			t.Errorf("line %d runs claude under $ErrorActionPreference = %s: %s", i+1, pref, trimmed)
		}
		if !pushed {
			t.Errorf("line %d runs claude from the analyst's current directory: %s", i+1, trimmed)
		}
		if strings.Contains(line, " -p ") {
			p, a := strings.Index(line, "\"Call "), strings.Index(line, "--allowedTools")
			if p < 0 || a < 0 || p > a || !strings.Contains(line, "--setting-sources user") {
				t.Errorf("line %d: the prompt must come before --allowedTools, with --setting-sources user: %s", i+1, trimmed)
			}
		}
	}
	if calls != 2 {
		t.Errorf("found %d claude calls in the ps1, want 2", calls)
	}
}

func TestStatusScripts_AreValidAndCarryNoSecret(t *testing.T) {
	for _, withCA := range []bool{false, true} {
		info := statusInfo("https://mcp.example.internal")
		if withCA {
			info.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}
		sh, _, err := admin.RenderStatusScript(info, "macos")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "gatte-status")
		os.WriteFile(p, []byte(sh), 0o600)
		if out, err := exec.Command("sh", "-n", p).CombinedOutput(); err != nil {
			t.Errorf("gatte-status (ca=%v) is not valid sh: %v\n%s", withCA, err, out)
		}
		ps, name, err := admin.RenderStatusScript(info, "windows")
		if err != nil || name != "gatte-status.ps1" {
			t.Fatalf("ps1: %q, %v", name, err)
		}
		for label, text := range map[string]string{"sh": sh, "ps1": ps} {
			for _, want := range []string{"https://mcp.example.internal/mcp", "/.well-known/oauth-protected-resource", "mcp__gatte__gatte_status", "resource_metadata"} {
				if !strings.Contains(text, want) {
					t.Errorf("%s (ca=%v) lacks %q", label, withCA, want)
				}
			}
			for _, never := range []string{"Authorization", "access_token", "claude-code'"} {
				if strings.Contains(text, never) {
					t.Errorf("%s (ca=%v) carries %q", label, withCA, never)
				}
			}
		}
		if strings.Contains(ps, "Invoke-WebRequest") || !strings.Contains(ps, "HttpWebRequest") {
			t.Errorf("ps1 (ca=%v) must use HttpWebRequest, not Invoke-WebRequest", withCA)
		}
		if withCA {
			for _, want := range []string{"ca.pem", "X509Chain", "ExtraStore", "AllowUnknownCertificateAuthority", "Thumbprint", "RemoteCertificateNameMismatch", "RevocationMode"} {
				if !strings.Contains(ps, want) {
					t.Errorf("ps1 with a CA lacks %q", want)
				}
			}
		} else if strings.Contains(ps, "ServerCertificateValidationCallback") {
			t.Error("ps1 without a CA replaces the system's validation")
		}
	}
}

// The connect scripts install gatte-status next to the CA, put its
// directory on the PATH once, and say so.
func TestConnectScripts_InstallGatteStatus(t *testing.T) {
	info := statusInfo("https://mcp.example.internal")
	sh, _, err := admin.RenderScript(info, "linux")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{".config/gatte/bin/gatte-status", "chmod 755", "gatte/bin", "GATTE_STATUS", "mcp__gatte__gatte_status"} {
		if !strings.Contains(sh, want) {
			t.Errorf("sh connect script lacks %q", want)
		}
	}
	ps, _, err := admin.RenderScript(info, "windows")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"gatte-status.ps1", "gatte-status.cmd", "-ExecutionPolicy Bypass", "[Environment]::SetEnvironmentVariable('Path'", "'User')", "mcp__gatte__gatte_status"} {
		if !strings.Contains(ps, want) {
			t.Errorf("ps1 connect script lacks %q", want)
		}
	}
	// Written with Set-Content -Encoding ascii, and PowerShell 5 reads a
	// script without a BOM as the system code page.
	for i, r := range ps {
		if r > 0x7e || (r < 0x20 && r != '\r' && r != '\n' && r != '\t') {
			t.Fatalf("ps1 connect script has %U at byte %d; it must be ASCII", r, i)
		}
	}
	if strings.Contains(strings.ToLower(ps), "setx") {
		t.Error("ps1 connect script uses setx, which cuts a long PATH at 1024 characters")
	}
}

// Run for real, twice, in a throwaway HOME: the command lands executable
// in ~/.config/gatte/bin, the profile gets the PATH line once, and the
// installed file is the rendered gatte-status.
func TestConnectScript_InstallsGatteStatusIdempotently(t *testing.T) {
	info := statusInfo("https://mcp.example.internal")
	text, _, _ := admin.RenderScript(info, "macos")
	want, _, _ := admin.RenderStatusScript(info, "macos")
	dir := t.TempDir()
	home, bin := filepath.Join(dir, "home"), filepath.Join(dir, "bin")
	for _, d := range []string{home, bin} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("# mine\n"), 0o600)
	os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\nexit 7\n"), 0o755)
	script := filepath.Join(dir, "connect-gatte.sh")
	os.WriteFile(script, []byte(text), 0o600)
	for i := 0; i < 2; i++ {
		cmd := exec.Command("sh", script)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run %d: %v\n%s", i+1, err, out)
		}
		// No username: the header is still a comment, not a command.
		if strings.Contains(string(out), "not found") || strings.Contains(string(out), "Generated") {
			t.Fatalf("run %d ran a header line as a command:\n%s", i+1, out)
		}
		if !strings.Contains(string(out), "gatte-status") {
			t.Fatalf("run %d does not mention gatte-status:\n%s", i+1, out)
		}
	}
	installed := filepath.Join(home, ".config", "gatte", "bin", "gatte-status")
	fi, err := os.Stat(installed)
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("gatte-status: %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(installed); string(got) != want {
		t.Errorf("installed gatte-status differs from the rendered one")
	}
	rc, _ := os.ReadFile(filepath.Join(home, ".zshrc"))
	if !strings.HasPrefix(string(rc), "# mine\n") || strings.Count(string(rc), "gatte/bin") != 1 {
		t.Fatalf(".zshrc after two runs:\n%s", rc)
	}
}

// TestStatusScripts_SayARefusedAccountIsNotALoginProblem: Claude Code shows
// Gatte's 403 for a refused account as "Needs authentication" and drops
// its body (measured on 2.1.285, design/adr/0042 item 2), so the one place
// the analyst can read that signing in again will not help is here.
func TestStatusScripts_SayARefusedAccountIsNotALoginProblem(t *testing.T) {
	for _, system := range []string{"linux", "windows"} {
		script, _, err := admin.RenderStatusScript(statusInfo("https://mcp.example.internal"), system)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(script, "signing in again will not help; ask the SOC operator.") {
			t.Errorf("%s: the needs-authentication branch does not say a refused account is not a login problem", system)
		}
	}
}
