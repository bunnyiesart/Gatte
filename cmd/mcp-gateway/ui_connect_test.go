//go:build !nofront

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
)

// withConnect configures the connect scripts on e, optionally with a CA
// file whose certificate is followed by junk that must never reach a
// script.
func withConnect(t *testing.T, e opTestEnv, withCA bool) {
	t.Helper()
	e.cfg.OIDC.Audience = "https://mcp.example.internal/mcp"
	e.cfg.Connect.ClientID = "claude-code"
	e.cfg.Connect.CallbackPort = 47823
	e.cfg.Connect.ServerName = "gatte"
	if !withCA {
		return
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lab CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	junk := "GATTE_CA\ntouch /tmp/owned\n'@\nRemove-Item C:\\\n"
	body := junk + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + junk
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cfg.Connect.CAFile = p
}

func TestConnectScripts_CarryTheGatewayAndTheClientAndNothingElse(t *testing.T) {
	for _, withCA := range []bool{false, true} {
		e := newOpTestEnv(t)
		withConnect(t, e, withCA)
		info, err := admin.ConnectInfoOf(e.cfg, "ana.souza", time.Now())
		if err != nil || !info.Ready {
			t.Fatalf("ConnectInfoOf: %+v, %v", info, err)
		}
		for _, osName := range []string{"macos", "linux", "windows"} {
			text, name, err := admin.RenderScript(info, osName)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"https://mcp.example.internal/mcp", "--client-id 'claude-code'", "--callback-port 47823", "'gatte'", "ana.souza", "claude mcp add --transport http --scope user"} {
				if !strings.Contains(text, want) {
					t.Errorf("%s script (ca=%v) lacks %q", osName, withCA, want)
				}
			}
			if strings.Contains(text, "touch /tmp/owned") || strings.Contains(text, "Remove-Item") {
				t.Errorf("%s script carries text from outside the CA certificate", osName)
			}
			if got := strings.Contains(text, "BEGIN CERTIFICATE"); got != withCA {
				t.Errorf("%s script (ca=%v): certificate present = %v", osName, withCA, got)
			}
			if osName == "windows" {
				if name != "connect-gatte.ps1" || !strings.Contains(text, "\r\n") {
					t.Errorf("windows script %q is not a CRLF .ps1", name)
				}
				continue
			}
			if name != "connect-gatte.sh" {
				t.Errorf("%s script named %q", osName, name)
			}
			p := filepath.Join(t.TempDir(), name)
			os.WriteFile(p, []byte(text), 0o600)
			if out, err := exec.Command("sh", "-n", p).CombinedOutput(); err != nil {
				t.Errorf("%s script (ca=%v) is not valid sh: %v\n%s", osName, withCA, err, out)
			}
		}
	}
}

func TestConnectScripts_RefuseAnAudienceThatCouldBreakOutOfAQuote(t *testing.T) {
	e := newOpTestEnv(t)
	withConnect(t, e, false)
	for _, bad := range []string{"https://mcp.example.internal/mcp'; touch x; '", "http://mcp.example.internal/mcp", "https://mcp.example.internal/a b"} {
		e.cfg.OIDC.Audience = bad
		if _, err := admin.ConnectInfoOf(e.cfg, "", time.Now()); err == nil {
			t.Errorf("audience %q reached a script", bad)
		}
	}
	e.cfg.OIDC.Audience = "https://mcp.example.internal/mcp"
	if _, err := admin.ConnectInfoOf(e.cfg, "ana'; x", time.Now()); err == nil {
		t.Error("a username with a quote reached a script")
	}
}

func TestUI_TheScriptDownloadsAndIsRefusedWhenNotSetUp(t *testing.T) {
	e, s, cookie := newUITest(t)
	w := uiDo(s, "GET", "/people/connect/script?os=macos&u=ana.souza", nil, cookie, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("download without [connect]: %d, want 404", w.Code)
	}
	withConnect(t, e, false)
	w = uiDo(s, "GET", "/people/connect/script?os=macos&u=ana.souza", nil, cookie, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), `attachment; filename="connect-gatte.sh"`) {
		t.Fatalf("download: %d %q", w.Code, w.Header().Get("Content-Disposition"))
	}
	if !strings.Contains(w.Body.String(), "--client-id 'claude-code'") {
		t.Fatal("downloaded script lacks the client id")
	}
	if w := uiDo(s, "GET", "/people/connect/script?os=plan9", nil, cookie, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown system: %d, want 404", w.Code)
	}
	body := uiDo(s, "GET", "/people/connect?u=ana.souza", nil, cookie, nil).Body.String()
	for _, want := range []string{"Download connect-gatte.sh", "Download connect-gatte.ps1", "/mcp", "ana.souza"} {
		if !strings.Contains(body, want) {
			t.Errorf("connect page lacks %q", want)
		}
	}
}

func TestUI_AddPersonAssistantWalksToTheHandover(t *testing.T) {
	e, s, cookie, path := newPeopleTest(t, true)
	withConnect(t, e, false)
	step2 := uiDo(s, "GET", "/people/new/access?displayname=Jo%C3%A3o+da+Silva&email=joao%40example.org", nil, cookie, nil).Body.String()
	if !strings.Contains(step2, `value="joao.da.silva"`) || !strings.Contains(step2, "ir-lead") {
		t.Fatalf("step 2 lacks the suggested username or the role cards:\n%s", step2)
	}
	taken := uiDo(s, "GET", "/people/new/access?displayname=Ana&username=ana", nil, cookie, nil).Body.String()
	if !strings.Contains(taken, "already taken") {
		t.Fatal("step 2 accepted a username that exists")
	}
	step3 := uiDo(s, "GET", "/people/new/review?displayname=Jo%C3%A3o&username=joao&group=blue-ir", nil, cookie, nil).Body.String()
	if !strings.Contains(step3, "Create account") || !strings.Contains(step3, "ir-lead") {
		t.Fatalf("step 3 does not review the choice:\n%s", step3)
	}
	w := uiDo(s, "POST", "/people/add", url.Values{"displayname": {"João"}, "username": {"joao"}, "group": {"blue-ir"}, "csrf": {s.csrf}}, cookie, samePost)
	body := w.Body.String()
	for _, want := range []string{"is ready", "secret-value", "Download connect-gatte.sh", "sign in as <code>joao</code>"} {
		if !strings.Contains(body, want) {
			t.Errorf("handover page lacks %q", want)
		}
	}
	if file, _ := os.ReadFile(path); !strings.Contains(string(file), "joao:") {
		t.Fatal("the account was not created")
	}
	if w := uiDo(s, "GET", "/people/new", nil, cookie, nil); w.Code != http.StatusOK {
		t.Fatalf("step 1: %d", w.Code)
	}
}

func TestUI_TheAssistantDoesNotExistWithoutManageUsers(t *testing.T) {
	_, s, cookie, _ := newPeopleTest(t, false)
	for _, target := range []string{"/people/new", "/people/new/access?displayname=A", "/people/new/review?displayname=A"} {
		if w := uiDo(s, "GET", target, nil, cookie, nil); w.Code != http.StatusNotFound {
			t.Errorf("GET %s without -manage-users: %d, want 404", target, w.Code)
		}
	}
}

func TestSuggestUsername(t *testing.T) {
	for in, want := range map[string]string{"Ana Souza": "ana.souza", "João da Silva": "joao.da.silva", "  Bruno  ": "bruno", "Ç-ã": "c.a"} {
		if got := admin.SuggestUsername(in); got != want {
			t.Errorf("admin.SuggestUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

// The macOS/Linux script, run for real against a stand-in claude and curl
// in a throwaway HOME: it registers the gateway with the IdP's client, puts
// only the certificate on disk, edits the shell profile once, and running
// it again changes nothing more.
func TestConnectScript_RunsAndRunningItTwiceIsHarmless(t *testing.T) {
	e := newOpTestEnv(t)
	withConnect(t, e, true)
	info, _ := admin.ConnectInfoOf(e.cfg, "ana.souza", time.Now())
	text, _, _ := admin.RenderScript(info, "macos")
	dir := t.TempDir()
	home, bin := filepath.Join(dir, "home"), filepath.Join(dir, "bin")
	for _, d := range []string{home, bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("# mine\n"), 0o600)
	log := filepath.Join(dir, "claude.log")
	os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\necho \"$@\" >> '"+log+"'\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\nexit 7\n"), 0o755)
	script := filepath.Join(dir, "connect-gatte.sh")
	os.WriteFile(script, []byte(text), 0o600)
	for i := 0; i < 2; i++ {
		cmd := exec.Command("sh", script)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run %d failed: %v\n%s", i+1, err, out)
		}
		if !strings.Contains(string(out), "sign in as ana.souza") || !strings.Contains(string(out), "VPN") {
			t.Fatalf("run %d output:\n%s", i+1, out)
		}
	}
	calls, _ := os.ReadFile(log)
	add := "mcp add --transport http --scope user --client-id claude-code --callback-port 47823 gatte https://mcp.example.internal/mcp"
	if strings.Count(string(calls), add) != 2 || strings.Count(string(calls), "mcp remove gatte --scope user") != 2 {
		t.Fatalf("claude was called with:\n%s", calls)
	}
	rc, _ := os.ReadFile(filepath.Join(home, ".zshrc"))
	if !strings.HasPrefix(string(rc), "# mine\n") || strings.Count(string(rc), "NODE_EXTRA_CA_CERTS") != 1 {
		t.Fatalf(".zshrc after two runs:\n%s", rc)
	}
	ca, _ := os.ReadFile(filepath.Join(home, ".config", "gatte", "ca.pem"))
	if !strings.HasPrefix(string(ca), "-----BEGIN CERTIFICATE-----") || strings.Contains(string(ca), "GATTE_CA") || strings.Contains(string(ca), "touch") {
		t.Fatalf("ca.pem:\n%s", ca)
	}
}
