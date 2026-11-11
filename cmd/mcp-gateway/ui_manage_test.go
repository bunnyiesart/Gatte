//go:build !nofront

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/control"
	controlsqlite "github.com/bunnyiesart/Gatte/internal/control/sqlite"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// The console manages everything (design/adr/0050), through the real
// management backend, at the places the two-tab console puts them
// (design/adr/0051): registering an http API from its OpenAPI document, a
// server's page with sign, redial and remove, clearing a sensitive tool, the
// vault's secrets, the roles file and a reload. Every screen is absent with
// [admin] console_manages off, and root's are absent without -manage-users.

// uiSecretMarker is a vault value no page may ever carry.
const uiSecretMarker = "ui-secret-marker-5f1c-not-real"

// memVault is the accounts socket's vault for these tests: the service's
// rules over it are the real ones, the encryption is sops's and tested in
// admin_manage_test.go.
type memVault struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (v *memVault) Names(context.Context, *config.Config) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for n := range v.values {
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

func (v *memVault) Set(_ context.Context, _ *config.Config, name string, value []byte) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, existed := v.values[name]
	v.values[name] = slices.Clone(value)
	return existed, nil
}

func (v *memVault) Delete(_ context.Context, _ *config.Config, name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, existed := v.values[name]
	delete(v.values, name)
	return existed, nil
}

func (v *memVault) get(name string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return string(v.values[name])
}

// manageUI is a logged-in console over a backend with console_manages as
// given, the accounts socket opened when root is true, and that socket's
// root ports given by the test: a vault in memory, a signer that records
// what it signed, and a real roles file validated by the real load.
type manageUI struct {
	e         opTestEnv
	s         *uiHarness
	cookie    *http.Cookie
	vault     *memVault
	signed    []string
	rolesPath string
	cfgPath   string
}

const uiRolesText = "[[role]]\nname = \"ir\"\ntools = []\n[group_to_role]\n\"blue-ir\" = \"ir\"\n"

func newManageUI(t *testing.T, manages, root bool, opOpts ...func(*admin.Deps)) *manageUI {
	t.Helper()
	m := &manageUI{e: newOpTestEnv(t), vault: &memVault{values: map[string][]byte{}}}
	m.e.cfg.Admin.ConsoleManages = manages

	// A configuration file with roles_file, for the roles text's real
	// validation; the backends themselves read e.cfg.
	cfgPath := writeOperatorConfig(t, "\n[signer]\nrequire_signed = false\n")
	body, _ := os.ReadFile(cfgPath)
	if err := os.WriteFile(cfgPath, append([]byte("roles_file = \"roles.toml\"\n"), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	m.rolesPath = filepath.Join(filepath.Dir(cfgPath), "roles.toml")
	m.cfgPath = cfgPath
	if err := os.WriteFile(m.rolesPath, []byte(uiRolesText), 0o640); err != nil {
		t.Fatal(err)
	}
	m.e.cfg.RolesFile = m.rolesPath

	var mu sync.Mutex
	acc := func(d *admin.Deps) {
		d.Vault = m.vault
		d.Roles = rolesFile{}
		d.ValidateRoles = func(text []byte) error { return config.ValidateRolesText(cfgPath, text) }
		d.Sign = func(_ context.Context, _ *config.Config, name string) (admin.SignOutcome, error) {
			mu.Lock()
			defer mu.Unlock()
			if _, err := m.e.upstreams().Get(context.Background(), name); errors.Is(err, registry.ErrNotFound) {
				return admin.SignOutcome{}, errors.New("no such backend")
			}
			m.signed = append(m.signed, name)
			return admin.SignOutcome{KeyFingerprint: "ed25519:test-key", Trusted: true, Output: []string{"Signed " + name + "."}}, nil
		}
		d.DeclaredSecrets = func(ctx context.Context, _ *config.Config) (map[string][]string, error) {
			list, err := m.e.upstreams().List(ctx)
			if err != nil {
				return nil, err
			}
			out := map[string][]string{}
			for _, u := range list {
				for _, n := range u.EnvVarNames {
					out[n] = append(out[n], u.Name)
				}
			}
			return out, nil
		}
	}
	m.s = newUIFrontWith(t, m.e, root, opOpts, []func(*admin.Deps){acc})
	m.cookie = uiLogin(t, m.s)
	return m
}

func (m *manageUI) get(target string) *httpResult {
	w := uiDo(m.s, "GET", target, nil, m.cookie, nil)
	return &httpResult{code: w.Code, body: w.Body.String()}
}

func (m *manageUI) post(target string, form url.Values) *httpResult {
	form = maps.Clone(form)
	if form == nil {
		form = url.Values{}
	}
	if form.Get("csrf") == "" {
		form.Set("csrf", m.s.csrf)
	}
	w := uiDo(m.s, "POST", target, form, m.cookie, samePost)
	return &httpResult{code: w.Code, body: w.Body.String()}
}

// postMultipart sends the Add an API form as a browser does, with a file.
func (m *manageUI) postMultipart(t *testing.T, target string, fields map[string]string, fileName, file string) *httpResult {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if fileName != "" {
		fw, err := mw.CreateFormFile("openapi_file", fileName)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(fw, file)
	}
	_ = mw.Close()
	target = m.s.session + target
	r, err := http.NewRequest("POST", m.s.origin+target, &b)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "127.0.0.1:8090"
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://127.0.0.1:8090")
	r.AddCookie(m.cookie)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &httpResult{code: resp.StatusCode, body: string(body)}
}

type httpResult struct {
	code int
	body string
}

func (h *httpResult) has(s string) bool { return strings.Contains(h.body, s) }

// manageRoutes are every screen and action of design/adr/0050, at the place
// the two-tab console puts them (design/adr/0051), with a form that would act
// if it were forwarded.
var manageRoutes = []struct {
	method, target string
	form           url.Values
}{
	{"GET", "/servers/new", nil},
	{"POST", "/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "auth_kind": {"none"}}},
	{"POST", "/servers/ioc/sign", nil},
	{"POST", "/servers/ioc/redial", nil},
	{"POST", "/servers/ioc/remove", url.Values{"confirm": {"ioc"}}},
	{"POST", "/servers/reporting/tools/submit_report/clear", nil},
	{"POST", "/servers/reload", url.Values{}},
	{"GET", "/serve-requests?id=1", nil},
	{"POST", "/servers/ioc/secrets/set", url.Values{"name": {"X_KEY"}, "value": {uiSecretMarker}}},
	{"POST", "/servers/ioc/secrets/delete", url.Values{"name": {"X_KEY"}, "confirm": {"yes"}}},
	{"GET", "/vault", nil},
	{"POST", "/vault/set", url.Values{"name": {"X_KEY"}, "value": {uiSecretMarker}}},
	{"POST", "/vault/delete", url.Values{"name": {"X_KEY"}, "confirm": {"yes"}}},
	{"POST", "/users/roles/edit", url.Values{"role": {"ir"}, "tool": {"casemgmt.list_cases"}, "op": {"grant"}}},
	{"POST", "/users/roles/non-read", url.Values{"role": {"ir"}, "on": {"true"}}},
}

// rootRoutes are the manageRoutes that also need root's accounts socket.
var rootRoutes = []string{"/servers/ioc/sign", "/servers/ioc/secrets/set", "/servers/ioc/secrets/delete",
	"/vault", "/vault/set", "/vault/delete", "/users/roles/edit", "/users/roles/non-read"}

func (m *manageUI) do(method, target string, form url.Values) *httpResult {
	if method == "GET" {
		return m.get(target)
	}
	return m.post(target, form)
}

func TestUIManage_NothingNewExistsWithTheKeyOff(t *testing.T) {
	m := newManageUI(t, false, true)
	for _, rt := range manageRoutes {
		if got := m.do(rt.method, rt.target, rt.form); got.code != http.StatusNotFound {
			t.Errorf("%s %s with console_manages off: %d, want 404", rt.method, rt.target, got.code)
		}
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("a register went through with console_manages off")
	}
	if m.vault.get("X_KEY") != "" || len(m.signed) != 0 {
		t.Fatal("the vault or the signer was reached with console_manages off")
	}
	if b, _ := os.ReadFile(m.rolesPath); string(b) != uiRolesText {
		t.Fatal("the roles file was written with console_manages off")
	}
	body := m.get("/servers").body
	for _, a := range []string{"/servers/reload", "Reload configuration", "Add a REST API", "/servers/new"} {
		if strings.Contains(body, a) {
			t.Errorf("GET /servers with console_manages off shows %q", a)
		}
	}
}

func TestUIManage_RootScreensDoNotExistWithoutManageUsers(t *testing.T) {
	m := newManageUI(t, true, false)
	for _, rt := range manageRoutes {
		if !slices.Contains(rootRoutes, strings.Split(rt.target, "?")[0]) {
			continue
		}
		if got := m.do(rt.method, rt.target, rt.form); got.code != http.StatusNotFound {
			t.Errorf("%s %s without -manage-users: %d, want 404", rt.method, rt.target, got.code)
		}
	}
	page := m.get("/servers/new")
	if !page.has("Add a REST API") || !page.has("sudo mcp-gateway ui -manage-users") {
		t.Errorf("the add page lacks the form or the -manage-users explanation:\n%s", page.body)
	}
	if page.has(`name="key_value"`) || page.has(`name="grant_role"`) {
		t.Error("without -manage-users the add page offers the vault or the roles")
	}
	// A key's value sent anyway is refused before anything is registered.
	got := m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_value": {uiSecretMarker}})
	if got.has(uiSecretMarker) || !got.has("accounts socket") {
		t.Fatalf("a key value without -manage-users:\n%s", got.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("registered although the key's value could not be written")
	}
	// Registering without root works, and says how to attest.
	got = m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}})
	if got.code != http.StatusOK || !got.has("not attested yet") || !got.has("sudo mcp-gateway sign ioc") {
		t.Fatalf("register without -manage-users:\n%s", got.body)
	}
	detail := m.get("/servers/ioc")
	if detail.has("/servers/ioc/sign") || !detail.has("sudo mcp-gateway ui -manage-users") {
		t.Errorf("the server page offers to attest without -manage-users:\n%s", detail.body)
	}
}

func TestUIManage_RegisterWritesTheKeyAndShowsTheReport(t *testing.T) {
	m := newManageUI(t, true, true)
	if list := m.get("/servers"); !list.has(`href="` + m.s.session + `/servers/new"`) {
		t.Error("the servers list does not link the add page")
	}
	page := m.get("/servers/new")
	for _, want := range []string{"Add a REST API", `enctype="multipart/form-data"`, `type="password" name="key_value"`} {
		if !page.has(want) {
			t.Errorf("the add page lacks %q", want)
		}
	}
	got := m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}, "key_value": {uiSecretMarker}})
	if got.code != http.StatusOK {
		t.Fatalf("register: %d\n%s", got.code, got.body)
	}
	for _, want := range []string{"Registered as a REST API", "1 safe · 1 sensitive", "report", "Sensitive", "Safe", "derived from the document",
		"X-API-Key", "IOC_KEY", "not attested yet", "Attest ioc", "Attest this configuration", "nothing about the tools", m.s.session + "/servers/ioc"} {
		if !got.has(want) {
			t.Errorf("the register report lacks %q", want)
		}
	}
	if got.has(uiSecretMarker) {
		t.Fatal("the key's value is on the register result page")
	}
	if m.vault.get("IOC_KEY") != uiSecretMarker {
		t.Fatal("the key's value was not written to the vault")
	}
	// Registering does not sign: the signature is the operator's act on
	// the page that shows what it covers.
	if len(m.signed) != 0 {
		t.Fatalf("registering signed %v", m.signed)
	}
	if sg := m.post("/servers/ioc/sign", nil); !sg.has("Configuration attested with a trusted key") || !slices.Equal(m.signed, []string{"ioc"}) {
		t.Fatalf("signing from the report: %v\n%s", m.signed, sg.body)
	}
	entry, err := m.e.upstreams().Get(context.Background(), "ioc")
	if err != nil || entry.Transport != registry.TransportHTTP || !slices.Equal(entry.EnvVarNames, []string{"IOC_KEY"}) {
		t.Fatalf("registry entry = %+v, %v", entry, err)
	}

	// A second register is the backend's refusal, with what was typed kept.
	again := m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_value": {uiSecretMarker}})
	if !again.has("already registered") || !again.has(`value="https://ioc.example.net"`) || again.has(uiSecretMarker) {
		t.Fatalf("a second register:\n%s", again.body)
	}
	// NAME=value pasted as the key's name: refused, and not written back.
	pasted := m.post("/servers", url.Values{"name": {"ioc3"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY=" + uiSecretMarker}})
	if !pasted.has("Not registered") || pasted.has(uiSecretMarker) {
		t.Fatalf("a NAME=value key name:\n%s", pasted.body)
	}
	// A key-name default for a keyed API.
	m.post("/servers", url.Values{"name": {"vt-intel"}, "url": {"https://vt.example.net"}, "openapi_text": {restSpecJSON}, "auth_kind": {"bearer"}})
	if e, err := m.e.upstreams().Get(context.Background(), "vt-intel"); err != nil || !slices.Equal(e.EnvVarNames, []string{"VT_INTEL_API_KEY"}) {
		t.Fatalf("default key name: %+v, %v", e, err)
	}
}

func TestUIManage_UploadingTheDocumentWorksAndStillNeedsTheFormToken(t *testing.T) {
	m := newManageUI(t, true, false)
	fields := map[string]string{"name": "ioc", "url": "https://ioc.example.net", "auth_kind": "none"}
	if got := m.postMultipart(t, "/servers", fields, "openapi.json", restSpecJSON); got.code != http.StatusForbidden {
		t.Fatalf("a multipart register without the form token: %d", got.code)
	}
	// Swap the first character for a different one: a fixed "0" equals the
	// real token whenever that token happens to start with "0".
	wrong := "0"
	if m.s.csrf[0] == '0' {
		wrong = "1"
	}
	fields["csrf"] = wrong + m.s.csrf[1:]
	if got := m.postMultipart(t, "/servers", fields, "openapi.json", restSpecJSON); got.code != http.StatusForbidden {
		t.Fatalf("a multipart register with a wrong form token: %d", got.code)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("a multipart POST without the form token registered")
	}
	fields["csrf"] = m.s.csrf
	got := m.postMultipart(t, "/servers", fields, "openapi.json", restSpecJSON)
	if got.code != http.StatusOK || !got.has("Registered as a REST API") || !got.has("report") {
		t.Fatalf("a multipart register with the file: %d\n%s", got.code, got.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); err != nil {
		t.Fatalf("not registered from the file: %v", err)
	}
	// Two ways at once is refused before the backend is asked.
	fields["name"], fields["openapi_text"] = "ioc2", restSpecJSON
	if got := m.postMultipart(t, "/servers", fields, "openapi.json", restSpecJSON); !got.has("one way") {
		t.Fatalf("a file and pasted text together:\n%s", got.body)
	}
}

func TestUIManage_TheServerPageSignsRedialsAndRemovesOnlyWithTheNameTyped(t *testing.T) {
	m := newManageUI(t, true, true)
	if got := m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "auth_kind": {"none"}}); got.code != http.StatusOK {
		t.Fatalf("register: %d\n%s", got.code, got.body)
	}
	if got := m.get("/servers/nope"); got.code != http.StatusNotFound {
		t.Fatalf("the page of an unknown backend: %d", got.code)
	}
	page := m.get("/servers/ioc")
	// The attestation state names the configuration, and the tools panel
	// is the separate tool-safety gate (ADR-0060).
	for _, want := range []string{"ioc", "REST API", "https://ioc.example.net/api/v2", "POST", "/report", "Sensitive", "Safe", "Remove this backend", `name="confirm"`, "/servers/ioc/sign",
		"Config not attested", "It is not served until a configuration is attested", "Attest this configuration",
		"Tool safety", "Attesting the configuration does not approve any tool"} {
		if !page.has(want) {
			t.Errorf("the server page lacks %q", want)
		}
	}
	if list := m.get("/servers"); !list.has("Config not attested") || list.has("Not signed") {
		t.Errorf("the servers list does not show the attestation state:\n%s", list.body)
	}
	if sign := m.post("/servers/ioc/sign", nil); !sign.has("Configuration attested with a trusted key") || !sign.has("ed25519:test-key") {
		t.Fatalf("sign:\n%s", sign.body)
	}

	// Redial with no gateway process: the backend's refusal.
	if !page.has("/servers/ioc/redial") {
		t.Error("the server page offers no redial")
	}
	if got := m.post("/servers/ioc/redial", nil); !got.has("result-icon danger") {
		t.Fatalf("a redial with nothing to ring:\n%s", got.body)
	}

	for _, confirm := range []string{"", "IOC", "io"} {
		got := m.post("/servers/ioc/remove", url.Values{"confirm": {confirm}})
		if !got.has("confirm must repeat") {
			t.Errorf("remove with confirm %q:\n%s", confirm, got.body)
		}
		if _, err := m.e.upstreams().Get(context.Background(), "ioc"); err != nil {
			t.Fatalf("removed with confirm %q", confirm)
		}
	}
	if got := m.post("/servers/ioc/remove", url.Values{"confirm": {"ioc"}}); !got.has("Deregistered") {
		t.Fatalf("remove:\n%s", got.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("still registered after remove")
	}
}

func TestUIManage_ReloadAndRedialShowAPendingRequestWithARefresh(t *testing.T) {
	ring := func(d *admin.Deps) {
		d.Ring = func(control.Process) error { return nil }
		d.ServeWait = 100 * time.Millisecond
	}
	m := newManageUI(t, true, true, ring)
	if err := controlsqlite.Migrate(m.e.db); err != nil {
		t.Fatal(err)
	}
	if !m.get("/servers").has("Reload configuration") {
		t.Fatal("the servers list lacks the reload button")
	}
	// No gateway process recorded: refused, said so.
	if got := m.post("/servers/reload", url.Values{}); !got.has("no gateway process") {
		t.Fatalf("reload with no serve:\n%s", got.body)
	}
	if err := controlsqlite.New(m.e.db).RecordProcess(context.Background(), control.Process{PID: 1 << 22, Boot: time.Now(), StartToken: "x"}); err != nil {
		t.Fatal(err)
	}
	got := m.post("/servers/reload", url.Values{})
	if !got.has("is pending") || !got.has(m.s.session+"/serve-requests?id=") {
		t.Fatalf("a pending reload:\n%s", got.body)
	}
	i := strings.Index(got.body, "/serve-requests?id=")
	id := got.body[i+len("/serve-requests?id="):]
	id = id[:strings.IndexByte(id, '"')]
	again := m.get("/serve-requests?id=" + id)
	if again.code != http.StatusOK || !again.has("is pending") || !again.has(`href="`+m.s.session+`/servers"`) {
		t.Fatalf("refreshing request %s: %d\n%s", id, again.code, again.body)
	}
	if m.get("/serve-requests?id=x").code != http.StatusNotFound {
		t.Fatal("a request id that is not a number was looked up")
	}
}

func TestUIManage_ASensitiveToolIsClearedFromItsPage(t *testing.T) {
	m := newManageUI(t, true, false)
	mustObserveSensitive(t, m.e, "reporting", submitReport)
	mustApprove(t, m.e, "reporting", "submit_report")
	page := m.get("/servers/reporting/tools/submit_report")
	if !page.has("Sensitive") || !page.has("Not cleared") || !page.has("/servers/reporting/tools/submit_report/clear") || page.has("Approve this version") {
		t.Fatalf("the tool page of an approved, uncleared sensitive tool:\n%s", page.body)
	}
	// No role reaches it: the backend refuses, and says why.
	got := m.post("/servers/reporting/tools/submit_report/clear", nil)
	if !got.has("result-icon danger") || !got.has("non_read") {
		t.Fatalf("clear with no role reaching it:\n%s", got.body)
	}
	m.e.cfg.Roles = []config.Role{{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true}}
	got = m.post("/servers/reporting/tools/submit_report/clear", nil)
	if !got.has("result-icon ok") || !got.has("ir-act") {
		t.Fatalf("clear:\n%s", got.body)
	}
	if after, _ := m.e.tools().Get(context.Background(), "reporting", "submit_report"); !after.Usable() {
		t.Fatal("cleared and still not usable")
	}
	if page := m.get("/servers/reporting/tools/submit_report"); !page.has("Cleared") || page.has("/servers/reporting/tools/submit_report/clear") {
		t.Fatalf("the tool page after clearing:\n%s", page.body)
	}
}

// The vault is written from the server's own Secrets panel and from the global
// vault view (design/adr/0053), and no response ever carries a value.
func TestUIManage_SecretsAreSetAndDeletedAndTheValueNeverShows(t *testing.T) {
	m := newManageUI(t, true, true)
	if got := m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}}); got.code != http.StatusOK {
		t.Fatalf("register: %d", got.code)
	}
	var bodies []string
	keep := func(h *httpResult) *httpResult { bodies = append(bodies, h.body); return h }

	page := keep(m.get("/servers/ioc"))
	if !page.has("IOC_KEY") || !page.has("Missing from the vault") || !page.has(`type="password"`) || !page.has(m.s.session+"/servers/ioc/secrets/set") {
		t.Fatalf("the server's Secrets panel before the key is set:\n%s", page.body)
	}
	if got := keep(m.post("/servers/ioc/secrets/set", url.Values{"name": {"IOC_KEY"}, "value": {uiSecretMarker}})); !got.has("result-icon ok") || !got.has("IOC_KEY") {
		t.Fatalf("set:\n%s", got.body)
	}
	if m.vault.get("IOC_KEY") != uiSecretMarker {
		t.Fatal("the value was not written")
	}
	keep(m.post("/servers/ioc/secrets/set", url.Values{"name": {"IOC_KEY"}, "value": {uiSecretMarker + "-2"}}))
	keep(m.post("/vault/set", url.Values{"name": {"bad name"}, "value": {uiSecretMarker}}))
	keep(m.post("/vault/set", url.Values{"name": {"X=" + uiSecretMarker}, "value": {uiSecretMarker}}))
	if page := keep(m.get("/servers/ioc")); !page.has("Replace") || page.has("Missing from the vault") {
		t.Fatalf("the Secrets panel after set:\n%s", page.body)
	}
	if got := keep(m.post("/vault/set", url.Values{"name": {"SHARED_KEY"}, "value": {uiSecretMarker}})); !got.has("result-icon ok") || m.vault.get("SHARED_KEY") == "" {
		t.Fatalf("set from the vault view:\n%s", got.body)
	}
	if v := keep(m.get("/vault")); !v.has("SHARED_KEY") || !v.has("Orphan") {
		t.Fatalf("the vault view:\n%s", v.body)
	}
	if got := keep(m.post("/servers/ioc/secrets/delete", url.Values{"name": {"IOC_KEY"}})); !got.has("tick the confirmation") || m.vault.get("IOC_KEY") == "" {
		t.Fatalf("delete without the confirmation:\n%s", got.body)
	}
	if got := keep(m.post("/servers/ioc/secrets/delete", url.Values{"name": {"IOC_KEY"}, "confirm": {"yes"}})); !got.has("result-icon ok") || m.vault.get("IOC_KEY") != "" {
		t.Fatalf("delete:\n%s", got.body)
	}
	if got := keep(m.post("/vault/delete", url.Values{"name": {"SHARED_KEY"}, "confirm": {"yes"}})); !got.has("result-icon ok") || m.vault.get("SHARED_KEY") != "" {
		t.Fatalf("delete from the vault view:\n%s", got.body)
	}
	for _, p := range []string{"/servers", "/servers/ioc", "/vault", "/users"} {
		keep(m.get(p))
	}
	for i, b := range bodies {
		if strings.Contains(b, uiSecretMarker) {
			t.Errorf("response %d carries the secret's value", i)
		}
	}
	recs, _ := m.e.auditTrail().List(context.Background())
	for _, r := range recs {
		if strings.Contains(r.Reason, uiSecretMarker) {
			t.Fatal("the value reached the audit trail")
		}
	}
}

// The Users tab's Roles section edits the roles file in place (design/adr/0054):
// a grant is one surgical change validated before it is written, the file's
// comments survive, and a role that does not exist changes nothing.
func TestUIManage_TheRolesSectionGrantsOneToolAndKeepsTheFile(t *testing.T) {
	m := newManageUI(t, true, true)
	mustObserve(t, m.e, "casemgmt", quarantine.ToolIdentity{Name: "list_cases", Description: "d", InputSchema: []byte(`{}`)})
	// The matrix's rows are the roles the running configuration holds; the
	// edits are to the file.
	m.e.cfg.Roles = []config.Role{{Name: "ir"}}
	text := "# reviewed by the SOC lead\n" + uiRolesText
	if err := os.WriteFile(m.rolesPath, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if page := m.get("/users"); !page.has(m.s.session+"/users/roles/edit") || !page.has("ir") {
		t.Fatalf("the Users tab has no editable Roles section:\n%s", page.body)
	}
	got := m.post("/users/roles/edit", url.Values{"role": {"ir"}, "tool": {"casemgmt.list_cases"}, "op": {"grant"}})
	if !got.has("result-icon ok") || !got.has("NOT applied yet") {
		t.Fatalf("grant:\n%s", got.body)
	}
	b, _ := os.ReadFile(m.rolesPath)
	if !strings.HasPrefix(string(b), "# reviewed by the SOC lead\n") || !strings.Contains(string(b), "list_cases") {
		t.Fatalf("the roles file after the grant:\n%s", b)
	}
	if err := config.ValidateRolesText(m.cfgPath, b); err != nil {
		t.Fatalf("the granted roles text does not load: %v", err)
	}
	if again := m.post("/users/roles/edit", url.Values{"role": {"ir"}, "tool": {"casemgmt.list_cases"}, "op": {"grant"}}); !again.has("No change") {
		t.Fatalf("the same grant again:\n%s", again.body)
	}
	before, _ := os.ReadFile(m.rolesPath)
	if got := m.post("/users/roles/edit", url.Values{"role": {"nobody"}, "tool": {"casemgmt.list_cases"}, "op": {"grant"}}); !got.has("no [[role]] named nobody") {
		t.Fatalf("an unknown role:\n%s", got.body)
	}
	if after, _ := os.ReadFile(m.rolesPath); string(after) != string(before) {
		t.Fatal("an unknown role changed the roles file")
	}
}

// TestUIManage_RegisterGrantsTheAPIToTheRoleNamed: the Add API form grants
// the new API's safe tools to a role, as `gatte api add` does, through the
// validated roles write; a role that does not exist grants nothing and says
// so, and a grant already present is not written twice.
func TestUIManage_RegisterGrantsTheAPIToTheRoleNamed(t *testing.T) {
	m := newManageUI(t, true, true)
	if page := m.get("/servers/new"); !page.has(`name="grant_role"`) || !page.has(`value="analyst"`) {
		t.Fatal("the Add API form has no grant field defaulting to analyst")
	}
	got := m.post("/servers", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}, "grant_role": {"ir"}})
	// No serve process in this harness: the grant is written and the page
	// says the reload did not apply it (applied end to end in the image).
	if !got.has("Granted to ir in the roles file") {
		t.Fatalf("the register report lacks the grant:\n%s", got.body)
	}
	b, _ := os.ReadFile(m.rolesPath)
	if !strings.Contains(string(b), "[role.grants]\n\"ioc\" = [\"*\"]") {
		t.Fatalf("the roles file does not grant ioc:\n%s", b)
	}
	if err := config.ValidateRolesText(m.cfgPath, b); err != nil {
		t.Fatalf("the granted roles text does not load: %v", err)
	}

	// A second API into the same, now existing, [role.grants].
	m.post("/servers", url.Values{"name": {"vt"}, "url": {"https://vt.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"VT_KEY"}, "grant_role": {"ir"}})
	b, _ = os.ReadFile(m.rolesPath)
	if strings.Count(string(b), "[role.grants]") != 1 || !strings.Contains(string(b), "\"vt\" = [\"*\"]") {
		t.Fatalf("the second grant:\n%s", b)
	}

	// No such role: nothing written, and the page says so.
	before, _ := os.ReadFile(m.rolesPath)
	got = m.post("/servers", url.Values{"name": {"gn"}, "url": {"https://gn.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"GN_KEY"}, "grant_role": {"nobody"}})
	if !got.has("no [[role]] named nobody") {
		t.Fatalf("an unknown role:\n%s", got.body)
	}
	if after, _ := os.ReadFile(m.rolesPath); string(after) != string(before) {
		t.Fatal("an unknown role changed the roles file")
	}
}

// podmanAs makes the operator socket's backend see podman, or not, whatever
// this machine has.
func podmanAs(err error) func(*admin.Deps) {
	return func(d *admin.Deps) { d.OCIRuntime = func() error { return err } }
}

// Without podman (the Docker image) the Container form is not offered, and a
// forced register says why instead of registering (design/adr/0059 §3).
func TestUIManage_WithoutPodmanTheContainerFormIsNotOffered(t *testing.T) {
	m := newManageUI(t, true, true, podmanAs(podmanOnPath(func(string) (string, error) { return "", exec.ErrNotFound })))
	page := m.get("/servers/new")
	if page.has("Container (oci)</a>") || page.has(`name="image"`) {
		t.Fatalf("the add page offers a container without podman:\n%s", page.body)
	}
	asked := m.get("/servers/new?kind=oci")
	if asked.code != http.StatusOK || asked.has(`name="image"`) || !asked.has("need podman on the gateway") || !asked.has("Add a REST API") {
		t.Fatalf("?kind=oci without podman:\n%s", asked.body)
	}
	forced := m.post("/servers", url.Values{"transport": {"oci"}, "name": {"intel"}, "image": {ociTestImage}})
	if !forced.has("Not registered") || !forced.has("podman is not on PATH") {
		t.Fatalf("a forced oci register without podman:\n%s", forced.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "intel"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("an oci entry was registered without podman")
	}
}

// With podman the Container form registers the CLI's entry and does not
// sign it: the result page shows what the signature will cover.
func TestUIManage_TheContainerFormRegistersAndDoesNotSign(t *testing.T) {
	m := newManageUI(t, true, true, podmanAs(nil))
	if page := m.get("/servers/new"); !page.has(`href="` + m.s.session + `/servers/new?kind=oci"`) {
		t.Fatalf("the add page does not offer the container form:\n%s", page.body)
	}
	form := m.get("/servers/new?kind=oci")
	for _, want := range []string{"Add a container (oci)", `name="transport" value="oci"`, `name="image"`, `name="network"`, `value="none"`, `name="env_var_names"`} {
		if !form.has(want) {
			t.Errorf("the container form lacks %q", want)
		}
	}
	if form.has(`name="openapi_url"`) {
		t.Error("the container form carries the REST fields")
	}

	got := m.post("/servers", url.Values{"transport": {"oci"}, "name": {"intel"}, "image": {ociTestImage},
		"network": {"slirp4netns"}, "env_var_names": {"INTEL_KEY, OTHER_KEY"}})
	if got.code != http.StatusOK {
		t.Fatalf("register: %d\n%s", got.code, got.body)
	}
	for _, want := range []string{"Registered as a container (oci)", ociTestImage, "slirp4netns", "INTEL_KEY", "OTHER_KEY", "not attested yet", "Attest intel", "Attest this configuration", "the image digest, the network and the variable names"} {
		if !got.has(want) {
			t.Errorf("the register result lacks %q", want)
		}
	}
	if len(m.signed) != 0 {
		t.Fatalf("registering signed %v", m.signed)
	}
	entry, err := m.e.upstreams().Get(context.Background(), "intel")
	if err != nil || entry.Transport != registry.TransportOCI || entry.Image != ociTestImage ||
		!slices.Equal(entry.Args, []string{"--network=slirp4netns"}) || !slices.Equal(entry.EnvVarNames, []string{"INTEL_KEY", "OTHER_KEY"}) {
		t.Fatalf("registry entry = %+v, %v", entry, err)
	}

	// The default network is none by omission, as the CLI writes it.
	m.post("/servers", url.Values{"transport": {"oci"}, "name": {"quiet"}, "image": {ociTestImage}, "network": {"none"}})
	if e, err := m.e.upstreams().Get(context.Background(), "quiet"); err != nil || len(e.Args) != 0 || len(e.EnvVarNames) != 0 {
		t.Fatalf("default network entry = %+v, %v", e, err)
	}

	// A tag is the backend's refusal, with the form kept as typed.
	tag := m.post("/servers", url.Values{"transport": {"oci"}, "name": {"tagged"}, "image": {"localhost/casemgmt-mcp:latest"}})
	if !tag.has("Not registered") || !tag.has(`value="localhost/casemgmt-mcp:latest"`) || !tag.has(`name="image"`) {
		t.Fatalf("a tagged image:\n%s", tag.body)
	}
	// NAME=value pasted as a variable name: refused, and not written back.
	pasted := m.post("/servers", url.Values{"transport": {"oci"}, "name": {"pasted"}, "image": {ociTestImage}, "env_var_names": {"KEY=" + uiSecretMarker}})
	if !pasted.has("Not registered") || pasted.has(uiSecretMarker) {
		t.Fatalf("a NAME=value variable name:\n%s", pasted.body)
	}
}

// The add page is a three-way choice (design/adr/0059 §1): REST API and
// Remote MCP server always, Container only with podman; stdio never.
func TestUIManage_TheAddPageOffersThreeWays(t *testing.T) {
	m := newManageUI(t, true, true, podmanAs(nil))
	page := m.get("/servers/new")
	for _, want := range []string{`href="` + m.s.session + `/servers/new"`, `href="` + m.s.session + `/servers/new?kind=remote"`,
		`href="` + m.s.session + `/servers/new?kind=oci"`, "A stdio backend is not added here"} {
		if !page.has(want) {
			t.Errorf("the add page lacks %q", want)
		}
	}
	for _, gone := range []string{"waits unsigned", "Sign button", `value="stdio"`} {
		if page.has(gone) {
			t.Errorf("the add page still says %q", gone)
		}
	}
	without := newManageUI(t, true, true, podmanAs(errors.New("podman is not on PATH")))
	if p := without.get("/servers/new"); !p.has("?kind=remote") || p.has("?kind=oci") {
		t.Fatalf("without podman, the choice is not REST and Remote only:\n%s", p.body)
	}
}

// The Remote MCP server form registers the CLI's entry and does not sign
// it: the result page shows what the signature will cover.
func TestUIManage_TheRemoteFormRegistersAndDoesNotSign(t *testing.T) {
	m := newManageUI(t, true, true)
	form := m.get("/servers/new?kind=remote")
	for _, want := range []string{"Add a remote MCP server", `name="transport" value="remote"`, `name="url"`, `name="auth_kind"`,
		`name="auth_name"`, `name="key_name"`, `name="remote_kind"`, `value="streamable"`} {
		if !form.has(want) {
			t.Errorf("the remote form lacks %q", want)
		}
	}
	for _, gone := range []string{`name="openapi_url"`, `name="image"`, `value="query"`} {
		if form.has(gone) {
			t.Errorf("the remote form carries %q", gone)
		}
	}

	got := m.post("/servers", url.Values{"transport": {"remote"}, "name": {"vendor"}, "url": {"https://mcp.vendor.example/mcp"},
		"remote_kind": {"streamable"}, "auth_kind": {"header"}, "auth_name": {"X-Api-Key"}, "key_name": {"VENDOR_TOKEN"}})
	if got.code != http.StatusOK {
		t.Fatalf("register: %d\n%s", got.code, got.body)
	}
	for _, want := range []string{"Registered as a remote MCP server", "https://mcp.vendor.example/mcp", "streamable", "X-Api-Key", "VENDOR_TOKEN",
		"not attested yet", "Attest vendor", "Attest this configuration", "the URL, the auth and its secret name, and the transport"} {
		if !got.has(want) {
			t.Errorf("the register result lacks %q", want)
		}
	}
	if len(m.signed) != 0 {
		t.Fatalf("registering signed %v", m.signed)
	}
	entry, err := m.e.upstreams().Get(context.Background(), "vendor")
	if err != nil || entry.Transport != registry.TransportRemote || entry.URL != "https://mcp.vendor.example/mcp" || entry.RemoteKind != registry.RemoteStreamable ||
		entry.AuthKind != registry.AuthHeader || entry.AuthName != "X-Api-Key" || !slices.Equal(entry.EnvVarNames, []string{"VENDOR_TOKEN"}) {
		t.Fatalf("registry entry = %+v, %v", entry, err)
	}

	// A keyed server with no key name gets NAME_API_KEY, as a REST API does.
	m.post("/servers", url.Values{"transport": {"remote"}, "name": {"bear"}, "url": {"https://mcp.bear.example/mcp"}, "auth_kind": {"bearer"}})
	if e, err := m.e.upstreams().Get(context.Background(), "bear"); err != nil || e.AuthKind != registry.AuthBearer || !slices.Equal(e.EnvVarNames, []string{"BEAR_API_KEY"}) {
		t.Fatalf("default key name entry = %+v, %v", e, err)
	}

	// A credential in the URL is the backend's refusal, with the form kept.
	cred := m.post("/servers", url.Values{"transport": {"remote"}, "name": {"leaky"}, "url": {"https://u:" + uiSecretMarker + "@mcp.leaky.example/mcp"}, "auth_kind": {"none"}})
	if !cred.has("Not registered") || !cred.has("userinfo") || !cred.has(`name="transport" value="remote"`) ||
		!cred.has(`value="https://mcp.leaky.example/mcp"`) || cred.has(uiSecretMarker) {
		t.Fatalf("a credential in the URL:\n%s", cred.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "leaky"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("a refused remote register left an entry")
	}
	// NAME=value pasted as the key's name: refused, and not written back.
	pasted := m.post("/servers", url.Values{"transport": {"remote"}, "name": {"pasted"}, "url": {"https://mcp.p.example/mcp"},
		"auth_kind": {"bearer"}, "key_name": {"KEY=" + uiSecretMarker}})
	if !pasted.has("Not registered") || pasted.has(uiSecretMarker) {
		t.Fatalf("a NAME=value key name:\n%s", pasted.body)
	}

	// A credential anywhere a vendor's key is pasted is refused, and neither
	// the refusal nor the redrawn form repeats it: userinfo beside another
	// fault the URL check could fire first on, a URL that does not parse, a
	// query, a fragment, and a header line as the header's name.
	for _, c := range []struct{ what, url, authKind, authName string }{
		{"userinfo and a bad scheme", "ftp://u:" + uiSecretMarker + "@mcp.leaky.example/", "none", ""},
		{"userinfo and no host", "http://u:" + uiSecretMarker + "@/mcp", "none", ""},
		{"userinfo and a bad port", "https://u:" + uiSecretMarker + "@mcp.leaky.example:bad/", "none", ""},
		{"a query", "https://mcp.leaky.example/mcp?api_key=" + uiSecretMarker, "none", ""},
		{"a fragment", "https://mcp.leaky.example/mcp#" + uiSecretMarker, "none", ""},
		{"a header line", "https://mcp.leaky.example/mcp", "header", "Authorization: Bearer " + uiSecretMarker},
	} {
		got := m.post("/servers", url.Values{"transport": {"remote"}, "name": {"leaky"}, "url": {c.url}, "remote_kind": {"streamable"},
			"auth_kind": {c.authKind}, "auth_name": {c.authName}})
		if !got.has("Not registered") || got.has(uiSecretMarker) || !got.has(`name="transport" value="remote"`) {
			t.Errorf("%s:\n%s", c.what, got.body)
		}
		if _, err := m.e.upstreams().Get(context.Background(), "leaky"); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("%s: a refused remote register left an entry", c.what)
		}
	}
}
