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
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// The console manages everything (design/adr/0050), through the real
// management backend: registering an http API from its OpenAPI document,
// a backend's page, sign, redial and remove, clearing a sensitive tool,
// the vault's secrets, the roles file and a reload. Every screen is absent
// with [admin] console_manages off, and root's are absent without
// -manage-users.

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

// manageRoutes are every screen and action of design/adr/0050, with a form
// that would act if it were forwarded.
var manageRoutes = []struct {
	method, target string
	form           url.Values
}{
	{"GET", "/upstreams/show?name=ioc", nil},
	{"POST", "/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "auth_kind": {"none"}}},
	{"POST", "/upstreams/sign", url.Values{"name": {"ioc"}}},
	{"POST", "/upstreams/redial", url.Values{"name": {"ioc"}}},
	{"POST", "/upstreams/remove", url.Values{"name": {"ioc"}, "confirm": {"ioc"}}},
	{"POST", "/tools/clear", url.Values{"server": {"reporting"}, "tool": {"submit_report"}}},
	{"POST", "/reload", url.Values{}},
	{"GET", "/serve-requests?id=1", nil},
	{"GET", "/secrets", nil},
	{"POST", "/secrets/set", url.Values{"name": {"X_KEY"}, "value": {uiSecretMarker}}},
	{"POST", "/secrets/delete", url.Values{"name": {"X_KEY"}, "confirm": {"yes"}}},
	{"GET", "/roles", nil},
	{"POST", "/roles", url.Values{"text": {uiRolesText}}},
}

func TestUIManage_NothingNewExistsWithTheKeyOff(t *testing.T) {
	m := newManageUI(t, false, true)
	for _, rt := range manageRoutes {
		var got *httpResult
		if rt.method == "GET" {
			got = m.get(rt.target)
		} else {
			got = m.post(rt.target, rt.form)
		}
		if got.code != http.StatusNotFound {
			t.Errorf("%s %s with console_manages off: %d, want 404", rt.method, rt.target, got.code)
		}
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("a register went through with console_manages off")
	}
	if m.vault.get("X_KEY") != "" || len(m.signed) != 0 {
		t.Fatal("the vault or the signer was reached with console_manages off")
	}
	for page, absent := range map[string][]string{
		"/":          {"/reload", "Reload configuration"},
		"/upstreams": {"Add an API", "/upstreams/register", "/upstreams/show"},
	} {
		body := m.get(page).body
		for _, a := range absent {
			if strings.Contains(body, a) {
				t.Errorf("GET %s with console_manages off shows %q", page, a)
			}
		}
		for _, nav := range []string{`href="` + m.s.session + `/secrets"`, `href="` + m.s.session + `/roles"`} {
			if strings.Contains(body, nav) {
				t.Errorf("GET %s with console_manages off has the navigation entry %s", page, nav)
			}
		}
	}
}

func TestUIManage_RootScreensDoNotExistWithoutManageUsers(t *testing.T) {
	m := newManageUI(t, true, false)
	for _, rt := range manageRoutes {
		switch rt.target {
		case "/upstreams/sign", "/secrets", "/secrets/set", "/secrets/delete", "/roles":
		default:
			continue
		}
		var got *httpResult
		if rt.method == "GET" {
			got = m.get(rt.target)
		} else {
			got = m.post(rt.target, rt.form)
		}
		if got.code != http.StatusNotFound {
			t.Errorf("%s %s without -manage-users: %d, want 404", rt.method, rt.target, got.code)
		}
	}
	page := m.get("/upstreams")
	if !page.has("Add an API") || !page.has("sudo mcp-gateway ui -manage-users") {
		t.Errorf("the Backends page lacks the form or the -manage-users explanation:\n%s", page.body)
	}
	if page.has(`name="key_value"`) || page.has(`/secrets"`) || page.has(`/roles"`) {
		t.Error("without -manage-users the page offers the vault or the roles")
	}
	// A key's value sent anyway is refused before anything is registered.
	got := m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_value": {uiSecretMarker}})
	if got.has(uiSecretMarker) || !got.has("accounts socket") {
		t.Fatalf("a key value without -manage-users:\n%s", got.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("registered although the key's value could not be written")
	}
	// Registering without root works, and says how to sign.
	got = m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}})
	if got.code != http.StatusOK || !got.has("Not signed") || !got.has("sudo mcp-gateway sign ioc") {
		t.Fatalf("register without -manage-users:\n%s", got.body)
	}
	detail := m.get("/upstreams/show?name=ioc")
	if detail.has("/upstreams/sign") || !detail.has("sudo mcp-gateway ui -manage-users") {
		t.Errorf("the backend page offers Sign without -manage-users:\n%s", detail.body)
	}
}

func TestUIManage_RegisterWritesTheKeySignsAndShowsTheReport(t *testing.T) {
	m := newManageUI(t, true, true)
	page := m.get("/upstreams")
	for _, want := range []string{"Add an API", `enctype="multipart/form-data"`, `type="password" name="key_value"`, `href="` + m.s.session + `/secrets"`, `href="` + m.s.session + `/roles"`} {
		if !page.has(want) {
			t.Errorf("the Backends page lacks %q", want)
		}
	}
	got := m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}, "key_value": {uiSecretMarker}})
	if got.code != http.StatusOK {
		t.Fatalf("register: %d\n%s", got.code, got.body)
	}
	for _, want := range []string{"Registered ioc", "1 safe, 1 sensitive", "report", "Sensitive", "Safe", "Derived from the document",
		"X-API-Key", "IOC_KEY", "Not signed yet", "Sign ioc", "Review the tools", "/tools/review-set?server=ioc", "Clear the sensitive ones", "upload"} {
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
	// the page that shows what it covers (found in review).
	if len(m.signed) != 0 {
		t.Fatalf("registering signed %v", m.signed)
	}
	if sg := m.post("/upstreams/sign", url.Values{"name": {"ioc"}}); !sg.has("Signed with a trusted key") || !slices.Equal(m.signed, []string{"ioc"}) {
		t.Fatalf("signing from the report: %v\n%s", m.signed, sg.body)
	}
	entry, err := m.e.upstreams().Get(context.Background(), "ioc")
	if err != nil || entry.Transport != registry.TransportHTTP || !slices.Equal(entry.EnvVarNames, []string{"IOC_KEY"}) {
		t.Fatalf("registry entry = %+v, %v", entry, err)
	}

	// A second register is the backend's refusal, with what was typed kept.
	again := m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_value": {uiSecretMarker}})
	if !again.has("already registered") || !again.has(`value="https://ioc.example.net"`) || again.has(uiSecretMarker) {
		t.Fatalf("a second register:\n%s", again.body)
	}
	// NAME=value pasted as the key's name: refused, and not written back.
	pasted := m.post("/upstreams/register", url.Values{"name": {"ioc3"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY=" + uiSecretMarker}})
	if !pasted.has("Not registered") || pasted.has(uiSecretMarker) {
		t.Fatalf("a NAME=value key name:\n%s", pasted.body)
	}
	// A key-name default for a keyed API.
	m.post("/upstreams/register", url.Values{"name": {"vt-intel"}, "url": {"https://vt.example.net"}, "openapi_text": {restSpecJSON}, "auth_kind": {"bearer"}})
	if e, err := m.e.upstreams().Get(context.Background(), "vt-intel"); err != nil || !slices.Equal(e.EnvVarNames, []string{"VT_INTEL_API_KEY"}) {
		t.Fatalf("default key name: %+v, %v", e, err)
	}
}

func TestUIManage_UploadingTheDocumentWorksAndStillNeedsTheFormToken(t *testing.T) {
	m := newManageUI(t, true, false)
	fields := map[string]string{"name": "ioc", "url": "https://ioc.example.net", "auth_kind": "none"}
	if got := m.postMultipart(t, "/upstreams/register", fields, "openapi.json", restSpecJSON); got.code != http.StatusForbidden {
		t.Fatalf("a multipart register without the form token: %d", got.code)
	}
	fields["csrf"] = "0" + m.s.csrf[1:]
	if got := m.postMultipart(t, "/upstreams/register", fields, "openapi.json", restSpecJSON); got.code != http.StatusForbidden {
		t.Fatalf("a multipart register with a wrong form token: %d", got.code)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatal("a multipart POST without the form token registered")
	}
	fields["csrf"] = m.s.csrf
	got := m.postMultipart(t, "/upstreams/register", fields, "openapi.json", restSpecJSON)
	if got.code != http.StatusOK || !got.has("Registered ioc") || !got.has("report") {
		t.Fatalf("a multipart register with the file: %d\n%s", got.code, got.body)
	}
	if _, err := m.e.upstreams().Get(context.Background(), "ioc"); err != nil {
		t.Fatalf("not registered from the file: %v", err)
	}
	// Two ways at once is refused before the backend is asked.
	fields["name"], fields["openapi_text"] = "ioc2", restSpecJSON
	if got := m.postMultipart(t, "/upstreams/register", fields, "openapi.json", restSpecJSON); !got.has("one way") {
		t.Fatalf("a file and pasted text together:\n%s", got.body)
	}
}

func TestUIManage_TheBackendPageSignsRedialsAndRemovesOnlyWithTheNameTyped(t *testing.T) {
	m := newManageUI(t, true, true)
	if got := m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "auth_kind": {"none"}}); got.code != http.StatusOK {
		t.Fatalf("register: %d\n%s", got.code, got.body)
	}
	if got := m.get("/upstreams/show?name=nope"); got.code != http.StatusNotFound {
		t.Fatalf("the page of an unknown backend: %d", got.code)
	}
	page := m.get("/upstreams/show?name=ioc")
	for _, want := range []string{"ioc", "REST API", "https://ioc.example.net/api/v2", "POST", "/report", "Sensitive", "Safe", "Remove backend", `name="confirm"`, "/upstreams/redial"} {
		if !page.has(want) {
			t.Errorf("the backend page lacks %q", want)
		}
	}
	// The register signed it; the page offers Sign only when it is not
	// signed, and this test's signer records no signature.
	if sign := m.post("/upstreams/sign", url.Values{"name": {"ioc"}}); !sign.has("Signed with a trusted key") || !sign.has("ed25519:test-key") {
		t.Fatalf("sign:\n%s", sign.body)
	}

	// Redial with no gateway process: the backend's refusal.
	if got := m.post("/upstreams/redial", url.Values{"name": {"ioc"}}); !got.has("result-icon danger") {
		t.Fatalf("a redial with nothing to ring:\n%s", got.body)
	}

	for _, confirm := range []string{"", "IOC", "io"} {
		got := m.post("/upstreams/remove", url.Values{"name": {"ioc"}, "confirm": {confirm}})
		if !got.has("confirm must repeat") {
			t.Errorf("remove with confirm %q:\n%s", confirm, got.body)
		}
		if _, err := m.e.upstreams().Get(context.Background(), "ioc"); err != nil {
			t.Fatalf("removed with confirm %q", confirm)
		}
	}
	if got := m.post("/upstreams/remove", url.Values{"name": {"ioc"}, "confirm": {"ioc"}}); !got.has("Deregistered") {
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
	if !m.get("/").has("Reload configuration") {
		t.Fatal("the overview lacks the reload button")
	}
	// No gateway process recorded: refused, said so.
	if got := m.post("/reload", url.Values{}); !got.has("no gateway process") {
		t.Fatalf("reload with no serve:\n%s", got.body)
	}
	if err := controlsqlite.New(m.e.db).RecordProcess(context.Background(), control.Process{PID: 1 << 22, Boot: time.Now(), StartToken: "x"}); err != nil {
		t.Fatal(err)
	}
	got := m.post("/reload", url.Values{})
	if !got.has("is pending") || !got.has(m.s.session+"/serve-requests?id=") {
		t.Fatalf("a pending reload:\n%s", got.body)
	}
	i := strings.Index(got.body, "/serve-requests?id=")
	id := got.body[i+len("/serve-requests?id="):]
	id = id[:strings.IndexByte(id, '"')]
	if again := m.get("/serve-requests?id=" + id); again.code != http.StatusOK || !again.has("is pending") {
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
	page := m.get("/tools/show?server=reporting&tool=submit_report")
	if !page.has("Sensitive") || !page.has("Not cleared") || !page.has("/tools/clear") || page.has("Approve this version") {
		t.Fatalf("the tool page of an approved, uncleared sensitive tool:\n%s", page.body)
	}
	// No role reaches it: the backend refuses, and says why.
	got := m.post("/tools/clear", url.Values{"server": {"reporting"}, "tool": {"submit_report"}})
	if !got.has("result-icon danger") || !got.has("non_read") {
		t.Fatalf("clear with no role reaching it:\n%s", got.body)
	}
	m.e.cfg.Roles = []config.Role{{Name: "ir-act", Tools: []string{"reporting.submit_report"}, NonRead: true}}
	got = m.post("/tools/clear", url.Values{"server": {"reporting"}, "tool": {"submit_report"}})
	if !got.has("result-icon ok") || !got.has("ir-act") {
		t.Fatalf("clear:\n%s", got.body)
	}
	if after, _ := m.e.tools().Get(context.Background(), "reporting", "submit_report"); !after.Usable() {
		t.Fatal("cleared and still not usable")
	}
	if page := m.get("/tools/show?server=reporting&tool=submit_report"); !page.has("Cleared") || page.has("/tools/clear") {
		t.Fatalf("the tool page after clearing:\n%s", page.body)
	}
}

func TestUIManage_SecretsAreSetAndDeletedAndTheValueNeverShows(t *testing.T) {
	m := newManageUI(t, true, true)
	if got := m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"}, "openapi_text": {restSpecJSON}, "key_name": {"IOC_KEY"}}); got.code != http.StatusOK {
		t.Fatalf("register: %d", got.code)
	}
	var bodies []string
	keep := func(h *httpResult) *httpResult { bodies = append(bodies, h.body); return h }

	page := keep(m.get("/secrets"))
	if !page.has("IOC_KEY") || !page.has("Missing") || !page.has("needed by ioc") || !page.has(`type="password"`) {
		t.Fatalf("the secrets page before the key is set:\n%s", page.body)
	}
	if got := keep(m.post("/secrets/set", url.Values{"name": {"IOC_KEY"}, "value": {uiSecretMarker}})); !got.has("result-icon ok") || !got.has("IOC_KEY") {
		t.Fatalf("set:\n%s", got.body)
	}
	if m.vault.get("IOC_KEY") != uiSecretMarker {
		t.Fatal("the value was not written")
	}
	keep(m.post("/secrets/set", url.Values{"name": {"IOC_KEY"}, "value": {uiSecretMarker + "-2"}}))
	keep(m.post("/secrets/set", url.Values{"name": {"bad name"}, "value": {uiSecretMarker}}))
	keep(m.post("/secrets/set", url.Values{"name": {"X=" + uiSecretMarker}, "value": {uiSecretMarker}}))
	if page := keep(m.get("/secrets")); !page.has("Replace") || page.has("Missing") {
		t.Fatalf("the secrets page after set:\n%s", page.body)
	}
	if got := keep(m.post("/secrets/delete", url.Values{"name": {"IOC_KEY"}})); !got.has("tick the confirmation") || m.vault.get("IOC_KEY") == "" {
		t.Fatalf("delete without the confirmation:\n%s", got.body)
	}
	if got := keep(m.post("/secrets/delete", url.Values{"name": {"IOC_KEY"}, "confirm": {"yes"}})); !got.has("result-icon ok") || m.vault.get("IOC_KEY") != "" {
		t.Fatalf("delete:\n%s", got.body)
	}
	for _, p := range []string{"/", "/upstreams", "/upstreams/show?name=ioc", "/audit", "/roles"} {
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

func TestUIManage_RolesAreAppliedAndARefusalKeepsWhatWasTyped(t *testing.T) {
	m := newManageUI(t, true, true)
	page := m.get("/roles")
	if page.code != http.StatusOK || !page.has("blue-ir") || !page.has(m.rolesPath) {
		t.Fatalf("the roles page: %d\n%s", page.code, page.body)
	}
	bad := uiRolesText + "\"blue-x\" = \"nobody-role\"\n"
	got := m.post("/roles", url.Values{"text": {bad}})
	if !got.has("Not written") || !got.has("nobody-role") || !got.has("&#34;blue-x&#34; = &#34;nobody-role&#34;") {
		t.Fatalf("a refused roles text:\n%s", got.body)
	}
	if b, _ := os.ReadFile(m.rolesPath); string(b) != uiRolesText {
		t.Fatal("a refused text was written")
	}
	next := uiRolesText + "\"blue-hunt\" = \"ir\"\n"
	got = m.post("/roles", url.Values{"text": {next}})
	if b, _ := os.ReadFile(m.rolesPath); string(b) != next {
		t.Fatalf("not written:\n%s", got.body)
	}
	// Written; the reload has no gateway process to ring here, and the
	// page says the file is written and not applied.
	if !got.has("written, and not applied") {
		t.Fatalf("the roles result:\n%s", got.body)
	}
	if same := m.post("/roles", url.Values{"text": {next}}); !same.has("already holds exactly this text") {
		t.Fatalf("the same text again:\n%s", same.body)
	}
}

// TestUIManage_RegisterGrantsTheAPIToTheRoleNamed: the Add API form grants
// the new API's safe tools to a role, as `gatte api add` does, through the
// validated roles write; a role that does not exist grants nothing and says
// so, and a grant already present is not written twice.
func TestUIManage_RegisterGrantsTheAPIToTheRoleNamed(t *testing.T) {
	m := newManageUI(t, true, true)
	if page := m.get("/upstreams"); !page.has(`name="grant_role"`) || !page.has(`value="analyst"`) {
		t.Fatal("the Add API form has no grant field defaulting to analyst")
	}
	got := m.post("/upstreams/register", url.Values{"name": {"ioc"}, "url": {"https://ioc.example.net"},
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
	m.post("/upstreams/register", url.Values{"name": {"vt"}, "url": {"https://vt.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"VT_KEY"}, "grant_role": {"ir"}})
	b, _ = os.ReadFile(m.rolesPath)
	if strings.Count(string(b), "[role.grants]") != 1 || !strings.Contains(string(b), "\"vt\" = [\"*\"]") {
		t.Fatalf("the second grant:\n%s", b)
	}

	// No such role: nothing written, and the page says what to do.
	before, _ := os.ReadFile(m.rolesPath)
	got = m.post("/upstreams/register", url.Values{"name": {"gn"}, "url": {"https://gn.example.net"},
		"openapi_text": {restSpecJSON}, "key_name": {"GN_KEY"}, "grant_role": {"nobody"}})
	if !got.has("no [[role]] named nobody") || !got.has("Grant it to a role") {
		t.Fatalf("an unknown role:\n%s", got.body)
	}
	if after, _ := os.ReadFile(m.rolesPath); string(after) != string(before) {
		t.Fatal("an unknown role changed the roles file")
	}
}
