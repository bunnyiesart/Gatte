package admin_test

// Tests of design/adr/0050 at the service, over fakes of its ports: every
// operation behind console_manages, one operator row per change, the
// rules (a deregister's confirmation, a vault name's grammar, the roles
// text validated before it is written), and a vault value that is in no
// answer, error, row or log line.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

type fakeVault struct {
	mu     sync.Mutex
	values map[string][]byte
	fail   error
}

func (v *fakeVault) Names(context.Context, *config.Config) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail != nil {
		return nil, v.fail
	}
	var out []string
	for n := range v.values {
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

func (v *fakeVault) Set(_ context.Context, _ *config.Config, name string, value []byte) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail != nil {
		return false, v.fail
	}
	_, ok := v.values[name]
	v.values[name] = append([]byte(nil), value...)
	return ok, nil
}

func (v *fakeVault) Delete(_ context.Context, _ *config.Config, name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail != nil {
		return false, v.fail
	}
	_, ok := v.values[name]
	delete(v.values, name)
	return ok, nil
}

type fakeRoles struct {
	text   []byte
	writes int
}

func (r *fakeRoles) Read(*config.Config) ([]byte, error) { return r.text, nil }
func (r *fakeRoles) Write(_ *config.Config, text []byte) error {
	r.text = append([]byte(nil), text...)
	r.writes++
	return nil
}

type manageHarness struct {
	svc        *admin.Service
	cfg        *config.Config
	rows       []audit.Record
	log        *bytes.Buffer
	vault      *fakeVault
	roles      *fakeRoles
	registered map[string]bool
	checked    [][]string
}

func newManageHarness(t *testing.T) *manageHarness {
	t.Helper()
	h := &manageHarness{
		cfg: &config.Config{Admin: config.Admin{ConsoleManages: true}, RolesFile: "/etc/gatte/roles.toml",
			Vault: config.Vault{SecretsFile: "/etc/gatte/secrets.json", AgeKeyFile: "/etc/gatte/age.key"}},
		log:        &bytes.Buffer{},
		vault:      &fakeVault{values: map[string][]byte{"EXISTING": []byte("x")}},
		roles:      &fakeRoles{text: []byte("[[role]]\nname = \"ir\"\ntools = []\n")},
		registered: map[string]bool{"casemgmt": true},
	}
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return h.cfg, nil },
		Record: func(_ context.Context, _ *config.Config, rec audit.Record) error {
			h.rows = append(h.rows, rec)
			return nil
		},
		Log: slog.New(slog.NewTextHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		ManageDeps: admin.ManageDeps{
			UpstreamDetail: func(_ context.Context, _ *config.Config, name string) (adminapi.UpstreamDetail, error) {
				if !h.registered[name] {
					return adminapi.UpstreamDetail{}, adminapi.NewError(adminapi.CodeNotFound, "no registered backend is named %q", name)
				}
				return adminapi.UpstreamDetail{Upstream: adminapi.Upstream{Name: name, Transport: "http"}}, nil
			},
			RegisterHTTP: func(_ context.Context, _ *config.Config, req adminapi.RegisterUpstreamRequest) (adminapi.RegisterUpstreamResult, error) {
				if h.registered[req.Name] {
					return adminapi.RegisterUpstreamResult{}, adminapi.NewError(adminapi.CodeUpstreamExists, "exists")
				}
				h.registered[req.Name] = true
				return adminapi.RegisterUpstreamResult{Name: req.Name, URL: req.URL, Source: "the document sent",
					Auth: adminapi.UpstreamAuth{Kind: "bearer", Secret: req.KeyName}, Signature: "no",
					Tools: []adminapi.UpstreamOperation{{Name: "list", Method: "GET", Path: "/x"}, {Name: "close", Method: "POST", Path: "/x", Class: adminapi.ClassSensitive}}}, nil
			},
			Deregister: func(_ context.Context, _ *config.Config, name string) (adminapi.DeregisterResult, error) {
				had := h.registered[name]
				delete(h.registered, name)
				return adminapi.DeregisterResult{Registered: had, SignatureRemoved: had, ToolsForgotten: map[bool]int{true: 2}[had]}, nil
			},
			Sign: func(_ context.Context, _ *config.Config, name string) (admin.SignOutcome, error) {
				if !h.registered[name] {
					return admin.SignOutcome{}, adminapi.NewError(adminapi.CodeNotFound, "no registered backend is named %q", name)
				}
				return admin.SignOutcome{KeyFingerprint: "SHA256:abcd", Trusted: false, Output: []string{"Signed \"" + name + "\"."}}, nil
			},
			Vault: h.vault,
			DeclaredSecrets: func(context.Context, *config.Config) (map[string][]string, error) {
				return map[string][]string{"CASEMGMT_TOKEN": {"casemgmt"}, "EXISTING": {"threatintel"}}, nil
			},
			Roles: h.roles,
			ValidateRoles: func(text []byte) error {
				if strings.Contains(string(text), "bogus") {
					return errors.New("config: invalid: /etc/gatte/config.toml (roles from /etc/gatte/roles.toml): unknown key bogus")
				}
				return nil
			},
			CheckPaths: func(paths []string) error {
				h.checked = append(h.checked, paths)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

// bob is an operator on the accounts socket: in [admin] operator_group, as
// the kernel said.
var bob = admin.Actor{Name: "bob", Front: "ui", Operator: true}

func requireManageCode(t *testing.T, err error, code, what string) {
	t.Helper()
	if !adminapi.IsCode(err, code) {
		t.Fatalf("%s: %v, want %s", what, err, code)
	}
}

func TestManage_EveryOperationIsFeatureDisabledWithTheKeyOff(t *testing.T) {
	h := newManageHarness(t)
	h.cfg.Admin.ConsoleManages = false
	ctx := context.Background()
	if h.svc.ConsoleManages() {
		t.Fatal("ConsoleManages with the key off")
	}
	ops := map[string]func() error{
		"getUpstream": func() error { _, err := h.svc.GetUpstream(ctx, "casemgmt"); return err },
		"registerUpstream": func() error {
			_, err := h.svc.RegisterUpstream(ctx, bob, adminapi.RegisterUpstreamRequest{Name: "x", URL: "https://x", OpenAPIDocument: "{}"})
			return err
		},
		"deregisterUpstream": func() error {
			_, err := h.svc.DeregisterUpstream(ctx, bob, "casemgmt", adminapi.DeregisterRequest{Confirm: "casemgmt"})
			return err
		},
		"signUpstream": func() error { _, err := h.svc.SignUpstream(ctx, bob, "casemgmt"); return err },
		"listSecrets":  func() error { _, err := h.svc.ListSecrets(ctx, bob); return err },
		"setSecret": func() error {
			_, err := h.svc.SetSecret(ctx, bob, "A", adminapi.SecretValue{Value: "v"})
			return err
		},
		"deleteSecret": func() error { _, err := h.svc.DeleteSecret(ctx, bob, "EXISTING"); return err },
		"getRoles":     func() error { _, err := h.svc.GetRoles(ctx, bob); return err },
		"putRoles": func() error {
			_, err := h.svc.PutRoles(ctx, bob, adminapi.RolesRequest{Text: "x"})
			return err
		},
	}
	for name, op := range ops {
		err := op()
		requireManageCode(t, err, adminapi.CodeFeatureDisabled, name)
		var ae *adminapi.Error
		if errors.As(err, &ae) && (ae.Details["key"] != "admin.console_manages" || ae.Status != 403) {
			t.Errorf("%s: %+v", name, ae)
		}
	}
	if len(h.rows) != 0 || len(h.registered) != 1 || h.roles.writes != 0 || len(h.vault.values) != 1 {
		t.Fatalf("something changed with the key off: rows %v", h.rows)
	}
}

func TestManage_RegisterUpstreamValidatesRecordsAndReports(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	base := adminapi.RegisterUpstreamRequest{Name: "intel", URL: "https://api.example.org", KeyName: "INTEL_KEY"}
	for _, tc := range []struct {
		name string
		edit func(*adminapi.RegisterUpstreamRequest)
		code string
	}{
		{"no document", func(*adminapi.RegisterUpstreamRequest) {}, adminapi.CodeInvalidArgument},
		{"both", func(r *adminapi.RegisterUpstreamRequest) { r.OpenAPIURL, r.OpenAPIDocument = "https://x/o.json", "{}" }, adminapi.CodeInvalidArgument},
		{"a path", func(r *adminapi.RegisterUpstreamRequest) { r.OpenAPIURL = "/etc/passwd" }, adminapi.CodeInvalidArgument},
		{"NAME=value", func(r *adminapi.RegisterUpstreamRequest) { r.OpenAPIDocument, r.KeyName = "{}", "INTEL_KEY=hunter2" }, adminapi.CodeInvalidArgument},
		{"bad key name", func(r *adminapi.RegisterUpstreamRequest) { r.OpenAPIDocument, r.KeyName = "{}", "1BAD" }, adminapi.CodeInvalidArgument},
		{"no name", func(r *adminapi.RegisterUpstreamRequest) { r.OpenAPIDocument, r.Name = "{}", "" }, adminapi.CodeInvalidArgument},
	} {
		req := base
		tc.edit(&req)
		_, err := h.svc.RegisterUpstream(ctx, bob, req)
		requireManageCode(t, err, tc.code, tc.name)
		if strings.Contains(fmt.Sprint(err), "hunter2") {
			t.Errorf("%s: the value after = is repeated: %v", tc.name, err)
		}
	}
	req := base
	req.OpenAPIDocument = "{}"
	res, err := h.svc.RegisterUpstream(ctx, bob, req)
	if err != nil || !res.Changed || !res.Recorded || res.Audit == nil || res.Audit.Tool != admin.UpstreamRegister {
		t.Fatalf("register = %+v, %v", res, err)
	}
	if len(h.rows) != 1 || !strings.HasPrefix(h.rows[0].Reason, `upstream "intel" registered: http https://api.example.org, 2 operations (1 safe, 1 sensitive), auth bearer <INTEL_KEY> [ui]`) {
		t.Fatalf("row = %+v", h.rows)
	}
	if res.Skipped == nil || res.IngestWarnings == nil || len(res.Tools) != 2 {
		t.Fatalf("report = %+v", res)
	}
	_, err = h.svc.RegisterUpstream(ctx, bob, req)
	requireManageCode(t, err, adminapi.CodeUpstreamExists, "a second register")
	if len(h.rows) != 1 {
		t.Fatal("a refused register wrote a row")
	}
}

func TestManage_DeregisterNeedsTheNameRepeated(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	for _, confirm := range []string{"", "casemgm", "CASEMGMT", "casemgmt "} {
		_, err := h.svc.DeregisterUpstream(ctx, bob, "casemgmt", adminapi.DeregisterRequest{Confirm: confirm})
		requireManageCode(t, err, adminapi.CodeInvalidArgument, "confirm "+confirm)
	}
	if !h.registered["casemgmt"] || len(h.rows) != 0 {
		t.Fatal("a wrong confirmation deregistered")
	}
	res, err := h.svc.DeregisterUpstream(ctx, bob, "casemgmt", adminapi.DeregisterRequest{Confirm: "casemgmt"})
	if err != nil || !res.Changed || !res.Registered || res.ToolsForgotten != 2 || len(h.rows) != 1 || h.rows[0].Tool != admin.UpstreamDeregister ||
		!strings.HasPrefix(h.rows[0].Reason, `upstream "casemgmt" deregistered`) {
		t.Fatalf("deregister = %+v, %v, rows %v", res, err, h.rows)
	}
	// Again: nothing left, no row.
	res, err = h.svc.DeregisterUpstream(ctx, bob, "casemgmt", adminapi.DeregisterRequest{Confirm: "casemgmt"})
	if err != nil || res.Changed || len(h.rows) != 1 {
		t.Fatalf("second deregister = %+v, %v", res, err)
	}
}

func TestManage_SignRecordsTheFingerprintAndWarnsOfAnUntrustedKey(t *testing.T) {
	h := newManageHarness(t)
	res, err := h.svc.SignUpstream(context.Background(), bob, "casemgmt")
	if err != nil || !res.Changed || res.KeyFingerprint != "SHA256:abcd" || res.Trusted || !res.HasWarning("key_not_trusted") {
		t.Fatalf("sign = %+v, %v", res, err)
	}
	if len(h.rows) != 1 || h.rows[0].Tool != admin.UpstreamSign || h.rows[0].Reason != `upstream "casemgmt" signed with key SHA256:abcd [ui]` {
		t.Fatalf("rows = %+v", h.rows)
	}
	_, err = h.svc.SignUpstream(context.Background(), bob, "nope")
	requireManageCode(t, err, adminapi.CodeNotFound, "sign of an unknown backend")
}

func TestManage_SecretsListSetDelete(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	list, err := h.svc.ListSecrets(ctx, bob)
	if err != nil || !list.RegistryRead || len(list.Secrets) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if s := list.Secrets[0]; s.Name != "CASEMGMT_TOKEN" || s.InVault || !slices.Equal(s.DeclaredBy, []string{"casemgmt"}) {
		t.Errorf("a declared name missing from the vault: %+v", s)
	}
	if s := list.Secrets[1]; s.Name != "EXISTING" || !s.InVault {
		t.Errorf("a name in the vault: %+v", s)
	}
	if len(h.checked) != 1 || !slices.Equal(h.checked[0], []string{"/etc/gatte/secrets.json", "/etc/gatte/age.key"}) {
		t.Errorf("vault paths checked: %v", h.checked)
	}
	for _, bad := range []string{"", "1A", "A-B", "A B", "a.b", "A=B", strings.Repeat("A", 129)} {
		_, err := h.svc.SetSecret(ctx, bob, bad, adminapi.SecretValue{Value: "v"})
		requireManageCode(t, err, adminapi.CodeInvalidArgument, "name "+bad)
	}
	_, err = h.svc.SetSecret(ctx, bob, "CASEMGMT_TOKEN", adminapi.SecretValue{})
	requireManageCode(t, err, adminapi.CodeInvalidArgument, "an empty value")
	_, err = h.svc.SetSecret(ctx, bob, "CASEMGMT_TOKEN", adminapi.SecretValue{Value: strings.Repeat("x", adminapi.MaxSecretValueBytes+1)})
	requireManageCode(t, err, adminapi.CodePayloadTooLarge, "a value over the limit")
	if len(h.rows) != 0 {
		t.Fatal("a refused set wrote a row")
	}

	res, err := h.svc.SetSecret(ctx, bob, "CASEMGMT_TOKEN", adminapi.SecretValue{Value: "v1"})
	if err != nil || !res.Changed || res.Existed || h.rows[0].Tool != admin.SecretSet || h.rows[0].Reason != `secret "CASEMGMT_TOKEN" created [ui]` {
		t.Fatalf("set = %+v, %v, %v", res, err, h.rows)
	}
	res, err = h.svc.SetSecret(ctx, bob, "CASEMGMT_TOKEN", adminapi.SecretValue{Value: "v2"})
	if err != nil || !res.Existed || h.rows[1].Reason != `secret "CASEMGMT_TOKEN" replaced [ui]` || string(h.vault.values["CASEMGMT_TOKEN"]) != "v2" {
		t.Fatalf("replace = %+v, %v", res, err)
	}
	res, err = h.svc.DeleteSecret(ctx, bob, "CASEMGMT_TOKEN")
	if err != nil || !res.Changed || !res.Existed || h.rows[2].Tool != admin.SecretDelete || h.rows[2].Reason != `secret "CASEMGMT_TOKEN" deleted [ui]` {
		t.Fatalf("delete = %+v, %v", res, err)
	}
	res, err = h.svc.DeleteSecret(ctx, bob, "CASEMGMT_TOKEN")
	if err != nil || res.Changed || len(h.rows) != 3 {
		t.Fatalf("delete of nothing = %+v, %v", res, err)
	}

	// A registry that cannot be read leaves the vault's names.
	h2 := newManageHarness(t)
	h2.svc, _ = admin.New(admin.Deps{Config: func() (*config.Config, error) { return h2.cfg, nil },
		Record:     func(context.Context, *config.Config, audit.Record) error { return nil },
		ManageDeps: admin.ManageDeps{Vault: h2.vault}})
	list, err = h2.svc.ListSecrets(ctx, bob)
	if err != nil || list.RegistryRead || len(list.Problems) != 1 || len(list.Secrets) != 1 || list.Secrets[0].DeclaredBy != nil {
		t.Fatalf("list without the registry = %+v, %v", list, err)
	}
}

// TestManage_ASecretValueIsInNoAnswerErrorRowOrLog is design/adr/0050 §2:
// "the value enters once and is never returned, recorded or logged" --
// through success, every refusal, and a failing vault.
func TestManage_ASecretValueIsInNoAnswerErrorRowOrLog(t *testing.T) {
	const marker = "MARKER-secret-value-5d1f0c9e"
	h := newManageHarness(t)
	ctx := context.Background()
	var seen []string
	add := func(v any, err error) {
		b, _ := json.Marshal(v)
		seen = append(seen, string(b), fmt.Sprint(err))
		if err != nil {
			var ae *adminapi.Error
			if errors.As(err, &ae) {
				d, _ := json.Marshal(ae)
				seen = append(seen, string(d))
			}
		}
	}
	add(h.svc.SetSecret(ctx, bob, "GOOD", adminapi.SecretValue{Value: marker}))
	add(h.svc.SetSecret(ctx, bob, "GOOD", adminapi.SecretValue{Value: marker}))
	add(h.svc.SetSecret(ctx, bob, "BAD NAME", adminapi.SecretValue{Value: marker}))
	add(h.svc.SetSecret(ctx, bob, "GOOD", adminapi.SecretValue{Value: marker + strings.Repeat("x", adminapi.MaxSecretValueBytes)}))
	add(h.svc.ListSecrets(ctx, bob))
	add(h.svc.SetSecret(ctx, admin.Actor{}, "GOOD", adminapi.SecretValue{Value: marker}))
	h.vault.fail = errors.New("sopsage: sops encrypt failed (exit status 1)")
	add(h.svc.SetSecret(ctx, bob, "OTHER", adminapi.SecretValue{Value: marker}))
	add(h.svc.DeleteSecret(ctx, bob, "GOOD"))
	h.cfg.Admin.ConsoleManages = false
	add(h.svc.SetSecret(ctx, bob, "GOOD", adminapi.SecretValue{Value: marker}))
	for _, r := range h.rows {
		seen = append(seen, fmt.Sprintf("%+v", r))
	}
	seen = append(seen, h.log.String())
	if string(h.vault.values["GOOD"]) != marker {
		t.Fatal("precondition: the value did not reach the vault")
	}
	if len(h.rows) != 2 {
		t.Fatalf("rows = %v", h.rows)
	}
	for _, s := range seen {
		if strings.Contains(s, marker) || strings.Contains(s, "5d1f0c9e") {
			t.Fatalf("the value is in: %s", s)
		}
	}
}

func TestManage_RolesAreValidatedBeforeTheyAreWrittenAndNotApplied(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	got, err := h.svc.GetRoles(ctx, bob)
	if err != nil || got.Path != "/etc/gatte/roles.toml" || got.Text != string(h.roles.text) || len(got.SHA256) != 64 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	_, err = h.svc.PutRoles(ctx, bob, adminapi.RolesRequest{Text: "bogus = 1\n"})
	requireManageCode(t, err, adminapi.CodeInvalidArgument, "an invalid text")
	if !strings.Contains(err.Error(), "unknown key bogus") || h.roles.writes != 0 || len(h.rows) != 0 {
		t.Fatalf("an invalid text: %v, writes %d", err, h.roles.writes)
	}
	text := "[[role]]\nname = \"hunt\"\ntools = []\n"
	res, err := h.svc.PutRoles(ctx, bob, adminapi.RolesRequest{Text: text})
	if err != nil || !res.Changed || !res.ReloadNeeded || h.roles.writes != 1 || string(h.roles.text) != text {
		t.Fatalf("put = %+v, %v", res, err)
	}
	if len(h.rows) != 1 || h.rows[0].Tool != admin.RolesSet || h.rows[0].Reason != "roles file /etc/gatte/roles.toml set to sha256:"+res.SHA256+" [ui]" {
		t.Fatalf("rows = %+v", h.rows)
	}
	res, err = h.svc.PutRoles(ctx, bob, adminapi.RolesRequest{Text: text})
	if err != nil || res.Changed || h.roles.writes != 1 || len(h.rows) != 1 {
		t.Fatalf("the same text again = %+v, %v", res, err)
	}
	h.cfg.RolesFile = ""
	_, err = h.svc.GetRoles(ctx, bob)
	requireManageCode(t, err, adminapi.CodeFeatureDisabled, "roles without roles_file")
	var ae *adminapi.Error
	if errors.As(err, &ae); ae.Details["key"] != "roles_file" {
		t.Fatalf("details = %v", ae.Details)
	}
}

func TestManage_GetUpstream(t *testing.T) {
	h := newManageHarness(t)
	d, err := h.svc.GetUpstream(context.Background(), "casemgmt")
	if err != nil || d.Name != "casemgmt" || d.Tools == nil {
		t.Fatalf("detail = %+v, %v", d, err)
	}
	_, err = h.svc.GetUpstream(context.Background(), "nope")
	requireManageCode(t, err, adminapi.CodeNotFound, "an unknown backend")
	_, err = h.svc.GetUpstream(context.Background(), "../x")
	requireManageCode(t, err, adminapi.CodeInvalidArgument, "a path as a name")
}

// TestManage_TheAccountGroupAloneCannotSignOrWriteTheVaultOrTheRoles: the
// accounts socket's delegation to [admin] account_group is of accounts
// (design/adr/0040 §1); signing and writing the vault and the roles are
// an operator's acts.
func TestManage_TheAccountGroupAloneCannotSignOrWriteTheVaultOrTheRoles(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	delegate := admin.Actor{Name: "dave", Front: "ui"}
	_, err := h.svc.SignUpstream(ctx, delegate, "casemgmt")
	requireManageCode(t, err, adminapi.CodeForbiddenPeer, "sign")
	_, err = h.svc.SetSecret(ctx, delegate, "A", adminapi.SecretValue{Value: "v"})
	requireManageCode(t, err, adminapi.CodeForbiddenPeer, "set")
	_, err = h.svc.DeleteSecret(ctx, delegate, "EXISTING")
	requireManageCode(t, err, adminapi.CodeForbiddenPeer, "delete")
	_, err = h.svc.PutRoles(ctx, delegate, adminapi.RolesRequest{Text: "x"})
	requireManageCode(t, err, adminapi.CodeForbiddenPeer, "roles")
	if len(h.rows) != 0 || h.roles.writes != 0 || len(h.vault.values) != 1 {
		t.Fatal("a delegate changed something")
	}
	root := admin.Actor{Name: "root", Root: true}
	if _, err := h.svc.SignUpstream(ctx, root, "casemgmt"); err != nil {
		t.Fatalf("root: %v", err)
	}
}

// TestManage_ANameThatReadsAsAFlagIsNeverSigned: `-h` passed the old name
// check, and the sign child printed its usage, exited 0 and was recorded as
// a signature that never happened (found in review). The registry's grammar
// refuses it before any child runs; the child also gets "--".
func TestManage_ANameThatReadsAsAFlagIsNeverSigned(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	for _, bad := range []string{"-h", "--help", "-all", "-config=/x", "gatte"} {
		if _, err := h.svc.SignUpstream(ctx, bob, bad); err == nil {
			t.Errorf("SignUpstream(%q) was accepted", bad)
		}
	}
}

// TestManage_ReadingTheVaultAndTheRolesIsAnOperatorsAct: a delegated
// account_group peer manages accounts, not the vault or the roles, and
// reading them is refused like writing them (found in review).
func TestManage_ReadingTheVaultAndTheRolesIsAnOperatorsAct(t *testing.T) {
	h := newManageHarness(t)
	ctx := context.Background()
	notOperator := admin.Actor{Name: "acct", Front: "ui"}
	if _, err := h.svc.ListSecrets(ctx, notOperator); err == nil {
		t.Error("a non-operator listed the vault's names")
	}
	if _, err := h.svc.GetRoles(ctx, notOperator); err == nil {
		t.Error("a non-operator read the roles")
	}
}
