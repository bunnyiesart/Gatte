package main

// The adapters of design/adr/0050 through the real service, the real
// database and the real ingestion: what the management API registers is
// what `upstream register -transport http` registers, a deregister removes
// what the CLI's does, the sign child's answers map onto the contract, and
// the vault and the roles file are written as they are read.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

var carol = admin.Actor{Name: "carol", Front: "ui", Operator: true}

func manageEnv(t *testing.T) (opTestEnv, *admin.Service) {
	t.Helper()
	e := newOpTestEnv(t)
	e.cfg.Admin.ConsoleManages = true
	svc, err := e.service()
	if err != nil {
		t.Fatal(err)
	}
	return e, svc
}

func TestManage_RegisterThroughTheAPIIsTheConsolesRegister(t *testing.T) {
	e, svc := manageEnv(t)
	ctx := context.Background()
	req := adminapi.RegisterUpstreamRequest{Name: "ioc", URL: "https://ioc.example.net", OpenAPIDocument: restSpecJSON, KeyName: "IOC_KEY"}
	res, err := svc.RegisterUpstream(ctx, carol, req)
	if err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}
	// The document's base path folded in, its apiKey scheme derived, and
	// the multipart operation skipped -- the ingestion's report, as the
	// CLI prints it.
	if res.URL != "https://ioc.example.net/api/v2" || !res.AuthDerived || res.Auth != (adminapi.UpstreamAuth{Kind: "header", Name: "X-API-Key", Secret: "IOC_KEY"}) {
		t.Fatalf("report = %+v", res)
	}
	if len(res.Tools) != 2 || len(res.Skipped) != 1 || res.Signature != "no" || res.FetchedBytes != 0 || res.Source != "the document sent" {
		t.Fatalf("report = %+v", res)
	}
	entry, err := e.upstreams().Get(ctx, "ioc")
	if err != nil || entry.Transport != registry.TransportHTTP || len(entry.Operations) == 0 || !slices.Equal(entry.EnvVarNames, []string{"IOC_KEY"}) {
		t.Fatalf("registry entry = %+v, %v", entry, err)
	}
	recs, _ := auditsqlite.New(e.db).List(ctx)
	if len(recs) != 1 || recs[0].Tool != admin.UpstreamRegister || recs[0].AnalystIdentity != "(operator:carol)" {
		t.Fatalf("rows = %+v", recs)
	}

	d, err := svc.GetUpstream(ctx, "ioc")
	if err != nil || d.Auth == nil || d.Auth.Secret != "IOC_KEY" || len(d.Operations) != 2 || len(d.OperationsSHA256) != 64 || d.Signature != "no" {
		t.Fatalf("detail = %+v, %v", d, err)
	}
	classes := map[string]string{}
	for _, op := range d.Operations {
		classes[op.Method] = op.Class
	}
	if classes["GET"] != adminapi.ClassSafe || classes["POST"] != adminapi.ClassSensitive {
		t.Errorf("operation classes = %v", classes)
	}

	_, err = svc.RegisterUpstream(ctx, carol, req)
	if !adminapi.IsCode(err, adminapi.CodeUpstreamExists) {
		t.Fatalf("a second register: %v", err)
	}

	// The CLI's own refusals, in the CLI's own words.
	bad := req
	bad.Name, bad.AuthKind = "ioc2", "bogus"
	_, err = svc.RegisterUpstream(ctx, carol, bad)
	if !adminapi.IsCode(err, adminapi.CodeInvalidArgument) || !strings.Contains(err.Error(), `-auth-kind "bogus" is not one of`) {
		t.Fatalf("a bad auth kind: %v", err)
	}
	bad = req
	bad.Name, bad.OpenAPIDocument = "ioc2", `{"openapi": "2.0"}`
	if _, err = svc.RegisterUpstream(ctx, carol, bad); !adminapi.IsCode(err, adminapi.CodeInvalidArgument) || !strings.Contains(err.Error(), `refusing to register "ioc2"`) {
		t.Fatalf("a bad document: %v", err)
	}
	if _, err := e.upstreams().Get(ctx, "ioc2"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("a refused register left an entry: %v", err)
	}

	out, err := svc.DeregisterUpstream(ctx, carol, "ioc", adminapi.DeregisterRequest{Confirm: "ioc"})
	if err != nil || !out.Registered || !out.Changed {
		t.Fatalf("deregister = %+v, %v", out, err)
	}
	if _, err := e.upstreams().Get(ctx, "ioc"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("still registered: %v", err)
	}
	if _, err := svc.GetUpstream(ctx, "ioc"); !adminapi.IsCode(err, adminapi.CodeNotFound) {
		t.Fatalf("detail after deregister: %v", err)
	}
}

func TestManage_SignChildAnswersMapOntoTheContract(t *testing.T) {
	keyFile := writeSigningKey(t, 0o600)
	cfgPath := writeOperatorConfig(t, signerSection(t, keyFile))
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	old := signChild
	t.Cleanup(func() { signChild = old })
	var gotArgs []string
	for _, tc := range []struct {
		code   int
		stdout string
		stderr string
		want   string
	}{
		{exitOK, "Signed \"casemgmt\".\n\n  transport  stdio\n", "", ""},
		{exitProblem, "", "no upstream named \"casemgmt\" is registered, so there is nothing to sign.\n", adminapi.CodeNotFound},
		{exitProblem, "", "refusing to sign \"casemgmt\": the dialer would refuse it\n", adminapi.CodeInvalidArgument},
		{exitCannotRun, "", "database: locked\n", adminapi.CodeInternal},
	} {
		signChild = func(_ context.Context, path, name string) (int, []byte, []byte, error) {
			gotArgs = []string{path, name}
			return tc.code, []byte(tc.stdout), []byte(tc.stderr), nil
		}
		out, err := spawnSign(cfgPath)(context.Background(), cfg, "casemgmt")
		if tc.want == "" {
			if err != nil || !out.Trusted || out.KeyFingerprint == "" || len(out.Output) == 0 {
				t.Fatalf("sign ok = %+v, %v", out, err)
			}
			continue
		}
		if !adminapi.IsCode(err, tc.want) {
			t.Errorf("exit %d %q: %v, want %s", tc.code, tc.stderr, err, tc.want)
		}
	}
	if !slices.Equal(gotArgs, []string{cfgPath, "casemgmt"}) {
		t.Errorf("child args = %v", gotArgs)
	}
	// No key configured: refused before any child.
	cfg.Signer.KeyFile = ""
	signChild = func(context.Context, string, string) (int, []byte, []byte, error) {
		t.Fatal("a child was started without a key")
		return 0, nil, nil, nil
	}
	if _, err := spawnSign(cfgPath)(context.Background(), cfg, "casemgmt"); !adminapi.IsCode(err, adminapi.CodeInvalidArgument) {
		t.Fatalf("no key_file: %v", err)
	}
}

func TestManage_RegistryReaderListsDeclaredNames(t *testing.T) {
	cfgPath := writeOperatorConfig(t, "\n[signer]\nrequire_signed = false\n")
	code, _, errText := runCLI("upstream", "register", "-config", cfgPath, "-name", "intel", "-transport", "oci",
		"-image", "ghcr.io/x/intel@sha256:"+strings.Repeat("a", 64), "-env", "INTEL_KEY")
	if code != exitOK {
		t.Fatalf("register: %d %s", code, errText)
	}
	var out, errb strings.Builder
	if code := runRegistryReader(cfgPath, &out, &errb); code != exitOK {
		t.Fatalf("registry reader: %d %s", code, errb.String())
	}
	var declared map[string][]string
	if err := json.Unmarshal([]byte(out.String()), &declared); err != nil || !slices.Equal(declared["INTEL_KEY"], []string{"intel"}) {
		t.Fatalf("declared = %v, %v (%s)", declared, err, out.String())
	}
}

func TestManage_RolesFileIsValidatedAndWrittenInPlace(t *testing.T) {
	cfgPath := writeOperatorConfig(t, "roles_file = \"roles.toml\"\n")
	// roles_file is a top-level key, and the fixture ends inside [vault].
	body, _ := os.ReadFile(cfgPath)
	if err := os.WriteFile(cfgPath, []byte("roles_file = \"roles.toml\"\n"+strings.Replace(string(body), "roles_file = \"roles.toml\"\n", "\n[signer]\nrequire_signed = false\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	rolesPath := filepath.Join(filepath.Dir(cfgPath), "roles.toml")
	const roles = "[[role]]\nname = \"ir\"\ntools = []\n[group_to_role]\n\"blue-ir\" = \"ir\"\n"
	if err := os.WriteFile(rolesPath, []byte(roles), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rolesPath, 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Admin.ConsoleManages = true
	var rows []string
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return cfg, nil },
		Record: func(_ context.Context, _ *config.Config, rec audit.Record) error {
			rows = append(rows, rec.Tool+" "+rec.Reason)
			return nil
		},
		ManageDeps: accountsManageDeps(cfgPath, 1, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := svc.GetRoles(ctx, admin.Actor{Name: "root", Operator: true})
	if err != nil || got.Text != roles || got.Path != rolesPath {
		t.Fatalf("GetRoles = %+v, %v", got, err)
	}
	// What the load would refuse is refused with its message, unwritten.
	_, err = svc.PutRoles(ctx, carol, adminapi.RolesRequest{Text: roles + "\"blue-x\" = \"nobody\"\n"})
	if !adminapi.IsCode(err, adminapi.CodeInvalidArgument) || !strings.Contains(err.Error(), "nobody") {
		t.Fatalf("an undefined role: %v", err)
	}
	next := roles + "\"blue-hunt\" = \"ir\"\n"
	res, err := svc.PutRoles(ctx, carol, adminapi.RolesRequest{Text: next})
	if err != nil || !res.Changed {
		t.Fatalf("PutRoles = %+v, %v", res, err)
	}
	b, _ := os.ReadFile(rolesPath)
	fi, _ := os.Stat(rolesPath)
	if string(b) != next || fi.Mode().Perm() != 0o640 {
		t.Fatalf("roles file %q mode %v", b, fi.Mode().Perm())
	}
	if after, err := config.Load(cfgPath); err != nil || after.GroupToRole["blue-hunt"] != "ir" {
		t.Fatalf("the written file does not load as written: %v", err)
	}
	if len(rows) != 1 || !strings.HasPrefix(rows[0], admin.RolesSet+" roles file "+rolesPath+" set to sha256:") {
		t.Fatalf("rows = %v", rows)
	}
}

// TestManage_VaultThroughTheAccountsAdapter writes the vault through the
// adapter the accounts socket uses, against the real sops and age, and
// reads it back as serve does. The value is in no answer and no row.
func TestManage_VaultThroughTheAccountsAdapter(t *testing.T) {
	const marker = "cmd-vault-marker-8e2a-not-real"
	secretsFile, ageKeyFile := newServeVaultFixture(t, map[string]string{"EXISTING": "x"})
	for _, p := range []*string{&secretsFile, &ageKeyFile} {
		r, err := filepath.EvalSymlinks(*p)
		if err != nil {
			t.Fatal(err)
		}
		*p = r
	}
	cfg := &config.Config{Admin: config.Admin{ConsoleManages: true}, Vault: config.Vault{SecretsFile: secretsFile, AgeKeyFile: ageKeyFile}}
	me := uint32(os.Getuid())
	old := adminRootOnly
	adminRootOnly = func(uid uint32) bool { return uid == 0 || uid == me }
	t.Cleanup(func() { adminRootOnly = old })
	var rows []string
	deps := accountsManageDeps("/nonexistent", me, me)
	deps.DeclaredSecrets = nil
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return cfg, nil },
		Record: func(_ context.Context, _ *config.Config, rec audit.Record) error {
			rows = append(rows, rec.Tool+" "+rec.Reason)
			return nil
		},
		ManageDeps: deps,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	set, err := svc.SetSecret(ctx, carol, "INTEL_KEY", adminapi.SecretValue{Value: marker})
	if err != nil {
		// A temporary directory a test cannot hold to the ownership rule
		// (another account above it) is the environment, not the code.
		if adminapi.IsCode(err, adminapi.CodeConfigUnavailable) {
			t.Skipf("the temporary directory does not pass the ownership check here: %v", err)
		}
		t.Fatalf("SetSecret: %v", err)
	}
	list, err := svc.ListSecrets(ctx, admin.Actor{Name: "root", Operator: true})
	if err != nil || len(list.Secrets) != 2 {
		t.Fatalf("ListSecrets = %+v, %v", list, err)
	}
	p, err := sopsage.New(ctx, secretsFile, ageKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := p.Resolve(ctx, "INTEL_KEY"); err != nil || s.Value() != marker {
		t.Fatalf("serve does not read the value set: %v", err)
	}
	del, err := svc.DeleteSecret(ctx, carol, "INTEL_KEY")
	if err != nil || !del.Existed {
		t.Fatalf("DeleteSecret = %+v, %v", del, err)
	}
	b, _ := json.Marshal([]any{set, list, del, rows})
	if strings.Contains(string(b), marker) {
		t.Fatalf("the value is in an answer or a row: %s", b)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
}
