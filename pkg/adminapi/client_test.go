package adminapi_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/control"
	controlsqlite "github.com/bunnyiesart/Gatte/internal/control/sqlite"
	healthsqlite "github.com/bunnyiesart/Gatte/internal/health/sqlite"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type backend struct {
	svc   *admin.Service
	tools quarantine.Store
}

func newBackend(t *testing.T) backend {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, m := range []func(*sql.DB) error{auditsqlite.Migrate, quarantinesqlite.Migrate, quotasqlite.Migrate, accesssqlite.Migrate, healthsqlite.Migrate, controlsqlite.Migrate} {
		if err := m(db); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := idp.HashPassword("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(t.TempDir(), "users.yml")
	fixture := "users:\n  ana:\n    displayname: \"Ana\"\n    PWKEY: \"" + hash + "\"\n    groups: [blue-ir]\n"
	if err := os.WriteFile(users, []byte(strings.Replace(fixture, "PWKEY", "pass"+"word", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Database: ":memory:", GroupToRole: map[string]string{"blue-ir": "ir"},
		// ir-act is the role clearTool needs (design/adr/0048): marked
		// non_read and naming the sensitive tool in `tools`; ir's
		// wildcard covers it without reaching it.
		Roles: []config.Role{{Name: "ir", Grants: map[string][]string{"casemgmt": {"*"}}},
			{Name: "ir-act", Tools: []string{"casemgmt.close_case"}, NonRead: true}},
		IdP:     config.IdP{UsersFile: users},
		OIDC:    config.OIDC{Audience: "https://gateway.example.internal/mcp"},
		Connect: config.Connect{ClientID: "claude-code", CallbackPort: 33418},
		// design/adr/0050, so the 1.6.0 operations answer.
		Admin: config.Admin{ConsoleManages: true}, RolesFile: "/etc/gatte/roles.toml"}
	trail := auditsqlite.New(db)
	tools := quarantinesqlite.New(db)
	ctl := controlsqlite.New(db)
	if err := ctl.RecordProcess(context.Background(), control.Process{PID: os.Getpid(), Boot: time.Now()}); err != nil {
		t.Fatal(err)
	}
	svc, err := admin.New(admin.Deps{
		// A stand-in for serve: ringing it answers every pending request
		// as applied, the way serve's SIGHUP handler finishes them.
		Control: ctl,
		Ring: func(control.Process) error {
			pending, err := ctl.Pending(context.Background())
			for _, r := range pending {
				_ = ctl.Finish(context.Background(), r.ID, control.OutcomeApplied, []byte(`{"recorded":false,"messages":["stand-in"]}`), time.Now(), time.Now())
			}
			return err
		},
		Upstreams: func(context.Context, *config.Config) ([]adminapi.Upstream, error) {
			return []adminapi.Upstream{{Name: "casemgmt"}}, nil
		},
		Config: func() (*config.Config, error) { return cfg, nil },
		Tools:  tools, Blocks: accesssqlite.New(db), Trail: trail, Quota: quotasqlite.New(db), Maintenance: healthsqlite.New(db), Health: healthsqlite.New(db),
		Record:   func(ctx context.Context, _ *config.Config, rec audit.Record) error { return trail.Record(ctx, rec) },
		Accounts: func(c *config.Config) (idp.Directory, error) { return autheliafile.New(c.IdP.UsersFile), nil },
		IsBusy:   store.IsBusy,
		// The ports of design/adr/0050 are adapters of the composition
		// root (cmd/mcp-gateway, tested there); here they are stand-ins,
		// and the rules in front of them are the real service's.
		ManageDeps: manageStandIns(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return backend{svc: svc, tools: tools}
}

func serve(t *testing.T, b backend, socket string) string {
	t.Helper()
	me := uint32(os.Getuid())
	sock := filepath.Join(shortDir(t), socket+".sock")
	ln, err := adminhttp.Listen(sock, adminhttp.SocketPolicy{Group: -1, Mode: 0o600, SelfUID: me, OwnDirOK: true,
		Trusted: func(uid uint32) bool { return uid == 0 || uid == me }})
	if err != nil {
		t.Fatal(err)
	}
	// The test's own group as [admin] operator_group: on the accounts
	// socket, signing and the vault are an operator's acts (design/adr/0050).
	gid := uint32(os.Getgid())
	srv, err := adminhttp.New(adminhttp.Options{Socket: socket, Service: b.svc, ServiceUID: 1 << 30, OperatorGID: &gid,
		LookupUser: func(uint32) (string, error) { return "alice", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return sock
}

// operationIDs lists every operationId in api/admin.openapi.yaml.
func operationIDs(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "admin.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ops := range doc.Paths {
		for _, op := range ops {
			out = append(out, op.OperationID)
		}
	}
	sort.Strings(out)
	return out
}

// TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend.
func TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend(t *testing.T) {
	b := newBackend(t)
	obs, err := b.tools.Observe(context.Background(), "casemgmt", quarantine.ToolIdentity{Name: "list_cases", Description: "List.", InputSchema: []byte(`{}`)}, quarantine.ClassSafe)
	if err != nil {
		t.Fatal(err)
	}
	op := adminapi.New(serve(t, b, adminapi.SocketOperator), adminapi.WithFront("test"), adminapi.WithServerUID(uint32(os.Geteuid())))
	acc := adminapi.NewAccounts(serve(t, b, adminapi.SocketAccounts), adminapi.WithFront("test"), adminapi.WithAccountsServerUIDForTest(uint32(os.Geteuid())))
	ctx := context.Background()

	covered := map[string]error{}
	do := func(id string, err error) { covered[id] = err }
	_, err = op.WhoAmI(ctx)
	do("whoAmI", err)
	_, err = op.Overview(ctx)
	do("overview", err)
	_, err = op.ListTools(ctx, "", "")
	do("listTools", err)
	rv, err := op.ReviewTool(ctx, "casemgmt", "list_cases")
	do("reviewTool", err)
	if err == nil && rv.Observed.Fingerprint != obs.Tool.ObservedHash {
		t.Errorf("review fingerprint %s, want %s", rv.Observed.Fingerprint, obs.Tool.ObservedHash)
	}
	_, err = op.ApproveTool(ctx, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: obs.Tool.ObservedHash})
	do("approveTool", err)
	_, err = op.RevokeTool(ctx, adminapi.ToolRef{Server: "casemgmt", Tool: "list_cases"})
	do("revokeTool", err)
	// clearTool (1.5.0): a sensitive tool, approved through the store so
	// it is not in the review set below, cleared through the client.
	if _, err := b.tools.Observe(ctx, "casemgmt", quarantine.ToolIdentity{Name: "close_case", Description: "Close.", InputSchema: []byte(`{}`)}, quarantine.ClassSensitive); err != nil {
		t.Fatal(err)
	}
	if _, err := b.tools.Approve(ctx, "casemgmt", "close_case"); err != nil {
		t.Fatal(err)
	}
	cleared, err := op.ClearTool(ctx, adminapi.ToolRef{Server: "casemgmt", Tool: "close_case"})
	do("clearTool", err)
	if err == nil && (!cleared.Changed || !cleared.Tool.Usable || cleared.Tool.Class != adminapi.ClassSensitive || len(cleared.ClearedBy) != 1 || !cleared.ClearedBy[0].NonRead) {
		t.Errorf("clearTool = %+v", cleared)
	}
	set, err := op.ReviewToolSet(ctx, "casemgmt")
	do("reviewToolSet", err)
	if err == nil && (len(set.Tools) != 1 || set.Manifest == "" || !set.Approvable) {
		t.Errorf("review set %+v", set)
	}
	approvedSet, err := op.ApproveToolSet(ctx, adminapi.ApproveSetRequest{Server: "casemgmt", Manifest: set.Manifest})
	do("approveToolSet", err)
	if err == nil && (!approvedSet.Changed || len(approvedSet.Approved) != 1 || len(approvedSet.Rows) != 1 || !strings.Contains(approvedSet.Rows[0].Reason, "[test]")) {
		t.Errorf("approve set %+v", approvedSet)
	}
	_, err = op.ListBlocks(ctx)
	do("listBlocks", err)
	end := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	_, err = op.BlockSubject(ctx, adminapi.BlockRequest{Subject: "sub-1", Until: &end})
	do("blockSubject", err)
	if bl, err := op.ListBlocks(ctx); err != nil || len(bl.Blocks) != 1 || bl.Blocks[0].Until == nil || !bl.Blocks[0].Until.Equal(end) || bl.Blocks[0].Expired {
		t.Errorf("blocks after a block with an end: %+v, %v", bl, err)
	}
	_, err = op.UnblockSubject(ctx, adminapi.BlockRequest{Subject: "sub-1"})
	do("unblockSubject", err)
	_, err = op.ListAudit(ctx, adminapi.AuditQuery{Limit: 10, Outcome: adminapi.OutcomeAllowed, Since: time.Now().Add(-time.Hour)})
	do("listAudit", err)
	// design/adr/0046: tool, server and until reach the backend.
	if p, err := op.ListAudit(ctx, adminapi.AuditQuery{Tool: "(access block)", Server: "(gateway)", Until: time.Now().Add(time.Minute)}); err != nil || len(p.Records) != 1 {
		t.Errorf("listAudit by tool: %+v, %v; want the one (access block) row", p, err)
	}
	if p, err := op.ListAudit(ctx, adminapi.AuditQuery{Tool: "(access block)", Until: time.Now().Add(-time.Hour)}); err != nil || len(p.Records) != 0 {
		t.Errorf("listAudit until an hour ago: %+v, %v; want nothing", p, err)
	}
	_, err = op.VerifyAudit(ctx, adminapi.VerifyRequest{})
	do("verifyAudit", err)
	_, err = op.ListUpstreams(ctx)
	do("listUpstreams", err)
	started, err := op.StartMaintenance(ctx, adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: `Atualização do "Gatte"`})
	do("startMaintenance", err)
	if err == nil && (!started.Changed || started.Maintenance == nil || started.Maintenance.SetBy != "(operator:alice)") {
		t.Errorf("startMaintenance = %+v", started)
	}
	listed, err := op.ListMaintenance(ctx)
	do("listMaintenance", err)
	if err == nil && (listed.Gateway == nil || listed.Gateway.Message != `Atualização do "Gatte"`) {
		t.Errorf("listMaintenance = %+v", listed)
	}
	_, err = op.EndMaintenance(ctx, adminapi.MaintenanceTarget{Scope: adminapi.ScopeGateway})
	do("endMaintenance", err)
	reloaded, err := op.Reload(ctx)
	do("reloadConfig", err)
	if err == nil && (reloaded.State != adminapi.ServeStateDone || reloaded.Outcome != adminapi.ServeOutcomeApplied || reloaded.RequestedBy != "(operator:alice)") {
		t.Errorf("reloadConfig = %+v", reloaded)
	}
	redialed, err := op.RedialUpstream(ctx, adminapi.RedialRequest{Upstream: "casemgmt"})
	do("redialUpstream", err)
	if err == nil && (redialed.Kind != adminapi.ServeKindRedial || redialed.Upstream != "casemgmt") {
		t.Errorf("redialUpstream = %+v", redialed)
	}
	again, err := op.ServeRequestByID(ctx, reloaded.ID)
	do("serveRequest", err)
	if err == nil && again.ID != reloaded.ID {
		t.Errorf("serveRequest = %+v", again)
	}
	_, err = op.QuotaUsage(ctx, adminapi.QuotaQuery{})
	do("quotaUsage", err)
	_, err = op.People(ctx)
	do("people", err)
	_, err = op.Connect(ctx, "ana")
	do("connect", err)
	script, name, err := op.ConnectScript(ctx, adminapi.OSLinux, "ana")
	do("connectScript", err)
	if err == nil && (name != "connect-gatte.sh" || !strings.HasPrefix(script, "#!/bin/sh")) {
		t.Errorf("connect script %q: %.40q", name, script)
	}
	_, err = acc.AssignableGroups(ctx)
	do("assignableGroups", err)
	_, err = acc.ListAccounts(ctx)
	do("listAccounts", err)
	_, err = acc.CheckAccount(ctx, adminapi.AccountDraft{DisplayName: "Bruno Lima"})
	do("checkAccount", err)
	added, err := acc.AddAccount(ctx, adminapi.NewAccount{Username: "bruno", DisplayName: "Bruno", Groups: []string{"blue-ir"}})
	do("addAccount", err)
	if err == nil && added.OneTimePassword == "" {
		t.Error("addAccount returned no one-time password")
	}
	_, err = acc.GetAccount(ctx, "bruno")
	do("getAccount", err)
	_, err = acc.DisableAccount(ctx, "bruno")
	do("disableAccount", err)
	_, err = acc.EnableAccount(ctx, "bruno")
	do("enableAccount", err)
	_, err = acc.ResetAccountPassword(ctx, "bruno")
	do("resetAccountPassword", err)
	off, err := acc.OffboardAccount(ctx, "ana", adminapi.OffboardRequest{Reason: "left the team"})
	do("offboardAccount", err)
	if err == nil && (!off.Changed || !off.Disabled || off.Blocked || len(off.Remaining) == 0 || len(off.Rows) != 2) {
		t.Errorf("offboardAccount = %+v", off)
	}
	_, err = acc.DeleteAccount(ctx, "ana")
	do("deleteAccount", err)
	// 1.6.0 (design/adr/0050).
	if me, err := op.WhoAmI(ctx); err != nil || !slices.Contains(me.Features, adminapi.FeatureConsoleManages) {
		t.Errorf("whoami with console_manages on: %+v, %v", me.Features, err)
	}
	reg, err := op.RegisterUpstream(ctx, adminapi.RegisterUpstreamRequest{Name: "intel", URL: "https://api.example.org", OpenAPIDocument: "{}", AuthKind: "bearer", KeyName: "INTEL_KEY"})
	do("registerUpstream", err)
	if err == nil && (!reg.Changed || !reg.Recorded || len(reg.Tools) != 1 || reg.Audit.Tool != "(upstream register)") {
		t.Errorf("registerUpstream = %+v", reg)
	}
	detail, err := op.GetUpstream(ctx, "intel")
	do("getUpstream", err)
	if err == nil && (detail.Name != "intel" || detail.Auth == nil || detail.Auth.Secret != "INTEL_KEY") {
		t.Errorf("getUpstream = %+v", detail)
	}
	signed, err := acc.SignUpstream(ctx, "intel")
	do("signUpstream", err)
	if err == nil && (signed.KeyFingerprint == "" || signed.Audit == nil || !strings.Contains(signed.Audit.Reason, signed.KeyFingerprint)) {
		t.Errorf("signUpstream = %+v", signed)
	}
	const marker = "client-marker-value-31c7"
	setRes, err := acc.SetSecret(ctx, "INTEL_KEY", marker)
	do("setSecret", err)
	if err == nil && (!setRes.Changed || setRes.Audit == nil || setRes.Audit.Tool != "(secret set)") {
		t.Errorf("setSecret = %+v", setRes)
	}
	secrets, err := acc.ListSecrets(ctx)
	do("listSecrets", err)
	if err == nil && (len(secrets.Secrets) != 1 || secrets.Secrets[0].Name != "INTEL_KEY" || !secrets.Secrets[0].InVault) {
		t.Errorf("listSecrets = %+v", secrets)
	}
	if b, _ := json.Marshal([]any{setRes, secrets}); strings.Contains(string(b), marker) {
		t.Error("a secret value came back")
	}
	_, err = acc.DeleteSecret(ctx, "INTEL_KEY")
	do("deleteSecret", err)
	roles, err := acc.GetRoles(ctx)
	do("getRoles", err)
	if err == nil && roles.Path != "/etc/gatte/roles.toml" {
		t.Errorf("getRoles = %+v", roles)
	}
	put, err := acc.PutRoles(ctx, roles.Text+"\n# edited\n")
	do("putRoles", err)
	if err == nil && (!put.Changed || !put.ReloadNeeded) {
		t.Errorf("putRoles = %+v", put)
	}
	if _, err := op.DeregisterUpstream(ctx, "intel", "inte"); !adminapi.IsCode(err, adminapi.CodeInvalidArgument) {
		t.Errorf("deregister with a wrong confirm: %v", err)
	}
	dereg, err := op.DeregisterUpstream(ctx, "intel", "intel")
	do("deregisterUpstream", err)
	if err == nil && (!dereg.Changed || !dereg.Registered) {
		t.Errorf("deregisterUpstream = %+v", dereg)
	}

	// Last: with no group left, the account is out of a non-root peer's
	// reach (design/adr/0040 §1).
	_, err = acc.SetAccountGroups(ctx, "bruno", []string{})
	do("setAccountGroups", err)

	for _, id := range operationIDs(t) {
		err, ok := covered[id]
		if !ok {
			t.Errorf("operation %s has no client call in this test", id)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	for id := range covered {
		found := false
		for _, want := range operationIDs(t) {
			found = found || want == id
		}
		if !found {
			t.Errorf("the client calls %s, which is not in the contract", id)
		}
	}
}

// TestClient_RefusesAnAccountsSocketServedByAnyoneButRoot: a fake socket
// put in place by another account cannot collect account creations.
func TestClient_RefusesAnAccountsSocketServedByAnyoneButRoot(t *testing.T) {
	b := newBackend(t)
	// Run as root, this test's own server would be uid 0 and genuine.
	if os.Geteuid() != 0 {
		acc := adminapi.NewAccounts(serve(t, b, adminapi.SocketAccounts))
		_, err := acc.AddAccount(context.Background(), adminapi.NewAccount{Username: "bruno", DisplayName: "Bruno", Groups: []string{"blue-ir"}})
		if !errors.Is(err, adminapi.ErrImpostor) {
			t.Fatalf("an accounts socket served by uid %d: %v, want ErrImpostor", os.Geteuid(), err)
		}
	}
	op := adminapi.New(serve(t, b, adminapi.SocketOperator), adminapi.WithServerUID(uint32(os.Geteuid()+1)))
	if _, err := op.WhoAmI(context.Background()); !errors.Is(err, adminapi.ErrImpostor) {
		t.Fatalf("an operator socket served by an unpinned uid: %v, want ErrImpostor", err)
	}
}

// TestClient_OmitsOptionalFieldsLeftAtZero: a newer optional field is sent
// only when set, so an older backend that refuses unknown fields keeps
// working.
func TestClient_OmitsOptionalFieldsLeftAtZero(t *testing.T) {
	sock := filepath.Join(shortDir(t), "f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(chan string, 4)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"changed":true,"recorded":true,"messages":[],"subject":"sub-1"}`)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := adminapi.New(sock)
	if _, err := c.BlockSubject(context.Background(), adminapi.BlockRequest{Subject: "sub-1"}); err != nil {
		t.Fatal(err)
	}
	if got := <-bodies; strings.Contains(got, "reason") {
		t.Fatalf("body %s carries the unset optional field", got)
	}
	if _, err := c.VerifyAudit(context.Background(), adminapi.VerifyRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := <-bodies; strings.Contains(got, "expect_head") {
		t.Fatalf("body %s carries the unset optional field", got)
	}
}

// memVault and memRoles are in-memory stand-ins for the vault and the
// roles file.
type memVault struct{ values map[string][]byte }

func (v *memVault) Names(context.Context, *config.Config) ([]string, error) {
	var out []string
	for n := range v.values {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (v *memVault) Set(_ context.Context, _ *config.Config, name string, value []byte) (bool, error) {
	_, ok := v.values[name]
	v.values[name] = append([]byte(nil), value...)
	return ok, nil
}

func (v *memVault) Delete(_ context.Context, _ *config.Config, name string) (bool, error) {
	_, ok := v.values[name]
	delete(v.values, name)
	return ok, nil
}

type memRoles struct{ text []byte }

func (r *memRoles) Read(*config.Config) ([]byte, error)    { return r.text, nil }
func (r *memRoles) Write(_ *config.Config, b []byte) error { r.text = b; return nil }

func manageStandIns() admin.ManageDeps {
	registered := map[string]adminapi.RegisterUpstreamRequest{}
	return admin.ManageDeps{
		UpstreamDetail: func(_ context.Context, _ *config.Config, name string) (adminapi.UpstreamDetail, error) {
			r, ok := registered[name]
			if !ok {
				return adminapi.UpstreamDetail{}, adminapi.NewError(adminapi.CodeNotFound, "no registered backend is named %q", name)
			}
			return adminapi.UpstreamDetail{Upstream: adminapi.Upstream{Name: name, Transport: "http", URL: r.URL, EnvVarNames: []string{r.KeyName}, Signature: "no"},
				Auth: &adminapi.UpstreamAuth{Kind: r.AuthKind, Secret: r.KeyName}}, nil
		},
		RegisterHTTP: func(_ context.Context, _ *config.Config, req adminapi.RegisterUpstreamRequest) (adminapi.RegisterUpstreamResult, error) {
			registered[req.Name] = req
			return adminapi.RegisterUpstreamResult{Name: req.Name, URL: req.URL, Source: "the document sent", Signature: "no",
				Auth: adminapi.UpstreamAuth{Kind: req.AuthKind, Secret: req.KeyName}, Tools: []adminapi.UpstreamOperation{{Name: "list", Method: "GET", Path: "/items"}}}, nil
		},
		Deregister: func(_ context.Context, _ *config.Config, name string) (adminapi.DeregisterResult, error) {
			_, ok := registered[name]
			delete(registered, name)
			return adminapi.DeregisterResult{Registered: ok}, nil
		},
		Sign: func(context.Context, *config.Config, string) (admin.SignOutcome, error) {
			return admin.SignOutcome{KeyFingerprint: "SHA256:stand-in", Trusted: true}, nil
		},
		Vault:         &memVault{values: map[string][]byte{}},
		Roles:         &memRoles{text: []byte("[[role]]\nname = \"ir\"\ntools = []\n")},
		ValidateRoles: func([]byte) error { return nil },
	}
}
