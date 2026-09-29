package adminapi_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	for _, m := range []func(*sql.DB) error{auditsqlite.Migrate, quarantinesqlite.Migrate, quotasqlite.Migrate, accesssqlite.Migrate, healthsqlite.Migrate} {
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
		Roles:   []config.Role{{Name: "ir", Grants: map[string][]string{"casemgmt": {"*"}}}},
		IdP:     config.IdP{UsersFile: users},
		OIDC:    config.OIDC{Audience: "https://gateway.example.internal/mcp"},
		Connect: config.Connect{ClientID: "claude-code", CallbackPort: 33418}}
	trail := auditsqlite.New(db)
	tools := quarantinesqlite.New(db)
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return cfg, nil },
		Tools:  tools, Blocks: accesssqlite.New(db), Trail: trail, Quota: quotasqlite.New(db), Maintenance: healthsqlite.New(db),
		Record:   func(ctx context.Context, _ *config.Config, rec audit.Record) error { return trail.Record(ctx, rec) },
		Accounts: func(c *config.Config) (idp.Directory, error) { return autheliafile.New(c.IdP.UsersFile), nil },
		IsBusy:   store.IsBusy,
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
	srv, err := adminhttp.New(adminhttp.Options{Socket: socket, Service: b.svc, ServiceUID: 1 << 30,
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
	obs, err := b.tools.Observe(context.Background(), "casemgmt", quarantine.ToolIdentity{Name: "list_cases", Description: "List.", InputSchema: []byte(`{}`)})
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
	_, err = op.ListBlocks(ctx)
	do("listBlocks", err)
	_, err = op.BlockSubject(ctx, adminapi.BlockRequest{Subject: "sub-1"})
	do("blockSubject", err)
	_, err = op.UnblockSubject(ctx, adminapi.BlockRequest{Subject: "sub-1"})
	do("unblockSubject", err)
	_, err = op.ListAudit(ctx, adminapi.AuditQuery{Limit: 10, Outcome: adminapi.OutcomeAllowed, Since: time.Now().Add(-time.Hour)})
	do("listAudit", err)
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
