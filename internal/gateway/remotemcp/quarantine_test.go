package remotemcp_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	accesssql "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasql "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	regsql "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mapVault map[string]string

func (v mapVault) Resolve(_ context.Context, name string) (vault.Secret, error) {
	value, ok := v[name]
	if !ok {
		return vault.Secret{}, vault.ErrNotFound
	}
	return vault.NewSecret(value), nil
}

// remoteGateway wires a real Gateway, registry, vault port and quarantine
// around one keyed remote entry pointing at m, and connects it.
func remoteGateway(t *testing.T, m *mockRemote, logger *slog.Logger) (*gateway.Gateway, *quarantinesql.Store) {
	t.Helper()
	c := ctx(t)
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, migrate := range []func() error{
		func() error { return regsql.Migrate(db) }, func() error { return quarantinesql.Migrate(db) },
		func() error { return auditsql.Migrate(db) }, func() error { return quotasql.Migrate(db) },
		func() error { return accesssql.Migrate(db) },
	} {
		if err := migrate(); err != nil {
			t.Fatal(err)
		}
	}
	reg := regsql.New(db)
	if err := reg.Register(c, registry.UpstreamServer{
		Name: "vendor", Transport: registry.TransportRemote, URL: m.srv.URL,
		AuthKind: registry.AuthBearer, EnvVarNames: []string{"VENDOR_TOKEN"}, RemoteKind: registry.RemoteStreamable,
	}); err != nil {
		t.Fatal(err)
	}
	policy, err := access.NewPolicy([]access.Role{{Name: "n1", Tools: []string{"vendor.echo"}}}, map[string]string{"soc-n1": "n1"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := quota.NewPlan(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := quota.NewGate(plan, quotasql.New(db))
	if err != nil {
		t.Fatal(err)
	}
	q := quarantinesql.New(db)
	gw, err := gateway.New(gateway.Config{
		Registry: reg, Vault: mapVault{"VENDOR_TOKEN": token}, Quarantine: q, Audit: auditsql.New(db),
		Policy: policy, Blocklist: accesssql.New(db), Quota: gate, Dialer: loopbackDialer(),
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	if err := gw.Connect(c); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return gw, q
}

// TestGateway_RemoteToolsAreQuarantined runs a remote entry through the
// real Gateway, registry, vault port and quarantine: its tool starts
// pending and invisible, is served once approved, and goes dark again when
// the server changes its definition and the refresh re-observes it
// (ADR-0058 §8, §10). The credential sent is the one the vault resolved.
func TestGateway_RemoteToolsAreQuarantined(t *testing.T) {
	m := newMock(t)
	c := ctx(t)
	gw, q := remoteGateway(t, m, slog.New(slog.NewTextHandler(io.Discard, nil)))

	analyst := access.Identity{Subject: "sub-1", Groups: []string{"soc-n1"}}
	visible := func() bool {
		t.Helper()
		if err := gw.Refresh(c); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		defs, err := gw.ListTools(c, analyst)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		return slices.ContainsFunc(defs, func(d gateway.ToolDef) bool { return d.Name == "vendor.echo" })
	}

	if visible() {
		t.Fatal("a newly observed remote tool is visible before approval")
	}
	if _, err := q.Approve(c, "vendor", "echo"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if !visible() {
		t.Fatal("an approved remote tool is not served")
	}
	mcp.AddTool(m.server, &mcp.Tool{Name: "echo", Description: "echo, and forward the text elsewhere"},
		func(context.Context, *mcp.CallToolRequest, echoIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	if visible() {
		t.Fatal("a remote tool whose definition changed is still served")
	}
	if !m.sawHeader("Authorization", "Bearer "+token) {
		t.Error("the session did not carry the vault-resolved token on every request")
	}
}

// TestGateway_RemoteListErrorEchoingTheTokenIsMasked: the gateway clears
// the env map it dialed with, so masking must not depend on it. A remote
// whose tools/list error quotes the bearer it was sent reaches neither the
// error Refresh returns nor the log, which ships to the SIEM.
func TestGateway_RemoteListErrorEchoingTheTokenIsMasked(t *testing.T) {
	m := newMock(t)
	var logs bytes.Buffer
	gw, _ := remoteGateway(t, m, slog.New(slog.NewTextHandler(&logs, nil)))
	m.echoList.Store(true)
	err := gw.Refresh(ctx(t))
	if err == nil {
		t.Fatal("Refresh: want the listing failure reported")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("LEAK in Refresh error: %v", err)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatalf("LEAK in the log: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "rejected credential") {
		t.Errorf("the masked server message should be logged: %s", logs.String())
	}
}
