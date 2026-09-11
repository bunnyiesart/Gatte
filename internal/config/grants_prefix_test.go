// This file is package config_test for the reason grants_integration_test.go
// states, and it extends that file's harness rather than repeating it: only
// the pieces that differ -- a fleet whose two upstream names are in a prefix
// relationship, and a Repository that hands them over without validating --
// live here.
package config_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// prefixFleet is the fleet the test below needs and the ordinary one cannot
// express: two upstreams whose registered names are "threatintel" and
// "threatintel" plus the namespace separator plus something else.
var prefixFleet = map[string][]string{
	"threatintel":         {"lookup_ip"},
	"threatintel.staging": {"debug_exec"},
}

type prefixDialer struct{}

func (prefixDialer) Dial(_ context.Context, spec gateway.UpstreamSpec, _ map[string]string) (gateway.Upstream, error) {
	tools, ok := prefixFleet[spec.Name]
	if !ok {
		return nil, errors.New("prefixDialer: no such backend " + spec.Name)
	}
	return &fakeUpstream{name: spec.Name, tools: tools}, nil
}

// frozenRegistry serves a fixed list of entries and never validates them.
//
// The SQLite adapter would not do: the entry this test turns on is one
// registry.UpstreamServer.Validate now refuses, so Register cannot be the way
// it gets into the store. A row that predates the rule -- or one written by
// anything other than this binary -- reaches the gateway exactly like this,
// through List, unchecked. That is the state the gateway has to survive, and
// a fake that refused to produce it would test the rule against nothing.
type frozenRegistry struct{ entries []registry.UpstreamServer }

func (r *frozenRegistry) List(context.Context) ([]registry.UpstreamServer, error) {
	return slices.Clone(r.entries), nil
}

func (r *frozenRegistry) Register(context.Context, registry.UpstreamServer) error {
	return errors.New("frozenRegistry: not used in these tests")
}

func (r *frozenRegistry) Get(context.Context, string) (registry.UpstreamServer, error) {
	return registry.UpstreamServer{}, registry.ErrNotFound
}

func (r *frozenRegistry) Deregister(context.Context, string) error { return registry.ErrNotFound }

var _ registry.Repository = (*frozenRegistry)(nil)

// TestGrantDoesNotReachAnUpstreamItOnlyPrefixes is ADR-0016's "resíduo
// conhecido", asserted as behaviour instead of left as a paragraph.
//
// Two readings of one namespaced name meet here. Authorization resolves the
// backend with strings.CutPrefix at the first separator (access.Role.Allows),
// so "threatintel.staging.debug_exec" is, to it, the tool "staging.debug_exec"
// of the backend "threatintel". Routing resolves it by exact lookup on
// Namespaced(registered name, tool), so the same string is the tool
// "debug_exec" of the backend "threatintel.staging". A role whose only grant
// is threatintel = ["*"] therefore used to list and successfully dispatch a
// tool of a backend it never named, on a process the operator never granted
// it.
//
// Nothing here is explained by Tool Quarantine: debug_exec is observed and
// approved before the gateway ever connects, so it is usable and the only
// thing that may keep it away from this role is the grant. That is
// deliberate -- ADR-0016 is explicit that approval is a claim about
// definition integrity, not about who may call.
func TestGrantDoesNotReachAnUpstreamItOnlyPrefixes(t *testing.T) {
	ctx := context.Background()

	db := openDB(t)
	quar := quarantinesqlite.New(db)

	// The operator approves debug_exec: observed first, because Approve
	// refuses a tool the gateway has never seen. The identity is exactly what
	// the fake upstream advertises, so a later observation leaves it approved
	// rather than flipping it to changed.
	staging := quarantine.ToolIdentity{
		Name:        "debug_exec",
		Description: "threatintel.staging debug_exec",
		InputSchema: []byte(`{"type":"object"}`),
	}
	if _, err := quar.Observe(ctx, "threatintel.staging", staging); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if _, err := quar.Approve(ctx, "threatintel.staging", "debug_exec"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(configFor(`
[[role]]
name = "hunter"

  [role.grants]
  threatintel = ["*"]
`, `"soc-hunt" = "hunter"`)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policy, err := cfg.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	reg := &frozenRegistry{}
	for _, name := range []string{"threatintel", "threatintel.staging"} {
		reg.entries = append(reg.entries, registry.UpstreamServer{
			Name:      name,
			Transport: registry.TransportStdio,
			Command:   "/nonexistent/" + name, // prefixDialer never runs it
		})
	}

	gw, err := gateway.New(gateway.Config{
		Registry:   reg,
		Vault:      emptyVault{},
		Quarantine: quar,
		Audit:      auditsqlite.New(db),
		Policy:     policy,
		Dialer:     prefixDialer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	connectErr := gw.Connect(ctx)

	s := &stack{gw: gw, quar: quar}
	s.approve(t, "threatintel", "lookup_ip")

	id := access.Identity{Subject: "hunter-1", Groups: []string{"soc-hunt"}}

	// The one tool of the backend the grant actually names is served, so a
	// gateway that served nothing at all would not pass this by accident.
	if got, want := s.listed(t, id), []string{"threatintel.lookup_ip"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- a %q grant on %q reached a tool of a different registered upstream",
			got, want, access.GrantAll, "threatintel")
	}
	if err := s.dispatch(id, "threatintel.lookup_ip"); err != nil {
		t.Errorf("Dispatch(%q) = %v, want nil", "threatintel.lookup_ip", err)
	}

	// The dangerous half: the call must not land. ErrUnknownTool and not
	// ErrForbidden, because the name is not routed at all -- the upstream
	// whose name would produce it is refused, so there is nothing to forbid.
	if err := s.dispatch(id, "threatintel.staging.debug_exec"); !errors.Is(err, gateway.ErrUnknownTool) {
		t.Errorf("Dispatch(%q) = %v, want ErrUnknownTool -- an approved tool of an upstream the role never named was reachable through a grant on a prefix of its name",
			"threatintel.staging.debug_exec", err)
	}

	// And the operator is told, rather than the upstream disappearing
	// silently: a backend that is registered and not served is a fact
	// somebody has to be able to find out about.
	if connectErr == nil {
		t.Errorf("Connect = nil, want an error naming %q: an upstream whose name contains %q cannot be routed unambiguously and must not be served in silence",
			"threatintel.staging", gateway.NameSeparator)
	} else if !strings.Contains(connectErr.Error(), "threatintel.staging") {
		t.Errorf("Connect = %v, want an error naming %q", connectErr, "threatintel.staging")
	}
}
