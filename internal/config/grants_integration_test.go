// This file is package config_test rather than package config because it
// imports internal/gateway, and internal/config imports internal/gateway.
// An in-package test file would be a cycle; an external test package is
// compiled separately and may depend on both.
//
// It lives in internal/config rather than internal/gateway on purpose: what
// it exercises is the whole of one configuration decision, from the TOML an
// operator writes to what an analyst can see and call. Splitting that across
// two packages would leave the claim ADR-0016 actually makes -- "a tool
// absent from the caller's profile is invisible in tools/list AND refused in
// tools/call" -- asserted in neither.
package config_test

import (
	"context"
	"database/sql"
	"encoding/json"
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
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// -----------------------------------------------------------------------
// A gateway over two fake backends
// -----------------------------------------------------------------------

// fleet is what the fake backends advertise. Two upstreams so the
// cross-backend isolation property has something to leak across, and
// several tools each so a wildcard has something to cover that a named
// grant does not.
var fleet = map[string][]string{
	"casemgmt":    {"list_cases", "get_case", "add_note", "delete_case"},
	"threatintel": {"lookup_ip", "shodan", "virustotal"},
}

// fakeUpstream serves a fixed tool list and echoes the tool name back as
// its result. Nothing here is under test; it exists so the gateway has a
// backend that answers.
type fakeUpstream struct {
	name  string
	tools []string
}

func (u *fakeUpstream) ListTools(context.Context) ([]gateway.ToolDef, error) {
	out := make([]gateway.ToolDef, 0, len(u.tools))
	for _, t := range u.tools {
		out = append(out, gateway.ToolDef{
			Name:        t,
			Description: u.name + " " + t,
			InputSchema: json.RawMessage(`{"type":"object"}`),
		})
	}
	return out, nil
}

func (u *fakeUpstream) CallTool(_ context.Context, tool string, _ json.RawMessage) (gateway.Result, error) {
	return gateway.Result{Content: json.RawMessage(`[{"type":"text","text":"` + u.name + "." + tool + `"}]`)}, nil
}

func (u *fakeUpstream) Close() error { return nil }

type fakeDialer struct{}

func (fakeDialer) Dial(_ context.Context, spec gateway.UpstreamSpec, _ map[string]string) (gateway.Upstream, error) {
	tools, ok := fleet[spec.Name]
	if !ok {
		return nil, errors.New("fakeDialer: no such backend " + spec.Name)
	}
	return &fakeUpstream{name: spec.Name, tools: tools}, nil
}

// emptyVault resolves nothing, which is all these fakes need: no registry
// entry below names an environment variable.
type emptyVault struct{}

func (emptyVault) Resolve(context.Context, string) (vault.Secret, error) {
	return vault.Secret{}, vault.ErrNotFound
}

// configFor renders a whole config file with roles written as the caller
// gives them. Everything outside [[role]] is fixed boilerplate that
// Validate requires; the roles block is the part under test.
func configFor(roles, mapping string) string {
	return `
listen   = "127.0.0.1:9443"
database = "/var/db/mcp-gateway/mcp-gateway.db"

[oidc]
issuer   = "https://id.soc.internal/realms/soc"
audience = "https://gw.soc.internal/mcp"

[vault]
secrets_file = "/usr/local/etc/mcp-gateway/secrets.enc.json"
age_key_file = "/usr/local/etc/mcp-gateway/age.key"

[signer]
require_signed = false
` + roles + `
[group_to_role]
` + mapping + "\n"
}

// stack is a live gateway built from a config file, over the fake fleet.
type stack struct {
	gw   *gateway.Gateway
	quar quarantine.Store
}

func newStack(t *testing.T, roles, mapping string) *stack {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := writeFile(path, configFor(roles, mapping)); err != nil {
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

	db := openDB(t)
	reg := registrysqlite.New(db)
	quar := quarantinesqlite.New(db)

	for name := range fleet {
		if err := reg.Register(context.Background(), registry.UpstreamServer{
			Name:      name,
			Transport: registry.TransportStdio,
			Command:   "/nonexistent/" + name, // fakeDialer never runs it
		}); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}

	gw, err := gateway.New(gateway.Config{
		Registry:   reg,
		Vault:      emptyVault{},
		Quarantine: quar,
		Audit:      auditsqlite.New(db),
		Policy:     policy,
		Dialer:     fakeDialer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	if err := gw.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return &stack{gw: gw, quar: quar}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, migrate := range []func(*sql.DB) error{
		registrysqlite.Migrate, auditsqlite.Migrate, quarantinesqlite.Migrate,
	} {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	return db
}

func writeFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}

// approve puts a tool into the usable set the way an operator does.
func (s *stack) approve(t *testing.T, upstream string, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := s.quar.Approve(context.Background(), upstream, tool); err != nil {
			t.Fatalf("approve %s.%s: %v", upstream, tool, err)
		}
	}
}

// listed returns the namespaced names this identity is shown.
func (s *stack) listed(t *testing.T, id access.Identity) []string {
	t.Helper()
	defs, err := s.gw.ListTools(context.Background(), id)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	out := make([]string, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.Name)
	}
	slices.Sort(out)
	return out
}

// dispatch runs one call and returns the error, if any.
func (s *stack) dispatch(id access.Identity, tool string) error {
	_, err := s.gw.Dispatch(
		context.Background(),
		gateway.Caller{Identity: id, SourceAddress: "127.0.0.1"},
		tool,
		json.RawMessage(`{}`),
	)
	return err
}

// -----------------------------------------------------------------------
// The wildcard does not bypass Tool Quarantine
// -----------------------------------------------------------------------

// TestWildcardGrantServesOnlyApprovedTools is the test ADR-0016 rests on.
//
// The prohibition it lifts was written down with a reason: "a wildcard is
// how a role silently gains a tool that was added to an upstream." If that
// were still true the wildcard would be indefensible. It is not, because
// approval is a separate gate that no grant touches -- and this asserts
// that as behaviour rather than by re-reading quarantine's doc comments.
//
// One role, one grant of ["*"] over the whole of threatintel. Of the three
// tools that backend advertises, two are approved and one is not. The
// unapproved one must be invisible in ListTools AND refused by Dispatch --
// both halves, because the ADR-0036 spec states the property as both and a
// gateway that filtered only the list would still be callable by name.
func TestWildcardGrantServesOnlyApprovedTools(t *testing.T) {
	s := newStack(t,
		`
[[role]]
name = "hunter"

  [role.grants]
  threatintel = ["*"]
`,
		`"soc-hunt" = "hunter"`)

	id := access.Identity{Subject: "hunter-1", Groups: []string{"soc-hunt"}}

	// Nothing is approved yet, so the wildcard reaches nothing. This is the
	// state every fresh upstream starts in: quarantine.NewTool makes each
	// observed tool pending, and Usable is false for a pending tool.
	if got := s.listed(t, id); len(got) != 0 {
		t.Fatalf("a %q grant listed %v before any tool was approved -- the wildcard bypassed Tool Quarantine", access.GrantAll, got)
	}
	if err := s.dispatch(id, "threatintel.lookup_ip"); !errors.Is(err, gateway.ErrUnknownTool) {
		t.Fatalf("Dispatch of an unapproved tool under a wildcard = %v, want ErrUnknownTool", err)
	}

	s.approve(t, "threatintel", "lookup_ip", "shodan")

	want := []string{"threatintel.lookup_ip", "threatintel.shodan"}
	if got := s.listed(t, id); !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- the wildcard must serve the approved tools and only those", got, want)
	}
	for _, tool := range want {
		if err := s.dispatch(id, tool); err != nil {
			t.Errorf("Dispatch(%q) = %v, want nil", tool, err)
		}
	}

	// The third tool of the same backend is inside the grant and outside
	// the approval. It must behave exactly as though it did not exist --
	// not as a 403, which would tell the caller it is there.
	if err := s.dispatch(id, "threatintel.virustotal"); !errors.Is(err, gateway.ErrUnknownTool) {
		t.Errorf("Dispatch of the one unapproved tool = %v, want ErrUnknownTool", err)
	}
	if errors.Is(s.dispatch(id, "threatintel.virustotal"), access.ErrForbidden) {
		t.Error("an unapproved tool inside the grant was refused as forbidden, which tells the caller it exists")
	}

	// And approving it is what makes it usable -- nothing else.
	s.approve(t, "threatintel", "virustotal")
	if got := s.listed(t, id); len(got) != 3 {
		t.Errorf("ListTools = %v, want all three once approved", got)
	}
	if err := s.dispatch(id, "threatintel.virustotal"); err != nil {
		t.Errorf("Dispatch after approval = %v, want nil", err)
	}
}

// TestWildcardGrantStopsAtItsOwnBackend: the wildcard covers one backend.
// The other backend's tools are approved and served to somebody -- so they
// are in the routing table and usable -- and must still be unreachable
// here. Approval and grant are independent gates and this is the case that
// proves the second one is still doing work.
func TestWildcardGrantStopsAtItsOwnBackend(t *testing.T) {
	s := newStack(t,
		`
[[role]]
name = "hunter"

  [role.grants]
  threatintel = ["*"]
`,
		`"soc-hunt" = "hunter"`)

	s.approve(t, "threatintel", "lookup_ip")
	s.approve(t, "casemgmt", "list_cases", "get_case", "add_note", "delete_case")

	id := access.Identity{Subject: "hunter-1", Groups: []string{"soc-hunt"}}

	if got, want := s.listed(t, id), []string{"threatintel.lookup_ip"}; !slices.Equal(got, want) {
		t.Errorf("ListTools = %v, want %v -- an approved tool of another backend reached a wildcard that does not name it", got, want)
	}
	for _, tool := range []string{"casemgmt.list_cases", "casemgmt.delete_case"} {
		err := s.dispatch(id, tool)
		if !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Dispatch(%q) = %v, want ErrForbidden", tool, err)
		}
	}
}

// -----------------------------------------------------------------------
// Isolation between profiles
// -----------------------------------------------------------------------

// TestPerBackendGrantDoesNotLeakIntoARoleLackingIt is the property the
// capability exists for, asserted against a running gateway rather than
// against the policy alone: two roles over one backend fleet produce two
// different, minimal menus.
//
// Every tool in the fleet is approved first, so nothing here is explained
// by quarantine. What each identity does not see, it does not see because
// of its grants.
func TestPerBackendGrantDoesNotLeakIntoARoleLackingIt(t *testing.T) {
	s := newStack(t,
		`
[[role]]
name = "triage"

  [role.grants]
  casemgmt = ["list_cases", "get_case"]

[[role]]
name = "hunter"

  [role.grants]
  threatintel = ["*"]

[[role]]
name = "flat-only"
tools = ["casemgmt.add_note"]

[[role]]
name = "onboarding"
`,
		`"soc-triage" = "triage"
"soc-hunt" = "hunter"
"soc-flat" = "flat-only"
"soc-new" = "onboarding"`)

	for upstream, tools := range fleet {
		s.approve(t, upstream, tools...)
	}

	for _, tc := range []struct {
		group string
		want  []string
	}{
		{"soc-triage", []string{"casemgmt.get_case", "casemgmt.list_cases"}},
		{"soc-hunt", []string{"threatintel.lookup_ip", "threatintel.shodan", "threatintel.virustotal"}},
		{"soc-flat", []string{"casemgmt.add_note"}},
		{"soc-new", nil},
	} {
		t.Run(tc.group, func(t *testing.T) {
			id := access.Identity{Subject: tc.group, Groups: []string{tc.group}}
			got := s.listed(t, id)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ListTools = %v, want %v", got, tc.want)
			}
		})
	}

	// Named crossings, so a failure says which grant leaked where.
	triage := access.Identity{Subject: "t", Groups: []string{"soc-triage"}}
	hunter := access.Identity{Subject: "h", Groups: []string{"soc-hunt"}}
	flat := access.Identity{Subject: "f", Groups: []string{"soc-flat"}}
	for _, tc := range []struct {
		who  access.Identity
		tool string
		why  string
	}{
		{triage, "casemgmt.delete_case", "a tool of a granted backend that the grant does not name"},
		{triage, "threatintel.lookup_ip", "another role's whole-backend wildcard"},
		{triage, "casemgmt.add_note", "another role's flat grant on the same backend"},
		{hunter, "casemgmt.list_cases", "another role's named grant"},
		{flat, "casemgmt.list_cases", "a neighbouring tool on the backend this role holds one tool of"},
		{flat, "threatintel.shodan", "another role's wildcard"},
	} {
		if err := s.dispatch(tc.who, tc.tool); !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Dispatch(%q, %q) = %v, want ErrForbidden -- reached %s", tc.who.Subject, tc.tool, err, tc.why)
		}
	}
}

// -----------------------------------------------------------------------
// The two gates agree
// -----------------------------------------------------------------------

// TestListToolsAndDispatchAgreeUnderGrants is the same property
// access_test's TestAuthorizeAndAllowedToolsAgree asserts one layer down,
// checked here against the two surfaces an analyst actually meets.
//
// The dangerous direction is callable-but-unlisted: a tool that works and
// that no operator reviewing a tool list would ever see. The other
// direction -- listed but refused -- is merely broken. Both are failures
// here, because ADR-0036 states the property as both.
//
// The universe includes tools nobody granted, tools granted but never
// approved, and the near-miss names a prefix implementation would get
// wrong.
func TestListToolsAndDispatchAgreeUnderGrants(t *testing.T) {
	s := newStack(t,
		`
[[role]]
name = "triage"
tools = ["logsearch.search_relative"]

  [role.grants]
  casemgmt = ["list_cases", "get_case"]

[[role]]
name = "hunter"

  [role.grants]
  threatintel = ["*"]
`,
		`"soc-triage" = "triage"
"soc-hunt" = "hunter"`)

	// Everything approved except casemgmt.get_case, so the universe has a
	// granted-but-unapproved member and the property has to hold over it.
	s.approve(t, "casemgmt", "list_cases", "add_note", "delete_case")
	s.approve(t, "threatintel", "lookup_ip", "shodan", "virustotal")

	universe := []string{
		"casemgmt.list_cases",
		"casemgmt.get_case", // granted to triage, never approved
		"casemgmt.add_note",
		"casemgmt.delete_case",
		"threatintel.lookup_ip",
		"threatintel.shodan",
		"threatintel.virustotal",
		"logsearch.search_relative", // named flat by a role; no such backend
		"casemgmt.",
		"casemgmt.*",
		"casemgmt",
		"threatintel.",
		"threatintelx.lookup_ip",
		"*",
		"",
		"unknown.tool",
	}

	for _, groups := range [][]string{
		{"soc-triage"},
		{"soc-hunt"},
		{"soc-triage", "soc-hunt"},
		{"unmapped"},
		nil,
	} {
		name := strings.Join(groups, "+")
		if name == "" {
			name = "no-groups"
		}
		t.Run(name, func(t *testing.T) {
			id := access.Identity{Subject: name, Groups: groups}
			listed := s.listed(t, id)

			for _, tool := range universe {
				err := s.dispatch(id, tool)
				callable := err == nil
				shown := slices.Contains(listed, tool)

				switch {
				case callable && !shown:
					t.Errorf("Dispatch(%q) succeeded but ListTools never offered it: an invisible execution path", tool)
				case shown && !callable:
					t.Errorf("ListTools offered %q but Dispatch = %v: an advertised tool that fails", tool, err)
				}
			}

			// Nothing may appear in the list that the universe does not
			// cover -- otherwise the loop above proves less than it looks.
			for _, tool := range listed {
				if !slices.Contains(universe, tool) {
					t.Errorf("ListTools offered %q, which is outside the tested universe; extend it", tool)
				}
			}
		})
	}
}
