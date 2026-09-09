package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

// completeConfig is a file that sets every field explicitly, including the
// ones that have defaults. Tests that want to exercise a specific failure
// remove exactly one thing from it, so a failing test points at the thing
// that was removed rather than at some unrelated omission.
const completeConfig = `
listen   = "0.0.0.0:9443"
database = "/var/db/mcp-gateway/mcp-gateway.db"

[oidc]
issuer                = "https://id.soc.internal/realms/soc"
audience              = "https://gw.soc.internal/mcp"
groups_claim          = "soc_groups"
authorization_servers = ["https://id.soc.internal/realms/soc", "https://id2.soc.internal/realms/soc"]

[vault]
secrets_file = "/usr/local/etc/mcp-gateway/secrets.enc.json"
age_key_file = "/usr/local/etc/mcp-gateway/age.key"

[signer]
key_file       = "/usr/local/etc/mcp-gateway/signing.key"
require_signed = true

[[role]]
name  = "n1-triage"
tools = ["casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"]

[[role]]
name  = "dfir-lead"
tools = ["casemgmt.list_cases", "docsearch.search", "threatintel.virustotal"]

[group_to_role]
"soc-n1"   = "n1-triage"
"soc-dfir" = "dfir-lead"
`

// minimalConfig sets only what is required, so the defaults are what fills
// in the rest. Deliberately does NOT set listen, groups_claim or
// authorization_servers.
const minimalConfig = `
database = "/var/db/mcp-gateway/mcp-gateway.db"

[oidc]
issuer   = "https://id.soc.internal/realms/soc"
audience = "https://gw.soc.internal/mcp"

[vault]
secrets_file = "/usr/local/etc/mcp-gateway/secrets.enc.json"
age_key_file = "/usr/local/etc/mcp-gateway/age.key"
`

// writeConfig writes contents to a temp file and returns its path.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

// withoutLine returns contents with the (single) line containing substr
// removed. It fails the test if substr is absent, so a fixture edit that
// invalidates a test's premise is caught immediately rather than turning
// the test into a tautology.
func withoutLine(t *testing.T, contents, substr string) string {
	t.Helper()
	lines := strings.Split(contents, "\n")
	out := make([]string, 0, len(lines))
	found := false
	for _, line := range lines {
		if strings.Contains(line, substr) {
			found = true
			continue
		}
		out = append(out, line)
	}
	if !found {
		t.Fatalf("fixture has no line containing %q -- the fixture changed and this test no longer tests what it says", substr)
	}
	return strings.Join(out, "\n")
}

func mustLoad(t *testing.T, contents string) *Config {
	t.Helper()
	c, err := Load(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	return c
}

func loadErr(t *testing.T, contents string) error {
	t.Helper()
	c, err := Load(writeConfig(t, contents))
	if err == nil {
		t.Fatalf("Load: expected an error, got a usable config: %+v", c)
	}
	return err
}

// -----------------------------------------------------------------------
// The happy path
// -----------------------------------------------------------------------

func TestLoadCompleteFile(t *testing.T) {
	c := mustLoad(t, completeConfig)

	if c.Listen != "0.0.0.0:9443" {
		t.Errorf("Listen = %q, want the configured value", c.Listen)
	}
	if c.Database != "/var/db/mcp-gateway/mcp-gateway.db" {
		t.Errorf("Database = %q", c.Database)
	}
	if c.OIDC.Issuer != "https://id.soc.internal/realms/soc" {
		t.Errorf("OIDC.Issuer = %q", c.OIDC.Issuer)
	}
	if c.OIDC.Audience != "https://gw.soc.internal/mcp" {
		t.Errorf("OIDC.Audience = %q", c.OIDC.Audience)
	}
	if c.OIDC.GroupsClaim != "soc_groups" {
		t.Errorf("OIDC.GroupsClaim = %q, want the configured value, not the default", c.OIDC.GroupsClaim)
	}
	wantServers := []string{
		"https://id.soc.internal/realms/soc",
		"https://id2.soc.internal/realms/soc",
	}
	if !reflect.DeepEqual(c.OIDC.AuthorizationServers, wantServers) {
		t.Errorf("OIDC.AuthorizationServers = %v, want %v", c.OIDC.AuthorizationServers, wantServers)
	}
	if c.Vault.SecretsFile != "/usr/local/etc/mcp-gateway/secrets.enc.json" {
		t.Errorf("Vault.SecretsFile = %q", c.Vault.SecretsFile)
	}
	if c.Vault.AgeKeyFile != "/usr/local/etc/mcp-gateway/age.key" {
		t.Errorf("Vault.AgeKeyFile = %q", c.Vault.AgeKeyFile)
	}
	if c.Signer.KeyFile != "/usr/local/etc/mcp-gateway/signing.key" {
		t.Errorf("Signer.KeyFile = %q", c.Signer.KeyFile)
	}
	if !c.Signer.RequireSigned {
		t.Error("Signer.RequireSigned = false, want true -- the file sets it, and a security setting that does not survive parsing is the whole failure mode this package guards")
	}

	if len(c.Roles) != 2 {
		t.Fatalf("len(Roles) = %d, want 2", len(c.Roles))
	}
	if c.Roles[0].Name != "n1-triage" {
		t.Errorf("Roles[0].Name = %q", c.Roles[0].Name)
	}
	wantTools := []string{"casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"}
	if !reflect.DeepEqual(c.Roles[0].Tools, wantTools) {
		t.Errorf("Roles[0].Tools = %v, want %v", c.Roles[0].Tools, wantTools)
	}
	wantMapping := map[string]string{"soc-n1": "n1-triage", "soc-dfir": "dfir-lead"}
	if !reflect.DeepEqual(c.GroupToRole, wantMapping) {
		t.Errorf("GroupToRole = %v, want %v", c.GroupToRole, wantMapping)
	}
}

// TestLoadAppliesDocumentedDefaults pins every default config.example.toml
// promises. A default that drifts from what the example file documents is
// a lie an operator has no way to detect.
func TestLoadAppliesDocumentedDefaults(t *testing.T) {
	c := mustLoad(t, minimalConfig)

	if c.Listen != DefaultListen {
		t.Errorf("Listen = %q, want the loopback default %q -- an unconfigured gateway must not be reachable from the network", c.Listen, DefaultListen)
	}
	if c.OIDC.GroupsClaim != DefaultGroupsClaim {
		t.Errorf("OIDC.GroupsClaim = %q, want %q", c.OIDC.GroupsClaim, DefaultGroupsClaim)
	}
	want := []string{"https://id.soc.internal/realms/soc"}
	if !reflect.DeepEqual(c.OIDC.AuthorizationServers, want) {
		t.Errorf("OIDC.AuthorizationServers = %v, want it defaulted to [issuer] %v", c.OIDC.AuthorizationServers, want)
	}

	// Not a default: the optional signer key stays empty, and
	// require_signed stays false. Both are asserted so that "optional"
	// cannot quietly become "invented".
	if c.Signer.KeyFile != "" {
		t.Errorf("Signer.KeyFile = %q, want empty -- a signing key must never be guessed", c.Signer.KeyFile)
	}
	if c.Signer.RequireSigned {
		t.Error("Signer.RequireSigned = true with nothing in the file; the ADR-0006 default is false until the Operator Console can sign at volume")
	}
}

// TestAudienceHasNoDefault is separate from the other required-field cases
// on purpose, because the reason it is required is not "we need a value"
// but a specific security property.
//
// Every other missing field could, in principle, be given a plausible
// default. Audience could not. `aud` is what distinguishes a token minted
// for THIS gateway from a token minted for some other service of the same
// IdP -- the internal wiki, Grafana, anything. Defaulting it (to the
// issuer, to the listen address, to anything at all) would mean accepting
// a token nobody issued for this resource, which is exactly the confused
// deputy RFC 8707's resource indicators exist to prevent. So: no default,
// not even a "sensible" one, and this test exists to keep someone from
// adding one later as a convenience.
func TestAudienceHasNoDefault(t *testing.T) {
	err := loadErr(t, withoutLine(t, minimalConfig, "audience"))

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "oidc.audience") {
		t.Errorf("error does not name oidc.audience: %v", err)
	}

	// And prove no value was invented on the way out: Validate must not
	// have quietly filled it in from the issuer.
	c := &Config{
		Database: "/tmp/x.db",
		OIDC:     OIDC{Issuer: "https://id.soc.internal/realms/soc"},
		Vault:    Vault{SecretsFile: "/tmp/s.json", AgeKeyFile: "/tmp/age.key"},
	}
	_ = c.Validate()
	if c.OIDC.Audience != "" {
		t.Errorf("Validate populated OIDC.Audience with %q -- an audience must never be defaulted (RFC 8707)", c.OIDC.Audience)
	}
}

// -----------------------------------------------------------------------
// Unknown keys
// -----------------------------------------------------------------------

// TestLoadRejectsUnknownKey uses a realistic typo rather than a nonsense
// key, because the realistic one is the whole argument: `require_signd`
// parses fine, is dropped by a permissive decoder, and leaves a file that
// reads as though signature enforcement were on while the process runs
// with it off.
func TestLoadRejectsUnknownKey(t *testing.T) {
	contents := strings.Replace(completeConfig, "require_signed = true", "require_signd = true", 1)
	err := loadErr(t, contents)

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "require_signd") {
		t.Errorf("error does not name the offending key %q -- an operator has to be told which key, not merely that one is wrong: %v", "require_signd", err)
	}
}

func TestLoadRejectsUnknownKeyVariants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(string) string
		wantKey  string
		wantAlso string
	}{
		{
			name:    "top level typo",
			mutate:  func(s string) string { return strings.Replace(s, "database =", "databse =", 1) },
			wantKey: "databse",
		},
		{
			name:    "nested typo keeps its table prefix",
			mutate:  func(s string) string { return strings.Replace(s, "groups_claim", "group_claim", 1) },
			wantKey: "oidc.group_claim",
		},
		{
			name:    "unknown table",
			mutate:  func(s string) string { return s + "\n[telemetry]\nendpoint = \"https://otel.soc.internal\"\n" },
			wantKey: "telemetry",
		},
		{
			name: "unknown key inside a role",
			mutate: func(s string) string {
				return strings.Replace(s, `name  = "dfir-lead"`, `name  = "dfir-lead"`+"\nallow_all = true", 1)
			},
			wantKey: "allow_all",
		},
		{
			name: "several at once are all reported",
			mutate: func(s string) string {
				s = strings.Replace(s, "require_signed = true", "require_signd = true", 1)
				return strings.Replace(s, "listen  ", "lisen   ", 1)
			},
			wantKey:  "require_signd",
			wantAlso: "lisen",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadErr(t, tc.mutate(completeConfig))
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Errorf("error does not name %q: %v", tc.wantKey, err)
			}
			if tc.wantAlso != "" && !strings.Contains(err.Error(), tc.wantAlso) {
				t.Errorf("error does not name %q as well: %v", tc.wantAlso, err)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Required fields
// -----------------------------------------------------------------------

func TestLoadRequiresEachField(t *testing.T) {
	for _, tc := range []struct {
		name      string
		omitLine  string
		wantNamed string
	}{
		{"database", "database =", "database"},
		{"oidc.issuer", "issuer   =", "oidc.issuer"},
		{"oidc.audience", "audience =", "oidc.audience"},
		{"vault.secrets_file", "secrets_file", "vault.secrets_file"},
		{"vault.age_key_file", "age_key_file", "vault.age_key_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadErr(t, withoutLine(t, minimalConfig, tc.omitLine))
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("error does not name the missing field %q: %v", tc.wantNamed, err)
			}
		})
	}
}

// TestLoadReportsEveryProblemAtOnce is the reason Validate uses
// errors.Join rather than returning on the first problem. An operator who
// fixes configuration one error per restart, on a jail they have to ssh
// into, spends an afternoon on a file they could have fixed in one pass.
func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	contents := minimalConfig
	contents = withoutLine(t, contents, "database =")
	contents = withoutLine(t, contents, "audience =")
	contents = withoutLine(t, contents, "age_key_file")

	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error does not wrap ErrInvalid: %v", err)
	}

	for _, want := range []string{"database", "oidc.audience", "vault.age_key_file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q -- all three missing fields must be reported in one run, not one per restart.\ngot: %v", want, err)
		}
	}
}

func TestLoadRejectsNonAbsoluteIssuer(t *testing.T) {
	contents := strings.Replace(minimalConfig, `"https://id.soc.internal/realms/soc"`, `"id.soc.internal/realms/soc"`, 1)
	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "oidc.issuer") {
		t.Errorf("error does not name oidc.issuer: %v", err)
	}
}

// -----------------------------------------------------------------------
// Roles and the group mapping
// -----------------------------------------------------------------------

// TestUndefinedRoleInMappingRejectedAtLoad: a group mapped to a role that
// does not exist -- a renamed [[role]] with a forgotten mapping, most
// likely -- must stop the process at startup. The alternative is that it
// silently denies a real analyst their tools, and the moment they notice
// is the moment they need the tools.
func TestUndefinedRoleInMappingRejectedAtLoad(t *testing.T) {
	contents := strings.Replace(completeConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-leed"`, 1)
	err := loadErr(t, contents)

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "dfir-leed") {
		t.Errorf("error does not name the undefined role: %v", err)
	}
	if !strings.Contains(err.Error(), "soc-dfir") {
		t.Errorf("error does not name the group that points at it: %v", err)
	}
}

func TestDuplicateRoleRejected(t *testing.T) {
	contents := completeConfig + `
[[role]]
name  = "n1-triage"
tools = ["docsearch.search"]
`
	err := loadErr(t, contents)

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "n1-triage") {
		t.Errorf("error does not name the duplicated role: %v", err)
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("error does not say the role is duplicated: %v", err)
	}
}

// TestRoleWithNoToolsIsAccepted: a role that grants nothing is a
// legitimate thing to define -- someone who may authenticate but may not
// act, which is how you confirm the identity path works before granting
// any tool. It must not be mistaken for an incomplete role.
func TestRoleWithNoToolsIsAccepted(t *testing.T) {
	contents := completeConfig + `
[[role]]
name  = "onboarding"
tools = []
`
	contents = strings.Replace(contents, "[group_to_role]", "[group_to_role]\n\"soc-onboarding\" = \"onboarding\"", 1)

	c := mustLoad(t, contents)

	var found bool
	for _, r := range c.Roles {
		if r.Name == "onboarding" {
			found = true
			if len(r.Tools) != 0 {
				t.Errorf("onboarding role has tools %v, want none", r.Tools)
			}
		}
	}
	if !found {
		t.Fatal("the empty role was dropped during load")
	}

	// And it must be fail-closed once it reaches the domain: a member of
	// that group may call nothing at all.
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	id := access.Identity{Subject: "u-new", Groups: []string{"soc-onboarding"}}
	if tools := policy.AllowedTools(id); len(tools) != 0 {
		t.Errorf("AllowedTools = %v, want none", tools)
	}
	if err := policy.Authorize(id, "casemgmt.list_cases"); !errors.Is(err, access.ErrForbidden) {
		t.Errorf("Authorize = %v, want ErrForbidden", err)
	}
}

func TestRoleWithEmptyToolNameRejected(t *testing.T) {
	contents := strings.Replace(completeConfig, `"threatintel.lookup_ip"`, `""`, 1)
	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "empty tool name") {
		t.Errorf("error does not describe the empty tool name: %v", err)
	}
}

// -----------------------------------------------------------------------
// ToAccessPolicy
// -----------------------------------------------------------------------

func TestToAccessPolicyMatchesTheFile(t *testing.T) {
	c := mustLoad(t, completeConfig)
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	for _, tc := range []struct {
		name   string
		groups []string
		want   []string
	}{
		{
			name:   "n1 gets exactly the n1-triage list",
			groups: []string{"soc-n1"},
			want:   []string{"casemgmt.get_case", "casemgmt.list_cases", "threatintel.lookup_ip"},
		},
		{
			name:   "dfir gets exactly the dfir-lead list",
			groups: []string{"soc-dfir"},
			want:   []string{"casemgmt.list_cases", "docsearch.search", "threatintel.virustotal"},
		},
		{
			// Overlapping tools across two roles are unioned, not doubled.
			name:   "both groups union and deduplicate",
			groups: []string{"soc-n1", "soc-dfir"},
			want: []string{
				"casemgmt.get_case", "casemgmt.list_cases", "docsearch.search",
				"threatintel.lookup_ip", "threatintel.virustotal",
			},
		},
		{
			// An IdP carries groups that have nothing to do with this
			// gateway; an unmapped one is ignored, and a caller with only
			// unmapped groups gets nothing.
			name:   "an unmapped group grants nothing",
			groups: []string{"everyone", "vpn-users"},
			want:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.AllowedTools(access.Identity{Subject: "u-1", Groups: tc.groups})
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AllowedTools = %v, want %v", got, tc.want)
			}
		})
	}

	// No wildcard: a near-miss on a tool the role does have is still a no.
	id := access.Identity{Subject: "u-1", Groups: []string{"soc-n1"}}
	for _, tool := range []string{"*", "casemgmt.*", "casemgmt.", "casemgmt.list_cases_extra", "docsearch.search"} {
		if err := policy.Authorize(id, tool); !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden -- tool names match exactly, there is no wildcard", tool, err)
		}
	}
}

// TestToAccessPolicyPropagatesNewPolicyErrors uses a config that
// Config.Validate accepts but access.NewPolicy does not: a role name with
// a trailing space. Validate only checks the name is non-blank; NewPolicy
// refuses it because " padded " and "padded" are distinct map keys, so an
// untrimmed name produces a role that exists, looks right in the file, and
// can never be resolved by any group mapping.
//
// The point of the test is not that specific rule -- it is that
// ToAccessPolicy does not swallow a domain error it cannot itself
// diagnose.
func TestToAccessPolicyPropagatesNewPolicyErrors(t *testing.T) {
	c := &Config{
		Database: "/var/db/mcp-gateway/mcp-gateway.db",
		OIDC: OIDC{
			Issuer:   "https://id.soc.internal/realms/soc",
			Audience: "https://gw.soc.internal/mcp",
		},
		Vault: Vault{
			SecretsFile: "/usr/local/etc/mcp-gateway/secrets.enc.json",
			AgeKeyFile:  "/usr/local/etc/mcp-gateway/age.key",
		},
		Roles: []Role{{Name: "n1-triage ", Tools: []string{"casemgmt.list_cases"}}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate rejected the fixture, so this test is no longer probing ToAccessPolicy: %v", err)
	}

	policy, err := c.ToAccessPolicy()
	if err == nil {
		t.Fatalf("ToAccessPolicy accepted a policy access.NewPolicy refuses: %+v", policy)
	}
	if !errors.Is(err, access.ErrInvalidPolicy) {
		t.Errorf("error does not wrap access.ErrInvalidPolicy: %v", err)
	}
	if policy != nil {
		t.Error("ToAccessPolicy returned both an error and a policy")
	}
}

// TestToAccessPolicyDoesNotShareSlices: the parsed config must not stay
// coupled to the live policy. access.Policy clones on both boundaries, and
// this asserts the config side does not undo that by handing over an
// aliased slice.
func TestToAccessPolicyDoesNotShareSlices(t *testing.T) {
	c := mustLoad(t, completeConfig)
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	id := access.Identity{Subject: "u-1", Groups: []string{"soc-n1"}}
	before := policy.AllowedTools(id)

	// Rewrite the config's own slice after the policy was built.
	c.Roles[0].Tools[0] = "casemgmt.delete_everything"

	after := policy.AllowedTools(id)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("mutating the parsed config changed what the live policy authorizes: %v -> %v", before, after)
	}
}

// -----------------------------------------------------------------------
// File and syntax errors
// -----------------------------------------------------------------------

func TestLoadMissingFileNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.toml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded on a file that does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file it tried to read: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error does not wrap os.ErrNotExist, so a caller cannot distinguish 'no file' from 'bad file': %v", err)
	}
}

// TestLoadMalformedTOMLReportsTheLine: BurntSushi's ParseError renders as
// "toml: line N: ...", and that line number is the single most useful part
// of the message for whoever has to fix the file. Wrapping must not lose
// it.
func TestLoadMalformedTOMLReportsTheLine(t *testing.T) {
	const broken = `listen   = "127.0.0.1:8080"
database = "/var/db/mcp-gateway/mcp-gateway.db"
this line is not valid toml
`
	path := writeConfig(t, broken)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted malformed TOML")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error does not carry the line number from the parser: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file: %v", err)
	}
}

// -----------------------------------------------------------------------
// The shipped example
// -----------------------------------------------------------------------

// exampleConfigPath is config.example.toml at the repository root, two
// levels up from internal/config.
func exampleConfigPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatalf("resolving the example config path: %v", err)
	}
	return path
}

// TestExampleConfigLoads keeps the shipped example honest against the
// parser that actually reads it.
//
// This is not ceremony. The example is the first thing an operator copies,
// and an example that has drifted -- a key renamed in Config, a section
// the loader now rejects -- is worse than no example: it teaches a file
// format that does not exist, and the person following it concludes the
// binary is broken. Because Load rejects unknown keys, this test also
// catches the reverse drift, where the example documents a setting nobody
// implemented.
func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("config.example.toml does not load -- the shipped example has drifted from the parser: %v", err)
	}

	// It must also be a *useful* example, not a file that merely parses.
	if len(c.Roles) < 2 {
		t.Errorf("the example defines %d role(s); it should show at least the n1-triage/dfir-lead split this gateway exists for", len(c.Roles))
	}
	if len(c.GroupToRole) == 0 {
		t.Error("the example maps no IdP group to a role, so it does not show how authorization is actually wired")
	}

	// Every mapped role resolves, and the whole thing survives the domain
	// type's own construction checks.
	if _, err := c.ToAccessPolicy(); err != nil {
		t.Errorf("the example's roles do not build an access.Policy: %v", err)
	}

	// The example must not recommend turning signature enforcement on
	// before the Operator Console can sign at volume (ADR-0006), and must
	// not quietly ship it on either -- it is declared debt with a trigger,
	// and the comment beside it is the deliverable.
	if c.Signer.RequireSigned {
		t.Error("config.example.toml sets require_signed = true; if the ADR-0006 trigger has been met, update the ADR, the default in Signer, and this test together")
	}
}

// stripTOMLComments returns src with every `#` comment removed, leaving
// only the settings themselves. Quoted strings are respected so a `#`
// inside a value is not mistaken for a comment.
//
// It exists so the secret scan below reads values, not prose: the example
// deliberately *discusses* client secrets and private keys in its
// comments, and that discussion is the documentation, not a finding.
func stripTOMLComments(src string) string {
	var out strings.Builder
	for _, line := range strings.Split(src, "\n") {
		inQuote := false
		cut := -1
		for i, r := range line {
			switch {
			case r == '"':
				inQuote = !inQuote
			case r == '#' && !inQuote:
				cut = i
			}
			if cut >= 0 {
				break
			}
		}
		if cut >= 0 {
			line = line[:cut]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// TestExampleConfigCarriesNoSecretValues enforces ADR-0009 §3 on the file
// an operator is most likely to copy: its *values* are paths and
// identifiers, and nothing that looks like a key, a password or a token.
// This is the automated half of that ADR's Compliance section.
//
// It is a heuristic on purpose. It cannot prove the absence of a secret,
// but it does catch the realistic accident -- someone pasting a working
// value into the example while debugging and committing it.
func TestExampleConfigCarriesNoSecretValues(t *testing.T) {
	raw, err := os.ReadFile(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	settings := strings.ToLower(stripTOMLComments(string(raw)))

	for _, marker := range []string{
		"-----begin",      // any PEM block: a private key pasted in whole
		"age-secret-key-", // an age identity
		"age1",            // an age recipient or identity string
		"eyj",             // the base64 header of a JWT
		"client_secret",   // a resource server has no use for one
		"password",
		"passwd",
		"api_key",
		"apikey",
		"token =",
	} {
		if strings.Contains(settings, marker) {
			t.Errorf("config.example.toml has a setting containing %q -- this file holds paths and identifiers only; a secret value belongs in the sops-encrypted file (ADR-0009 §3)", marker)
		}
	}

	// Guard the guard: if the strip ever stops finding the settings, the
	// scan above would pass on an empty string.
	if !strings.Contains(settings, "age_key_file") {
		t.Fatal("stripTOMLComments removed the settings themselves; the scan above proves nothing")
	}
}
