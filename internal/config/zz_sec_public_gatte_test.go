package config

// Security/doc-rot tests for the public examples/ directory.
//
// examples/README.md says: "Each file in this directory was checked this
// way, appended to base.toml with a real key pasted into
// signer.trusted_keys." Until these tests nothing in `go test` did that, so
// the claim could rot silently. Every assertion below goes through the real
// Load (rejectUnknownKeys, rejectCollapsedMapKeys, Validate) and, where the
// README makes an authorization claim, through ToAccessPolicy and the real
// access.Policy.Authorize.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
)

const secExamplesDir = "../../examples"

const secBasePlaceholder = "REPLACE-WITH-THE-LINE-PRINTED-BY-sign-generate-key"

func secReadExample(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(secExamplesDir, name))
	if err != nil {
		t.Fatalf("reading examples/%s: %v", name, err)
	}
	return string(raw)
}

// secBaseWithKey is base.toml with the documented edit applied: a real key
// in place of the placeholder. It fails if the placeholder is gone, so the
// test cannot silently stop substituting.
func secBaseWithKey(t *testing.T) string {
	t.Helper()
	base := secReadExample(t, "base.toml")
	if !strings.Contains(base, secBasePlaceholder) {
		t.Fatalf("examples/base.toml no longer carries the %q placeholder; update this test", secBasePlaceholder)
	}
	return strings.ReplaceAll(base, secBasePlaceholder, testTrustedKey)
}

func secExampleFiles(t *testing.T) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(secExamplesDir, "*.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range matches {
		if filepath.Base(m) != "base.toml" {
			out = append(out, filepath.Base(m))
		}
	}
	sort.Strings(out)
	if len(out) < 8 {
		t.Fatalf("expected at least 8 example files besides base.toml, found %v", out)
	}
	return out
}

// TestSecExamplesEveryFileLoadsAppendedToBase is the README's own dry run,
// made mechanical.
func TestSecExamplesEveryFileLoadsAppendedToBase(t *testing.T) {
	base := secBaseWithKey(t)
	for _, name := range secExampleFiles(t) {
		t.Run(name, func(t *testing.T) {
			body := base + "\n" + secReadExample(t, name)
			c, err := Load(writeConfig(t, body))
			if err != nil {
				t.Fatalf("examples/%s appended to base.toml does not load: %v", name, err)
			}
			if len(c.Roles) == 0 {
				t.Errorf("examples/%s defines no [[role]] after load; the example is untested prose", name)
			}
			if len(c.GroupToRole) == 0 {
				t.Errorf("examples/%s defines no [group_to_role]", name)
			}
			if _, err := c.ToAccessPolicy(); err != nil {
				t.Errorf("examples/%s loads but does not build an access policy: %v", name, err)
			}
			// The shipped examples must not quietly weaken the defaults
			// base.toml documents.
			if !c.Signer.SignaturesRequired() {
				t.Errorf("examples/%s turns signature enforcement off", name)
			}
			if err := RequireLoopbackBind(c.Listen); err != nil {
				t.Errorf("examples/%s listens off loopback: %v", name, err)
			}
		})
	}
}

// TestSecExamplesUneditedBaseIsRefused pins the README's "The unedited
// base.toml is refused on purpose".
func TestSecExamplesUneditedBaseIsRefused(t *testing.T) {
	if _, err := Load(writeConfig(t, secReadExample(t, "base.toml"))); err == nil {
		t.Fatal("unedited examples/base.toml loaded; its trusted_keys placeholder was accepted as a key")
	}
	// And base.toml alone, with the key edit, loads (it is the "minimal
	// configuration without roles").
	if _, err := Load(writeConfig(t, secBaseWithKey(t))); err != nil {
		t.Fatalf("examples/base.toml with a real key does not load: %v", err)
	}
}

// TestSecExamplesLoaderRefusalsTheReadmeClaims checks each "The loader
// refuses, at startup, ..." sentence of examples/README.md step 5.
func TestSecExamplesLoaderRefusalsTheReadmeClaims(t *testing.T) {
	base := secBaseWithKey(t)
	cases := map[string]string{
		"tools entry without a namespace": `
[[role]]
name = "r"
tools = ["list_cases"]
[group_to_role]
"g" = "r"
`,
		"upstream.* in tools": `
[[role]]
name = "r"
tools = ["cases.*"]
[group_to_role]
"g" = "r"
`,
		"* mixed with named tools": `
[[role]]
name = "r"
tools = []
  [role.grants]
  intel = ["*", "lookup_ip"]
[group_to_role]
"g" = "r"
`,
		"duplicate tools": `
[[role]]
name = "r"
tools = ["cases.get_case", "cases.get_case"]
[group_to_role]
"g" = "r"
`,
		"duplicate grant ids": `
[[role]]
name = "r"
tools = []
  [role.grants]
  edr = ["get_host", "get_host"]
[group_to_role]
"g" = "r"
`,
		"group mapped to undefined role": `
[[role]]
name = "r"
tools = ["cases.get_case"]
[group_to_role]
"g" = "no-such-role"
`,
		"non-loopback listen": "", // built from base below
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			body := base + "\n" + extra
			if name == "non-loopback listen" {
				body = strings.Replace(base, `listen = "127.0.0.1:8080"`, `listen = "0.0.0.0:8080"`, 1)
				if body == base {
					t.Fatal("base.toml no longer has listen = \"127.0.0.1:8080\"; update this test")
				}
			}
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Errorf("README says the loader refuses %s, but it loaded", name)
			}
		})
	}
}

// TestSecExamplesBlueTeamRolesMeanWhatTheyDocument drives the combined
// policy through the real access.Policy: the README's authorization claims
// are true of the code, not only of the prose.
func TestSecExamplesBlueTeamRolesMeanWhatTheyDocument(t *testing.T) {
	body := secBaseWithKey(t) + "\n" + secReadExample(t, "blue-team-roles.toml")
	c, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("blue-team-roles.toml does not load: %v", err)
	}
	p, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	who := func(group string) access.Identity {
		return access.Identity{Subject: "sub-" + group, Groups: []string{group}}
	}
	type claim struct {
		group, tool string
		allow       bool
	}
	claims := []claim{
		// tier1: EDR read, never response actions.
		{"blue-tier1", "edr.get_host", true},
		{"blue-tier1", "edr.list_detections", true},
		{"blue-tier1", "edr.isolate_host", false},
		{"blue-tier1", "edr.release_host", false},
		{"blue-tier1", "cases.add_case_note", false},
		{"blue-tier1", "siem.search_events", true},
		// intel wildcard is per-backend and does not leak to other backends.
		{"blue-tier1", "intel.lookup_ip", true},
		{"blue-tier1", "intelx.lookup_ip", false},
		{"blue-tier1", "vulnscan.launch_scan", false},
		// ir-lead gets the response actions.
		{"blue-ir", "edr.isolate_host", true},
		{"blue-ir", "cases.update_case_status", true},
		// vuln-analyst: never the scan launcher.
		{"blue-vuln", "vulnscan.launch_scan", false},
		{"blue-vuln", "vulnscan.list_findings", true},
		{"blue-vuln", "intel.lookup_ip", false},
		// onboarding: nothing at all.
		{"blue-onboarding", "cases.list_cases", false},
		{"blue-onboarding", "intel.lookup_ip", false},
		// an unmapped group: nothing at all.
		{"not-a-blue-group", "intel.lookup_ip", false},
	}
	for _, cl := range claims {
		err := p.Authorize(who(cl.group), cl.tool)
		if got := err == nil; got != cl.allow {
			t.Errorf("group %q tool %q: allowed=%v, the example documents allowed=%v (err=%v)", cl.group, cl.tool, got, cl.allow, err)
		}
	}
}

// TestSecExamplesCarryNoSecretValues guards the README's "No secret value
// goes in this file": nothing that looks like a vault assignment or a key
// is in any example.
func TestSecExamplesCarryNoSecretValues(t *testing.T) {
	files := append([]string{"base.toml"}, secExampleFiles(t)...)
	bad := []string{"AGE-SECRET-KEY-", "BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "client_secret =", "password =", "api_key ="}
	for _, name := range files {
		body := secReadExample(t, name)
		for _, needle := range bad {
			if strings.Contains(strings.ToLower(body), strings.ToLower(needle)) {
				t.Errorf("examples/%s contains %q", name, needle)
			}
		}
	}
}
