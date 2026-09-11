package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// Tests for the `[role.grants]` table added by
// design/adr/0016-per-backend-role-grants.md.
//
// The file-format half. What a grant *means* is tested in
// internal/access/grants_test.go; what it means once a real gateway is
// serving is tested in grants_integration_test.go next door.

// grantsConfig is completeConfig with one role rewritten to use the
// per-backend form, and a third role added that uses both forms at once.
// It is the shape ADR-0016's TOML example shows.
const grantsConfig = completeConfig + `
[[role]]
name = "hunter"
tools = ["logsearch.search_absolute"]

  [role.grants]
  casemgmt    = ["get_case", "add_note"]
  threatintel = ["*"]
`

// -----------------------------------------------------------------------
// The happy path
// -----------------------------------------------------------------------

func TestLoadGrantsRoundTrip(t *testing.T) {
	contents := strings.Replace(grantsConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-lead"
"soc-hunt" = "hunter"`, 1)

	c := mustLoad(t, contents)

	var hunter *Role
	for i := range c.Roles {
		if c.Roles[i].Name == "hunter" {
			hunter = &c.Roles[i]
		}
	}
	if hunter == nil {
		t.Fatal("the role carrying [role.grants] was dropped during load")
	}
	if !reflect.DeepEqual(hunter.Tools, []string{"logsearch.search_absolute"}) {
		t.Errorf("tools = %v, want the flat entry preserved alongside the grants", hunter.Tools)
	}
	want := map[string][]string{
		"casemgmt":    {"get_case", "add_note"},
		"threatintel": {"*"},
	}
	if !reflect.DeepEqual(hunter.Grants, want) {
		t.Errorf("grants = %v, want %v", hunter.Grants, want)
	}

	// And it must reach the domain, not merely survive parsing. A field
	// that loads and is never converted is the quietest possible way for a
	// grant to do nothing.
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	id := access.Identity{Subject: "u", Groups: []string{"soc-hunt"}}
	for _, tool := range []string{
		"logsearch.search_absolute", // flat
		"casemgmt.get_case",         // named grant
		"casemgmt.add_note",
		"threatintel.lookup_ip", // wildcard
		"threatintel.whatever_gets_added_later",
	} {
		if err := policy.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil", tool, err)
		}
	}
	for _, tool := range []string{
		"casemgmt.delete_case",      // same backend, not granted
		"logsearch.search_relative", // same backend as the flat entry, not granted
		"docsearch.search",          // a backend this role never names
	} {
		if err := policy.Authorize(id, tool); !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden", tool, err)
		}
	}
}

// TestGrantsDoNotLeakBetweenRolesInOneFile is the isolation property at the
// file level: the roles that came with completeConfig must be unchanged by
// the presence of a third role that grants more.
func TestGrantsDoNotLeakBetweenRolesInOneFile(t *testing.T) {
	contents := strings.Replace(grantsConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-lead"
"soc-hunt" = "hunter"`, 1)

	policy, err := mustLoad(t, contents).ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	n1 := access.Identity{Subject: "n1", Groups: []string{"soc-n1"}}
	if err := policy.Authorize(n1, "casemgmt.list_cases"); err != nil {
		t.Fatalf("premise broken: n1-triage lost its own tool: %v", err)
	}
	// "threatintel.lookup_ip" is deliberately absent: n1-triage really does
	// hold it, in its own flat list, so it would prove nothing here.
	for _, tool := range []string{
		"casemgmt.add_note",  // granted to hunter, never to n1-triage
		"threatintel.shodan", // only hunter's wildcard reaches this
		"logsearch.search_absolute",
	} {
		if err := policy.Authorize(n1, tool); !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Authorize(n1, %q) = %v, want ErrForbidden -- another role's grant reached this one", tool, err)
		}
	}
}

// -----------------------------------------------------------------------
// Load-time rejections
// -----------------------------------------------------------------------

// TestLoadRejectsMalformedGrants walks every structural rule, as an
// operator meets it: a whole file, refused by Load, with a message naming
// what is wrong.
//
// The rules themselves live in access.validateGrants and are unit-tested
// there. This asserts the two are actually connected -- that Validate runs
// them over what the file parsed into, rather than leaving them to
// ToAccessPolicy and a crash at the next restart, which is the GAB-30
// shape this project has now found five times.
func TestLoadRejectsMalformedGrants(t *testing.T) {
	for _, tc := range []struct {
		name    string
		grants  string
		wantMsg string
	}{
		{
			name:    "empty backend key",
			grants:  `"" = ["get_case"]`,
			wantMsg: "empty backend name",
		},
		{
			name:    "untrimmed backend key",
			grants:  `"casemgmt " = ["get_case"]`,
			wantMsg: "leading or trailing whitespace",
		},
		{
			name:    "separator in the backend key",
			grants:  `"casemgmt.sub" = ["get_case"]`,
			wantMsg: "contains",
		},
		{
			name:    "star as a backend key",
			grants:  `"*" = ["get_case"]`,
			wantMsg: "no wildcard over backends",
		},
		{
			name:    "namespaced tool id",
			grants:  `casemgmt = ["casemgmt.get_case"]`,
			wantMsg: "not namespaced",
		},
		{
			name:    "empty tool id",
			grants:  `casemgmt = ["get_case", ""]`,
			wantMsg: "empty tool id",
		},
		{
			name:    "untrimmed tool id",
			grants:  `casemgmt = ["get_case "]`,
			wantMsg: "leading or trailing whitespace",
		},
		{
			name:    "star mixed with named tools",
			grants:  `casemgmt = ["*", "get_case"]`,
			wantMsg: "already grants every tool",
		},
		{
			name:    "duplicate tool id",
			grants:  `casemgmt = ["get_case", "get_case"]`,
			wantMsg: "more than once",
		},
		{
			// The one TOML itself will not catch, and the only one of these
			// whose likely ordering is an OVER-grant rather than an
			// under-grant. See rejectCollapsedMapKeys.
			name: "same backend named twice",
			grants: `casemgmt = ["get_case"]
  casemgmt = ["*"]`,
			wantMsg: "written more than once",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := completeConfig + `
[[role]]
name = "hunter"

  [role.grants]
  ` + tc.grants + "\n"

			err := loadErr(t, contents)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error does not contain %q: %v", tc.wantMsg, err)
			}
		})
	}
}

// TestLoadRejectsADottedGrantKeyWrittenBare covers the other way an
// operator writes a separator into a grant key. `casemgmt.sub = [...]` is
// not a key containing a dot at all in TOML -- it is a dotted key, which
// asks for a sub-table -- so it never reaches Validate. It must still be
// refused rather than ignored, and it is, by the decoder.
func TestLoadRejectsADottedGrantKeyWrittenBare(t *testing.T) {
	contents := completeConfig + `
[[role]]
name = "hunter"

  [role.grants]
  casemgmt.sub = ["get_case"]
`
	err := loadErr(t, contents)
	if !strings.Contains(err.Error(), "casemgmt") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// TestLoadRejectsAWildcardInTheFlatToolsList.
//
// `tools = ["casemgmt.*"]` parses, is namespaced, and grants exactly one
// tool: the one literally called "*". It reads, especially now that
// `[role.grants]` a few lines below really does take "*", like a grant of
// the whole backend. That is the silent-no-op shape GAB-30 item 3 was, so
// it is refused and the message points at the form that works.
func TestLoadRejectsAWildcardInTheFlatToolsList(t *testing.T) {
	contents := strings.Replace(completeConfig, `"casemgmt.get_case"`, `"casemgmt.*"`, 1)
	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	for _, want := range []string{"NOT a wildcard", "[role.grants]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q: %v", want, err)
		}
	}
}

// TestDuplicateGroupMappingIsRefusedByTheDecoder pins the half of the
// collapsed-key problem that rejectCollapsedMapKeys deliberately does NOT
// cover.
//
// `[group_to_role]` is the file's other map-typed table and would have the
// same defect if the decoder let it through: a group listed twice, the
// last role silently winning, a mapping an operator wrote and reviewed
// doing nothing. It does not, because BurntSushi enforces TOML's
// duplicate-key rule at the top level -- only NESTED tables escape it,
// which is why `[role.grants]` needs the check and this does not.
//
// This test exists so that fact is asserted rather than assumed. If the
// decoder's behaviour ever changes, this fails first, and the fix is to
// extend rejectCollapsedMapKeys to cover group_to_role as well.
func TestDuplicateGroupMappingIsRefusedByTheDecoder(t *testing.T) {
	contents := strings.Replace(completeConfig,
		`"soc-n1"   = "n1-triage"`,
		`"soc-n1"   = "n1-triage"
"soc-n1"   = "dfir-lead"`, 1)

	err := loadErr(t, contents)
	if !strings.Contains(err.Error(), "group_to_role.soc-n1") {
		t.Errorf("a group mapped twice is no longer refused with its key named -- "+
			"if the decoder stopped enforcing this, rejectCollapsedMapKeys must be extended to cover "+
			"[group_to_role] the way it covers [role.grants]: %v", err)
	}
}

// TestTwoRolesMayGrantTheSameBackend guards the false positive the
// duplicate-key check could easily have. toml.MetaData.Keys flattens
// `[[role]]` elements, so `role.grants.casemgmt` legitimately appears once
// per role that grants casemgmt. Counting written-versus-survived is what
// tells the two apart, and this is the case that would break a naive
// "appears twice, therefore duplicate" rule.
func TestTwoRolesMayGrantTheSameBackend(t *testing.T) {
	contents := strings.Replace(completeConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-lead"
"soc-a" = "a"
"soc-b" = "b"`, 1) + `
[[role]]
name = "a"

  [role.grants]
  casemgmt = ["get_case"]

[[role]]
name = "b"

  [role.grants]
  casemgmt = ["add_note"]
`
	c := mustLoad(t, contents)

	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	a := access.Identity{Subject: "a", Groups: []string{"soc-a"}}
	b := access.Identity{Subject: "b", Groups: []string{"soc-b"}}
	if err := policy.Authorize(a, "casemgmt.get_case"); err != nil {
		t.Errorf("role a lost its grant: %v", err)
	}
	if err := policy.Authorize(b, "casemgmt.add_note"); err != nil {
		t.Errorf("role b lost its grant: %v", err)
	}
	if err := policy.Authorize(a, "casemgmt.add_note"); !errors.Is(err, access.ErrForbidden) {
		t.Errorf("role a reached role b's grant: %v", err)
	}
}

// -----------------------------------------------------------------------
// Backward compatibility
// -----------------------------------------------------------------------

// TestFilesWithoutGrantsAreUnchanged is the compatibility guarantee
// ADR-0016 makes: the flat `tools = [...]` form is not deprecated, and a
// file written before `[role.grants]` existed must load and authorize
// exactly as it did.
//
// It asserts the decision as well as the parse. A change that made Grants
// default to something -- an empty map read as "grant nothing", or worse
// an absent map read as "grant everything" -- would still parse.
func TestFilesWithoutGrantsAreUnchanged(t *testing.T) {
	c := mustLoad(t, completeConfig)

	for _, r := range c.Roles {
		if r.Grants != nil {
			t.Errorf("role %q acquired a grants map from a file that declares none: %v", r.Name, r.Grants)
		}
	}

	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	// Exactly the tools completeConfig lists for n1-triage, and nothing a
	// grant-shaped reading of an absent map might have added.
	id := access.Identity{Subject: "u", Groups: []string{"soc-n1"}}
	for _, tool := range []string{"casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"} {
		if err := policy.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil", tool, err)
		}
	}
	for _, tool := range []string{
		"casemgmt.delete_case",
		"casemgmt.anything",
		"threatintel.shodan",
		"docsearch.search",
	} {
		if err := policy.Authorize(id, tool); !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden -- a file with no grants must grant nothing extra", tool, err)
		}
	}
}

// TestToAccessPolicyDoesNotShareGrantMaps is the grants half of
// TestToAccessPolicyDoesNotShareSlices: the parsed config must not stay
// coupled to the live policy through the map either, and a map is worse
// than a slice because a shallow copy of one still shares every value.
//
// Note what this can and cannot show on its own. access.NewPolicy clones
// as well, so with that clone in place this passes whatever ToAccessPolicy
// does -- and that redundancy is deliberate (load.go says the conversion
// should be safe "even if that guarantee ever changes"). Verified by
// removing BOTH clones at once, which this does catch; either one alone
// holds the line.
func TestToAccessPolicyDoesNotShareGrantMaps(t *testing.T) {
	contents := strings.Replace(grantsConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-lead"
"soc-hunt" = "hunter"`, 1)
	c := mustLoad(t, contents)

	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	id := access.Identity{Subject: "u", Groups: []string{"soc-hunt"}}
	if err := policy.Authorize(id, "casemgmt.get_case"); err != nil {
		t.Fatalf("premise broken: %v", err)
	}

	// Rewrite the config's own grants after the policy was built, both by
	// editing a list in place and by adding a backend to the map.
	for i := range c.Roles {
		if c.Roles[i].Name != "hunter" {
			continue
		}
		c.Roles[i].Grants["casemgmt"][0] = "delete_case"
		c.Roles[i].Grants["docsearch"] = []string{"*"}
	}

	if err := policy.Authorize(id, "casemgmt.delete_case"); err == nil {
		t.Error("rewriting a grant list in the parsed config changed what the live policy authorizes")
	}
	if err := policy.Authorize(id, "docsearch.anything"); err == nil {
		t.Error("adding a backend to the parsed config's grants map changed what the live policy authorizes")
	}
	if err := policy.Authorize(id, "casemgmt.get_case"); err != nil {
		t.Errorf("the original grant was lost when the parsed config was edited: %v", err)
	}
}

// TestGrantsFieldIsOptionalInEveryFixture: minimalConfig has no roles at
// all, and completeConfig has roles with no grants. Both must still load.
// Cheap, and it is the case a required-field mistake would break first.
func TestGrantsFieldIsOptionalInEveryFixture(t *testing.T) {
	for name, contents := range map[string]string{
		"minimal":  minimalConfig,
		"complete": completeConfig,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, contents)); err != nil {
				t.Errorf("a fixture with no [role.grants] no longer loads: %v", err)
			}
		})
	}
}

// TestLoadRejectsADuplicatedTrustedKeysList is the trust-anchor half of the
// collapsed-key problem, and the one that costs most.
//
// TOML's duplicate-key error does not reach inside [signer], so writing
// trusted_keys twice keeps the LAST list and discards the first without a
// word. A file that reads as trusting two keys can be running on one -- and
// ADR-0010 moved this list into the config precisely so it would be
// reviewable there.
func TestLoadRejectsADuplicatedTrustedKeysList(t *testing.T) {
	// The duplicate must go INSIDE the existing [signer] table: a second
	// [signer] header is a top-level duplicate, which TOML rejects on its
	// own and is a different bug from the one under test here.
	src := strings.Replace(completeConfig,
		`trusted_keys   = ["YBVP3wMTzQlOQqvDUZ31FVpYqX9Yenqw5fPVYLlQ9HE=", "95hrvkq5Lv2DH0yrq4V/4YgBs/0B/InLgZzpBF0+QxU="]`,
		"trusted_keys   = [\"YBVP3wMTzQlOQqvDUZ31FVpYqX9Yenqw5fPVYLlQ9HE=\"]\ntrusted_keys   = [\"95hrvkq5Lv2DH0yrq4V/4YgBs/0B/InLgZzpBF0+QxU=\"]",
		1)
	if src == completeConfig {
		t.Fatal("the fixture's trusted_keys line moved; this test is not exercising what it claims")
	}
	err := loadErr(t, src)
	if !strings.Contains(err.Error(), "signer.trusted_keys") {
		t.Errorf("the error does not name the key that was lost: %v", err)
	}
}

// TestLoadRejectsADuplicatedToolsList is the same defect on the older half
// of a role's grant.
func TestLoadRejectsADuplicatedToolsList(t *testing.T) {
	err := loadErr(t, completeConfig+
		"\n[[role]]\nname = \"n1-dup\"\ntools = [\"casemgmt.list_cases\"]\ntools = [\"casemgmt.get_case\"]\n")
	if !strings.Contains(err.Error(), "role.tools") {
		t.Errorf("the error does not name the key that was lost: %v", err)
	}
}
