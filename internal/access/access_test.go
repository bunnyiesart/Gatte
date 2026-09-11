package access

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The roles used across most tests. They deliberately overlap on
// "casemgmt.list_cases" so that union and deduplication are exercised, and
// "n1-triage" contains "casemgmt.list_cases" so the no-wildcard tests have a
// realistic near-miss to probe ("casemgmt.list_cases_extra", "casemgmt.", "*").
func testRoles() []Role {
	return []Role{
		{
			Name:  "n1-triage",
			Tools: []string{"casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"},
		},
		{
			Name:  "dfir-lead",
			Tools: []string{"casemgmt.list_cases", "docsearch.search", "threatintel.virustotal"},
		},
		{
			Name:  "read-only",
			Tools: []string{"logsearch.list_streams"},
		},
	}
}

func testGroupToRole() map[string]string {
	return map[string]string{
		"soc-n1":      "n1-triage",
		"soc-dfir":    "dfir-lead",
		"soc-readers": "read-only",
	}
}

func mustPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := NewPolicy(testRoles(), testGroupToRole())
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func roleNames(roles []Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Name)
	}
	return out
}

// -----------------------------------------------------------------------
// Construction
// -----------------------------------------------------------------------

// TestNewPolicy_UndefinedRoleFailsAtConstruction pins the deliberate choice
// to reject a bad mapping at startup rather than at request time. A typo in
// a group mapping that only surfaced on the request path would present as
// an analyst being silently denied their tools mid-incident, which is both
// the worst moment to discover it and the hardest failure to attribute.
func TestNewPolicy_UndefinedRoleFailsAtConstruction(t *testing.T) {
	p, err := NewPolicy(testRoles(), map[string]string{
		"soc-n1":  "n1-triage",
		"soc-tpo": "n1-triaje", // typo
	})
	if !errors.Is(err, ErrNoSuchRole) {
		t.Fatalf("NewPolicy with an undefined role = %v, want ErrNoSuchRole", err)
	}
	if p != nil {
		t.Error("NewPolicy returned a non-nil Policy alongside an error; a half-built policy must never be usable")
	}
	if !strings.Contains(err.Error(), "n1-triaje") {
		t.Errorf("error %q does not name the offending role; an operator needs to find the typo", err)
	}
}

func TestNewPolicy_RejectsBadRoleDefinitions(t *testing.T) {
	cases := []struct {
		name  string
		roles []Role
	}{
		{
			name:  "empty role name",
			roles: []Role{{Name: "", Tools: []string{"casemgmt.list_cases"}}},
		},
		{
			name:  "whitespace-only role name",
			roles: []Role{{Name: "   ", Tools: []string{"casemgmt.list_cases"}}},
		},
		{
			name: "duplicate role name",
			roles: []Role{
				{Name: "n1-triage", Tools: []string{"casemgmt.list_cases"}},
				{Name: "n1-triage", Tools: []string{"docsearch.search"}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPolicy(c.roles, nil); err == nil {
				t.Fatalf("NewPolicy(%+v) = nil error, want a rejection", c.roles)
			}
		})
	}
}

func TestNewPolicy_ValidPolicyBuilds(t *testing.T) {
	p, err := NewPolicy(testRoles(), testGroupToRole())
	if err != nil {
		t.Fatalf("NewPolicy on a valid definition: %v", err)
	}
	if p == nil {
		t.Fatal("NewPolicy returned a nil Policy with a nil error")
	}

	// An empty policy is valid too: no roles, no mappings, nobody allowed
	// anything. That is a legitimate (maximally closed) configuration.
	empty, err := NewPolicy(nil, nil)
	if err != nil {
		t.Fatalf("NewPolicy(nil, nil): %v", err)
	}
	if got := empty.AllowedTools(Identity{Subject: "a", Groups: []string{"soc-n1"}}, toolUniverse); len(got) != 0 {
		t.Errorf("AllowedTools under an empty policy = %v, want empty", got)
	}
}

// -----------------------------------------------------------------------
// Fail-closed defaults
// -----------------------------------------------------------------------

// TestAuthorize_IdentityWithNoGroupsIsForbiddenEverything is the primary
// fail-closed default: a caller the IdP authenticated but for whom no group
// claim arrived is a caller nobody decided to grant anything, and the safe
// reading of "nobody decided" is "no".
func TestAuthorize_IdentityWithNoGroupsIsForbiddenEverything(t *testing.T) {
	p := mustPolicy(t)

	for _, id := range []Identity{
		{Subject: "nil-groups", Name: "Nil Groups", Groups: nil},
		{Subject: "empty-groups", Name: "Empty Groups", Groups: []string{}},
	} {
		t.Run(id.Subject, func(t *testing.T) {
			for _, tool := range toolUniverse {
				if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
					t.Errorf("Authorize(%q, %q) = %v, want ErrForbidden", id.Subject, tool, err)
				}
			}
			if got := p.RolesFor(id); len(got) != 0 {
				t.Errorf("RolesFor = %v, want no roles", roleNames(got))
			}
			if got := p.AllowedTools(id, toolUniverse); len(got) != 0 {
				t.Errorf("AllowedTools = %v, want empty", got)
			}
		})
	}
}

// TestAuthorize_GroupsThatMapToNoRoleAreForbiddenEverything is a different
// failure from having no groups at all: the caller does carry group claims,
// they just are not groups this gateway was told about. The result must be
// identical -- no role, therefore nothing.
func TestAuthorize_GroupsThatMapToNoRoleAreForbiddenEverything(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{
		Subject: "stranger",
		Name:    "Someone From Another Team",
		Groups:  []string{"finance", "all-staff", "vpn-users"},
	}

	if got := p.RolesFor(id); len(got) != 0 {
		t.Fatalf("RolesFor = %v, want no roles for unmapped groups", roleNames(got))
	}
	if got := p.AllowedTools(id, toolUniverse); len(got) != 0 {
		t.Fatalf("AllowedTools = %v, want empty", got)
	}
	for _, tool := range toolUniverse {
		if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
			t.Errorf("Authorize(%q, %q) = %v, want ErrForbidden", id.Subject, tool, err)
		}
	}
}

// TestRolesFor_UnmappedGroupsAreIgnoredNotFatal pins the documented
// tolerance: an IdP carries groups that have nothing to do with this
// gateway, so an unrelated group must not poison the decision. If unmapped
// groups were treated as an error the gateway would break every time
// somebody joined an unrelated team.
func TestRolesFor_UnmappedGroupsAreIgnoredNotFatal(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{
		Subject: "analyst-1",
		Name:    "Analyst One",
		Groups:  []string{"all-staff", "soc-n1", "vpn-users", "coffee-club"},
	}

	if got, want := roleNames(p.RolesFor(id)), []string{"n1-triage"}; !slices.Equal(got, want) {
		t.Fatalf("RolesFor = %v, want %v", got, want)
	}

	want := []string{"casemgmt.get_case", "casemgmt.list_cases", "threatintel.lookup_ip"}
	if got := p.AllowedTools(id, toolUniverse); !slices.Equal(got, want) {
		t.Errorf("AllowedTools = %v, want exactly the mapped role's tools %v", got, want)
	}
	for _, tool := range want {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q, %q) = %v, want nil", id.Subject, tool, err)
		}
	}
}

// TestRolesFor_DuplicateGroupsResolveToOneRole guards against a group claim
// list that repeats an entry (IdPs do this when a group is inherited by
// more than one path) inflating the role list.
func TestRolesFor_DuplicateGroupsResolveToOneRole(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{Subject: "dup", Groups: []string{"soc-n1", "soc-n1", "soc-n1"}}

	if got, want := roleNames(p.RolesFor(id)), []string{"n1-triage"}; !slices.Equal(got, want) {
		t.Errorf("RolesFor = %v, want %v", got, want)
	}
}

// -----------------------------------------------------------------------
// Authorization
// -----------------------------------------------------------------------

func TestAuthorize_ExactToolAllowedOtherwiseForbidden(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{Subject: "analyst-1", Groups: []string{"soc-n1"}}

	cases := []struct {
		tool    string
		allowed bool
	}{
		{"casemgmt.list_cases", true},
		{"casemgmt.get_case", true},
		{"threatintel.lookup_ip", true},
		{"docsearch.search", false},       // belongs to another role
		{"logsearch.list_streams", false}, // belongs to another role
		{"casemgmt.delete_case", false},   // exists nowhere
	}

	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			err := p.Authorize(id, c.tool)
			if c.allowed {
				if err != nil {
					t.Fatalf("Authorize(%q) = %v, want nil", c.tool, err)
				}
				return
			}
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("Authorize(%q) = %v, want ErrForbidden", c.tool, err)
			}
		})
	}
}

// TestAuthorize_HasNoWildcardMatching is the test that stops someone
// "helpfully" adding prefix or glob semantics to the FLAT Role.Tools list.
// Matching there is exact, and stayed exact when design/adr/0016 added a
// wildcard to Role.Grants: the two forms are deliberately not the same
// dialect, so that a "*" typed into `tools` cannot quietly become a
// whole-backend grant. Every name below would match the role's real tools
// under some plausible globbing scheme, and every one of them must be
// denied.
//
// The roles under test here hold no Grants at all, which is what makes
// this an assertion about the flat list specifically. The wildcard that
// does exist is exercised in TestRoleGrants_WildcardCoversTheWholeBackend.
func TestAuthorize_HasNoWildcardMatching(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{Subject: "analyst-1", Groups: []string{"soc-n1"}}

	// The role really holds "casemgmt.list_cases", "casemgmt.get_case" and
	// "threatintel.lookup_ip".
	nearMisses := []string{
		"*",
		"**",
		"casemgmt.*",
		"casemgmt.",
		"casemgmt",
		"casemgmt.list_cases_extra", // prefix of the request matches a real tool
		"casemgmt.list_case",        // real tool is a prefix of nothing; caller truncated
		"casemgmt.list_cases.sub",
		".",
		"",
		"CASEMGMT.LIST_CASES", // exact means case-sensitive too
		"Casemgmt.List_Cases",
		" casemgmt.list_cases", // no trimming
		"casemgmt.list_cases ",
		"threatintel.*",
		"threatintel.lookup_ipv6",
		"?ris.list_cases",
		"casemgmt.list_[c]ases",
	}

	for _, tool := range nearMisses {
		t.Run("denied/"+tool, func(t *testing.T) {
			if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
				t.Fatalf("Authorize(%q) = %v, want ErrForbidden -- matching must be exact, with no wildcard or prefix semantics", tool, err)
			}
			if slices.Contains(p.AllowedTools(id, nearMisses), tool) {
				t.Fatalf("AllowedTools contains %q, want it absent", tool)
			}
		})
	}

	// ...and a role whose tool list literally contains "*" grants exactly
	// the tool named "*", not everything. The character has no meaning.
	star, err := NewPolicy(
		[]Role{{Name: "star", Tools: []string{"*"}}},
		map[string]string{"g": "star"},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	starID := Identity{Subject: "star", Groups: []string{"g"}}
	if err := star.Authorize(starID, "*"); err != nil {
		t.Errorf(`Authorize("*") with a role holding "*" = %v, want nil (it is just a name)`, err)
	}
	if err := star.Authorize(starID, "casemgmt.list_cases"); !errors.Is(err, ErrForbidden) {
		t.Errorf(`a role holding "*" authorized %q (= %v); "*" must not be a wildcard`, "casemgmt.list_cases", err)
	}
}

// TestAuthorize_MultipleRolesUnion covers an analyst who is in two mapped
// groups: they hold both roles and may call the tools of both, with the
// overlap counted once.
func TestAuthorize_MultipleRolesUnion(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{
		Subject: "lead-1",
		Name:    "Lead One",
		Groups:  []string{"soc-dfir", "soc-n1", "unrelated"},
	}

	if got, want := roleNames(p.RolesFor(id)), []string{"dfir-lead", "n1-triage"}; !slices.Equal(got, want) {
		t.Fatalf("RolesFor = %v, want %v (sorted by role name)", got, want)
	}

	want := []string{
		"casemgmt.get_case",
		"casemgmt.list_cases", // in both roles, must appear once
		"docsearch.search",
		"threatintel.lookup_ip",
		"threatintel.virustotal",
	}
	got := p.AllowedTools(id, toolUniverse)
	if !slices.Equal(got, want) {
		t.Fatalf("AllowedTools = %v, want the sorted, deduplicated union %v", got, want)
	}

	for _, tool := range want {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil for a tool from one of the held roles", tool, err)
		}
	}
	// A third role the identity does not hold stays out of reach.
	if err := p.Authorize(id, "logsearch.list_streams"); !errors.Is(err, ErrForbidden) {
		t.Errorf("Authorize(logsearch.list_streams) = %v, want ErrForbidden", err)
	}
}

func TestRole_Allows(t *testing.T) {
	r := Role{Name: "n1-triage", Tools: []string{"casemgmt.list_cases"}}

	if !r.Allows("casemgmt.list_cases") {
		t.Error("Allows on the exact tool = false, want true")
	}
	for _, tool := range []string{"casemgmt.list_cases_extra", "casemgmt.", "*", ""} {
		if r.Allows(tool) {
			t.Errorf("Allows(%q) = true, want false", tool)
		}
	}
	if (Role{Name: "empty"}).Allows("anything") {
		t.Error("a role with no tools allowed something, want nothing")
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	// 401 and 403 must not be collapsed: a 401 for an authorization
	// failure tells an attacker their credential might work with other
	// permissions, and a 403 for a missing credential confirms a resource
	// exists to somebody who never authenticated.
	p := mustPolicy(t)
	err := p.Authorize(Identity{Subject: "nobody"}, "casemgmt.list_cases")

	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Authorize = %v, want ErrForbidden", err)
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Error("an authorization failure also matches ErrUnauthenticated; 401 and 403 must stay distinguishable")
	}
	if errors.Is(err, ErrNoSuchRole) {
		t.Error("an authorization failure also matches ErrNoSuchRole")
	}
	if errors.Is(ErrForbidden, ErrUnauthenticated) || errors.Is(ErrUnauthenticated, ErrForbidden) {
		t.Error("ErrForbidden and ErrUnauthenticated are not distinct sentinels")
	}
}

// -----------------------------------------------------------------------
// The consistency property: AllowedTools and Authorize must agree
// -----------------------------------------------------------------------

// toolUniverse is the closed set of names the consistency property is
// checked over. It contains every tool any test role holds, tools held by
// no role, and the near-miss names a wildcard implementation would
// wrongly match.
var toolUniverse = []string{
	"casemgmt.list_cases",
	"casemgmt.get_case",
	"casemgmt.list_case_iocs",
	"casemgmt.delete_case",
	"threatintel.lookup_ip",
	"threatintel.virustotal",
	"threatintel.shodan",
	"docsearch.search",
	"docsearch.docsearch_api",
	"logsearch.list_streams",
	"logsearch.search_absolute",
	"",
	"*",
	"casemgmt.",
	"casemgmt.*",
	"casemgmt.list_cases_extra",
	"CASEMGMT.LIST_CASES",
	"unknown.tool",
}

// TestAuthorizeAndAllowedToolsAgree is the most important property in this
// package. AllowedTools filters the tool list a client is shown; Authorize
// gates the actual call. If the two ever disagree you get one of two bugs,
// and the second is far worse than the first:
//
//   - a tool listed but not callable: an analyst hits a 403 on something
//     the gateway advertised, which is confusing but visible;
//   - a tool callable but never listed: an execution path that exists and
//     that no operator reviewing the tool list would ever see.
//
// This is checked as a real property, not with examples: for a policy with
// several overlapping roles, and for a spread of identities, every name in
// toolUniverse is asserted in both directions -- Authorize returns nil if
// and only if AllowedTools contains it.
func TestAuthorizeAndAllowedToolsAgree(t *testing.T) {
	roles := []Role{
		{Name: "n1-triage", Tools: []string{"casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"}},
		{Name: "dfir-lead", Tools: []string{"casemgmt.list_cases", "docsearch.search", "threatintel.virustotal", "casemgmt.list_case_iocs"}},
		{Name: "read-only", Tools: []string{"logsearch.list_streams", "casemgmt.list_cases"}},
		{Name: "hunter", Tools: []string{"docsearch.docsearch_api", "logsearch.search_absolute", "threatintel.shodan", "threatintel.lookup_ip"}},
		{Name: "empty-role", Tools: nil},
		// "*" and "casemgmt." are deliberately here: in the FLAT list they
		// are ordinary strings, and holding them must grant only the tools
		// literally named "*" and "casemgmt." -- never wildcard or prefix
		// semantics. "" is NOT here: NewPolicy rejects an empty tool name
		// outright, so that a bug elsewhere passing "" to the gate can
		// never find a role that happens to hold it.
		{Name: "odd-names", Tools: []string{"*", "casemgmt."}},
		// The per-backend form, in all three of its shapes: named ids, a
		// whole-backend wildcard, and a role that mixes flat and granted.
		// The property below must hold over these exactly as it does over
		// the flat ones -- that is the point of including them.
		{Name: "granted", Grants: map[string][]string{
			"casemgmt":    {"list_cases", "delete_case"},
			"threatintel": {"shodan"},
		}},
		{Name: "wildcarded", Grants: map[string][]string{"docsearch": {GrantAll}}},
		{
			Name:   "mixed",
			Tools:  []string{"logsearch.list_streams"},
			Grants: map[string][]string{"casemgmt": {"get_case"}},
		},
	}
	groupToRole := map[string]string{
		"soc-n1":       "n1-triage",
		"soc-dfir":     "dfir-lead",
		"soc-readers":  "read-only",
		"soc-hunt":     "hunter",
		"soc-nothing":  "empty-role",
		"soc-odd":      "odd-names",
		"soc-granted":  "granted",
		"soc-wild":     "wildcarded",
		"soc-mixed":    "mixed",
		"soc-wild-too": "wildcarded",
	}

	p, err := NewPolicy(roles, groupToRole)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	identities := []Identity{
		{Subject: "no-groups"},
		{Subject: "empty-groups", Groups: []string{}},
		{Subject: "unmapped-only", Groups: []string{"finance", "all-staff"}},
		{Subject: "n1", Groups: []string{"soc-n1"}},
		{Subject: "n1-plus-noise", Groups: []string{"all-staff", "soc-n1", "vpn"}},
		{Subject: "dfir", Groups: []string{"soc-dfir"}},
		{Subject: "n1-and-dfir", Groups: []string{"soc-n1", "soc-dfir"}},
		{Subject: "dfir-and-n1-reversed", Groups: []string{"soc-dfir", "soc-n1"}},
		{Subject: "three-roles", Groups: []string{"soc-n1", "soc-hunt", "soc-readers"}},
		{Subject: "everything", Groups: []string{"soc-n1", "soc-dfir", "soc-readers", "soc-hunt", "soc-odd"}},
		{Subject: "empty-role-only", Groups: []string{"soc-nothing"}},
		{Subject: "odd-names-only", Groups: []string{"soc-odd"}},
		{Subject: "duplicated-group", Groups: []string{"soc-n1", "soc-n1"}},
		{Subject: "granted-only", Groups: []string{"soc-granted"}},
		{Subject: "wildcard-only", Groups: []string{"soc-wild"}},
		{Subject: "mixed-only", Groups: []string{"soc-mixed"}},
		{Subject: "flat-and-granted", Groups: []string{"soc-n1", "soc-granted"}},
		{Subject: "wildcard-and-flat", Groups: []string{"soc-wild", "soc-readers"}},
		{Subject: "every-shape", Groups: []string{"soc-n1", "soc-granted", "soc-wild", "soc-mixed", "soc-odd"}},
	}

	for _, id := range identities {
		t.Run(id.Subject, func(t *testing.T) {
			allowed := p.AllowedTools(id, toolUniverse)

			// Direction 1: over the whole universe, listed <=> callable.
			for _, tool := range toolUniverse {
				callable := p.Authorize(id, tool) == nil
				listed := slices.Contains(allowed, tool)

				switch {
				case callable && !listed:
					t.Errorf("Authorize(%q) allows %q but AllowedTools omits it: an invisible execution path", id.Subject, tool)
				case listed && !callable:
					t.Errorf("AllowedTools lists %q for %q but Authorize denies it: an advertised tool that 403s", tool, id.Subject)
				}
			}

			// Direction 2: nothing AllowedTools returns may fall outside
			// the list it was given, and every entry must be callable.
			// The second half is not implied by direction 1 -- that one
			// only checks names the universe happens to contain, and this
			// one checks the output itself.
			for _, tool := range allowed {
				if err := p.Authorize(id, tool); err != nil {
					t.Errorf("AllowedTools returned %q for %q but Authorize = %v", tool, id.Subject, err)
				}
				if !slices.Contains(toolUniverse, tool) {
					t.Errorf("AllowedTools returned %q, which was never advertised to it", tool)
				}
			}

			// AllowedTools must also be sorted and deduplicated, since it
			// is what a client sees and what an audit record records.
			if !slices.IsSorted(allowed) {
				t.Errorf("AllowedTools = %v, want sorted", allowed)
			}
			for i := 1; i < len(allowed); i++ {
				if allowed[i] == allowed[i-1] {
					t.Errorf("AllowedTools = %v, want deduplicated (%q repeats)", allowed, allowed[i])
					break
				}
			}
		})
	}
}

// -----------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------

// TestRolesForAndAllowedTools_AreDeterministic guards against map iteration
// order leaking into the result. Go randomizes map iteration, so an
// implementation that walked p.groupToRole or p.roles instead of sorting
// would fail this reliably rather than intermittently. Determinism matters
// beyond tidiness: these values reach the audit trail and the tool list a
// client caches, and a set that reshuffles per request is impossible to
// diff after an incident.
func TestRolesForAndAllowedTools_AreDeterministic(t *testing.T) {
	p := mustPolicy(t)
	id := Identity{
		Subject: "lead-1",
		Groups:  []string{"soc-dfir", "soc-n1", "soc-readers", "unrelated", "all-staff"},
	}

	wantRoles := roleNames(p.RolesFor(id))
	wantTools := p.AllowedTools(id, toolUniverse)

	const iterations = 100
	for i := range iterations {
		if got := roleNames(p.RolesFor(id)); !slices.Equal(got, wantRoles) {
			t.Fatalf("iteration %d: RolesFor = %v, want %v on every call", i, got, wantRoles)
		}
		if got := p.AllowedTools(id, toolUniverse); !slices.Equal(got, wantTools) {
			t.Fatalf("iteration %d: AllowedTools = %v, want %v on every call", i, got, wantTools)
		}
	}

	// Group claim order arriving differently from the IdP must not change
	// the answer either.
	shuffled := Identity{
		Subject: id.Subject,
		Groups:  []string{"all-staff", "soc-readers", "unrelated", "soc-n1", "soc-dfir"},
	}
	if got := roleNames(p.RolesFor(shuffled)); !slices.Equal(got, wantRoles) {
		t.Errorf("RolesFor with reordered group claims = %v, want %v", got, wantRoles)
	}
	if got := p.AllowedTools(shuffled, toolUniverse); !slices.Equal(got, wantTools) {
		t.Errorf("AllowedTools with reordered group claims = %v, want %v", got, wantTools)
	}
}

// TestNewPolicy_IsDeterministicAcrossBuilds: rebuilding the policy is how
// it changes (it is immutable once built), so two builds from the same
// definition must behave identically -- including when the role slice is
// given in a different order.
func TestNewPolicy_IsDeterministicAcrossBuilds(t *testing.T) {
	id := Identity{Subject: "lead-1", Groups: []string{"soc-n1", "soc-dfir"}}

	a := mustPolicy(t)
	reordered := testRoles()
	slices.Reverse(reordered)
	b, err := NewPolicy(reordered, testGroupToRole())
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	if got, want := b.AllowedTools(id, toolUniverse), a.AllowedTools(id, toolUniverse); !slices.Equal(got, want) {
		t.Errorf("AllowedTools differs by role declaration order: %v vs %v", got, want)
	}
	if got, want := roleNames(b.RolesFor(id)), roleNames(a.RolesFor(id)); !slices.Equal(got, want) {
		t.Errorf("RolesFor differs by role declaration order: %v vs %v", got, want)
	}
}

// -----------------------------------------------------------------------
// Credential stripping: the structural guarantee
// -----------------------------------------------------------------------

// TestIdentity_CarriesNoCredentialField turns a doc comment into something
// the compiler-plus-test-suite enforces.
//
// ADR-0003 requires credential stripping: the token a client presents is
// removed before any upstream call and never forwarded, and per ADR-0008
// passthrough is forbidden by the MCP spec at MUST level. access.Identity
// is therefore built with nowhere to put a raw token -- once verified, the
// token has no further use inside the gateway.
//
// The risk this test exists for is not today's code, which is correct. It
// is the future change that "just adds the token for convenience" -- to
// re-verify downstream, to debug an upstream call, to stash it on a
// session. That field is how a bearer token ends up interpolated into an
// audit record or a log line, at which point the credential outlives the
// request in durable storage and the strip guarantee is gone silently. A
// reviewer may not notice one extra struct field; this test will.
//
// The check is deliberately scoped to Identity: it is the value that
// crosses from the adapter into the domain and gets attached to audit
// records, so it is the one place a token would be most tempting to carry
// and most damaging to keep.
func TestIdentity_CarriesNoCredentialField(t *testing.T) {
	forbidden := []string{
		"token",
		"secret",
		"password",
		"credential",
		"bearer",
		"jwt",
		"assertion",
	}

	typ := reflect.TypeOf(Identity{})
	if typ.Kind() != reflect.Struct {
		t.Fatalf("access.Identity is a %s, want a struct", typ.Kind())
	}
	if typ.NumField() == 0 {
		t.Fatal("access.Identity has no fields; this test would pass vacuously")
	}

	for i := range typ.NumField() {
		field := typ.Field(i)
		lower := strings.ToLower(field.Name)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("access.Identity has field %q, whose name contains %q: Identity must never carry the caller's credential (ADR-0003 credential stripping, ADR-0008 no passthrough). "+
					"If this field is genuinely not a credential, rename it; if it is, it does not belong here.",
					field.Name, bad)
			}
		}
	}

	// A sanity check that the detector actually detects, so the test above
	// cannot rot into a no-op if the matching logic is ever "simplified".
	type canary struct {
		Subject  string
		RawToken string
	}
	found := false
	ct := reflect.TypeOf(canary{})
	for i := range ct.NumField() {
		lower := strings.ToLower(ct.Field(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				found = true
			}
		}
	}
	if !found {
		t.Error("the credential-name detector did not flag a field named RawToken; the check above is not actually checking anything")
	}
}

// -----------------------------------------------------------------------
// The TokenVerifier port
// -----------------------------------------------------------------------

// stubVerifier is a domain-side stand-in; the real adapter lives in the
// oidc subpackage. Its only job here is to prove the port is satisfiable
// without importing HTTP, a JWT library, or an IdP -- which is the ports &
// adapters property this package's doc comment claims.
type stubVerifier struct {
	id  Identity
	err error
}

func (s stubVerifier) Verify(_ context.Context, _ string) (Identity, error) {
	return s.id, s.err
}

func TestTokenVerifier_PortIsSatisfiableFromTheDomain(t *testing.T) {
	var v TokenVerifier = stubVerifier{id: Identity{Subject: "u1", Groups: []string{"soc-n1"}}}

	id, err := v.Verify(context.Background(), "irrelevant")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	p := mustPolicy(t)
	if err := p.Authorize(id, "casemgmt.list_cases"); err != nil {
		t.Errorf("Authorize on a verified identity = %v, want nil", err)
	}

	// A failing verifier must be distinguishable as 401, never as 403.
	failing := stubVerifier{err: ErrUnauthenticated}
	if _, err := failing.Verify(context.Background(), "bad"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("failing Verify = %v, want ErrUnauthenticated", err)
	}
}

// TestPolicyIsActuallyImmutable pins a real defect found during Phase 4:
// Policy documented itself as immutable, but stored the caller's Role
// structs directly. Role.Tools is a slice, so the policy shared a backing
// array with whoever built it -- and RolesFor handed that same array to
// the request path. Both directions were exploitable: mutating the
// caller's slice after construction, or mutating RolesFor's return value,
// silently rewrote what the live gateway authorized.
//
// The no-locking design of Policy rests on immutability, so this is not a
// tidiness test. Verified to fail against the pre-fix implementation.
func TestPolicyIsActuallyImmutable(t *testing.T) {
	const forbidden = "casemgmt.delete_case"

	build := func() ([]Role, *Policy, Identity) {
		roles := []Role{{Name: "n1", Tools: []string{"casemgmt.list_cases"}}}
		p, err := NewPolicy(roles, map[string]string{"soc-n1": "n1"})
		if err != nil {
			t.Fatalf("NewPolicy: %v", err)
		}
		return roles, p, Identity{Subject: "u1", Groups: []string{"soc-n1"}}
	}

	t.Run("mutating the constructor's input does not change the policy", func(t *testing.T) {
		roles, p, id := build()
		roles[0].Tools[0] = forbidden

		if err := p.Authorize(id, forbidden); err == nil {
			t.Fatal("policy authorized a tool injected by mutating the slice passed to NewPolicy")
		}
		if got := p.AllowedTools(id, []string{forbidden, "casemgmt.list_cases"}); slices.Contains(got, forbidden) {
			t.Fatalf("AllowedTools leaked an injected tool: %v", got)
		}
	})

	t.Run("mutating RolesFor output does not change the policy", func(t *testing.T) {
		_, p, id := build()
		got := p.RolesFor(id)
		if len(got) != 1 || len(got[0].Tools) != 1 {
			t.Fatalf("unexpected RolesFor result: %+v", got)
		}
		got[0].Tools[0] = forbidden

		if err := p.Authorize(id, forbidden); err == nil {
			t.Fatal("policy authorized a tool injected by mutating RolesFor's return value -- the request path can rewrite the policy")
		}
		if again := p.RolesFor(id); again[0].Tools[0] != "casemgmt.list_cases" {
			t.Fatalf("RolesFor now returns mutated data: %v", again[0].Tools)
		}
	})
}

// TestNewPolicyRejectsMalformedNames covers the validations added after
// the Phase 4 review: an empty tool name, an untrimmed role name, and an
// empty group key. All three are config that looks plausible and grants
// something nobody intended -- an untrimmed role name in particular
// produces a role that exists, reads correctly in config, and is
// unreachable by any group mapping.
func TestNewPolicyRejectsMalformedNames(t *testing.T) {
	tests := []struct {
		name        string
		roles       []Role
		groupToRole map[string]string
	}{
		{
			name:  "empty tool name",
			roles: []Role{{Name: "n1", Tools: []string{"casemgmt.list_cases", ""}}},
		},
		{
			name:  "whitespace-only tool name",
			roles: []Role{{Name: "n1", Tools: []string{"   "}}},
		},
		{
			name:  "role name with trailing space",
			roles: []Role{{Name: "n1 ", Tools: []string{"casemgmt.list_cases"}}},
		},
		{
			name:  "role name with leading space",
			roles: []Role{{Name: " n1", Tools: []string{"casemgmt.list_cases"}}},
		},
		{
			name:        "empty group key",
			roles:       []Role{{Name: "n1", Tools: []string{"casemgmt.list_cases"}}},
			groupToRole: map[string]string{"": "n1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPolicy(tc.roles, tc.groupToRole)
			if err == nil {
				t.Fatalf("NewPolicy accepted %s", tc.name)
			}
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("error = %v, want it to wrap ErrInvalidPolicy", err)
			}
			if p != nil {
				t.Error("NewPolicy returned a non-nil Policy alongside an error")
			}
		})
	}
}

// TestResourceIdentifier covers the predicate that decides what
// oidc.audience, oidc.issuer and oidc.authorization_servers may hold. It
// lives here, and not in the HTTP adapter that renders the metadata
// document, because two callers now depend on the same answer: the adapter
// at boot, and config.Validate in front of the operator who just edited the
// file. Two copies of this rule is how GAB-30 happened.
func TestResourceIdentifier(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		allowInsecure bool
		wantErr       string
	}{
		{name: "https with a path", raw: "https://gw.soc.internal/mcp"},
		{name: "https bare host", raw: "https://gw.soc.internal"},
		{name: "loopback http", raw: "http://127.0.0.1:8080/mcp"},
		{name: "loopback http by name", raw: "http://localhost:8080/mcp"},
		{name: "ipv6 loopback http", raw: "http://[::1]:8080/mcp"},
		{name: "http when explicitly allowed", raw: "http://gw.soc.internal/mcp", allowInsecure: true},

		{name: "opaque string", raw: "mcp-gateway", wantErr: "absolute URI"},
		{name: "scheme with no host", raw: "https:///mcp", wantErr: "absolute URI"},
		{name: "routable http", raw: "http://gw.soc.internal/mcp", wantErr: "https"},
		{name: "query string", raw: "https://gw.soc.internal/mcp?v=1", wantErr: "query"},
		{name: "fragment", raw: "https://gw.soc.internal/mcp#f", wantErr: "fragment"},
		// An empty fragment leaves URL.Fragment empty but still ships a
		// "#" to every client that reads the metadata, which RFC 9728
		// section 2 forbids outright.
		{name: "empty fragment", raw: "https://gw.soc.internal/mcp#", wantErr: "fragment"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ResourceIdentifier(tc.raw, tc.allowInsecure)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ResourceIdentifier(%q) = %v, want it accepted", tc.raw, err)
				}
				if u == nil {
					t.Fatal("accepted the value but returned no URL")
				}
				return
			}
			if err == nil {
				t.Fatalf("ResourceIdentifier(%q) accepted a value the metadata document cannot carry", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.raw) {
				t.Errorf("error %q does not echo the offending value", err)
			}
		})
	}
}
