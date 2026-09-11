package access

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Tests for the per-backend grant form added by
// design/adr/0016-per-backend-role-grants.md -- what ADR-0036 of the
// reference design calls a "profile".
//
// Everything here is about Role.Grants. The flat Role.Tools list is
// unchanged and its own tests (TestAuthorize_HasNoWildcardMatching above
// all) still assert that it has no wildcard; the two forms are
// deliberately different dialects and both files should stay readable as
// such.

func grantPolicy(t *testing.T, roles []Role, mapping map[string]string) *Policy {
	t.Helper()
	p, err := NewPolicy(roles, mapping)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

// -----------------------------------------------------------------------
// What a grant grants
// -----------------------------------------------------------------------

// TestRoleGrants_NamedToolsOnTheNamedBackend is the base case: a grant
// names a backend and tool ids on it, and those become callable under
// their namespaced names.
//
// The ids are written WITHOUT the namespace -- "get_case", not
// "casemgmt.get_case" -- because the key already says which backend they
// are on. Repeating it would be the second place a name could be wrong.
func TestRoleGrants_NamedToolsOnTheNamedBackend(t *testing.T) {
	p := grantPolicy(t,
		[]Role{{Name: "n1", Grants: map[string][]string{"casemgmt": {"get_case", "add_note"}}}},
		map[string]string{"soc-n1": "n1"},
	)
	id := Identity{Subject: "u1", Groups: []string{"soc-n1"}}

	for _, tool := range []string{"casemgmt.get_case", "casemgmt.add_note"} {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil", tool, err)
		}
	}
	for _, tool := range []string{
		"casemgmt.delete_case", // same backend, not granted
		"casemgmt.get_case_v2", // the granted id is a prefix of this one
		"casemgmt.get_cas",     // this one is a prefix of the granted id
		"casemgmt.",
		"casemgmt",
		"get_case",              // un-namespaced: not what the policy gates
		"threatintel.get_case",  // right tool id, backend never granted
		"CASEMGMT.GET_CASE",     // exact means case-sensitive here too
		" casemgmt.get_case",    // no trimming of the name under test
		"casemgmt.get_case ",    //
		"casemgmt.get_case.sub", // a deeper name is not the granted one
	} {
		if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden", tool, err)
		}
	}
}

// TestRoleGrants_WildcardCoversTheWholeBackend is the capability the old
// comment on Role.Tools refused outright ("there is no wildcard, because a
// wildcard is how a role silently gains a tool that was added to an
// upstream later"). ADR-0016 revises that, and this pins what the revision
// actually delivers: every tool of the named backend, and nothing of any
// other.
//
// Note what this test does NOT show, because it is a domain test and
// cannot: that a tool the wildcard reaches is still refused until an
// operator approves it in Tool Quarantine. That is the whole basis for
// allowing the wildcard at all, and it is asserted end to end in
// TestWildcardGrantServesOnlyApprovedTools
// (internal/config/grants_integration_test.go).
func TestRoleGrants_WildcardCoversTheWholeBackend(t *testing.T) {
	p := grantPolicy(t,
		[]Role{{Name: "hunter", Grants: map[string][]string{"threatintel": {GrantAll}}}},
		map[string]string{"soc-hunt": "hunter"},
	)
	id := Identity{Subject: "u1", Groups: []string{"soc-hunt"}}

	// Names the role's author never wrote and could not have: the point of
	// the wildcard is that a tool appearing later is covered.
	for _, tool := range []string{
		"threatintel.lookup_ip",
		"threatintel.virustotal",
		"threatintel.a_tool_invented_after_the_role_was_reviewed",
		"threatintel.x",
		"threatintel.has.dots.in.its.own.name",
	} {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil under a %q grant", tool, err, GrantAll)
		}
	}

	// And the boundary. "threatintel." is not a tool of threatintel, it is
	// a malformed name; a prefix test written without the empty-remainder
	// guard in Role.Allows would let it through.
	for _, tool := range []string{
		"threatintel.",
		"threatintel",
		"threatintelx.lookup_ip", // the separator is what bounds the backend
		"threatintel2.lookup_ip",
		"casemgmt.lookup_ip",
		"*",
		"",
	} {
		if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden -- %q covers one backend's tools, nothing else", tool, err, GrantAll)
		}
	}
}

// TestRoleGrants_DoNotLeakIntoARoleThatLacksThem is the isolation
// property, and it is the one a per-caller grant layer exists for: two
// roles over the same backend fleet must produce two different menus.
//
// Both directions are asserted, because a leak in either is the same bug
// wearing a different hat.
func TestRoleGrants_DoNotLeakIntoARoleThatLacksThem(t *testing.T) {
	roles := []Role{
		{Name: "triage", Grants: map[string][]string{"casemgmt": {"get_case"}}},
		{Name: "hunt", Grants: map[string][]string{"threatintel": {GrantAll}}},
		{Name: "nothing"},
	}
	mapping := map[string]string{"soc-triage": "triage", "soc-hunt": "hunt", "soc-none": "nothing"}
	p := grantPolicy(t, roles, mapping)

	triage := Identity{Subject: "t", Groups: []string{"soc-triage"}}
	hunt := Identity{Subject: "h", Groups: []string{"soc-hunt"}}
	none := Identity{Subject: "n", Groups: []string{"soc-none"}}

	if err := p.Authorize(triage, "casemgmt.get_case"); err != nil {
		t.Fatalf("premise broken: triage cannot reach its own tool: %v", err)
	}
	if err := p.Authorize(hunt, "threatintel.lookup_ip"); err != nil {
		t.Fatalf("premise broken: hunt cannot reach its own tool: %v", err)
	}

	for _, tc := range []struct {
		who  Identity
		tool string
	}{
		{triage, "threatintel.lookup_ip"}, // hunt's wildcard must not reach triage
		{triage, "threatintel.anything"},
		{hunt, "casemgmt.get_case"}, // triage's named grant must not reach hunt
		{none, "casemgmt.get_case"}, // a role with no grants at all gets nothing
		{none, "threatintel.lookup_ip"},
	} {
		if err := p.Authorize(tc.who, tc.tool); !errors.Is(err, ErrForbidden) {
			t.Errorf("Authorize(%q, %q) = %v, want ErrForbidden -- a grant reached a role that does not hold it",
				tc.who.Subject, tc.tool, err)
		}
	}

	// The same statement as a menu rather than as a decision, since that is
	// the form an analyst actually meets.
	advertised := []string{"casemgmt.get_case", "casemgmt.delete_case", "threatintel.lookup_ip", "threatintel.shodan"}
	for _, tc := range []struct {
		who  Identity
		want []string
	}{
		{triage, []string{"casemgmt.get_case"}},
		{hunt, []string{"threatintel.lookup_ip", "threatintel.shodan"}},
		{none, nil},
	} {
		got := p.AllowedTools(tc.who, advertised)
		slices.Sort(tc.want)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("AllowedTools(%q) = %v, want %v", tc.who.Subject, got, tc.want)
		}
	}
}

// TestRoleGrants_UnionWithTheFlatToolsList: the two forms compose inside
// one role, and neither shadows the other. ADR-0016 keeps the flat form
// valid rather than deprecating it, so a role written before the grant
// form existed and then extended must grant the sum.
func TestRoleGrants_UnionWithTheFlatToolsList(t *testing.T) {
	p := grantPolicy(t,
		[]Role{{
			Name:   "both",
			Tools:  []string{"logsearch.search_relative"},
			Grants: map[string][]string{"casemgmt": {"get_case"}},
		}},
		map[string]string{"g": "both"},
	)
	id := Identity{Subject: "u", Groups: []string{"g"}}

	for _, tool := range []string{"logsearch.search_relative", "casemgmt.get_case"} {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil -- tools and grants union", tool, err)
		}
	}
	// The flat entry does not make the whole of logsearch reachable, and
	// the grant does not make the whole of casemgmt reachable.
	for _, tool := range []string{"logsearch.search_absolute", "casemgmt.delete_case"} {
		if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden", tool, err)
		}
	}
}

// TestRoleGrants_UnionAcrossSeveralRoles: an analyst in two mapped groups
// holds both roles, and the grants of both apply. This is the reason
// ADR-0016 keeps grants ON the role rather than introducing a separate
// one-profile-per-caller binding -- RolesFor returns several roles and
// unions them, and a profile that replaced the role would have had to pick
// one.
func TestRoleGrants_UnionAcrossSeveralRoles(t *testing.T) {
	p := grantPolicy(t,
		[]Role{
			{Name: "a", Grants: map[string][]string{"casemgmt": {"get_case"}}},
			{Name: "b", Grants: map[string][]string{"casemgmt": {"add_note"}, "docsearch": {GrantAll}}},
		},
		map[string]string{"ga": "a", "gb": "b"},
	)
	id := Identity{Subject: "u", Groups: []string{"ga", "gb"}}

	for _, tool := range []string{"casemgmt.get_case", "casemgmt.add_note", "docsearch.anything"} {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("Authorize(%q) = %v, want nil", tool, err)
		}
	}
	if err := p.Authorize(id, "casemgmt.delete_case"); !errors.Is(err, ErrForbidden) {
		t.Error("two roles granting different tools of one backend must not add up to the whole backend")
	}
}

// TestRoleGrants_EmptyListGrantsNothing. `casemgmt = []` is a legitimate
// thing to write -- it is a backend being staged, or one whose grants were
// emptied during an incident -- and it must mean what it says rather than
// falling back to anything.
func TestRoleGrants_EmptyListGrantsNothing(t *testing.T) {
	p := grantPolicy(t,
		[]Role{{Name: "staged", Grants: map[string][]string{"casemgmt": {}}}},
		map[string]string{"g": "staged"},
	)
	id := Identity{Subject: "u", Groups: []string{"g"}}
	for _, tool := range []string{"casemgmt.get_case", "casemgmt.", "casemgmt.x"} {
		if err := p.Authorize(id, tool); !errors.Is(err, ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden under an empty grant list", tool, err)
		}
	}
}

// -----------------------------------------------------------------------
// Structural validation
// -----------------------------------------------------------------------

// TestValidateRole_RejectsMalformedGrants covers every structural rule
// validateGrants owns. Each case is a single defect in an otherwise
// well-formed role, so a failure points at the rule and not at the
// fixture.
//
// Every one of these is refused rather than tolerated for the same reason:
// left to load, each produces a file that reads as one grant and enforces
// another. wantMsg pins the part of the message an operator would search
// for.
func TestValidateRole_RejectsMalformedGrants(t *testing.T) {
	for _, tc := range []struct {
		name    string
		grants  map[string][]string
		wantMsg string
	}{
		{
			name:    "empty backend key",
			grants:  map[string][]string{"": {"get_case"}},
			wantMsg: "empty backend name",
		},
		{
			name:    "whitespace-only backend key",
			grants:  map[string][]string{"   ": {"get_case"}},
			wantMsg: "empty backend name",
		},
		{
			name:    "untrimmed backend key",
			grants:  map[string][]string{"casemgmt ": {"get_case"}},
			wantMsg: "leading or trailing whitespace",
		},
		{
			// It reads as "every backend" and is not that. Load-bearing
			// rather than pedantic: the file would state a fleet-wide grant
			// and enforce nothing.
			name:    "star as a backend key",
			grants:  map[string][]string{GrantAll: {"get_case"}},
			wantMsg: "no wildcard over backends",
		},
		{
			// The one whose absence would be a real over-grant: see
			// Role.Allows on why a key containing the separator can match
			// a tool that belongs to a different backend.
			name:    "separator in the backend key",
			grants:  map[string][]string{"casemgmt.sub": {"get_case"}},
			wantMsg: "contains",
		},
		{
			name:    "namespaced tool id inside a grant",
			grants:  map[string][]string{"casemgmt": {"casemgmt.get_case"}},
			wantMsg: "not namespaced",
		},
		{
			name:    "empty tool id",
			grants:  map[string][]string{"casemgmt": {"get_case", ""}},
			wantMsg: "empty tool id",
		},
		{
			name:    "untrimmed tool id",
			grants:  map[string][]string{"casemgmt": {"get_case "}},
			wantMsg: "leading or trailing whitespace",
		},
		{
			name:    "star mixed with named tools",
			grants:  map[string][]string{"casemgmt": {GrantAll, "get_case"}},
			wantMsg: "already grants every tool",
		},
		{
			name:    "star mixed, named tool first",
			grants:  map[string][]string{"casemgmt": {"get_case", GrantAll}},
			wantMsg: "already grants every tool",
		},
		{
			name:    "star repeated",
			grants:  map[string][]string{"casemgmt": {GrantAll, GrantAll}},
			wantMsg: "already grants every tool",
		},
		{
			name:    "duplicate tool id",
			grants:  map[string][]string{"casemgmt": {"get_case", "add_note", "get_case"}},
			wantMsg: "more than once",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Role{Name: "n1", Grants: tc.grants}

			err := ValidateRole(r)
			if err == nil {
				t.Fatalf("ValidateRole accepted %+v", tc.grants)
			}
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("error does not wrap ErrInvalidPolicy: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error does not contain %q: %v", tc.wantMsg, err)
			}

			// NewPolicy must refuse it too. ValidateRole is the rule;
			// NewPolicy applying it is what stops a caller that skipped
			// config from building a policy the domain would not accept.
			if _, err := NewPolicy([]Role{r}, nil); !errors.Is(err, ErrInvalidPolicy) {
				t.Errorf("NewPolicy accepted a role ValidateRole refuses: %v", err)
			}
		})
	}
}

// TestValidateRole_AcceptsWellFormedGrants is the other half: the rules
// above must not be so eager that an ordinary grant is refused. A test
// suite that only ever asserts refusals passes trivially against a
// ValidateRole that refuses everything.
func TestValidateRole_AcceptsWellFormedGrants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		grants map[string][]string
	}{
		{"named tools", map[string][]string{"casemgmt": {"get_case", "add_note"}}},
		{"whole-backend wildcard", map[string][]string{"threatintel": {GrantAll}}},
		{"several backends", map[string][]string{"casemgmt": {"get_case"}, "threatintel": {GrantAll}}},
		{"empty list", map[string][]string{"casemgmt": {}}},
		{"empty map", map[string][]string{}},
		{"nil map", nil},
		{"underscores and digits", map[string][]string{"threat_intel2": {"lookup_ip_v6"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateRole(Role{Name: "n1", Grants: tc.grants}); err != nil {
				t.Errorf("ValidateRole refused a well-formed grant %+v: %v", tc.grants, err)
			}
		})
	}
}

// TestValidateRole_ReportsEveryGrantProblemAtOnce. The file's contract is
// that one pass over it lists everything wrong with it, and grants are not
// exempt: an operator fixing four typos one restart at a time is the
// experience ValidateRole's joined errors exist to prevent.
func TestValidateRole_ReportsEveryGrantProblemAtOnce(t *testing.T) {
	err := ValidateRole(Role{
		Name: "n1",
		Grants: map[string][]string{
			"":             {"a"},
			"casemgmt.sub": {"b"},
			"threatintel":  {GrantAll, "c"},
			"docsearch":    {"d", "d"},
		},
	})
	if err == nil {
		t.Fatal("ValidateRole accepted a role with four distinct defects")
	}
	for _, want := range []string{"empty backend name", "casemgmt.sub", "already grants every tool", "more than once"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error omits %q: %v", want, err)
		}
	}
}

// TestValidateRole_GrantErrorOrderIsStable. Map iteration order is random
// in Go, so an error list built by ranging over Grants would reshuffle
// between two runs over one unchanged file -- and an operator diffing two
// startup failures would see churn that means nothing.
func TestValidateRole_GrantErrorOrderIsStable(t *testing.T) {
	r := Role{Name: "n1", Grants: map[string][]string{
		"aaa": {""},
		"bbb": {""},
		"ccc": {""},
		"ddd": {""},
		"eee": {""},
	}}
	want := ValidateRole(r).Error()
	for i := range 50 {
		if got := ValidateRole(r).Error(); got != want {
			t.Fatalf("iteration %d: error text changed between runs:\n%s\n\nvs\n\n%s", i, got, want)
		}
	}
}

// -----------------------------------------------------------------------
// Immutability
// -----------------------------------------------------------------------

// TestPolicyGrantsAreActuallyImmutable is TestPolicyIsActuallyImmutable one
// level deeper. Grants is a map of slices, so a copy that is shallow in
// EITHER dimension leaves the live policy writable from outside: a shallow
// map copy shares every value slice, and no copy at all shares the map.
//
// Verified to fail with cloneGrants replaced by a plain assignment, and
// again with it replaced by a top-level-only map copy.
func TestPolicyGrantsAreActuallyImmutable(t *testing.T) {
	const forbidden = "casemgmt.delete_case"

	build := func() ([]Role, *Policy, Identity) {
		roles := []Role{{Name: "n1", Grants: map[string][]string{"casemgmt": {"get_case"}}}}
		p := grantPolicy(t, roles, map[string]string{"soc-n1": "n1"})
		return roles, p, Identity{Subject: "u1", Groups: []string{"soc-n1"}}
	}

	t.Run("rewriting a granted id in the constructor's input", func(t *testing.T) {
		roles, p, id := build()
		roles[0].Grants["casemgmt"][0] = "delete_case"
		if err := p.Authorize(id, forbidden); err == nil {
			t.Fatal("policy authorized a tool injected by mutating the grant slice passed to NewPolicy")
		}
	})

	t.Run("adding a backend to the constructor's input", func(t *testing.T) {
		roles, p, id := build()
		roles[0].Grants["threatintel"] = []string{GrantAll}
		if err := p.Authorize(id, "threatintel.anything"); err == nil {
			t.Fatal("policy authorized a backend added to the map passed to NewPolicy")
		}
	})

	t.Run("rewriting a granted id in RolesFor's output", func(t *testing.T) {
		_, p, id := build()
		got := p.RolesFor(id)
		if len(got) != 1 || len(got[0].Grants["casemgmt"]) != 1 {
			t.Fatalf("unexpected RolesFor result: %+v", got)
		}
		got[0].Grants["casemgmt"][0] = "delete_case"
		if err := p.Authorize(id, forbidden); err == nil {
			t.Fatal("policy authorized a tool injected by mutating RolesFor's return value -- the request path can rewrite the policy")
		}
		if again := p.RolesFor(id); again[0].Grants["casemgmt"][0] != "get_case" {
			t.Fatalf("RolesFor now returns mutated data: %v", again[0].Grants)
		}
	})

	t.Run("adding a backend to RolesFor's output", func(t *testing.T) {
		_, p, id := build()
		p.RolesFor(id)[0].Grants["threatintel"] = []string{GrantAll}
		if err := p.Authorize(id, "threatintel.anything"); err == nil {
			t.Fatal("policy authorized a backend added to RolesFor's returned map")
		}
	})
}

// TestRolesFor_NilGrantsStayNil: a role with no per-backend grants must not
// acquire an empty map on its way through the policy. Nothing depends on
// the difference for a decision, but RolesFor's output is compared in tests
// and rendered by the operator surface, and "grants: {}" says something
// different from "grants: none".
func TestRolesFor_NilGrantsStayNil(t *testing.T) {
	p := grantPolicy(t,
		[]Role{{Name: "flat", Tools: []string{"casemgmt.list_cases"}}},
		map[string]string{"g": "flat"},
	)
	got := p.RolesFor(Identity{Subject: "u", Groups: []string{"g"}})
	if len(got) != 1 {
		t.Fatalf("RolesFor = %+v, want one role", got)
	}
	if got[0].Grants != nil {
		t.Errorf("Grants = %v, want nil for a role that declared none", got[0].Grants)
	}
	if !reflect.DeepEqual(got[0].Tools, []string{"casemgmt.list_cases"}) {
		t.Errorf("Tools = %v, want the role's flat list", got[0].Tools)
	}
}
