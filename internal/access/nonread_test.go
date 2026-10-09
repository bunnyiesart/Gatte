package access

import (
	"errors"
	"testing"
)

// Tests for the role marking and the name-only predicate that
// design/adr/0048 Decisão 5 added for the gateway's class-aware gate.
//
// Everything here is class-blind on purpose: no test mentions a security
// class, because this package never learns one. What is pinned is that
// Role.Allows is UNCHANGED by the new field, that AllowsExplicitly reads
// the flat list and nothing else, and that AuthorizeNonRead needs both the
// marking and the explicit name on ONE role.

// TestAllowsExplicitly_ReadsTheFlatListOnly: a Grants entry, wildcard or
// named, is not an explicit grant. The whole point of the predicate is that
// "every tool this backend advertises, now and later" is not a decision
// about any one tool.
func TestAllowsExplicitly_ReadsTheFlatListOnly(t *testing.T) {
	r := Role{
		Name:   "mixed",
		Tools:  []string{"casemgmt.close_case"},
		Grants: map[string][]string{"casemgmt": {GrantAll}, "threatintel": {"submit_sample"}},
	}
	for _, tc := range []struct {
		tool             string
		allows, explicit bool
	}{
		{"casemgmt.close_case", true, true},        // named in Tools
		{"casemgmt.list_cases", true, false},       // reached by the wildcard only
		{"threatintel.submit_sample", true, false}, // reached by a named Grants id only
		{"threatintel.lookup_ip", false, false},
	} {
		if got := r.Allows(tc.tool); got != tc.allows {
			t.Errorf("Allows(%q) = %v, want %v -- Allows must be unchanged by the new field", tc.tool, got, tc.allows)
		}
		if got := r.AllowsExplicitly(tc.tool); got != tc.explicit {
			t.Errorf("AllowsExplicitly(%q) = %v, want %v", tc.tool, got, tc.explicit)
		}
	}
}

// TestAllowsExplicitly_HasNoWildcard restates TestAuthorize_HasNoWildcardMatching
// for the new predicate: a "*" in Tools is a name, and matches nothing.
func TestAllowsExplicitly_HasNoWildcard(t *testing.T) {
	r := Role{Name: "star", Tools: []string{GrantAll, "casemgmt.*"}}
	for _, tool := range []string{"casemgmt.close_case", "casemgmt.list_cases", "x"} {
		if r.AllowsExplicitly(tool) {
			t.Errorf("AllowsExplicitly(%q) = true under Tools %v: the flat list has no wildcard", tool, r.Tools)
		}
	}
}

// TestNonRead_SurvivesThePolicy: the marking must come out of RolesFor the
// way it went into NewPolicy. Both copy the Role field by field, and a
// field left out there is exactly the silent drop reload.toAccess once had
// (ADR-0048): the gate would then refuse every sensitive tool for every
// role, with the file saying otherwise.
func TestNonRead_SurvivesThePolicy(t *testing.T) {
	p := grantPolicy(t,
		[]Role{
			{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true},
			{Name: "n1-triage", Tools: []string{"casemgmt.list_cases"}},
		},
		map[string]string{"soc-dfir": "dfir-lead", "soc-n1": "n1-triage"},
	)
	got := p.RolesFor(Identity{Subject: "u", Groups: []string{"soc-n1", "soc-dfir"}})
	if len(got) != 2 {
		t.Fatalf("RolesFor = %+v, want two roles", got)
	}
	// Sorted by name: dfir-lead, n1-triage.
	if !got[0].NonRead || got[0].Name != "dfir-lead" {
		t.Errorf("role %q NonRead = %v, want true", got[0].Name, got[0].NonRead)
	}
	if got[1].NonRead || got[1].Name != "n1-triage" {
		t.Errorf("role %q NonRead = %v, want false", got[1].Name, got[1].NonRead)
	}
}

// TestAuthorizeNonRead_NeedsTheMarkingAndTheNameOnOneRole is the domain
// half of the bypass ADR-0048's review caught: a read role with a
// per-backend wildcard reaches, by Allows, every tool that backend
// advertises -- including one that can act. The narrower question must
// say no to that, yes only to a role that is marked AND names the tool,
// and no to the two halves spread over two roles.
func TestAuthorizeNonRead_NeedsTheMarkingAndTheNameOnOneRole(t *testing.T) {
	const tool = "casemgmt.close_case"
	roles := []Role{
		{Name: "read-wildcard", Grants: map[string][]string{"casemgmt": {GrantAll}}},
		{Name: "read-explicit", Tools: []string{tool}},
		{Name: "nonread-wildcard", Grants: map[string][]string{"casemgmt": {GrantAll}}, NonRead: true},
		{Name: "nonread-explicit", Tools: []string{tool}, NonRead: true},
		{Name: "nonread-grants-id", Grants: map[string][]string{"casemgmt": {"close_case"}}, NonRead: true},
	}
	mapping := map[string]string{}
	for _, r := range roles {
		mapping["g-"+r.Name] = r.Name
	}
	p := grantPolicy(t, roles, mapping)

	for _, tc := range []struct {
		name   string
		groups []string
		want   bool
	}{
		{"wildcard in a read role: the bypass", []string{"g-read-wildcard"}, false},
		{"explicit name in a read role", []string{"g-read-explicit"}, false},
		{"wildcard in a non-read role", []string{"g-nonread-wildcard"}, false},
		{"a named Grants id in a non-read role is not the flat list", []string{"g-nonread-grants-id"}, false},
		{"explicit name in a non-read role", []string{"g-nonread-explicit"}, true},
		{"the two halves on two different roles", []string{"g-read-explicit", "g-nonread-wildcard"}, false},
		{"one qualifying role among others", []string{"g-read-wildcard", "g-nonread-explicit"}, true},
		{"no role at all", nil, false},
	} {
		id := Identity{Subject: "u", Groups: tc.groups}
		err := p.AuthorizeNonRead(id, tool)
		if (err == nil) != tc.want {
			t.Errorf("%s: AuthorizeNonRead = %v, want allowed=%v", tc.name, err, tc.want)
		}
		if err != nil && !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: refusal = %v, want one wrapping ErrForbidden", tc.name, err)
		}
		// Every one of these callers passes Authorize by name except the
		// last: the narrower question is asked after it and is strictly
		// narrower, never wider.
		if tc.want && p.Authorize(id, tool) != nil {
			t.Errorf("%s: AuthorizeNonRead allowed what Authorize refuses", tc.name)
		}
	}
}

// TestAuthorizeNonRead_RefusalReadsLikeAuthorize: at the boundary the two
// refusals are one class. The text is pinned equal so the serving adapter
// -- and a client reading the body -- cannot tell which gate said no.
func TestAuthorizeNonRead_RefusalReadsLikeAuthorize(t *testing.T) {
	p := grantPolicy(t, []Role{{Name: "none", Tools: []string{"x.y"}}}, map[string]string{"g": "none"})
	id := Identity{Subject: "sub-1", Groups: []string{"g"}}
	a := p.Authorize(id, "casemgmt.close_case")
	b := p.AuthorizeNonRead(id, "casemgmt.close_case")
	if a == nil || b == nil || a.Error() != b.Error() {
		t.Fatalf("Authorize = %v, AuthorizeNonRead = %v: want the same refusal text", a, b)
	}
}
