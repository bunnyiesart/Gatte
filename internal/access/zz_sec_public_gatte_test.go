package access

// Authorization-bypass shapes for per-backend grants (public Gatte).

import "testing"

func TestSecGrantDoesNotBleedAcrossNames(t *testing.T) {
	p, err := NewPolicy([]Role{{
		Name:   "r",
		Tools:  []string{"cases.get_case"},
		Grants: map[string][]string{"edr": {"get_host"}, "intel": {GrantAll}},
	}}, map[string]string{"g": "r"})
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "s", Groups: []string{"g"}}
	allowed := []string{"cases.get_case", "edr.get_host", "intel.lookup_ip", "intel.a.b"}
	denied := []string{
		"edr.get_hostx", "edr.get_hos", "edr.GET_HOST", "EDR.get_host", "edr..get_host",
		"edr.get_host ", " edr.get_host", "edr.get_host\x00", "edr.", "edr", "edrx.get_host",
		"intel", "intel.", "intelx.lookup_ip", "Intel.lookup_ip", ".intel.lookup_ip",
		"cases.get_case ", "cases.get_casex", "cases.*", "*", "", "edr.*",
		"cases.get_case.x", "x.cases.get_case",
	}
	for _, tool := range allowed {
		if err := p.Authorize(id, tool); err != nil {
			t.Errorf("control: %q should be allowed: %v", tool, err)
		}
	}
	for _, tool := range denied {
		if err := p.Authorize(id, tool); err == nil {
			t.Errorf("%q was authorized", tool)
		}
	}
	// No group, unknown group, empty-string group, group differing by case
	// or whitespace: nothing.
	for _, groups := range [][]string{nil, {}, {""}, {"G"}, {" g"}, {"g "}, {"other"}} {
		if err := p.Authorize(Identity{Subject: "s", Groups: groups}, "edr.get_host"); err == nil {
			t.Errorf("groups %q were authorized", groups)
		}
	}
}

func TestSecGrantKeysThatCouldConfuseRoutingAreRefused(t *testing.T) {
	for _, key := range []string{"", " ", "a.b", ".", "edr.", ".edr", "*"} {
		r := Role{Name: "r", Grants: map[string][]string{key: {"x"}}}
		if err := ValidateRole(r); err == nil {
			t.Errorf("grant key %q was accepted", key)
		}
	}
	for _, id := range []string{"", " ", "a.b"} {
		r := Role{Name: "r", Grants: map[string][]string{"edr": {id}}}
		if err := ValidateRole(r); err == nil {
			t.Errorf("grant id %q was accepted", id)
		}
	}
}

// TestSecGlobLookalikesAreInertLiterals: "edr*" as a key and "*x"/"x*" as
// ids are accepted by ValidateRole but must behave as literals that match
// nothing real -- never as prefix/suffix wildcards.
func TestSecGlobLookalikesAreInertLiterals(t *testing.T) {
	r := Role{Name: "r", Grants: map[string][]string{"edr*": {GrantAll}, "intel": {"*x", "look*"}}}
	if err := ValidateRole(r); err != nil {
		t.Fatalf("ValidateRole accepts glob lookalikes; if this changes, update the literal-match expectations below: %v", err)
	}
	for _, tool := range []string{"edr.get_host", "edrx.get_host", "intel.abcx", "intel.lookup_ip", "intel.x"} {
		if r.Allows(tool) {
			t.Errorf("glob lookalike granted %q", tool)
		}
	}
}
