package access

import (
	"errors"
	"testing"
)

// TestSecNewPolicyRejectsUntrimmedGroupKey: the oidc adapter TrimSpaces
// every group it reads from the token, so a group_to_role key with leading
// or trailing whitespace can never match any caller: the mapping would
// load, look correct and grant nothing. ValidateRole already refuses the
// same shape for role names for exactly this reason (GAB-30). Ported from
// the internal tree's security pass of 24 Sep 2026.
func TestSecNewPolicyRejectsUntrimmedGroupKey(t *testing.T) {
	roles := []Role{{Name: "dfir-lead", Tools: []string{"casemgmt.delete_case"}}}
	for _, key := range []string{" soc-dfir", "soc-dfir ", "soc-dfir\t", "\nsoc-dfir"} {
		_, err := NewPolicy(roles, map[string]string{key: "dfir-lead"})
		if err == nil {
			t.Fatalf("NewPolicy accepted untrimmed group_to_role key %q, a dead mapping the oidc adapter can never produce", key)
		}
		if !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("key %q: err = %v, want ErrInvalidPolicy", key, err)
		}
	}
	if _, err := NewPolicy(roles, map[string]string{"soc-dfir": "dfir-lead"}); err != nil {
		t.Fatalf("NewPolicy refused a trimmed key: %v", err)
	}
}
