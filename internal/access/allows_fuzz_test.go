package access

import (
	"slices"
	"strings"
	"testing"
)

// FuzzRoleAllowsStaysOnGrantedBackend checks the property Role.Allows' doc
// states after the 11 Sep 2026 cross-backend grant bug: for a role that
// ValidateRole accepts, a tool allowed through Grants is always one whose
// first-separator prefix -- the upstream routing actually dispatches to --
// is a granted backend, and the tool id after it is granted there.
func FuzzRoleAllowsStaysOnGrantedBackend(f *testing.F) {
	f.Add("threatintel", "*", "threatintel.staging.lookup")
	f.Add("casemgmt", "list_cases", "casemgmt.list_cases")
	f.Add("casemgmt", "*", "casemgmt.")
	f.Add("a.b", "*", "a.b.c")
	f.Add("casemgmt", "sub.x", "casemgmt.sub.x")
	f.Fuzz(func(t *testing.T, backend, id, tool string) {
		r := Role{Name: "fuzz", Grants: map[string][]string{backend: {id}}}
		if ValidateRole(r) != nil {
			return
		}
		if !r.Allows(tool) {
			return
		}
		up, rest, ok := strings.Cut(tool, nameSeparator)
		if !ok || rest == "" {
			t.Fatalf("role %+v allowed malformed tool %q", r, tool)
		}
		ids, granted := r.Grants[up]
		if !granted {
			t.Fatalf("role granting backend %q allowed %q, which routes to backend %q", backend, tool, up)
		}
		if !slices.Contains(ids, GrantAll) && !slices.Contains(ids, rest) {
			t.Fatalf("role %+v allowed %q whose id %q is not granted on %q", r, tool, rest, up)
		}
	})
}
