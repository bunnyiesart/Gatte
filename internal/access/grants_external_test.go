// This file is package access_test rather than package access for one
// reason: it needs to import internal/gateway, and internal/gateway
// imports internal/access. An in-package test file could not do that
// without a cycle; an external test package can, because it is compiled as
// a separate package that depends on both.
package access_test

import (
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// TestNameSeparatorMatchesGateway pins the one value this project states
// twice.
//
// internal/access resolves a per-backend grant by finding which backend a
// namespaced name belongs to, which means it needs the separator that
// joins the two halves. It cannot import gateway.NameSeparator for it (the
// dependency runs the other way), so it declares its own unexported copy.
// A rule stated twice is a rule that will diverge -- this project has the
// GAB-30 scars to prove it -- so the two are held equal here instead of
// trusted to stay that way.
//
// If they ever diverge the failure is not cosmetic. A grant on "casemgmt"
// would stop matching the tools the routing table namespaces under
// "casemgmt", and every per-backend grant in the fleet would silently
// authorize nothing.
//
// access.nameSeparator is unexported, so this reaches it the only way an
// external test can: through the behaviour it drives. A role granting
// every tool of "casemgmt" must accept exactly the name
// gateway.Namespaced builds for that backend.
func TestNameSeparatorMatchesGateway(t *testing.T) {
	p, err := access.NewPolicy(
		[]access.Role{{Name: "r", Grants: map[string][]string{"casemgmt": {access.GrantAll}}}},
		map[string]string{"g": "r"},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	id := access.Identity{Subject: "u", Groups: []string{"g"}}

	name := gateway.Namespaced("casemgmt", "list_cases")
	if err := p.Authorize(id, name); err != nil {
		t.Fatalf("a %q grant on %q does not authorize %q (= %v): "+
			"internal/access and internal/gateway disagree about the namespace separator, "+
			"so every per-backend grant authorizes nothing",
			access.GrantAll, "casemgmt", name, err)
	}

	// The same check for a named id, which exercises the other half of
	// Role.Allows: the remainder after the separator must be the tool id
	// exactly as gateway.SplitNamespaced would recover it.
	p2, err := access.NewPolicy(
		[]access.Role{{Name: "r", Grants: map[string][]string{"casemgmt": {"list_cases"}}}},
		map[string]string{"g": "r"},
	)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	if err := p2.Authorize(id, name); err != nil {
		t.Fatalf("a named grant of %q on %q does not authorize %q (= %v)", "list_cases", "casemgmt", name, err)
	}
	upstream, tool, ok := gateway.SplitNamespaced(name)
	if !ok || upstream != "casemgmt" || tool != "list_cases" {
		t.Fatalf("gateway.SplitNamespaced(%q) = (%q, %q, %v): the premise of the check above no longer holds",
			name, upstream, tool, ok)
	}
}
