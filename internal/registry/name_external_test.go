// This file is package registry_test rather than package registry for the
// reason internal/access/grants_external_test.go gives about itself: it
// imports internal/gateway, and internal/gateway imports internal/registry.
// An in-package test file would be a cycle; an external test package is
// compiled separately and may depend on both.
package registry_test

import (
	"testing"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// TestRegistryNameSeparatorMatchesGateway pins the third declaration of the
// one character this project now states three times.
//
// gateway.NameSeparator is the original; access.nameSeparator is the second
// (pinned by TestNameSeparatorMatchesGateway); registry's is the third, and
// it exists for the same reason the second does -- internal/gateway imports
// internal/registry, so the dependency cannot run back the other way.
//
// Divergence here is not cosmetic. registry's rule is what guarantees that
// cutting a namespaced name at the first separator recovers the upstream
// that actually serves it. If registry refused some other character while
// the gateway kept joining on this one, the rule would refuse harmless names
// and permit exactly the ambiguous ones it exists to keep out.
//
// The constant is unexported, so this reaches it the only way an external
// test can: through the behaviour it drives.
func TestRegistryNameSeparatorMatchesGateway(t *testing.T) {
	ambiguous := gateway.Namespaced("threatintel", "staging")
	s := registry.UpstreamServer{
		Name:      ambiguous,
		Transport: registry.TransportStdio,
		Command:   "/usr/local/bin/x",
	}
	if err := s.Validate(); err == nil {
		t.Fatalf("Validate() = nil for the name %q, which gateway.Namespaced itself builds: "+
			"internal/registry and internal/gateway disagree about the namespace separator, so an upstream can be registered "+
			"under a name whose tools route to it and authorize as another backend's", ambiguous)
	}
}
