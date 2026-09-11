package registry

import (
	"errors"
	"strings"
	"testing"
)

// TestUpstreamNameRejectsNamespaceSeparator pins the rule that makes the
// gateway's two readings of a namespaced tool name coincide.
//
// A client-facing name is Namespaced(upstream, tool) -- the two joined by a
// separator -- and everything downstream recovers the upstream half by
// cutting at the *first* separator: gateway.SplitNamespaced,
// access.Role.Allows resolving a per-backend grant, `tool approve` deciding
// which roles an approval serves. If a registered name may itself contain
// the separator, that cut lands in the middle of it, and the upstream those
// callers name is not the upstream that serves the call. A grant on
// "threatintel" then reaches the tools of a different registered upstream
// called "threatintel.staging" -- ADR-0016's "resíduo conhecido", which that
// ADR assigns to the registry to close.
func TestUpstreamNameRejectsNamespaceSeparator(t *testing.T) {
	for _, name := range []string{
		"threatintel.staging",
		".threatintel",
		"threatintel.",
		"a.b.c",
	} {
		t.Run(name, func(t *testing.T) {
			s := UpstreamServer{
				Name:      name,
				Transport: TransportStdio,
				Command:   "/usr/local/bin/x",
			}
			err := s.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil for name %q, want an error: its tools would be namespaced under a different upstream than the one that serves them", name)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Validate() error = %v, want it to wrap ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("Validate() error = %v, want it to name the offending value %q", err, name)
			}
		})
	}
}

// TestUpstreamNameAllowsAPrefixOfAnotherName is the other side of the rule,
// and it is here so the fix is not quietly widened later.
//
// Being a prefix of another upstream's name is harmless on its own:
// "threatintel" is a prefix of "threatintelx", and no name
// Namespaced("threatintelx", ...) builds ever begins with "threatintel" plus
// the separator. Only the separator makes a prefix ambiguous, so only the
// separator is refused. Refusing every prefix would cost an operator the
// right to register "casemgmt2" beside "casemgmt" and buy nothing.
func TestUpstreamNameAllowsAPrefixOfAnotherName(t *testing.T) {
	for _, name := range []string{"threatintel", "threatintelx", "threatintel-staging", "threatintel_staging"} {
		s := UpstreamServer{
			Name:      name,
			Transport: TransportStdio,
			Command:   "/usr/local/bin/x",
		}
		if err := s.Validate(); err != nil {
			t.Errorf("Validate() = %v for name %q, want nil", err, name)
		}
	}
}
