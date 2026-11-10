package signer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

// remoteEntry is a well-formed keyed remote entry (ADR-0058): a native MCP
// server reached by URL, sent one secret as a bearer token.
func remoteEntry() registry.UpstreamServer {
	return registry.UpstreamServer{
		Name:        "vendor",
		Transport:   registry.TransportRemote,
		URL:         "https://mcp.vendor.example/v1/mcp",
		AuthKind:    registry.AuthBearer,
		EnvVarNames: []string{"VENDOR_TOKEN"},
		RemoteKind:  registry.RemoteStreamable,
	}
}

// TestCanonicalRemoteUsesADistinctTag: a remote entry signs under
// canonical/v4-remote, and an http entry with the same URL and descriptor
// never produces the same bytes.
func TestCanonicalRemoteUsesADistinctTag(t *testing.T) {
	remote := Canonical(remoteEntry())
	if !bytes.Contains(remote, []byte(canonicalTagV4Remote)) {
		t.Fatal("remote entry canonical does not carry the v4-remote tag")
	}
	for _, tag := range []string{canonicalTagImage, canonicalTagV3HTTP} {
		if bytes.Contains(remote, []byte(tag)) {
			t.Errorf("remote canonical carries the %s tag", tag)
		}
	}
	h := remoteEntry()
	h.Transport, h.RemoteKind, h.Operations = registry.TransportHTTP, "", []byte(`[]`)
	if bytes.Equal(Canonical(h), remote) {
		t.Error("http and remote entries produced equal canonical bytes")
	}
}

// TestCanonicalRemoteCoversURLAuthAndKind: every field ADR-0058 §5 names
// is in the signed bytes, so a direct database write to any of them breaks
// the signature.
func TestCanonicalRemoteCoversURLAuthAndKind(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	sig := s.Sign(remoteEntry())
	if err := v.Verify(remoteEntry(), sig); err != nil {
		t.Fatalf("untouched entry: %v", err)
	}
	cases := map[string]func(*registry.UpstreamServer){
		"url host":         func(e *registry.UpstreamServer) { e.URL = "https://mcp.attacker.example/v1/mcp" },
		"url port":         func(e *registry.UpstreamServer) { e.URL = "https://mcp.vendor.example:8443/v1/mcp" },
		"url path":         func(e *registry.UpstreamServer) { e.URL = "https://mcp.vendor.example/v2/mcp" },
		"url scheme":       func(e *registry.UpstreamServer) { e.URL = "http://mcp.vendor.example/v1/mcp" },
		"auth kind":        func(e *registry.UpstreamServer) { e.AuthKind, e.AuthName = registry.AuthHeader, "X-Api-Key" },
		"auth name":        func(e *registry.UpstreamServer) { e.AuthKind, e.AuthName = registry.AuthHeader, "X-Other" },
		"remote kind":      func(e *registry.UpstreamServer) { e.RemoteKind = registry.RemoteSSE },
		"remote kind lost": func(e *registry.UpstreamServer) { e.RemoteKind = "" },
		"secret ref":       func(e *registry.UpstreamServer) { e.EnvVarNames = []string{"OTHER_TOKEN"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := remoteEntry()
			mutate(&e)
			if err := v.Verify(e, sig); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("signature still verifies after changing the %s: %v", name, err)
			}
		})
	}
}
