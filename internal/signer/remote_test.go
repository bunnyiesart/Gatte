package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// TestCanonicalRemoteCoversEgressAllowlist: the per-backend egress allowlist is
// signed for a remote entry too (ADR-0058 §7, reusing ADR-0048 Decisão 6), so a
// database write that widens or clears it breaks the signature; the order the
// CIDRs are stored in does not; and an empty allowlist -- every remote entry
// signed before this field -- produces the same bytes as before, so existing
// signatures still verify.
func TestCanonicalRemoteCoversEgressAllowlist(t *testing.T) {
	base := Canonical(remoteEntry())

	// An empty allowlist is byte-for-byte the pre-field form (back-compat).
	empty := remoteEntry()
	empty.EgressAllowCIDRs = []string{}
	if !bytes.Equal(Canonical(empty), base) {
		t.Error("an empty allowlist changed the remote canonical bytes; existing remote signatures would break")
	}

	// Adding an allowlist changes the bytes.
	with := remoteEntry()
	with.EgressAllowCIDRs = []string{"10.0.0.0/8"}
	if bytes.Equal(Canonical(with), base) {
		t.Error("adding an egress allowlist did not change the remote canonical bytes; the field is not covered")
	}

	// Order does not matter: the set is sorted before hashing.
	a := remoteEntry()
	a.EgressAllowCIDRs = []string{"10.0.0.0/8", "192.168.0.0/24"}
	b := remoteEntry()
	b.EgressAllowCIDRs = []string{"192.168.0.0/24", "10.0.0.0/8"}
	if !bytes.Equal(Canonical(a), Canonical(b)) {
		t.Error("the allowlist order changed the signed bytes; it must be order-independent")
	}

	// A different set is a different signature.
	c := remoteEntry()
	c.EgressAllowCIDRs = []string{"10.0.0.0/8"}
	if bytes.Equal(Canonical(a), Canonical(c)) {
		t.Error("two different allowlists produced equal canonical bytes")
	}
}

// TestVerifyRemoteAllowlistTamper: a signature over a remote entry no longer
// verifies once the stored allowlist is widened, so a database write that opens
// egress cannot keep an old signature.
func TestVerifyRemoteAllowlistTamper(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	entry := remoteEntry()
	entry.EgressAllowCIDRs = []string{"10.0.0.0/8"}
	sig := s.Sign(entry)
	if err := v.Verify(entry, sig); err != nil {
		t.Fatalf("Verify of the signed remote entry: %v", err)
	}
	widened := entry
	widened.EgressAllowCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	if err := v.Verify(widened, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify after widening the allowlist = %v, want ErrInvalidSignature", err)
	}
}

// TestCanonical_RemoteAndHTTPBytesArePinned pins the v4-remote and v3-http
// encodings with a golden hash, as TestCanonical_StdioEntryKeepsV1Bytes
// pins v1. Changing either constant invalidates every deployed signature
// of that transport: the backends drop out of service at the next
// reconcile until each entry is signed again.
func TestCanonical_RemoteAndHTTPBytesArePinned(t *testing.T) {
	for _, tc := range []struct {
		tag    string
		entry  registry.UpstreamServer
		golden string
	}{
		{"v4-remote", remoteEntry(), "d214f351e73b6829295779db67599ff05083a0bd4544d94e5f3cacc2916c445c"},
		{"v3-http", httpEntry(), "9403006a75df45ae3294c7db57e1bf127adafdf6c6bc626faa819c6382ef9628"},
	} {
		sum := sha256.Sum256(Canonical(tc.entry))
		if got := hex.EncodeToString(sum[:]); got != tc.golden {
			t.Errorf("%s canonical bytes moved: sha256 %s, want %s", tc.tag, got, tc.golden)
		}
	}
}
