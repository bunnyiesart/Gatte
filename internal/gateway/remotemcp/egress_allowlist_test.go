package remotemcp_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/egress"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/remotemcp"
)

// The remote adapter reads the same per-backend private-CIDR allowlist the
// REST adapter does (ADR-0058 §7, reusing ADR-0048 Decisão 6): a native MCP
// backend on a private address is refused by default and reachable only when
// explicitly allowlisted. These mirror internal/gateway/resthttp's
// egress_allowlist_test.go.

// specAllow is spec() with a per-backend egress allowlist.
func specAllow(url string, cidrs ...string) gateway.UpstreamSpec {
	s := spec(url, "", "")
	s.EgressAllowCIDRs = cidrs
	return s
}

// TestDial_AllowlistLetsAListedPrivateAddressThrough: an entry whose allowlist
// covers the resolved private address passes the egress policy, where without
// it the same address is refused (TestDial_EgressRefusals pins 10.0.0.5). The
// resolver cancels the ctx so the policy is reached and the dial attempted, but
// no packet leaves.
func TestDial_AllowlistLetsAListedPrivateAddressThrough(t *testing.T) {
	d := remotemcp.New()
	c, cancel := context.WithCancel(context.Background())
	defer cancel()
	remotemcp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	})
	_, err := d.Dial(c, specAllow("https://siem.internal.test/mcp", "10.0.0.0/8"), nil)
	if errors.Is(err, egress.ErrRefused) {
		t.Fatalf("a private address inside the allowlist was refused: %v", err)
	}
}

// TestDial_AllowlistDoesNotCoverOtherPrivateRanges: the allowlist opens only
// the ranges it names. A private address in another block is still refused.
func TestDial_AllowlistDoesNotCoverOtherPrivateRanges(t *testing.T) {
	d := remotemcp.New()
	remotemcp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.0.9")}, nil
	})
	_, err := d.Dial(ctx(t), specAllow("https://x.internal.test/mcp", "10.0.0.0/8"), nil)
	if !errors.Is(err, egress.ErrRefused) {
		t.Fatalf("a private address outside the allowlist must be refused, got %v", err)
	}
}

// TestDial_AllowlistAcceptsAPrivateLiteralHostAtDial: a private literal host is
// refused at Dial without the allowlist and accepted with it, the same seam
// ValidateURL exposes at register.
func TestDial_AllowlistAcceptsAPrivateLiteralHostAtDial(t *testing.T) {
	if _, err := remotemcp.New().Dial(ctx(t), spec("http://10.0.0.5/mcp", "", ""), nil); !errors.Is(err, egress.ErrRefused) {
		t.Fatalf("private literal without allowlist: want egress.ErrRefused, got %v", err)
	}
	// A pre-cancelled ctx stops the dial before a packet leaves: the literal
	// passed the endpoint check, so the failure is not an egress refusal.
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := remotemcp.New().Dial(c, specAllow("http://10.0.0.5/mcp", "10.0.0.0/8"), nil); errors.Is(err, egress.ErrRefused) {
		t.Fatalf("private literal inside allowlist refused at Dial: %v", err)
	}
}

// TestDial_RefusesANonPrivateAllowlist: the adapter re-validates the stored
// allowlist, so a public (or otherwise non-private) CIDR -- which register and
// registry.Validate would already refuse -- is refused at Dial rather than
// silently widening egress.
func TestDial_RefusesANonPrivateAllowlist(t *testing.T) {
	if _, err := remotemcp.New().Dial(ctx(t), specAllow("https://h/mcp", "8.8.8.0/24"), nil); !errors.Is(err, egress.ErrRefused) {
		t.Fatalf("want egress.ErrRefused for a public allowlist CIDR, got %v", err)
	}
}

// TestValidateURL_Allowlist: the register seam accepts a private -url the
// allowlist covers, refuses it with none, refuses a bad allowlist, and accepts
// a public host name -- mirroring resthttp.ValidateBaseURL.
func TestValidateURL_Allowlist(t *testing.T) {
	if err := remotemcp.ValidateURL("https://10.0.0.5/mcp", []string{"10.0.0.0/8"}); err != nil {
		t.Errorf("a private literal inside the allowlist: want accepted, got %v", err)
	}
	if err := remotemcp.ValidateURL("https://10.0.0.5/mcp", nil); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("a private literal with no allowlist: want egress.ErrRefused, got %v", err)
	}
	if err := remotemcp.ValidateURL("https://10.0.0.5/mcp", []string{"127.0.0.0/8"}); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("a loopback allowlist entry must be refused, got %v", err)
	}
	if err := remotemcp.ValidateURL("https://mcp.vendor.example/mcp", nil); err != nil {
		t.Errorf("a public host name: want accepted, got %v", err)
	}
}
