package resthttp_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
)

// specAllow is spec() with a per-backend egress allowlist (ADR-0048 Decisão 6).
func specAllow(t *testing.T, url string, cidrs ...string) gateway.UpstreamSpec {
	t.Helper()
	s := spec(t, url, resthttp.AuthNone, "")
	s.EgressAllowCIDRs = cidrs
	return s
}

// TestDial_AllowlistLetsAListedPrivateAddressThrough: an entry whose allowlist
// covers the resolved private address passes the egress policy, where without
// the allowlist the same address is refused (TestDial_ResolvedForbiddenAddress
// IsRefused pins 10.0.0.5). The resolver cancels the ctx so the policy is
// reached and the dial attempted, but no packet leaves. The Dialer is the
// plain one (RefuseAddr), not the loopback-allowing test Dialer.
func TestDial_AllowlistLetsAListedPrivateAddressThrough(t *testing.T) {
	d := resthttp.New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resthttp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	})
	up, err := d.Dial(context.Background(), specAllow(t, "https://siem.internal.test/v1", "10.0.0.0/8"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	_, err = up.CallTool(ctx, "check", []byte(`{"path_ip":"1.2.3.4"}`))
	if errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("a private address inside the allowlist was refused: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled (policy passed, dial attempted), got %v", err)
	}
}

// TestDial_AllowlistDoesNotCoverOtherPrivateRanges: the allowlist opens only
// the ranges it names. A private address in another block is still refused.
func TestDial_AllowlistDoesNotCoverOtherPrivateRanges(t *testing.T) {
	d := resthttp.New(nil)
	resthttp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.0.9")}, nil
	})
	up, err := d.Dial(context.Background(), specAllow(t, "https://x.internal.test/v1", "10.0.0.0/8"), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	_, err = up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4"}`))
	if !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("a private address outside the allowlist must be refused, got %v", err)
	}
}

// TestDial_AllowlistAcceptsAPrivateLiteralHostAtDial: a private literal host is
// refused at Dial without the allowlist and accepted with it, the same seam
// ValidateBaseURL exposes at register (ADR-0047 §2).
func TestDial_AllowlistAcceptsAPrivateLiteralHostAtDial(t *testing.T) {
	d := resthttp.New(nil)
	if _, err := d.Dial(context.Background(), spec(t, "http://10.0.0.5/v1", resthttp.AuthNone, ""), nil); !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("private literal without allowlist: want ErrEgressRefused, got %v", err)
	}
	up, err := d.Dial(context.Background(), specAllow(t, "http://10.0.0.5/v1", "10.0.0.0/8"), nil)
	if err != nil {
		t.Fatalf("private literal inside allowlist refused at Dial: %v", err)
	}
	_ = up.Close()
}

// TestDial_RefusesANonPrivateAllowlist: the adapter re-validates the stored
// allowlist, so a public (or otherwise non-private) CIDR -- which register and
// registry.Validate would already refuse -- is refused at Dial rather than
// silently widening egress.
func TestDial_RefusesANonPrivateAllowlist(t *testing.T) {
	d := resthttp.New(nil)
	if _, err := d.Dial(context.Background(), specAllow(t, "https://h/v1", "8.8.8.0/24"), nil); !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("want ErrEgressRefused for a public allowlist CIDR, got %v", err)
	}
}

// TestValidateBaseURL_AllowlistAcceptsAPrivateLiteral: the register seam
// accepts a private -url the allowlist covers and refuses a bad allowlist.
func TestValidateBaseURL_AllowlistAcceptsAPrivateLiteral(t *testing.T) {
	if err := resthttp.ValidateBaseURL("https://10.0.0.5/v1", []string{"10.0.0.0/8"}); err != nil {
		t.Errorf("a private literal inside the allowlist: want accepted, got %v", err)
	}
	if err := resthttp.ValidateBaseURL("https://10.0.0.5/v1", nil); !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Errorf("a private literal with no allowlist: want ErrEgressRefused, got %v", err)
	}
	if err := resthttp.ValidateBaseURL("https://10.0.0.5/v1", []string{"127.0.0.0/8"}); !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Errorf("a loopback allowlist entry must be refused, got %v", err)
	}
}
