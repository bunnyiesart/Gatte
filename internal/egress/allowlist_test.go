package egress_test

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/egress"
)

// TestPrivatePrefix_AcceptsOnlyPrivateSpace: a per-backend allowlist may name
// only CIDRs that lie wholly within private address space. Loopback,
// link-local (the metadata endpoint), the unspecified address, multicast and
// public space are refused, so an allowlist can never re-open what RefuseAddr
// exists to close (ADR-0048 Decisão 6).
func TestPrivatePrefix_AcceptsOnlyPrivateSpace(t *testing.T) {
	ok := []string{
		"10.0.0.0/8", "10.1.2.0/24", "172.16.0.0/12", "192.168.0.0/24",
		"100.64.0.0/10", "fc00::/7", "fd12:3456::/48",
	}
	for _, s := range ok {
		if err := egress.PrivatePrefix(netip.MustParsePrefix(s)); err != nil {
			t.Errorf("%s: want accepted, got %v", s, err)
		}
	}
	bad := []string{
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local, the metadata range
		"0.0.0.0/8",      // this network
		"8.8.8.0/24",     // public
		"192.168.0.0/8",  // too wide: spills past 192.168/16 into public space
		"172.16.0.0/11",  // too wide: spills past 172.16/12
		"224.0.0.0/4",    // multicast
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"2001:db8::/32",  // public IPv6
		"0.0.0.0/0",      // everything
	}
	for _, s := range bad {
		if err := egress.PrivatePrefix(netip.MustParsePrefix(s)); !errors.Is(err, egress.ErrRefused) {
			t.Errorf("%s: want ErrRefused, got %v", s, err)
		}
	}
}

// TestParseAllowPrefixes_NormalisesAndRejects: the allowlist is parsed into a
// masked, de-duplicated, sorted form -- so the same list always signs to the
// same bytes -- and a bad CIDR fails the whole list.
func TestParseAllowPrefixes_NormalisesAndRejects(t *testing.T) {
	got, err := egress.ParseAllowPrefixes([]string{"192.168.0.0/24", "10.0.0.7/8", " 10.0.0.9/8 ", "192.168.0.0/24"})
	if err != nil {
		t.Fatalf("ParseAllowPrefixes: %v", err)
	}
	var strs []string
	for _, p := range got {
		strs = append(strs, p.String())
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/24"}
	if !reflect.DeepEqual(strs, want) {
		t.Errorf("normalised to %v, want %v (masked, de-duplicated, sorted)", strs, want)
	}
	if _, err := egress.ParseAllowPrefixes([]string{"10.0.0.0/8", "8.8.8.0/24"}); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("a public CIDR in the list must fail the whole list; got %v", err)
	}
	if got, err := egress.ParseAllowPrefixes(nil); err != nil || len(got) != 0 {
		t.Errorf("empty list = (%v, %v), want (empty, nil)", got, err)
	}
}

// TestAllowPrefixes_AllowsOnlyTheListedRanges: the policy admits an address
// inside a listed prefix (an IPv4-mapped form unmapped first) and defers every
// other address to the base policy -- so a private address outside the list,
// and loopback, stay refused.
func TestAllowPrefixes_AllowsOnlyTheListedRanges(t *testing.T) {
	prefixes, err := egress.ParseAllowPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	p := egress.AllowPrefixes(egress.RefuseAddr, prefixes)

	allowed := []string{"10.0.0.5", "10.255.255.1", "::ffff:10.1.2.3"}
	for _, s := range allowed {
		if err := p(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: want allowed by the list, got %v", s, err)
		}
	}
	// Addresses RefuseAddr refuses stay refused when outside the list; a public
	// address (8.8.8.8) is not in this set because RefuseAddr allows it anyway.
	refused := []string{"192.168.0.1", "127.0.0.1", "169.254.169.254"}
	for _, s := range refused {
		if err := p(netip.MustParseAddr(s)); !errors.Is(err, egress.ErrRefused) {
			t.Errorf("%s: want refused (outside the list), got %v", s, err)
		}
	}
	// A public address is allowed by the base policy, allowlist or not.
	if err := p(netip.MustParseAddr("8.8.8.8")); err != nil {
		t.Errorf("8.8.8.8: a public address is allowed by RefuseAddr, got %v", err)
	}

	// With no prefixes the policy is the base unchanged.
	base := egress.AllowPrefixes(egress.RefuseAddr, nil)
	if err := base(netip.MustParseAddr("10.0.0.5")); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("an empty allowlist must leave RefuseAddr's refusal of 10.0.0.5 in place, got %v", err)
	}
}
