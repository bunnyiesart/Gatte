package resthttp_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
)

// TestRefuseAddr_Policy pins the IP policy of ADR-0048 Decisão 6 as a
// table: what is refused, what is not, with the v4, v6 and v4-mapped
// spellings side by side. No network is involved.
func TestRefuseAddr_Policy(t *testing.T) {
	refused := []string{
		// loopback
		"127.0.0.1", "127.255.255.254", "::1", "::ffff:127.0.0.1",
		// unspecified and "this network"
		"0.0.0.0", "::", "0.0.0.1", "0.255.255.255", "::ffff:0.0.0.0",
		// private
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.77.5", "::ffff:10.0.0.1", "fc00::1", "fd12::1",
		// link-local, metadata
		"169.254.169.254", "169.254.0.1", "fe80::1", "::ffff:169.254.169.254",
		// CGNAT
		"100.64.0.1", "100.127.255.255", "::ffff:100.64.0.1",
		// multicast and broadcast
		"224.0.0.1", "239.255.255.255", "ff02::1", "255.255.255.255",
		// IPv6 addresses that embed a forbidden IPv4: NAT64 well-known,
		// NAT64 local-use (RFC 8215), 6to4
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::7f00:1", "64:ff9b:1::a9fe:a9fe", "64:ff9b:1:ffff::a00:1",
		"2002:7f00:1::1", "2002:a9fe:a9fe::1",
		// a zone
		"fe80::1%lo0",
	}
	for _, s := range refused {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		err = resthttp.RefuseAddr(a)
		if !errors.Is(err, resthttp.ErrEgressRefused) {
			t.Errorf("%s: want ErrEgressRefused, got %v", s, err)
		}
	}

	allowed := []string{
		"203.0.113.10", "8.8.8.8", "1.1.1.1", "198.51.100.1", "::ffff:203.0.113.10",
		"2606:4700:4700::1111", "2001:db8::1",
		// NAT64 (well-known and local-use) and 6to4 of a public IPv4
		"64:ff9b::cb00:710a", "64:ff9b:1::cb00:710a", "2002:cb00:710a::1",
	}
	for _, s := range allowed {
		a := netip.MustParseAddr(s)
		if err := resthttp.RefuseAddr(a); err != nil {
			t.Errorf("%s: want allowed, got %v", s, err)
		}
	}

	if err := resthttp.RefuseAddr(netip.Addr{}); !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Errorf("zero address: want refused, got %v", err)
	}
}

// TestDial_ResolvedForbiddenAddressIsRefused: a name whose resolver answer
// is a forbidden address -- the DNS-rebind case -- is refused with
// ErrEgressRefused by the dial path, before any socket is opened. The
// resolver is the injected test hook; no DNS and no network.
func TestDial_ResolvedForbiddenAddressIsRefused(t *testing.T) {
	for _, answer := range []string{"127.0.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.5"} {
		t.Run(answer, func(t *testing.T) {
			d := resthttp.New(nil)
			resthttp.SetLookupForTest(d, func(_ context.Context, host string) ([]netip.Addr, error) {
				if host != "api.example.test" {
					t.Errorf("resolver asked for %q", host)
				}
				return []netip.Addr{netip.MustParseAddr(answer)}, nil
			})
			up := dialKeyless(t, d, "https://api.example.test/v1")
			_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4"}`))
			if !errors.Is(err, resthttp.ErrEgressRefused) {
				t.Fatalf("want ErrEgressRefused, got %v", err)
			}
			if errors.Is(err, gateway.ErrUpstreamGone) {
				t.Errorf("an egress refusal must never read as the upstream being gone")
			}
		})
	}
}

// TestDial_MixedResolverAnswerIsRefusedWhole: one forbidden address among
// public ones poisons the whole answer. Happy-eyeballs would otherwise pick
// whichever connected first.
func TestDial_MixedResolverAnswerIsRefusedWhole(t *testing.T) {
	d := resthttp.New(nil)
	resthttp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("169.254.169.254")}, nil
	})
	up := dialKeyless(t, d, "https://api.example.test")
	// A live ctx: the refusal happens in dialPinned before any socket is
	// opened, so nothing is dialled even though the public address would
	// have been reachable.
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4"}`))
	if !errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("want ErrEgressRefused, got %v", err)
	}
}

// TestDial_PublicAddressPassesThePolicy: a public answer is accepted by the
// policy, on the dial path and not only in the table above. The ctx is
// live on entry -- http.Transport returns ctx.Err() before it ever dials
// when it is not -- and is cancelled INSIDE the resolver hook, so dialPinned
// has run the lookup, judged the address, and reaches net.Dialer with a
// cancelled ctx, which refuses before a packet leaves. What is proved: the
// resolver was consulted once, the policy said yes (no ErrEgressRefused),
// and the dial was attempted (context.Canceled through the redaction).
func TestDial_PublicAddressPassesThePolicy(t *testing.T) {
	d := resthttp.New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lookups atomic.Int32
	resthttp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		cancel()
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	})
	up := dialKeyless(t, d, "https://api.example.test")
	_, err := up.CallTool(ctx, "check", []byte(`{"path_ip":"1.2.3.4"}`))
	if err == nil {
		t.Fatal("a cancelled dial cannot succeed")
	}
	if lookups.Load() != 1 {
		t.Fatalf("resolver consulted %d times, want 1: the policy was not reached", lookups.Load())
	}
	if errors.Is(err, resthttp.ErrEgressRefused) {
		t.Fatalf("public address was refused: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled through the scrubbed error, got %v", err)
	}
}

// TestDial_ControlIsTheSecondLine proves net.Dialer.Control is wired, not
// just described: one call over a fresh connection consults the policy
// exactly twice -- dialPinned on the resolved address, then Control on the
// socket's address -- and both see the same literal. Dial consults it once
// more, on the base's literal host (httptest's URL is one). Keep-alive is
// off, so a second call opens a new connection and counts again.
func TestDial_ControlIsTheSecondLine(t *testing.T) {
	srv, _ := recorder(t, 200, nil)
	d := resthttp.New(nil)
	var seen []netip.Addr
	var mu sync.Mutex
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(seen) }
	resthttp.SetEgressForTest(d, func(a netip.Addr) error {
		mu.Lock()
		seen = append(seen, a)
		mu.Unlock()
		if a.Unmap().IsLoopback() {
			return nil
		}
		return resthttp.RefuseAddr(a)
	})
	up := dialKeyless(t, d, srv.URL)
	if n := count(); n != 1 {
		t.Fatalf("Dial consulted the policy %d times, want 1 (the literal host)", n)
	}
	for i := 1; i <= 2; i++ {
		if _, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1"}`)); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if n := count(); n != 1+2*i {
			t.Fatalf("after call %d the policy was consulted %d times, want %d (1 at Dial, then dialPinned + Control per connection)", i, n, 1+2*i)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if seen[1] != seen[2] || seen[3] != seen[4] {
		t.Errorf("dialPinned and Control saw different addresses: %v", seen)
	}
}

// TestDial_ResolverFailureIsAnOrdinaryError: a name that does not resolve
// is a failed call, not an egress refusal and not the upstream gone.
func TestDial_ResolverFailureIsAnOrdinaryError(t *testing.T) {
	d := resthttp.New(nil)
	resthttp.SetLookupForTest(d, func(context.Context, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "api.example.test", IsNotFound: true}
	})
	up := dialKeyless(t, d, "https://api.example.test")
	_, err := up.CallTool(context.Background(), "check", []byte(`{"path_ip":"1.2.3.4"}`))
	if err == nil || errors.Is(err, resthttp.ErrEgressRefused) || errors.Is(err, gateway.ErrUpstreamGone) {
		t.Fatalf("want a plain failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "no such host") {
		t.Errorf("the resolver's reason should survive: %v", err)
	}
}

// TestDial_LiteralForbiddenHostIsRefusedWithoutResolving: a URL whose host
// is a literal forbidden address never reaches the resolver -- and since
// the console's seam (ValidateBaseURL) refuses it at register, Dial
// refuses it too, with the same policy, so the two cannot disagree. The
// socket path is kept honest as well: a dialer whose Dial-time check is
// bypassed by the loopback allowance still refuses the literal at
// dialPinned (TestDial_RefusesWhatItMustRefuse covers the dial).
func TestDial_LiteralForbiddenHostIsRefusedWithoutResolving(t *testing.T) {
	d := resthttp.New(nil)
	resthttp.SetLookupForTest(d, func(_ context.Context, host string) ([]netip.Addr, error) {
		t.Errorf("resolver called for literal host %q", host)
		return nil, errors.New("unexpected")
	})
	for _, u := range []string{"http://169.254.169.254/latest", "http://[::1]:8080", "http://10.0.0.1", "http://[::ffff:127.0.0.1]/"} {
		_, err := d.Dial(context.Background(), spec(t, u, resthttp.AuthNone, ""), nil)
		if !errors.Is(err, resthttp.ErrEgressRefused) || !errors.Is(err, resthttp.ErrInvalidURL) {
			t.Errorf("%s: want ErrInvalidURL wrapping ErrEgressRefused at dial, got %v", u, err)
		}
	}
	// A loopback literal through the test allowance dials, and the policy
	// then judges the socket: 169.254.169.254 is still refused there.
	allowed := newDialer(t, nil)
	resthttp.SetLookupForTest(allowed, func(_ context.Context, host string) ([]netip.Addr, error) {
		t.Errorf("resolver called for literal host %q", host)
		return nil, errors.New("unexpected")
	})
	if _, err := allowed.Dial(context.Background(), spec(t, "http://127.0.0.1:1/", resthttp.AuthNone, ""), nil); err != nil {
		t.Errorf("loopback literal under the test allowance: %v", err)
	}
}
