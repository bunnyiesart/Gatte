package egress_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/egress"
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
		// IPv4-compatible and IPv4-translated (SIIT) forms
		"::7f00:1", "::a9fe:a9fe", "::a00:1", "::ffff:0:7f00:1", "::ffff:0:a9fe:a9fe",
		// Teredo and the discard prefix
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", "100::1",
		// reserved and benchmarking IPv4
		"240.0.0.1", "254.1.2.3", "198.18.0.1", "198.19.255.255",
		// a zone
		"fe80::1%lo0",
	}
	for _, s := range refused {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		err = egress.RefuseAddr(a)
		if !errors.Is(err, egress.ErrRefused) {
			t.Errorf("%s: want ErrRefused, got %v", s, err)
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
		if err := egress.RefuseAddr(a); err != nil {
			t.Errorf("%s: want allowed, got %v", s, err)
		}
	}

	if err := egress.RefuseAddr(netip.Addr{}); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("zero address: want refused, got %v", err)
	}
}

// TestPinRedirects: a redirect off the signed origin is refused with
// ErrRefused; the default port is made explicit before comparing; a
// same-origin chain stops at the request limit with the last response.
func TestPinRedirects(t *testing.T) {
	check := egress.PinRedirects("https://api.example.test:443", 3)
	req := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	for _, off := range []string{"http://api.example.test/x", "https://other.test/x", "https://api.example.test:8443/x"} {
		if err := check(req(off), nil); !errors.Is(err, egress.ErrRefused) {
			t.Errorf("%s: want ErrRefused, got %v", off, err)
		}
	}
	if err := check(req("https://API.example.test/v2"), make([]*http.Request, 1)); err != nil {
		t.Errorf("same origin, default port implicit: %v", err)
	}
	if err := check(req("https://api.example.test/v2"), make([]*http.Request, 3)); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("past the limit: want ErrUseLastResponse, got %v", err)
	}
}

// TestLiteralHostRefusal: an IP literal is judged without a resolver; a
// name is left for the dial.
func TestLiteralHostRefusal(t *testing.T) {
	var g egress.Guard
	if err := g.LiteralHostRefusal("169.254.169.254"); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("metadata literal: want ErrRefused, got %v", err)
	}
	if err := g.LiteralHostRefusal("api.example.test"); err != nil {
		t.Errorf("a name is not judged here: %v", err)
	}
}

// TestGuardTransport_ProxyEnvironmentIsIgnored: an HTTP(S)_PROXY in the
// environment would carry every request past the IP policy, which would
// then only see the proxy. The target is a name, not a loopback literal,
// because net/http never proxies loopback anyway.
func TestGuardTransport_ProxyEnvironmentIsIgnored(t *testing.T) {
	var proxied atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Store(true)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()

	tr := loopbackGuard(nil).Transport()
	if tr.Proxy != nil || !tr.DisableKeepAlives {
		t.Fatalf("transport: Proxy set = %v, DisableKeepAlives = %v; want no proxy and no keep-alive", tr.Proxy != nil, tr.DisableKeepAlives)
	}
	resp, err := (&http.Client{Transport: tr}).Get("http://backend.example.test:" + portOf(target.URL) + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || proxied.Load() {
		t.Errorf("status %d, proxied %v: want the target reached directly", resp.StatusCode, proxied.Load())
	}
}

// TestGuardTransport_ControlIsTheSecondLine: one connection consults the
// policy twice, on the resolved address and on the socket's, and a refusal
// at the socket alone still refuses.
func TestGuardTransport_ControlIsTheSecondLine(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	endpoint := "http://backend.example.test:" + portOf(target.URL) + "/"

	var checks atomic.Int64
	resp, err := (&http.Client{Transport: loopbackGuard(func() error {
		checks.Add(1)
		return nil
	}).Transport()}).Get(endpoint)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if n := checks.Load(); n != 2 {
		t.Errorf("policy consulted %d times for one connection, want 2", n)
	}

	var seen atomic.Int64
	_, err = (&http.Client{Transport: loopbackGuard(func() error {
		if seen.Add(1) == 2 {
			return egress.ErrRefused
		}
		return nil
	}).Transport()}).Get(endpoint)
	if !errors.Is(err, egress.ErrRefused) {
		t.Errorf("a refusal at the socket alone: want ErrRefused, got %v", err)
	}
}

// loopbackGuard resolves every name to 127.0.0.1 and allows loopback,
// calling hook (when set) on every check.
func loopbackGuard(hook func() error) egress.Guard {
	return egress.Guard{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Policy: func(a netip.Addr) error {
			if hook != nil {
				if err := hook(); err != nil {
					return err
				}
			}
			if a.Unmap().IsLoopback() {
				return nil
			}
			return egress.RefuseAddr(a)
		},
	}
}

func portOf(rawURL string) string { return rawURL[strings.LastIndex(rawURL, ":")+1:] }
