// Package egress is the SSRF/egress guard every adapter that makes the
// gateway itself an HTTP client dials through (ADR-0048 Decisão 6, ADR-0058
// §7): the REST adapter (internal/gateway/resthttp) and the remote MCP
// adapter (internal/gateway/remotemcp). It was lifted out of resthttp so the
// two share one policy instead of two copies that could drift.
//
// It holds three things: the IP policy (RefuseAddr), applied to every
// address a name resolves to and again at the socket; a transport that
// dials only through that policy (Guard.Transport); and the redirect pin
// that keeps a client on the signed origin (PinRedirects). The host
// allowlist is structural -- a client built here is pinned to one origin --
// because by the time an address exists the name is already gone.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrRefused means a connection would not be opened, or a redirect not
// followed: the destination resolved to an address this gateway must not
// reach from inside its own network (loopback, private, link-local, the
// metadata range, ...), or a redirect pointed at an origin other than the
// one the entry signed. The text of an error wrapping it names the address
// or origin that was refused and never a credential -- none is in scope
// where these are produced.
var ErrRefused = errors.New("egress refused")

// Lookup resolves a host name to its addresses.
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

// Policy reports why an address may not be dialled, or nil when it may.
type Policy func(netip.Addr) error

// SystemLookup is the system resolver, asking for both families: the policy
// must see EVERY address a name resolves to, not whichever one
// happy-eyeballs would try first.
func SystemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Address ranges the net/netip predicates do not name on their own.
var (
	// cgnat is RFC 6598 shared address space: carrier NAT, which from
	// inside a provider's network reaches other customers and the
	// provider's own gear, like 10/8 does.
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	// thisNetwork is RFC 1122 §3.2.1.3 "this host, this network": Linux
	// routes a connect to 0.x.y.z to the local host, so a rebind to 0.0.0.1
	// would reach loopback past a check that only knew 0.0.0.0.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	// nat64 is the RFC 6052 well-known prefix: the last four bytes are an
	// IPv4 address a translator connects to on the client's behalf, so
	// 64:ff9b::7f00:1 is loopback wearing an IPv6 address.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
	// nat64Local is RFC 8215's local-use prefix for a site's own NAT64
	// translator, judged by the same rule as the well-known prefix. In the
	// common /96-embedded form the IPv4 is in the last four bytes, so
	// 64:ff9b:1::7f00:1 routes to loopback and embeddedIPv4 reads it. RFC
	// 6052 also permits shorter embeddings within this /48 (the IPv4 in bits
	// 48-63 + 72-87); embeddedIPv4 does not decode those, so for a non-/96
	// address it judges whatever the last four bytes hold, not the true
	// embedded IPv4. This gateway runs no NAT64, so the /96 form is the only
	// one seen in practice.
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	// sixToFour is RFC 3056: bytes 2-5 are an IPv4 address the packet is
	// tunnelled to, with the same consequence as nat64.
	sixToFour = netip.MustParsePrefix("2002::/16")
	// ipv4Compatible is the deprecated RFC 4291 §2.5.5.1 ::a.b.c.d form and
	// ipv4Translated the RFC 2765 (SIIT) ::ffff:0:a.b.c.d form. Both carry
	// the IPv4 in the last four bytes, and a host with a translator or a
	// legacy ::/96 auto-tunnel reaches it, so they are judged by it.
	ipv4Compatible = netip.MustParsePrefix("::/96")
	ipv4Translated = netip.MustParsePrefix("::ffff:0:0:0/96")
	// teredo (RFC 4380) carries an obfuscated IPv4 the tunnel delivers to,
	// and discard (RFC 6666) is a black hole: neither is a backend address.
	teredo  = netip.MustParsePrefix("2001::/32")
	discard = netip.MustParsePrefix("100::/64")
	// reserved4 is 240.0.0.0/4 (RFC 1112, "future use") and benchmarking
	// 198.18.0.0/15 (RFC 2544): neither is a public service, and both are
	// global unicast to net/netip.
	reserved4    = netip.MustParsePrefix("240.0.0.0/4")
	benchmarking = netip.MustParsePrefix("198.18.0.0/15")
	broadcast    = netip.MustParseAddr("255.255.255.255")
)

// RefuseAddr is the IP policy (ADR-0048 Decisão 6, second bullet): it
// reports why a resolved address may not be dialled, or nil when it may. It
// is applied to the address the socket is about to connect to -- after
// resolution, so a name that rebinds between the check and the dial cannot
// slip past it.
//
// Refused, in this order: a zoned or invalid address; the unspecified
// address (0.0.0.0 and ::, which the kernel turns into loopback) and the
// rest of 0.0.0.0/8; loopback; RFC 1918 and fc00::/7 private space;
// link-local (169.254.0.0/16, which holds the cloud metadata endpoint, and
// fe80::/10); multicast and the limited broadcast; CGNAT 100.64.0.0/10; and
// an IPv6 address that embeds one of the above (IPv4-mapped ::ffff:a.b.c.d
// is unmapped before every test; IPv4-compatible ::a.b.c.d, IPv4-translated
// ::ffff:0:a.b.c.d, NAT64 -- the well-known and the RFC 8215 local-use
// prefix -- and 6to4 are unwrapped and judged by their IPv4); Teredo
// 2001::/32 and the discard prefix 100::/64; and the reserved 240.0.0.0/4
// and benchmarking 198.18.0.0/15 ranges. Anything left that is not global unicast is refused as well: a class is a
// permission, and an address this function cannot name is not evidence that
// it is safe to reach.
//
// Post-condition: nil only for a global-unicast address outside every range
// above.
func RefuseAddr(a netip.Addr) error {
	if !a.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrRefused)
	}
	if a.Zone() != "" {
		return fmt.Errorf("%w: %s has an interface zone, which only a link-local address carries", ErrRefused, a)
	}
	a = a.Unmap()
	if a.Is6() {
		if teredo.Contains(a) || discard.Contains(a) {
			return fmt.Errorf("%w: %s is a Teredo or discard address, not a backend", ErrRefused, a)
		}
		// :: and ::1 sit in ::/96 too; the switch below names them better.
		compatible := ipv4Compatible.Contains(a) && !a.IsUnspecified() && !a.IsLoopback()
		if compatible || ipv4Translated.Contains(a) ||
			nat64.Contains(a) || nat64Local.Contains(a) || sixToFour.Contains(a) {
			if err := RefuseAddr(embeddedIPv4(a)); err != nil {
				return fmt.Errorf("%w: %s embeds an IPv4 address that is refused: %v", ErrRefused, a, detail(err))
			}
			return nil
		}
	}
	switch {
	case a.IsUnspecified():
		return fmt.Errorf("%w: %s is the unspecified address, which the kernel connects to loopback", ErrRefused, a)
	case a.Is4() && thisNetwork.Contains(a):
		return fmt.Errorf("%w: %s is in 0.0.0.0/8 (\"this network\"), which routes to the local host", ErrRefused, a)
	case a.IsLoopback():
		return fmt.Errorf("%w: %s is a loopback address", ErrRefused, a)
	case a.IsPrivate():
		return fmt.Errorf("%w: %s is a private address", ErrRefused, a)
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("%w: %s is link-local (the range that holds the cloud metadata endpoint)", ErrRefused, a)
	case a.IsMulticast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s is a multicast address", ErrRefused, a)
	case a.Is4() && a == broadcast:
		return fmt.Errorf("%w: %s is the broadcast address", ErrRefused, a)
	case a.Is4() && cgnat.Contains(a):
		return fmt.Errorf("%w: %s is carrier-grade NAT space (100.64.0.0/10)", ErrRefused, a)
	case a.Is4() && (reserved4.Contains(a) || benchmarking.Contains(a)):
		return fmt.Errorf("%w: %s is reserved or benchmarking space", ErrRefused, a)
	case !a.IsGlobalUnicast():
		return fmt.Errorf("%w: %s is not a global unicast address", ErrRefused, a)
	}
	return nil
}

// embeddedIPv4 extracts the IPv4 address an IPv4-compatible,
// IPv4-translated or NAT64 address (last four bytes) or a 6to4 address
// (bytes 2-5) carries. Pre-condition: a is in one of those prefixes.
func embeddedIPv4(a netip.Addr) netip.Addr {
	b := a.As16()
	if sixToFour.Contains(a) {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	}
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

// detail strips the sentinel prefix so a nested refusal is not prefixed
// twice.
func detail(err error) string {
	return strings.TrimPrefix(err.Error(), ErrRefused.Error()+": ")
}

// Timeouts of the transport itself, below any per-call ceiling the caller
// puts on ctx: one TCP connect or one TLS handshake that takes longer than
// this is a dead host, not a slow API.
const (
	connectTimeout   = 15 * time.Second
	handshakeTimeout = 15 * time.Second
)

// Guard is a resolver and an IP policy. The zero value uses SystemLookup
// and RefuseAddr; the fields exist so tests can point a name at a forbidden
// address, or let httptest's loopback listener through, without a network.
// The backend adapters leave them nil; the accounts backend's Wazuh check
// sets a Policy that also allows private ranges, for an indexer named by
// root's config.toml (design/adr/0063).
type Guard struct {
	Lookup Lookup
	Policy Policy
}

func (g Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.Lookup != nil {
		return g.Lookup(ctx, host)
	}
	return SystemLookup(ctx, host)
}

// Check applies the guard's policy to a.
func (g Guard) Check(a netip.Addr) error {
	if g.Policy != nil {
		return g.Policy(a)
	}
	return RefuseAddr(a)
}

// Transport builds an http.Transport that dials only through the guard.
//
// Four things are deliberate about it, each closing a path a default
// transport leaves open:
//
//   - Proxy is nil, not http.ProxyFromEnvironment. An HTTPS_PROXY variable
//     in the gateway's environment would route every request -- with the
//     injected credential -- through whatever it names, past the IP policy,
//     which would then only ever see the proxy's address.
//   - DialContext resolves the name HERE, judges every address, and opens
//     the socket to the literal address that passed. net.Dialer.Control
//     judges the address a second time at the socket, so a future change
//     that let a name reach the dialer would still be caught.
//   - No HTTP/2. ForceAttemptHTTP2 is false and a custom DialContext
//     disables the automatic upgrade.
//   - No keep-alive. A kept-alive connection's bufio.Writer holds the bytes
//     of the last request it sent -- the credential header among them --
//     for as long as the connection sits idle, reachable from the adapter's
//     client. With DisableKeepAlives each exchange closes its connection
//     when the body is read. The price is one TCP (and TLS) handshake per
//     request, which this team's traffic easily affords.
func (g Guard) Transport() *http.Transport {
	dialer := &net.Dialer{
		Timeout: connectTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			return g.controlCheck(network, address)
		},
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return g.dialPinned(ctx, dialer, network, addr)
		},
		TLSHandshakeTimeout: handshakeTimeout,
		DisableKeepAlives:   true,
	}
}

// dialPinned resolves addr's host, refuses the dial if ANY resolved address
// fails the policy, and otherwise connects to the addresses in turn -- as
// literal IPs, so what was checked is what is dialled.
//
// "Any" rather than "the one we pick" is the fail-closed reading of a
// resolver answer an attacker may control: a name answering {public,
// 169.254.169.254} would otherwise be reached on whichever the dialer
// happened to try first.
func (g Guard) dialPinned(ctx context.Context, dialer *net.Dialer, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: network %q is not TCP", ErrRefused, network)
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: address %q: %v", ErrRefused, addr, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: address %q has no numeric port", ErrRefused, addr)
	}

	var addrs []netip.Addr
	if literal, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{literal}
	} else {
		addrs, err = g.lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", host)
		}
	}
	for _, a := range addrs {
		if err := g.Check(a); err != nil {
			return nil, fmt.Errorf("host %q: %w", host, err)
		}
	}

	var last error
	for _, a := range addrs {
		target := netip.AddrPortFrom(a.Unmap(), uint16(port)).String()
		conn, err := dialer.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// controlCheck is the net.Dialer.Control hook: the address here is the
// literal IP:port the socket is about to connect to, judged once more by
// the same policy. It cannot see the host name, which is why it is the
// second check and not the only one.
func (g Guard) controlCheck(network, address string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("%w: network %q is not TCP", ErrRefused, network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: socket address %q: %v", ErrRefused, address, err)
	}
	return g.Check(ap.Addr())
}

// LiteralHostRefusal applies the guard's policy to hostname when it is
// already an IP literal, and returns nil for a host name (judged at dial,
// when it has addresses). It needs no resolver, so a console can refuse
// http://169.254.169.254/ at the prompt instead of in the trail of the
// first failed call.
func (g Guard) LiteralHostRefusal(hostname string) error {
	a, err := netip.ParseAddr(hostname)
	if err != nil {
		return nil
	}
	return g.Check(a)
}

// Origin renders u's origin with the default port explicit, so "https://h"
// and "https://h:443" compare equal and "https://h" and "http://h:443" do
// not.
func Origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// JoinHostPort brackets an IPv6 literal, as net.JoinHostPort does.
func JoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// PinRedirects returns an http.Client.CheckRedirect that is the structural
// host pin: a redirect whose scheme, host or port differs from origin is
// refused with ErrRefused -- not followed, and not reported at all beyond
// the fact, since a Location a server controls can carry anything, its host
// included. net/http still puts the raw Location in the *url.Error it wraps
// this in; each adapter replaces that URL before the error leaves it. A
// same-origin
// redirect is followed while fewer than maxRequests requests have been
// sent; past that the last 3xx is returned as the response
// (http.ErrUseLastResponse).
func PinRedirects(origin string, maxRequests int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if Origin(req.URL) != origin {
			return fmt.Errorf("%w: a redirect off %s was refused; this upstream is pinned to it", ErrRefused, origin)
		}
		if len(via) >= maxRequests {
			return http.ErrUseLastResponse
		}
		return nil
	}
}
