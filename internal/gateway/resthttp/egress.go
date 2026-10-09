package resthttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// ErrEgressRefused means the adapter would not open, or follow, a
// connection: the destination resolved to an address this gateway must not
// reach from inside its own network (loopback, private, link-local, the
// metadata range, ...), or a redirect pointed at a host other than the one
// the entry signed (ADR-0048 Decisão 6). The text of an error wrapping it
// names the address or host that was refused and never the credential --
// the credential is not even in scope where these are produced.
var ErrEgressRefused = errors.New("resthttp: egress refused")

// lookupFunc resolves a host name to its addresses. It is a field rather
// than a call to net.DefaultResolver so that the tests can hand the dialer
// a name that "resolves" to 169.254.169.254 without a DNS server; outside
// _test.go nothing sets it.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// defaultLookup is the system resolver, asking for both families: the
// policy must see EVERY address a name resolves to, not whichever one
// happy-eyeballs would try first.
func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
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
	// nat64Local is RFC 8215's local-use counterpart of the well-known
	// prefix, reserved for a site's own IPv4/IPv6 translator; it embeds the
	// IPv4 address in the same last four bytes, so a host with a local
	// NAT64 routes 64:ff9b:1::7f00:1 to loopback exactly as the well-known
	// one would. Judged by the same rule for the same reason.
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	// sixToFour is RFC 3056: bytes 2-5 are an IPv4 address the packet is
	// tunnelled to, with the same consequence as nat64.
	sixToFour = netip.MustParsePrefix("2002::/16")
	broadcast = netip.MustParseAddr("255.255.255.255")
)

// refuseAddr is the IP-security half of the egress guard (ADR-0048
// Decisão 6, second bullet): it reports why a resolved address may not be
// dialled, or nil when it may. It is applied to the address the socket is
// about to connect to -- after resolution, so a name that rebinds between
// the check and the dial cannot slip past it -- and only to that: the host
// allowlist is structural (host-pinned client, checkRedirect), because by
// the time an address exists the name is already gone.
//
// Refused, in this order: a zoned or invalid address; the unspecified
// address (0.0.0.0 and ::, which the kernel turns into loopback) and the
// rest of 0.0.0.0/8; loopback; RFC 1918 and fc00::/7 private space;
// link-local (169.254.0.0/16, which holds the cloud metadata endpoint, and
// fe80::/10); multicast and the limited broadcast; CGNAT 100.64.0.0/10; and
// an IPv6 address that embeds one of the above (IPv4-mapped ::ffff:a.b.c.d
// is unmapped before every test; NAT64 -- the well-known and the RFC 8215
// local-use prefix -- and 6to4 are unwrapped and judged by their IPv4).
// Anything left that is not global unicast is refused as well:
// a class is a permission, and an address this function cannot name is not
// evidence that it is safe to reach.
//
// Pre-condition: none. Post-condition: nil only for a global-unicast
// address outside every range above.
func refuseAddr(a netip.Addr) error {
	if !a.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrEgressRefused)
	}
	if a.Zone() != "" {
		return fmt.Errorf("%w: %s has an interface zone, which only a link-local address carries", ErrEgressRefused, a)
	}
	a = a.Unmap()
	if a.Is6() {
		if nat64.Contains(a) || nat64Local.Contains(a) || sixToFour.Contains(a) {
			if err := refuseAddr(embeddedIPv4(a)); err != nil {
				return fmt.Errorf("%w: %s embeds an IPv4 address that is refused: %v", ErrEgressRefused, a, detailEgress(err))
			}
			return nil
		}
	}
	switch {
	case a.IsUnspecified():
		return fmt.Errorf("%w: %s is the unspecified address, which the kernel connects to loopback", ErrEgressRefused, a)
	case a.Is4() && thisNetwork.Contains(a):
		return fmt.Errorf("%w: %s is in 0.0.0.0/8 (\"this network\"), which routes to the local host", ErrEgressRefused, a)
	case a.IsLoopback():
		return fmt.Errorf("%w: %s is a loopback address", ErrEgressRefused, a)
	case a.IsPrivate():
		return fmt.Errorf("%w: %s is a private address", ErrEgressRefused, a)
	case a.IsLinkLocalUnicast():
		return fmt.Errorf("%w: %s is link-local (the range that holds the cloud metadata endpoint)", ErrEgressRefused, a)
	case a.IsMulticast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: %s is a multicast address", ErrEgressRefused, a)
	case a.Is4() && a == broadcast:
		return fmt.Errorf("%w: %s is the broadcast address", ErrEgressRefused, a)
	case a.Is4() && cgnat.Contains(a):
		return fmt.Errorf("%w: %s is carrier-grade NAT space (100.64.0.0/10)", ErrEgressRefused, a)
	case !a.IsGlobalUnicast():
		return fmt.Errorf("%w: %s is not a global unicast address", ErrEgressRefused, a)
	}
	return nil
}

// embeddedIPv4 extracts the IPv4 address a NAT64 (well-known or local-use,
// last four bytes) or 6to4 (bytes 2-5) address carries. Pre-condition: a is
// in one of those three prefixes.
func embeddedIPv4(a netip.Addr) netip.Addr {
	b := a.As16()
	if sixToFour.Contains(a) {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	}
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

// detailEgress strips the sentinel prefix so a nested refusal is not
// prefixed twice.
func detailEgress(err error) string {
	msg := err.Error()
	if prefix := ErrEgressRefused.Error() + ": "; len(msg) > len(prefix) && msg[:len(prefix)] == prefix {
		return msg[len(prefix):]
	}
	return msg
}

// Timeouts of the transport itself, below the per-call ceiling the gateway
// puts on ctx (Gateway.CallTimeout) and the client-wide one
// (WithHTTPClientTimeout): one TCP connect or one TLS handshake that takes
// longer than this is a dead host, not a slow API.
const (
	connectTimeout   = 15 * time.Second
	handshakeTimeout = 15 * time.Second
)

// newTransport builds the one http.Transport an upstream's client uses.
//
// Four things are deliberate about it, each closing a path a default
// transport leaves open:
//
//   - Proxy is nil, not http.ProxyFromEnvironment. An HTTPS_PROXY variable
//     in the gateway's environment would route every REST call -- with the
//     injected credential -- through whatever it names, past the IP policy
//     below, which only ever sees the proxy's address.
//   - DialContext is dialPinned: the name is resolved HERE, every address
//     is judged by refuseAddr, and the socket is opened to the literal
//     address that passed. net.Dialer.Control judges the address a second
//     time at the socket, so a future change that let a name reach the
//     dialer would still be caught.
//   - No HTTP/2. ForceAttemptHTTP2 is false and a custom DialContext
//     disables the automatic upgrade; one request per connection is
//     enough for this team's traffic and keeps the body-size ceiling an
//     honest per-response number.
//   - No keep-alive. A kept-alive connection's bufio.Writer holds the bytes
//     of the last request it sent -- the request line with "?key=<value>"
//     for AuthKind=query, the Authorization or X-API-Key line for the other
//     kinds -- for as long as the connection sits idle, reachable from the
//     upstream through client.Transport. That would make "the credential
//     value is never held" (doc.go, rule 2) true of this package's own
//     fields and false of what they point at. With DisableKeepAlives each
//     exchange closes its connection when the body is read, and nothing the
//     upstream references outlives the call. The price is one TCP (and
//     TLS) handshake per call, which the same reasoning as the HTTP/2 point
//     already accepted. TestSecUpstreamRetainsNoCredential walks the live
//     transport after a call to keep this true.
func (d *Dialer) newTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout: connectTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			return d.controlCheck(network, address)
		},
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.dialPinned(ctx, dialer, network, addr)
		},
		TLSHandshakeTimeout: handshakeTimeout,
		DisableKeepAlives:   true,
	}
}

// dialPinned resolves addr's host, refuses the dial if ANY resolved
// address fails the policy, and otherwise connects to the addresses in
// turn -- as literal IPs, so what was checked is what is dialled.
//
// "Any" rather than "the one we pick" is the fail-closed reading of a
// resolver answer an attacker may control: a name answering {public,
// 169.254.169.254} would otherwise be reached on whichever the dialer
// happened to try first.
//
// Pre-condition: addr is host:port as http.Transport hands it over.
// Post-condition: a returned conn is to an address refuseAddr (or the
// test override) accepted; every error path wraps ErrEgressRefused or the
// dial error, never anything from a request.
func (d *Dialer) dialPinned(ctx context.Context, dialer *net.Dialer, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: network %q is not TCP", ErrEgressRefused, network)
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: address %q: %v", ErrEgressRefused, addr, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: address %q has no numeric port", ErrEgressRefused, addr)
	}

	var addrs []netip.Addr
	if literal, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{literal}
	} else {
		addrs, err = d.lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", host)
		}
	}
	for _, a := range addrs {
		if err := d.egress(a); err != nil {
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
// the same policy. It cannot see the host name (ADR-0048 Decisão 6, first
// bullet), which is why it is the second check and not the only one.
func (d *Dialer) controlCheck(network, address string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("%w: network %q is not TCP", ErrEgressRefused, network)
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: socket address %q: %v", ErrEgressRefused, address, err)
	}
	return d.egress(ap.Addr())
}
