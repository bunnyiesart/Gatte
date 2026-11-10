package resthttp

import (
	"net/http"

	"github.com/bunnyiesart/Gatte/internal/egress"
)

// ErrEgressRefused means the adapter would not open, or follow, a
// connection: the destination resolved to an address this gateway must not
// reach from inside its own network, or a redirect pointed at a host other
// than the one the entry signed (ADR-0048 Decisão 6). It is the shared
// guard's sentinel (internal/egress), so errors.Is against either name
// answers the same.
var ErrEgressRefused = egress.ErrRefused

// refuseAddr is the shared IP policy (egress.RefuseAddr), named here so the
// Dialer's default and the console seam read as this package's rule.
var refuseAddr = egress.RefuseAddr

// newTransport builds the one http.Transport an upstream's client uses: the
// shared egress guard (egress.Guard.Transport -- no proxy, resolved-address
// policy at dial and at the socket, no HTTP/2, no keep-alive), with this
// Dialer's resolver and policy, which only the tests replace.
func (d *Dialer) newTransport() *http.Transport {
	return egress.Guard{Lookup: d.lookup, Policy: d.egress}.Transport()
}
