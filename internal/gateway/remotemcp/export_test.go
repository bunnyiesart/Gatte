package remotemcp

import (
	"context"
	"net/netip"

	"github.com/bunnyiesart/Gatte/internal/egress"
)

// The hooks below exist only in the test binary: httptest listens on
// loopback, which the egress policy refuses, and the DNS-rebind case needs a
// name that "resolves" to a forbidden address without a resolver. There is
// no Option for either, so a production build has one resolver and one
// policy.

// AllowLoopbackForTest keeps the real policy for every address except
// loopback.
func AllowLoopbackForTest(d *Dialer) {
	d.guard.Policy = func(a netip.Addr) error {
		if a.Unmap().IsLoopback() {
			return nil
		}
		return egress.RefuseAddr(a)
	}
}

// SetLookupForTest replaces the resolver with fn.
func SetLookupForTest(d *Dialer, fn func(ctx context.Context, host string) ([]netip.Addr, error)) {
	d.guard.Lookup = fn
}
