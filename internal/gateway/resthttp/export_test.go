package resthttp

import (
	"context"
	"net/netip"
)

// The hooks below exist only in the test binary. They reach the two
// unexported policy fields of Dialer so that the tests can (a) make a name
// "resolve" to a forbidden address without DNS and (b) let httptest's
// loopback listener through a policy that otherwise refuses loopback.
// Nothing outside _test.go can set either field: there is no Option for
// them on purpose, so a production build has exactly one resolver and one
// egress policy.

// SetLookupForTest replaces the resolver with fn.
func SetLookupForTest(d *Dialer, fn func(ctx context.Context, host string) ([]netip.Addr, error)) {
	d.lookup = fn
}

// AllowLoopbackForTest keeps the real policy for every address except
// loopback, which httptest listens on.
func AllowLoopbackForTest(d *Dialer) {
	d.egress = func(a netip.Addr) error {
		if a.Unmap().IsLoopback() {
			return nil
		}
		return refuseAddr(a)
	}
}

// SetEgressForTest replaces the whole IP policy with fn, so a test can
// count how many times a dial consults it (dialPinned and then
// net.Dialer.Control: TestDial_ControlIsTheSecondLine) or let loopback
// through with its own rule.
func SetEgressForTest(d *Dialer, fn func(a netip.Addr) error) {
	d.egress = fn
}

// Unexported names the tests exercise directly.
var (
	RefuseAddr     = refuseAddr
	ScrubCallError = scrubCallError
	ParseBase      = parseBase
)

// BaseOrigin exposes what a parsed base pins the client to.
func BaseOrigin(b base) (origin, path string) { return b.origin, b.path }
