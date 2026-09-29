//go:build linux && 386

package peercred

// peerGroups is not read on 386, where getsockopt goes through socketcall;
// a group check there fails closed.
func peerGroups(int) []uint32 { return nil }
