//go:build linux && !386

package peercred

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// peerGroups reads SO_PEERGROUPS: the peer's supplementary groups as the
// kernel held them at connect time. Nil on any failure, so a group check
// fails closed.
func peerGroups(fd int) []uint32 {
	buf := make([]uint32, 64)
	for attempt := 0; attempt < 2; attempt++ {
		n := uint32(len(buf) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
		switch errno {
		case 0:
			return append([]uint32(nil), buf[:n/4]...)
		case unix.ERANGE:
			buf = make([]uint32, n/4+1)
			continue
		default:
			return nil
		}
	}
	return nil
}
