//go:build darwin

package peercred

import "golang.org/x/sys/unix"

func peerPID(fd int) int32 {
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return 0
	}
	return int32(pid)
}
