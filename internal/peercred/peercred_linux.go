//go:build linux

package peercred

import (
	"golang.org/x/sys/unix"
)

func fromFD(fd int) (Cred, error) {
	uc, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Cred{PIDFD: -1}, err
	}
	c := Cred{UID: uc.Uid, GID: uc.Gid, PID: uc.Pid, PIDFD: -1}
	c.Groups = peerGroups(fd)
	// SO_PEERPIDFD exists from Linux 6.5; an older kernel answers ENOPROTOOPT
	// and the loginuid is then checked through /proc/PID/status only.
	if pfd, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD); err == nil && pfd >= 0 {
		c.PIDFD = pfd
	}
	return c, nil
}

// Release closes the pidfd, if any.
func (c *Cred) Release() {
	if c.PIDFD >= 0 {
		_ = unix.Close(c.PIDFD)
		c.PIDFD = -1
	}
}

// Alive reports whether the process the pidfd pins still exists. True when
// there is no pidfd: the caller then relies on the /proc/PID/status check.
func (c Cred) Alive() bool {
	if c.PIDFD < 0 {
		return true
	}
	return unix.PidfdSendSignal(c.PIDFD, 0, nil, 0) == nil
}

// HasLoginUID is true where the kernel keeps an audit login uid.
const HasLoginUID = true
