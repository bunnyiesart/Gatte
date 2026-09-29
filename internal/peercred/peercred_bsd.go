//go:build darwin || freebsd

package peercred

import (
	"golang.org/x/sys/unix"
)

func fromFD(fd int) (Cred, error) {
	xu, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Cred{PIDFD: -1}, err
	}
	c := Cred{UID: xu.Uid, PIDFD: -1}
	n := int(xu.Ngroups)
	if n > len(xu.Groups) {
		n = len(xu.Groups)
	}
	if n > 0 {
		// cr_groups[0] is the effective group id.
		c.GID = xu.Groups[0]
		c.Groups = append([]uint32(nil), xu.Groups[:n]...)
	}
	c.PID = peerPID(fd)
	return c, nil
}

// Release is a no-op: there is no pidfd on this system.
func (c *Cred) Release() {}

// Alive is always true here; there is no loginuid to protect.
func (c Cred) Alive() bool { return true }

// HasLoginUID is false: FreeBSD and macOS keep no audit login uid that
// this package reads (design/adr/0040 §2).
const HasLoginUID = false
