// Package peercred reads, from the kernel, who is at the other end of a
// UNIX socket (design/adr/0040 §2).
//
// The management API takes the operator's identity from here and from
// nowhere else: no request field, header or environment variable names the
// operator. The same call works on both ends of a connection, so a client
// can also check who serves the socket it dialled (§4).
//
// Linux uses SO_PEERCRED and SO_PEERGROUPS; FreeBSD and macOS use
// LOCAL_PEERCRED (struct xucred). Other systems are refused at build time
// by the absence of an implementation: a platform where the kernel cannot
// say who connected has no management API.
package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Cred is what the kernel says about a peer.
type Cred struct {
	// UID is the peer's effective user id.
	UID uint32
	// GID is the peer's primary (effective) group id.
	GID uint32
	// Groups are the peer's groups as the kernel holds them for its
	// process, supplementary groups included. Nil when the kernel could
	// not say: a group check then fails closed.
	Groups []uint32
	// PID is the peer's process id where the kernel reports one (Linux,
	// macOS), 0 elsewhere. Only ever used to read the loginuid.
	PID int32
	// PIDFD is an open pidfd for the peer's process (Linux 6.5+,
	// SO_PEERPIDFD), -1 when there is none. It pins the process: while it
	// is open the pid cannot be reused unnoticed. Close with Release.
	PIDFD int
}

// HasGroup reports whether gid is among the peer's groups or is its
// primary group.
func (c Cred) HasGroup(gid uint32) bool {
	if c.GID == gid {
		return true
	}
	for _, g := range c.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

// ErrUnsupported is returned where the connection is not a UNIX socket.
var ErrUnsupported = errors.New("peercred: not a UNIX socket connection")

// Of returns the credentials of conn's peer. conn must be a *net.UnixConn
// (or wrap one and expose it through an UnixConn method).
func Of(conn net.Conn) (Cred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		if u, ok2 := conn.(interface{ UnixConn() *net.UnixConn }); ok2 {
			uc = u.UnixConn()
		}
	}
	if uc == nil {
		return Cred{PIDFD: -1}, ErrUnsupported
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{PIDFD: -1}, fmt.Errorf("peercred: %w", err)
	}
	var cred Cred
	var inner error
	if err := raw.Control(func(fd uintptr) { cred, inner = fromFD(int(fd)) }); err != nil {
		return Cred{PIDFD: -1}, fmt.Errorf("peercred: %w", err)
	}
	if inner != nil {
		return Cred{PIDFD: -1}, fmt.Errorf("peercred: %w", inner)
	}
	return cred, nil
}

// Unset is the loginuid value of a process no login session set.
const Unset = 4294967295

// LoginUID returns the audit login uid of the process pid, read under
// procRoot (normally "/proc"), and whether it may be used.
//
// It may not be used when the file cannot be read, when it holds Unset,
// or when /proc/PID/status says the process's real or effective uid is
// not wantUID -- which is what a pid that was reused by another process
// between the accept and this read looks like (design/adr/0040 §2). alive,
// when not nil, is asked after the read whether the original process still
// exists (the pidfd check); false discards the value too.
func LoginUID(procRoot string, pid int32, wantUID uint32, alive func() bool) (uint32, bool) {
	if pid <= 0 {
		return 0, false
	}
	dir := filepath.Join(procRoot, strconv.Itoa(int(pid)))
	b, err := os.ReadFile(filepath.Join(dir, "loginuid"))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || v == Unset {
		return 0, false
	}
	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil || !statusUIDIs(string(status), wantUID) {
		return 0, false
	}
	if alive != nil && !alive() {
		return 0, false
	}
	return uint32(v), true
}

// statusUIDIs reports whether the "Uid:" line of a /proc/PID/status names
// uid as both the real and the effective user.
func statusUIDIs(status string, uid uint32) bool {
	for _, line := range strings.Split(status, "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			return false
		}
		want := strconv.FormatUint(uint64(uid), 10)
		return f[0] == want && f[1] == want
	}
	return false
}
