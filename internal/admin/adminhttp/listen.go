package adminhttp

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// SocketPolicy is how a foreground backend creates its socket
// (design/adr/0040 §4).
type SocketPolicy struct {
	// Group is the socket file's group, -1 for the process's own.
	Group int
	// Mode is the socket file's mode: 0600, or 0660 with a Group. Nothing
	// for others, ever.
	Mode os.FileMode
	// SelfUID is the process's uid.
	SelfUID uint32
	// OwnDirOK lets the socket's own directory belong to SelfUID (the
	// operator socket run as the service account). The directories above
	// it must still be Trusted.
	OwnDirOK bool
	// Trusted reports whether a uid may own a directory on the way to the
	// socket (root, in production).
	Trusted func(uid uint32) bool
}

// RootOnly is the production Trusted: only root may own a directory on the
// way to a socket.
func RootOnly(uid uint32) bool { return uid == 0 }

// Listen creates the socket at path under p: it checks the directory chain,
// refuses a path that exists and is not a socket, and applies group and
// mode before the first connection can be accepted.
func Listen(path string, p SocketPolicy) (*net.UnixListener, error) {
	if p.Mode&^0o660 != 0 || p.Mode&0o600 != 0o600 {
		return nil, fmt.Errorf("socket mode %04o: use 0600, or 0660 with a socket group; nothing for others", p.Mode.Perm())
	}
	if p.Mode&0o060 != 0 && p.Group < 0 {
		return nil, fmt.Errorf("socket mode %04o gives a group access, and no socket group is named", p.Mode.Perm())
	}
	if p.Trusted == nil {
		p.Trusted = RootOnly
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := CheckDirChain(filepath.Dir(abs), p); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(abs); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket; refusing to replace it", abs)
		}
		if err := os.Remove(abs); err != nil {
			return nil, fmt.Errorf("removing the stale socket %s: %w", abs, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Created 0600 whatever the umask: nobody else can connect before the
	// group and mode below are applied.
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: abs, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if p.Group >= 0 {
		if err := os.Chown(abs, -1, p.Group); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("setting the socket's group: %w", err)
		}
	}
	if err := os.Chmod(abs, p.Mode.Perm()); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("setting the socket's mode: %w", err)
	}
	return ln, nil
}

// CheckDirChain checks, with Lstat, dir and every directory above it up to
// "/": no symbolic link, nothing writable by group or others, every one
// above dir owned by a Trusted uid, and dir itself Trusted or -- with
// OwnDirOK -- the process's own. Mode bits are not enough on their own: a
// 0755 directory of the service account still lets it replace the socket.
func CheckDirChain(dir string, p SocketPolicy) error {
	if p.Trusted == nil {
		p.Trusted = RootOnly
	}
	var chain []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		chain = append([]string{d}, chain...)
		if d == filepath.Dir(d) {
			break
		}
	}
	for i, d := range chain {
		leaf := i == len(chain)-1
		fi, err := os.Lstat(d)
		if err != nil {
			return fmt.Errorf("socket directory: %w", err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("socket directory: %s is a symbolic link", d)
		}
		if !fi.IsDir() {
			return fmt.Errorf("socket directory: %s is not a directory", d)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("socket directory: %s is writable by group or others, so another account could replace the socket", d)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("socket directory: %s has no owner this system reports", d)
		}
		if p.Trusted(st.Uid) || leaf && p.OwnDirOK && st.Uid == p.SelfUID {
			continue
		}
		return fmt.Errorf("socket directory: %s belongs to uid %d; every directory above the socket's own must be root's", d, st.Uid)
	}
	return nil
}

// ListenersFromFiles turns sockets a service manager handed over into
// listeners, refusing any that is not a UNIX stream socket.
func ListenersFromFiles(files []*os.File) ([]net.Listener, error) {
	var out []net.Listener
	closeAll := func() {
		for _, l := range out {
			_ = l.Close()
		}
	}
	for _, f := range files {
		fd := int(f.Fd())
		typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("activation fd %d is not a socket: %w", fd, err)
		}
		sa, err := unix.Getsockname(fd)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("activation fd %d: %w", fd, err)
		}
		if _, ok := sa.(*unix.SockaddrUnix); !ok || typ != unix.SOCK_STREAM {
			closeAll()
			return nil, fmt.Errorf("activation fd %d is not a UNIX stream socket; the management API listens on nothing else", fd)
		}
		l, err := net.FileListener(f)
		if err != nil {
			closeAll()
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// Activated returns the sockets systemd passed (LISTEN_PID, LISTEN_FDS),
// or none when the process was not socket-activated.
func Activated() ([]net.Listener, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil, nil
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, fmt.Errorf("LISTEN_FDS=%q", os.Getenv("LISTEN_FDS"))
	}
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	files := make([]*os.File, n)
	for i := range files {
		fd := 3 + i
		unix.CloseOnExec(fd)
		files[i] = os.NewFile(uintptr(fd), "activation-"+strconv.Itoa(fd))
	}
	ls, err := ListenersFromFiles(files)
	for _, f := range files {
		f.Close()
	}
	return ls, err
}

// CheckAccountsFile holds the accounts socket file to [admin]
// account_group (design/adr/0040 §1): with no delegation the file admits
// no group, and with one it is that group's, 0660. Both settings are
// required, so a mismatch refuses to start.
func CheckAccountsFile(fileGID uint32, mode os.FileMode, configGID *uint32) error {
	perm := mode.Perm()
	if perm&0o007 != 0 {
		return fmt.Errorf("the accounts socket is %04o: open to others", perm)
	}
	if configGID == nil {
		if perm&0o070 != 0 {
			return fmt.Errorf("the accounts socket is %04o, group %d, and [admin] account_group names no group: set both, or neither", perm, fileGID)
		}
		return nil
	}
	if perm&0o060 != 0o060 {
		return fmt.Errorf("[admin] account_group is set and the accounts socket is %04o: make it 0660 (SocketMode=0660, or -socket-mode 0660)", perm)
	}
	if fileGID != *configGID {
		return fmt.Errorf("the accounts socket's group is %d and [admin] account_group is %d: they must match", fileGID, *configGID)
	}
	return nil
}

// CheckOperatorFile holds the operator socket file to design/adr/0040 §1,
// where the barrier is the file's mode: a file other users may connect to
// admits every local uid as an operator, so it refuses to start. With
// [admin] operator_group set, a file open to a group must be that group's.
func CheckOperatorFile(fileGID uint32, mode os.FileMode, operatorGID *uint32) error {
	perm := mode.Perm()
	if perm&0o007 != 0 {
		return fmt.Errorf("the operator socket is %04o: open to every local user (SocketMode=0660, or -socket-mode 0660)", perm)
	}
	if operatorGID != nil && perm&0o070 != 0 && fileGID != *operatorGID {
		return fmt.Errorf("the operator socket's group is %d and [admin] operator_group is %d: they must match", fileGID, *operatorGID)
	}
	return nil
}

// SocketFileOf stats the socket file behind a listener.
func SocketFileOf(ln net.Listener) (uint32, os.FileMode, string, error) {
	path := ln.Addr().String()
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, path, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, path, errors.New("no owner reported")
	}
	return st.Gid, fi.Mode(), path, nil
}
