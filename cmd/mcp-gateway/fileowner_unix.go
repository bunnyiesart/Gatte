//go:build unix

package main

import (
	"os"
	"syscall"
)

// fileOwnerIDs is the numeric owner and group of a file, as the kernel keeps
// them. ok is false where the platform does not say.
func fileOwnerIDs(fi os.FileInfo) (uid, gid uint32, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

// effectiveUID is this process's effective uid.
func effectiveUID() int { return os.Geteuid() }
