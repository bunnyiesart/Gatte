// Package atomicfile replaces a file so that a reader sees either the old
// bytes or the new ones, never a part of each, and the file keeps its
// owner and mode (design/adr/0050: the console writes the vault and the
// roles file, both read by serve on its own schedule).
package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Replace writes data to path through a temporary file in the same
// directory and a rename, so the replacement is atomic on one file
// system.
//
// An existing path keeps its owner, group and permission bits: a root
// process rewriting a file the service account reads must not leave it
// root's, nor widen it. A path that does not exist is created with
// newMode. A path that exists and is not a regular file (a symbolic link,
// a directory) is refused, not followed: the rename would replace the link
// and the caller asked for the file.
//
// Pre-condition: data is the whole new content. Post-condition: on nil the
// file holds data, synced, with the owner and mode above; on error the
// file is as it was and no temporary file is left behind.
func Replace(path string, data []byte, newMode os.FileMode) error {
	mode := newMode.Perm()
	uid, gid := -1, -1
	switch fi, err := os.Lstat(path); {
	case err == nil:
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("atomicfile: %s is not a regular file; refusing to replace it", path)
		}
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("atomicfile: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	name := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	// Mode and owner before the content: the temporary file never holds
	// the new bytes under looser permissions than the file it replaces.
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if uid >= 0 && (uid != os.Geteuid() || gid != os.Getegid()) {
		if err := tmp.Chown(uid, gid); err != nil {
			return fmt.Errorf("atomicfile: keeping %s's owner %d:%d: %w", path, uid, gid, err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	done = true
	// The rename is durable once the directory is synced; a failure here
	// leaves the new content in place, so it is not an error of Replace.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
