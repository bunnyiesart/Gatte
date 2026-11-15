// Package testenv checks, once per test binary, that the machine running the
// tests matches what they assume. The gateway refuses a socket or file under a
// directory that group or others may write, so a test run under such a TMPDIR
// fails dozens of tests with that same refusal; Main reports it once instead.
package testenv

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Main runs m after checking the temporary directory, and is meant to be a
// package's whole TestMain: os.Exit(testenv.Main(m)).
func Main(m *testing.M) int {
	if err := CheckTempDir(); err != nil {
		fmt.Fprintf(os.Stderr, "testenv: %v\n", err)
		return 1
	}
	return m.Run()
}

// CheckTempDir reports the first directory, from os.TempDir() up to "/",
// that group or others may write.
func CheckTempDir() error {
	dir, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return fmt.Errorf("the temporary directory %s: %w", os.TempDir(), err)
	}
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return fmt.Errorf("the temporary directory %s: %w", dir, err)
		}
		if fi.Mode().Perm()&fs.FileMode(0o022) != 0 {
			return fmt.Errorf("%s is writable by group or others, and the temporary directory %s is in it or is it: "+
				"these tests create sockets and files the gateway refuses there. Rerun with TMPDIR set to a private directory: "+
				"mkdir -m 700 -p \"$HOME/gotmp\" && TMPDIR=\"$HOME/gotmp\" go test ./...", d, dir)
		}
		if d == filepath.Dir(d) {
			return nil
		}
	}
}
