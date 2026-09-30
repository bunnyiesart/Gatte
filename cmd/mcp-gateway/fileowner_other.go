//go:build !unix

package main

import "os"

// fileOwnerIDs has no answer off unix: check reports the ownership checks as
// skipped rather than guessing.
func fileOwnerIDs(os.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }

// effectiveUID is -1 off unix: never root.
func effectiveUID() int { return -1 }
