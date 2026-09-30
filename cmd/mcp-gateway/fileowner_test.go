package main

import (
	"os"
	"syscall"
	"testing"
)

// fileOwner is fi's uid and gid.
func fileOwner(t *testing.T, fi os.FileInfo) []int {
	t.Helper()
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no Stat_t")
	}
	return []int{int(st.Uid), int(st.Gid)}
}
