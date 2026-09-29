//go:build freebsd

package peercred

func peerPID(int) int32 { return 0 }
