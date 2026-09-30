//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// processStartToken is the start time of pid, in clock ticks since boot,
// from /proc/PID/stat (field 22): with the pid, it names one process for
// the life of the host, so a pid reused by another process of the service
// account is not rung (design/adr/0044). Empty when it cannot be read.
func processStartToken(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	// The command name (field 2) is in parentheses and may hold spaces
	// and parentheses itself; the fields after the last ')' are fixed.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return ""
	}
	fields := strings.Fields(s[i+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}
