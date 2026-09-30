package main

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/bunnyiesart/Gatte/internal/control"
)

// errServeGone means the pid serve recorded is no longer that process.
var errServeGone = errors.New("the gateway process that recorded itself is no longer running")

// ringServe sends SIGHUP to the gateway process p (design/adr/0044). Where
// the system can say which process a pid is (Linux), a pid now held by
// another process is not rung. Only the service account (or root) may
// signal serve, which is the same account every operator command that
// writes the database already runs as.
func ringServe(p control.Process) error {
	if p.PID <= 1 {
		return fmt.Errorf("recorded pid %d is not a gateway process", p.PID)
	}
	if p.StartToken != "" {
		if now := processStartToken(p.PID); now != p.StartToken {
			return errServeGone
		}
	}
	switch err := syscall.Kill(p.PID, syscall.SIGHUP); {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		return errServeGone
	case errors.Is(err, syscall.EPERM):
		return fmt.Errorf("not permitted to signal pid %d: run this as the gateway's service account", p.PID)
	default:
		return err
	}
}
