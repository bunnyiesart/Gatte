package gateway

// Refusals a caller can act on (design/adr/0042 item 2).
//
// Each type below is a granted, approved call the gateway refused or gave
// up on for a reason of its OWN -- a limit in the operator's file, the
// caller's own allowance, the caller's own calls in flight -- and not for
// anything a backend said. Like UnavailableError and BackendFailedError
// (ADR-0041 item 2), every field is the gateway's state or the operator's
// declared policy, never an upstream's text, and the serving adapter turns
// each into one constant sentence with those fields in it. They unwrap to
// the sentinels the trail and the older tests already classify by, so the
// audit reasons do not move.

import (
	"context"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quota"
)

// ResultTooLargeError is a result the backend returned over the size
// ceiling (ADR-0014), refused whole. The call did run at the backend.
type ResultTooLargeError struct {
	// Tool is the namespaced name the caller called.
	Tool string
	// Limit is the ceiling in bytes, from the operator's file.
	Limit   int64
	Gateway *MaintenanceNotice
	cause   error
}

func (e *ResultTooLargeError) Error() string {
	return fmt.Sprintf("gateway: call %q: result over the %d-byte ceiling", e.Tool, e.Limit)
}

func (e *ResultTooLargeError) Unwrap() error { return e.cause }

// CallTimeoutError is a call the backend did not answer within the
// gateway's per-call ceiling (ADR-0025). The caller did not hang up: that
// case stays the constant internal error, since nobody is left to read it.
type CallTimeoutError struct {
	Backend string
	// Limit is the per-call ceiling, from the operator's file.
	Limit   time.Duration
	Gateway *MaintenanceNotice
}

func (e *CallTimeoutError) Error() string {
	return fmt.Sprintf("gateway: backend %q did not answer within %s", e.Backend, e.Limit)
}

func (e *CallTimeoutError) Unwrap() error { return context.DeadlineExceeded }

// ConcurrencyLimitedError is a call refused because the caller already has
// Limit calls in flight, across every session of theirs (ADR-0035).
type ConcurrencyLimitedError struct {
	Limit   int
	Gateway *MaintenanceNotice
}

func (e *ConcurrencyLimitedError) Error() string {
	return fmt.Sprintf("%v (limit %d)", ErrConcurrencyLimited, e.Limit)
}

func (e *ConcurrencyLimitedError) Unwrap() error { return ErrConcurrencyLimited }

// QuotaExhaustedError is a call refused because the caller's allowance on
// one budgeted account is spent for this window (ADR-0030). Budget is the
// quota's own typed refusal: account, limit, window and reset -- policy,
// never a count.
type QuotaExhaustedError struct {
	Budget  *quota.ExhaustedError
	Gateway *MaintenanceNotice
}

func (e *QuotaExhaustedError) Error() string { return e.Budget.Error() }

func (e *QuotaExhaustedError) Unwrap() error { return e.Budget }

// CallerStanding is the "you" block of gatte.status (ADR-0042 item 3): the
// caller's own display name and roles, and each budget their served tools
// spend, with their own use of it. Nothing here is about anybody else.
type CallerStanding struct {
	Name    string
	Roles   []string
	Budgets []quota.Standing
}
