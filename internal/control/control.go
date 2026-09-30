// Package control is how an operator asks the running gateway process
// (`serve`) to do something only that process can do
// (design/adr/0044): reload the part of the configuration that is
// reloadable, or drop and re-dial one backend.
//
// Everything else an operator does -- approve, revoke, block, maintenance
// -- is a row in the shared database that `serve` reads on the next call,
// and needs no channel into the process. These two cannot work that way:
// the role policy and the quota plan live in `serve`'s memory, and so do
// the backend connections. So the request is still a row, in the same
// database, written by the CLI or the management backend with the
// operator's name, and SIGHUP is only the doorbell: `serve` wakes, takes
// every pending request in order, does it, and writes the outcome back on
// the same row. Nothing listens on a new socket or port, and a SIGHUP with
// no pending request (`systemctl reload`, `kill -HUP`) is a reload
// attributed to the signal.
//
// The row carries the operator's name as the requester established it,
// the same way every CLI operator row does: whoever can write this table
// can write the audit trail directly, so the table adds no new way to put
// a name on a row.
package control

import (
	"context"
	"errors"
	"time"
)

// Kinds of request.
const (
	// KindReload re-reads the configuration file and applies its
	// reloadable part ([[role]], [group_to_role], [quota]).
	KindReload = "reload"
	// KindRedial drops the connection to one backend and dials it again.
	KindRedial = "redial"
)

// States of a request.
const (
	StatePending = "pending"
	StateDone    = "done"
)

// Outcomes of a finished request.
const (
	// OutcomeApplied: the change is in force.
	OutcomeApplied = "applied"
	// OutcomeRefused: nothing changed, and the detail says why.
	OutcomeRefused = "refused"
)

var (
	// ErrUnavailable means the control table could not be read or written.
	ErrUnavailable = errors.New("control: store unavailable")
	// ErrNotFound means no request has that id.
	ErrNotFound = errors.New("control: no such request")
	// ErrNoProcess means no gateway process has ever recorded itself.
	ErrNoProcess = errors.New("control: no gateway process has recorded itself")
	// ErrInvalid means a request is missing a field it needs.
	ErrInvalid = errors.New("control: invalid request")
)

// Request is one thing an operator asked `serve` to do.
type Request struct {
	ID   int64
	Kind string
	// Target is the backend of a redial; empty for a reload.
	Target string
	// Actor is the ANALYST value of the operator row the outcome is
	// recorded under, e.g. "(operator:alice)".
	Actor string
	// Tag is the actor's marker, e.g. "[cli]" or "[ui] [via root]".
	Tag         string
	RequestedAt time.Time

	State string
	// DoneAt, Outcome and Result are set once State is StateDone. Result
	// is the JSON the requester reads back (an adminapi result).
	DoneAt  time.Time
	Outcome string
	Result  []byte
	// Boot is the boot time of the process that finished it.
	Boot time.Time
}

// Process is what the running gateway process says about itself, so a
// requester knows whom to ring.
type Process struct {
	PID  int
	Boot time.Time
	// StartToken identifies this process beyond its pid where the system
	// can say so (Linux: the start time in /proc/PID/stat), so a pid that
	// was reused by another process of the same account is not rung.
	// Empty where the system cannot say.
	StartToken string
}

// Store is the gateway process's side: it records itself, takes the
// pending requests, and finishes them.
type Store interface {
	RecordProcess(ctx context.Context, p Process) error
	Pending(ctx context.Context) ([]Request, error)
	Finish(ctx context.Context, id int64, outcome string, result []byte, boot, at time.Time) error
}

// Requester is the operator's side: it files a request, reads it back,
// and learns whom to ring.
type Requester interface {
	Submit(ctx context.Context, r Request) (int64, error)
	Get(ctx context.Context, id int64) (Request, error)
	Process(ctx context.Context) (Process, error)
	// Abandon finishes a request that is still pending as refused, with
	// result as its answer: for one filed and then never rung.
	Abandon(ctx context.Context, id int64, result []byte, at time.Time) error
}
