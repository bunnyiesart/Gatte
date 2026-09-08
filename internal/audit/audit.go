// Package audit is the domain package for the Audit Trail component
// (design/02-components.md): one record per tool call -- analyst identity,
// tool, target upstream, timestamp. It defines the Record entity, its
// validation rules, and the Recorder port that any storage adapter must
// implement.
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter.
//
// Per WORKFLOW.md's Phase 1 scope, Record's schema is deliberately limited
// to who/what/where/when -- outcome/success and any other telemetry are
// out of scope until a later, currently-undesigned hardening phase
// (AGENTS.md §2, "Telemetry/observability").
package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrInvalid is returned when a Record fails Validate.
var ErrInvalid = errors.New("audit: invalid record")

// Record is one entry in the audit trail: who called which tool, which
// upstream server served it, and when.
type Record struct {
	// AnalystIdentity identifies who made the call.
	AnalystIdentity string
	// Tool identifies which tool was invoked, e.g. "casemgmt.list_cases".
	Tool string
	// TargetUpstream identifies which backend server served the call,
	// e.g. "casemgmt".
	TargetUpstream string
	// Timestamp is when the call was made. Record does not decide how
	// "now" is obtained -- the caller supplies it, keeping this component
	// trivially testable without a Clock dependency.
	Timestamp time.Time
	// Outcome says whether the call was allowed, refused, or attempted
	// and failed. See the Outcome type.
	Outcome Outcome
	// Reason is an optional short, operator-facing classification of a
	// refusal or failure, e.g. "forbidden" or "quarantined".
	//
	// This deliberately holds the distinction the *caller* is not told.
	// The gateway returns an opaque error to a client so it cannot probe
	// which tools exist or which are currently under suspicion; the audit
	// trail is read by the operator, who needs exactly that distinction to
	// answer "why was this blocked". Free text, never parsed for a
	// decision -- it is evidence, not control flow.
	Reason string
}

// Outcome is what happened to a call.
//
// This field exists because an audit trail that cannot distinguish a
// refused call from a completed one answers the wrong question. CONCEPTS.md
// §2.5 names outcome as one of five things a useful record needs -- who,
// what, when, target, outcome -- and is blunt that without them together
// "the log is decoration, not evidence". For a SOC, "was this blocked?" is
// the first question asked of the trail, and it was unanswerable until
// this field existed.
type Outcome string

const (
	// OutcomeAllowed means the call passed every gate and was forwarded to
	// its upstream.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeDenied means the gateway refused the call: no such tool, not
	// approved by Tool Quarantine, or not permitted by the caller's role.
	// The specific reason belongs in Reason.
	OutcomeDenied Outcome = "denied"
	// OutcomeFailed means the call was allowed and forwarded, but the
	// upstream did not complete it. Distinct from OutcomeDenied because
	// "the gateway said no" and "the backend broke" are different
	// incidents with different responses.
	OutcomeFailed Outcome = "failed"
)

// Valid reports whether o is one of the defined outcomes.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeAllowed, OutcomeDenied, OutcomeFailed:
		return true
	}
	return false
}

// Validate checks that r satisfies the audit trail's entry contract:
//
//   - AnalystIdentity must be non-empty.
//   - Tool must be non-empty.
//   - TargetUpstream must be non-empty.
//   - Timestamp must not be the zero value (time.Time{}).
//
// Validate returns ErrInvalid, wrapped with a description of every rule
// that failed (not just the first one encountered), on any violation; it
// returns nil when r is well-formed.
func (r Record) Validate() error {
	var errs []error

	if r.AnalystIdentity == "" {
		errs = append(errs, errors.New("analyst identity must not be empty"))
	}
	if r.Tool == "" {
		errs = append(errs, errors.New("tool must not be empty"))
	}
	if r.TargetUpstream == "" {
		errs = append(errs, errors.New("target upstream must not be empty"))
	}
	if r.Timestamp.IsZero() {
		errs = append(errs, errors.New("timestamp must not be the zero value"))
	}
	// Required, with no default. A zero-value Outcome would silently
	// record every call as the same thing, which is the failure this
	// field was added to prevent -- so an unset Outcome is a rejected
	// record, not an "unknown" one.
	if !r.Outcome.Valid() {
		errs = append(errs, fmt.Errorf("outcome %q is not one of %q, %q, %q",
			r.Outcome, OutcomeAllowed, OutcomeDenied, OutcomeFailed))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalid}, errs...)...)
}

// Recorder is the port through which the domain durably stores and
// retrieves Records. Implementations are adapters (e.g. the sqlite
// subpackage) and must honor the contracts documented on each method.
type Recorder interface {
	// Record durably stores r. It returns ErrInvalid if r.Validate()
	// fails, and nothing is written in that case. There is no return
	// value beyond error on success -- the audit trail is append-only,
	// so there is no ID to hand back in this phase.
	Record(ctx context.Context, r Record) error

	// List returns every recorded Record in chronological order by
	// Timestamp, oldest first. This ordering is guaranteed: the Operator
	// Console reads this trail and relies on it. When nothing has been
	// recorded yet, List returns an empty, non-nil slice and a nil
	// error -- an empty audit trail is not an error condition.
	List(ctx context.Context) ([]Record, error)
}
