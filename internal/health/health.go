// Package health is the domain of design/adr/0041: what the gateway says
// about its backends being up or not, and the planned maintenance an
// operator announces for one backend or for the whole gateway.
//
// It holds types, validation and ports, and no storage: the sqlite
// subpackage is the adapter. Three readers share it and each holds only the
// port it needs -- the Gateway reads maintenance on every call and writes
// what it observed about its backends; the management service writes
// maintenance and reads what the Gateway observed, because it is another
// process and cannot see the Gateway's memory (ADR-0041 item 7).
package health

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bunnyiesart/Gatte/internal/visible"
)

// GatewayTarget is the maintenance target that means the whole gateway
// rather than one backend. In parentheses, like the audit actors, so it
// cannot collide with a registry name, whose charset has none.
const GatewayTarget = "(gateway)"

// MaxMessageRunes bounds an operator's maintenance message, counted in
// Unicode code points -- the count JSON Schema's maxLength uses.
const MaxMessageRunes = 200

// MaxUntilAhead bounds how far ahead a maintenance may announce its end:
// far enough for any planned window, near enough to catch a mistyped year.
const MaxUntilAhead = 90 * 24 * time.Hour

var (
	// ErrInvalid is returned by ValidateMessage and ValidateUntil.
	ErrInvalid = errors.New("health: invalid maintenance")
	// ErrUnavailable means the maintenance or health state could not be
	// read or written. The Gateway reads maintenance fail-open (ADR-0041
	// item 6): an unreadable table serves as if there were none.
	ErrUnavailable = errors.New("health: state unavailable")
)

// Maintenance is one maintenance row (ADR-0041 item 6).
type Maintenance struct {
	// Target is a backend's registered name, or GatewayTarget.
	Target string
	// Message is the operator's text, as written. It reaches analysts and
	// their models.
	Message string
	// Until is the announced end, or zero for none. A forecast, not a
	// deadline: only an explicit end ends a maintenance.
	Until time.Time
	// StartedAt is when the maintenance was opened. A repeated start with
	// another message or until does not move it; it is shown to analysts
	// as the maintenance's "since".
	StartedAt time.Time
	// SetBy and SetAt are the operator and the instant of the last change.
	// They never reach an analyst.
	SetBy string
	SetAt time.Time
}

// UntilPassed reports whether an announced end is in the past at now.
func (m Maintenance) UntilPassed(now time.Time) bool {
	return !m.Until.IsZero() && now.After(m.Until)
}

// ValidateMessage trims raw and checks it is a maintenance message the
// gateway may put in front of a model: 1 to MaxMessageRunes code points,
// valid UTF-8, one line, and no control or hidden code point -- refused,
// not escaped, because the operator should see the refusal, not a message
// silently different from what they typed. `"` and `\` are allowed: where
// the gateway embeds the message in its own text it quotes it.
func ValidateMessage(raw string) (string, error) {
	msg := strings.TrimSpace(raw)
	switch n := utf8.RuneCountInString(msg); {
	case msg == "":
		return "", fmt.Errorf("%w: the message is required", ErrInvalid)
	case n > MaxMessageRunes:
		return "", fmt.Errorf("%w: the message is %d characters, over the %d allowed", ErrInvalid, n, MaxMessageRunes)
	case !utf8.ValidString(msg):
		return "", fmt.Errorf("%w: the message is not valid UTF-8", ErrInvalid)
	}
	for _, r := range msg {
		if visible.Hides(r) {
			return "", fmt.Errorf("%w: the message carries a control, line-break or hidden character (%U); write it on one line with visible characters", ErrInvalid, r)
		}
	}
	return msg, nil
}

// ValidateUntil checks an announced end at now: zero (none) is valid;
// otherwise it must be in the future and at most MaxUntilAhead away.
func ValidateUntil(until, now time.Time) error {
	switch {
	case until.IsZero():
		return nil
	case !until.After(now):
		return fmt.Errorf("%w: until %s is not in the future", ErrInvalid, until.UTC().Format(time.RFC3339))
	case until.Sub(now) > MaxUntilAhead:
		return fmt.Errorf("%w: until %s is more than 90 days ahead", ErrInvalid, until.UTC().Format(time.RFC3339))
	}
	return nil
}

// MaintenanceReader is what the Gateway holds: it can read the whole
// table, once per call, and nothing else.
type MaintenanceReader interface {
	// Maintenance returns every maintenance row. An error wraps
	// ErrUnavailable.
	Maintenance(ctx context.Context) ([]Maintenance, error)
}

// StartResult is what a start did.
type StartResult struct {
	// Stored is the row now in force.
	Stored Maintenance
	// Previous is the row it replaced, or nil when there was none.
	Previous *Maintenance
	// Changed is false when the same message and until were already in
	// force: nothing was written.
	Changed bool
}

// MaintenanceStore is the management service's port.
type MaintenanceStore interface {
	MaintenanceReader
	// Start opens, or updates, the maintenance of m.Target. An existing
	// row keeps its StartedAt; the same message and until again changes
	// nothing. m.Message must already be valid.
	Start(ctx context.Context, m Maintenance) (StartResult, error)
	// End removes the maintenance of target and returns the row it ended,
	// or nil when there was none.
	End(ctx context.Context, target string) (*Maintenance, error)
}

// Cause is why a backend is not live. Operator only: it never reaches an
// analyst (ADR-0041 item 3).
type Cause string

const (
	// CauseProcessGone: the backend's process was seen gone (ADR-0024).
	CauseProcessGone Cause = "process_gone"
	// CauseNotBroughtUp: a dial was tried and failed.
	CauseNotBroughtUp Cause = "not_brought_up"
	// CauseHeldBack: dials are frozen while the quota and the registry
	// disagree (ADR-0030).
	CauseHeldBack Cause = "held_back"
	// CauseNotListed: a new process is connected but no listing of it has
	// succeeded yet, so it takes no call (ADR-0041 item 4).
	CauseNotListed Cause = "not_listed"
)

// BackendRecord is what the gateway process last observed about one
// servable backend.
type BackendRecord struct {
	Backend string
	// Live is true when there is an open connection not found dead.
	Live bool
	// Since is when Live took its current value, in the reporting process.
	Since time.Time
	// LastAttempt is the last dial tried, or zero.
	LastAttempt time.Time
	// NextAttempt is when the next round is expected to dial it, or zero
	// when no dial is scheduled.
	NextAttempt time.Time
	// Cause is set when not live.
	Cause Cause
	// UpdatedAt is when the row was written.
	UpdatedAt time.Time
}

// ListedTool is one tool of a backend's last successful live listing: the
// source of the stable listing when the gateway boots with that backend
// down (ADR-0041 item 4).
type ListedTool struct {
	Tool string
	Hash string
}

// ServeStatus is what the gateway process last said about itself.
type ServeStatus struct {
	Boot          time.Time
	LastRoundAt   time.Time
	RoundInterval time.Duration
}

// Snapshot is one write of the gateway's observed state.
type Snapshot struct {
	// Backends replaces the whole backend_health set: a backend absent
	// from it is no longer servable and loses its row.
	Backends []BackendRecord
	// Listings rewrites the listing of each backend it names, in the same
	// transaction; backends it does not name keep theirs.
	Listings map[string][]ListedTool
	// ListedAt stamps the rewritten listings.
	ListedAt time.Time
	// Serve, when non-nil, replaces the serve_status row.
	Serve *ServeStatus
}

// StateStore is what the Gateway writes its observations through.
type StateStore interface {
	// WriteState writes s in one transaction.
	WriteState(ctx context.Context, s Snapshot) error
	// Listings returns every backend's last live listing, keyed by backend.
	Listings(ctx context.Context) (map[string][]ListedTool, error)
}

// StateReader is what the management service reads.
type StateReader interface {
	// Backends returns the last written row of every servable backend.
	Backends(ctx context.Context) ([]BackendRecord, error)
	// Serve returns the serve_status row, and false when there is none.
	Serve(ctx context.Context) (ServeStatus, bool, error)
}
