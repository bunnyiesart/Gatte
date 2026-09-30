// Package admin is Gatte's management service (design/adr/0040 §3): every
// rule an operator action is held to, returning the typed results of
// pkg/adminapi instead of printed text.
//
// Two renderers sit on top of it and add no rule of their own: the CLI
// commands of cmd/mcp-gateway, which print, and the management API of
// internal/admin/adminhttp, which answers JSON over a UNIX socket. So
// "approve only the fingerprint shown", "one operator row for every
// change", "groups only from [group_to_role]" and "the one-time password
// hashed and handed over once" each exist exactly once, here.
//
// The service depends on ports only (quarantine.Store, access.BlockStore,
// ...); the composition root wires the adapters.
package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Trail is what the service reads of the audit trail.
type Trail interface {
	// Page returns the newest records matching q, newest first, with
	// their chain positions, and whether more match; it never holds the
	// whole trail.
	Page(ctx context.Context, q audit.TrailQuery) ([]audit.PositionedRecord, bool, error)
	// Analysts summarises every person's identity on the trail.
	Analysts(ctx context.Context) ([]audit.AnalystSeen, error)
	// HasAnalyst reports whether any record carries identity.
	HasAnalyst(ctx context.Context, identity string) (bool, error)
	// VerifyChain walks the hash chain.
	VerifyChain(ctx context.Context) (audit.ChainCheck, error)
}

// Deps is everything the service is built from. Config and Record are
// required; a nil store makes the operations that need it answer
// internal, which is how the accounts backend (no database) is built.
type Deps struct {
	// Config reads the configuration again. It is called for every
	// operation: a backend may live for hours, and grants, groups and
	// signers change in the file. Its error, when it is an
	// *adminapi.Error, is answered as it is (config_unavailable).
	Config func() (*config.Config, error)
	Tools  quarantine.Store
	Blocks access.BlockStore
	// Maintenance is where planned maintenance is written
	// (design/adr/0041); the gateway reads it per call.
	Maintenance health.MaintenanceStore
	// Health is what the gateway process last wrote about its backends
	// and itself (design/adr/0041 item 7). nil: the overview and the
	// upstream list carry no health.
	Health health.StateReader
	// ServeGrace is how long past twice its round interval serve may go
	// without completing a round before it counts as not reporting: the
	// reconciliation timeout, the longest a round may take.
	ServeGrace time.Duration
	Trail      Trail
	Quota      quota.Reader
	// Upstreams lists the registry with each entry's signature state and
	// network, the way `upstream list -json` computes them.
	Upstreams func(ctx context.Context, cfg *config.Config) ([]adminapi.Upstream, error)
	// Record appends one operator row, through the same recorder `serve`
	// uses (SQLite, then the SIEM copies).
	Record func(ctx context.Context, cfg *config.Config, rec audit.Record) error
	// Accounts opens the IdP's account store named by cfg.
	Accounts func(cfg *config.Config) (idp.Directory, error)
	// IsBusy reports whether err is a database that stayed locked.
	IsBusy func(error) bool
	Now    func() time.Time
	Log    *slog.Logger
}

// Service is the management service. Its methods are safe for concurrent
// use; state changes are serialised.
type Service struct {
	d  Deps
	mu sync.Mutex
}

// New builds the service.
func New(d Deps) (*Service, error) {
	if d.Config == nil || d.Record == nil {
		return nil, errors.New("admin: Config and Record are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.IsBusy == nil {
		d.IsBusy = func(error) bool { return false }
	}
	if d.Log == nil {
		d.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{d: d}, nil
}

// Actor is who an action is attributed to, as the renderer established it:
// the kernel's peer credentials for the API, the environment or the
// loginuid for the CLI. The service never decides it.
type Actor struct {
	// Name is the system account name the row is attributed to.
	Name string
	// Via is the shared account (root, the service account) the process
	// ran as when its loginuid named the human. Empty otherwise.
	Via string
	// Front labels where the action came from: "ui", "api", "cli",
	// "cli env", or a third-party front's name. Display only.
	Front string
	// Root is true when the kernel said the peer is uid 0. Only root
	// reaches IdP accounts Gatte does not manage (design/adr/0040 §1).
	Root bool
}

// Identity is the ANALYST value of the actor's rows.
func (a Actor) Identity() string { return OperatorIdentity(a.Name) }

// Tag is the marker the actor's rows carry in their reason, e.g. "[ui]" or
// "[cli] [via root]".
func (a Actor) Tag() string {
	front := a.Front
	if front == "" {
		front = "api"
	}
	t := "[" + front + "]"
	if a.Via != "" {
		t += " [via " + a.Via + "]"
	}
	return t
}

// OperatorIdentity is the ANALYST value of an operator action's row. In
// parentheses, like "(unauthenticated)", because no IdP issues a subject
// in parentheses: this row can never be read as an analyst's.
func OperatorIdentity(name string) string { return "(operator:" + name + ")" }

// The Tool and TargetUpstream of operator rows. Declared interface
// strings: a SIEM rule matches on them.
const (
	ToolApprove    = "(tool approve)"
	ToolRevoke     = "(tool revoke)"
	AccessBlock    = "(access block)"
	AccessUnblock  = "(access unblock)"
	AccountAdd     = "(account add)"
	AccountGroups  = "(account groups)"
	AccountDisable = "(account disable)"
	AccountEnable  = "(account enable)"
	AccountReset   = "(account reset password)"
	OperatorTarget = "(gateway)"
)

// Operator rows of design/adr/0043.
const (
	// ToolApproveSet is the summary row of a review set approved in one
	// act; each tool of it has its own ToolApprove row.
	ToolApproveSet = "(tool approve set)"
	// UpstreamUpdate is `upstream update` replacing an entry's image in
	// place, keeping the quarantine.
	UpstreamUpdate = "(upstream update)"
)

// config reads the configuration for one operation.
func (s *Service) config() (*config.Config, error) {
	cfg, err := s.d.Config()
	if err != nil {
		var ae *adminapi.Error
		if errors.As(err, &ae) {
			return nil, ae
		}
		return nil, adminapi.NewError(adminapi.CodeConfigUnavailable, "the configuration file does not load: %v", err).
			With("problem", "does_not_load")
	}
	return cfg, nil
}

// retryBusy runs fn again when it fails because another writer held the
// database's write lock for the whole busy_timeout (design/adr/0031 §5).
// A busy error means nothing was written, so a retry cannot duplicate a
// row. It stops at ctx's deadline.
func (s *Service) retryBusy(ctx context.Context, fn func() error) error {
	backoff := 100 * time.Millisecond
	var err error
	for attempt := 0; attempt < busyAttempts; attempt++ {
		if err = fn(); err == nil || !s.d.IsBusy(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return err
}

// busyAttempts bounds retryBusy: with busy_timeout at five seconds, four
// attempts wait at most about twenty-one seconds.
const busyAttempts = 4

// storeErr maps a store failure onto the contract.
func (s *Service) storeErr(what string, err error) error {
	switch {
	case err == nil:
		return nil
	case s.d.IsBusy(err):
		return adminapi.NewError(adminapi.CodeStoreBusy, "%s: the database stayed locked through every retry; nothing was written", what)
	case errors.Is(err, quarantine.ErrInvalidStatus):
		return adminapi.NewError(adminapi.CodeCorruptState, "%s: a stored row has an unrecognised status; refusing to touch it", what)
	}
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae
	}
	return adminapi.NewError(adminapi.CodeInternal, "%s: %v", what, err)
}

// record writes the operator row of a change that already took effect and
// fills res: recorded with the row, or not recorded with the warning. It
// never turns the change into an error (design/adr/0040 §3).
func (s *Service) record(ctx context.Context, cfg *config.Config, res *adminapi.ActionResult, rec audit.Record) {
	err := s.retryBusy(ctx, func() error { return s.d.Record(ctx, cfg, rec) })
	if err != nil {
		res.Recorded = false
		res.Audit = nil
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnAuditWriteFailed,
			Message: "The change is in force and the audit trail has no row for it: " + err.Error()})
		res.Messages = append(res.Messages, "The change was made, but the audit trail could not record it. Record it by hand before anything else.")
		s.d.Log.Warn("admin: operator row not recorded", "tool", rec.Tool, "operator", rec.AnalystIdentity, "detail", err.Error())
		return
	}
	res.Recorded = true
	res.Audit = &adminapi.OperatorRow{Identity: rec.AnalystIdentity, Tool: rec.Tool, Reason: rec.Reason, Timestamp: rec.Timestamp}
	res.Messages = append(res.Messages, fmt.Sprintf("Recorded in the audit trail as %s by %s.", rec.Tool, rec.AnalystIdentity))
}

// operatorRow builds the row of one action.
func (s *Service) operatorRow(a Actor, tool, reason string, at time.Time) audit.Record {
	return audit.Record{AnalystIdentity: a.Identity(), Tool: tool, TargetUpstream: OperatorTarget,
		Timestamp: at, Outcome: audit.OutcomeAllowed, Reason: reason}
}

// checkActor refuses an action nobody can be held to.
func checkActor(a Actor) error {
	if a.Name == "" || strings.ContainsAny(a.Name, " \t\r\n()") {
		return adminapi.NewError(adminapi.CodePeerUnattributable, "the operator has no usable account name")
	}
	return nil
}

func newResult() adminapi.ActionResult { return adminapi.ActionResult{Messages: []string{}} }

// need reports an operation this backend was built without the store for.
func need(ok bool, what string) error {
	if ok {
		return nil
	}
	return adminapi.NewError(adminapi.CodeInternal, "this backend has no %s", what)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
