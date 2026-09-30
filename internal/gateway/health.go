package gateway

// Backend health and planned maintenance (design/adr/0041).
//
// A backend is an entry of the registry that passed every gate of the most
// recent round -- Validate, quota coverage, signature -- which is what
// Connect calls `ready` and Reconcile `want`, kept here as `servable`. Under
// each servable backend there is one fact of life, kept in memory: whether
// there is an open connection to it not found dead (`live`), since when,
// the last dial tried and, for the operator only, why it is not live. Over
// it the public state is derived at the moment it is asked for:
// maintenance, else up, else down when its cause is held_back (no dial is
// scheduled), else reconnecting. The management backend derives the same
// state from the same persisted cause, so the two never disagree.
//
// Nothing in this file reads an upstream's error text. Every field of the
// errors below is the gateway's own state -- a name, a state, instants, an
// operator's message -- so the serving adapter can put them in front of a
// model without deciding what may leak (ADR-0041 items 2 and 3).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// GatteStatusTool is the client-facing name of the tool the gateway serves
// itself. Its namespace is registry.ReservedName, which no upstream may
// register, so no route of the table can ever carry it.
const GatteStatusTool = "gatte.status"

// backendHealthTool is the Tool of the gateway's rows about a backend's
// life (ADR-0041 item 7). A declared interface string, like the reasons.
const backendHealthTool = "(backend health)"

// Reasons of design/adr/0041. The first three are refusals of a call the
// gateway answered without dialing; the rest are the gateway's own rows
// about a backend, written only on a transition.
const (
	reasonBackendReconnecting = "backend unavailable: reconnecting"
	reasonBackendDown         = "backend unavailable: down"
	reasonBackendMaintenance  = "backend in maintenance"
	reasonBackendUpFirst      = "backend up: first observed"
	// reasonBackendDownPrefix is followed by ": " and the cause.
	reasonBackendDownPrefix = "backend down"
	// reasonBackendUpPrefix is followed by " " and an RFC 3339 instant.
	reasonBackendUpPrefix = "backend up: down since"
	reasonBackendRemoved  = "backend removed: no longer servable per the registry"
)

// BackendState is the public state of a backend.
type BackendState string

const (
	StateUp           BackendState = "up"
	StateReconnecting BackendState = "reconnecting"
	StateDown         BackendState = "down"
	StateMaintenance  BackendState = "maintenance"
)

// MaintenanceNotice is the part of a maintenance row an analyst may see
// (ADR-0041 item 6): exactly the message, the start (as "since"), the
// announced end and whether it has passed. Who set it and when it last
// changed are not here, so no path can carry them to a caller.
type MaintenanceNotice struct {
	Message     string
	Since       time.Time
	Until       time.Time
	UntilPassed bool
}

func noticeOf(m health.Maintenance, now time.Time) *MaintenanceNotice {
	return &MaintenanceNotice{Message: m.Message, Since: m.StartedAt, Until: m.Until, UntilPassed: m.UntilPassed(now)}
}

var (
	// ErrBackendUnavailable is what an UnavailableError answered without
	// dialing unwraps to.
	ErrBackendUnavailable = errors.New("gateway: backend unavailable")
	// ErrBackendFailed is what a BackendFailedError for a backend's own
	// error unwraps to. Its text is never the backend's.
	ErrBackendFailed = errors.New("gateway: backend failed the call")
)

// UnavailableError is a granted, approved call the gateway answered with
// the state of its backend: down, reconnecting, in maintenance, or found
// dead during this very call.
type UnavailableError struct {
	Backend string
	State   BackendState
	// Since is when the backend stopped being live, or the maintenance's
	// start.
	Since time.Time
	// LastAttempt is the last dial tried, zero when none was.
	LastAttempt time.Time
	// NextAttempt is roughly when the next round dials it, zero when none
	// is scheduled (down) or not known.
	NextAttempt time.Time
	// Maintenance is set for StateMaintenance.
	Maintenance *MaintenanceNotice
	// Gateway is the whole gateway's maintenance, when there is one.
	Gateway *MaintenanceNotice
	// cause is a sentinel -- ErrBackendUnavailable or ErrUpstreamGone --
	// and never an upstream's error, which may carry its text.
	cause error
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("gateway: backend %q is %s", e.Backend, e.State)
}

func (e *UnavailableError) Unwrap() error { return e.cause }

// BackendFailedError is a call a live backend failed: it answered with an
// error, or not within the call's deadline. Only the backend's name is
// kept; the gateway does not forward why.
type BackendFailedError struct {
	Backend string
	Gateway *MaintenanceNotice
	// cause is ErrBackendFailed or context.DeadlineExceeded.
	cause error
}

func (e *BackendFailedError) Error() string {
	return fmt.Sprintf("gateway: backend %q failed the call", e.Backend)
}

func (e *BackendFailedError) Unwrap() error { return e.cause }

// BackendStatus is one backend as gatte.status reports it.
type BackendStatus struct {
	Name        string
	State       BackendState
	Since       time.Time
	LastAttempt time.Time
	NextAttempt time.Time
	Maintenance *MaintenanceNotice
}

// StatusReport is gatte.status's answer.
type StatusReport struct {
	CheckedAt time.Time
	// Gateway is the whole gateway's maintenance, nil when none.
	Gateway  *MaintenanceNotice
	Backends []BackendStatus
	// You is the caller's own standing (design/adr/0042 item 3).
	You CallerStanding
}

// backendHealth is the fact of life under one servable backend.
type backendHealth struct {
	live        bool
	since       time.Time
	lastAttempt time.Time
	cause       health.Cause
}

// healthEvent is one row to write about a transition.
type healthEvent struct {
	backend string
	outcome audit.Outcome
	reason  string
}

// observeLive records whether name is live, under g.mu, and returns the
// row the transition earns, if any. attempted says a dial was tried now.
func (g *Gateway) observeLive(name string, live bool, cause health.Cause, attempted bool, now time.Time) *healthEvent {
	b, seen := g.health[name]
	var ev *healthEvent
	switch {
	case !seen:
		b = &backendHealth{live: live, since: now}
		g.health[name] = b
		if live {
			ev = &healthEvent{backend: name, outcome: audit.OutcomeAllowed, reason: reasonBackendUpFirst}
		} else {
			ev = &healthEvent{backend: name, outcome: audit.OutcomeDenied, reason: reasonBackendDownPrefix + ": " + string(cause)}
		}
	case b.live != live && live:
		ev = &healthEvent{backend: name, outcome: audit.OutcomeAllowed, reason: reasonBackendUpPrefix + " " + b.since.UTC().Format(time.RFC3339)}
		b.live, b.since = true, now
	case b.live != live:
		ev = &healthEvent{backend: name, outcome: audit.OutcomeDenied, reason: reasonBackendDownPrefix + ": " + string(cause)}
		// The dial that brought it up is not a reconnect attempt: from here
		// on, lastAttempt is the last try at bringing it BACK.
		b.live, b.since, b.lastAttempt = false, now, time.Time{}
	}
	if live {
		b.cause = ""
	} else if cause != "" {
		b.cause = cause
	}
	if attempted {
		b.lastAttempt = now
	}
	return ev
}

// forgetHealth drops a backend that left servable, under g.mu, and returns
// its row.
func (g *Gateway) forgetHealth(name string) *healthEvent {
	if _, ok := g.health[name]; !ok {
		return nil
	}
	delete(g.health, name)
	return &healthEvent{backend: name, outcome: audit.OutcomeDenied, reason: reasonBackendRemoved}
}

// writeHealthEvents puts the transition rows on the trail, attributed to
// the gateway. Called with no lock held.
func (g *Gateway) writeHealthEvents(ctx context.Context, events []*healthEvent) {
	for _, ev := range events {
		if ev == nil {
			continue
		}
		if ev.outcome == audit.OutcomeDenied {
			g.log.WarnContext(ctx, "gateway: backend is not live", slog.String("upstream", ev.backend), slog.String("reason", ev.reason))
		} else {
			g.log.InfoContext(ctx, "gateway: backend is live", slog.String("upstream", ev.backend), slog.String("reason", ev.reason))
		}
		g.auditGatewayRow(ctx, backendHealthTool, ev.backend, ev.outcome, ev.reason)
	}
}

// settleHealth records, for every name the round considers servable,
// whether it is live now, and drops the names that left. It returns the
// rows to write. frozen is the quota freeze (held_back); dialed is what
// this round tried to dial.
func (g *Gateway) settleHealth(servable []string, keep func(string) bool, frozen bool, dialed map[string]bool, now time.Time) []*healthEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	var events []*healthEvent
	next := make(map[string]bool, len(servable))
	for _, name := range servable {
		next[name] = true
		up, connected := g.conns[name]
		alive := connected && g.gone[name] != up
		// A connection no Refresh has listed takes no call, so it is not
		// live either: it becomes live when markListed says so.
		live := alive && g.unlisted[name] != up
		cause := health.Cause("")
		switch {
		case live:
		case alive:
			cause = health.CauseNotListed
		case frozen:
			cause = health.CauseHeldBack
		case dialed[name]:
			cause = health.CauseNotBroughtUp
		default:
			cause = health.CauseNotBroughtUp
			if b, ok := g.health[name]; ok && b.cause != "" {
				cause = b.cause
			}
		}
		events = append(events, g.observeLive(name, live, cause, dialed[name], now))
	}
	for _, name := range slices.Sorted(maps.Keys(g.health)) {
		if !next[name] && (keep == nil || !keep(name)) {
			events = append(events, g.forgetHealth(name))
		}
	}
	for name := range g.health {
		next[name] = true
	}
	g.servable = next
	g.heldBack = frozen
	return events
}

// publicState derives what a caller is told about name. Called under
// g.mu (read).
func (g *Gateway) publicState(name string, maint map[string]health.Maintenance, now time.Time) (BackendStatus, bool) {
	b, ok := g.health[name]
	if !ok {
		return BackendStatus{}, false
	}
	st := BackendStatus{Name: name, Since: b.since, LastAttempt: b.lastAttempt}
	if !b.live && b.cause != health.CauseHeldBack {
		st.NextAttempt = g.nextAttempt()
	}
	switch m, inMaint := maint[name]; {
	case inMaint:
		st.State, st.Since, st.Maintenance = StateMaintenance, m.StartedAt, noticeOf(m, now)
		if b.live {
			st.NextAttempt = time.Time{}
		}
	case b.live:
		st.State = StateUp
	case b.cause == health.CauseHeldBack:
		st.State = StateDown
	default:
		st.State = StateReconnecting
	}
	return st, true
}

// nextAttempt is the start of the last round plus the round interval,
// "around" because the loop rests the interval after its work. Zero when
// either is unknown. Called under g.mu.
func (g *Gateway) nextAttempt() time.Time {
	if g.lastRound.IsZero() || g.roundInterval <= 0 {
		return time.Time{}
	}
	return g.lastRound.Add(g.roundInterval)
}

// readMaintenance reads the maintenance table, keyed by target. Fail-open
// (ADR-0041 item 6): an unreadable table is logged and served as if it
// were empty, and ok reports which it was.
func (g *Gateway) readMaintenance(ctx context.Context) (rows map[string]health.Maintenance, ok bool) {
	if g.maint == nil {
		return nil, true
	}
	list, err := g.maint.Maintenance(ctx)
	if err != nil {
		if ctx.Err() == nil {
			g.log.ErrorContext(ctx, "gateway: the maintenance table could not be read; serving as if nothing were in maintenance",
				slog.String("detail", err.Error()))
		}
		return nil, false
	}
	rows = make(map[string]health.Maintenance, len(list))
	for _, m := range list {
		rows[m.Target] = m
	}
	return rows, true
}

// gatewayNotice is the whole gateway's maintenance in maint, or nil.
func gatewayNotice(maint map[string]health.Maintenance, now time.Time) *MaintenanceNotice {
	if m, ok := maint[health.GatewayTarget]; ok {
		return noticeOf(m, now)
	}
	return nil
}

// availability is Dispatch's step 4: the answer for a granted, approved
// call whose backend cannot take it, or nil when it can.
func (g *Gateway) availability(name string, up Upstream, maint map[string]health.Maintenance, now time.Time) *UnavailableError {
	g.mu.RLock()
	defer g.mu.RUnlock()
	gw := gatewayNotice(maint, now)
	if m, ok := maint[name]; ok {
		st, _ := g.publicState(name, maint, now)
		return &UnavailableError{Backend: name, State: StateMaintenance, Since: m.StartedAt, LastAttempt: st.LastAttempt,
			NextAttempt: st.NextAttempt, Maintenance: noticeOf(m, now), Gateway: gw, cause: ErrBackendUnavailable}
	}
	if up != nil && g.gone[name] != up && g.unlisted[name] != up {
		return nil
	}
	st, ok := g.publicState(name, maint, now)
	if !ok || st.State == StateUp {
		// Found dead a moment ago and not yet settled by a round.
		st = BackendStatus{Name: name, State: StateReconnecting, Since: now, NextAttempt: g.nextAttempt()}
		if b, known := g.health[name]; known {
			st.LastAttempt = b.lastAttempt
			if !b.live {
				st.Since = b.since
			}
		}
	}
	return &UnavailableError{Backend: name, State: st.State, Since: st.Since, LastAttempt: st.LastAttempt,
		NextAttempt: st.NextAttempt, Gateway: gw, cause: ErrBackendUnavailable}
}

// markListed records that up, the connection for name, has been listed
// and observed, so the routes built from that listing may reach it. That
// is the moment a re-dialled backend is up again, and not the dial: the
// transition row is returned for Refresh to write once the table that
// routes to it is installed.
func (g *Gateway) markListed(name string, up Upstream) *healthEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	if up == nil || g.unlisted[name] != up {
		return nil
	}
	delete(g.unlisted, name)
	if _, known := g.health[name]; !known || g.gone[name] == up {
		return nil
	}
	return g.observeLive(name, true, "", false, g.now())
}

// reasonFor is the audit reason of a step-4 refusal.
func (e *UnavailableError) reason() string {
	switch e.State {
	case StateMaintenance:
		return reasonBackendMaintenance
	case StateDown:
		return reasonBackendDown
	default:
		return reasonBackendReconnecting
	}
}

// GatteStatus is the built-in gatte.status (ADR-0041 item 5): the state of
// each backend in backends -- which the serving adapter fills with the
// backends of the tools it actually registered for this caller, and
// nothing else -- plus the whole gateway's maintenance. It writes exactly
// one allowed row, aimed at the gateway, and refuses a blocked subject the
// way every other path does.
//
// tools is the set of tool names the adapter registered for this caller;
// the "you" block names only the budgets those tools spend
// (design/adr/0042 item 3).
func (g *Gateway) GatteStatus(ctx context.Context, c Caller, backends, tools []string) (StatusReport, error) {
	if err := g.checkBlock(ctx, c.Identity.Subject); err != nil {
		g.refuseBlocked(ctx, c, GatteStatusTool, gatewayItself, err)
		return StatusReport{}, err
	}
	maint, _ := g.readMaintenance(ctx)
	now := g.now()
	rep := StatusReport{CheckedAt: now, Gateway: gatewayNotice(maint, now), Backends: []BackendStatus{}}
	names := slices.Clone(backends)
	slices.Sort(names)
	names = slices.Compact(names)
	g.mu.RLock()
	for _, name := range names {
		if st, ok := g.publicState(name, maint, now); ok {
			rep.Backends = append(rep.Backends, st)
		}
	}
	g.mu.RUnlock()
	rep.You = g.standingOf(ctx, c, tools, now)

	writeCtx, cancel := auditWriteCtx(ctx)
	defer cancel()
	if err := g.record(writeCtx, c, GatteStatusTool, gatewayItself, audit.OutcomeAllowed, ""); err != nil {
		g.log.ErrorContext(ctx, "gateway: refusing unauditable gatte.status", slog.String("detail", err.Error()))
		return StatusReport{}, err
	}
	return rep, nil
}

// MaintenanceCounts is the heartbeat's view of maintenance: how many
// backends have a row, and whether the gateway does ("on", "off"), or -1
// and "unknown" when the table could not be read.
func (g *Gateway) MaintenanceCounts(ctx context.Context) (backends int, gateway string) {
	maint, ok := g.readMaintenance(ctx)
	if !ok {
		return -1, "unknown"
	}
	gateway = "off"
	for target := range maint {
		if target == health.GatewayTarget {
			gateway = "on"
			continue
		}
		backends++
	}
	return backends, gateway
}

// ------------------------------------------------------------ the listing

// recordListing replaces name's last live listing with what routes it
// earned this round, and marks it to be written.
func (g *Gateway) recordListing(name string, routes map[string]routedTool) {
	listed := make([]health.ListedTool, 0, len(routes))
	for _, rt := range routes {
		listed = append(listed, health.ListedTool{Tool: rt.route.originalName, Hash: quarantine.Hash(identityOf(rt.def))})
	}
	slices.SortFunc(listed, func(a, b health.ListedTool) int {
		switch {
		case a.Tool < b.Tool:
			return -1
		case a.Tool > b.Tool:
			return 1
		}
		return 0
	})
	g.mu.Lock()
	g.listing[name] = listed
	g.dirtyListing[name] = true
	g.mu.Unlock()
}

// loadListings reads the persisted listings once per process, for a boot
// with a backend down. Called under refreshMu.
func (g *Gateway) loadListings(ctx context.Context) {
	if g.listingLoaded || g.state == nil {
		return
	}
	stored, err := g.state.Listings(ctx)
	if err != nil {
		g.log.ErrorContext(ctx, "gateway: the last live listings could not be read; a backend down at boot lists nothing until it comes back",
			slog.String("detail", err.Error()))
		return
	}
	g.listingLoaded = true
	g.mu.Lock()
	defer g.mu.Unlock()
	for name, listed := range stored {
		if _, have := g.listing[name]; !have {
			g.listing[name] = listed
		}
	}
}

// stableRoutesFor is the stable listing of a servable backend that is not
// live (ADR-0041 item 4): the tools of its last live listing whose
// approval is still in force at the same fingerprint, served from the
// definition the quarantine kept for that fingerprint, re-checked by the
// same rules routesFor applies. Nothing is observed. unmeasured reports a
// quarantine that could not be read, so the caller keeps what it had.
func (g *Gateway) stableRoutesFor(ctx context.Context, upstream string) upstreamRoutes {
	out := upstreamRoutes{routes: map[string]routedTool{}}
	g.mu.RLock()
	listed := slices.Clone(g.listing[upstream])
	g.mu.RUnlock()
	for _, lt := range listed {
		t, err := g.quarantine.Get(ctx, upstream, lt.Tool)
		switch {
		case errors.Is(err, quarantine.ErrNotFound):
			continue
		case err != nil:
			out.unmeasured = true
			continue
		}
		if !t.Usable() || t.ApprovedHash != lt.Hash {
			continue
		}
		id, err := g.quarantine.Definition(ctx, lt.Hash)
		switch {
		case errors.Is(err, quarantine.ErrDefinitionNotKept):
			g.log.WarnContext(ctx, "gateway: an approved tool of a backend that is down is not listed: its approval predates kept definitions",
				slog.String("upstream", upstream), slog.String("tool", lt.Tool))
			continue
		case errors.Is(err, quarantine.ErrDefinitionMismatch):
			continue
		case err != nil:
			out.unmeasured = true
			continue
		}
		def := ToolDef{Name: id.Name, Description: id.Description, InputSchema: id.InputSchema, OutputSchema: id.OutputSchema}
		if def.Name != lt.Tool || !validToolName(def.Name) || definitionSize(def) > maxToolDefinitionBytes || validateSchema(def.InputSchema) != nil {
			continue
		}
		output, err := resolveOutputSchema(def.OutputSchema)
		if err != nil {
			continue
		}
		out.routes[Namespaced(upstream, def.Name)] = routedTool{route: route{upstream: upstream, originalName: def.Name}, def: def, output: output}
	}
	return out
}

// ------------------------------------------------------------ persistence

// persistHealth writes what this process observed, for the management
// backend and for the next boot (ADR-0041 item 7). round says a round just
// completed. A failure is logged and changes nothing served.
func (g *Gateway) persistHealth(ctx context.Context, round bool) {
	if g.state == nil {
		return
	}
	now := g.now()
	g.mu.RLock()
	snap := health.Snapshot{ListedAt: now, Listings: map[string][]health.ListedTool{}}
	for _, name := range slices.Sorted(maps.Keys(g.health)) {
		b := g.health[name]
		rec := health.BackendRecord{Backend: name, Live: b.live, Since: b.since, LastAttempt: b.lastAttempt, Cause: b.cause, UpdatedAt: now}
		if !b.live && b.cause != health.CauseHeldBack {
			rec.NextAttempt = g.nextAttempt()
		}
		snap.Backends = append(snap.Backends, rec)
	}
	for name := range g.dirtyListing {
		snap.Listings[name] = slices.Clone(g.listing[name])
	}
	if round && g.roundInterval > 0 {
		snap.Serve = &health.ServeStatus{Boot: g.boot, LastRoundAt: now, RoundInterval: g.roundInterval}
	}
	g.mu.RUnlock()

	writeCtx, cancel := auditWriteCtx(ctx)
	defer cancel()
	if err := g.state.WriteState(writeCtx, snap); err != nil {
		g.log.ErrorContext(ctx, "gateway: the backend health could not be written; the consoles show the previous state",
			slog.String("detail", err.Error()))
		return
	}
	g.mu.Lock()
	for name := range snap.Listings {
		delete(g.dirtyListing, name)
	}
	g.mu.Unlock()
}

// standingOf is the caller's own block of gatte.status: their display
// name, the names of their roles, and the budgets their served tools
// spend with their own use of each (design/adr/0042 item 3).
//
// The quota is asked about c.Identity.Subject and nothing else -- the
// verified subject of this very request -- and a fitness function pins
// that argument, because this is the one counter read on the request
// path. A read failure reports each budget's use as unknown (-1) and is
// logged; gatte.status still answers.
func (g *Gateway) standingOf(ctx context.Context, c Caller, tools []string, now time.Time) CallerStanding {
	you := CallerStanding{Name: c.Identity.Name, Roles: []string{}}
	for _, r := range g.policy.Load().RolesFor(c.Identity) {
		you.Roles = append(you.Roles, r.Name)
	}
	slices.Sort(you.Roles)
	you.Roles = slices.Compact(you.Roles)
	budgets, err := g.quota.Load().Standing(ctx, c.Identity.Subject, tools, now)
	if err != nil {
		g.log.WarnContext(ctx, "gateway: gatte.status could not read the caller's own quota use; reporting it as unknown",
			slog.String("detail", err.Error()))
	}
	you.Budgets = budgets
	return you
}
