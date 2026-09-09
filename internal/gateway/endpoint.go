package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// Additional sentinel errors, alongside the ones in gateway.go.
var (
	// ErrClosed means the Gateway has been closed and will not connect or
	// serve anything again. A closed Gateway is terminal: build a new one.
	ErrClosed = errors.New("gateway: closed")

	// ErrUpstreamUnavailable means one registered backend could not be
	// brought up -- its credentials would not resolve, it would not dial,
	// or it would not list its tools.
	//
	// It is deliberately partial, and that is the difference from
	// ErrRegistryUnavailable: one broken backend must not take the whole
	// gateway down, so Connect keeps going and serves the upstreams that
	// did come up. A caller tells the two apart with errors.Is --
	// ErrRegistryUnavailable means nothing at all is served, whereas
	// ErrUpstreamUnavailable means some of the fleet is missing and the
	// rest is live.
	ErrUpstreamUnavailable = errors.New("gateway: upstream unavailable")

	// ErrQuarantineUnavailable means Tool Quarantine could not be consulted.
	// The gateway refuses the call rather than guessing, for the same
	// fail-closed reason ADR-0004 gives for the registry: a routing or
	// admission decision made without the state that governs it is exactly
	// the decision an attacker wants us to make.
	ErrQuarantineUnavailable = errors.New("gateway: quarantine unavailable")
)

// unknownUpstream is the TargetUpstream recorded in the audit trail for a
// call whose tool name does not even parse into upstream + tool, so there
// is no backend to name. audit.Record.Validate requires a non-empty
// TargetUpstream and a probe of a garbage name is precisely the event a
// SOC wants recorded, so the record is written with this placeholder
// rather than dropped. It is shaped so it cannot be mistaken for a
// registered name at a glance.
const unknownUpstream = "(unknown)"

// unnamedTool is the Tool recorded for an attempt that supplied no tool
// name at all. Like unknownUpstream it exists so audit.Record.Validate --
// which requires a non-empty Tool -- cannot turn a malformed probe into a
// dropped record. A client that POSTs a tools/call with an empty name is
// doing something no legitimate client does, which makes it more worth
// recording than less.
const unnamedTool = "(unnamed)"

// reasonNotVisible is the audit Reason for a call naming a tool that was
// never put on the caller's own MCP surface. See RecordRefusedProbe.
//
// It is deliberately distinct from Dispatch's "unknown tool" and
// "forbidden": those are answers about the fleet and about the policy,
// reached with a route in hand, whereas this one is only ever "whatever
// the caller asked for, they were not offered it". An operator triaging
// probing behaviour needs to tell the two apart -- one denial per
// reachable-but-refused tool is routine, a burst of these is somebody
// walking the name space.
const reasonNotVisible = "not visible to caller"

// redacted replaces a resolved credential value wherever one is found in
// text that is about to leave this package.
const redacted = "[redacted]"

// Config carries the ports a Gateway orchestrates. Every field except Now
// and Logger is required: the Gateway holds no infrastructure of its own
// and cannot substitute a default for a missing port.
type Config struct {
	// Registry is the Upstream Registry to read the backend fleet from.
	Registry registry.Repository
	// Vault is the Credential Vault used to resolve each upstream's
	// environment immediately before dialing it.
	Vault vault.Provider
	// Quarantine is the Tool Quarantine consulted -- through
	// quarantine.Tool.Usable, never through Status -- at both list and
	// dispatch time.
	Quarantine quarantine.Store
	// Audit is the Audit Trail every dispatch attempt is written to.
	Audit audit.Recorder
	// Policy decides which namespaced tools an identity may see and call.
	Policy *access.Policy
	// Dialer opens a connection to one backend.
	Dialer Dialer

	// Now supplies the timestamp for audit records and quarantine
	// observations. Optional; defaults to time.Now. Injected rather than
	// called directly so tests need no clock dependency, matching how
	// audit.Record takes its timestamp from the caller.
	Now func() time.Time

	// Logger receives the operational detail the returned errors
	// deliberately withhold -- in particular whether a refused dispatch was
	// refused because the tool does not exist or because Tool Quarantine
	// has not approved it. Optional; defaults to slog.Default().
	//
	// Nothing written here ever contains a resolved credential value.
	Logger *slog.Logger
}

// Gateway is the Gateway Endpoint: one MCP surface in front of every
// registered upstream.
//
// It owns the routing table and the live upstream connections and nothing
// else; every other capability it needs arrives as a port through Config.
// A Gateway is safe for concurrent use: Connect and Close mutate the
// routing table under a write lock, ListTools and Dispatch read it under a
// read lock and then talk to the upstream with the lock released, so a
// slow backend call never blocks a refresh or another analyst's listing.
type Gateway struct {
	registry   registry.Repository
	vault      vault.Provider
	quarantine quarantine.Store
	audit      audit.Recorder
	policy     *access.Policy
	dialer     Dialer
	now        func() time.Time
	log        *slog.Logger

	mu     sync.RWMutex
	conns  map[string]Upstream
	routes map[string]routedTool
	closed bool
}

// routedTool is one row of the routing table: where a namespaced tool goes
// and what the upstream said about it at discovery time.
//
// The definition is kept so ListTools can re-advertise the tool without a
// round trip to the backend. It is *not* kept as a quarantine decision:
// whether the tool may be listed or called is re-read from the Store at
// every list and every dispatch, so a tool that flips to changed stops
// being served immediately rather than at the next refresh.
type routedTool struct {
	route route
	def   ToolDef
}

// New returns a Gateway wired to the ports in cfg. It returns an error if
// any required port is nil -- a missing port is a wiring bug at startup,
// and the alternative (a nil-checking request path) would mean discovering
// it during an incident.
func New(cfg Config) (*Gateway, error) {
	var missing []string
	if cfg.Registry == nil {
		missing = append(missing, "Registry")
	}
	if cfg.Vault == nil {
		missing = append(missing, "Vault")
	}
	if cfg.Quarantine == nil {
		missing = append(missing, "Quarantine")
	}
	if cfg.Audit == nil {
		missing = append(missing, "Audit")
	}
	if cfg.Policy == nil {
		missing = append(missing, "Policy")
	}
	if cfg.Dialer == nil {
		missing = append(missing, "Dialer")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("gateway: missing required port(s): %s", strings.Join(missing, ", "))
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Gateway{
		registry:   cfg.Registry,
		vault:      cfg.Vault,
		quarantine: cfg.Quarantine,
		audit:      cfg.Audit,
		policy:     cfg.Policy,
		dialer:     cfg.Dialer,
		now:        now,
		log:        logger,
		conns:      map[string]Upstream{},
		routes:     map[string]routedTool{},
	}, nil
}

// Connect reads the Upstream Registry, brings up every registered backend
// and rebuilds the routing table from what they advertise. It is also the
// refresh path: calling it again re-reads the registry, re-dials, and
// replaces the previous table and connections wholesale.
//
// For each upstream, in order: the credentials named by the registry entry
// are resolved through the Credential Vault, the backend is dialed with
// those values, its tools are listed, and every tool is handed to
// quarantine.Store.Observe. Observing is what makes a newly-appeared tool
// land in pending and a silently-rewritten one land in changed, so a tool
// the gateway has never routed before is never served on the strength of
// having been discovered.
//
// # Failure modes
//
// Reading the registry is all-or-nothing and fails closed, per ADR-0004:
// on failure Connect drops the routing table, closes every connection it
// held, serves nothing, and returns an error wrapping
// ErrRegistryUnavailable. It never falls back to the table it had before
// -- a stale table is how a tool revoked during the outage keeps getting
// served, which is precisely what the ADR rejects.
//
// A failure affecting one upstream -- unresolvable credentials, a dial
// that fails, a backend that will not list its tools -- is recorded and
// skipped, and the remaining upstreams are still brought up. Connect then
// returns a joined error in which every element wraps
// ErrUpstreamUnavailable. That error means "part of the fleet is missing,"
// not "nothing works": the table has been rebuilt and is serving. One
// broken backend taking the whole SOC's gateway offline would be a
// self-inflicted outage, and the failure is loud in both the error and the
// log.
func (g *Gateway) Connect(ctx context.Context) error {
	if g.isClosed() {
		return ErrClosed
	}

	entries, err := g.registry.List(ctx)
	if err != nil {
		// Fail closed, and do it before anything else: whatever the old
		// table said, we can no longer confirm it is current.
		g.swap(nil, nil)
		g.log.ErrorContext(ctx, "gateway: registry unreadable, serving nothing", slog.String("detail", err.Error()))
		return fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	}

	conns := make(map[string]Upstream, len(entries))
	routes := make(map[string]routedTool)
	collisions := map[string]bool{}
	var failures []error

	for _, entry := range entries {
		up, err := g.bringUp(ctx, entry)
		if err != nil {
			failures = append(failures, err)
			g.log.ErrorContext(ctx, "gateway: upstream not brought up",
				slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
			continue
		}

		defs, err := up.ListTools(ctx)
		if err != nil {
			// The connection is useless without a tool list, and leaving it
			// open would leak a subprocess.
			_ = up.Close()
			failures = append(failures, fmt.Errorf("%w: %q: list tools: %w", ErrUpstreamUnavailable, entry.Name, err))
			continue
		}
		conns[entry.Name] = up

		for _, def := range defs {
			if err := validateSchema(def.InputSchema); err != nil {
				// Refused at discovery, deliberately, rather than guarded at
				// each serving surface. mcp.Server.AddTool *panics* on a
				// schema that is nil or not a JSON object of type "object",
				// and InputSchema is upstream-controlled -- so a backend
				// advertising one malformed tool could crash the gateway
				// process, which ADR-0001 already accepts as a single point
				// of failure for every analyst's tooling. A remotely
				// triggerable panic in that position is not acceptable.
				//
				// Refusing here means no surface, present or future, has to
				// remember to guard. Not routed, and not substituted with a
				// permissive default either: `{"type":"object"}` in place of
				// whatever the upstream actually sent would advertise a
				// contract Tool Quarantine never approved.
				failures = append(failures, fmt.Errorf("%w: %q: tool %q has an unusable input schema: %w", ErrUpstreamUnavailable, entry.Name, def.Name, err))
				continue
			}
			if _, err := g.quarantine.Observe(ctx, entry.Name, identityOf(def)); err != nil {
				// A tool whose quarantine state could not be recorded is a
				// tool whose approval we cannot check later. Do not route it.
				failures = append(failures, fmt.Errorf("%w: %q: observe tool %q: %w", ErrUpstreamUnavailable, entry.Name, def.Name, err))
				continue
			}

			name := Namespaced(entry.Name, def.Name)
			if _, dup := routes[name]; dup {
				// Namespacing normally makes collisions impossible, but it
				// cannot rule out every case: an upstream named "a" with a
				// tool named "b.c" produces the same client-facing name as an
				// upstream named "a.b" with a tool named "c", and a
				// misbehaving backend can advertise the same tool twice.
				// Serving *either* candidate would mean a call landing on a
				// backend nobody can predict from the name -- the exact harm
				// namespacing exists to prevent -- so neither is served.
				collisions[name] = true
				failures = append(failures, fmt.Errorf("%w: %q: tool %q collides with an already-routed name; neither is served", ErrUpstreamUnavailable, entry.Name, name))
				continue
			}
			routes[name] = routedTool{
				route: route{upstream: entry.Name, originalName: def.Name},
				def:   def,
			}
		}
	}
	for name := range collisions {
		delete(routes, name)
	}

	if closedDuringConnect := g.swap(conns, routes); closedDuringConnect {
		return ErrClosed
	}
	return errors.Join(failures...)
}

// bringUp resolves one entry's credentials and dials it.
//
// Resolution happens here, one step before the dial and nowhere else, so
// that every line of code that can see a plaintext credential fits on one
// screen. The resolved map is handed to the Dialer and then cleared: this
// package keeps no reference to it, writes none of it to a log, and puts
// none of it in an error (see redact).
func (g *Gateway) bringUp(ctx context.Context, entry registry.UpstreamServer) (Upstream, error) {
	env, err := g.resolveEnv(ctx, entry)
	if err != nil {
		return nil, err
	}
	defer func() { clear(env) }()

	up, err := g.dialer.Dial(ctx, specFor(entry), env)
	if err != nil {
		// redact, even though Dialer's contract already forbids a value in
		// an error: this is the boundary where a buggy adapter's mistake
		// would become a logged secret, and the check costs one pass over
		// a short string.
		return nil, fmt.Errorf("%w: %q: dial: %w", ErrUpstreamUnavailable, entry.Name, redact(err, env))
	}
	return up, nil
}

// resolveEnv resolves every credential the entry names into the
// environment map the Dialer receives.
//
// Only the variable *name* ever reaches an error message. The name is not
// a secret -- the registry stores it in plaintext precisely because it is
// not one (registry.UpstreamServer, EnvVarNames) -- while the value is
// never returned, logged, or wrapped.
func (g *Gateway) resolveEnv(ctx context.Context, entry registry.UpstreamServer) (map[string]string, error) {
	env := make(map[string]string, len(entry.EnvVarNames))
	for _, name := range entry.EnvVarNames {
		secret, err := g.vault.Resolve(ctx, name)
		if err != nil {
			wrapped := fmt.Errorf("%w: %q: resolve credential %q: %w", ErrUpstreamUnavailable, entry.Name, name, redact(err, env))
			// Nothing resolved so far may outlive this failure.
			clear(env)
			return nil, wrapped
		}
		env[name] = secret.Value()
	}
	return env, nil
}

// ListTools returns the tools id may use, under their namespaced names.
//
// A tool appears only if it passes *both* gates: the access Policy allows
// this identity to call that namespaced name, and Tool Quarantine reports
// the tool Usable. The gates are the same two, consulted in the same
// order, as Dispatch's -- that is what makes the list and the call path
// agree. A tool in this list is dispatchable; a tool missing from it is
// not.
//
// The returned ToolDef carries the namespaced Name (what the client calls)
// with the Description and InputSchema exactly as the upstream advertised
// them -- unaltered, since those bytes are what the quarantine
// fingerprinted (ADR-0007).
//
// Quarantine being unreadable fails the whole call with
// ErrQuarantineUnavailable rather than quietly returning a short list: an
// empty tool list and a broken approval store must not look the same to an
// operator.
func (g *Gateway) ListTools(ctx context.Context, id access.Identity) ([]ToolDef, error) {
	routes := g.snapshot()

	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	slices.Sort(names)

	out := make([]ToolDef, 0, len(names))
	for _, name := range names {
		rt := routes[name]
		if err := g.policy.Authorize(id, name); err != nil {
			continue
		}
		switch err := g.admit(ctx, rt.route); {
		case err == nil:
			out = append(out, ToolDef{
				Name:        name,
				Description: rt.def.Description,
				// Cloned, not shared. InputSchema is a json.RawMessage --
				// a slice -- so handing out rt.def.InputSchema directly
				// would let a caller mutate the routing table's advertised
				// schema in place, and that schema is the one Tool
				// Quarantine fingerprinted and an operator approved.
				//
				// Same defect class as the access.Policy aliasing bug this
				// project already caught by test; fixed here for the same
				// reason and to keep one standard rather than two.
				InputSchema: slices.Clone(rt.def.InputSchema),
			})
		case errors.Is(err, ErrToolQuarantined):
			continue
		default:
			return nil, err
		}
	}
	return out, nil
}

// Dispatch forwards one call to the backend that serves namespacedTool and
// returns its result.
//
// # The decision sequence
//
// The order below is a security property, not an implementation detail:
//
//  1. Resolve the namespaced name to a route. An unknown name never
//     reaches any other component.
//  2. Authorize the identity for that name. This runs before the
//     quarantine check so that a caller with no business calling a tool
//     cannot learn its approval state by calling it -- authorization is a
//     fact about the caller and is answered first.
//  3. Re-check Tool Quarantine, at call time. Checking only at list time
//     would leave a window: a client lists tools, an upstream rewrites a
//     description, the quarantine flips the tool to changed, and the
//     client's call -- issued against a list that was true a second ago --
//     would still land. quarantine.Tool.Usable is the single gate here and
//     in ListTools (ADR-0007 rule 3).
//  4. Write the audit record.
//  5. Forward to the upstream.
//
// # Why the audit record is written before the call, and on refusals too
//
// The record goes in immediately before step 5 because step 5 is the only
// step that leaves this process. Steps 1-3 are in-memory decisions that
// cannot hang; a call in flight to a backend can hang, be cancelled, or
// die with the process. Recording afterwards would mean the attempts most
// worth investigating -- the ones that never returned -- are the ones with
// no record. Writing first can over-record (a record for a call whose
// result never came back); that is a reconcilable annoyance, whereas
// under-recording is an action nobody can see. If the record cannot be
// written the call is not made: an unauditable call is refused, since the
// gateway's reason to exist is that every analyst action against
// production leaves a trace.
//
// Refusals are recorded too, on every path, exactly once per Dispatch. A
// call a SOC gateway turned down is a signal -- a probe, a stale client, a
// revoked analyst, a rug-pulled tool -- and a trail holding only the
// successful calls describes only the uninteresting half of the traffic. A
// failure to record a *refusal* does not change the refusal: the caller
// gets the denial it earned, and the audit failure goes to the log.
//
// # What the caller is told
//
// An unknown tool and a quarantined tool both return ErrUnknownTool. The
// two stay distinct inside the gateway -- the quarantine path carries
// ErrToolQuarantined and the log records which happened -- but they are
// indistinguishable at the boundary, on the same reasoning
// internal/access/oidc applies to token rejection: a caller able to tell
// "no such tool" from "that tool exists but is not approved" has an oracle
// for mapping the fleet's tools and, worse, for reading the SOC's current
// security posture, tool by tool, from outside.
//
// An unauthorized call is the deliberate exception: it returns the
// Policy's own error, wrapping access.ErrForbidden. Collapsing that into
// ErrUnknownTool would break the distinction access.Policy exists to draw
// (CONCEPTS.md §3.3) and would tell an analyst who simply lacks a role
// that the tool does not exist, sending them to debug the wrong thing. The
// residual leak is accepted and bounded: the tool names in a Role are an
// operator-authored list of names, not secrets, whereas which tool is
// currently under suspicion is -- and that is the fact the opaque error
// protects.
func (g *Gateway) Dispatch(ctx context.Context, id access.Identity, namespacedTool string, args json.RawMessage) (Result, error) {
	rt, up, found := g.lookup(namespacedTool)
	if !found {
		g.auditRefusal(ctx, id, namespacedTool, targetOf(namespacedTool), "unknown tool")
		return Result{}, ErrUnknownTool
	}

	if err := g.policy.Authorize(id, namespacedTool); err != nil {
		g.auditRefusal(ctx, id, namespacedTool, rt.route.upstream, "forbidden")
		return Result{}, err
	}

	if err := g.admit(ctx, rt.route); err != nil {
		if errors.Is(err, ErrToolQuarantined) {
			g.auditRefusal(ctx, id, namespacedTool, rt.route.upstream, "quarantined")
			// Internally distinct (err is ErrToolQuarantined and the log says
			// so); opaque on the way out. See the doc comment.
			return Result{}, ErrUnknownTool
		}
		g.auditRefusal(ctx, id, namespacedTool, rt.route.upstream, "quarantine unavailable")
		return Result{}, err
	}

	if err := g.record(ctx, id, namespacedTool, rt.route.upstream, audit.OutcomeAllowed, ""); err != nil {
		g.log.ErrorContext(ctx, "gateway: refusing unauditable call",
			slog.String("tool", namespacedTool), slog.String("detail", err.Error()))
		return Result{}, err
	}

	res, err := up.CallTool(ctx, rt.route.originalName, args)
	if err != nil {
		return Result{}, fmt.Errorf("gateway: call %q: %w", namespacedTool, err)
	}
	return res, nil
}

// RecordRefusedProbe writes the audit record for a call that named a tool
// the caller's serving surface never offered, and which therefore never
// reached Dispatch.
//
// # Why this exists
//
// A serving adapter may -- and internal/gateway/httpapi does -- expose
// only the tools ListTools returned for one identity, so that a caller
// cannot enumerate what they may not use. That filtering is correct and is
// not changed by anything here. Its side effect is that a call naming
// anything else is refused by the adapter's own protocol machinery before
// Dispatch runs, and Dispatch is where every other refusal is written to
// the trail. Composed with no third thing, the two correct features leave
// a caller free to probe tool names and leave no record at all -- which,
// for a SOC, is precisely the event worth keeping.
//
// This method is that third thing, and it lives here rather than in the
// adapter so that every audit record this system writes is still written
// by one component. An adapter that grows its own audit.Recorder is an
// adapter free to drift from Dispatch's attribution, ordering and
// reasons.
//
// # What it does and does not do
//
// It records and nothing else. It makes no admission decision, reads no
// route, and returns nothing: the caller has already refused the call, and
// the refusal must not change shape because of what happened here. A
// record that cannot be written is loud in the log and leaves the
// refusal alone, exactly as auditRefusal does for Dispatch -- see its
// comment.
//
// namespacedTool is recorded as the caller wrote it, unresolved. The name
// may be a real tool belonging to another role, a tool this caller's own
// role holds but Tool Quarantine has not approved, or a pure fabrication
// that matches nothing in the fleet; all three are recorded the same way
// and under the same Reason. That is deliberate. Resolving which of the
// three it was would mean a routing-table lookup on behalf of a caller who
// was refused before any lookup happened, and the answer would be the
// oracle Dispatch's opaque error exists to deny. The trail records who
// asked for what and that they were turned away; an operator with the
// routing table in front of them can classify it afterwards.
func (g *Gateway) RecordRefusedProbe(ctx context.Context, id access.Identity, namespacedTool string) {
	tool := namespacedTool
	if strings.TrimSpace(tool) == "" {
		tool = unnamedTool
	}
	g.auditRefusal(ctx, id, tool, targetOf(tool), reasonNotVisible)
}

// Close shuts every dialed upstream down and empties the routing table.
//
// It is idempotent: the second and later calls do nothing and return nil.
// Every upstream is closed even if some of them fail to close, and the
// failures come back joined -- stopping at the first error would leak the
// subprocesses behind the rest.
//
// A closed Gateway is terminal. Connect returns ErrClosed and Dispatch
// finds an empty table, so nothing is served after shutdown begins.
func (g *Gateway) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	conns := g.conns
	g.conns = map[string]Upstream{}
	g.routes = map[string]routedTool{}
	g.mu.Unlock()

	return closeAll(conns)
}

// admit reports whether Tool Quarantine allows r to be listed and called.
//
// It returns nil when the tool is usable, ErrToolQuarantined when the
// quarantine has not approved this exact definition, and an error wrapping
// ErrQuarantineUnavailable when the state could not be read at all. Both
// ListTools and Dispatch go through this one function, so "is this tool
// allowed" has exactly one implementation and the two sites cannot drift
// apart -- the property quarantine.Tool.Usable's doc comment and ADR-0007
// rule 3 require.
//
// A route with no quarantine entry is treated as not approved rather than
// as an error: it means discovery and the store have diverged, and the
// fail-closed reading of "no record of approval" is "not approved."
func (g *Gateway) admit(ctx context.Context, r route) error {
	t, err := g.quarantine.Get(ctx, r.upstream, r.originalName)
	if err != nil {
		if errors.Is(err, quarantine.ErrNotFound) {
			return fmt.Errorf("%w: %s: no quarantine entry", ErrToolQuarantined, r)
		}
		return fmt.Errorf("%w: %s: %w", ErrQuarantineUnavailable, r, err)
	}
	if !t.Usable() {
		return fmt.Errorf("%w: %s", ErrToolQuarantined, r)
	}
	return nil
}

// record writes one audit record for an attempted call and returns any
// failure to the caller, which refuses the call on it.
func (g *Gateway) record(ctx context.Context, id access.Identity, tool, upstream string, outcome audit.Outcome, reason string) error {
	rec := audit.Record{
		// Subject, not Name: the IdP's stable identifier is what the trail
		// attributes to, since a display name can change under it.
		AnalystIdentity: id.Subject,
		Tool:            tool,
		TargetUpstream:  upstream,
		Timestamp:       g.now(),
		Outcome:         outcome,
		// The reason is recorded even though the caller is never told it.
		// That asymmetry is the point: an operator reading the trail needs
		// to know *why* a call was blocked, while a caller who could tell
		// "no such tool" from "not approved" would have an oracle for
		// mapping the fleet and reading the SOC's current posture.
		Reason: reason,
	}
	if err := g.audit.Record(ctx, rec); err != nil {
		return fmt.Errorf("gateway: audit record for %q: %w", tool, err)
	}
	return nil
}

// auditRefusal records a refused attempt and logs the reason the caller is
// not told.
//
// The refusal stands whether or not the record could be written -- turning
// a denial into a different error because the audit store hiccuped would
// hand the caller a signal and change a "no" into a "maybe". The failure
// is loud in the log instead.
func (g *Gateway) auditRefusal(ctx context.Context, id access.Identity, tool, upstream, reason string) {
	g.log.WarnContext(ctx, "gateway: refused dispatch",
		slog.String("subject", id.Subject),
		slog.String("tool", tool),
		slog.String("upstream", upstream),
		slog.String("reason", reason),
	)
	if err := g.record(ctx, id, tool, upstream, audit.OutcomeDenied, reason); err != nil {
		g.log.ErrorContext(ctx, "gateway: refused dispatch was not audited",
			slog.String("tool", tool), slog.String("detail", err.Error()))
	}
}

// lookup returns the route for a namespaced name and the live connection
// serving it, both read under one lock so they cannot come from different
// generations of the routing table.
func (g *Gateway) lookup(name string) (routedTool, Upstream, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	rt, ok := g.routes[name]
	if !ok {
		return routedTool{}, nil, false
	}
	up, ok := g.conns[rt.route.upstream]
	if !ok {
		return routedTool{}, nil, false
	}
	return rt, up, true
}

// snapshot copies the routing table so a listing can iterate it without
// holding the lock across the quarantine reads it makes.
func (g *Gateway) snapshot() map[string]routedTool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make(map[string]routedTool, len(g.routes))
	for name, rt := range g.routes {
		out[name] = rt
	}
	return out
}

// swap installs a freshly built table and closes the connections it
// replaces. It reports whether the Gateway was closed while the table was
// being built, in which case the new connections are closed instead of
// installed -- otherwise a Close racing a Connect would leak every
// subprocess Connect had just spawned.
func (g *Gateway) swap(conns map[string]Upstream, routes map[string]routedTool) (closedDuringConnect bool) {
	if conns == nil {
		conns = map[string]Upstream{}
	}
	if routes == nil {
		routes = map[string]routedTool{}
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = closeAll(conns)
		return true
	}
	old := g.conns
	g.conns = conns
	g.routes = routes
	g.mu.Unlock()

	if err := closeAll(old); err != nil {
		g.log.Warn("gateway: closing replaced upstreams", slog.String("detail", err.Error()))
	}
	return false
}

func (g *Gateway) isClosed() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.closed
}

// closeAll closes every upstream and joins the failures, so one stubborn
// backend cannot keep the others' processes alive.
func closeAll(conns map[string]Upstream) error {
	names := make([]string, 0, len(conns))
	for name := range conns {
		names = append(names, name)
	}
	slices.Sort(names)

	var errs []error
	for _, name := range names {
		if err := conns[name].Close(); err != nil {
			errs = append(errs, fmt.Errorf("gateway: close upstream %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// identityOf projects a discovered tool onto what Tool Quarantine
// fingerprints.
//
// The schema bytes are handed on exactly as the Dialer's adapter produced
// them: this package adds no re-marshalling and no canonicalization of its
// own (ADR-0007 rule 2, as amended -- the guarantee is "no normalization
// of ours", since the MCP SDK has already decoded and re-encoded the
// schema by the time an adapter can see it).
func identityOf(def ToolDef) quarantine.ToolIdentity {
	return quarantine.ToolIdentity{
		Name:        def.Name,
		Description: def.Description,
		InputSchema: def.InputSchema,
	}
}

// specFor narrows a registry entry to what a Dialer is allowed to see. It
// drops the timestamps and, deliberately, EnvVarNames: the Dialer receives
// resolved values and has no business knowing what else the entry names.
func specFor(entry registry.UpstreamServer) UpstreamSpec {
	return UpstreamSpec{
		Name:      entry.Name,
		Transport: string(entry.Transport),
		Command:   entry.Command,
		Args:      slices.Clone(entry.Args),
		URL:       entry.URL,
	}
}

// targetOf names the upstream an unroutable call was aimed at, for the
// audit record. A name that does not split has no upstream to name.
func targetOf(namespacedTool string) string {
	if upstream, _, ok := SplitNamespaced(namespacedTool); ok {
		return upstream
	}
	return unknownUpstream
}

// redact returns err with every resolved credential value in env replaced
// by a placeholder, preserving the error chain so errors.Is still works on
// the cause.
//
// The Dialer and Provider contracts both already forbid a value in an
// error. This is the belt to those braces, applied at the one boundary
// where such a mistake would be turned into a returned error and a log
// line by this package.
func redact(err error, env map[string]string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, value := range env {
		if value == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, value, redacted)
	}
	if msg == err.Error() {
		return err
	}
	return redactedError{msg: msg, cause: err}
}

// redactedError carries a scrubbed message over an unscrubbed cause: the
// text is safe to print, and errors.Is/As still see through to the
// original.
type redactedError struct {
	msg   string
	cause error
}

func (e redactedError) Error() string { return e.msg }
func (e redactedError) Unwrap() error { return e.cause }

// ErrUnusableSchema means an upstream advertised a tool whose input
// schema the gateway cannot serve.
var ErrUnusableSchema = errors.New("gateway: unusable input schema")

// validateSchema reports whether raw is an input schema this gateway can
// safely advertise.
//
// The bar is set by what mcp.Server.AddTool will accept without panicking:
// a non-nil JSON object whose "type" is "object". Anything else -- absent,
// null, a bare array, a string, or an object typed as something other than
// "object" -- is refused at discovery rather than allowed to reach a
// serving surface.
//
// This is a validation of shape only. It deliberately does not attempt to
// judge whether the schema is *good*, and it does not rewrite it: the
// bytes an upstream sent are the bytes Tool Quarantine fingerprinted, and
// normalizing them here would move the hash out from under an operator's
// approval.
func validateSchema(raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: absent", ErrUnusableSchema)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("%w: not a JSON object", ErrUnusableSchema)
	}
	if probe == nil {
		return fmt.Errorf("%w: null", ErrUnusableSchema)
	}
	typ, ok := probe["type"]
	if !ok {
		return fmt.Errorf("%w: no \"type\"", ErrUnusableSchema)
	}
	if typ != "object" {
		return fmt.Errorf("%w: type is %v, want \"object\"", ErrUnusableSchema, typ)
	}
	return nil
}
