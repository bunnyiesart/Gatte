package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/bunnyiesart/Gatte/internal/signer"
	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/google/jsonschema-go/jsonschema"
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

// The placeholders and Reason for a request refused at authentication.
// See RecordAuthFailure.
const (
	// unauthenticatedIdentity is the AnalystIdentity of a request that
	// never authenticated. audit.Record.Validate requires a non-empty
	// identity and there is, by definition, no verified one -- so it gets
	// a marker, shaped like unknownUpstream and unnamedTool so that it
	// cannot be read as an IdP `sub`. No IdP this project will ever talk
	// to issues a subject in parentheses, and an operator scanning the
	// ANALYST column sees at a glance that this row attributes to nobody.
	//
	// Never a plausible-looking placeholder, and never the empty string:
	// a row that quietly borrows an identity is worse evidence than no
	// row, and a row that fails Validate is no row.
	unauthenticatedIdentity = "(unauthenticated)"

	// authenticationTool and gatewayItself fill Tool and TargetUpstream,
	// which Validate also requires. A request refused at the front door
	// named no tool -- it was refused before anything read its body -- and
	// was aimed at this gateway, not at any backend. Saying so is more
	// honest than reusing unnamedTool, which means "a tools/call arrived
	// with an empty name": that is a different event.
	authenticationTool = "(authentication)"
	gatewayItself      = "(gateway)"

	// reasonAuthFailed is the ONLY reason an authentication failure is
	// ever recorded with, and the uniformity is the point.
	//
	// internal/access/oidc collapses eight distinct rejection causes --
	// no signature, wrong issuer, wrong audience, expired, not yet valid,
	// unknown key, malformed, IdP unreachable -- into one error, so that a
	// caller cannot use the gateway as an oracle for which of them it hit.
	// That is correct, and its consequence is that this layer genuinely
	// does not know either. Recording "authentication failed" is the whole
	// of what can be said honestly; a trail that appeared to know more
	// would be inventing it.
	//
	// The value of the record is not the cause. It is that the attempt
	// existed, when it was, and where it came from.
	reasonAuthFailed = "authentication failed"
)

// Reasons for a call that was dispatched and then did not come back.
//
// They are a small closed set drawn from the context package's own
// sentinels, deliberately: Reason is operator-facing evidence, and an
// upstream's error text is attacker-adjacent data this gateway is not
// going to copy into it. The detail goes to the log, where it belongs.
const (
	// reasonUpstreamTimeout means the backend never answered. For an
	// analyst this is the difference between "my query is wrong" and "the
	// SIEM is down", and it is the case design/adr/0012 opens with.
	reasonUpstreamTimeout = "upstream timed out"
	// reasonCallCancelled means the caller (or the process) went away
	// before the backend answered. Not the backend's fault, and an
	// operator counting backend incidents needs it separated out.
	reasonCallCancelled = "call cancelled"
	// reasonUpstreamFailed is everything else: the backend answered with
	// an error, the transport broke, the subprocess died.
	reasonUpstreamFailed = "upstream call failed"
)

// Reasons for a call the gateway refused before it left the process.
//
// These four were bare string literals at their call sites until the audit
// trail acquired a second reader. That was survivable while the only
// consumer was a human reading `mcp-gateway audit`, who forgives a
// reworded phrase. It stops being survivable the moment a SIEM query or an
// alert matches on the value: rewording one of these then breaks a
// detection somewhere else, silently, and the person who reworded it has
// no way to know. A constant makes the string a declared interface rather
// than an incidental one.
const (
	// reasonUnknownTool means no route matched the namespaced name. It is
	// deliberately indistinguishable, to the CALLER, from a quarantined
	// tool (ADR-0007 rule 3) -- but the operator reading the trail needs
	// the two separated, which is what Reason is for.
	reasonUnknownTool = "unknown tool"
	// reasonForbidden means the caller is known and their roles do not
	// reach this tool.
	reasonForbidden = "forbidden"
	// reasonQuarantined means the tool exists and is not approved, or was
	// approved and has since changed.
	reasonQuarantined = "quarantined"
	// reasonQuarantineUnavailable means the approval store could not be
	// read, so the gateway refused rather than guessing. An empty tool
	// list and a broken approval store must not look alike.
	reasonQuarantineUnavailable = "quarantine unavailable"
)

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

	// Signatures, when non-nil, is consulted at Connect time to verify
	// each registry entry against its Ed25519 signature
	// (design/adr/0003, design/adr/0006). An entry whose stored signature
	// does not match what the registry now says is **never** served: an
	// invalid signature is positive evidence that the command, args or
	// env var names an upstream is spawned with were changed by something
	// other than the signer, and there is no benign reading of that.
	//
	// Optional only in the sense that a Gateway without it still runs --
	// but then nothing checks entry integrity at all, which is the state
	// this project shipped in until GAB-18.
	Signatures signer.Store

	// Verifier holds the trusted public keys a stored signature is checked
	// against (design/adr/0010-signature-trust-anchor.md). Required
	// whenever Signatures is set: a signature store without a trust anchor
	// verifies signatures against the key that arrived with them, which is
	// the flaw ADR-0010 exists to remove, so New refuses the combination
	// rather than letting it be assembled.
	Verifier *signer.Verifier

	// RequireSigned makes an entry with *no* signature unusable too.
	//
	// The asymmetry with an invalid signature is deliberate and is
	// ADR-0006's declared debt: while nothing produces signatures at
	// volume, refusing unsigned entries would make the gateway unusable
	// before the Operator Console exists, with no security gained --
	// there would simply be no signed entries to serve. The ADR is
	// explicit that this default must invert once signing is ergonomic.
	//
	// It may not be set without Signatures. See New.
	RequireSigned bool

	// MaxResultBytes is the ceiling on the size of one tool result.
	// Optional; zero or negative selects DefaultMaxResultBytes.
	MaxResultBytes int64

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
	signatures signer.Store
	verifier   *signer.Verifier
	requireSig bool
	// maxResultBytes is always positive: New resolves an unset or
	// nonsensical value to DefaultMaxResultBytes, so there is no way to
	// hold a Gateway that enforces no ceiling at all.
	maxResultBytes int64
	now            func() time.Time
	log            *slog.Logger

	// refreshMu serializes Connect against Refresh. It is not the same lock
	// as mu, and it guards a different thing: mu protects the table for the
	// microseconds a read or a swap takes, while this one holds for the
	// whole of a discovery -- dialing every backend, or asking every
	// connected one for its tool list. Without it, a ticker's Refresh could
	// compute a table from the connections a concurrent Connect is in the
	// middle of replacing, and install it over the newer one.
	refreshMu sync.Mutex

	// credKey keys the digests in creds. It is 32 random bytes generated
	// once per process and never persisted, and that is deliberate: a
	// plain hash of a credential is still derived from the credential, and
	// a low-entropy one is recoverable from a dictionary if a digest ever
	// reaches a core dump or a log. Keyed with a value that dies with the
	// process, a digest is inert everywhere except inside this Gateway --
	// which is the only place that needs to compare two of them.
	credKey []byte

	mu    sync.RWMutex
	conns map[string]Upstream
	// creds records, per connected upstream, a keyed digest of each
	// credential value that was handed to it at dial time -- keyed by the
	// variable NAME, which is not a secret (the registry stores it in
	// plaintext for exactly that reason).
	//
	// It exists because the value itself must not be kept. The Credential
	// Vault's contract is that plaintext exists only in passing
	// (see bringUp, which clears the map it built), so "is the connected
	// upstream still using what the vault holds now?" cannot be answered
	// by comparing values -- only by comparing something derived from them
	// that is safe to keep. See CredentialDrift.
	creds  map[string]map[string]string
	routes map[string]routedTool
	closed bool
}

// upstreamRoutes is what one upstream's advertised tool list earned it: the
// routes it should contribute to the table, whatever it did wrong, and
// whether its tools could be measured at all.
type upstreamRoutes struct {
	// routes are keyed by client-facing (namespaced) name.
	routes map[string]routedTool
	// failures are per-tool problems, each wrapping ErrUpstreamUnavailable.
	failures []error
	// unmeasured reports that at least one of this upstream's tools could
	// not be handed to Tool Quarantine -- the store was unreadable, not the
	// tool unacceptable.
	//
	// The distinction is the whole of ADR-0013's failure rule. "The
	// quarantine said no" is a measurement; "the quarantine could not be
	// asked" is the absence of one, and the two must not produce the same
	// outcome. Connect ignores this flag (at boot there is no earlier
	// measurement to fall back to, so fail-closed is the only honest
	// reading); Refresh acts on it, keeping the previous observation rather
	// than treating an unreadable store as evidence that the fleet changed.
	unmeasured bool
}

// routedTool is one row of the routing table: where a namespaced tool goes
// and what the upstream said about it at discovery time.
//
// The definition is kept so ListTools can re-advertise the tool without a
// round trip to the backend. It is *not* kept as a quarantine decision:
// whether the tool may be listed or called is re-read from the Store at
// every list and every dispatch.
//
// Be precise about what that buys, because this comment used to claim more
// than the code delivered (ADR-0013). Re-reading per call means a state
// change already recorded in the store takes effect on the very next call
// -- `tool approve` and `tool revoke` need no restart and no refresh. It
// does NOT mean the gateway notices an upstream rewriting a tool under it:
// that requires re-running `tools/list` and re-Observing, which is
// Refresh's job and happens on a ticker. Between two ticks, a tool poisoned
// upstream is still served under its old approval. See Refresh.
type routedTool struct {
	route route
	def   ToolDef
	// output is def.OutputSchema compiled, or nil when the tool declares
	// none -- which is every tool in this fleet today (design/adr/0014).
	// Compiled once here rather than per call: see resolveOutputSchema.
	output *jsonschema.Resolved
}

// New returns a Gateway wired to the ports in cfg. It returns an error if
// any required port is nil -- a missing port is a wiring bug at startup,
// and the alternative (a nil-checking request path) would mean discovering
// it during an incident.
//
// It also refuses two combinations that are individually well-formed and
// together mean "the security control is off but the configuration says it
// is on" (design/adr/0010 item 3):
//
//   - RequireSigned with no Signatures store. verifyEntry has nothing to
//     read, so every entry would sail through unchecked while the operator
//     believes unsigned entries are being refused. Unreachable from cmd
//     today; refused anyway, because a control that can be silently
//     disabled by a wiring mistake is the exact failure this project keeps
//     writing ADRs about.
//   - Signatures with no Verifier. Verification would have no trust
//     anchor, which is the ADR-0010 flaw.
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

	if cfg.RequireSigned && cfg.Signatures == nil {
		return nil, errors.New(
			"gateway: RequireSigned is set but no Signatures store was wired: " +
				"there would be nothing to read a signature from, so every entry would be served unchecked " +
				"while the configuration claims unsigned entries are refused",
		)
	}
	if cfg.Signatures != nil && cfg.Verifier == nil {
		return nil, errors.New(
			"gateway: a Signatures store was wired without a Verifier: " +
				"a signature can only be checked against keys trusted in advance (design/adr/0010-signature-trust-anchor.md), " +
				"and the key stored alongside the signature is not one of those",
		)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// A missing, zero or negative ceiling becomes the default rather than
	// "no ceiling". The limit is the one control in design/adr/0014 that
	// has an effect on today's fleet, and a control a wiring mistake can
	// switch off is the failure this project keeps writing ADRs about --
	// so it is not switchable off from here at all. An operator who finds
	// the default too tight raises the number in the file, where a
	// reviewer can see it.
	maxResultBytes := cfg.MaxResultBytes
	if maxResultBytes <= 0 {
		maxResultBytes = DefaultMaxResultBytes
	}

	// The key for the credential digests (see the credKey field). Read
	// from crypto/rand and never stored: a failure here is fatal to
	// construction rather than silently downgraded to an unkeyed hash,
	// because "the digest turned out to be reversible" is not a thing to
	// discover later.
	credKey := make([]byte, 32)
	if _, err := rand.Read(credKey); err != nil {
		return nil, fmt.Errorf("gateway: generating the credential-digest key: %w", err)
	}

	return &Gateway{
		credKey:        credKey,
		creds:          map[string]map[string]string{},
		registry:       cfg.Registry,
		vault:          cfg.Vault,
		quarantine:     cfg.Quarantine,
		audit:          cfg.Audit,
		policy:         cfg.Policy,
		dialer:         cfg.Dialer,
		signatures:     cfg.Signatures,
		verifier:       cfg.Verifier,
		requireSig:     cfg.RequireSigned,
		maxResultBytes: maxResultBytes,
		now:            now,
		log:            logger,
		conns:          map[string]Upstream{},
		routes:         map[string]routedTool{},
	}, nil
}

// Connect reads the Upstream Registry, brings up every registered backend
// and rebuilds the routing table from what they advertise. Calling it again
// re-reads the registry, re-dials, and replaces the previous table and
// connections wholesale -- which is how a registry change is picked up, and
// is also why it is not what runs on a ticker: it tears down every live
// connection, cutting in-flight calls and respawning every subprocess.
// Periodic re-observation of the backends already connected is Refresh.
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
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()

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
	candidates := map[string]map[string]routedTool{}
	var failures []error

	// Once per Connect, not once per entry: a per-entry warning in a fleet
	// of twenty is a wall of text nobody reads, and these are precisely the
	// conditions that should stay legible.
	switch {
	case len(entries) == 0:
	case g.signatures == nil:
		g.log.WarnContext(ctx, "gateway: no signature store configured -- registry entry integrity is NOT being checked",
			slog.Int("upstreams", len(entries)))
	case g.verifier.TrustedCount() == 0:
		// Reachable only with require_signed = false, since Config.Validate
		// refuses the other combination. Worth saying out loud anyway: in
		// this state a *signed* entry is refused (nothing vouches for the
		// key that signed it) while an unsigned one is served, which reads
		// backwards until you know why.
		g.log.WarnContext(ctx, "gateway: signer.trusted_keys is empty -- no signature can be accepted, so any signed entry will be refused as invalid",
			slog.Int("upstreams", len(entries)))
	}

	for _, entry := range entries {
		if err := g.verifyEntry(ctx, entry); err != nil {
			failures = append(failures, err)
			g.log.ErrorContext(ctx, "gateway: upstream refused by signature check",
				slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
			continue
		}

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

		// unmeasured is deliberately ignored here. At boot there is no
		// earlier observation to fall back on, so a tool the quarantine
		// could not be asked about is a tool whose approval cannot be
		// checked later -- and the fail-closed reading of that is "do not
		// route it", which is what routesFor already did. Refresh, which
		// does have an earlier measurement, reads the flag instead.
		got := g.routesFor(ctx, entry.Name, defs)
		candidates[entry.Name] = got.routes
		failures = append(failures, got.failures...)
	}

	routes, conflicts := mergeRoutes(candidates)
	failures = append(failures, conflicts...)

	if closedDuringConnect := g.swap(conns, routes); closedDuringConnect {
		return ErrClosed
	}
	return errors.Join(failures...)
}

// Refresh re-asks every *already-connected* upstream what tools it
// advertises, hands each answer to Tool Quarantine, and rebuilds the
// routing table from the result. It is what makes rug-pull detection fire
// on a running gateway.
//
// # Why this exists at all
//
// Until ADR-0013 it did not, and the gap emptied half of what Tool
// Quarantine is for. quarantine.Store.Observe -- the only thing that
// advances ObservedHash -- was reachable from exactly one place (Connect),
// and Connect ran exactly once, at startup. There was no ticker, no SIGHUP,
// and the MCP client is built with nil options so `notifications/
// tools/list_changed` is ignored. A backend that rewrote a tool's
// description at 09:00 kept being served that description until somebody
// restarted the process, which in a SOC gateway can be weeks. The component
// built to catch tool poisoning (OWASP MCP03) could not fire while the
// gateway was doing its job.
//
// # The window this does NOT close
//
// **Between two refreshes there is a window in which a poisoned tool is
// still served.** Refresh shortens that window to the configured interval;
// it does not remove it, and nothing here can. Making it smaller means
// lowering the interval and paying one `tools/list` per upstream more
// often. That is an explicit trade, not a bug, and it is the first thing to
// say to anyone asking why a tool was served for four minutes after it
// changed.
//
// What is *not* subject to that window, and is worth not confusing with it:
// an operator's own decisions. admit re-reads quarantine.Tool.Usable on
// every list and every dispatch, so `tool approve` and `tool revoke` land
// on the very next call with no refresh involved.
//
// # Why a ticker and not the notification
//
// `notifications/tools/list_changed` is cheaper and nearly instant, and it
// depends entirely on the upstream choosing to send it. A compromised
// backend simply does not -- and a compromised backend is the entire
// scenario this component exists for. The notification, if it is ever
// implemented, is an optimisation layered on top of this loop and never a
// replacement for it (ADR-0013). Written down here so that nobody
// "simplifies" the ticker away later by swapping one for the other.
//
// # What it deliberately does not do
//
// Refresh does not read the registry, does not dial, and does not close
// anything. An upstream registered since the last Connect is invisible to
// it, one deregistered since then keeps being served, and a backend whose
// process died is not respawned -- all of that is Connect's job, and doing
// it on a ticker would tear down every live connection (killing in-flight
// analyst calls and respawning every subprocess) at every interval.
//
// # Failure
//
// An upstream that cannot be listed, or whose tools cannot be handed to the
// quarantine, keeps the routes and the observation it already had. Failing
// to measure is not evidence that something changed (ADR-0004's reasoning,
// applied to observation), and conflating the two would turn one bad
// network minute into a fleet-wide quarantine -- an outage manufactured by
// the control that exists to prevent them. The failure is loud in the log
// and comes back as an error wrapping ErrUpstreamUnavailable, and every
// upstream that did answer is refreshed regardless.
func (g *Gateway) Refresh(ctx context.Context) error {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()

	if g.isClosed() {
		return ErrClosed
	}

	conns, previous := g.tableSnapshot()
	names := make([]string, 0, len(conns))
	for name := range conns {
		names = append(names, name)
	}
	slices.Sort(names)

	candidates := map[string]map[string]routedTool{}
	var failures []error

	for _, name := range names {
		defs, err := conns[name].ListTools(ctx)
		if err != nil {
			failures = append(failures, fmt.Errorf("%w: %q: list tools: %w", ErrUpstreamUnavailable, name, err))
			g.log.ErrorContext(ctx, "gateway: upstream could not be re-observed; keeping its previous tool list and quarantine state",
				slog.String("upstream", name), slog.String("detail", err.Error()))
			candidates[name] = routesOf(previous, name)
			continue
		}

		got := g.routesFor(ctx, name, defs)
		failures = append(failures, got.failures...)
		if got.unmeasured {
			// The quarantine store, not the backend, is what failed. Nothing
			// about this upstream can be judged right now, so nothing about
			// it changes: a store that is briefly unreadable must not be able
			// to unroute the fleet. The next tick tries again.
			g.log.ErrorContext(ctx, "gateway: tool quarantine could not be consulted during refresh; keeping this upstream's previous tool list",
				slog.String("upstream", name))
			candidates[name] = routesOf(previous, name)
			continue
		}
		candidates[name] = got.routes
	}

	routes, conflicts := mergeRoutes(candidates)
	failures = append(failures, conflicts...)

	if closedDuringRefresh := g.swapRoutes(routes); closedDuringRefresh {
		return ErrClosed
	}
	return errors.Join(failures...)
}

// routesFor observes every tool an upstream advertises and returns the
// routes they earn.
//
// Observing is what makes a newly-appeared tool land in pending and a
// silently-rewritten one land in changed, so no tool is ever served on the
// strength of having been discovered. Nothing here decides whether a tool
// is *usable* -- that is read from the store per call, in admit.
func (g *Gateway) routesFor(ctx context.Context, upstream string, defs []ToolDef) upstreamRoutes {
	out := upstreamRoutes{routes: make(map[string]routedTool, len(defs))}
	// A backend advertising the same tool twice: neither copy is served,
	// for the same reason a cross-upstream collision is not.
	dupes := map[string]bool{}

	for _, def := range defs {
		if err := validateSchema(def.InputSchema); err != nil {
			// Refused at discovery, deliberately, rather than guarded at
			// each serving surface. mcp.Server.AddTool *panics* on a schema
			// that is nil or not a JSON object of type "object", and
			// InputSchema is upstream-controlled -- so a backend advertising
			// one malformed tool could crash the gateway process, which
			// ADR-0001 already accepts as a single point of failure for
			// every analyst's tooling. A remotely triggerable panic in that
			// position is not acceptable.
			//
			// Refusing here means no surface, present or future, has to
			// remember to guard. Not routed, and not substituted with a
			// permissive default either: `{"type":"object"}` in place of
			// whatever the upstream actually sent would advertise a contract
			// Tool Quarantine never approved.
			//
			// Note this is a *measurement*, not a failure to measure: the
			// upstream answered and what it said is unusable. It therefore
			// does not set unmeasured, and a refresh acts on it.
			out.failures = append(out.failures, fmt.Errorf("%w: %q: tool %q has an unusable input schema: %w", ErrUpstreamUnavailable, upstream, def.Name, err))
			continue
		}
		// Same reasoning one field over: a declared output contract that
		// will not compile can never be checked against, so the tool is
		// refused here rather than at whatever hour an analyst first calls
		// it. Also a measurement and not a failure to measure, so a refresh
		// acts on it.
		output, err := resolveOutputSchema(def.OutputSchema)
		if err != nil {
			out.failures = append(out.failures, fmt.Errorf("%w: %q: tool %q has an unusable output schema: %w", ErrUpstreamUnavailable, upstream, def.Name, err))
			continue
		}
		if _, err := g.quarantine.Observe(ctx, upstream, identityOf(def)); err != nil {
			// A tool whose quarantine state could not be recorded is a tool
			// whose approval we cannot check later. Do not route it -- and
			// say that the failure was ours, not the backend's, so a refresh
			// can tell "this changed" from "this could not be read".
			out.failures = append(out.failures, fmt.Errorf("%w: %q: observe tool %q: %w", ErrUpstreamUnavailable, upstream, def.Name, err))
			out.unmeasured = true
			continue
		}

		name := Namespaced(upstream, def.Name)
		if _, dup := out.routes[name]; dup {
			dupes[name] = true
			out.failures = append(out.failures, fmt.Errorf("%w: %q: tool %q is advertised more than once; neither copy is served", ErrUpstreamUnavailable, upstream, name))
			continue
		}
		out.routes[name] = routedTool{
			route:  route{upstream: upstream, originalName: def.Name},
			def:    def,
			output: output,
		}
	}
	for name := range dupes {
		delete(out.routes, name)
	}
	return out
}

// mergeRoutes folds each upstream's candidate routes into the one table,
// dropping any client-facing name that more than one upstream claims.
//
// Namespacing normally makes a collision impossible, but it cannot rule out
// every case: an upstream named "a" with a tool named "b.c" produces the
// same client-facing name as an upstream named "a.b" with a tool named "c".
// Serving *either* candidate would mean a call landing on a backend nobody
// can predict from the name -- the exact harm namespacing exists to prevent
// -- so neither is served.
//
// candidates is keyed by upstream name; the keys are sorted first so that
// which upstream gets named in the error is stable rather than a product of
// map iteration order.
func mergeRoutes(candidates map[string]map[string]routedTool) (map[string]routedTool, []error) {
	upstreams := make([]string, 0, len(candidates))
	for name := range candidates {
		upstreams = append(upstreams, name)
	}
	slices.Sort(upstreams)

	merged := map[string]routedTool{}
	collisions := map[string]bool{}
	var failures []error

	for _, upstream := range upstreams {
		names := make([]string, 0, len(candidates[upstream]))
		for name := range candidates[upstream] {
			names = append(names, name)
		}
		slices.Sort(names)

		for _, name := range names {
			if _, dup := merged[name]; dup {
				collisions[name] = true
				failures = append(failures, fmt.Errorf("%w: %q: tool %q collides with an already-routed name; neither is served", ErrUpstreamUnavailable, upstream, name))
				continue
			}
			merged[name] = candidates[upstream][name]
		}
	}
	for name := range collisions {
		delete(merged, name)
	}
	return merged, failures
}

// routesOf returns the subset of a routing table belonging to one upstream.
// It is how a refresh carries an unmeasurable upstream's previous routes
// forward untouched.
func routesOf(table map[string]routedTool, upstream string) map[string]routedTool {
	out := map[string]routedTool{}
	for name, rt := range table {
		if rt.route.upstream == upstream {
			out[name] = rt
		}
	}
	return out
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

	// Taken here, while the plaintext is briefly in hand, and nowhere
	// else -- this is the only moment the gateway knows what the upstream
	// is actually being given. Digests, not values: see the creds field.
	g.rememberCredentials(entry.Name, env)

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
//  6. Check what came back: its size, always, and its structured content
//     against the tool's own output schema when the tool declared one
//     (design/adr/0014). A result that fails either is refused whole --
//     never truncated, never partly forwarded.
//  7. If the upstream did not complete the call, or step 6 refused what it
//     answered with, APPEND a second record.
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
// # Why a failure is a second row, and what that costs
//
// Because of the above, by the time a failure is known the `allowed` row
// is already on disk. design/adr/0012-audit-completeness.md appends
// rather than rewrites it: an audit record that can be edited after the
// fact is state, not evidence, and the pair says strictly more than the
// corrected row would -- that the call really was dispatched, and how
// long it ran before it broke.
//
// **A failed call therefore produces TWO rows.** Anyone counting rows to
// answer "how many calls were there" over-counts by exactly the number of
// failures; count `allowed` rows and read a `failed` row as an annotation
// on the one before it. This is stated again on audit.OutcomeFailed and
// in `mcp-gateway audit`'s own help, because it is the kind of thing a
// reader meets in the data long before they meet it in a comment.
//
// A tool-level error -- the upstream ran the tool and the tool said no,
// Result.IsError -- is NOT a failure here and gets no second row. The
// call completed; what it returned is between the analyst and the
// backend, and recording it as a gateway-visible failure would put a
// wrong query and a dead SIEM in the same bucket.
//
// A result refused at step 6 IS a failure and does get one. The
// difference from the paragraph above is who decided: there the tool
// answered and its answer was "no", here the gateway looked at the answer
// and would not pass it on. The second is a fact about this gateway's own
// behaviour, and an analyst reporting "the tool returned nothing" needs it
// to be visible to whoever reads the trail. Note that a tool-level error
// is still subject to the size ceiling -- a refusal floods a context as
// readily as an answer -- so an oversized IsError result produces the
// failure row too.
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
func (g *Gateway) Dispatch(ctx context.Context, c Caller, namespacedTool string, args json.RawMessage) (Result, error) {
	rt, up, found := g.lookup(namespacedTool)
	if !found {
		g.auditRefusal(ctx, c, namespacedTool, targetOf(namespacedTool), reasonUnknownTool)
		return Result{}, ErrUnknownTool
	}

	if err := g.policy.Authorize(c.Identity, namespacedTool); err != nil {
		g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, reasonForbidden)
		return Result{}, err
	}

	if err := g.admit(ctx, rt.route); err != nil {
		if errors.Is(err, ErrToolQuarantined) {
			g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, reasonQuarantined)
			// Internally distinct (err is ErrToolQuarantined and the log says
			// so); opaque on the way out. See the doc comment.
			return Result{}, ErrUnknownTool
		}
		g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, reasonQuarantineUnavailable)
		return Result{}, err
	}

	if err := g.record(ctx, c, namespacedTool, rt.route.upstream, audit.OutcomeAllowed, ""); err != nil {
		g.log.ErrorContext(ctx, "gateway: refusing unauditable call",
			slog.String("tool", namespacedTool), slog.String("detail", err.Error()))
		return Result{}, err
	}

	res, err := up.CallTool(ctx, rt.route.originalName, args)
	if err != nil {
		g.auditFailure(ctx, c, namespacedTool, rt.route.upstream, err)
		return Result{}, fmt.Errorf("gateway: call %q: %w", namespacedTool, err)
	}
	// Step 6, added by design/adr/0014: the backend answered, and what it
	// answered with is checked before it is handed on. A result over the
	// size ceiling, or one diverging from an output schema the tool itself
	// declared, is refused whole -- never truncated, never partially
	// forwarded -- and appended to the trail as OutcomeFailed by the same
	// path an unreturned call takes. The call did leave this process and
	// did run, which is why this is a failure row rather than a denial.
	if err := g.checkResult(rt, res); err != nil {
		g.auditFailure(ctx, c, namespacedTool, rt.route.upstream, err)
		return Result{}, fmt.Errorf("gateway: call %q: %w", namespacedTool, err)
	}
	return res, nil
}

// RecordAuthFailure writes the audit record for a request that was
// refused before it had an identity at all: no bearer credential, a
// credential that did not verify, or a verifier that returned an identity
// with no subject.
//
// # Why this exists
//
// Until design/adr/0012 it did not, and the gap was the loudest one in
// the trail. A rejected request produced a slog.Warn and nothing more, so
// token grinding, replay of an expired token, and the wrong-audience
// probing that RFC 8707 exists to stop -- the control this project is
// proudest of -- were all invisible to the one artifact a SOC would go to
// after an incident. The gateway blocked them and could not show it.
//
// It lives here, not in the serving adapter, for the reason
// RecordRefusedProbe gives: every audit record this system writes is
// written by one component, so attribution, ordering and reasons cannot
// drift between surfaces.
//
// # What is recorded, and what deliberately is not
//
// A denial, attributed to unauthenticatedIdentity, aimed at
// gatewayItself, with the single generic reasonAuthFailed. Read those
// constants for why each is what it is; the short version is that this
// layer honestly does not know which of eight causes it hit, and the
// value of the row is that the attempt existed, when, and from where.
//
// **The presented credential never appears in the record**, in any field,
// not even truncated. A rejected token is still somebody's credential --
// possibly the credential of the analyst it was stolen from -- and a
// prefix of one is enough to correlate against a leak. Nothing here is
// given the token in the first place, which is the only reliable way to
// guarantee that.
//
// # The pending debt, stated rather than buried
//
// Nothing rate-limits this. Somebody hammering tokens writes one row per
// attempt, and under a sustained grind the trail becomes mostly this. It
// is still better than today's silence -- a burst of these rows *is* the
// detection -- but it is a real gap and design/adr/0012 records it as
// one, not as a detail.
//
// Like auditRefusal, it returns nothing: the 401 stands whether or not
// the row could be written, and a failure is loud in the log instead.
func (g *Gateway) RecordAuthFailure(ctx context.Context, source string) {
	g.log.WarnContext(ctx, "gateway: unauthenticated request refused",
		slog.String("source", source),
	)
	c := Caller{
		Identity:      access.Identity{Subject: unauthenticatedIdentity},
		SourceAddress: source,
	}
	if err := g.record(ctx, c, authenticationTool, gatewayItself, audit.OutcomeDenied, reasonAuthFailed); err != nil {
		g.log.ErrorContext(ctx, "gateway: unauthenticated request was not audited",
			slog.String("detail", err.Error()))
	}
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
func (g *Gateway) RecordRefusedProbe(ctx context.Context, c Caller, namespacedTool string) {
	tool := namespacedTool
	if strings.TrimSpace(tool) == "" {
		tool = unnamedTool
	}
	g.auditRefusal(ctx, c, tool, targetOf(tool), reasonNotVisible)
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

// verifyEntry checks a registry entry against its stored Ed25519
// signature before anything is spawned with it.
//
// Ordering matters: this runs *before* bringUp, so an entry whose
// command was tampered with is never executed, not executed and then
// judged. Verification is worthless after the process has started.
//
// Three outcomes:
//
//   - No signer configured: nothing is checked. Reported once at Connect
//     rather than per entry, so it cannot be missed in a wall of logs. New
//     guarantees this cannot coexist with RequireSigned, so the early
//     return below cannot be a silent bypass of it.
//   - Signature present and invalid: refused, always, regardless of
//     RequireSigned. This is the case with no benign reading, and since
//     ADR-0010 it includes a signature made by a key that is not in
//     signer.trusted_keys.
//   - Signature absent: refused only when RequireSigned is set. See the
//     note on Config.RequireSigned for why that default is what it is.
func (g *Gateway) verifyEntry(ctx context.Context, entry registry.UpstreamServer) error {
	if g.signatures == nil {
		return nil
	}

	sig, err := g.signatures.Get(ctx, entry.Name)
	switch {
	case errors.Is(err, signer.ErrNotFound):
		if g.requireSig {
			return fmt.Errorf("%w: %q: no signature, and unsigned entries are refused", ErrUpstreamUnavailable, entry.Name)
		}
		g.log.WarnContext(ctx, "gateway: upstream entry is unsigned",
			slog.String("upstream", entry.Name))
		return nil
	case err != nil:
		// The store is there but unreadable. Fail closed, same reasoning
		// as ADR-0004 gives for the registry: an integrity decision made
		// without the state that governs it is the decision an attacker
		// wants.
		return fmt.Errorf("%w: %q: signature store unreadable: %w", ErrUpstreamUnavailable, entry.Name, err)
	}

	if err := g.verifier.Verify(entry, sig); err != nil {
		return fmt.Errorf("%w: %q: %w", ErrUpstreamUnavailable, entry.Name, err)
	}
	return nil
}

// record writes one audit record for an attempted call and returns any
// failure to the caller, which refuses the call on it.
func (g *Gateway) record(ctx context.Context, c Caller, tool, upstream string, outcome audit.Outcome, reason string) error {
	rec := audit.Record{
		// Subject, not Name: the IdP's stable identifier is what the trail
		// attributes to, since a display name can change under it.
		AnalystIdentity: c.Identity.Subject,
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
		// Passed through exactly as the serving adapter resolved it. This
		// package does not parse it, normalize it, or second-guess it: the
		// question "which of the addresses in this request do we believe"
		// is answerable only where the transport is, and answering it
		// twice would be two answers. See Caller.SourceAddress.
		SourceAddress: c.SourceAddress,
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
func (g *Gateway) auditRefusal(ctx context.Context, c Caller, tool, upstream, reason string) {
	g.log.WarnContext(ctx, "gateway: refused dispatch",
		slog.String("subject", c.Identity.Subject),
		slog.String("source", c.SourceAddress),
		slog.String("tool", tool),
		slog.String("upstream", upstream),
		slog.String("reason", reason),
	)
	if err := g.record(ctx, c, tool, upstream, audit.OutcomeDenied, reason); err != nil {
		g.log.ErrorContext(ctx, "gateway: refused dispatch was not audited",
			slog.String("tool", tool), slog.String("detail", err.Error()))
	}
}

// auditFailure appends the second record for a call that was dispatched
// and did not come back, and logs the detail the record does not carry.
//
// The row is APPENDED, never an edit of the `allowed` one written before
// the call. See Dispatch's doc comment for why, and for the two-rows cost
// that follows from it.
//
// Like auditRefusal, it returns nothing. The call has already failed and
// the caller is already getting an error; turning an audit hiccup into a
// different error would change what the client sees on account of
// something that happened after the fact. The failure is loud in the log.
func (g *Gateway) auditFailure(ctx context.Context, c Caller, tool, upstream string, cause error) {
	reason := classifyFailure(cause)
	g.log.WarnContext(ctx, "gateway: dispatched call failed",
		slog.String("subject", c.Identity.Subject),
		slog.String("source", c.SourceAddress),
		slog.String("tool", tool),
		slog.String("upstream", upstream),
		slog.String("reason", reason),
		// The upstream's own text goes here and only here. It is
		// upstream-controlled data, and the audit trail is not a place this
		// gateway lets a backend write free text into.
		slog.String("detail", cause.Error()),
	)
	if err := g.record(ctx, c, tool, upstream, audit.OutcomeFailed, reason); err != nil {
		g.log.ErrorContext(ctx, "gateway: failed dispatch was not audited -- the trail shows this call as allowed and nothing else",
			slog.String("tool", tool), slog.String("detail", err.Error()))
	}
}

// classifyFailure reduces a failed call to one of a small closed set of
// operator-facing reasons.
//
// Closed is the requirement, and it is why every new refusal that reaches
// this function arrives as a sentinel with a constant beside it rather
// than as text. The distinction that has to survive for a call that did
// not come back is "the backend never answered" versus "the backend
// answered badly" -- design/adr/0012 opens on a timed-out call recorded as
// `allowed` -- and that is exactly what the context sentinels already say.
// The two ADR-0014 cases are the reverse situation, a call that came back
// and was refused on the way out, and they stay separate for the same kind
// of reason: an operator looking at "this backend is answering in a shape
// nobody approved" is looking at a different incident from "this backend
// is flooding us", and both are different from "the SIEM is down".
// Everything else collapses, because the alternative is putting
// upstream-authored text in the evidence field.
func classifyFailure(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return reasonUpstreamTimeout
	case errors.Is(err, context.Canceled):
		return reasonCallCancelled
	case errors.Is(err, ErrResultTooLarge):
		return reasonResultTooLarge
	case errors.Is(err, ErrResultSchemaViolation):
		return reasonResultSchemaViolation
	default:
		return reasonUpstreamFailed
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

// tableSnapshot copies both halves of the routing state under one lock, so
// a refresh cannot read connections from one generation of the table and
// routes from another.
func (g *Gateway) tableSnapshot() (map[string]Upstream, map[string]routedTool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	conns := make(map[string]Upstream, len(g.conns))
	for name, up := range g.conns {
		conns[name] = up
	}
	routes := make(map[string]routedTool, len(g.routes))
	for name, rt := range g.routes {
		routes[name] = rt
	}
	return conns, routes
}

// swapRoutes installs a rebuilt routing table over the same connections,
// which is what a refresh produces. It reports whether the Gateway was
// closed while the table was being built, in which case nothing is
// installed -- a table restored after Close would advertise tools whose
// subprocesses have already been reaped.
//
// Unlike swap it closes nothing: the connections in the table are the ones
// still in use, not a replaced generation.
func (g *Gateway) swapRoutes(routes map[string]routedTool) (closedDuringRefresh bool) {
	if routes == nil {
		routes = map[string]routedTool{}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return true
	}
	g.routes = routes
	return false
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

// CredentialDrift is one connected upstream still running on a credential
// value the vault no longer holds.
//
// It names the upstream and the environment variable NAME. Neither is a
// secret -- the registry stores both in plaintext because neither can be
// one -- and nothing else is carried, in particular not the value, the
// previous value, or a digest of either.
type CredentialDrift struct {
	// Upstream is the registered name of the connected upstream.
	Upstream string
	// VarName is the environment variable whose value diverged.
	VarName string
}

// credDigest returns the keyed digest of a credential value. See the
// credKey field for why it is keyed rather than a bare hash.
func (g *Gateway) credDigest(value string) string {
	mac := hmac.New(sha256.New, g.credKey)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// rememberCredentials records what one upstream was handed at dial time.
func (g *Gateway) rememberCredentials(upstream string, env map[string]string) {
	digests := make(map[string]string, len(env))
	for name, value := range env {
		digests[name] = g.credDigest(value)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.creds == nil {
		g.creds = map[string]map[string]string{}
	}
	g.creds[upstream] = digests
}

// CredentialDrift reports every connected upstream whose credentials no
// longer match what the Credential Vault holds now.
//
// # What this is for
//
// Credentials resolve at *dial* time and are copied into the upstream
// subprocess's environment, so rotating one in the vault changes what the
// NEXT connect will use and nothing else. An already-connected upstream
// keeps the old value until the gateway restarts. That was true, correct,
// documented in deploy/freebsd-jail.md -- and invisible: nothing reported
// it, so "I rotated that credential" and "the old credential is still in
// active use" were the same state with two different beliefs attached to
// it. Rotation usually means somebody thinks the old value is
// compromised, which makes the gap between those two beliefs the whole
// problem (GAB-20).
//
// # What it does not do
//
// It does not reconnect anything, and it does not close the window. The
// upstream keeps serving with the old credential until a human acts; what
// changed is that the divergence can be seen. Reconnecting without a full
// restart is the other half of GAB-20 and is not built here.
//
// It also cannot see a credential that was rotated and then rotated back,
// nor one whose value is unchanged but whose *meaning* was revoked
// upstream -- a digest compares bytes, and an API key deactivated at the
// provider is byte-identical to the one that still works.
//
// A vault that cannot be read is NOT drift and is not reported. An
// unreadable vault says nothing about whether the value changed, and
// crying drift during the incident that makes the vault unreachable is
// how a warning gets trained out of an operator. The read failure is
// logged instead.
func (g *Gateway) CredentialDrift(ctx context.Context) []CredentialDrift {
	g.mu.RLock()
	snapshot := make(map[string]map[string]string, len(g.creds))
	for upstream, digests := range g.creds {
		// Only upstreams that are actually connected. A record left over
		// from one that has since gone away describes nothing running.
		if _, live := g.conns[upstream]; !live {
			continue
		}
		copied := make(map[string]string, len(digests))
		for name, digest := range digests {
			copied[name] = digest
		}
		snapshot[upstream] = copied
	}
	g.mu.RUnlock()

	upstreams := make([]string, 0, len(snapshot))
	for name := range snapshot {
		upstreams = append(upstreams, name)
	}
	slices.Sort(upstreams)

	var drift []CredentialDrift
	for _, upstream := range upstreams {
		names := make([]string, 0, len(snapshot[upstream]))
		for name := range snapshot[upstream] {
			names = append(names, name)
		}
		slices.Sort(names)

		for _, name := range names {
			secret, err := g.vault.Resolve(ctx, name)
			if err != nil {
				// Deliberately not drift. Only the variable name reaches
				// the log; resolveEnv's rule applies here too.
				g.log.ErrorContext(ctx, "gateway: could not re-read a credential to check it against the running upstream; not treating this as a rotation",
					slog.String("upstream", upstream),
					slog.String("env_var_name", name),
					slog.String("detail", err.Error()))
				continue
			}
			if g.credDigest(secret.Value()) != snapshot[upstream][name] {
				drift = append(drift, CredentialDrift{Upstream: upstream, VarName: name})
			}
		}
	}
	return drift
}
