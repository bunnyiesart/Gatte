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
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/bunnyiesart/Gatte/internal/visible"
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

	// ErrQuotaMisconfigured means the declared quota accounts and the
	// Upstream Registry disagree: a [[quota.provider]] names an upstream
	// that is not registered, or a budgeted entry shares an environment
	// variable -- which is to say a credential -- with an entry no account
	// budgets. See CheckQuotaCoverage.
	//
	// At Connect it is fatal, and it is the second error in this package
	// that is -- ErrRegistryUnavailable being the first. The reasoning is
	// ADR-0004's: a limit written against an account nobody serves is a
	// control the operator believes is on and that cannot fire, and the
	// process that keeps running is the one nobody investigates.
	//
	// At Reconcile it cannot be fatal -- the process is already serving --
	// and it freezes the fleet instead: nothing is dialled or re-dialled
	// while the two disagree, and a live entry spending a budgeted
	// credential uncounted is closed (design/adr/0030-quota-por-analista.md).
	// A registry that changed under a running gateway is exactly how the
	// disagreement arises there, and serving a backend registered in that
	// state would be serving it past the check Connect makes at boot.
	//
	// Cross-checked here rather than in config.Validate because this is the
	// only place both sides are in hand: the file is parsed long before the
	// registry is read, and inventing a second place to ask the question
	// would be inventing a second answer.
	ErrQuotaMisconfigured = errors.New("gateway: quota misconfigured")

	// ErrQuotaUndeclaredTool reports that a budgeted upstream serves one or
	// more tools no account charges and quota.free_tools does not excuse.
	// Those tools are NOT routed; everything else about that upstream is
	// served normally.
	//
	// Deliberately NOT ErrQuotaMisconfigured, and the difference is the
	// whole design. The account-level check has no safe partial state
	// available to it. This one has one -- withhold the tool -- and choosing
	// it keeps a backend that grew a tool from taking the SOC's gateway down
	// at the next restart, which is the self-inflicted outage serve.go
	// declines everywhere else. The hole is still closed: an uncounted call
	// against the budget cannot be made, because the call cannot be routed.
	ErrQuotaUndeclaredTool = errors.New("gateway: tool of a budgeted upstream is not declared")

	// errSignatureUnmeasured marks the one verifyEntry failure that is the
	// ABSENCE of a measurement rather than a measurement: the signature
	// store could not be read at all.
	//
	// It is unexported because only Reconcile needs the distinction, and it
	// needs it badly. The two failures look alike and must not act alike --
	// the rule ADR-0013 states for the quarantine and Refresh repeats in
	// its own failure section: "failing to measure is not evidence that
	// something changed." An invalid signature is positive evidence that an
	// entry was altered by something other than the signer. An unreadable
	// store says nothing about the entry, and the store is the SAME SQLite
	// file as the registry -- so treating the two alike means the disk
	// hiccup ADR-0020 promises to survive by keeping connections would
	// close every one of them instead.
	errSignatureUnmeasured = errors.New("gateway: signature store unreadable")
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
	// reasonAuthFlood means this source went over the ceiling on how many
	// authentication failures are written durably, and this is the one line
	// that says so for the window (design/adr/0027). It is what keeps the
	// suppression from being silent: the trail stops answering "how many"
	// and still answers "this source tried, and the ceiling fired".
	reasonAuthFlood = "auth failures rate-limited"
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
	// reasonUpstreamGone means the backend process behind this call is not
	// there any more -- the stream ended, which the adapter reports as
	// gateway.ErrUpstreamGone. Separate from reasonUpstreamFailed because
	// the two send an operator to different places: one is a backend that
	// answered badly, the other is a backend that is not running
	// (design/adr/0024).
	reasonUpstreamGone = "upstream gone"
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
	// reasonRegistryUnavailable means the fleet is suspended: the Upstream
	// Registry could not be read, so ADR-0004's fail-closed rule applies
	// and nothing is served until it can be (ADR-0020 item 4). Separate
	// from reasonUnknownTool because the two are opposite facts -- "that
	// tool does not exist" versus "we cannot currently confirm anything
	// exists" -- and the trail is where an operator tells one incident
	// from the other.
	reasonRegistryUnavailable = "registry unavailable"
)

// The rows the gateway writes about itself rather than about a call
// (design/adr/0032 item 4): a tool seen for the first time, an approved
// tool whose definition changed, and a registry entry whose signature
// started being refused. Each is written on the transition only.
//
// They are `denied` rows, not a fourth outcome. Every one of them is the
// gateway refusing to serve something -- a pending tool, a changed tool, an
// upstream -- which is what denied means, and audit.Outcome stays the closed
// set of three that saved searches, `audit -outcome` and the heartbeat's
// counters are written against. What tells them apart from a call refusal
// is gatewayActor in the caller field and the reason.
//
// The reason is one of the three prefixes below followed by gateway-made
// detail (fingerprints, "invalid" or "unsigned"), never backend text. A
// SIEM query matches on the prefix.
const (
	// gatewayActor is the AnalystIdentity of these rows: nobody called
	// anything, the gateway observed something. Parenthesised like
	// unauthenticatedIdentity, so it cannot be read as an IdP subject.
	gatewayActor = "(gateway)"
	// registryEntryTool is the Tool of a signature row: the refusal is of
	// an upstream's registry entry, before any tool of it was listed.
	registryEntryTool = "(registry entry)"

	// reasonToolFirstSeen: "tool first seen: sha256:OBSERVED".
	reasonToolFirstSeen = "tool first seen"
	// reasonToolChanged: "tool changed: sha256:APPROVED -> sha256:OBSERVED".
	reasonToolChanged = "tool changed"
	// reasonSignatureRefused: "signature refused: invalid" or
	// "signature refused: unsigned".
	reasonSignatureRefused = "signature refused"
)

// maxToolNameLen and validToolName are the tool-name charset of
// design/adr/0032 item 6: ^[A-Za-z0-9_-]{1,64}$. A tool name reaches the
// model, the operator's terminal, every log line and the audit trail, and it
// is the backend's choice. Before this it was not checked at all.
//
// The dot is outside the set on purpose. It is NameSeparator, and a tool
// named "b.c" on upstream "a" reads as the same client-facing name as tool
// "c" on an upstream "a.b" -- the ambiguity the registry already refuses
// from the other side.
const maxToolNameLen = 64

// maxToolDefinitionBytes bounds one advertised definition -- name,
// description, input and output schema together -- before the quarantine
// stores it (design/adr/0032 item 1). The store keeps at most two
// definitions per tool; this bounds how large each of those is. 64 KiB is
// far past any real tool definition, and caps one tool at 128 KiB stored.
const maxToolDefinitionBytes = 64 << 10

func definitionSize(def ToolDef) int {
	return len(def.Name) + len(def.Description) + len(def.InputSchema) + len(def.OutputSchema)
}

func validToolName(name string) bool {
	if name == "" || len(name) > maxToolNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// shownName renders an untrusted name for an error or a log line: hidden
// code points escaped, and cut short, since the name was refused precisely
// because nothing bounds what a backend sends.
func shownName(name string) string {
	const limit = 96
	if len(name) <= limit {
		return `"` + visible.Escape(name) + `"`
	}
	// A code point cut in half shows as \x{..} bytes, which is visible
	// and harmless.
	return fmt.Sprintf(`"%s"... (%d bytes)`, visible.Escape(name[:limit]), len(name))
}

// Reasons for a call the per-analyst quota turned down
// (design/adr/0030-quota-por-analista.md decision 7). Declared interface
// strings like the ones above, for the same reason.
const (
	// reasonQuotaExhausted means the analyst has spent this window's
	// allowance for one of the accounts the call would have consumed.
	// Nothing was debited: a reservation is all or nothing, so a refused
	// call costs no quota.
	//
	// It is deliberately distinct from "forbidden". Forbidden is a fact
	// about the analyst's role and does not change on its own; this one
	// resolves by itself when the window rolls over, and an operator
	// triaging "I cannot call this tool any more" needs to know which of
	// the two they are looking at before deciding whether to edit a file.
	reasonQuotaExhausted = "quota exhausted"

	// reasonQuotaUnavailable means the counter could not be established --
	// unreadable, unwritable, or a reservation this gateway built wrong.
	// The call is refused, because a quota that turned into a free pass
	// when its counter broke would be the one control here with the
	// inverse failure mode, and whoever wanted the team's budget would
	// only have to break the counter (ADR-0030 decision 6).
	//
	// Read failures and write failures share this one reason on purpose.
	// The distinction is not one an operator can act on differently, and
	// naming it in the trail would invite somebody to treat half of it as
	// infrastructure noise.
	reasonQuotaUnavailable = "quota unavailable"
)

// Reasons for a request refused by the operator's per-analyst kill switch
// (design/adr/0031-bloqueio-imediato-por-analista.md). Declared interface
// strings, like the ones above.
const (
	// reasonSubjectBlocked means the operator blocked this subject with
	// `mcp-gateway access block`. The caller is told only "forbidden".
	reasonSubjectBlocked = "subject blocked"
	// reasonBlocklistUnavailable means the blocklist could not be read, so
	// the request was refused rather than waved through.
	reasonBlocklistUnavailable = "blocklist unavailable"
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
	// Blocklist is the operator's per-analyst kill switch
	// (design/adr/0031-bloqueio-imediato-por-analista.md), read on every
	// AdmitCaller, ListTools and Dispatch. Required: a nil one would have to
	// mean "nobody can be blocked", which is a control switched off by an
	// unset field. The port can only ask; placing a block is the console's.
	Blocklist access.Blocklist
	// Quota is the per-analyst quota, consulted on every dispatch between
	// Tool Quarantine's admission and the audit record that says the call
	// was allowed (design/adr/0030-quota-por-analista.md).
	//
	// Required, like every other port here: a nil one would have to mean
	// "then nothing is counted", and a security control switched off by an
	// unset field is the failure mode require_signed and
	// quarantine.refresh_interval were both shaped to avoid. An
	// installation with no account to protect says so out loud, by wiring a
	// Gate built over an empty plan (quota.NewPlan(nil, nil)) -- which
	// charges nothing, admits every call without touching the counter, and
	// leaves the gateway behaving exactly as it did before the quota
	// existed.
	//
	// It is a *quota.Gate rather than an interface because the Gate is the
	// domain's own decision procedure, not infrastructure: the port it
	// hides behind is quota.Store, which the Gate holds. Note which half
	// arrives here -- the Gate can reserve and cannot read, so nothing in
	// this package can ask what an analyst has spent (quota.Reader is the
	// Operator Console's, and a fitness function keeps it out of here).
	Quota *quota.Gate
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

	// CallTimeout is the ceiling on how long one tool call may take
	// (design/adr/0025-prazo-por-chamada.md). Optional; zero or negative
	// selects DefaultCallTimeout. Like MaxResultBytes it cannot be switched
	// off from here -- an operator who needs more time raises the number in
	// the configuration file, where a reviewer sees it.
	CallTimeout time.Duration

	// MaxConcurrentCallsPerAnalyst is how many calls one subject may have
	// in flight at once (design/adr/0035). Optional; zero or negative
	// selects DefaultMaxConcurrentCallsPerAnalyst, so like the two ceilings
	// above it cannot be switched off from here.
	MaxConcurrentCallsPerAnalyst int

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

	// Maintenance is read on every call that reaches the availability step
	// (design/adr/0041 item 6). Optional: nil means nothing is ever in
	// maintenance. Read fail-open -- an unreadable table serves as if
	// empty -- because it is an availability notice, not access control.
	Maintenance health.MaintenanceReader
	// State receives what this process observes about its backends, for
	// the management backend (another process) and for the stable listing
	// of the next boot (ADR-0041 items 4 and 7). Optional: nil keeps it in
	// memory only. A write failure is logged and changes nothing served.
	State health.StateStore
	// RoundInterval is the maintenance loop's interval, from which a
	// caller is told roughly when the next reconnect attempt is. Optional:
	// zero leaves next_attempt unknown.
	RoundInterval time.Duration
	// Boot is when this process started, for the serve status row.
	// Optional; defaults to the time New runs.
	Boot time.Time
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
	blocklist  access.Blocklist
	quota      *quota.Gate
	dialer     Dialer
	signatures signer.Store
	verifier   *signer.Verifier
	requireSig bool
	// maxResultBytes is always positive: New resolves an unset or
	// nonsensical value to DefaultMaxResultBytes, so there is no way to
	// hold a Gateway that enforces no ceiling at all.
	maxResultBytes int64
	// callTimeout is the per-call ceiling, always positive by the same rule
	// and for the same reason (ADR-0025).
	callTimeout time.Duration
	// slots is the per-subject concurrency cap (ADR-0035), always
	// positive by the same rule.
	slots *callSlots
	now   func() time.Time
	log   *slog.Logger

	// refreshMu serializes Connect against Refresh. It is not the same lock
	// as mu, and it guards a different thing: mu protects the table for the
	// microseconds a read or a swap takes, while this one holds for the
	// whole of a discovery -- dialing every backend, or asking every
	// connected one for its tool list. Without it, a ticker's Refresh could
	// compute a table from the connections a concurrent Connect is in the
	// middle of replacing, and install it over the newer one.
	refreshMu sync.Mutex

	// sigRefused is, per upstream name, the reason its entry's signature
	// was last refused, so noteSignature writes an audit row on the
	// transition and not on every round (design/adr/0032). Guarded by
	// refreshMu: only Connect and Reconcile verify entries, and both hold it.
	sigRefused map[string]string

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
	creds map[string]map[string]string
	// dialed records the registry entry each live connection was dialed
	// from, so Reconcile can tell "this entry is unchanged" from "this
	// entry now names a different command" without re-dialing to find out
	// (ADR-0020 item 1). It is written wherever conns is, under the same
	// lock, and holds exactly the same key set.
	//
	// It keeps the whole entry rather than a digest because the comparison
	// is small and a digest would hide which field moved from the log.
	// Nothing secret is in it: EnvVarNames are names, which the registry
	// stores in plaintext for that reason.
	dialed map[string]registry.UpstreamServer
	routes map[string]routedTool
	// authLimit decides which authentication failures reach the durable
	// trail (design/adr/0027). Guarded by mu, like everything else here that
	// is not atomic.
	authLimit *authLimiter

	// gone records, per upstream name, the CONNECTION that was found dead.
	//
	// Keyed by name but holding the Upstream itself, and the value is what
	// makes it correct: Reconcile acts only when the connection it is about
	// to close is still the same object that was found dead. A marker by
	// name alone would, on a round where that upstream had meanwhile been
	// retired and re-dialled for an unrelated reason, close a brand-new
	// healthy process on the strength of an observation about its
	// predecessor (design/adr/0024).
	gone map[string]Upstream

	// allowed, denied and failed count the audit records this process has
	// written, by outcome, since it started. Atomics rather than a mutex:
	// they are incremented on the dispatch path, by every concurrent
	// caller, and they guard nothing else.
	//
	// What they mean is exact and narrow -- see Status. They are a gauge
	// an operator reads in a heartbeat (design/adr/0021), never a source
	// of truth: the trail is durable and chained, and these die with the
	// process.
	allowed atomic.Uint64
	denied  atomic.Uint64
	failed  atomic.Uint64

	// confirmed reports that the Upstream Registry was read successfully by
	// the most recent attempt. It is NOT the same as serving: a round can
	// confirm the fleet and still leave the routing table empty, because
	// Reconcile does not build one (ADR-0020 item 2).
	//
	// The pair exists because lifting the suspension at the moment of the
	// successful read opened a window nobody decided to open: routes were
	// still empty, so every call in it was answered -- and audited -- as
	// `unknown tool`, which is the exact confusion ADR-0020 item 4 exists
	// to prevent. Suspension now ends where serving begins, in swapRoutes.
	confirmed bool

	// suspended reports that the Upstream Registry could not be read and
	// the fleet is therefore serving nothing (ADR-0004 fail-closed, as
	// implemented by ADR-0020 item 3). It is not the same as an empty
	// routing table: an empty table is a fleet with nothing approved in
	// it, and this is a fleet whose contents cannot currently be
	// confirmed. ListTools and Dispatch say which one it is.
	suspended bool
	closed    bool

	// Backend health (design/adr/0041). maint and state are the ports;
	// the rest is guarded by mu.
	maint         health.MaintenanceReader
	state         health.StateStore
	roundInterval time.Duration
	boot          time.Time
	// health is the fact of life of every servable backend.
	health map[string]*backendHealth
	// servable is the set of the most recent round, nil before the first.
	servable map[string]bool
	// heldBack is the quota freeze of the most recent round: no dial is
	// scheduled, so a backend that is not live is down, not reconnecting.
	heldBack bool
	// lastRound is when the most recent round started.
	lastRound time.Time
	// listing is each backend's last successful live listing, the source of
	// its stable routes while it is not live; dirtyListing marks the ones
	// not yet written. listingLoaded is guarded by refreshMu.
	listing       map[string][]health.ListedTool
	dirtyListing  map[string]bool
	listingLoaded bool
	// unlisted holds each connection Reconcile adopted that no Refresh has
	// listed yet. Its routes, if any, are the kept ones of the process it
	// replaced, approved for what THAT process announced; until the new
	// one is observed it receives no call (design/adr/0041 item 4).
	unlisted map[string]Upstream
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
	if cfg.Blocklist == nil {
		missing = append(missing, "Blocklist")
	}
	if cfg.Quota == nil {
		missing = append(missing, "Quota")
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
	callTimeout := cfg.CallTimeout
	if callTimeout <= 0 {
		callTimeout = DefaultCallTimeout
	}
	maxConcurrent := cfg.MaxConcurrentCallsPerAnalyst
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentCallsPerAnalyst
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

	boot := cfg.Boot
	if boot.IsZero() {
		boot = now()
	}

	return &Gateway{
		maint:          cfg.Maintenance,
		state:          cfg.State,
		roundInterval:  cfg.RoundInterval,
		boot:           boot,
		health:         map[string]*backendHealth{},
		listing:        map[string][]health.ListedTool{},
		dirtyListing:   map[string]bool{},
		unlisted:       map[string]Upstream{},
		credKey:        credKey,
		creds:          map[string]map[string]string{},
		sigRefused:     map[string]string{},
		registry:       cfg.Registry,
		vault:          cfg.Vault,
		quarantine:     cfg.Quarantine,
		audit:          cfg.Audit,
		policy:         cfg.Policy,
		blocklist:      cfg.Blocklist,
		quota:          cfg.Quota,
		dialer:         cfg.Dialer,
		signatures:     cfg.Signatures,
		verifier:       cfg.Verifier,
		requireSig:     cfg.RequireSigned,
		maxResultBytes: maxResultBytes,
		callTimeout:    callTimeout,
		slots:          newCallSlots(maxConcurrent),
		now:            now,
		log:            logger,
		conns:          map[string]Upstream{},
		dialed:         map[string]registry.UpstreamServer{},
		gone:           map[string]Upstream{},
		authLimit:      newAuthLimiter(),
		routes:         map[string]routedTool{},
	}, nil
}

// Connect reads the Upstream Registry, brings up every registered backend
// and rebuilds the routing table from what they advertise. Calling it again
// re-reads the registry, re-dials, and replaces the previous table and
// connections wholesale -- which is why it is not what runs on a ticker: it
// tears down every live connection, cutting in-flight calls and respawning
// every subprocess.
//
// It is the boot path. On a running gateway, a registry change is picked up
// by Reconcile and periodic re-observation of the backends already
// connected is Refresh, and neither of those tears anything down that the
// registry still describes the same way.
//
// For each upstream, concurrently with the others (see the body for why):
// the credentials named by the registry entry are resolved through the
// Credential Vault, the backend is dialed with those values, its tools are
// listed, and every tool is handed to quarantine.Store.Observe. Observing is what makes a newly-appeared tool
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
		g.swap(nil, nil, nil)
		g.suspend()
		g.log.ErrorContext(ctx, "gateway: registry unreadable, serving nothing", slog.String("detail", err.Error()))
		return fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	}

	// Before anything is dialed: the declared quota accounts and the
	// registry have to agree. This is fatal and the swap is what makes it
	// honest -- nothing is served, rather than served with a budget nobody
	// is counting. See ErrQuotaMisconfigured. With no [[quota.provider]]
	// block the plan is empty and this is a no-op.
	if err := CheckQuotaCoverage(g.quota.Plan(), entries); err != nil {
		g.swap(nil, nil, nil)
		g.log.ErrorContext(ctx, "gateway: quota policy and upstream registry disagree, serving nothing",
			slog.String("detail", err.Error()))
		return err
	}

	conns := make(map[string]Upstream, len(entries))
	dialed := make(map[string]registry.UpstreamServer, len(entries))
	candidates := map[string]map[string]routedTool{}
	var failures []error
	// ready is every entry that passed both gates, in registry order.
	var ready []registry.UpstreamServer

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
		// The registry's own contract, re-checked on the way out of the
		// store rather than trusted from the way in. Register validates,
		// List does not, so a row that predates a rule -- or one written by
		// anything other than this binary -- arrives here unchecked.
		//
		// One clause of that contract is load-bearing for this package and
		// is the reason this check exists at all: a name containing
		// NameSeparator makes Namespaced(name, tool) indistinguishable from
		// the name another upstream would produce, so the backend every
		// consumer reads out of a client-facing name (SplitNamespaced here,
		// access.Role.Allows resolving a per-backend grant) stops being the
		// backend that serves the call. Serving such an entry is how a grant
		// on "threatintel" reaches the tools of "threatintel.staging".
		// Refusing it is what lets access.Role.Allows state that its reading
		// and this table's agree.
		if err := entry.Validate(); err != nil {
			failures = append(failures, fmt.Errorf("%w: %q: registry entry is not servable: %w", ErrUpstreamUnavailable, entry.Name, err))
			g.log.ErrorContext(ctx, "gateway: upstream refused by the registry's own entry contract",
				slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
			continue
		}

		err := g.verifyEntry(ctx, entry)
		g.noteSignature(ctx, entry.Name, err)
		if err != nil {
			failures = append(failures, err)
			g.log.ErrorContext(ctx, "gateway: upstream refused by signature check",
				slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
			continue
		}

		ready = append(ready, entry)
	}
	g.forgetSignatures(entries)

	// The last live listings, once per process, for a backend that is down
	// at this boot (design/adr/0041 item 4); and this is a round.
	g.loadListings(ctx)
	g.mu.Lock()
	g.lastRound = g.now()
	g.mu.Unlock()

	// Each ready entry is brought up and listed in its own goroutine, all
	// under ctx, and handed to the quarantine as soon as it answers. Done
	// one after another, as it used to be, a backend whose dial or
	// tools/list never answered spent the whole connect budget and every
	// entry after it failed with an expired context -- one hung upstream
	// kept the rest of the fleet down until a restart, which is not the
	// "one broken backend is skipped" promise above. A fixed per-entry
	// slice of the budget would fix that by starving a slow but healthy
	// start instead; concurrency gives every entry the whole budget and
	// costs the hung one only itself. (Ported from the internal tree,
	// 2026-09-24.)
	//
	// routesFor stays on this goroutine, in the order answers arrive, so
	// the quarantine is consulted while ctx is still live for everyone who
	// answered in time. Failures are joined in name order afterwards so the
	// error does not depend on who answered first.
	answers := make(chan broughtUp, len(ready))
	for _, entry := range ready {
		go func() { answers <- g.bringUpAndList(ctx, entry) }()
	}
	perUpstream := make(map[string][]error, len(ready))
	for range ready {
		got := <-answers
		perUpstream[got.entry.Name] = got.errs
		if got.up == nil {
			continue
		}
		conns[got.entry.Name] = got.up
		dialed[got.entry.Name] = got.entry

		// unmeasured is deliberately ignored here. At boot there is no
		// earlier observation to fall back on, so a tool the quarantine
		// could not be asked about is a tool whose approval cannot be
		// checked later -- and the fail-closed reading of that is "do not
		// route it", which is what routesFor already did. Refresh, which
		// does have an earlier measurement, reads the flag instead.
		routed := g.routesFor(ctx, got.entry.Name, got.defs)
		candidates[got.entry.Name] = routed.routes
		perUpstream[got.entry.Name] = append(perUpstream[got.entry.Name], routed.failures...)
		if !routed.unmeasured {
			g.recordListing(got.entry.Name, routed.routes)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(perUpstream)) {
		failures = append(failures, perUpstream[name]...)
	}
	// A ready entry that did not come up keeps its stable listing: what it
	// last announced, still approved at the same fingerprint (ADR-0041
	// item 4). One never listed by a serve of this version has none.
	readyNames := make([]string, 0, len(ready))
	dialedAll := make(map[string]bool, len(ready))
	for _, entry := range ready {
		readyNames = append(readyNames, entry.Name)
		dialedAll[entry.Name] = true
		if _, up := conns[entry.Name]; up {
			continue
		}
		if stable := g.stableRoutesFor(ctx, entry.Name); len(stable.routes) > 0 {
			candidates[entry.Name] = stable.routes
		} else {
			g.log.WarnContext(ctx, "gateway: upstream is down at boot and has no stable listing; its tools are not listed until it comes back",
				slog.String("upstream", entry.Name))
		}
	}

	routes, conflicts := mergeRoutes(candidates)
	failures = append(failures, conflicts...)

	// The second quota cross-check, and it has to be here rather than
	// beside the first one: the first compares the plan against the
	// REGISTRY, which is readable before anything is dialed, while this one
	// compares it against what the gateway will actually serve, which is
	// not known until every upstream has been asked for its tools and
	// quarantine has had its say. See withholdUndeclaredQuotaTools.
	failures = append(failures, g.withholdUndeclaredQuotaTools(ctx, routes)...)

	// The registry was read AND this call builds the table itself, so both
	// halves are true at once -- which is what makes Connect the one place
	// that can end a suspension on its own. Set before the swap installs
	// the table it authorises, never after: the reverse order would publish
	// routes that ListTools still refuses to serve.
	g.serving()
	if closedDuringConnect := g.swap(conns, dialed, routes); closedDuringConnect {
		return ErrClosed
	}
	g.writeHealthEvents(ctx, g.settleHealth(readyNames, nil, false, dialedAll, g.now()))
	g.persistHealth(ctx, true)
	return errors.Join(failures...)
}

// broughtUp is one entry's outcome in Connect: a live connection and its
// tool list, or no connection and the failures that explain why.
type broughtUp struct {
	entry registry.UpstreamServer
	up    Upstream
	defs  []ToolDef
	errs  []error
}

// bringUpAndList dials entry and asks it for its tools, for Connect. It
// touches no state Connect owns -- bringUp's rememberCredentials takes g.mu
// itself -- which is what lets Connect run it for every entry at once.
func (g *Gateway) bringUpAndList(ctx context.Context, entry registry.UpstreamServer) (got broughtUp) {
	got.entry = entry
	up, err := g.bringUp(ctx, entry)
	if err != nil {
		got.errs = append(got.errs, err)
		g.log.ErrorContext(ctx, "gateway: upstream not brought up",
			slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
		return got
	}

	defs, err := up.ListTools(ctx)
	if err != nil {
		// The connection is useless without a tool list, and leaving it
		// open would leak a subprocess.
		_ = up.Close()
		got.errs = append(got.errs, fmt.Errorf("%w: %q: list tools: %w", ErrUpstreamUnavailable, entry.Name, err))
		return got
	}
	got.up, got.defs = up, defs
	return got
}

// Reconcile makes the set of live connections match the Upstream Registry,
// without touching a connection the registry still describes the same way.
//
// It is the half of ADR-0004 that did not exist until ADR-0020: Connect
// runs once at boot, so before this, an upstream registered with the
// gateway up was invisible, a deregistered one kept being served, an entry
// whose signature stopped verifying kept being served, and a backend that
// failed to dial at boot stayed down -- all until somebody restarted the
// process.
//
// # What one round does
//
// Every entry is put through the same two gates Connect applies --
// entry.Validate and verifyEntry -- and then, against the live set:
//
//   - registered but not connected: dialed. This covers both an upstream
//     registered since boot and one that failed to dial at boot; one rule,
//     not two.
//   - connected but no longer registered, no longer valid, or no longer
//     verifying: closed, with its routes pruned in the same swap so the
//     table never points at a closed connection.
//   - connected, registered, and the entry's SPEC changed: closed and
//     re-dialed, in that order -- fail closed, and no two processes of one
//     backend alive at once holding the same credential.
//   - connected, registered, unchanged: left alone. This is the common
//     case and it is the whole difference between this and calling Connect
//     on a ticker, which would tear down every live connection and respawn
//     every subprocess at every interval.
//
// A dial that fails leaves that upstream out and is retried next round, as
// at boot. One backend refusing to come up is not a reason to suspend the
// others.
//
// The quota's registry cross-check (CheckQuotaCoverage) runs first, every
// round, and the boot rule it enforces is kept after boot: while the
// declared accounts and the registry disagree, nothing is dialled -- the
// live set only shrinks -- and an entry spending a budgeted credential
// without being budgeted is closed. So an upstream registered after boot
// is served only if the plan and the registry agree with it in place, and
// its tools then reach the table through Refresh, which withholds the
// undeclared ones exactly as Connect does (design/adr/0030).
//
// # What it deliberately does not do
//
// It does not build the routing table. Discovering what a newly connected
// upstream advertises is Refresh's job, and cmd/mcp-gateway's loop calls
// the two in that order on the same tick. One place builds the table from
// live connections; a second one would have to agree with mergeRoutes
// about name collisions forever, and would stop agreeing (ADR-0020 item 2).
// Calling Reconcile alone therefore leaves a new upstream connected and
// serving nothing until the next Refresh.
//
// It also does not re-dial on a rotated credential. That is GAB-20's
// deliberately unbuilt half; the comparison here is over the entry's spec,
// by content, so re-registering an identical entry is not a reconnect
// command either (ADR-0020 item 6).
//
// It IS a liveness check since ADR-0024, and only for the one fact an
// adapter can prove: a connection whose far end is gone (ErrUpstreamGone)
// is closed here and re-dialled by the rule above, because the registry
// still names it. Nothing else counts -- an upstream that merely failed to
// list is kept, by the rule this paragraph used to state absolutely.
//
// Until 16 Sep 2026 this said "it is not a liveness check", and it was
// true: a backend whose subprocess had died stayed in the live set forever
// and every call to it failed until somebody restarted the whole gateway.
//
// Nor does it close a freshly dialed upstream that will not list its tools,
// which Connect does. The asymmetry is deliberate: Connect has no later
// round to fall back on, while here closing it would mean re-dialing --
// respawning a subprocess -- once per interval for as long as the backend
// stays broken. It stays connected, routes nothing, and is retried by the
// next Refresh.
//
// # Registry unreadable
//
// Fail closed, per ADR-0004: the routing table is dropped, the gateway
// serves nothing, and it stays that way until a later round reads the
// registry successfully. The connections are NOT closed -- the decision is
// "nothing is served while the registry cannot be confirmed", not "kill
// every subprocess over a disk hiccup", and keeping them is what makes the
// retry cheaper than a restart.
//
// While suspended, ListTools and Dispatch return ErrRegistryUnavailable
// rather than an empty list or an unknown tool: this state is the one
// serve.go calls worse than refusing to start, so it is legible at both
// ends rather than deduced (ADR-0020 items 3 and 4).
func (g *Gateway) Reconcile(ctx context.Context) error {
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()

	if g.isClosed() {
		return ErrClosed
	}

	entries, err := g.registry.List(ctx)
	if err != nil {
		// Our own context ending is not the registry being unreadable, and
		// suspending on it would be a self-inflicted outage announced to
		// the SIEM.
		//
		// Two ways it happens, both routine: the process is shutting down
		// (run cancels the loop's context), or this round hit
		// reconcileTimeout. Neither says anything about the file. Treating
		// them as "serving nothing" made every shutdown emit a heartbeat
		// with suspended=true -- the field an operator is told to alert on
		// -- and it was caught by a test that only flaked under load,
		// which is the kind of thing that reaches production as a 3 a.m.
		// page about a gateway that stopped on purpose.
		//
		// Same rule as everywhere else here: failing to measure is not
		// evidence that something changed (ADR-0013, ADR-0020 item 1).
		if ctxErr := ctx.Err(); ctxErr != nil {
			g.log.WarnContext(ctx, "gateway: reconciliation ended before it could read the registry; the fleet is unchanged",
				slog.String("detail", err.Error()))
			return fmt.Errorf("%w: %w", ErrUpstreamUnavailable, err)
		}
		g.suspend()
		g.log.ErrorContext(ctx, "gateway: registry unreadable, serving nothing until it can be read; connections kept",
			slog.String("detail", err.Error()))
		return fmt.Errorf("%w: %w", ErrRegistryUnavailable, err)
	}

	live, dialed := g.fleetSnapshot()
	g.mu.Lock()
	g.lastRound = g.now()
	g.mu.Unlock()

	var failures []error

	// The quota's cross-check against the registry, every round and not
	// only at boot (design/adr/0030-quota-por-analista.md, "Reconcile").
	// Connect refuses to serve anything when the two disagree; this is the
	// same function applied to a registry that changed under a running
	// gateway, which is the only way they come to disagree once the process
	// is up -- an upstream registered, removed or renamed since boot.
	//
	// It cannot refuse to start, so it freezes instead. While frozen,
	// nothing is dialled: not an upstream registered since the last round,
	// not one whose entry changed, not one found dead. The live set can
	// only shrink. That is what makes the boot check hold after boot -- a
	// backend registered in a state CheckQuotaCoverage refuses is never
	// brought up, and so never reaches the Refresh that would route it --
	// and it is cheaper than it sounds: every connection already serving
	// was brought up while the two agreed, and keeps serving.
	//
	// uncounted is the exception to "keeps serving": an entry no account
	// budgets that declares one of a budgeted entry's variables is spending
	// that account's credential without a counter, so it is taken out of
	// the wanted set below, which closes it if it is live.
	uncounted, coverageErr := quotaCoverage(g.quota.Plan(), entries)
	frozen := coverageErr != nil
	if frozen {
		failures = append(failures, coverageErr)
		g.log.ErrorContext(ctx, "gateway: quota policy and upstream registry disagree; no upstream will be brought up until they agree",
			slog.String("detail", coverageErr.Error()))
	}

	want := make(map[string]registry.UpstreamServer, len(entries))
	// unmeasured holds the entries whose signature could not be CHECKED
	// this round, as opposed to refused. See errSignatureUnmeasured.
	unmeasured := map[string]bool{}
	for _, entry := range entries {
		// Same two gates as Connect, and re-run every round on purpose:
		// this is what makes an entry tampered with IN THE DATABASE -- or
		// one whose signature row was removed under require_signed -- take
		// a backend out of service within one interval instead of at the
		// next restart.
		//
		// Not a revoked trust anchor: g.verifier is built once at startup
		// from the config file and nothing reloads it, so removing a key
		// from signer.trusted_keys still needs a restart. This comment
		// claimed otherwise until 15 Sep 2026.
		if err := entry.Validate(); err != nil {
			failures = append(failures, fmt.Errorf("%w: %q: registry entry is not servable: %w", ErrUpstreamUnavailable, entry.Name, err))
			g.log.ErrorContext(ctx, "gateway: upstream refused by the registry's own entry contract",
				slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
			continue
		}
		// Before the signature, so that an unreadable signature store --
		// which leaves a live connection alone -- cannot keep serving an
		// entry that is spending a budgeted credential uncounted. Already
		// reported, with the variable it shares, in coverageErr.
		if uncounted[entry.Name] {
			g.log.ErrorContext(ctx, "gateway: upstream carries a budgeted credential without being budgeted and is not served",
				slog.String("upstream", entry.Name))
			continue
		}
		err := g.verifyEntry(ctx, entry)
		g.noteSignature(ctx, entry.Name, err)
		if err != nil {
			failures = append(failures, err)
			if errors.Is(err, errSignatureUnmeasured) {
				// Not refused: unreadable. The entry stays out of `want`,
				// so nothing new is brought up on an unchecked signature,
				// and it is remembered here so the removal loop below does
				// not mistake "could not check" for "must not serve".
				unmeasured[entry.Name] = true
				g.log.ErrorContext(ctx, "gateway: signature store could not be read; this upstream is neither newly served nor torn down this round",
					slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
				continue
			}
			g.log.ErrorContext(ctx, "gateway: upstream refused by signature check",
				slog.String("upstream", entry.Name), slog.String("detail", err.Error()))
			continue
		}
		want[entry.Name] = entry
	}
	g.forgetSignatures(entries)

	// Sorted so a round's log reads in the same order every time, and so
	// the dials below are deterministic under test.
	liveNames := make([]string, 0, len(live))
	for name := range live {
		liveNames = append(liveNames, name)
	}
	slices.Sort(liveNames)
	wantNames := make([]string, 0, len(want))
	for name := range want {
		wantNames = append(wantNames, name)
	}
	slices.Sort(wantNames)

	var remove []string
	// drop is the part of remove that also loses its routes: a backend that
	// is no longer servable. One closed to be re-dialled -- changed entry,
	// dead process -- keeps them, so a call in the gap is answered with its
	// state and not "unknown tool" (design/adr/0041 item 4).
	drop := map[string]bool{}
	for _, name := range liveNames {
		entry, ok := want[name]
		switch {
		case !ok && unmeasured[name]:
			// Left alone on purpose. The registry still names it and the
			// only thing that failed is reading the signature store, which
			// is the same database file the registry lives in -- so the
			// I/O fault that would close this connection is exactly the
			// one ADR-0020 item 3 promises to survive without killing
			// subprocesses. Already logged above.
		case !ok:
			remove = append(remove, name)
			drop[name] = true
			g.log.InfoContext(ctx, "gateway: upstream is no longer servable per the registry; closing it",
				slog.String("upstream", name))
		case specChanged(dialed[name], entry):
			remove = append(remove, name)
			g.log.InfoContext(ctx, "gateway: upstream entry changed; closing the connection so it can be re-dialed from the new entry",
				slog.String("upstream", name))
		case g.takeGone(name, live[name]):
			// The process behind this connection is gone (ADR-0024). The
			// registry still describes it, so closing it here hands it
			// straight to the dial loop below -- the same rule that brings
			// up an upstream registered since the last round.
			remove = append(remove, name)
			g.log.WarnContext(ctx, "gateway: upstream process died; closing the dead connection and re-dialling it",
				slog.String("upstream", name))
		}
	}

	// Closed before anything is dialed. A changed entry means the running
	// process is executing a specification the operator has replaced, and
	// serving it for the length of a dial is exactly the stale-decision
	// window ADR-0004 rejected.
	// The routes of a servable backend that is not live stay too (its
	// stable listing), and those of one that left servable go now, whether
	// or not it was connected.
	g.mu.RLock()
	for _, rt := range g.routes {
		if _, still := want[rt.route.upstream]; !still && !unmeasured[rt.route.upstream] {
			drop[rt.route.upstream] = true
		}
	}
	g.mu.RUnlock()
	if closedDuringReconcile := g.retire(remove, drop); closedDuringReconcile {
		return ErrClosed
	}

	var toDial []string
	for _, name := range wantNames {
		if _, stillLive := live[name]; stillLive && !slices.Contains(remove, name) {
			continue
		}
		toDial = append(toDial, name)
	}
	if frozen && len(toDial) > 0 {
		// Named, so the operator reading the log knows what the freeze is
		// costing and not only that it is on. Already in the returned
		// error as coverageErr.
		g.log.ErrorContext(ctx, "gateway: upstreams held back while the quota policy and the registry disagree",
			slog.String("upstreams", strings.Join(toDial, ", ")))
		toDial = nil
	}

	// Dialed concurrently, each under the round's whole ctx, for the reason
	// Connect's comment gives: one after another, a backend whose dial
	// never returned spent the whole reconcileTimeout and every entry
	// sorted after it failed with an expired context -- round after round,
	// for as long as it hung, so a healthy upstream registered beside a
	// broken one never came up. Outcomes are read back in name order so
	// the log and the joined error stay deterministic.
	type dialOutcome struct {
		up  Upstream
		err error
	}
	outcomes := make([]dialOutcome, len(toDial))
	var wg sync.WaitGroup
	for i, name := range toDial {
		wg.Add(1)
		go func() {
			defer wg.Done()
			up, err := g.bringUp(ctx, want[name])
			outcomes[i] = dialOutcome{up: up, err: err}
		}()
	}
	wg.Wait()

	add := map[string]Upstream{}
	addEntries := map[string]registry.UpstreamServer{}
	for i, name := range toDial {
		if err := outcomes[i].err; err != nil {
			failures = append(failures, err)
			g.log.ErrorContext(ctx, "gateway: upstream not brought up; it will be retried next round",
				slog.String("upstream", name), slog.String("detail", err.Error()))
			continue
		}
		add[name] = outcomes[i].up
		addEntries[name] = want[name]
	}

	// After the work, and before the new connections are published: this
	// round read the registry, so the fleet is confirmed. It is NOT yet
	// being served -- the table is whatever the last Refresh left, which
	// after a suspension is empty -- so the suspension stands until the
	// Refresh that follows installs a confirmed table.
	g.confirm()
	if closedDuringReconcile := g.adopt(add, addEntries); closedDuringReconcile {
		return ErrClosed
	}
	tried := make(map[string]bool, len(toDial))
	for _, name := range toDial {
		tried[name] = true
	}
	g.writeHealthEvents(ctx, g.settleHealth(wantNames, func(name string) bool { return unmeasured[name] }, frozen, tried, g.now()))
	g.persistHealth(ctx, false)
	return errors.Join(failures...)
}

// specChanged reports whether an entry now describes a different backend
// than the one a live connection was dialed from.
//
// It compares what reaching the backend depends on -- what specFor hands a
// Dialer, plus the names of the credentials resolved into its environment
// -- and nothing else. CreatedAt and UpdatedAt are deliberately excluded:
// a re-registration that changes no field is not a reconnect command, and
// reading UpdatedAt here would quietly make it one (ADR-0020 item 6).
func specChanged(was, now registry.UpstreamServer) bool {
	return was.Transport != now.Transport ||
		was.Command != now.Command ||
		was.URL != now.URL ||
		was.Image != now.Image ||
		!slices.Equal(was.Args, now.Args) ||
		!slices.Equal(was.EnvVarNames, now.EnvVarNames)
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
// anything -- including a backend it just found dead, which it records for
// Reconcile to act on (ADR-0024). An upstream registered since the last
// round is invisible to it, one deregistered since then keeps being served,
// and a backend whose process died is not respawned HERE. That is
// Reconcile's job (ADR-0020), and
// cmd/mcp-gateway's loop runs the two in that order on one tick: Reconcile
// settles which backends are connected, Refresh asks the connected ones
// what they now advertise.
//
// Until ADR-0020 the sentence above ended at "that is Connect's job", and
// Connect ran once, at boot -- so the honest reading was that nothing did
// it at all while the gateway was up.
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
	var events []*healthEvent

	// Every upstream is asked at once, and each answer is handed to the
	// quarantine as it arrives. Asked one after another under the one ctx,
	// as they used to be, an upstream whose tools/list never answered spent
	// the whole refresh budget, and every upstream sorted after it failed
	// with an expired context and kept its previous tool list -- so a rug
	// pull on any of them went un-observed, and stayed served, for as long
	// as the first one hung. That broke the promise above that every
	// upstream that did answer is refreshed regardless. (Ported from the
	// internal tree, 2026-09-24.)
	//
	// Only ListTools runs off this goroutine. Everything that reads or
	// writes gateway state -- markGone, routesFor and its quarantine
	// Observe, the candidate table -- stays here, one answer at a time.
	// Failures are joined in name order so the error does not depend on
	// who answered first.
	type listed struct {
		name string
		defs []ToolDef
		err  error
	}
	answers := make(chan listed, len(names))
	for _, name := range names {
		up := conns[name]
		go func() {
			defs, err := up.ListTools(ctx)
			answers <- listed{name: name, defs: defs, err: err}
		}()
	}
	perUpstream := make(map[string][]error, len(names))
	for range names {
		answer := <-answers
		name, defs, err := answer.name, answer.defs, answer.err
		if err != nil {
			perUpstream[name] = append(perUpstream[name], fmt.Errorf("%w: %q: list tools: %w", ErrUpstreamUnavailable, name, err))
			// Death is the one listing failure that is evidence rather
			// than the absence of it (ADR-0024). Recorded here, acted on
			// by the next Reconcile -- this function closes nothing, by
			// the rule stated in its own doc comment.
			if errors.Is(err, ErrUpstreamGone) {
				events = append(events, g.markGone(name, conns[name]))
				g.log.ErrorContext(ctx, "gateway: upstream process is gone; it will be closed and re-dialled on the next reconciliation",
					slog.String("upstream", name), slog.String("detail", err.Error()))
				// Dead is not "could not measure": its stable listing is
				// what it serves until it is back (ADR-0041 item 4).
				if stable := g.stableRoutesFor(ctx, name); !stable.unmeasured {
					candidates[name] = stable.routes
					continue
				}
			}
			kept := routesOf(previous, name)
			// Two different situations, and the log used to describe both
			// as the first: normally there IS a previous tool list and
			// keeping it is the whole point, but coming out of a suspension
			// the table was emptied, so there is nothing to keep and this
			// upstream routes nothing until a listing succeeds. Saying
			// "keeping its previous tool list" there is a false statement
			// at the moment an operator reads it.
			if len(kept) == 0 {
				g.log.ErrorContext(ctx, "gateway: upstream could not be re-observed and has NO previous tool list to fall back on; it routes nothing until a listing succeeds",
					slog.String("upstream", name), slog.String("detail", err.Error()))
			} else {
				g.log.ErrorContext(ctx, "gateway: upstream could not be re-observed; keeping its previous tool list and quarantine state",
					slog.String("upstream", name), slog.String("detail", err.Error()))
			}
			candidates[name] = kept
			continue
		}

		got := g.routesFor(ctx, name, defs)
		perUpstream[name] = append(perUpstream[name], got.failures...)
		if got.unmeasured {
			// The quarantine store, not the backend, is what failed. Nothing
			// about this upstream can be judged right now, so nothing about
			// it changes: a store that is briefly unreadable must not be able
			// to unroute the fleet. The next tick tries again.
			kept := routesOf(previous, name)
			if len(kept) == 0 {
				g.log.ErrorContext(ctx, "gateway: tool quarantine could not be consulted during refresh and this upstream has NO previous tool list to fall back on; it routes nothing until the store answers",
					slog.String("upstream", name))
			} else {
				g.log.ErrorContext(ctx, "gateway: tool quarantine could not be consulted during refresh; keeping this upstream's previous tool list",
					slog.String("upstream", name))
			}
			candidates[name] = kept
			continue
		}
		candidates[name] = got.routes
		g.recordListing(name, got.routes)
		events = append(events, g.markListed(name, conns[name]))
	}
	for _, name := range names {
		failures = append(failures, perUpstream[name]...)
	}
	// A servable backend with no connection -- down, or being re-dialled --
	// is listed from its stable listing (design/adr/0041 item 4). A
	// quarantine that cannot be read keeps what it had, by the rule above.
	for _, name := range g.servableNotConnected(conns) {
		stable := g.stableRoutesFor(ctx, name)
		if stable.unmeasured {
			candidates[name] = routesOf(previous, name)
			continue
		}
		candidates[name] = stable.routes
	}

	routes, conflicts := mergeRoutes(candidates)
	failures = append(failures, conflicts...)
	// The same check Connect makes, over the table this round built. It is
	// the one that matters most here: a tool a budgeted upstream grew after
	// boot, or every tool of a budgeted upstream Reconcile brought up after
	// boot, reaches the routing table through this line and no other.
	failures = append(failures, g.withholdUndeclaredQuotaTools(ctx, routes)...)

	if closedDuringRefresh := g.swapRoutes(routes); closedDuringRefresh {
		return ErrClosed
	}
	g.writeHealthEvents(ctx, events)
	g.persistHealth(ctx, true)
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
		// First, and before the quarantine sees it: a name outside the
		// charset never gets a quarantine row, an audit row or a route, so
		// nothing downstream ever has to print it (design/adr/0032 item 6).
		// A measurement, like the schema checks below.
		if !validToolName(def.Name) {
			out.failures = append(out.failures, fmt.Errorf("%w: %q: tool name %s is refused: a tool name must match ^[A-Za-z0-9_-]{1,64}$", ErrUpstreamUnavailable, upstream, shownName(def.Name)))
			continue
		}
		// Same place, same reason: every observed definition is stored, so
		// its size is bounded before the store sees it. A measurement.
		if n := definitionSize(def); n > maxToolDefinitionBytes {
			out.failures = append(out.failures, fmt.Errorf("%w: %q: tool %q is refused: its definition is %d bytes, over the %d-byte limit", ErrUpstreamUnavailable, upstream, def.Name, n, maxToolDefinitionBytes))
			continue
		}
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
		obs, err := g.quarantine.Observe(ctx, upstream, identityOf(def))
		if err != nil {
			// A tool whose quarantine state could not be recorded is a tool
			// whose approval we cannot check later. Do not route it -- and
			// say that the failure was ours, not the backend's, so a refresh
			// can tell "this changed" from "this could not be read".
			out.failures = append(out.failures, fmt.Errorf("%w: %q: observe tool %q: %w", ErrUpstreamUnavailable, upstream, def.Name, err))
			out.unmeasured = true
			continue
		}
		g.auditQuarantineEvent(ctx, upstream, obs)

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
// Since 11 Sep 2026 that cross-upstream case can no longer arrive here
// through the registry: producing it requires a registered name containing
// the separator, which registry.UpstreamServer.Validate refuses and Connect
// refuses again on entries read back out of the store. This is kept as the
// second line rather than deleted because it is cheap, because it is what
// the request path would fall back on if either of those checks were ever
// relaxed, and because dropping a name is the only safe answer if a
// collision does appear. Do not read its presence as evidence that the
// registry rule is redundant with it: the case that rule closes is the one
// where there is no collision at all. "threatintel" serving "lookup_ip" and
// "threatintel.staging" serving "debug_exec" produce two distinct names,
// nothing is dropped here, and a grant naming only "threatintel" still
// reaches "threatintel.staging.debug_exec" -- an authorization hole this
// function cannot see, because it is looking for duplicates.
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

	up, err := g.dialer.Dial(ctx, specFor(entry), env)
	if err != nil {
		// redact, even though Dialer's contract already forbids a value in
		// an error: this is the boundary where a buggy adapter's mistake
		// would become a logged secret, and the check costs one pass over
		// a short string.
		return nil, fmt.Errorf("%w: %q: dial: %w", ErrUpstreamUnavailable, entry.Name, redact(err, env))
	}

	// Taken here, after the dial succeeded and while the plaintext is still
	// briefly in hand -- this is the only moment the gateway knows what a
	// running upstream was actually given. Digests, not values: see the
	// creds field.
	//
	// AFTER, not before, since ADR-0020 put this on a timer: recording the
	// digest first meant an upstream that never dials rewrote its entry
	// every round, so "there is a digest for this name" stopped implying
	// "a process is running on it". Nothing reported a false rotation --
	// CredentialDrift filters on the live set -- but the invariant held by
	// that filter rather than by construction, and one is a guarantee while
	// the other is a habit.
	//
	// The `defer clear(env)` above is what makes "briefly" true in code
	// rather than in prose, and it is load-bearing: an attempt to redact
	// call-time errors by holding this map on the connection produced a
	// wrapper that redacted nothing, because by then the map was empty.
	// Keeping a COPY would have bought that redaction by defeating this
	// control; auditFailure drops the upstream's text instead.
	g.rememberCredentials(entry.Name, env)
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
	// First, before the suspension answer: a blocked subject learns nothing
	// about the fleet, not even that it is suspended (ADR-0031). Not
	// audited here, because it never refuses a request the serving adapter
	// admitted: on a context AdmitCaller returned for this same subject the
	// check is that admission, with no second read. It reads -- and
	// refuses -- only for a caller that skipped AdmitCaller, which no
	// serving surface does.
	if err := g.checkBlock(ctx, id.Subject); err != nil {
		return nil, err
	}
	// Suspended is not the same answer as "you may use nothing", for the
	// reason the quarantine-unavailable case above gives: an empty list
	// and a fleet that cannot be confirmed must not look alike to whoever
	// is reading (ADR-0020 item 4).
	if g.isSuspended() {
		return nil, fmt.Errorf("%w: the fleet cannot be confirmed, so nothing is being served", ErrRegistryUnavailable)
	}

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
//  0. Refuse a subject the operator blocked (design/adr/0031), before
//     anything is said about the fleet or the tool.
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
//  4. Reserve the per-analyst quota for every third-party account this
//     tool spends (design/adr/0030-quota-por-analista.md). After step 3 so
//     that a quarantined tool cannot be told apart from an absent one by
//     the answer it gets; before step 5 because that record means the call
//     went out. The debit is taken here and is never reversed. A tool no
//     account names -- every tool, when no [quota] section exists -- is
//     admitted without touching the counter.
//  5. Write the audit record.
//  6. Forward to the upstream.
//  7. Check what came back: its size, always, and its structured content
//     against the tool's own output schema when the tool declared one
//     (design/adr/0014). A result that fails either is refused whole --
//     never truncated, never partly forwarded.
//  8. If the upstream did not complete the call, or step 7 refused what it
//     answered with, APPEND a second record.
//
// # Why the audit record is written before the call, and on refusals too
//
// The record goes in immediately before step 6 because step 6 is the only
// step that leaves this process. Steps 1-4 are decided here -- the quota's
// reservation is the only one of them that touches a disk, and it is the
// same disk this record is about to be written to a line later; a call in
// flight to a backend can hang, be cancelled, or
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
// A result refused at step 7 IS a failure and does get one. The
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
// Policy's own error, wrapping access.ErrForbidden. A call refused for
// quota is the second exception, on the same reasoning and with the same
// bound: it returns the quota's own error, wrapping quota.ErrExhausted,
// because what that discloses is the operator's published limit and the
// caller's own consumption of it -- a fact about the caller, told to the
// caller -- and never which tools exist or which are under suspicion. A
// quota that could not be ESTABLISHED is not that exception: it returns
// quota.ErrUnavailable, which the serving adapter reports as an internal
// error, because which of this gateway's stores is unwell is none of the
// caller's business. Collapsing the forbidden case into
// ErrUnknownTool would break the distinction access.Policy exists to draw
// (CONCEPTS.md §3.3) and would tell an analyst who simply lacks a role
// that the tool does not exist, sending them to debug the wrong thing. The
// residual leak is accepted and bounded: the tool names in a Role are an
// operator-authored list of names, not secrets, whereas which tool is
// currently under suspicion is -- and that is the fact the opaque error
// protects.
func (g *Gateway) Dispatch(ctx context.Context, c Caller, namespacedTool string, args json.RawMessage) (res Result, err error) {
	// First, so it covers everything below (ADR-0035): a panic anywhere in
	// this call -- an adapter, the scrub, a store -- becomes one audited
	// row and ErrInternal, instead of the SDK's handler goroutine taking
	// the process down for every analyst. dispatched says which row.
	dispatched := false
	defer g.containPanic(ctx, c, namespacedTool, &dispatched, &res, &err)

	// The kill switch next (ADR-0031), ahead of every answer below: a
	// blocked subject is told "forbidden" whatever they named, so the
	// refusal cannot be used to tell a real tool from an invented one. The
	// serving adapter already asked at AdmitCaller, and on the context it
	// returned this is that answer, not a second read; this is the same
	// check at the gate every surface shares, for a caller that did not.
	if err := g.checkBlock(ctx, c.Identity.Subject); err != nil {
		g.refuseBlocked(ctx, c, namespacedTool, targetOf(namespacedTool), err)
		return Result{}, err
	}

	// Before the routing table is consulted at all: while the fleet is
	// suspended the table is empty by construction, and answering "unknown
	// tool" would tell a caller -- and the audit trail -- that a tool they
	// used this morning has been removed, when what happened is that the
	// registry cannot be read (ADR-0020 item 4).
	if g.isSuspended() {
		g.auditRefusal(ctx, c, namespacedTool, targetOf(namespacedTool), reasonRegistryUnavailable)
		return Result{}, fmt.Errorf("%w: the fleet cannot be confirmed, so nothing is being served", ErrRegistryUnavailable)
	}

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

	// Availability (design/adr/0041 item 2). After Authorize and the
	// quarantine, so only a caller who may call this approved tool learns
	// the state of its backend -- anybody else got the answer above, byte
	// for byte what it was. Before the slot and the quota, so a call that
	// never leaves the process spends neither. A backend in maintenance, or
	// with no live connection, is answered with its state and not dialled.
	maint, _ := g.readMaintenance(ctx)
	now := g.now()
	gwNotice := gatewayNotice(maint, now)
	if ue := g.availability(rt.route.upstream, up, maint, now); ue != nil {
		g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, ue.reason())
		return Result{}, ue
	}

	// The per-analyst concurrency cap (design/adr/0035), fail-fast.
	//
	// After admit, for the reason the quota is: a quarantined tool must
	// stay indistinguishable from one that does not exist. Before the
	// quota, because the debit is never reversed -- a call refused here
	// would otherwise have spent budget for a call that never left. Before
	// the allowed row, because that row means the call was dispatched.
	// Held until the call, the result check and the scrub are done.
	release, ok := g.slots.acquire(c.Identity.Subject)
	if !ok {
		g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, reasonConcurrencyLimited)
		return Result{}, fmt.Errorf("%w (limit %d)", ErrConcurrencyLimited, g.slots.max)
	}
	defer release()

	// The per-analyst quota, and this is the only place it can go
	// (design/adr/0030-quota-por-analista.md decision 5).
	//
	// After admit, because a quarantined tool must stay indistinguishable
	// from one that does not exist: answering "you are over your limit"
	// for it would confirm it exists, and would do it through the newest
	// path rather than the one ADR-0007 hardened.
	//
	// Before the OutcomeAllowed record, because that row means the call
	// was dispatched (ADR-0012 §1). A refusal written after it would leave
	// the trail asserting something that did not happen, and the trail is
	// the only attribution this system has.
	//
	// The debit happens here, before the call, and is never reversed. A
	// debit taken on the answer would leave free exactly the case this
	// control exists for -- the loop whose calls never come back -- and
	// the gateway cannot learn whether the third party charged anyway: the
	// fan-out happens inside the upstream's process, so a call that fails
	// at the backend may well have already spent the provider's quota. The
	// error is conservative in the right direction. Over-counting protects
	// the budget; under-counting burns it.
	if err := g.quota.Admit(ctx, c.Identity.Subject, namespacedTool, g.now()); err != nil {
		if errors.Is(err, quota.ErrExhausted) {
			g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, reasonQuotaExhausted)
			// Returned rather than collapsed into ErrUnknownTool, which is
			// the same deliberate exception to opacity access.ErrForbidden
			// already is, on the same test: what leaks is the operator's
			// own published policy, not the SOC's security posture. The
			// serving adapter reduces it to one constant message for its
			// own class -- see internal/gateway/httpapi/errors.go, where
			// the forbidden error's text does not reach a client either.
			return Result{}, err
		}
		// Unreadable, unwritable, or a reservation built wrong: refuse.
		// Fail-closed, with no distinction between not being able to read
		// the counter and not being able to write it, because whoever
		// wants free quota has no preference between the two.
		g.log.ErrorContext(ctx, "gateway: refusing call whose quota could not be established",
			slog.String("tool", namespacedTool), slog.String("detail", err.Error()))
		g.auditRefusal(ctx, c, namespacedTool, rt.route.upstream, reasonQuotaUnavailable)
		return Result{}, err
	}

	if err := g.record(ctx, c, namespacedTool, rt.route.upstream, audit.OutcomeAllowed, ""); err != nil {
		g.log.ErrorContext(ctx, "gateway: refusing unauditable call",
			slog.String("tool", namespacedTool), slog.String("detail", err.Error()))
		return Result{}, err
	}
	dispatched = true

	// The gateway's own ceiling on one call (ADR-0025), derived from the
	// caller's context so a client that disconnects still cuts its call
	// immediately -- whichever comes first wins. Without it, a backend that
	// accepted the call and never answered held this goroutine and that
	// upstream's connection until the process restarted, and the audit
	// reason `upstream timed out` described an event nothing produced.
	callCtx, cancelCall := context.WithTimeout(ctx, g.callTimeout)
	defer cancelCall()

	res, err = up.CallTool(callCtx, rt.route.originalName, args)
	if err != nil {
		// An analyst's call is usually where a dead backend is noticed
		// first: Refresh runs on a tick, and this runs whenever somebody
		// works. Recording it here means the repair starts from the next
		// reconciliation rather than from the next listing.
		gone := errors.Is(err, ErrUpstreamGone)
		if gone {
			if ev := g.markGone(rt.route.upstream, up); ev != nil {
				g.writeHealthEvents(ctx, []*healthEvent{ev})
				g.persistHealth(ctx, false)
			}
		}
		g.auditFailure(ctx, c, namespacedTool, rt.route.upstream, err)
		// What the caller is told is built from the gateway's own state and
		// never from err, which is the backend's (ADR-0041 items 2 and 3):
		// the backend died during this call, or it failed it.
		switch {
		case gone:
			g.mu.RLock()
			next := g.nextAttempt()
			g.mu.RUnlock()
			return Result{}, &UnavailableError{Backend: rt.route.upstream, State: StateReconnecting, Since: now,
				NextAttempt: next, Gateway: gwNotice, cause: ErrUpstreamGone}
		case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			return Result{}, &BackendFailedError{Backend: rt.route.upstream, Gateway: gwNotice, cause: context.DeadlineExceeded}
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrInternal):
			return Result{}, fmt.Errorf("gateway: call %q: %w", namespacedTool, err)
		default:
			return Result{}, &BackendFailedError{Backend: rt.route.upstream, Gateway: gwNotice, cause: ErrBackendFailed}
		}
	}
	// Step 7, added by design/adr/0014: the backend answered, and what it
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
	// Step 7b (24 set 2026): the credential this upstream was spawned with
	// is taken out of what it answered. auditFailure already drops an
	// upstream's error TEXT because "401: token=... rejected" is an
	// ordinary thing for an API client to say -- and an MCP SDK server
	// turns exactly that handler error into an IsError result, which
	// arrived here verbatim and went to the analyst and their model. The
	// whole point of this gateway is that the backend's credential never
	// reaches that side. After checkResult on purpose: the size ceiling
	// and the output schema judge the bytes the upstream sent.
	scrubbed, err := g.scrubResult(ctx, rt.route.upstream, res)
	if err != nil {
		g.auditFailure(ctx, c, namespacedTool, rt.route.upstream, err)
		return Result{}, fmt.Errorf("gateway: call %q: %w", namespacedTool, err)
	}
	// After the checks and the scrub, so the notice counts against nothing
	// and never enters structuredContent (ADR-0041 item 6).
	scrubbed.Notice = gwNotice
	return scrubbed, nil
}

// ErrResultUnscrubbable means a result carried an injected credential and
// could not be rewritten without it into something that is still JSON.
// It is refused whole, the same way an oversized result is (ADR-0014):
// forwarding it would forward the secret.
var ErrResultUnscrubbable = errors.New("gateway: result carried an injected credential and could not be redacted")

// scrubResult replaces, in res.Content and res.StructuredContent, every
// credential value this upstream was handed at dial time.
//
// The values are RE-RESOLVED from the vault here, not remembered from the
// dial. bringUp's `defer clear(env)` is a deliberate control -- the
// plaintext lives only while it is being handed over -- and keeping a
// copy on the connection to redact with would defeat it. What IS kept is
// the per-upstream digest set (rememberCredentials), which names the
// variables; a freshly resolved value whose digest matches is, byte for
// byte, what the upstream holds. Resolve is a map lookup behind a stat
// (sopsage, ADR-0023), the same price CredentialDrift pays every tick.
//
// Known residual, stated rather than hidden: after a rotation the vault
// holds the NEW value while the running upstream still holds the old
// one, so an echo of the old value is not caught. CredentialDrift already
// reports that state as something to act on. An echo in another encoding
// (base64, split across blocks) is not caught either: this is exact
// matching of a known string, not detection.
func (g *Gateway) scrubResult(ctx context.Context, upstream string, res Result) (Result, error) {
	g.mu.RLock()
	names := make([]string, 0, len(g.creds[upstream]))
	for name := range g.creds[upstream] {
		names = append(names, name)
	}
	g.mu.RUnlock()
	if len(names) == 0 {
		return res, nil
	}
	slices.Sort(names)

	env := make(map[string]string, len(names))
	defer func() { clear(env) }()
	for _, name := range names {
		secret, err := g.vault.Resolve(ctx, name)
		if err != nil {
			// Not fatal to the call: the vault being briefly unreadable is
			// not evidence the result holds a secret, and CredentialDrift
			// makes the same call. Only the variable name is logged.
			g.log.ErrorContext(ctx, "gateway: could not re-read a credential to redact it from a tool result; that value is not being scrubbed from this result",
				slog.String("upstream", upstream),
				slog.String("env_var_name", name),
				slog.String("detail", err.Error()))
			continue
		}
		env[name] = secret.Value()
	}

	var hit []string
	var err error
	if res.Content, err = scrubJSON(res.Content, env, &hit); err != nil {
		return Result{}, err
	}
	if res.StructuredContent, err = scrubJSON(res.StructuredContent, env, &hit); err != nil {
		return Result{}, err
	}
	if len(hit) > 0 {
		// The operator wants to know a backend echoes its key -- it will do
		// it in its own logs too. Names only, never the value.
		slices.Sort(hit)
		g.log.WarnContext(ctx, "gateway: upstream echoed an injected credential in a tool result; redacted before it reached the client",
			slog.String("upstream", upstream),
			slog.Any("env_var_names", slices.Compact(hit)))
	}
	return res, nil
}

// scrubJSON masks every value of env found in raw with the redaction
// placeholder, appending the variable's name to hit when it did.
//
// raw is JSON text, so a value appears inside a string literal as a JSON
// encoder wrote it -- itself when nothing needs escaping, escaped when it
// holds <, >, &, " or \ -- and a backend that formatted it with %q or
// embedded a JSON payload in its message puts that rendering in, escaped
// once more. [jsonRenderingsOf] lists all of them, and [maskSpans] masks
// the union of their matches in one pass, so a short value inside a longer
// one cannot split it. The bare form of a value JSON must escape is never
// matched -- it could straddle structure and corrupt the document rather
// than a string inside it.
func scrubJSON(raw json.RawMessage, env map[string]string, hit *[]string) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	names := make([]string, 0, len(env))
	for name, value := range env {
		if value != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	forms := make([][]string, len(names))
	for i, name := range names {
		forms[i] = jsonRenderingsOf(env[name])
	}
	out, matched := maskSpans(string(raw), forms)
	changed := false
	for i, m := range matched {
		if m {
			changed = true
			*hit = append(*hit, names[i])
		}
	}
	if !changed {
		return raw, nil
	}
	if !json.Valid([]byte(out)) {
		// A value short or common enough to match JSON syntax itself. Fail
		// closed: the one thing this must not do is forward the secret.
		return nil, ErrResultUnscrubbable
	}
	return json.RawMessage(out), nil
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
// # What bounds it
//
// Rows are capped per source (design/adr/0027, the authLimit below): past
// the ceiling one `auth failures rate-limited` row marks the window and the
// rest reach only the log. A forged token no longer costs the IdP anything
// either: the verifier refetches the JWKS at most once per 30s
// (design/adr/0035). What neither bounds is the TLS and HTTP work of the
// request itself; that belongs to the reverse proxy in front.
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
	// Detached, like auditRefusal's and auditFailure's writes and for the
	// same reason -- and this was the one path that was not.
	//
	// The record of a rejected request is the ONLY trace that request ever
	// existed: there is no route, no tool, no analyst, nothing else to
	// correlate later. Writing it under the request's own context means a
	// client that disconnects cancels the evidence of its own attempt, and
	// a client that is grinding tokens disconnects constantly.
	//
	// Measured under a flood that made the write slow: with the client
	// closing 10 ms after sending, 9 of 50 auth-failure records were lost
	// (0 of 50 with no flood). The load that makes this path worth
	// auditing is the load that made it silently fail to audit.
	// The ceiling on how many of these reach the durable trail (ADR-0027).
	// Consulted AFTER the log line above, which is never limited: slog to a
	// file sustains twenty times what the database does, so the exact count
	// survives there for free.
	//
	// The two halves of this function have to ship together. Detaching the
	// write (above) stops an attacker cancelling the evidence of their own
	// attempt, and on its own it would make each rejected request hold a
	// goroutine for up to five seconds under exactly the load that makes
	// the write slow. The ceiling is what bounds that.
	g.mu.Lock()
	verdict := g.authLimit.classify(source, g.now())
	g.mu.Unlock()

	reason := reasonAuthFailed
	switch verdict {
	case authDrop:
		return
	case authMark:
		reason = reasonAuthFlood
	}

	writeCtx, cancel := auditWriteCtx(ctx)
	defer cancel()
	if err := g.record(writeCtx, c, authenticationTool, gatewayItself, audit.OutcomeDenied, reason); err != nil {
		g.log.ErrorContext(ctx, "gateway: unauthenticated request was not audited",
			slog.String("detail", err.Error()))
	}
}

// AdmitCaller is the per-analyst kill switch at the front door
// (design/adr/0031-bloqueio-imediato-por-analista.md): the serving adapter
// calls it right after the token verified, before anything else is done
// for the request.
//
// A blocked subject gets access.ErrSubjectBlocked, which wraps
// access.ErrForbidden, so the caller hears the one constant "forbidden" and
// nothing about why. A blocklist that cannot be read refuses too, with an
// error wrapping access.ErrBlocklistUnavailable, which is NOT forbidden: a
// serving adapter reports it as an internal error. Both are written to the
// trail the way every other refusal is, as a denied row with the verified
// subject, the source address and the reason the caller is not told.
//
// The table is read on every call, which is what makes a block reach a
// token that is still valid on its very next request, with no restart and
// no cache to go stale. It is one primary-key read per request: the
// returned context carries the admission, bound to this subject, and
// ListTools and Dispatch on it reuse the answer instead of reading again.
// So a block committed while a request is in flight takes effect on the
// next request, and never refuses the admitted one half-way with no row on
// the trail.
//
// A request whose context is already done -- the client hung up -- is
// refused with the context's error and not recorded: nothing is served to
// it, and writing "blocklist unavailable" would be a false alarm about the
// kill switch's store that any caller could raise at will.
func (g *Gateway) AdmitCaller(ctx context.Context, c Caller) (context.Context, error) {
	if err := g.readBlock(ctx, c.Identity.Subject); err != nil {
		g.refuseBlocked(ctx, c, authenticationTool, gatewayItself, err)
		return ctx, err
	}
	return context.WithValue(ctx, admittedKey{}, c.Identity.Subject), nil
}

// admittedKey is the unexported, and so unforgeable from outside this
// package, context key under which AdmitCaller records the subject it
// found unblocked for this request.
type admittedKey struct{}

// refuseBlocked writes the one audit row for a request checkBlock refused,
// with the reason that matches the error -- or none, when the error is the
// caller's own context ending (see AdmitCaller).
func (g *Gateway) refuseBlocked(ctx context.Context, c Caller, tool, target string, err error) {
	switch {
	case errors.Is(err, access.ErrSubjectBlocked):
		g.auditRefusal(ctx, c, tool, target, reasonSubjectBlocked)
	case ctx.Err() != nil:
		g.log.DebugContext(ctx, "gateway: request ended before its blocklist check",
			slog.String("subject", c.Identity.Subject), slog.String("detail", err.Error()))
	default:
		g.log.ErrorContext(ctx, "gateway: refusing request whose blocklist could not be read",
			slog.String("detail", err.Error()))
		g.auditRefusal(ctx, c, tool, target, reasonBlocklistUnavailable)
	}
}

// checkBlock is the kill switch as ListTools and Dispatch apply it: the
// admission AdmitCaller recorded on ctx for this very subject, else a
// fresh read. It is the one implementation behind all three, so they
// cannot disagree about who is blocked.
func (g *Gateway) checkBlock(ctx context.Context, subject string) error {
	if admitted, ok := ctx.Value(admittedKey{}).(string); ok && admitted == subject {
		return nil
	}
	return g.readBlock(ctx, subject)
}

// readBlock asks the blocklist about subject and reduces the answer to
// nil, access.ErrSubjectBlocked, the context's own error when the request
// has already ended, or an error wrapping access.ErrBlocklistUnavailable.
func (g *Gateway) readBlock(ctx context.Context, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	blocked, err := g.blocklist.Blocked(ctx, subject)
	switch {
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil && errors.Is(err, access.ErrBlocklistUnavailable):
		return err
	case err != nil:
		return fmt.Errorf("%w: %w", access.ErrBlocklistUnavailable, err)
	case blocked:
		return access.ErrSubjectBlocked
	}
	return nil
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
	g.dialed = map[string]registry.UpstreamServer{}
	g.creds = map[string]map[string]string{}
	g.gone = map[string]Upstream{}
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
			return signatureRefusal{error: fmt.Errorf("%w: %q: no signature, and unsigned entries are refused", ErrUpstreamUnavailable, entry.Name), unsigned: true}
		}
		g.log.WarnContext(ctx, "gateway: upstream entry is unsigned",
			slog.String("upstream", entry.Name))
		return nil
	case err != nil:
		// The store is there but unreadable. Fail closed, same reasoning
		// as ADR-0004 gives for the registry: an integrity decision made
		// without the state that governs it is the decision an attacker
		// wants.
		//
		// Fail closed means "do not START serving this entry on the
		// strength of a check that did not run". It does not mean "tear
		// down what is already running", and errSignatureUnmeasured is how
		// Reconcile tells the two apart -- see its doc comment.
		return fmt.Errorf("%w: %w: %q: %w", ErrUpstreamUnavailable, errSignatureUnmeasured, entry.Name, err)
	}

	if err := g.verifier.Verify(entry, sig); err != nil {
		return signatureRefusal{error: fmt.Errorf("%w: %q: %w", ErrUpstreamUnavailable, entry.Name, err)}
	}
	return nil
}

// withholdUndeclaredQuotaTools deletes from routes every tool of a
// budgeted upstream that no quota account charges and quota.free_tools
// does not excuse, and returns the error saying so (none if there were
// none).
//
// Connect and Refresh call it on every table they build, immediately
// before installing it, and those are the only two places a routing table
// is built: Reconcile only ever removes routes (retire) and never adds
// one. That is what makes "an undeclared tool of a budgeted upstream is
// not routed" hold for every path a tool can take into the table -- at
// boot, as a tool a backend grew and an operator approved, and as every
// tool of a budgeted upstream Reconcile brought up after boot.
//
// Fatal to the route, by the same argument as ErrQuotaMisconfigured
// everywhere else: a budgeted upstream serving a tool nobody costed is a
// budget this gateway reports as protected and is not. Refusing to serve is
// louder than serving with a hole, and the operator's fix is one line in
// the config file (ADR-0030 decision 11).
func (g *Gateway) withholdUndeclaredQuotaTools(ctx context.Context, routes map[string]routedTool) []error {
	undeclared := UndeclaredQuotaTools(g.quota.Plan(), slices.Collect(maps.Keys(routes)))
	if len(undeclared) == 0 {
		return nil
	}
	for _, tool := range undeclared {
		delete(routes, tool)
	}
	g.log.ErrorContext(ctx, "gateway: tools of a budgeted upstream are not declared and are not being routed",
		slog.Int("tools", len(undeclared)), slog.String("detail", strings.Join(undeclared, ", ")))
	// One error naming all of them, not one per tool: an operator fixing a
	// config file should see the whole list in one round.
	return []error{fmt.Errorf(
		"%w: %d tool(s) of a budgeted upstream are not routed because no account charges them and "+
			"quota.free_tools does not excuse them: %s. "+
			"Each would have been a permanent uncounted path against a budget this gateway reports as "+
			"protected. Add each to the tools of the account it spends, or to quota.free_tools to state "+
			"that it spends nothing, and it will be served again",
		ErrQuotaUndeclaredTool, len(undeclared), strings.Join(undeclared, ", "))}
}

// CheckQuotaCoverage reports whether every account in plan names an
// upstream that is in entries, and whether any entry carries a budgeted
// credential without being budgeted itself.
//
// Exported because it has two callers and must not become two rules. The
// Gateway applies it at Connect, where a disagreement stops the process
// from serving, and at every Reconcile, where it stops the fleet from
// growing; `mcp-gateway quota list` applies the same function to say so
// before the operator restarts anything. A predicate restated for a second
// caller eventually answers differently, and the operator fixes what the
// console listed only to meet a different error from the same file.
//
// config.Validate cannot make this check: the file is parsed before any
// database is opened, so it has no registry to compare against.
//
// Two ways to fail, and both mean the same thing -- an operator believes a
// third party's budget is protected and it is not:
//
//   - The named upstream is not registered. Nothing routes to it, so the
//     limit governs no call. Usually a rename on one side of the pair, or
//     a deregistered backend somebody expected to come back -- and a
//     rename is the dangerous one, because the backend under its new name
//     spends the account with no account naming it.
//   - A budgeted entry and an entry no account names declare the same
//     environment variable. One variable name is one credential, so calls
//     through the second spend the account uncounted (ADR-0030 decision
//     12).
//
// There is no credential-mode clause. Every entry in this gateway's
// registry shares its credential among all analysts; that is the only mode
// there is, and it is the premise a per-analyst count rests on.
//
// Every disagreement is reported, not just the first, so an operator
// fixing a config file sees the whole list at once.
//
// The reverse direction is deliberately NOT an error: an upstream that no
// quota account names is the ordinary case (casemgmt, logsearch and
// docsearch have no external budget), and requiring a block per upstream
// would be requiring a limit where there is nothing to limit.
func CheckQuotaCoverage(plan *quota.Plan, entries []registry.UpstreamServer) error {
	_, err := quotaCoverage(plan, entries)
	return err
}

// quotaCoverage is CheckQuotaCoverage, plus the names of the entries the
// shared-credential clause implicates: the ones no account budgets that
// declare a budgeted entry's variable. Reconcile needs those names to stop
// serving exactly them; every other caller needs only the verdict.
func quotaCoverage(plan *quota.Plan, entries []registry.UpstreamServer) (map[string]bool, error) {
	if plan == nil {
		// A nil plan is not "no accounts": it is a caller that has not
		// built one. quota.NewGate refuses a nil plan for the same reason,
		// and answering "everything is fine" here would be the one way to
		// get a pass out of this function without declaring anything.
		return nil, fmt.Errorf("%w: no quota plan was built; pass the result of quota.NewPlan", ErrQuotaMisconfigured)
	}
	providers := plan.Providers()
	if len(providers) == 0 {
		return nil, nil
	}

	registered := make(map[string]bool, len(entries))
	// Which registered entries carry which environment variable names. An
	// account's budget is a THIRD-PARTY account, and what reaches it is the
	// key -- so two entries holding the same variable name hold the same
	// key, and a limit declared over one of them governs half the traffic
	// that spends it.
	//
	// Measured on 14 set 2026: two entries `threatintel` and
	// `threatintel2`, both carrying THREATINTEL_VIRUSTOTAL_API_KEY, with an
	// account declared over `threatintel`. A thousand calls through
	// `threatintel2` cost zero reservations, the one control call through
	// `threatintel` cost one, and this function returned nil. The realistic
	// path there is not an attacker -- registering an entry needs operator
	// access and a signature -- it is a `threatintel-v2` somebody stood up
	// to try a new image and forgot to mention in [[quota.provider]]. In
	// this gateway that entry would be dialled by the next Reconcile,
	// without a restart, which is why Reconcile runs this too.
	byEnvVar := map[string][]string{}
	for _, entry := range entries {
		registered[entry.Name] = true
		for _, name := range entry.EnvVarNames {
			byEnvVar[name] = append(byEnvVar[name], entry.Name)
		}
	}
	budgeted := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		budgeted[p.Upstream] = struct{}{}
	}

	var problems []error
	for _, p := range providers {
		if !registered[p.Upstream] {
			problems = append(problems, fmt.Errorf(
				"quota account %q charges tools of upstream %q, which is not registered: "+
					"the limit would govern no call, so the account's budget is unprotected -- "+
					"register the upstream, or remove the [[quota.provider]] block",
				p.Name, p.Upstream))
		}
	}

	// The second direction, over the credential rather than the name.
	uncounted := map[string]bool{}
	for _, entry := range entries {
		if _, counted := budgeted[entry.Name]; !counted {
			continue
		}
		for _, envVar := range entry.EnvVarNames {
			for _, other := range byEnvVar[envVar] {
				if other == entry.Name {
					continue
				}
				if _, alsoCounted := budgeted[other]; alsoCounted {
					continue
				}
				uncounted[other] = true
				problems = append(problems, fmt.Errorf(
					"upstream %q is budgeted and upstream %q is not, and both declare %s: "+
						"one environment variable name is one credential, so calls through %q spend the same "+
						"third-party account without being counted -- budget %q too, or stop it carrying that credential",
					entry.Name, other, envVar, other, other))
			}
		}
	}

	if len(problems) == 0 {
		return nil, nil
	}
	return uncounted, errors.Join(append([]error{ErrQuotaMisconfigured}, problems...)...)
}

// UndeclaredQuotaTools returns, sorted, every tool in served that belongs
// to a budgeted upstream and that the plan neither charges nor lists as
// free.
//
// It is the other half of CheckQuotaCoverage, and it exists because that
// function checks the direction that cannot hurt you. "This account names
// an upstream that is not registered" is a limit governing nothing, which
// is visible the moment anybody calls the tool. "This upstream is budgeted
// and serves a tool no account mentions" is the opposite: everything
// works, `quota list` exits 0, the counter moves for the tools that were
// listed, and the account is spent through the ones that were not until
// the provider starts answering 429 inside the backend process, where the
// gateway cannot see it.
//
// Why it runs over ROUTES and not over the account's declared tool list:
// routes are what the backend actually advertises and the gateway would
// dispatch once Tool Quarantine allows it. A tool the backend has just
// added is in the table as pending -- admit refuses it per call -- and is
// withheld here all the same, so the operator hears that it is uncosted in
// the round that first sees it, before anybody approves it. Approval alone
// never routes it: approving a tool of a budgeted upstream IS a budget
// decision, and the budget half is a line in the config file.
//
// An upstream no account names is not checked at all; requiring a
// declaration per tool there would be paperwork with no control behind it.
//
// # Why this does not stop the gateway, when the account-level check does
//
// CheckQuotaCoverage has no safe partial behaviour available to it: an
// account naming an absent upstream governs nothing, and no subset of the
// fleet can be served with that fixed. Here there is one -- do not route
// the tool -- and it closes the hole at exactly the granularity of the
// hole, which is ADR-0004's per-entry rule one level down. A backend that
// grows a tool would otherwise take the gateway down at the next restart,
// an outage caused by somebody else shipping a feature.
func UndeclaredQuotaTools(plan *quota.Plan, served []string) []string {
	if plan == nil {
		return nil
	}
	providers := plan.Providers()
	if len(providers) == 0 {
		return nil
	}
	budgeted := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		budgeted[p.Upstream] = struct{}{}
	}

	var undeclared []string
	for _, tool := range served {
		upstream, _, ok := SplitNamespaced(tool)
		if !ok {
			continue
		}
		if _, counted := budgeted[upstream]; !counted {
			continue
		}
		if plan.IsDeclared(tool) {
			continue
		}
		undeclared = append(undeclared, tool)
	}
	slices.Sort(undeclared)
	return undeclared
}

// record writes one audit record for an attempted call and returns any
// failure to the caller, which refuses the call on it.
func (g *Gateway) record(ctx context.Context, c Caller, tool, upstream string, outcome audit.Outcome, reason string) error {
	rec := audit.Record{
		// Subject, not Name: the IdP's stable identifier is what the trail
		// attributes to, since a display name can change under it.
		AnalystIdentity: c.Identity.Subject,
		// Name beside it, for the reader only (design/adr/0037). Every row
		// this system writes for a caller passes through here, so this is
		// the one place it is set. Rows nobody authenticated for -- the
		// gateway's own events, an unauthenticated request -- build a
		// Caller with no Name and so carry none; DisplayName also drops a
		// name that only repeats the subject.
		AnalystName:    audit.DisplayName(c.Identity.Subject, c.Identity.Name),
		Tool:           tool,
		TargetUpstream: upstream,
		Timestamp:      g.now(),
		Outcome:        outcome,
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
	// Counted here, after the durable write, because here is the only
	// place this system writes an audit record at all -- Dispatch,
	// auditRefusal, auditFailure, RecordAuthFailure and RecordRefusedProbe
	// all pass through. That is what lets Status say exactly what the
	// numbers are: rows written, by outcome, and not an approximation of
	// "calls" maintained in parallel with the thing it approximates.
	switch outcome {
	case audit.OutcomeAllowed:
		g.allowed.Add(1)
	case audit.OutcomeDenied:
		g.denied.Add(1)
	case audit.OutcomeFailed:
		g.failed.Add(1)
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
	// Normalised here, for every refusal path, and not only in
	// RecordRefusedProbe: audit.Record.Validate refuses an empty Tool, so
	// Dispatch(ctx, c, "", ...) used to be refused with no row at all -- a
	// denial that escaped the trail its doc says every refusal reaches
	// exactly once (ported from the internal line, 28 Sep 2026).
	if strings.TrimSpace(tool) == "" {
		tool = unnamedTool
	}
	g.log.WarnContext(ctx, "gateway: refused dispatch",
		slog.String("subject", c.Identity.Subject),
		slog.String("source", c.SourceAddress),
		slog.String("tool", tool),
		slog.String("upstream", upstream),
		slog.String("reason", reason),
	)
	// Same detachment as auditFailure, for the same reason: a client that
	// disconnects mid-request cancels the context, and the record of what
	// it was refused for would go with it.
	writeCtx, cancel := auditWriteCtx(ctx)
	defer cancel()
	if err := g.record(writeCtx, c, tool, upstream, audit.OutcomeDenied, reason); err != nil {
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
		// The upstream's own text is NOT logged, and this used to be the one
		// place it was. A backend that echoes the credential it was handed --
		// `401: token=...` is an ordinary thing for an API client to say --
		// put that value straight into this line, which is shipped off the
		// box to a SIEM and read by everyone with access to it. Confirmed by
		// TestDispatch_AnUpstreamEchoingItsCredentialDoesNotLeakItIntoTheLog.
		//
		// Redacting it instead would mean holding the resolved values for the
		// connection's lifetime, which defeats the `defer clear(env)` in
		// bringUp -- a control this project enforces rather than merely
		// documents. Losing the text costs the difference between "the
		// backend rejected our credential" and "the backend is down"; that
		// distinction is recoverable from the backend's own logs, and a
		// credential in ours is not recoverable at all.
		slog.String("error_class", fmt.Sprintf("%T", cause)),
	)
	writeCtx, cancel := auditWriteCtx(ctx)
	defer cancel()
	if err := g.record(writeCtx, c, tool, upstream, audit.OutcomeFailed, reason); err != nil {
		g.log.ErrorContext(ctx, "gateway: failed dispatch was not audited -- the trail shows this call as allowed and nothing else",
			slog.String("tool", tool), slog.String("detail", err.Error()))
	}
}

// auditQuarantineEvent writes the row for a quarantine transition, if obs
// carries one (design/adr/0032 item 4).
//
// Before it, endpoint.go discarded what Observe returned: a tool appearing
// and an approved tool being rewritten -- the two events this component
// exists to catch -- produced no log line, no audit row and nothing the
// SIEM could alert on. The gateway still failed closed; the operator just
// found out from an analyst's "quarantined".
//
// The store decides the transition inside the transaction that recorded
// it, so this runs once per transition whatever the refresh interval. The
// row is written after the state it describes is committed; if the write
// fails the state stands and the loss is logged, which is the same order
// and the same trade as every other refusal row here.
func (g *Gateway) auditQuarantineEvent(ctx context.Context, upstream string, obs quarantine.Observation) {
	var reason string
	switch obs.Event {
	case quarantine.EventFirstSeen:
		reason = fmt.Sprintf("%s: sha256:%s", reasonToolFirstSeen, obs.ObservedHash)
		g.log.WarnContext(ctx, "gateway: new tool observed; it is pending and not served until an operator approves it",
			slog.String("upstream", upstream), slog.String("tool", obs.ToolName),
			slog.String("fingerprint", shortHash(obs.ObservedHash)))
	case quarantine.EventChanged:
		reason = fmt.Sprintf("%s: sha256:%s -> sha256:%s", reasonToolChanged, obs.ApprovedHash, obs.ObservedHash)
		g.log.ErrorContext(ctx, "gateway: an APPROVED tool changed its definition; it is no longer served",
			slog.String("upstream", upstream), slog.String("tool", obs.ToolName),
			slog.String("approved", shortHash(obs.ApprovedHash)), slog.String("observed", shortHash(obs.ObservedHash)))
	default:
		return
	}
	g.auditEvent(ctx, Namespaced(upstream, obs.ToolName), upstream, reason)
}

// shortHash is the first twelve hex digits of a fingerprint, for log lines.
// The full value is in the audit row the same event writes, which is where
// an operator matches it against `tool show`; the log carries the prefix
// only, so that no 64-hex run in it can be mistaken for -- or hide -- a
// credential digest (TestCredentialDrift_TheKeyNeverLeaves).
func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// signatureRefusal is what verifyEntry returns for an entry it refused on
// the evidence -- as opposed to errSignatureUnmeasured, which is no
// evidence at all. It only carries which of the two refusals it was, for
// the audit reason.
type signatureRefusal struct {
	error
	unsigned bool
}

func (e signatureRefusal) Unwrap() error { return e.error }

// noteSignature records the outcome of verifying one entry, and writes an
// audit row when the entry STARTS being refused (design/adr/0032 item 4).
//
// Reconcile re-verifies every entry every round, so a row per refusal
// would be a row per interval for as long as the entry stays bad. The
// state is in memory and guarded by refreshMu, which every caller holds:
// a restart writes the refusal once more, which is a restart announcing
// what it found.
//
// An unreadable signature store is neither refused nor accepted, and
// changes nothing here.
func (g *Gateway) noteSignature(ctx context.Context, name string, err error) {
	var refused signatureRefusal
	switch {
	case err == nil:
		delete(g.sigRefused, name)
		return
	case !errors.As(err, &refused):
		return
	}
	reason := reasonSignatureRefused + ": invalid"
	if refused.unsigned {
		reason = reasonSignatureRefused + ": unsigned"
	}
	if g.sigRefused[name] == reason {
		return
	}
	g.sigRefused[name] = reason
	g.auditEvent(ctx, registryEntryTool, name, reason)
}

// forgetSignatures drops the refusal state of entries no longer in the
// registry, so one re-registered later is reported afresh.
func (g *Gateway) forgetSignatures(entries []registry.UpstreamServer) {
	for name := range g.sigRefused {
		if !slices.ContainsFunc(entries, func(e registry.UpstreamServer) bool { return e.Name == name }) {
			delete(g.sigRefused, name)
		}
	}
}

// auditEvent writes one row the gateway records about itself: attributed
// to gatewayActor, outcome denied, with no source address. Detached from
// the caller's cancellation like every other audit write.
func (g *Gateway) auditEvent(ctx context.Context, tool, upstream, reason string) {
	g.auditGatewayRow(ctx, tool, upstream, audit.OutcomeDenied, reason)
}

// auditGatewayRow is auditEvent with the outcome chosen: a backend coming
// back is the gateway serving something again, which is allowed
// (design/adr/0041 item 7).
func (g *Gateway) auditGatewayRow(ctx context.Context, tool, upstream string, outcome audit.Outcome, reason string) {
	writeCtx, cancel := auditWriteCtx(ctx)
	defer cancel()
	c := Caller{Identity: access.Identity{Subject: gatewayActor}}
	if err := g.record(writeCtx, c, tool, upstream, outcome, reason); err != nil {
		g.log.ErrorContext(ctx, "gateway: an event about the gateway itself was not audited",
			slog.String("tool", tool), slog.String("upstream", upstream),
			slog.String("reason", reason), slog.String("detail", err.Error()))
	}
}

// Backlog is the Tool Quarantine's approval queue in two numbers, for the
// heartbeat (design/adr/0032 item 5).
type Backlog struct {
	// Pending is tools never approved; Changed is approved tools whose
	// definition moved -- rug pulls nobody has answered yet.
	Pending int
	Changed int
}

// Backlog counts the quarantine's pending and changed tools across every
// upstream it has seen, connected or not: it is the same set `mcp-gateway
// tool list` shows, read from the store and not from the routing table.
func (g *Gateway) Backlog(ctx context.Context) (Backlog, error) {
	tools, err := g.quarantine.List(ctx, "")
	if err != nil {
		return Backlog{}, fmt.Errorf("%w: %w", ErrQuarantineUnavailable, err)
	}
	var b Backlog
	for _, t := range tools {
		switch t.Status {
		case quarantine.StatusPending:
			b.Pending++
		case quarantine.StatusChanged:
			b.Changed++
		}
	}
	return b, nil
}

// auditWriteCtx returns the context an audit write runs under: the
// caller's values, detached from its cancellation, with a short deadline
// of its own.
//
// # Why the caller's context cannot be used directly
//
// The two failures most worth recording are the ones the caller's context
// CAUSES -- a deadline that fired, a client that went away. Writing the
// record under that same context means the INSERT is cancelled before it
// runs, so precisely those two never reach the trail. Measured, not
// reasoned: a timed-out call left one row, `allowed`, which reads as a
// call that succeeded. ADR-0012 argues the appended row exists because
// "the attempts most worth investigating are the ones that never came
// back"; without this, those were the only ones it could not hold.
//
// # Why it is not context.Background()
//
// Values carry: a trace or request id attached upstream stays attached, so
// the audit write remains correlatable with the call that produced it.
// Only cancellation is dropped.
//
// # Why there is still a deadline
//
// An audit write detached from all cancellation is a write that can hang
// forever on a wedged database, holding a request goroutine with it. The
// bound is generous relative to a local SQLite append and short relative
// to any human's patience: if it is hit, the record is lost and said so
// loudly, which is the same outcome as before this function existed, for a
// far rarer cause.
// The cancel func is returned rather than released internally: the caller
// defers it, which is the only form that frees the timer as soon as the
// write finishes instead of holding it for the whole timeout.
func auditWriteCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
}

// auditWriteTimeout bounds an audit write that has been detached from the
// caller's cancellation. See auditWriteCtx for why the bound exists at all.
const auditWriteTimeout = 5 * time.Second

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
	case errors.Is(err, ErrUpstreamGone):
		return reasonUpstreamGone
	case errors.Is(err, ErrInternal):
		return reasonInternalError
	default:
		return reasonUpstreamFailed
	}
}

// lookup returns the route for a namespaced name and the live connection
// serving it -- nil when there is none -- both read under one lock so they
// cannot come from different generations of the routing table.
func (g *Gateway) lookup(name string) (routedTool, Upstream, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	rt, ok := g.routes[name]
	if !ok {
		return routedTool{}, nil, false
	}
	// A route with no connection is a servable backend that is not live,
	// listed from its stable listing (design/adr/0041 item 4): the caller
	// gets its state at the availability step, not "unknown tool".
	return rt, g.conns[rt.route.upstream], true
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

// Status is what this gateway can say about itself right now, for the
// operational heartbeat (design/adr/0021).
//
// Every field is a number or a flag. Nothing here names an analyst, a
// tool, a backend or an address: this is the shape that gets emitted on a
// timer to a SIEM whether or not anything happened, and a field that
// carried an identity would put an analyst's subject into a stream on a
// schedule rather than on a decision.
type Status struct {
	// Allowed, Denied and Failed are the audit records written since this
	// process started, by outcome.
	//
	// They are RECORD counts, not call counts, and the difference is not
	// pedantic: a call that fails writes an allowed record and then a
	// failed one (ADR-0012). Count Allowed for attempts and read Failed as
	// an annotation on some of them.
	Allowed uint64
	Denied  uint64
	Failed  uint64
	// Upstreams is how many backends are connected and Tools how many
	// routes the table holds. Both are "now", not "at boot": after
	// ADR-0020 they move without a restart.
	Upstreams int
	Tools     int
	// Suspended reports a fleet serving nothing because the registry could
	// not be read. A gateway can be up, answering, and suspended -- see
	// ADR-0020 item 3.
	Suspended bool
	// BackendsUp, BackendsReconnecting and BackendsDown count the servable
	// backends by their state of life (design/adr/0041 item 7). Maintenance
	// is not a state of life and is counted apart (MaintenanceCounts).
	BackendsUp           int
	BackendsReconnecting int
	BackendsDown         int
}

// Status returns the current counters and fleet state.
//
// It takes no lock beyond the one the routing table already uses for a
// read, and it is safe to call from a maintenance loop while requests are
// being served. The numbers are a snapshot: two fields may come from
// either side of a concurrent dispatch, which is exactly as precise as a
// heartbeat needs to be.
func (g *Gateway) Status() Status {
	g.mu.RLock()
	upstreams, tools, suspended := len(g.conns), len(g.routes), g.suspended
	var up, reconnecting, down int
	for _, b := range g.health {
		switch {
		case b.live:
			up++
		case b.cause == health.CauseHeldBack:
			down++
		default:
			reconnecting++
		}
	}
	g.mu.RUnlock()

	return Status{
		Allowed:              g.allowed.Load(),
		Denied:               g.denied.Load(),
		Failed:               g.failed.Load(),
		Upstreams:            upstreams,
		Tools:                tools,
		Suspended:            suspended,
		BackendsUp:           up,
		BackendsReconnecting: reconnecting,
		BackendsDown:         down,
	}
}

// markGone records that a specific connection was observed dead.
//
// The connection is stored, not just the name -- see the gone field. A
// marker for an upstream that is no longer live is dropped rather than
// kept: it describes a process nobody is talking to any more.
//
// It is also the moment the backend stops being live (design/adr/0041
// item 1): the connection receives no more calls, and the transition row
// is returned for the caller to write once no lock is held.
func (g *Gateway) markGone(name string, up Upstream) *healthEvent {
	if up == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if live, ok := g.conns[name]; !ok || live != up {
		return nil
	}
	g.gone[name] = up
	if g.servable != nil && !g.servable[name] {
		return nil
	}
	ev := g.observeLive(name, false, health.CauseProcessGone, false, g.now())
	// While dials are held back nobody will re-dial it: it is down, not
	// reconnecting, for the caller and for the consoles alike, which read
	// the state from this cause. The row still says what happened.
	if b, ok := g.health[name]; ok && g.heldBack {
		b.cause = health.CauseHeldBack
	}
	return ev
}

// servableNotConnected lists, sorted, the servable backends conns has no
// connection for.
func (g *Gateway) servableNotConnected(conns map[string]Upstream) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []string
	for name := range g.servable {
		if _, ok := conns[name]; !ok {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// takeGone reports whether the live connection for name is the one that was
// found dead, and clears the marker either way: it has served its purpose
// once read, and a stale marker is the thing this design must not keep.
func (g *Gateway) takeGone(name string, live Upstream) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	marked, ok := g.gone[name]
	if !ok {
		return false
	}
	delete(g.gone, name)
	return marked == live
}

// fleetSnapshot copies the live connections and the registry entry each
// one was dialed from, under one lock, so a reconciliation compares two
// halves of the same generation.
func (g *Gateway) fleetSnapshot() (map[string]Upstream, map[string]registry.UpstreamServer) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	conns := make(map[string]Upstream, len(g.conns))
	for name, up := range g.conns {
		conns[name] = up
	}
	dialed := make(map[string]registry.UpstreamServer, len(g.dialed))
	for name, entry := range g.dialed {
		dialed[name] = entry
	}
	return conns, dialed
}

// confirm records that the registry was read. It deliberately does NOT
// lift the suspension: the table is still empty at this point, and a
// gateway that reports itself serving while routing nothing answers
// "unknown tool" to tools that exist. swapRoutes lifts it, when there is
// something to serve.
func (g *Gateway) confirm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.confirmed = true
}

// serving records a fleet that was both confirmed and routed, which is
// what Connect does in one step. Reconcile and Refresh reach the same
// state in two.
func (g *Gateway) serving() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.confirmed, g.suspended = true, false
}

// suspended reports the same thing to the request path.
func (g *Gateway) isSuspended() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.suspended
}

// suspend is the fail-closed step of ADR-0004 as ADR-0020 implements it:
// serve nothing, keep the connections. Both halves happen under one lock,
// so there is no instant in which the table is empty and the gateway still
// reports itself confirmable -- a caller landing there would be told
// "unknown tool" about a fleet that is merely unreadable.
func (g *Gateway) suspend() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.suspended, g.confirmed = true, false
	g.routes = map[string]routedTool{}
}

// retire closes the named upstreams and removes every trace of them from
// the serving state: the connection, the entry it was dialed from, its
// credential digests, and its routes.
//
// The routes go in the same swap rather than being left for the next
// Refresh. A route whose upstream is closed resolves to "unknown tool" in
// lookup, which is harmless, but ListTools reads the table alone and would
// advertise a deregistered backend's tools until the next round.
//
// It reports whether the Gateway was closed meanwhile, in which case Close
// has already reaped everything and there is nothing left to do.
func (g *Gateway) retire(names []string, dropRoutes map[string]bool) (closedDuringReconcile bool) {
	if len(names) == 0 && len(dropRoutes) == 0 {
		return false
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return true
	}
	going := make(map[string]Upstream, len(names))
	for _, name := range names {
		if up, ok := g.conns[name]; ok {
			going[name] = up
		}
		delete(g.conns, name)
		delete(g.dialed, name)
		delete(g.creds, name)
		delete(g.gone, name)
		delete(g.unlisted, name)
	}
	for tool, rt := range g.routes {
		if dropRoutes[rt.route.upstream] {
			delete(g.routes, tool)
		}
	}
	g.mu.Unlock()

	if err := closeAll(going); err != nil {
		g.log.Warn("gateway: closing retired upstreams", slog.String("detail", err.Error()))
	}
	return false
}

// adopt adds freshly dialed connections to the live set, leaving the ones
// already there alone. It is Reconcile's counterpart to swap, which
// replaces the whole generation.
//
// Like swap, it closes what it was given rather than installing it if the
// Gateway was closed while the dials were in flight -- otherwise a Close
// racing a reconciliation leaks one subprocess per upstream dialed.
func (g *Gateway) adopt(add map[string]Upstream, entries map[string]registry.UpstreamServer) (closedDuringReconcile bool) {
	if len(add) == 0 {
		return g.isClosed()
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		_ = closeAll(add)
		return true
	}
	for name, up := range add {
		g.conns[name] = up
		g.dialed[name] = entries[name]
		g.unlisted[name] = up
	}
	g.mu.Unlock()
	return false
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
	if !g.confirmed {
		// A refresh that ran while the registry is unreadable has built a
		// table from connections nothing currently vouches for. Installing
		// it would undo the suspension without anybody deciding to, which
		// is the stale-decision window ADR-0004 rejected -- reached, once
		// again, by omission rather than by choice. The next successful
		// Reconcile confirms the fleet and the Refresh after it installs a
		// table that has been confirmed.
		return false
	}
	g.routes = routes
	// Installing a confirmed table IS the end of a suspension, and doing it
	// here rather than at the moment of the successful read is what closes
	// the window in which the gateway called itself available while routing
	// nothing.
	g.suspended = false
	return false
}

// swap installs a freshly built table and closes the connections it
// replaces. It reports whether the Gateway was closed while the table was
// being built, in which case the new connections are closed instead of
// installed -- otherwise a Close racing a Connect would leak every
// subprocess Connect had just spawned.
func (g *Gateway) swap(conns map[string]Upstream, dialed map[string]registry.UpstreamServer, routes map[string]routedTool) (closedDuringConnect bool) {
	if conns == nil {
		conns = map[string]Upstream{}
	}
	if dialed == nil {
		dialed = map[string]registry.UpstreamServer{}
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
	g.dialed = dialed
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
		Name:         def.Name,
		Description:  def.Description,
		InputSchema:  def.InputSchema,
		OutputSchema: def.OutputSchema,
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
		Image:     entry.Image,
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
// line by this package. The masking itself is [MaskCredentials]: the
// union of every match span, raw and escaped, in one pass.
func redact(err error, env map[string]string) error {
	if err == nil {
		return nil
	}
	msg, masked := MaskCredentials(err.Error(), env)
	if !masked {
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
	if err := validateHeaderAnnotations(raw); err != nil {
		return fmt.Errorf("%w: %w", ErrUnusableSchema, err)
	}
	return nil
}

// headerSchemaProperty is the slice of a JSON Schema property that
// x-mcp-header validation reads. It deliberately mirrors the go-sdk's own
// decoding (mcp/streamable_headers.go, v1.7.0) field for field, including
// "type" as a plain string: a schema the SDK cannot decode this way is one
// it skips validating, and refusing it here would withhold a tool the SDK
// serves without complaint.
type headerSchemaProperty struct {
	Type       string                          `json:"type"`
	XMCPHeader json.RawMessage                 `json:"x-mcp-header,omitempty"`
	Properties map[string]headerSchemaProperty `json:"properties,omitempty"`
}

// validateHeaderAnnotations applies the rules mcp.Server.AddTool enforces
// on x-mcp-header annotations -- and panics on (go-sdk v1.7.0,
// validateParamHeaderAnnotations) -- so that discovery refuses a schema
// that breaks them instead of letting it reach a serving surface.
//
// The shape checks above were the whole of the "what AddTool accepts" bar,
// and an upstream advertising `x-mcp-header` on an array property, a
// header name that is not an HTTP token, or two names equal but for case
// passed discovery; once approved, AddTool panicked in httpapi.getServer
// on every request from every caller whose role included the tool,
// tools/list included. The rules are restated rather than borrowed because
// this package does not import the SDK; httpapi also recovers around each
// AddTool, so a rule the SDK grows later costs one tool, not the listing.
// Re-check this against the SDK on every bump.
func validateHeaderAnnotations(raw json.RawMessage) error {
	var root headerSchemaProperty
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil // The SDK skips what it cannot decode; see headerSchemaProperty.
	}
	return validateHeadersIn(root.Properties, "", map[string]bool{})
}

func validateHeadersIn(props map[string]headerSchemaProperty, prefix string, seen map[string]bool) error {
	// Sorted so the property named in the error does not depend on map
	// order; the SDK's order does not matter, only whether it refuses.
	for _, name := range slices.Sorted(maps.Keys(props)) {
		prop := props[name]
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if prop.XMCPHeader != nil {
			switch prop.Type {
			case "string", "integer", "boolean":
			default:
				return fmt.Errorf("property %q: x-mcp-header on a non-primitive type %q", path, prop.Type)
			}
			var header string
			if err := json.Unmarshal(prop.XMCPHeader, &header); err != nil || header == "" {
				return fmt.Errorf("property %q: x-mcp-header must be a non-empty string", path)
			}
			if strings.IndexFunc(header, func(c rune) bool { return !isHTTPTokenChar(c) }) >= 0 {
				return fmt.Errorf("property %q: x-mcp-header value is not an HTTP token", path)
			}
			lower := strings.ToLower(header)
			if seen[lower] {
				return fmt.Errorf("property %q: duplicate x-mcp-header value (case-insensitive)", path)
			}
			seen[lower] = true
		}
		if len(prop.Properties) > 0 {
			if err := validateHeadersIn(prop.Properties, path, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// isHTTPTokenChar reports whether c is an RFC 9110 tchar.
func isHTTPTokenChar(c rune) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", c)
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
// # It depends on the vault adapter noticing the rotation
//
// This compares what an upstream was handed against what vault.Provider
// returns NOW, so it is only as good as "now". Until ADR-0023 the sops
// adapter decrypted once at construction and answered from a frozen map,
// which made both sides of the comparison the same value and this whole
// function inert -- running every tick, documented in three places, unable
// to report anything. The adapter now re-reads when the encrypted file's
// stamp moves. An adapter that caches without invalidating would put this
// back to sleep, silently, so the property lives in that package's tests
// (TestResolveSeesARotationAfterTheFileChanges) rather than here.
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
