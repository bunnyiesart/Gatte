// Package config is the gateway's configuration contract: the TOML file
// an operator writes, and the validation that refuses a bad one at
// startup rather than at the first request.
//
// Two rules govern what may appear here, both from
// design/adr/0009-configuration-in-toml.md:
//
//   - **No secret values, ever.** Fields hold paths and identifiers --
//     where the age identity lives, where the signing key lives, which
//     issuer to trust. The secrets themselves stay in the sops-encrypted
//     file and in owner-only key files. This is what makes the config
//     file safe to commit, and it is enforced by test.
//   - **Roles live here, not in the database.** An upstream is
//     operational state and belongs in the registry; a role is policy,
//     and changing who may call what should be a reviewed diff rather
//     than a command that leaves no trace.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quota"
)

// ErrInvalid is returned for a configuration that parses but cannot be
// used. Callers check it with errors.Is.
var ErrInvalid = errors.New("config: invalid")

// Config is the whole configuration file.
type Config struct {
	// Listen is the address the MCP endpoint serves on, e.g.
	// "127.0.0.1:8080". Defaults to loopback deliberately: a gateway
	// holding every backend credential should not become reachable from
	// the network because someone forgot to set an address.
	Listen string `toml:"listen"`

	// Database is the path to the embedded SQLite file holding the
	// Upstream Registry, Tool Quarantine, Audit Trail, entry signatures
	// and quota counters. Never holds a secret (design/adr/0001).
	Database string `toml:"database"`

	OIDC       OIDC       `toml:"oidc"`
	Vault      Vault      `toml:"vault"`
	Signer     Signer     `toml:"signer"`
	Quarantine Quarantine `toml:"quarantine"`
	Response   Response   `toml:"response"`
	Audit      Audit      `toml:"audit"`
	Quota      Quota      `toml:"quota"`
	Telemetry  Telemetry  `toml:"telemetry"`

	// Roles defines what each role may call. Order is irrelevant.
	Roles []Role `toml:"role"`

	// GroupToRole maps an IdP group claim to a role name. A group with no
	// mapping is ignored, not an error -- an IdP carries groups that have
	// nothing to do with this gateway.
	GroupToRole map[string]string `toml:"group_to_role"`
}

// OIDC identifies the self-hosted provider this gateway trusts
// (design/adr/0008). It names an issuer; it never holds a client secret,
// because a resource server does not need one -- it validates tokens, it
// does not obtain them.
type OIDC struct {
	// Issuer is the provider's base URL, used for discovery.
	//
	// An absolute https URI (http is allowed only for a loopback host, for
	// local development), with no query and no fragment -- see Audience
	// for why the shape is fixed rather than merely "absolute".
	Issuer string `toml:"issuer"`
	// Audience is this gateway's own resource identifier. A token minted
	// for a different service of the same IdP must not be accepted here
	// (RFC 8707), which is why this is required and has no default.
	//
	// It must be an absolute https URI with no query and no fragment
	// (loopback http excepted). That is stricter than a JWT `aud` claim
	// needs to be -- "mcp-gateway" is a perfectly legal audience value --
	// and the reason is that this field does double duty: it is also
	// published as `resource` in the RFC 9728 protected-resource metadata,
	// which requires an absolute URI, and advertising an http one would
	// instruct every client that reads it to put a bearer token on the
	// wire in cleartext. Validate applies exactly the predicate the
	// metadata document is built with, so a value that loads is a value
	// that serves.
	Audience string `toml:"audience"`
	// GroupsClaim names the claim carrying group membership. Providers
	// differ; making it configurable is what keeps the gateway
	// provider-agnostic. Defaults to "groups".
	GroupsClaim string `toml:"groups_claim"`
	// AuthorizationServers is advertised in RFC 9728 protected-resource
	// metadata so a client can discover where to get a token. Defaults to
	// [Issuer].
	AuthorizationServers []string `toml:"authorization_servers"`
}

// Vault points at the sops-encrypted secrets file and the age identity
// that decrypts it (design/adr/0003, design/adr/0005). Paths only.
type Vault struct {
	// SecretsFile is the sops-encrypted JSON document. Safe to commit --
	// that is the entire point of sops.
	SecretsFile string `toml:"secrets_file"`
	// AgeKeyFile is the age identity. Must be owner-only on disk; this
	// project's one knowingly-accepted plaintext-on-disk exposure.
	AgeKeyFile string `toml:"age_key_file"`
}

// Signer points at the Ed25519 key used to sign registry entries
// (design/adr/0006), and holds the public keys the gateway will accept
// signatures from (design/adr/0010).
type Signer struct {
	// KeyFile is the Ed25519 private key, PEM-wrapped PKCS#8, owner-only.
	// Optional: without it the gateway can still *verify* signatures, it
	// just cannot create them, which is the right split for a serving
	// process that never signs.
	KeyFile string `toml:"key_file"`

	// TrustedKeys are the Ed25519 public keys whose signatures this gateway
	// accepts on a registry entry: base64 (standard encoding, with padding)
	// of the raw 32 bytes. A signature made by any other key is refused.
	//
	// This is the trust anchor, and it lives here rather than in the
	// database for the reason ADR-0010 gives: an anchor stored beside the
	// thing it authenticates is not an anchor. The entries and their
	// signatures share one SQLite file, so "can rewrite the registry" and
	// "can rewrite the signatures" are the same permission -- verifying an
	// entry against a key read out of that same file proved exactly
	// nothing, and was demonstrated exploitable. A public key is not a
	// secret, which is precisely why it can sit in a versioned, reviewed
	// file; what it needs is to be out of the attacker's write radius.
	//
	// A list rather than a single value, so a key can be rotated without a
	// window in which nothing verifies: add the new key, re-sign, remove
	// the old one.
	//
	// Required whenever RequireSigned is in effect -- see Validate.
	TrustedKeys []string `toml:"trusted_keys"`

	// RequireSigned makes an entry without a valid signature unusable.
	//
	// **Defaults to true as of 09 Sep 2026.** It defaulted to false while
	// nothing could produce signatures at volume, and ADR-0006 recorded
	// that as debt with an explicit trigger: flip it once the Operator
	// Console ships. The console shipped in Phase 6, so it is flipped.
	//
	// A pointer rather than a bool because the zero value of a bool
	// cannot be told apart from an operator writing `require_signed =
	// false`, and silently reading "unset" as "off" is precisely how a
	// security default rots.
	//
	// An *invalid* signature is refused regardless of this setting: there
	// is no benign reading of a signature that does not match the entry.
	RequireSigned *bool `toml:"require_signed"`
}

// Quarantine tunes the Tool Quarantine's periodic re-observation of the
// connected upstreams (design/adr/0013-quarantine-refresh-and-removal.md).
type Quarantine struct {
	// RefreshInterval is how often the gateway re-runs `tools/list` against
	// every connected upstream and feeds the answers back through the
	// quarantine, so that a tool rewritten under an existing approval is
	// noticed.
	//
	// **There is deliberately no value that turns this off.** Not 0, not
	// "never", not a boolean beside it. Re-observation is the only thing
	// that makes rug-pull detection fire on a running gateway, and a switch
	// for it would be flipped off "for a minute" during an incident and
	// found still off a quarter later -- exactly how require_signed's
	// default rotted until ADR-0006 wrote its trigger down. Somebody who
	// does not want to pay the cost raises the interval, and that choice
	// stays legible in the file as a number a reviewer can argue with.
	//
	// The cost being traded is one `tools/list` per upstream per interval,
	// forever. The thing being bought is a shorter window in which a
	// poisoned definition is still served: that window IS the interval, and
	// it never reaches zero.
	//
	// A pointer for the same reason Signer.RequireSigned is one: the zero
	// value cannot be told apart from an operator writing `refresh_interval
	// = "0s"`, and "unset" quietly meaning "disabled" is the failure this
	// field is shaped to prevent. Unset means DefaultRefreshInterval;
	// written as zero or negative is refused by Validate.
	RefreshInterval *time.Duration `toml:"refresh_interval"`
}

// Response bounds what a backend is allowed to answer with
// (design/adr/0014-response-validation-scope.md).
type Response struct {
	// MaxBytes is the largest tool result, in bytes, the gateway will pass
	// on to a client: the serialised content blocks plus the serialised
	// structured content. A result over it is REFUSED and recorded, never
	// truncated -- handing a model a document cut off mid-sentence, with
	// nothing saying it was cut, is a lie told to the consumer of the data.
	//
	// The harm being bounded is not only memory. A backend answering with
	// tens of megabytes floods the model's context, pushing out everything
	// the analyst actually asked about; that is an attack whether or not
	// anybody intended it, and it needs no cooperation from the analyst to
	// happen.
	//
	// **There is deliberately no value that turns this off.** Not 0, not a
	// boolean beside it -- the same rule, for the same reason, as
	// Quarantine.RefreshInterval. This is also the only control in ADR-0014
	// with an effect on today's fleet, since no backend declares an output
	// schema, so an off switch here would switch off the whole of it.
	// Somebody who needs more room raises the number, and that choice stays
	// legible in the file.
	//
	// A pointer for the reason Signer.RequireSigned and
	// Quarantine.RefreshInterval are pointers: the zero value cannot be
	// told apart from an operator writing `max_bytes = 0`, and reading that
	// as "unset, so use the default" would silently ignore what somebody
	// wrote while they believed they had lifted the limit. Unset means the
	// default; written as zero or negative is refused by Validate, which
	// tells them there is no off switch and what to do instead.
	MaxBytes *int64 `toml:"max_bytes"`

	// CallTimeout is how long one tool call may take before the gateway
	// cuts it (design/adr/0025-prazo-por-chamada.md).
	//
	// The ceiling is the GATEWAY's, derived from the caller's context, so a
	// client that disconnects still cuts its own call immediately -- this
	// only bounds the case where that cancellation never comes, which is
	// every client that vanishes without closing: a laptop that sleeps, a
	// network that drops, a proxy that holds the connection open.
	//
	// Until ADR-0025 there was no ceiling at all, and a backend that
	// accepted a call and never answered held a goroutine and that
	// upstream's connection until the process restarted. The audit reason
	// `upstream timed out` existed and was tested; nothing in the system
	// produced it.
	//
	// A pointer, and with no off switch, for the same reasons MaxBytes
	// gives: zero cannot be told from unset, and a timeout that can be
	// switched off during an incident is one that stays off.
	CallTimeout *time.Duration `toml:"call_timeout"`
}

// MinCallTimeout is the shortest ceiling the file may ask for.
//
// Same job as MinResultBytes, same class of mistake: TOML reads a bare
// integer as NANOSECONDS, so `call_timeout = 30` is 30ns and refuses every
// call the fleet can make. One second is below any real backend's slowest
// answer and far above anything somebody wrote while meaning seconds.
const MinCallTimeout = time.Second

// DefaultCallTimeout is the ceiling an unconfigured gateway applies.
//
// Two minutes: above anything the four backends of this fleet produce
// today, and below the point where the analyst has already given up and
// asked somebody. It is an informed guess about one fleet, not a law --
// raising it is a one-line change that stays visible in the file, and
// needing to raise it is itself information about a backend.
const DefaultCallTimeout = 2 * time.Minute

// CallTimeoutOrDefault reports the per-call ceiling, resolving the unset
// case. Validate has already refused zero and negative.
func (r Response) CallTimeoutOrDefault() time.Duration {
	if r.CallTimeout == nil {
		return DefaultCallTimeout
	}
	return *r.CallTimeout
}

// MinResultBytes is the smallest ceiling the file may ask for.
//
// Like MinRefreshInterval it exists to catch one specific mistake rather
// than to police taste. The unit here is BYTES, and the realistic slip is
// somebody thinking in megabytes and writing `max_bytes = 8`. That is not
// a tight limit, it is an outage: every result the fleet can produce is
// refused, and the first report of it is an analyst mid-incident. Four
// kibibytes is below anything a real backend answers with and far above
// any number written by someone who meant megabytes.
const MinResultBytes int64 = 4096

// MaxResultBytes reports the ceiling on one tool result, resolving the
// unset case to the default.
//
// The default is gateway.DefaultMaxResultBytes and is deliberately not
// restated here: two constants for one number is how the file's
// documentation and the code's behaviour drift apart. Read that constant
// for the argument behind its value -- both why not larger and why not
// smaller, since a ceiling below real traffic is an outage and one above
// the context window is a formality.
func (r Response) MaxResultBytes() int64 {
	if r.MaxBytes == nil {
		return gateway.DefaultMaxResultBytes
	}
	return *r.MaxBytes
}

// Audit configures what happens to the Audit Trail beyond the SQLite
// table every record is written to first. There is nothing here that can
// turn the durable trail off; the only thing this section adds is a
// second, downstream copy.
type Audit struct {
	SIEM SIEM `toml:"siem"`
}

// SIEM is the JSONL sink that a shipper forwards to the SOC's Graylog
// (design/adr/0017-audit-jsonl-siem-sink.md).
//
// The whole section is optional. Omitted, the gateway behaves exactly as
// it did before ADR-0017: every record is written to SQLite and nothing
// leaves the host, so the chain has no external anchor. That is a real
// gap, not a mode, and it is wider than the tail ADR-0015 item 6 named:
// a truncated local trail verifies perfectly, and so does an edited one
// whose following hashes were recomputed (ADR-0015's correction of
// 11 Sep 2026). Only an anchor the gateway cannot write to makes either
// visible.
//
// Present, it is present WHOLE: see Validate. A half-written block is
// refused rather than degraded into a pass-through, because a gateway that
// reads as though it ships to the SIEM and does not is this project's own
// defect class.
type SIEM struct {
	// Path is the local file lines are appended to. Setting it is what
	// enables the sink.
	//
	// Local, never a network address, and there is deliberately no key for
	// one. Shipping is a separate process's job (filebeat, vector,
	// whatever the deployment runs) because the gateway's request path must
	// carry no remote dependency at all -- not even a swallowed one, since
	// a hung TCP connect is latency and no error-swallowing hides latency.
	//
	// The file is opened O_APPEND and created 0600. It grows without bound
	// and the deployment owns rotating it; see deploy/freebsd-jail.md,
	// which also records the reopen gap that makes copytruncate the safe
	// form today.
	Path string `toml:"path"`

	// Chain names which gateway's hash chain these lines belong to, e.g.
	// "gatte-jail-01". Required whenever Path is set.
	//
	// It exists because two gateways shipping into one Graylog stream
	// produce interleaved hashes with nothing saying which trail a head
	// belongs to, and `mcp-gateway audit -verify -expect-head` against the
	// wrong chain's head is a false alarm during an incident. It is also
	// the field a Graylog query filters on, which is why Validate refuses
	// one with whitespace on either end: `chain:"gatte-jail-01 "` is not a
	// query anybody will think to write, so the padded value would simply
	// never be found.
	Chain string `toml:"chain"`
}

// Enabled reports whether the SIEM sink is configured. Path is what
// enables it; Validate has already refused a Path without a Chain, so an
// enabled sink is a complete one.
func (s SIEM) Enabled() bool { return strings.TrimSpace(s.Path) != "" }

// validate applies the rules that make [SIEM.Enabled] mean what it says.
//
// The half-written block is the whole point of this function, and it is
// refused in BOTH directions on purpose.
//
// A path with no chain would die at boot inside jsonl.New, which requires
// a chain name -- the operator would meet an error from a package they
// never configured, three lines into startup, over a file this package had
// already pronounced valid. That is the GAB-30 shape for the sixth time,
// and the fix is the same one: the rule belongs where the file is checked,
// so what loads is what serves.
//
// A chain with no path is the other half and is not symmetrical hygiene.
// That block reads as "this gateway ships its trail to the SIEM under this
// name" and ships nothing -- a control the file claims and the code does
// not apply. Defaulting a path would be worse still: it would start
// writing analyst-attributed records to a filename nobody chose.
func (s SIEM) validate() []error {
	path, chain := strings.TrimSpace(s.Path), strings.TrimSpace(s.Chain)
	if path == "" && chain == "" {
		return nil
	}

	var errs []error
	switch {
	case path == "":
		errs = append(errs, errors.New(
			"audit.siem.chain is set but audit.siem.path is empty: naming a chain does not ship anything. "+
				"Set audit.siem.path to the local JSONL file a shipper reads, or remove the whole [audit.siem] block "+
				"(without it the trail stays in SQLite and nothing leaves this host)"))
	case s.Path != path:
		errs = append(errs, fmt.Errorf(
			"audit.siem.path (%q) has leading or trailing whitespace: that is a different filename, and no shipper glob would find it", s.Path))
	}

	switch {
	case chain == "" && path != "":
		errs = append(errs, errors.New(
			"audit.siem.path is set but audit.siem.chain is empty: every emitted line carries the chain name, and a line "+
				"whose chain is blank is a hash with no statement about which trail it belongs to -- which is exactly what "+
				"`mcp-gateway audit -verify -expect-head` needs it for once a second gateway ships into the same stream. "+
				`Name this gateway, e.g. chain = "gatte-jail-01"`))
	case s.Chain != chain:
		errs = append(errs, fmt.Errorf(
			"audit.siem.chain (%q) has leading or trailing whitespace: the SIEM stores it verbatim, so the Graylog query "+
				"an operator would write (chain:%q) would never match it", s.Chain, chain))
	}
	return errs
}

// Role is a named set of namespaced tools, mirroring access.Role. It
// exists separately so the file format is not hostage to the domain type,
// and so a config field can carry documentation the domain type has no
// reason to.
type Role struct {
	// Name identifies the role, referenced from group_to_role. Leading or
	// trailing whitespace is refused rather than trimmed: "analyst " is a
	// different map key from "analyst", so it would define a role no group
	// mapping ever resolves to.
	Name string `toml:"name"`
	// Tools are the namespaced tool names this role may call, e.g.
	// "casemgmt.list_cases". Matched exactly -- there is no wildcard in
	// THIS list, and Validate refuses "casemgmt.*" here rather than
	// letting it load as a name that matches nothing. A wildcard over a
	// whole backend is written under Grants, where it is a different
	// syntactic act.
	//
	// The namespace is required, and Validate refuses a bare
	// "list_cases", because exact matching makes an un-namespaced name a
	// grant of nothing rather than an error: the role would load, build a
	// well-formed policy, and deny every call it was written to allow.
	// An empty list is fine and means what it says.
	//
	// This flat form is NOT deprecated by Grants. Both are in the file
	// format, both are unioned by the policy, and a role may use either or
	// both (design/adr/0016).
	Tools []string `toml:"tools"`

	// Grants composes the role per backend, which is what
	// design/adr/0016 calls a profile:
	//
	//	[[role]]
	//	name = "n1-triage"
	//	tools = ["casemgmt.list_cases"]
	//	  [role.grants]
	//	  casemgmt    = ["get_case", "add_note"]
	//	  threatintel = ["*"]
	//
	// The key is an upstream's registered name; the values are that
	// upstream's own tool ids, NOT namespaced -- the key already says
	// which backend they are on. A backend not named here is not granted
	// at all, which is the deny-by-default half and the reason there is no
	// "deny" form.
	//
	// "*" grants every tool that backend advertises. Read ADR-0016 before
	// using it: it does not bypass Tool Quarantine -- an unapproved tool
	// is still invisible and uncallable -- but it does collapse two human
	// acts into one, and the act it keeps is a judgement about a
	// definition's integrity, not about who may call it.
	//
	// Validate refuses, structurally: an empty backend key or tool id,
	// either containing the namespace separator, "*" as a backend key,
	// "*" mixed with named tools, a repeated tool id, and a backend key
	// written twice in one role. What it cannot refuse here is a key that
	// names no registered upstream -- upstreams live in the SQLite
	// registry and this package holds no handle to it. That is a
	// serve-time diagnostic; see ADR-0016.
	Grants map[string][]string `toml:"grants"`
}

// DefaultListen is the address used when none is configured: loopback,
// so an unconfigured gateway is not exposed to the network.
const DefaultListen = "127.0.0.1:8080"

// RequireLoopbackBind reports whether listen is an address this gateway
// may serve on (design/adr/0011-network-exposure-and-tls-termination.md
// item 1), returning a refusal naming the fix if it is not.
//
// This used to warn and continue, and then it refused -- but from inside
// `serve`, three lines into startup, over a value this package had already
// pronounced valid. The rule lives here now because the set of acceptable
// listen addresses is part of the configuration contract, not a startup
// detail: Validate applies it, every subcommand that loads a file gets the
// same answer, and what loads is what serves. That is the GAB-30 shape,
// found a fourth time.
//
// The refusal itself is unchanged, and its force is the control. Under
// ADR-0011 the gateway terminates no TLS and holds no certificate, so a
// non-loopback bind is not a slightly weaker deployment -- it is every
// analyst's bearer token crossing the network in cleartext, along with the
// case data and IOCs behind it. A warning hands that decision to whoever
// is in a hurry at the time.
//
// Reaching this gateway from another machine is a job for something in
// front of it: a TLS-terminating reverse proxy sharing this jail, itself
// reachable only over the VPN. That is why the message names the fix
// rather than just the problem.
//
// There is deliberately no override. An `allow_insecure_bind` would be
// switched on once "just to test" and never switched off -- the exact
// mechanism by which require_signed would have rotted had ADR-0006 not
// written its trigger down. If terminating TLS here ever becomes right,
// that is an amendment to ADR-0011 with a real listen_tls, not a flag that
// disables a check.
func RequireLoopbackBind(listen string) error {
	if IsLoopbackAddr(listen) {
		// The host half is settled; the PORT half was not checked at all,
		// which left this function open to the very defect its own doc says
		// it was moved into config to close. `listen = "127.0.0.1:https!"`
		// passed here, worked in every operator subcommand, and killed
		// serve at net.Listen -- the operator fixing what Validate listed
		// meeting a different error from the same unchanged file.
		//
		// LookupPort rather than a numeric parse: net.Listen accepts a
		// service name, so rejecting one here would refuse a config that
		// actually works.
		_, port, err := net.SplitHostPort(listen)
		if err != nil {
			return fmt.Errorf("listen: %q is not a host:port address: %w", listen, err)
		}
		// LookupPort("") returns 0 with no error, and ":" is a real thing
		// an operator types when deleting a port to "use the default".
		// There is no default here; net.Listen would pick a random one.
		//
		// An EXPLICIT ":0" is a different thing and is allowed on purpose
		// (24 set 2026, after a fuzz seed asked): nobody types a zero by
		// deleting something, serve's startup summary prints the port the
		// kernel chose, and cmd/mcp-gateway's serve tests depend on it to
		// run in parallel without colliding. The host is still loopback,
		// so ADR-0011's property -- never network-reachable directly --
		// holds either way.
		if port == "" {
			return fmt.Errorf("listen: %q has no port. This gateway does not choose one for you -- "+
				"an ephemeral port is a gateway nothing can reach", listen)
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			return fmt.Errorf("listen: %q has no usable port: %q is neither a number in 0-65535 nor a known service name. "+
				"This is refused here rather than at startup so the whole address is checked in one place", listen, port)
		}
		return nil
	}
	// Note this also refuses an address that cannot be parsed: IsLoopbackAddr
	// returns false when SplitHostPort fails. "Cannot tell" must not read as
	// "loopback" -- the same fail-closed reading ADR-0004 applies to a
	// registry it cannot read.
	//lint:ignore ST1005 Multi-sentence operator guidance, not a fragment meant to
	// be wrapped into a chain. ST1005 protects the reading of "open file: %w"
	// compositions; this one is terminal prose an operator reads at 03:00, and
	// dropping its final period would leave a sentence hanging.
	return fmt.Errorf(
		"listen: %q is not a loopback address, and this gateway refuses to be network-reachable directly (design/adr/0011)\n"+
			"It terminates no TLS, so binding here would put every analyst's bearer token on the wire in cleartext.\n"+
			"Set listen to 127.0.0.1:PORT and put a TLS-terminating reverse proxy in front of it, in this same jail.",
		listen)
}

// IsLoopbackAddr reports whether a host:port address is reachable only
// from this machine. An address it cannot parse, and the wildcard bind, are
// reported as not loopback: the fail-loud reading, since the cost of a
// spurious warning is one log line and the cost of a missed one is an
// unnoticed exposure.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// DefaultGroupsClaim matches the most common provider convention.
const DefaultGroupsClaim = "groups"

// DefaultConnectTimeout bounds the startup connect to all upstreams.
const DefaultConnectTimeout = 30 * time.Second

// DefaultRequireSigned is what signer.require_signed means when the file
// does not say. See the field's own doc for why it changed.
const DefaultRequireSigned = true

// DefaultRefreshInterval is how often an unconfigured gateway re-observes
// its connected upstreams.
//
// Five minutes is the conservative end of a real trade, and both halves are
// worth stating. What it costs: one `tools/list` per upstream every five
// minutes -- for this fleet, four backends, so 48 requests an hour, against
// backends that answer analyst queries measured in seconds. That is noise.
// What it buys: the window in which a rewritten tool is still served under
// its old approval is at most five minutes, instead of the weeks a SOC
// gateway can go between restarts, which is what it was before ADR-0013.
//
// Five rather than one because a minute's window is not meaningfully safer
// than five for an attack that has to be noticed and acted on by a human
// anyway, and it multiplies the standing load by five for that. Five rather
// than an hour because an hour is long enough that "when did this start
// being served?" stops having a useful answer during an incident review.
const DefaultRefreshInterval = 5 * time.Minute

// MinRefreshInterval is the shortest interval the file may ask for.
//
// It exists to catch one specific mistake rather than to police taste.
// TOML decodes a bare integer into a time.Duration as *nanoseconds*, so
// `refresh_interval = 300` -- which any reader would take for five minutes
// -- is 300ns, and would spin `tools/list` against every backend in a hot
// loop with no error anywhere. Anything below a second is that typo, not a
// decision; a real one is written with a unit.
const MinRefreshInterval = time.Second

// RefreshEvery reports how often the connected upstreams are re-observed,
// resolving the unset case to DefaultRefreshInterval. Validate has already
// refused a non-positive value, so what this returns is always usable as a
// ticker period.
func (q Quarantine) RefreshEvery() time.Duration {
	if q.RefreshInterval == nil {
		return DefaultRefreshInterval
	}
	return *q.RefreshInterval
}

// SignaturesRequired reports whether an unsigned registry entry may be
// served, resolving the unset case to DefaultRequireSigned.
func (s Signer) SignaturesRequired() bool {
	if s.RequireSigned == nil {
		return DefaultRequireSigned
	}
	return *s.RequireSigned
}

// TrustedPublicKeys decodes TrustedKeys into the form signer.NewVerifier
// wants, returning an error naming the offending entry -- both its position
// and the text as written -- if any of them is not base64 of exactly
// ed25519.PublicKeySize bytes.
//
// Naming the entry matters more here than in most validation messages: the
// values are 44 characters of base64 that differ from each other in no way
// a human eye picks up, so "one of your trusted keys is wrong" would leave
// an operator diffing the list by hand. Echoing the text is safe -- a
// public key is not a secret, and one that fails to decode is not even a
// public key.
//
// Validate calls this, so a Config that came out of Load has already been
// through it and callers can treat a failure here as a wiring bug.
func (s Signer) TrustedPublicKeys() ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(s.TrustedKeys))
	for i, raw := range s.TrustedKeys {
		text := strings.TrimSpace(raw)
		if text == "" {
			return nil, fmt.Errorf("signer.trusted_keys[%d]: empty", i)
		}
		decoded, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf(
				"signer.trusted_keys[%d] (%q): not valid base64 -- expected the standard encoding of the raw 32-byte ed25519 public key, which `mcp-gateway sign` prints ready to paste",
				i, text,
			)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(
				"signer.trusted_keys[%d] (%q): decodes to %d bytes, want %d -- this is the raw public key, not a PEM block, not a fingerprint, and not the private key",
				i, text, len(decoded), ed25519.PublicKeySize,
			)
		}
		keys = append(keys, ed25519.PublicKey(decoded))
	}
	return keys, nil
}

// Validate reports whether c can be used, applying defaults as it goes.
//
// It is deliberately strict at startup. A configuration error discovered
// on the first request is discovered during an incident, by an analyst
// who cannot fix it; the same error at startup is discovered by the
// operator who just changed the file. This is the same reasoning
// access.NewPolicy uses in refusing an undefined role mapping at
// construction time.
func (c *Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = DefaultListen
	}
	// Applied here rather than only in the serving process: GAB-30 again,
	// the fourth instance. `listen = "0.0.0.0:9443"` used to load cleanly,
	// work in every operator subcommand, and kill serve at the next
	// restart -- the operator fixing what this function listed met a
	// different error from the same unchanged file. One predicate, two
	// callers.
	if err := RequireLoopbackBind(c.Listen); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(c.Database) == "" {
		errs = append(errs, errors.New("database: required (path to the SQLite file)"))
	}

	// Edge whitespace in a path is refused, not trimmed away.
	//
	// audit.siem.path already refused it, with a written rationale; the
	// other path fields were checked with TrimSpace and then USED
	// untrimmed, so `database = " /var/db/x.db"` passed validation and then
	// opened a different file -- one with a leading space in its name,
	// created on the spot. Trimming silently would be worse: it would mean
	// the file the operator wrote and the file the gateway uses differ,
	// with nothing saying so.
	for _, f := range []struct{ name, value string }{
		{"database", c.Database},
		{"vault.secrets_file", c.Vault.SecretsFile},
		{"vault.age_key_file", c.Vault.AgeKeyFile},
		{"signer.key_file", c.Signer.KeyFile},
	} {
		if f.value != "" && f.value != strings.TrimSpace(f.value) {
			errs = append(errs, fmt.Errorf("%s: %q has leading or trailing whitespace; "+
				"the path is used as written, so this names a different file than it appears to", f.name, f.value))
		}
	}

	// The three OIDC identifiers go through access.ResourceIdentifier, the
	// same predicate the RFC 9728 metadata document is built with at boot,
	// rather than a looser rule restated here.
	//
	// That is the whole of GAB-30 item 1. This used to accept any non-empty
	// audience and any absolute-URL issuer, while the serving process
	// required an absolute https URI with no query and no fragment. So
	// `audience = "mcp-gateway"` -- an unremarkable JWT `aud` value -- and
	// `issuer = "http://idp.internal:8080"` both validated, worked for
	// every operator subcommand, and killed serve. The operator fixed what
	// this function listed, restarted, and met a different error from the
	// same unchanged file. One predicate, two callers, no gap to fall
	// through.
	if strings.TrimSpace(c.OIDC.Issuer) == "" {
		errs = append(errs, errors.New("oidc.issuer: required"))
	} else if _, err := access.ResourceIdentifier(strings.TrimSpace(c.OIDC.Issuer), false); err != nil {
		errs = append(errs, fmt.Errorf("oidc.issuer: %w", err))
	}
	if strings.TrimSpace(c.OIDC.Audience) == "" {
		// No default, deliberately. Defaulting an audience would mean
		// accepting tokens minted for some other service of the same IdP,
		// which RFC 8707 exists to prevent.
		errs = append(errs, errors.New("oidc.audience: required (this gateway's resource identifier; never defaulted)"))
	} else if _, err := access.ResourceIdentifier(strings.TrimSpace(c.OIDC.Audience), false); err != nil {
		errs = append(errs, fmt.Errorf("oidc.audience: %w -- this value is not only the token's `aud` claim, it is also published as `resource` in the RFC 9728 metadata document, and that document may only carry an absolute https URI", err))
	}
	if strings.TrimSpace(c.OIDC.GroupsClaim) == "" {
		c.OIDC.GroupsClaim = DefaultGroupsClaim
	}
	if len(c.OIDC.AuthorizationServers) == 0 && c.OIDC.Issuer != "" {
		c.OIDC.AuthorizationServers = []string{c.OIDC.Issuer}
	}
	for i, raw := range c.OIDC.AuthorizationServers {
		// Checked even when it was defaulted from Issuer just above, which
		// duplicates one error in that case. That is the cheaper side of
		// the trade: an operator seeing the same URL named twice loses a
		// second, and a list nobody checked is a startup failure.
		if _, err := access.ResourceIdentifier(strings.TrimSpace(raw), false); err != nil {
			errs = append(errs, fmt.Errorf("oidc.authorization_servers[%d]: %w", i, err))
		}
	}

	if strings.TrimSpace(c.Vault.SecretsFile) == "" {
		errs = append(errs, errors.New("vault.secrets_file: required"))
	}
	if strings.TrimSpace(c.Vault.AgeKeyFile) == "" {
		errs = append(errs, errors.New("vault.age_key_file: required"))
	}

	if _, err := c.Signer.TrustedPublicKeys(); err != nil {
		errs = append(errs, err)
	}
	if c.Signer.SignaturesRequired() && len(c.Signer.TrustedKeys) == 0 {
		// Requiring a signature with nothing to verify it against is asking
		// for a guarantee that cannot be produced: every entry would be
		// refused, and the operator would be debugging a fleet-wide outage
		// rather than reading this line.
		//
		// This is the breaking change ADR-0010 accepts on purpose.
		// require_signed has defaulted to true since Phase 6, so every
		// existing configuration that enforces signing needs one edit. The
		// gateway has never run outside test, so there is no deployment to
		// migrate, and the alternative -- defaulting the trust anchor to
		// something -- is not a thing a trust anchor can do.
		//lint:ignore ST1005 Multi-sentence operator guidance with a remediation
		// command in it; see the note on the loopback error above for why the
		// wrapped-fragment convention does not apply.
		errs = append(errs, errors.New(
			"signer.require_signed is true but signer.trusted_keys is empty: "+
				"signatures are verified against the keys listed there and nothing else, so with an empty list every entry would be refused. "+
				"If you have no signing key yet: `mcp-gateway sign -generate-key -out PATH` creates one and prints both lines to paste "+
				"(it reads no config, so it works before this file is valid). "+
				"If you already have one: `mcp-gateway sign NAME` prints the trusted_keys line.",
		))
	}

	if c.Quarantine.RefreshInterval != nil {
		switch d := *c.Quarantine.RefreshInterval; {
		case d <= 0:
			// The one value this field must never accept. See the field's doc
			// for why there is no off switch; the message says what to do
			// instead, because somebody who wrote a zero here wanted
			// something and should be told how to ask for it.
			errs = append(errs, errors.New(
				"quarantine.refresh_interval: must be positive -- there is deliberately no value that "+
					"disables re-observation, because it is the only thing that notices an upstream rewriting "+
					"an already-approved tool. If the cost is the problem, raise the interval "+
					`(quarantine.refresh_interval = "30m") rather than switching the check off`,
			))
		case d < MinRefreshInterval:
			errs = append(errs, fmt.Errorf(
				"quarantine.refresh_interval: %s is shorter than the %s minimum -- if you wrote a bare number, "+
					"note that TOML reads it as NANOSECONDS, so `refresh_interval = 300` is 300ns and not five "+
					`minutes. Write the unit: refresh_interval = "5m"`,
				d, MinRefreshInterval,
			))
		}
	}

	if c.Response.MaxBytes != nil {
		switch n := *c.Response.MaxBytes; {
		case n <= 0:
			// The one value this field must never accept. See the field's doc
			// for why there is no off switch; the message says what to do
			// instead, because somebody who wrote a zero here wanted something
			// and should be told how to ask for it.
			errs = append(errs, errors.New(
				"response.max_bytes: must be positive -- there is deliberately no value that disables the "+
					"result ceiling, because it is the only part of the response check that runs against today's "+
					"backends (none of them declares an output schema), and a result over the limit is refused "+
					"rather than truncated. If a real query needs more room, raise the limit "+
					`(response.max_bytes = 4194304) rather than switching the check off`,
			))
		case n < MinResultBytes:
			errs = append(errs, fmt.Errorf(
				"response.max_bytes: %d is below the %d minimum (MinResultBytes) -- note the unit is BYTES, so "+
					"`max_bytes = 8` is eight bytes and not eight megabytes, and would refuse every result this "+
					"fleet can produce. Write the whole number: max_bytes = 8388608",
				n, MinResultBytes,
			))
		}
	}

	if c.Response.CallTimeout != nil {
		switch d := *c.Response.CallTimeout; {
		case d <= 0:
			errs = append(errs, errors.New(
				"response.call_timeout: must be positive -- there is deliberately no value that disables the "+
					"per-call ceiling (design/adr/0025). A call with no ceiling holds a goroutine and its "+
					"upstream's connection until the process restarts, which is the state this key exists to "+
					`end. If a real query needs more time, raise it (response.call_timeout = "5m")`,
			))
		case d < MinCallTimeout:
			errs = append(errs, fmt.Errorf(
				"response.call_timeout: %s is below the %s minimum (MinCallTimeout) -- TOML reads a bare "+
					"integer as NANOSECONDS, so `call_timeout = 30` is 30ns and refuses every call this fleet "+
					`can make. Write the unit: call_timeout = "30s"`,
				d, MinCallTimeout,
			))
		}
	}

	errs = append(errs, c.Audit.SIEM.validate()...)

	seen := map[string]bool{}
	for i, r := range c.Roles {
		// access.ValidateRole rather than a restatement of it. The rules it
		// owns -- a name that is empty, or that carries leading or trailing
		// whitespace, or a tool name that is blank -- used to be written
		// out again here, slightly differently, and `name = "analyst "`
		// lived in the difference: rejected by access.NewPolicy for not
		// being trimmed, accepted here because it is not empty *after*
		// trimming. It loaded, every operator subcommand worked, and serve
		// died at the next restart (GAB-30 item 2).
		//
		// Grants is passed too, and must be: leaving it out was not a
		// missing feature but a silently-disabled control -- every
		// structural rule access.validateGrants owns would have been
		// enforced by NewPolicy at serve time and by nothing at all in
		// front of the operator editing the file, which is GAB-30 exactly.
		// Caught by TestLoadRejectsMalformedGrants.
		if err := access.ValidateRole(access.Role{Name: r.Name, Tools: r.Tools, Grants: r.Grants}); err != nil {
			errs = append(errs, fmt.Errorf("role[%d]: %w", i, err))
		}
		if strings.TrimSpace(r.Name) == "" {
			// Nothing below says anything useful about a role with no
			// usable name, and "role %q" would print the empty string.
			continue
		}
		if seen[r.Name] {
			errs = append(errs, fmt.Errorf("role %q: defined more than once", r.Name))
		}
		seen[r.Name] = true

		// A role granting nothing is legitimate and deliberately not
		// flagged: it is how someone who may authenticate but may not act
		// is defined, and config.example.toml ships one.
		granted := map[string]bool{}
		for _, tool := range r.Tools {
			if strings.TrimSpace(tool) == "" {
				continue // Already reported by ValidateRole.
			}
			// GAB-30 item 3, and the quiet one: nothing crashes. The
			// policy matches the namespaced names the Gateway Endpoint
			// advertises, exactly, with no wildcard -- so `tools =
			// ["list_cases"]` is a well-formed policy that grants
			// precisely nothing, and the first report of it is an analyst
			// denied mid-incident with neither the file nor the startup
			// log explaining why.
			//
			// gateway.SplitNamespaced is the routing table's own splitter,
			// not a copy of its shape: what it accepts is what can name a
			// route.
			upstream, toolID, ok := gateway.SplitNamespaced(tool)
			if !ok {
				errs = append(errs, fmt.Errorf(
					"role %q: tool %q is not namespaced -- a role grants UPSTREAM%sTOOL (e.g. %q), matched exactly, and there is no wildcard in this list, so this name matches nothing and the role silently grants nothing",
					r.Name, tool, gateway.NameSeparator, "casemgmt"+gateway.NameSeparator+"list_cases"))
				continue
			}
			// The same silent-no-op shape as the un-namespaced name above,
			// and newly worth naming because "*" now means something a few
			// lines away in the file. `tools = ["casemgmt.*"]` splits,
			// validates, and matches a tool literally called "*" -- which
			// is to say nothing -- while reading exactly like the wildcard
			// that [role.grants] does have. Refused rather than loaded, and
			// the message says where the wildcard actually lives.
			if toolID == access.GrantAll {
				errs = append(errs, fmt.Errorf(
					"role %q: tool %q ends in %q, which is NOT a wildcard in `tools` -- this list is matched exactly, so it would grant only a tool literally named %q. To grant every tool of %q, write it as a per-backend grant:\n\n    [role.grants]\n    %s = [%q]",
					r.Name, tool, access.GrantAll, access.GrantAll, upstream, upstream, access.GrantAll))
				continue
			}
			// Harmless to the policy, which deduplicates -- which is
			// exactly why it would sit in the file for a year. It is
			// almost always a paste or a half-finished rename, and the
			// person who should see it is the reviewer of that diff.
			if granted[tool] {
				errs = append(errs, fmt.Errorf("role %q: tool %q is listed more than once", r.Name, tool))
			}
			granted[tool] = true
		}
	}

	// Quota accounts. The rules the domain owns are delegated to it, in
	// the shape the role loop above uses for access.ValidateRole and for
	// the reason recorded there (GAB-30): a rule restated in two places
	// eventually says two things, and the file that loads is then not the
	// file that serves.
	//
	// What is added here is what the domain cannot see. quota.Provider
	// deliberately does not know how a tool name is spelled -- the
	// namespacing rule has one owner, gateway.SplitNamespaced, the routing
	// table's own splitter -- and it does not know that this file may
	// declare the same account twice.
	//
	// What is NOT checked here, and cannot be: that the named upstream
	// exists. No database is open at this point. That cross-check is
	// gateway.CheckQuotaCoverage's (see gateway.ErrQuotaMisconfigured), and
	// inventing a second home for it would eventually mean a second answer.
	accounts := map[string]bool{}
	for i, p := range c.Quota.Providers {
		if err := (quota.Provider{
			Name:     p.Name,
			Upstream: p.Upstream,
			Limit:    p.Limit,
			Window:   p.Window,
			Tools:    p.Tools,
		}).Validate(); err != nil {
			errs = append(errs, fmt.Errorf("quota.provider[%d]: %w", i, err))
		}
		if strings.TrimSpace(p.Name) == "" {
			// Nothing below says anything useful about an account with no
			// usable name, and every message would print the empty string.
			continue
		}
		if accounts[p.Name] {
			// Two blocks with one name are two budgets against one
			// account, which is the abuse.ch counting mistake in another
			// hat -- and the counter is keyed by name, so whichever block
			// wins would be decided by iteration order.
			errs = append(errs, fmt.Errorf("quota.provider %q: declared more than once", p.Name))
		}
		accounts[p.Name] = true

		for _, tool := range p.Tools {
			if strings.TrimSpace(tool) == "" {
				continue // Already reported by quota.Provider.Validate.
			}
			if containsSpace(tool) {
				errs = append(errs, fmt.Errorf(
					"quota.provider %q: tool %q contains whitespace -- an account is spent by the dispatched name, matched exactly, so this name matches no call and the limit would never apply",
					p.Name, tool))
				continue
			}
			upstream, _, ok := gateway.SplitNamespaced(tool)
			if !ok {
				// The same quiet failure the role loop guards against: the
				// charge table is matched against the namespaced names the
				// Gateway Endpoint dispatches, exactly, so a bare
				// "lookup_ip" matches nothing. The block would load, the
				// limit would look enforced, and the account would be
				// spent without a single unit ever being debited.
				errs = append(errs, fmt.Errorf(
					"quota.provider %q: tool %q is not namespaced -- an account is spent by UPSTREAM%sTOOL (e.g. %q), "+
						"matched exactly, so this name matches no call and the limit would never apply",
					p.Name, tool, gateway.NameSeparator, "threatintel"+gateway.NameSeparator+"lookup_ip"))
				continue
			}
			if strings.TrimSpace(p.Upstream) != "" && upstream != p.Upstream {
				// An account's key reaches exactly one backend, as one of
				// that entry's EnvVarNames. A tool of a different upstream
				// cannot spend it, so charging one to this account bills an
				// analyst for a call that consumed nothing -- and, worse,
				// leaves the calls that DO spend it uncounted while the
				// file reads as though they were covered.
				errs = append(errs, fmt.Errorf(
					"quota.provider %q: tool %q belongs to upstream %q, but this account is declared on upstream %q -- "+
						"an account's key is held by one backend, so a tool of another cannot spend it",
					p.Name, tool, upstream, p.Upstream))
			}
		}
	}

	// The free list, checked for the same things as an account's tool list
	// and for one more: it may not contradict an account. The domain refuses
	// that too (quota.NewPlan), and it is restated here for the reason every
	// other rule is restated here -- Validate reports every problem in the
	// file at once, and a contradiction the operator only discovers on the
	// eleventh restart is a rule that taught nothing.
	charged := map[string]string{}
	for _, p := range c.Quota.Providers {
		for _, tool := range p.Tools {
			charged[tool] = p.Name
		}
	}
	declaredFree := map[string]bool{}
	for i, tool := range c.Quota.FreeTools {
		if strings.TrimSpace(tool) == "" {
			errs = append(errs, fmt.Errorf("quota.free_tools[%d]: empty tool name", i))
			continue
		}
		if containsSpace(tool) {
			// quota.NewPlan happens to trim free names while account tools
			// are matched as written; refusing the padding here keeps the
			// two lists from disagreeing about what a name is.
			errs = append(errs, fmt.Errorf("quota.free_tools[%d]: tool %q contains whitespace", i, tool))
			continue
		}
		if _, _, ok := gateway.SplitNamespaced(tool); !ok {
			errs = append(errs, fmt.Errorf(
				"quota.free_tools[%d]: tool %q is not namespaced -- the coverage check compares against the "+
					"names the Gateway Endpoint dispatches, exactly, so a bare %q matches nothing and the "+
					"tool it was meant to excuse stays withheld from the routing table",
				i, tool, tool))
			continue
		}
		if declaredFree[tool] {
			errs = append(errs, fmt.Errorf("quota.free_tools: tool %q is listed more than once", tool))
		}
		declaredFree[tool] = true
		if account, both := charged[tool]; both {
			errs = append(errs, fmt.Errorf(
				"quota.free_tools: tool %q is also charged to account %q -- it cannot both spend that "+
					"account and spend nothing; remove it from one of the two lists",
				tool, account))
		}
	}

	// [telemetry] (design/adr/0029). The section is optional and absent by
	// default, so none of these rules is about a control somebody left off:
	// what they refuse is a block that reads as though telemetry were on
	// when it is not, and a block that would send messages the SOC's
	// Graylog cannot route.
	//
	// The messages below are in Portuguese, unlike the rest of this file,
	// and that follows ADR-0029 rather than drifting from it: this is the
	// one section whose failure mode is a Graylog stream rule, and the
	// person reading the error at 03:00 is the SOC analyst who wrote the
	// stream rule.
	//
	// What is NOT checked here, and cannot be: that the address answers,
	// that the name resolves, that tls_ca_file exists and holds a
	// certificate. The first two are network questions, and a gateway that
	// asks them at startup is a gateway a DNS blip refuses to boot. The
	// third is local and belongs to the adapter, which is the code that
	// reads the file -- also a startup failure, just not this one's.
	tel := c.Telemetry
	// `tls = false` is deliberately not in this list and cannot be: it is
	// indistinguishable from the key being absent. The consequence is
	// narrow and worth naming -- a [telemetry] block holding nothing but
	// `tls = false` loads as a section that says nothing, which is what it
	// is.
	telemetryWritten := strings.TrimSpace(tel.Transport) != "" ||
		tel.TLS ||
		strings.TrimSpace(tel.TLSCAFile) != "" ||
		strings.TrimSpace(tel.Host) != "" ||
		strings.TrimSpace(tel.ClienteSOC) != "" ||
		tel.Buffer != nil

	switch {
	case !tel.Enabled() && telemetryWritten:
		errs = append(errs, errors.New(
			`telemetry.address: obrigatorio quando qualquer outra chave de [telemetry] e escrita -- a secao inteira ausente e o jeito de desligar a telemetria, e um bloco preenchido sem destino e um operador que acha que ligou. Escreva o destino (address = "192.0.2.11:12201") ou apague a secao`))
	case tel.Enabled():
		// Validated as written, not trimmed. `address = " 192.0.2.11:12201"`
		// splits cleanly into a host with a leading space, which resolves to
		// nothing -- and trimming it here would be this package quietly
		// repairing a value the adapter receives verbatim, which is the
		// GAB-30 shape.
		host, port, err := net.SplitHostPort(tel.Address)
		if err != nil || host == "" || port == "" ||
			strings.TrimSpace(host) != host || strings.TrimSpace(port) != port {
			errs = append(errs, fmt.Errorf(
				`telemetry.address: %q nao e host:port -- um input GELF e uma porta, nao um nome, e nao ha porta padrao para adivinhar. Escreva: address = "192.0.2.11:12201"`,
				tel.Address))
		}

		switch tel.Transport {
		case telemetryTransportUDP, telemetryTransportTCP:
		default:
			errs = append(errs, fmt.Errorf(
				`telemetry.transport: %q nao e "udp" nem "tcp", e nao ha default -- a escolha muda o que este gateway consegue te CONTAR: sob udp uma escrita bem-sucedida significa que o datagrama saiu do socket e nada mais, entao perda no caminho e invisivel para o contador. Escreva: transport = "tcp"`,
				tel.Transport))
		}

		if tel.TLS && tel.Transport == telemetryTransportUDP {
			errs = append(errs, errors.New(
				`telemetry.tls: nao existe GELF UDP sobre TLS -- ou transport = "tcp", ou tls = false`))
		}
		if strings.TrimSpace(tel.TLSCAFile) != "" && !tel.TLS {
			errs = append(errs, errors.New(
				"telemetry.tls_ca_file: escrito com tls = false, e as duas linhas se contradizem -- uma ancora de confianca para uma conexao em claro nao e usada por nada. Escreva tls = true ou apague a linha"))
		}

		if strings.TrimSpace(tel.Host) == "" {
			errs = append(errs, errors.New(
				`telemetry.host: obrigatorio -- e o campo pelo qual todo dashboard do Graylog agrupa, e resolver hostname em runtime devolve um id que muda a cada restart quando o processo e containerizado, o que estilhaca o agrupamento sem avisar ninguem. Escreva o nome estavel: host = "mcp-gateway-01"`))
		}

		switch {
		case strings.TrimSpace(tel.ClienteSOC) == "":
			errs = append(errs, errors.New(
				`telemetry.cliente_soc: obrigatorio -- e o campo por onde o Graylog do SOC roteia mensagem para o stream do cliente, e sem ele os eventos entram no sistema sem cair em stream nenhum, o que e pior do que nao enviar: parece que funcionou. Escreva: cliente_soc = "example-client"`))
		case strings.TrimSpace(tel.ClienteSOC) != tel.ClienteSOC:
			// GAB-30's class, a fourth time: `name = "analyst "` lived in the
			// gap between a rule that trimmed and a rule that did not. Here
			// the second reader is not another package, it is a Graylog
			// stream rule.
			errs = append(errs, fmt.Errorf(
				`telemetry.cliente_soc: %q tem espaco no inicio ou no fim -- uma stream rule que casa "example-client" nao casa "example-client ", e as mensagens chegariam e ficariam invisiveis. Escreva: cliente_soc = "example-client"`,
				tel.ClienteSOC))
		}

		if tel.Buffer != nil {
			switch n := *tel.Buffer; {
			case n <= 0:
				errs = append(errs, errors.New(
					"telemetry.buffer: precisa ser positivo -- buffer = 0 seria envio sincrono, e o caminho de request nunca espera pela telemetria. Se a intencao era desligar a telemetria, apague a secao [telemetry]; se era diminuir a memoria, escreva o numero: buffer = 512"))
			case n < MinTelemetryBuffer:
				errs = append(errs, fmt.Errorf(
					"telemetry.buffer: %d esta abaixo do minimo %d -- uma fila desse tamanho descarta em qualquer rajada normal, e o contador de descarte vira ruido em vez de sinal. Escreva: buffer = 4096",
					n, MinTelemetryBuffer))
			}
		}
	}

	for group, role := range c.GroupToRole {
		// access.ValidateGroupName, not a restatement of it (GAB-30): an
		// untrimmed key is refused by access.NewPolicy, so it must be
		// refused here too or the file loads and serve dies on restart.
		if strings.TrimSpace(group) == "" {
			errs = append(errs, errors.New("group_to_role: contains an empty group name"))
		} else if err := access.ValidateGroupName(group); err != nil {
			errs = append(errs, fmt.Errorf("group_to_role[%q]: %w", group, err))
		}
		if !seen[role] {
			errs = append(errs, fmt.Errorf("group_to_role[%q]: maps to undefined role %q", group, role))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalid}, errs...)...)
}

// Quota holds the per-analyst limits (design/adr/0030-quota-por-analista.md).
//
// The LIMIT is here and the COUNTER is not, and the split is the same one
// ADR-0009 §2 drew for roles: a limit decides what somebody may do, which
// makes it policy and makes widening it a reviewed diff; a counter is how
// much has been spent, which makes it operational state and puts it in the
// database. A limit stored beside its counter would be policy raised by an
// UPDATE, with no diff, no review, and no history outliving the file.
//
// The price is the one that ADR already accepted for roles: changing a
// limit takes a commit and a restart. During an incident the way out is
// another analyst with budget making the call, not a button.
type Quota struct {
	// Providers are the third-party accounts being budgeted, one
	// [[quota.provider]] block each.
	//
	// Empty is valid and means no account is budgeted -- the honest state
	// for a deployment whose upstreams all speak to internal systems.
	// Note what it does NOT mean: the quota component is still wired and
	// still consulted, it simply charges nothing. There is no key here
	// that switches the control off, for the reason
	// Quarantine.RefreshInterval has none.
	Providers []QuotaProvider `toml:"provider"`

	// FreeTools names tools that spend no budgeted account, as
	// UPSTREAM<sep>TOOL, and is the operator saying so out loud.
	//
	// It buys nothing on the request path -- a tool listed here costs
	// exactly what a tool nobody mentioned costs, which is nothing -- and
	// that is the point. Before it existed, "this tool is free" and "nobody
	// remembered this tool" were indistinguishable, and for a tool of an
	// upstream whose third-party budget is being protected they are not the
	// same fact at all: the provider bills the call regardless of whether
	// this file mentioned it.
	//
	// Measured on 14 set 2026: an account declared over
	// `threatintel.virustotal` alone admitted 5000 calls to
	// `threatintel.lookup_ip`, `threatintel.lookup_hash`,
	// `threatintel.lookup_domain`, `threatintel.lookup_url` and
	// `threatintel.enrich` -- all of which spend the same VirusTotal account
	// through the server's fan-out -- without one counter lookup, while
	// startup reported no problem and `quota list` exited 0.
	//
	// So the gateway requires every SERVED tool of an upstream some account
	// names to be either charged or listed here, and does not route one
	// that is neither (gateway.ErrQuotaUndeclaredTool). That is
	// deliberately the same posture ADR-0030 takes on `limit = 0`: a
	// control that is off for a tool may not be off silently. Tools of an
	// upstream no account names need no entry -- casemgmt, logsearch and
	// docsearch have no external budget to protect.
	FreeTools []string `toml:"free_tools"`
}

// QuotaProvider is one third-party account and what one analyst may spend
// against it, mirroring quota.Provider the way Role mirrors access.Role --
// so the file format is not hostage to the domain type, and so the file's
// fields can carry documentation the domain type has no reason to.
//
// # One block is one ACCOUNT, and that is the whole design
//
// Not one upstream, not one tool, not one environment variable. The
// investigation behind ADR-0030 found all three of those wrong:
//
//   - A threat-intel backend is one registry entry serving dozens of
//     tools, many of which spend no third-party account at all (MITRE,
//     CISA, Exploit-DB, DNS, local libraries). A ceiling on the upstream
//     stops the analyst running `decode` in a loop and not the one running
//     `lookup_ip`.
//   - One `lookup_ip` can fan out to several accounts at once, VirusTotal
//     and Shodan among them, while `decode` touches none -- a per-tool
//     counter is wrong by a factor swinging from 0 to N.
//   - THREATINTEL_MALWAREBAZAAR_API_KEY, THREATINTEL_THREATFOX_API_KEY and
//     THREATINTEL_URLHAUS_API_KEY can hold the same value: one abuse.ch
//     account. Three variables, three budgets, one account -- and so no
//     protection at all.
//
// Hence: name the account, then list the tools that spend it. One tool may
// appear under several accounts; one account may be spent by several
// tools.
type QuotaProvider struct {
	// Name identifies the account. Operator-chosen, operator-facing, and
	// the key the counter is stored under: renaming it starts a fresh
	// counter, which is the same trap a renamed role is.
	Name string `toml:"name"`

	// Upstream is the registered backend whose credential carries this
	// account's key, e.g. "threatintel".
	//
	// Checked against the registry by the gateway, not here -- this file
	// is parsed before any database is opened. A block naming an upstream
	// that is not registered stops the gateway from serving at startup,
	// and stops a running one from bringing any backend up until the two
	// agree again (see gateway.ErrQuotaMisconfigured).
	Upstream string `toml:"upstream"`

	// Limit is how many calls ONE analyst may make against this account
	// per Window. Never a pool: a pooled ceiling would let the first
	// analyst in a loop exhaust everybody, which is the defect the whole
	// component exists to remove.
	//
	// So the arithmetic the operator has to do, and it is NOT the obvious
	// one: the window is fixed and aligned by truncation, not sliding, so
	// two adjacent windows are two independent counters. An analyst who
	// spends the whole allowance just before a boundary and the whole
	// allowance just after has made 2N calls inside one window's length.
	// Measured on 14 set 2026: 200 calls in two seconds against a declared
	// limit of 100 per 24h.
	//
	// The worst case against the provider is therefore 2N per analyst per
	// window, and 2 x heads x N for the team -- so the limit is the
	// provider's budget divided by TWICE the number of analysts, with
	// margin, and that arithmetic belongs in a comment beside the line.
	// The fixed window is still the right choice (ADR-0030 decision 4: a
	// sliding window is a second accounting model on the request path); it
	// is the sizing rule that has to know about it.
	//
	// Zero, negative and absent are refused at startup -- never read as
	// "no limit". The precedent is quarantine.refresh_interval = 0,
	// refused with a message telling the operator to raise it, so that a
	// security control switched off "for a minute" cannot exist without
	// the file admitting it.
	Limit int `toml:"limit"`

	// Window is the accounting period, e.g. "24h". Windows are fixed and
	// aligned by truncation in UTC, never sliding: sliding would mean
	// storing a timestamp per call, which is a second audit trail under
	// another name.
	//
	// Note the unit trap TOML sets, the same one refresh_interval
	// documents: a bare number is read as NANOSECONDS, so `window = 3600`
	// is 3.6 microseconds and not an hour. Write the unit.
	Window time.Duration `toml:"window"`

	// Tools are the namespaced tools that spend this account, e.g.
	// "threatintel.lookup_ip". A call to any of them debits one unit.
	//
	// This table is static and the fan-out it models lives in the
	// upstream's own code, so it can drift. Nothing in this gateway
	// observes a backend's outbound requests, and the honest mitigation is
	// procedural rather than technical: a new or changed tool is invisible
	// and uncallable until a human approves it (ADR-0007), and that
	// approval is the moment to check this list against what the tool now
	// does. The residual, stated because it is thin: a tool that starts
	// calling a new account WITHOUT changing its name, description or
	// schema is invisible to both controls.
	//
	// An empty list is refused. An account no tool spends is a limit that
	// can never apply, which is a control that is off with the file
	// implying it is on.
	Tools []string `toml:"tools"`
}

// Telemetry sends one GELF message to a Graylog input per record the Audit
// Trail accepted (design/adr/0029-telemetria-gelf.md). It is an ADDITIONAL
// sink: the SQLite trail stays the source of truth (ADR-0012), so an event
// lost on this path loses a COPY and never the evidence.
//
// The whole section is optional, and its absence is the normal state of
// this deployment today -- see Address for why nothing ships enabled.
//
// That shape reads like the trap Quarantine.RefreshInterval and
// Response.MaxBytes are built to prevent, so the difference is written down
// rather than left to be re-derived. There, a zero switches a SECURITY
// CONTROL off, and the file refuses it. Telemetry is not a security
// control: it is a copy of a trail that keeps being written either way, and
// a gateway with no [telemetry] section still audits everything it audited
// before.
//
// The omission is still defended twice, because "I thought I had turned it
// on" is a real failure even for a copy. A section written without a
// destination is a fatal load error (Validate, first rule below), and
// startup says out loud where the events are going or that they are going
// nowhere.
type Telemetry struct {
	// Address is the GELF input to send to, as host:port -- e.g.
	// "192.0.2.11:12201". Empty is the off switch, and empty is what ships.
	//
	// Never resolved here, and not by the adapter's constructor either. A
	// SIEM whose name resolves at 03:00 and does not at 04:00 must not get
	// to decide whether this gateway starts.
	Address string `toml:"address"`

	// Transport is "udp" or "tcp". Required, and deliberately with NO
	// default.
	//
	// The choice changes what this gateway can afterwards TELL you, which
	// is too much to decide on somebody's behalf: under udp a successful
	// write means the datagram left the socket and nothing more, so loss on
	// the way is invisible to the counters; under tcp it means the bytes
	// were accepted by the connection, which still does not say Graylog
	// indexed them. An operator who had to write the word has met the
	// argument.
	Transport string `toml:"transport"`

	// TLS wraps the TCP connection. Only with Transport "tcp": there is no
	// GELF UDP over TLS, and a file asking for one is refused rather than
	// quietly sending in the clear.
	//
	// There is no key that disables certificate verification, and that is
	// not an omission -- an InsecureSkipVerify in a file is a
	// production-grade hole opened during one afternoon of debugging.
	TLS bool `toml:"tls"`

	// TLSCAFile is the PEM holding the CA that signed the Graylog input's
	// certificate. Empty means the system pool.
	//
	// A PATH, never a value (ADR-0009 §3) -- and note that a CA certificate
	// is public material, so this whole section accepts no secret at all.
	// That is a property of the design rather than an accident: the sink
	// authenticates to nothing and carries no credential.
	//
	// Whether the file exists on this host and has a certificate inside is
	// read and answered by the adapter, not here. This package validates
	// FORM and CONTRADICTION; both failures stop startup either way.
	TLSCAFile string `toml:"tls_ca_file"`

	// Host is the GELF `host` field. Required, with no fallback.
	//
	// It could have defaulted to os.Hostname(), and that was refused: in a
	// containerised process that returns an id which changes at every
	// restart, while every Graylog dashboard groups by this field -- so the
	// grouping would shatter with nobody being told. One line in the file
	// removes the failure mode.
	Host string `toml:"host"`

	// ClienteSOC is the GELF `_cliente_soc` field: the SOC's Graylog routes
	// a message to a client's stream by it, so a message without it enters
	// the system and lands in no stream at all -- which is worse than not
	// sending, because it looks like it worked.
	//
	// One thing measured on 14 set 2026, worth knowing before writing this
	// line: on all 16 GELF AMQP inputs of that Graylog, cliente_soc is a
	// STATIC FIELD OF THE INPUT. Graylog does not overwrite a field the
	// message already carries, so the value written here OVERRIDES what a
	// correctly configured input would have said. It is necessary -- one
	// shared input cannot tell which gateway a message came from -- and it
	// does invert the authority: a wrong value here beats a right one
	// there.
	ClienteSOC string `toml:"cliente_soc"`

	// Buffer is how many events may wait in the queue while the destination
	// is unreachable. Unset means DefaultTelemetryBuffer.
	//
	// The only number in this section the code cannot pick, because the
	// right value depends on the installation's traffic: it decides how
	// much of an outage is absorbed without losing anything. Every other
	// number the sink needs -- dial timeout, write timeout, backoff, close
	// budget -- is a constant in the adapter, which is also how this
	// section stays free of duration fields and therefore of TOML's
	// bare-integer trap (see MinRefreshInterval). What that costs is not
	// being able to retune without recompiling; what it buys is nobody
	// writing `write_timeout = 5` at 03:00 and turning the sink into a
	// 100% discarder.
	//
	// A pointer for the reason Signer.RequireSigned,
	// Quarantine.RefreshInterval and Response.MaxBytes are pointers: the
	// zero value cannot be told apart from an operator writing zero. Unset
	// means the default; written as zero or negative is refused, and so is
	// a number too small to have been meant.
	Buffer *int `toml:"buffer"`
}

// The two transports telemetry.transport may name. Unexported: the adapter
// owns the type that carries them onto the wire (gelf.Transport), and a
// second exported spelling of the same two words in this package would be
// one more thing that can disagree with it.
const (
	telemetryTransportUDP = "udp"
	telemetryTransportTCP = "tcp"
)

// DefaultTelemetryBuffer is the queue capacity when the file does not say.
//
// 4096 events. An audit.Record is ~200 bytes in memory, so the queue's
// worst case is ~1 MiB -- irrelevant beside the 1 MiB ceiling on ONE tool
// result. What 4096 buys is the WINDOW: minutes of traffic, long enough for
// Graylog to restart without a single event being discarded. A much larger
// number would buy nothing more, because an outage lasting longer than
// minutes is the case `mcp-gateway audit --since` answers, not the case
// memory answers.
const DefaultTelemetryBuffer = 4096

// MinTelemetryBuffer catches the operator who thought "a few messages".
//
// Under it the queue discards on any ordinary burst, and the discard
// counter stops being a signal that something is wrong and becomes noise
// nobody reads.
const MinTelemetryBuffer = 64

// Enabled reports whether any audit event is sent anywhere.
//
// It is the address and nothing else. There is deliberately no `enabled`
// key beside it: a second way to spell "off" is a second thing to misread
// at 03:00, and the two would eventually disagree.
func (t Telemetry) Enabled() bool {
	return strings.TrimSpace(t.Address) != ""
}

// BufferSize reports the queue capacity, resolving the unset case to
// DefaultTelemetryBuffer. Validate has already refused a non-positive or
// too-small value, so what this returns is always usable as a channel
// capacity.
func (t Telemetry) BufferSize() int {
	if t.Buffer == nil {
		return DefaultTelemetryBuffer
	}
	return *t.Buffer
}

// containsSpace reports whether s holds any Unicode whitespace. A quota
// tool name is matched exactly against the name Dispatch routes, so a name
// with a space in it can never match a call.
func containsSpace(s string) bool {
	return strings.IndexFunc(s, unicode.IsSpace) >= 0
}
