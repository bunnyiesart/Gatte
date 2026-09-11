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

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
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
	// Upstream Registry, Tool Quarantine, Audit Trail and entry
	// signatures. Never holds a secret (design/adr/0001).
	Database string `toml:"database"`

	OIDC       OIDC       `toml:"oidc"`
	Vault      Vault      `toml:"vault"`
	Signer     Signer     `toml:"signer"`
	Quarantine Quarantine `toml:"quarantine"`
	Response   Response   `toml:"response"`
	Audit      Audit      `toml:"audit"`

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

	for group, role := range c.GroupToRole {
		if strings.TrimSpace(group) == "" {
			errs = append(errs, errors.New("group_to_role: contains an empty group name"))
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
