// Package gateway is the Gateway Endpoint component
// (design/02-components.md): the single MCP surface that aggregates every
// registered upstream behind one address and dispatches each call to the
// right backend.
//
// It is the integration point -- it depends on Upstream Registry,
// Credential Vault, Tool Quarantine, Audit Trail and Access Control all
// existing -- and it is the first place the whole system does something
// end to end.
//
// This package holds the orchestration and the routing table. It talks to
// the outside world only through ports: the Dialer below for reaching an
// upstream, and the other components' own interfaces for everything else.
// The stdio subpackage is the Dialer adapter.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// Sentinel errors.
var (
	// ErrUnknownTool means the requested namespaced tool is not in the
	// routing table -- either it was never registered, or its upstream is
	// gone.
	ErrUnknownTool = errors.New("gateway: unknown tool")
	// ErrToolQuarantined means the tool exists but Tool Quarantine has not
	// approved this version of it. Deliberately distinct from
	// ErrUnknownTool internally, for the audit trail -- but see the note
	// on Dispatch about what a caller is told.
	ErrToolQuarantined = errors.New("gateway: tool not approved")
	// ErrSensitiveNotGranted means the tool's quarantine class is sensitive
	// -- it can act, not only read -- and none of the caller's roles both
	// carries the non-read marking and names the tool explicitly
	// (design/adr/0048 Decisão 5, the class-aware gate). The error returned
	// to a caller wraps this AND access.ErrForbidden: at the boundary it is
	// the forbidden class, byte for byte, and only the trail says which
	// gate refused (reasonSensitiveNotGranted).
	ErrSensitiveNotGranted = errors.New("gateway: sensitive tool is not explicitly granted in a non-read role")
	// ErrRegistryUnavailable means the Upstream Registry could not be
	// read. Per design/adr/0004 the gateway fails closed when this
	// happens: no tools are served, rather than serving a possibly-stale
	// last-known-good set.
	//
	// It reaches a caller, and not only the operator: while the fleet is
	// suspended, ListTools and Dispatch return this rather than an empty
	// list or ErrUnknownTool, so "that tool is gone" and "nothing about
	// the fleet can be confirmed right now" stay distinguishable at both
	// ends (design/adr/0020 item 4).
	ErrRegistryUnavailable = errors.New("gateway: upstream registry unavailable")
	// ErrUpstreamGone means the far end of a live connection is gone: the
	// backend process exited, or the transport carrying it closed. It is
	// positive evidence, not a guess -- see the Upstream interface for what
	// an implementation may and may not wrap it around.
	//
	// The distinction it exists to make is the one this project keeps
	// having to re-make: a backend that did not ANSWER is not a backend
	// that DIED. A timeout, a cancelled context, a slow container under
	// load -- none of those are this error, and treating them as this error
	// would turn a busy afternoon into a fleet-wide respawn
	// (design/adr/0024).
	ErrUpstreamGone = errors.New("gateway: upstream is gone")
)

// NameSeparator joins an upstream's name to a tool's own name to form the
// namespaced name clients see.
//
// Namespacing is required, not cosmetic: tool-name uniqueness is only
// guaranteed *within* one MCP server, so two backends may both expose
// "search". Without a namespace the aggregated list silently collides and
// one upstream's tool shadows the other's -- which, in a gateway whose
// whole job is routing calls to the right backend, means calls quietly
// going to the wrong system.
const NameSeparator = "."

// Namespaced returns the client-facing name for a tool on an upstream.
func Namespaced(upstream, tool string) string {
	return upstream + NameSeparator + tool
}

// SplitNamespaced splits a client-facing name back into its upstream and
// tool parts. It splits on the *first* separator, so a tool whose own name
// contains a dot round-trips correctly.
//
// That the upstream half is the upstream which actually serves the tool is
// not a property of this function: it holds because no registered upstream
// name may contain the separator (registry.UpstreamServer.Validate, and
// Connect's re-check of the same contract on entries read back out of the
// store). Without that rule this split and the routing table would disagree
// for an upstream named "a.b", and so would access.Role.Allows, which
// resolves a per-backend grant the same way.
func SplitNamespaced(name string) (upstream, tool string, ok bool) {
	upstream, tool, ok = strings.Cut(name, NameSeparator)
	if !ok || upstream == "" || tool == "" {
		return "", "", false
	}
	return upstream, tool, true
}

// ToolDef is an upstream's declaration of one tool, as the gateway needs
// it: enough to re-advertise the tool to clients and to compute the
// quarantine identity hash over it.
type ToolDef struct {
	// Name is the tool's own name, as the upstream calls it -- not
	// namespaced.
	Name string
	// Description is what the upstream says the tool does. This is the
	// field a tool-poisoning attack targets, because it reaches the model
	// as trusted operational context; it is part of the quarantine hash
	// for exactly that reason.
	Description string
	// InputSchema is the tool's JSON schema.
	//
	// CORRECTED: this said "raw JSON schema bytes, passed through
	// unaltered ... not reformatted or canonicalized anywhere in this
	// system", which is what ADR-0007 §2 intended and not what arrives.
	// The MCP SDK decodes the upstream's schema into map[string]any before
	// any of this code runs, so what is here is a re-marshal of that map:
	// there IS a canonicalization and it is Go's, applied before our
	// boundary. internal/gateway/stdio.rawJSON says the same thing at the
	// point it happens; this said the opposite at the point a reader meets
	// the field.
	//
	// What that costs is measured, not guessed, in
	// TestRawJSON_TheSDKRoundTripCollapsesDuplicateKeys: duplicate keys
	// collapse, so two schemas a different parser could read differently
	// produce one fingerprint. Numbers normalise and key order vanishes.
	// Every SEMANTIC change still moves the hash, so the rug-pull defence
	// stands with one fewer edge than ADR-0007 claimed (GAB-15,
	// design/adr/0019).
	InputSchema json.RawMessage

	// OutputSchema is the raw JSON schema an upstream declares for the
	// StructuredContent of this tool's results (SEP-2106), or nil when it
	// declares none. Passed through unaltered, like InputSchema.
	//
	// **Optional, and empty for every backend in this fleet today** --
	// checked, not assumed (design/adr/0014). When it is present, Dispatch
	// holds the result to it and refuses a divergence; when it is absent
	// there is no schema validation, and the gateway does not invent one
	// from a response it has seen.
	//
	// Deliberately NOT part of the quarantine fingerprint. identityOf
	// hashes name, description and input schema, which is what ADR-0007
	// approved and what every stored approval was computed over; folding
	// this in would invalidate every existing approval and is an amendment
	// to that ADR rather than a detail of this one. The consequence, stated
	// so nobody has to discover it: an upstream can widen its own output
	// schema without the quarantine flipping the tool to changed.
	OutputSchema json.RawMessage

	// SecurityClass is whether the operation behind this tool can only read
	// (quarantine.ClassSafe, the zero value) or can act
	// (quarantine.ClassSensitive) -- design/adr/0048 Decisão 5. A Dialer
	// derives it from the operation's HTTP method; the stdio and oci
	// adapters leave it zero, since an MCP tool has no method to derive a
	// class from and every tool of this fleet is safe by that definition.
	//
	// Deliberately NOT part of the quarantine fingerprint, and not by
	// analogy with OutputSchema -- which IS in the fingerprint when declared
	// (ADR-0014/0019) -- but by construction: identityOf never reads this
	// field, so it cannot reach quarantine.Hash. It is metadata the gateway
	// hands to Store.Observe beside the identity, and the quarantine keeps
	// it as a column of its own. The consequence, stated: an operation
	// whose method changes keeps its fingerprint and its approval; what
	// changes is which conditions Usable and the dispatch gate impose, and
	// those are re-read from the latest observation on every call.
	SecurityClass quarantine.Class
}

// Result is an upstream's response to a tool call, passed back to the
// client as-is.
type Result struct {
	// Content is the raw JSON of the MCP result's content field.
	Content json.RawMessage
	// StructuredContent is the raw JSON of the result's structuredContent
	// field (SEP-2106), or nil when the upstream sent none. Like Content it
	// is bytes, not a decoded value: this package measures it and, when the
	// tool declared an OutputSchema, validates it -- and hands on exactly
	// what arrived either way, save for one edit: an injected credential
	// the upstream echoed is replaced by a placeholder (Dispatch, step 7).
	StructuredContent json.RawMessage
	// IsError reports a tool-level error (the call reached the tool and
	// the tool refused), as distinct from a transport or routing failure.
	IsError bool
	// Notice is the whole gateway's planned maintenance, when there is one
	// (design/adr/0041 item 6). The gateway sets it, never an upstream;
	// the serving adapter appends it as a text block of its own.
	Notice *MaintenanceNotice
}

// Upstream is a live connection to one backend MCP server.
//
// Implementations are adapters. An Upstream is obtained from a Dialer and
// must be closed by whoever obtained it.
// # Reporting that the far end died
//
// An implementation that can tell its connection is GONE -- the child
// process exited, the transport closed under it -- must return an error
// wrapping [ErrUpstreamGone] from ListTools and CallTool, and must NOT wrap
// it around anything weaker. "I asked and got no answer in time" is a
// timeout; "the stream ended" is this. The gateway acts on the second by
// closing and re-dialing (design/adr/0024), so an implementation that
// reported the first as the second would respawn healthy backends under
// load.
//
// An implementation that cannot tell simply never returns it, and the
// gateway's behaviour is what it was before: the upstream stays connected
// and every call to it fails until a human intervenes. That is the
// permitted degradation, not a violation.
type Upstream interface {
	// ListTools returns everything this upstream advertises.
	ListTools(ctx context.Context) ([]ToolDef, error)
	// CallTool invokes one tool by its own (not namespaced) name.
	CallTool(ctx context.Context, tool string, args json.RawMessage) (Result, error)
	// Close shuts the connection down and reaps the process, if there is
	// one.
	Close() error
}

// Dialer opens a connection to an upstream server.
//
// env carries the environment the upstream process is spawned with,
// already resolved: the caller (this package) resolves secret references
// through the Credential Vault immediately before dialing and passes the
// values here. An implementation MUST NOT persist env, log it, or include
// any of its values in an error -- it is the plaintext credential, alive
// for exactly as long as the spawn takes.
//
// Splitting resolution (here) from spawning (the adapter) is deliberate:
// it keeps every path that touches a plaintext secret inside two small
// places that can be read in full, rather than spread across the dialer,
// the registry and the request path.
type Dialer interface {
	Dial(ctx context.Context, entry UpstreamSpec, env map[string]string) (Upstream, error)
}

// UpstreamSpec is what a Dialer needs to reach one backend. It is
// deliberately a narrower view than registry.UpstreamServer: a Dialer has
// no business seeing timestamps, and -- more to the point -- no business
// seeing the list of env var *names*, since it receives the resolved
// values it needs and nothing more.
type UpstreamSpec struct {
	// Name is the upstream's registered name, used to namespace its tools
	// and to attribute audit records.
	Name string
	// Transport is "stdio", "oci" or "http" as a TYPE. "stdio" spawns a
	// process and "oci" is a stdio child that is `podman run`
	// (internal/gateway/oci). "http" is a REST API the gateway itself calls,
	// served by the stateless adapter in internal/gateway/resthttp
	// (ADR-0047 §2, ADR-0048 Decisões 6, 7, 9): no connection is held, the
	// entry's secret is re-resolved per call, and health is a fixed "up".
	// All three are served by this build; cmd/mcp-gateway/dialer.go routes
	// on this field.
	Transport string
	// Command and Args describe the process to spawn, for stdio. For oci,
	// Command is empty and Args are the extra `podman run` flags the entry
	// signs (its network policy, ADR-0016 item 5a in the internal line).
	// Both are empty for http.
	Command string
	Args    []string
	// Image is the digest-pinned image reference, for oci; empty otherwise.
	// Never a value: credentials reach the container as environment, set by
	// the dialer from the resolved env map, not through the reference.
	Image string
	// URL is the endpoint to reach, for http: scheme, host, port and base
	// path, as signed (signer canonical/v3-http). Empty for stdio and oci.
	URL string
	// AuthKind and AuthName are the http credential-injection descriptor
	// (ADR-0047 §5): where on the outbound request the secret is placed. The
	// secret *value* is not here -- the resthttp adapter re-resolves it per
	// call from the Credential Vault, using the single name in the resolved
	// env map as the secret reference. Both empty for stdio and oci.
	AuthKind string
	AuthName string
	// Operations is the frozen REST operation set an http entry serves, as
	// canonical JSON (ADR-0047 §3): one entry per generated tool, carrying
	// its method, path, namespaced input schema and security class. Empty for
	// stdio and oci.
	Operations []byte
}

// Caller is everything the Gateway is told about who is making one call:
// the identity a token attested, and the address the serving surface saw
// the request arrive from.
//
// The two are a struct rather than two parameters on purpose. They are
// both strings-in-a-trenchcoat at the call site, and transposing them
// would compile and would quietly file a subject as a source address; a
// field name makes that mistake impossible. They are kept apart inside
// the struct for the opposite reason: Identity is *attested* -- the IdP
// signed for it -- while SourceAddress is merely *observed*, and only as
// trustworthy as the guarantee that the co-located reverse proxy is the
// sole path to this port (design/adr/0011). Nothing in this package ever
// makes an authorization decision on SourceAddress, and nothing should:
// it is evidence for an operator, not an input to a gate.
type Caller struct {
	// Identity is the verified caller. Its Subject is what the audit
	// trail attributes to.
	Identity access.Identity
	// SourceAddress is where the request came from, already reduced to
	// one address by the serving adapter -- for HTTP, the rightmost
	// X-Forwarded-For entry, which is the one the proxy wrote rather than
	// the one the client sent. See internal/gateway/httpapi.sourceAddress
	// and audit.Record.SourceAddress.
	//
	// Empty is allowed and means "no address was available", which is an
	// honest thing for a surface with no network peer to say. It is not a
	// reason to refuse a call.
	SourceAddress string
}

// route is one entry in the routing table: which live connection serves a
// namespaced tool, and what that tool is called on the other side.
type route struct {
	upstream     string
	originalName string
}

// String renders a route for logs and errors.
func (r route) String() string {
	return fmt.Sprintf("%s -> %s.%s", Namespaced(r.upstream, r.originalName), r.upstream, r.originalName)
}
