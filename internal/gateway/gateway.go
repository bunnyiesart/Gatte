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
	// ErrRegistryUnavailable means the Upstream Registry could not be
	// read. Per design/adr/0004 the gateway fails closed when this
	// happens: no tools are served, rather than serving a possibly-stale
	// last-known-good set.
	ErrRegistryUnavailable = errors.New("gateway: upstream registry unavailable")
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
	// InputSchema is the raw JSON schema bytes, passed through unaltered.
	// Not reformatted or canonicalized anywhere in this system: see
	// design/adr/0007.
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
	// what arrived either way.
	StructuredContent json.RawMessage
	// IsError reports a tool-level error (the call reached the tool and
	// the tool refused), as distinct from a transport or routing failure.
	IsError bool
}

// Upstream is a live connection to one backend MCP server.
//
// Implementations are adapters. An Upstream is obtained from a Dialer and
// must be closed by whoever obtained it.
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
	// Transport is "stdio" or "http".
	Transport string
	// Command and Args describe the process to spawn, for stdio.
	Command string
	Args    []string
	// URL is the endpoint to reach, for http.
	URL string
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
