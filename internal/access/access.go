// Package access is the domain package for the Access Control component
// (design/02-components.md): it decides who a caller is and which tools
// they may reach, and it is where the client's own credential stops.
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to HTTP, JWT libraries, or any identity provider.
// The oidc subpackage is the adapter. [ResourceIdentifier] parses a URI and
// reads a scheme, which is the closest this package comes to the wire and
// is not the same thing -- see its doc for why the rule lives here.
//
// The identity model is self-hosted OIDC
// (design/adr/0008-identity-model-self-hosted-oidc.md): the gateway is an
// OAuth 2.0 Resource Server. It never issues identity, only verifies
// tokens issued by a provider the team hosts, and never forwards a
// caller's token to an upstream.
package access

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Sentinel errors. Callers distinguish these deliberately: per
// CONCEPTS.md §3.3, "I don't know who you are" (401) and "I know who you
// are and you may not" (403) must not be collapsed, because doing so
// leaks information in both directions -- a 401 for an authorization
// failure tells an attacker their credential might work with different
// permissions, and a 403 for a missing credential confirms a resource
// exists to someone who never authenticated.
var (
	// ErrUnauthenticated means no usable credential was presented, or the
	// one presented could not be verified. Maps to HTTP 401.
	ErrUnauthenticated = errors.New("access: unauthenticated")
	// ErrForbidden means the caller is known, and is not allowed to reach
	// the tool they asked for. Maps to HTTP 403.
	ErrForbidden = errors.New("access: forbidden")
	// ErrNoSuchRole is returned when a policy references a role that was
	// never defined.
	ErrNoSuchRole = errors.New("access: no such role")
	// ErrInvalidPolicy is returned by NewPolicy for a policy that is
	// malformed rather than merely incomplete: an empty or untrimmed role
	// name, a duplicate role, an empty tool name, an empty group key.
	ErrInvalidPolicy = errors.New("access: invalid policy")
	// ErrInsecureResourceIdentifier is the one [ResourceIdentifier] failure
	// a caller may legitimately want to override, so it is the one that is
	// distinguishable without reading the message. Every other failure is a
	// malformed identifier with no override worth offering.
	ErrInsecureResourceIdentifier = errors.New("access: resource identifier is not https")
)

// Identity is who a caller is, as attested by a verified token. It holds
// only what the gateway needs: something stable to attribute actions to,
// something human-readable for the audit trail, and the group claims that
// drive authorization.
//
// It deliberately does NOT carry the raw token. Once a token has been
// verified, the token itself has no further use inside the gateway, and
// anything that still holds it is a chance to log or forward it by
// accident (design/adr/0003's credential-stripping requirement).
type Identity struct {
	// Subject is the IdP's stable unique identifier for this caller (the
	// `sub` claim). This is what the Audit Trail attributes calls to --
	// not the display name, which an IdP may allow a user to change.
	Subject string
	// Name is a human-readable label for logs and operator surfaces.
	// Never used for an access decision.
	Name string
	// Groups are the group/role claims asserted by the IdP, used to
	// resolve which Role this caller has.
	Groups []string
}

// TokenVerifier verifies a bearer token and returns the Identity it
// attests. Implementations are adapters (the oidc subpackage).
//
// A verifier MUST validate, at minimum: the signature against the
// issuer's current keys, the issuer, the audience (RFC 8707 -- a token
// minted for a different service of the same IdP must not be accepted
// here), and expiry. It MUST return ErrUnauthenticated, wrapped with
// detail, for every failure -- a caller must not be able to distinguish
// "expired" from "wrong audience" from "bad signature" by the error it
// gets back.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (Identity, error)
}

// Role is a named subset of the aggregated tool list.
//
// This is deliberately a concrete list of tool names rather than a set of
// abstract scopes or a policy expression. At roughly 65 tools and two
// roles this is a list a person can read in full and reason about at
// 03:00 during an incident; a policy DSL would be one more thing nobody
// on a seven-person team remembers how to debug (a conclusion reached in
// the trade-off analysis recorded in DEVELOPMENT-LOG.md, and the reason
// Cedar/CEL engines were explicitly rejected).
type Role struct {
	// Name identifies the role, e.g. "n1-triage" or "dfir-lead".
	Name string
	// Tools are the namespaced tool names this role may call, e.g.
	// "casemgmt.list_cases". Matching is exact: there is no wildcard, because
	// a wildcard is how a role silently gains a tool that was added to an
	// upstream later. Adding a tool to a role is a deliberate act.
	Tools []string
}

// Allows reports whether this role may call the named tool.
func (r Role) Allows(tool string) bool {
	return slices.Contains(r.Tools, tool)
}

// ValidateRole reports whether r is well-formed, independently of any
// policy it might go into.
//
// It is exported because it has two callers, and that is the point:
// [NewPolicy] applies it to protect the domain type from any caller, and
// the configuration package applies it to every [[role]] in the file so
// that the operator who just wrote a bad one is told while they are still
// editing. Those two used to state the rule separately and had already
// drifted -- config rejected a name that was empty *after* trimming, this
// package rejects a name that is not *already* trimmed, and `name =
// "analyst "` fell straight through the gap: it loaded, it survived every
// operator subcommand, and it killed serve at the next restart (GAB-30).
// A rule stated twice is a rule that will diverge again, so it is stated
// once, here, where the domain enforces it.
//
// Every problem with r is reported, joined, rather than only the first:
// the config file's contract is that one pass over it lists everything
// wrong with it.
//
// What it deliberately does NOT check is whether the tool names refer to
// anything that exists. This package has no idea what an upstream is, and
// a role naming a tool no backend advertises is legal -- it is how a role
// is written before the backend it is for is registered.
func ValidateRole(r Role) error {
	var errs []error

	// Reject a name that isn't already trimmed rather than trimming it
	// silently: "admin " stored as-is is a distinct map key from "admin",
	// so a trailing space produces a role no group mapping will ever
	// resolve to -- a role that exists, looks correct in config, and grants
	// nothing.
	if r.Name != strings.TrimSpace(r.Name) {
		errs = append(errs, fmt.Errorf("%w: role name %q has leading or trailing whitespace", ErrInvalidPolicy, r.Name))
	}
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, fmt.Errorf("%w: role with empty name", ErrInvalidPolicy))
	}
	for _, tool := range r.Tools {
		if strings.TrimSpace(tool) == "" {
			errs = append(errs, fmt.Errorf("%w: role %q has an empty tool name", ErrInvalidPolicy, r.Name))
		}
	}

	return errors.Join(errs...)
}

// Policy maps a caller's IdP groups to the roles they hold, and answers
// the one question the request path asks: may this identity call this
// tool?
//
// A Policy is immutable once built. Rebuilding it is how it changes,
// which keeps the request path free of any locking discipline.
//
// That immutability is enforced by copying, not merely documented, and
// the distinction is not academic: a Role's Tools is a slice, so simply
// storing the caller's Role would leave the policy sharing a backing
// array with whoever built it -- and RolesFor would hand that same array
// to the request path. Both were true in an earlier version of this file
// and were caught by test: mutating the caller's slice after
// construction, or mutating the slice returned by RolesFor, silently
// rewrote what the live policy authorized. Every Tools slice crossing
// this type's boundary is cloned, in both directions.
type Policy struct {
	roles       map[string]Role
	groupToRole map[string]string
}

// NewPolicy builds a Policy from the defined roles and a mapping of IdP
// group name to role name.
//
// It returns ErrNoSuchRole if the mapping references a role that does not
// exist. That check happens here, at construction, rather than at request
// time: a typo in a group mapping should fail at startup, loudly, not
// silently deny a real analyst their tools during an incident.
func NewPolicy(roles []Role, groupToRole map[string]string) (*Policy, error) {
	byName := make(map[string]Role, len(roles))
	for _, r := range roles {
		if err := ValidateRole(r); err != nil {
			return nil, err
		}
		if _, dup := byName[r.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate role %q", ErrInvalidPolicy, r.Name)
		}
		// Clone Tools: see the note on Policy. Without this the policy
		// shares a backing array with the caller's slice.
		byName[r.Name] = Role{Name: r.Name, Tools: slices.Clone(r.Tools)}
	}

	mapping := make(map[string]string, len(groupToRole))
	for group, roleName := range groupToRole {
		if strings.TrimSpace(group) == "" {
			return nil, fmt.Errorf("%w: empty group name in mapping", ErrInvalidPolicy)
		}
		if _, ok := byName[roleName]; !ok {
			return nil, fmt.Errorf("%w: group %q maps to undefined role %q", ErrNoSuchRole, group, roleName)
		}
		mapping[group] = roleName
	}

	return &Policy{roles: byName, groupToRole: mapping}, nil
}

// RolesFor returns the roles an identity holds, resolved from its group
// claims. Groups with no mapping are ignored rather than rejected: an IdP
// commonly carries groups that have nothing to do with this gateway, and
// treating an unrelated group as an error would make the gateway break
// every time someone is added to an unrelated team.
//
// The result is deterministic (sorted by role name) so that audit records
// and tests don't depend on map iteration order.
func (p *Policy) RolesFor(id Identity) []Role {
	var names []string
	for _, g := range id.Groups {
		if roleName, ok := p.groupToRole[g]; ok && !slices.Contains(names, roleName) {
			names = append(names, roleName)
		}
	}
	slices.Sort(names)

	out := make([]Role, 0, len(names))
	for _, n := range names {
		r := p.roles[n]
		// Clone on the way out too. Returning p.roles[n] directly would
		// hand the caller -- which is the request path -- a slice aliasing
		// the policy's own storage, so `p.RolesFor(id)[0].Tools[0] = ...`
		// would rewrite what the gateway authorizes. See the note on Policy.
		out = append(out, Role{Name: r.Name, Tools: slices.Clone(r.Tools)})
	}
	return out
}

// Authorize reports whether id may call tool, returning nil if allowed
// and ErrForbidden if not.
//
// An identity with no mapped role is forbidden everything. That is the
// fail-closed default and it is deliberate: a caller the IdP authenticated
// but this gateway has no mapping for is a caller nobody decided to grant
// anything, and the safe reading of "nobody decided" is "no".
func (p *Policy) Authorize(id Identity, tool string) error {
	for _, r := range p.RolesFor(id) {
		if r.Allows(tool) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q may not call %q", ErrForbidden, id.Subject, tool)
}

// AllowedTools returns every tool this identity may call, across all the
// roles it holds, sorted and deduplicated.
//
// This is what the Gateway Endpoint uses to filter the aggregated tool
// list before it reaches the client. Filtering the *list* with the same
// Policy that gates the *call* is what keeps the two consistent -- a tool
// a caller cannot invoke should never have appeared in their list, and a
// tool in their list must be invocable.
func (p *Policy) AllowedTools(id Identity) []string {
	var out []string
	for _, r := range p.RolesFor(id) {
		for _, t := range r.Tools {
			if !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ResourceIdentifier parses and validates an OAuth resource or issuer
// identifier: this gateway's own `aud` value, the OIDC issuer, and every
// entry of the advertised authorization-server list.
//
// RFC 9728 section 2 and RFC 8707 section 2 both require an absolute URI
// with no fragment. This adds one rule of its own: the scheme must be https
// unless the host is a loopback address (or the caller has explicitly opted
// out). A resource identifier advertised over http:// is an instruction to
// every client that reads it to put a bearer token on the wire in
// cleartext.
//
// # Why it lives in the domain package
//
// This is the one rule in the file that is not "who may call what", and it
// is here for a reason that outranks tidiness. It used to live in the HTTP
// adapter that renders the RFC 9728 document, which is the only place it is
// *applied* -- and config.Validate, which is where an operator finds out
// their file is wrong, restated a much looser version of it. So `audience =
// "mcp-gateway"` validated, worked for every operator subcommand, and
// killed serve on the next restart with an error nothing had shown the
// person who wrote it (GAB-30 item 1). The fix is one predicate with two
// callers, and it has to sit somewhere both may import: the adapter depends
// on this package already, and the config package builds this package's
// Policy.
//
// It does not make this package speak HTTP. It parses a URI and looks at a
// scheme; it opens no connection, holds no client, and knows nothing about
// requests. What it encodes is an authorization rule -- which identifiers
// this resource server will answer to -- expressed in the terms RFC 8707
// writes it in.
func ResourceIdentifier(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid URI", raw)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("%q must be an absolute URI with a host", raw)
	}
	// The raw check is not redundant with the parsed one: a trailing "#"
	// leaves Fragment empty, and the "#" still reaches every client that
	// reads the document.
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%q must not carry a fragment (RFC 9728 section 2)", raw)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("%q must not carry a query string", raw)
	}
	if u.Scheme != "https" && !allowInsecure && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("%w: %q must use https -- an http resource identifier tells clients to send bearer tokens in cleartext",
			ErrInsecureResourceIdentifier, raw)
	}
	return u, nil
}

// isLoopbackHost reports whether host names the local machine, the one case
// where http:// is not a credential-on-the-wire problem.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}
