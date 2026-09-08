// Package access is the domain package for the Access Control component
// (design/02-components.md): it decides who a caller is and which tools
// they may reach, and it is where the client's own credential stops.
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to HTTP, JWT libraries, or any identity provider.
// The oidc subpackage is the adapter.
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
		// Reject a name that isn't already trimmed rather than trimming it
		// silently: "admin " stored as-is is a distinct map key from
		// "admin", so a trailing space produces a role no group mapping
		// will ever resolve to -- a role that exists, looks correct in
		// config, and grants nothing.
		if r.Name != strings.TrimSpace(r.Name) {
			return nil, fmt.Errorf("%w: role name %q has leading or trailing whitespace", ErrInvalidPolicy, r.Name)
		}
		if r.Name == "" {
			return nil, fmt.Errorf("%w: role with empty name", ErrInvalidPolicy)
		}
		if _, dup := byName[r.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate role %q", ErrInvalidPolicy, r.Name)
		}
		for _, tool := range r.Tools {
			if strings.TrimSpace(tool) == "" {
				return nil, fmt.Errorf("%w: role %q has an empty tool name", ErrInvalidPolicy, r.Name)
			}
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
