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

// GrantAll is the one value a [Role.Grants] list may hold in place of tool
// ids: it grants every tool the named backend advertises, now and later.
//
// It is meaningful ONLY inside Grants. In [Role.Tools] the same three
// characters are an ordinary name matching a tool literally called "*",
// and that asymmetry is deliberate rather than an oversight -- see the
// note on Tools.
const GrantAll = "*"

// nameSeparator is the character that joins an upstream's name to a tool's
// own name in the namespaced names this package gates.
//
// It is a second declaration of gateway.NameSeparator, and that is a debt
// paid knowingly rather than a copy nobody noticed. internal/gateway
// imports this package, so this package cannot import it back for the
// original; and this package genuinely needs the value, because a per-
// backend grant is resolved by finding which backend a namespaced name
// belongs to. The two are pinned equal by
// TestNameSeparatorMatchesGateway in grants_external_test.go, which sits
// in package access_test precisely so it may import both and fail the
// build the day they diverge.
const nameSeparator = "."

// Role is a named subset of the aggregated tool list.
//
// This is deliberately a concrete list of tool names rather than a set of
// abstract scopes or a policy expression. At roughly 65 tools and two
// roles this is a list a person can read in full and reason about at
// 03:00 during an incident; a policy DSL would be one more thing nobody
// on a seven-person team remembers how to debug (a conclusion reached in
// the trade-off analysis recorded in DEVELOPMENT-LOG.md, and the reason
// Cedar/CEL engines were explicitly rejected).
//
// A Role carries two forms of the same grant, unioned. Tools is the flat
// list this package started with; Grants composes the role per backend and
// is what design/adr/0016 calls a profile. Neither supersedes the other,
// and a role may use both.
//
// Every method below assumes the Role passed [ValidateRole]. [NewPolicy]
// guarantees that for any Role the request path can reach; a Role built by
// hand and queried directly has not, and [Role.Allows] documents what it
// relies on.
type Role struct {
	// Name identifies the role, e.g. "n1-triage" or "dfir-lead".
	Name string
	// Tools are the namespaced tool names this role may call, e.g.
	// "casemgmt.list_cases". Matching is exact: there is no wildcard here,
	// and "casemgmt.*" in this list is a name that matches nothing rather
	// than a prefix. A wildcard over a whole backend is written in Grants,
	// where it is a distinct syntactic act an operator cannot reach by
	// typo.
	Tools []string
	// Grants composes this role per backend: the key is an upstream's
	// registered name and the value is the tool ids granted on it, as that
	// upstream calls them -- NOT namespaced, since the key already says
	// which backend they belong to.
	//
	// A backend absent from this map is not granted at all. That is the
	// deny-by-default half, and it is why there is no "deny" form: the
	// absence of a key is the denial.
	//
	// The single value [GrantAll] in place of a list of ids grants every
	// tool that backend advertises. What that costs is one of two human
	// acts, not both: a tool still has to be approved in Tool Quarantine
	// before anyone can call it, but nobody has to separately decide who
	// may call it. design/adr/0016 states that trade in full; do not read
	// the wildcard as free.
	//
	// Neither a key nor a tool id may contain [nameSeparator], and
	// [ValidateRole] refuses one that does. That is not tidiness: it is
	// half of what makes the backend a namespaced name belongs to
	// unambiguous. The other half is not this package's to enforce -- the
	// registry refuses an upstream *name* containing the separator -- and
	// [Role.Allows] says why both halves are needed.
	Grants map[string][]string
}

// Allows reports whether this role may call the named tool.
//
// tool is a namespaced name ("casemgmt.list_cases"). The flat Tools list
// is matched exactly. A Grants entry matches when tool begins with the
// backend's name followed by the separator and the remainder is either
// listed or covered by [GrantAll].
//
// It relies on two guarantees, and only one of them is this package's.
//
// The first is r having passed [ValidateRole], in exactly one clause: no
// Grants key contains the separator. Without it a key like "casemgmt.sub"
// would match "casemgmt.sub.x" -- a tool that cutting at the first
// separator attributes to the backend "casemgmt", not to "casemgmt.sub" --
// and the grant would match under a backend the operator did not name.
//
// The second is that no registered *upstream name* contains the separator
// either. This package cannot check that and does not own it: it has never
// known what an upstream is. registry.UpstreamServer.Validate refuses such
// a name, and gateway.Gateway.Connect refuses an entry that does not
// satisfy that contract, so every name in the routing table is one upstream
// name, one separator, and one tool name -- which is what makes cutting at
// the first separator recover the upstream that actually serves the call.
//
// Both halves are needed and the second was missing until 11 Sep 2026. An
// upstream registered as "threatintel.staging" had its tools routed under
// "threatintel.staging.<tool>", and a grant key of "threatintel" matched
// that same name with the remainder "staging.<tool>": authorization decided
// about one backend while routing dispatched to another, so a ["*"] grant
// on one upstream served every approved tool of a different one. The first
// half alone could not prevent it -- the offending key contained no
// separator at all.
func (r Role) Allows(tool string) bool {
	if slices.Contains(r.Tools, tool) {
		return true
	}
	for backend, ids := range r.Grants {
		rest, ok := strings.CutPrefix(tool, backend+nameSeparator)
		// rest == "" rejects "casemgmt.", which is not a tool of casemgmt
		// but a malformed name; under GrantAll it would otherwise pass.
		if !ok || rest == "" {
			continue
		}
		if slices.Contains(ids, GrantAll) || slices.Contains(ids, rest) {
			return true
		}
	}
	return false
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
// is written before the backend it is for is registered. The same applies
// to a Grants key: see validateGrants, which owns every structural rule
// about the per-backend form and states why the existence question is not
// one of them.
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

	errs = append(errs, validateGrants(r)...)

	return errors.Join(errs...)
}

// validateGrants checks the structure of r.Grants.
//
// Every rule here is structural -- it can be decided by looking at the map
// alone. Whether a key names an upstream that exists is deliberately NOT
// checked, and cannot be: upstreams live in the SQLite registry, this
// package has never known what an upstream is, and a grant written before
// the backend it is for is registered is the normal order of work. That
// check is a serve-time diagnostic against the live registry, recorded as
// such in design/adr/0016.
//
// Backends are visited in sorted order so that a file with several
// problems reports them the same way every run; map iteration order would
// otherwise shuffle the operator's error list between two runs over one
// unchanged file.
func validateGrants(r Role) []error {
	if len(r.Grants) == 0 {
		return nil
	}

	backends := make([]string, 0, len(r.Grants))
	for backend := range r.Grants {
		backends = append(backends, backend)
	}
	slices.Sort(backends)

	var errs []error
	for _, backend := range backends {
		// Whitespace is refused rather than trimmed for the reason the
		// role name is: "casemgmt " is a distinct map key, so it would
		// define a grant against a backend no tool is ever namespaced
		// under -- a grant that exists, looks correct in the file, and
		// reaches nothing.
		switch {
		case strings.TrimSpace(backend) == "":
			errs = append(errs, fmt.Errorf("%w: role %q has a grant with an empty backend name", ErrInvalidPolicy, r.Name))
		case backend != strings.TrimSpace(backend):
			errs = append(errs, fmt.Errorf("%w: role %q: grant backend %q has leading or trailing whitespace", ErrInvalidPolicy, r.Name, backend))
		case backend == GrantAll:
			// Refused because it reads as "every backend" and is not that.
			// Left alone it would be a grant over a backend literally named
			// "*", which no upstream can usefully be called -- so the file
			// would state a fleet-wide grant and enforce nothing.
			errs = append(errs, fmt.Errorf(
				"%w: role %q: %q is not a valid grant backend -- there is no wildcard over backends, only over one backend's tools; name each backend you mean to grant",
				ErrInvalidPolicy, r.Name, GrantAll))
		case strings.Contains(backend, nameSeparator):
			// Load-bearing, not cosmetic: see Role.Allows. A key with a
			// separator in it can match a name whose real backend is a
			// different one. It is also only half of the guarantee -- the
			// registry's refusal of an upstream name containing the
			// separator is the other half -- so do not read this rule, or
			// the message below, as making that reach impossible on its own.
			errs = append(errs, fmt.Errorf(
				"%w: role %q: grant backend %q contains %q -- a grant key is an upstream's own name, never a namespaced tool, and a key containing the separator would match tools that belong to a different backend",
				ErrInvalidPolicy, r.Name, backend, nameSeparator))
		}

		ids := r.Grants[backend]
		if slices.Contains(ids, GrantAll) && len(ids) > 1 {
			// "*" plus names is either a half-finished edit or a belief
			// that the two compose into something narrower than "*". They
			// do not: "*" already covers every name beside it, so the file
			// would read as a limit and enforce none.
			errs = append(errs, fmt.Errorf(
				"%w: role %q: grant %q lists %q alongside %d other entr%s -- %q already grants every tool of that backend, so write it alone or drop it and name the tools",
				ErrInvalidPolicy, r.Name, backend, GrantAll, len(ids)-1, plural(len(ids)-1, "y", "ies"), GrantAll))
		}

		seen := make(map[string]bool, len(ids))
		for _, id := range ids {
			switch {
			case strings.TrimSpace(id) == "":
				errs = append(errs, fmt.Errorf("%w: role %q: grant %q has an empty tool id", ErrInvalidPolicy, r.Name, backend))
				continue
			case id != strings.TrimSpace(id):
				errs = append(errs, fmt.Errorf("%w: role %q: grant %q lists tool id %q with leading or trailing whitespace", ErrInvalidPolicy, r.Name, backend, id))
				continue
			case id == GrantAll:
				continue
			case strings.Contains(id, nameSeparator):
				errs = append(errs, fmt.Errorf(
					"%w: role %q: grant %q lists %q, which contains %q -- inside a grant a tool is named as its own backend names it, not namespaced, because the key above already says which backend it is on",
					ErrInvalidPolicy, r.Name, backend, id, nameSeparator))
				continue
			}
			// Harmless to the decision, which is a membership test -- which
			// is exactly why it would sit unnoticed in the file. It is
			// almost always a paste or a half-finished rename, and the
			// person who should see it is the reviewer of that diff.
			if seen[id] {
				errs = append(errs, fmt.Errorf("%w: role %q: grant %q lists tool id %q more than once", ErrInvalidPolicy, r.Name, backend, id))
			}
			seen[id] = true
		}
	}
	return errs
}

// plural picks between two word endings. It exists so an error message
// about one stray entry does not read "1 other entries".
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
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
//
// Grants is worse in the same way and is cloned the same way. A map is a
// reference too, and a shallow copy of one shares every value slice with
// the original -- so a Grants map cloned only at the top level would still
// let `role.Grants["casemgmt"][0] = "delete_case"` rewrite the live
// policy. cloneGrants copies both levels.
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
		// Clone Tools and Grants: see the note on Policy. Without this the
		// policy shares a backing array -- and a map -- with the caller.
		byName[r.Name] = Role{Name: r.Name, Tools: slices.Clone(r.Tools), Grants: cloneGrants(r.Grants)}
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
		out = append(out, Role{Name: r.Name, Tools: slices.Clone(r.Tools), Grants: cloneGrants(r.Grants)})
	}
	return out
}

// cloneGrants deep-copies a grants map: a new map, and a new backing array
// for every list in it. A shallow copy would share every value slice with
// the original, which is the aliasing bug the note on Policy describes one
// level up.
//
// nil in, nil out: a role with no per-backend grants should not acquire an
// empty map on its way through the policy, because reflect.DeepEqual and a
// reader both distinguish the two.
func cloneGrants(g map[string][]string) map[string][]string {
	if g == nil {
		return nil
	}
	out := make(map[string][]string, len(g))
	for backend, ids := range g {
		out[backend] = slices.Clone(ids)
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

// AllowedTools returns the members of advertised this identity may call,
// sorted and deduplicated.
//
// Filtering the *list* with the same Policy that gates the *call* is what
// keeps the two consistent -- a tool a caller cannot invoke should never
// have appeared in their list, and a tool in their list must be invocable.
//
// # Why it takes the list rather than producing one
//
// It used to enumerate: no argument, and a return value documented as
// "every tool this identity may call". That was answerable only while
// every grant was a literal name. [Role.Grants] with [GrantAll] grants
// every tool a backend advertises, which is a fact about the live fleet
// that this package cannot see and must not guess at -- it has never known
// what an upstream is, let alone what one currently serves.
//
// Both ways of keeping the old signature were worse than changing it.
// Returning only the literally-named grants would under-report, and an
// under-reporting filter hides a tool that is nonetheless callable: an
// invisible execution path, which quarantine.Tool.Usable's doc calls out
// as the strictly more dangerous of the two inconsistencies. Returning
// something that pretends to enumerate a wildcard would be the claim this
// project keeps writing ADRs about. So the caller supplies the universe --
// which it always had, since the only thing worth filtering is a list of
// tools that actually exist -- and the answer is total over it.
//
// A name in advertised that no role grants is simply absent from the
// result; nothing is rejected, because "this tool is not yours" is not an
// error at listing time.
func (p *Policy) AllowedTools(id Identity, advertised []string) []string {
	roles := p.RolesFor(id)
	out := make([]string, 0, len(advertised))
	for _, tool := range advertised {
		if slices.Contains(out, tool) {
			continue
		}
		for _, r := range roles {
			if r.Allows(tool) {
				out = append(out, tool)
				break
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
