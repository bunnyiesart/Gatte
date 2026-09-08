// Package oidc is the OpenID Connect adapter for the Access Control
// domain (internal/access): it turns a bearer token minted by the team's
// self-hosted identity provider into an access.Identity.
//
// Per design/adr/0008-identity-model-self-hosted-oidc.md the gateway is an
// OAuth 2.0 Resource Server. It never issues identity and never forwards a
// caller's token upstream (ADR-0003's credential stripping); this package
// only answers "is this token real, is it for me, and who does it say the
// caller is?".
//
// It is deliberately provider-agnostic. Keycloak, Authelia and Zitadel are
// all reached through the same three inputs -- issuer URL, expected
// audience, and the name of the claim that carries groups -- so which IdP
// the team runs is a deployment decision, not a code change. Nothing in
// this package names a vendor.
//
// Verification itself is delegated to github.com/coreos/go-oidc/v3, again
// per ADR-0008: JWKS fetching, key rotation and JWS signature checking are
// cryptographic plumbing where a hand-rolled implementation is notoriously
// where "passes my tests" and "is correct" diverge in silence.
package oidc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// DefaultGroupsClaim is the claim inspected for a caller's groups when
// Config.GroupsClaim is empty.
//
// It is configurable rather than fixed because providers disagree: a claim
// called "groups" is the common case, but a deployment may need "roles" or
// a provider-specific name. That single knob is most of what keeps this
// adapter provider-agnostic.
const DefaultGroupsClaim = "groups"

// defaultDiscoveryTimeout bounds discovery and JWKS HTTP requests when the
// caller does not supply its own http.Client. An IdP that accepts a
// connection and then never answers must not be able to pin a request
// goroutine open indefinitely.
const defaultDiscoveryTimeout = 10 * time.Second

// rejection is the single message every Verify failure carries. It is a
// constant on purpose: see Verifier's doc comment.
const rejection = "token could not be verified"

// allowedSigningAlgs is the set of JWS algorithms this package will ever
// accept, and the reason algorithm confusion cannot happen here.
//
// Every entry is asymmetric. The HMAC family (HS256/384/512) is absent and
// cannot be configured in, because an HMAC-signed token verified against a
// key set of *public* keys is the classic algorithm-confusion attack: the
// verifying key is public, so anyone can mint a token that "verifies". The
// "none" algorithm is absent for the obvious reason. go-jose (through
// go-oidc) will not even parse a JWS whose header algorithm is outside the
// list handed to it, so an unlisted alg is rejected before any signature
// or claim is looked at.
var allowedSigningAlgs = []string{
	goidc.RS256, goidc.RS384, goidc.RS512,
	goidc.ES256, goidc.ES384, goidc.ES512,
	goidc.PS256, goidc.PS384, goidc.PS512,
	goidc.EdDSA,
}

// DefaultSigningAlgs returns the JWS algorithms accepted when
// Config.SupportedSigningAlgs is empty: the asymmetric algorithms of RFC
// 7518, and nothing else.
//
// It returns a fresh copy each call so a caller cannot widen the package's
// own defaults by mutating the returned slice.
func DefaultSigningAlgs() []string {
	return slices.Clone(allowedSigningAlgs)
}

// Config is everything this adapter needs to know about a deployment's
// identity provider.
type Config struct {
	// Issuer is the IdP's issuer URL, e.g.
	// "https://auth.example.internal". OIDC discovery is performed against
	// Issuer + "/.well-known/openid-configuration", and the issuer the
	// discovery document declares must match. Required.
	Issuer string

	// Audience is the value that must appear in a token's `aud` claim,
	// normally this gateway's client ID at the IdP. Required, and there is
	// deliberately no way to switch the check off: RFC 8707 audience
	// validation is what stops a token the same IdP minted for some other
	// internal service from being replayed here.
	Audience string

	// GroupsClaim names the claim carrying the caller's groups.
	// Defaults to DefaultGroupsClaim.
	GroupsClaim string

	// SupportedSigningAlgs restricts which JWS algorithms are accepted.
	// Defaults to DefaultSigningAlgs(). Every entry must be one of those
	// algorithms; New rejects anything else, so a configuration mistake
	// cannot introduce a symmetric or "none" algorithm.
	SupportedSigningAlgs []string

	// HTTPClient is used for discovery and for JWKS fetches. Optional; a
	// client with a modest timeout is used when nil.
	HTTPClient *http.Client

	// Logger receives the real reason a token was rejected, which the
	// returned error deliberately withholds. Optional; defaults to
	// slog.Default().
	Logger *slog.Logger
}

// Verifier verifies bearer tokens against a single OIDC issuer and
// implements access.TokenVerifier.
//
// # Uniform errors
//
// Every failure -- malformed token, bad signature, wrong issuer, wrong
// audience, expired, missing subject, unreachable IdP -- returns the exact
// same error text wrapping access.ErrUnauthenticated. A caller holding a
// token must not be able to learn *why* it was refused, because that turns
// the gateway into an oracle: "wrong audience" tells an attacker the
// signature was fine and the token is genuine, "expired" tells them the
// audience matched. The distinguishing detail goes to Config.Logger, where
// operators can see it and attackers cannot.
//
// # Behaviour when the IdP is unreachable
//
// This was decided deliberately, not discovered in production (ADR-0008
// records it as a mandatory Phase 4 decision):
//
//   - Verification fails closed. If a signing key is not already cached and
//     the JWKS endpoint cannot be reached, no token is accepted. The
//     gateway never falls back to skipping signature verification, and
//     never admits a caller it could not verify.
//   - A brief IdP outage does not immediately stop the SOC working. go-oidc
//     caches the issuer's JWKS in memory and re-fetches only when it meets
//     a key ID it has not seen -- so while the signing keys are unchanged,
//     verification keeps succeeding from cache with no network call at all.
//     Signing keys rotate rarely; verifying against a cached key is safe
//     until that key is revoked.
//
// The consequence worth stating plainly: a *long* IdP outage that outlives
// a key rotation does lock everyone out. That is the fail-closed side of
// the trade, and it is the intended behaviour.
//
// A Verifier is safe for concurrent use and is meant to be long-lived --
// one per issuer, for the life of the process. Constructing a new one per
// request would throw away the JWKS cache the paragraph above depends on.
type Verifier struct {
	verifier    *goidc.IDTokenVerifier
	groupsClaim string
	logger      *slog.Logger
}

// Verifier implements the domain port; this fails the build if it stops
// doing so.
var _ access.TokenVerifier = (*Verifier)(nil)

// New performs OIDC discovery against cfg.Issuer and returns a Verifier
// ready to verify tokens.
//
// ctx bounds the discovery request. It is also retained by go-oidc as a
// carrier for the HTTP client used by later JWKS fetches -- its
// cancellation is explicitly ignored for those, so cancelling ctx after
// New returns does not disable the Verifier.
//
// Discovery happening once, at construction, is what makes a broken issuer
// URL or an unreachable IdP a loud startup failure rather than a silent
// 401 for every analyst during an incident.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		// Refusing to construct, rather than defaulting to "accept any
		// audience", is the fail-closed reading of a missing setting.
		return nil, fmt.Errorf("oidc: audience is required; a verifier that skips audience validation would accept tokens minted for other services")
	}

	algs := cfg.SupportedSigningAlgs
	if len(algs) == 0 {
		algs = DefaultSigningAlgs()
	} else {
		algs = slices.Clone(algs)
		for _, alg := range algs {
			if !slices.Contains(allowedSigningAlgs, alg) {
				// %q on a config value the operator typed, never on token
				// input.
				return nil, fmt.Errorf("oidc: signing algorithm %q is not an accepted asymmetric algorithm", alg)
			}
		}
	}

	groupsClaim := strings.TrimSpace(cfg.GroupsClaim)
	if groupsClaim == "" {
		groupsClaim = DefaultGroupsClaim
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultDiscoveryTimeout}
	}
	ctx = goidc.ClientContext(ctx, client)

	provider, err := goidc.NewProvider(ctx, issuer)
	if err != nil {
		// A startup error, not a token error: the operator needs the
		// detail, and no attacker-controlled input is in scope here.
		return nil, fmt.Errorf("oidc: discovery against issuer %q failed: %w", issuer, err)
	}

	// SupportedSigningAlgs is set explicitly rather than left empty. Left
	// empty, go-oidc adopts whatever `id_token_signing_alg_values_supported`
	// the discovery document advertises -- which would let the IdP (or
	// anyone who can tamper with its metadata) widen what this gateway
	// accepts. Setting it here means discovery can only ever be narrower in
	// practice, never broader.
	verifier := provider.VerifierContext(ctx, &goidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: algs,
		// Every check left at its default (enabled): signature, issuer,
		// audience, expiry. Nothing here sets a Skip* or Insecure* flag,
		// and nothing should.
	})

	return &Verifier{
		verifier:    verifier,
		groupsClaim: groupsClaim,
		logger:      logger,
	}, nil
}

// Verify implements access.TokenVerifier. It validates rawToken's
// signature against the issuer's JWKS and checks issuer, audience and
// expiry, then maps the claims it trusts into an access.Identity:
//
//   - `sub` becomes Identity.Subject, and a token without one is rejected:
//     the audit trail has nothing to attribute a call to without it.
//   - `name`, else `preferred_username`, else `sub` becomes Identity.Name,
//     which is for humans reading logs and is never used for a decision.
//   - The configured groups claim becomes Identity.Groups.
//
// rawToken is attacker-controlled input. It never appears in the returned
// error, in any log line, or in the returned Identity -- access.Identity
// has no field for it by design, and echoing it is exactly how a bearer
// credential ends up sitting in a log aggregator.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (access.Identity, error) {
	if strings.TrimSpace(rawToken) == "" {
		return access.Identity{}, v.reject(ctx, "empty bearer token", nil, rawToken)
	}

	// This single call covers signature (against the cached-or-fetched
	// JWKS), permitted algorithm, issuer, audience and expiry.
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return access.Identity{}, v.reject(ctx, "token failed OIDC verification", err, rawToken)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return access.Identity{}, v.reject(ctx, "token payload is not a JSON object", err, rawToken)
	}

	if idToken.Subject == "" {
		return access.Identity{}, v.reject(ctx, "token has no sub claim", nil, rawToken)
	}

	return access.Identity{
		Subject: idToken.Subject,
		Name:    displayName(claims, idToken.Subject),
		Groups:  v.groupsFrom(ctx, claims),
	}, nil
}

// reject logs why a token was refused and returns the one error every
// failure path returns. The returned value is byte-for-byte identical
// regardless of reason, so it carries no signal an attacker can probe;
// reason and cause reach the operator's log instead.
//
// cause is scrubbed before logging: go-oidc and encoding/json can quote
// fragments of what they failed to parse, and what they failed to parse is
// the token.
func (v *Verifier) reject(ctx context.Context, reason string, cause error, rawToken string) error {
	attrs := []slog.Attr{slog.String("reason", reason)}
	if cause != nil {
		attrs = append(attrs, slog.String("detail", scrub(cause.Error(), rawToken)))
	}
	v.logger.LogAttrs(ctx, slog.LevelWarn, "oidc: rejected bearer token", attrs...)

	return fmt.Errorf("%w: %s", access.ErrUnauthenticated, rejection)
}

// groupsFrom reads the configured groups claim.
//
// A missing claim, a claim that is not an array, or an array element that
// is not a string all yield no group rather than an error. That is
// fail-closed, not lenient: per access.Policy.Authorize an identity with no
// mapped group is forbidden everything, so the worst case of a
// misconfigured claim name is an analyst who can call nothing -- never an
// analyst who can call something they should not. It is logged so the
// misconfiguration is visible rather than mysterious.
func (v *Verifier) groupsFrom(ctx context.Context, claims map[string]any) []string {
	raw, present := claims[v.groupsClaim]
	if !present || raw == nil {
		return nil
	}

	list, ok := raw.([]any)
	if !ok {
		v.logger.LogAttrs(ctx, slog.LevelWarn, "oidc: groups claim is not an array; treating caller as having no groups",
			slog.String("claim", v.groupsClaim),
			slog.String("type", fmt.Sprintf("%T", raw)),
		)
		return nil
	}

	groups := make([]string, 0, len(list))
	for _, element := range list {
		s, ok := element.(string)
		if !ok {
			v.logger.LogAttrs(ctx, slog.LevelWarn, "oidc: ignoring non-string entry in groups claim",
				slog.String("claim", v.groupsClaim),
				slog.String("type", fmt.Sprintf("%T", element)),
			)
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			groups = append(groups, s)
		}
	}
	return groups
}

// displayName picks the most human-readable label available, falling back
// to the subject so Identity.Name is never empty in an audit record.
func displayName(claims map[string]any, subject string) string {
	for _, claim := range []string{"name", "preferred_username"} {
		if s, ok := claims[claim].(string); ok {
			if s = strings.TrimSpace(s); s != "" {
				return s
			}
		}
	}
	return subject
}

// scrub removes rawToken, and each of its dot-separated segments, from a
// diagnostic string. Defense in depth for the log path: the callers here
// are not expected to echo the token, but "not expected to" is not a
// guarantee worth resting a credential on.
func scrub(detail, rawToken string) string {
	if rawToken == "" {
		return detail
	}
	detail = strings.ReplaceAll(detail, rawToken, "[redacted]")
	for _, segment := range strings.Split(rawToken, ".") {
		// Short segments would match harmlessly common substrings; a JWS
		// segment carrying anything sensitive is far longer than this.
		if len(segment) >= 8 {
			detail = strings.ReplaceAll(detail, segment, "[redacted]")
		}
	}
	return detail
}
