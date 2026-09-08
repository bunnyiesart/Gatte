// Tests for the OIDC adapter.
//
// Every test here is hermetic: no identity provider runs, nothing leaves
// the machine. An httptest.Server plays the IdP, serving a discovery
// document and a JWKS built from an RSA key generated in-process, and the
// tests mint their own JWTs against that key. ADR-0008's Compliance
// section asks for exactly this shape -- expired, wrong audience, wrong
// issuer, bad signature, alg none, and a valid token -- with no IdP
// running.
package oidc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/bunnyiesart/Gatte/internal/access"
	oidcadapter "github.com/bunnyiesart/Gatte/internal/access/oidc"
)

const (
	testAudience = "mcp-gateway"
	testKeyID    = "idp-signing-key"
	attackerKID  = "attacker-key"
)

// RSA key generation is the slowest thing in this package, so the two keys
// are generated once and shared. Neither is ever mutated.
var (
	keysOnce    sync.Once
	idpKey      *rsa.PrivateKey
	attackerKey *rsa.PrivateKey
)

func testKeys(t *testing.T) (idp, attacker *rsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if idpKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if attackerKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return idpKey, attackerKey
}

// harness is a fake OIDC provider plus the log sink the Verifier writes to.
type harness struct {
	t      *testing.T
	server *httptest.Server
	issuer string
	key    *rsa.PrivateKey
	logs   *bytes.Buffer
}

// newHarness stands up a discovery endpoint and a JWKS endpoint.
//
// The discovery document deliberately advertises HS256 and none alongside
// RS256. A verifier that trusted `id_token_signing_alg_values_supported`
// would widen itself to accept them; this adapter pins its own algorithm
// list, so every test in this file also asserts, implicitly, that a
// hostile or misconfigured discovery document cannot loosen verification.
func newHarness(t *testing.T) *harness {
	t.Helper()
	key, _ := testKeys(t)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"authorization_endpoint":                server.URL + "/authorize",
			"token_endpoint":                        server.URL + "/token",
			"jwks_uri":                              server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256", "HS256", "none"},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				Key:       key.Public(),
				KeyID:     testKeyID,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}},
		})
	})

	return &harness{t: t, server: server, issuer: server.URL, key: key, logs: &bytes.Buffer{}}
}

// verifier builds a Verifier against the fake provider. mutate may adjust
// the Config before construction.
func (h *harness) verifier(mutate ...func(*oidcadapter.Config)) *oidcadapter.Verifier {
	h.t.Helper()
	cfg := oidcadapter.Config{
		Issuer:     h.issuer,
		Audience:   testAudience,
		HTTPClient: h.server.Client(),
		Logger:     slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := oidcadapter.New(context.Background(), cfg)
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	return v
}

// claims returns a claim set that passes every check, for a test to spoil
// one field at a time.
func (h *harness) claims() map[string]any {
	return map[string]any{
		"iss":                h.issuer,
		"aud":                testAudience,
		"sub":                "a1b2c3-analyst",
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"exp":                time.Now().Add(time.Hour).Unix(),
		"name":               "Ana Lista",
		"preferred_username": "ana",
		"groups":             []any{"soc-n1", "soc-oncall"},
	}
}

// mint signs claims with the provider's real key and key ID.
func (h *harness) mint(claims map[string]any) string {
	h.t.Helper()
	return sign(h.t, jose.RS256, h.key, testKeyID, claims)
}

// sign produces a compact JWS. key must be acceptable to go-jose for alg.
func sign(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return compact
}

// unsignedToken hand-builds an `alg: none` JWT -- go-jose will not produce
// one, which is itself reassuring, so it is assembled by hand here to make
// sure the verifier is the thing rejecting it.
func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	header := enc([]byte(`{"alg":"none","typ":"JWT"}`))
	return header + "." + enc(payload) + "."
}

// assertRejected is the assertion every failure case shares: the error
// wraps access.ErrUnauthenticated, and neither the error nor anything the
// Verifier logged contains the token or any part of it.
func (h *harness) assertRejected(err error, rawToken string) {
	h.t.Helper()
	if err == nil {
		h.t.Fatal("expected the token to be rejected, got nil error")
	}
	if !errors.Is(err, access.ErrUnauthenticated) {
		h.t.Fatalf("expected an error wrapping access.ErrUnauthenticated, got: %v", err)
	}
	assertNoTokenLeak(h.t, "returned error", err.Error(), rawToken)
	assertNoTokenLeak(h.t, "log output", h.logs.String(), rawToken)
}

// assertNoTokenLeak fails if haystack contains the token or any
// non-trivial segment of it. The failure message never prints the token.
func assertNoTokenLeak(t *testing.T, where, haystack, rawToken string) {
	t.Helper()
	if rawToken == "" {
		return
	}
	if strings.Contains(haystack, rawToken) {
		t.Fatalf("%s contains the raw bearer token", where)
	}
	for i, segment := range strings.Split(rawToken, ".") {
		if len(segment) >= 8 && strings.Contains(haystack, segment) {
			t.Fatalf("%s contains segment %d of the raw bearer token", where, i)
		}
	}
}

func TestVerifyValidToken(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	identity, err := v.Verify(context.Background(), h.mint(h.claims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if identity.Subject != "a1b2c3-analyst" {
		t.Errorf("Subject = %q, want %q", identity.Subject, "a1b2c3-analyst")
	}
	if identity.Name != "Ana Lista" {
		t.Errorf("Name = %q, want %q", identity.Name, "Ana Lista")
	}
	if want := []string{"soc-n1", "soc-oncall"}; !slices.Equal(identity.Groups, want) {
		t.Errorf("Groups = %v, want %v", identity.Groups, want)
	}
}

func TestVerifyDisplayNameFallbacks(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	t.Run("falls back to preferred_username", func(t *testing.T) {
		claims := h.claims()
		delete(claims, "name")
		identity, err := v.Verify(context.Background(), h.mint(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if identity.Name != "ana" {
			t.Errorf("Name = %q, want %q", identity.Name, "ana")
		}
	})

	t.Run("falls back to sub", func(t *testing.T) {
		claims := h.claims()
		delete(claims, "name")
		delete(claims, "preferred_username")
		identity, err := v.Verify(context.Background(), h.mint(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if identity.Name != "a1b2c3-analyst" {
			t.Errorf("Name = %q, want the subject", identity.Name)
		}
	})
}

func TestVerifyGroupsClaim(t *testing.T) {
	t.Run("absent yields no groups, not an error", func(t *testing.T) {
		h := newHarness(t)
		v := h.verifier()
		claims := h.claims()
		delete(claims, "groups")

		identity, err := v.Verify(context.Background(), h.mint(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(identity.Groups) != 0 {
			t.Errorf("Groups = %v, want none", identity.Groups)
		}
	})

	t.Run("not an array yields no groups, not a panic", func(t *testing.T) {
		h := newHarness(t)
		v := h.verifier()
		claims := h.claims()
		claims["groups"] = "soc-n1" // some providers emit a bare string

		identity, err := v.Verify(context.Background(), h.mint(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(identity.Groups) != 0 {
			t.Errorf("Groups = %v, want none (fail closed)", identity.Groups)
		}
	})

	t.Run("array with non-string entries keeps the strings", func(t *testing.T) {
		h := newHarness(t)
		v := h.verifier()
		claims := h.claims()
		claims["groups"] = []any{"soc-n1", 42, nil, "dfir"}

		identity, err := v.Verify(context.Background(), h.mint(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if want := []string{"soc-n1", "dfir"}; !slices.Equal(identity.Groups, want) {
			t.Errorf("Groups = %v, want %v", identity.Groups, want)
		}
	})

	t.Run("configurable claim name", func(t *testing.T) {
		h := newHarness(t)
		v := h.verifier(func(c *oidcadapter.Config) { c.GroupsClaim = "roles" })
		claims := h.claims()
		delete(claims, "groups")
		claims["roles"] = []any{"dfir-lead"}

		identity, err := v.Verify(context.Background(), h.mint(claims))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if want := []string{"dfir-lead"}; !slices.Equal(identity.Groups, want) {
			t.Errorf("Groups = %v, want %v", identity.Groups, want)
		}
	})

	t.Run("groups feed the domain policy", func(t *testing.T) {
		// The point of mapping Groups at all: an identity this adapter
		// produced has to be usable by access.Policy unchanged.
		h := newHarness(t)
		v := h.verifier()
		identity, err := v.Verify(context.Background(), h.mint(h.claims()))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		policy, err := access.NewPolicy(
			[]access.Role{{Name: "n1-triage", Tools: []string{"casemgmt.list_cases"}}},
			map[string]string{"soc-n1": "n1-triage"},
		)
		if err != nil {
			t.Fatalf("NewPolicy: %v", err)
		}
		if err := policy.Authorize(identity, "casemgmt.list_cases"); err != nil {
			t.Errorf("Authorize: %v", err)
		}
	})
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	claims := h.claims()
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := h.mint(claims)

	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	// A genuine token from the same IdP, minted for a different service.
	// RFC 8707: it must not be usable here.
	claims := h.claims()
	claims["aud"] = "some-other-internal-service"
	token := h.mint(claims)

	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	claims := h.claims()
	claims["iss"] = "https://not-our-idp.example"
	token := h.mint(claims)

	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

func TestVerifyRejectsUnknownSigningKey(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	_, attacker := testKeys(t)
	// Correct claims in every respect, signed by a key the JWKS has never
	// published. The unfamiliar kid also forces a JWKS re-fetch, so this
	// exercises the "maybe the key rotated" path and still fails.
	token := sign(t, jose.RS256, attacker, attackerKID, h.claims())

	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	token := unsignedToken(t, h.claims())

	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

// TestVerifyRejectsAlgorithmConfusion is the HS256-against-an-RSA-public-key
// attack: the attacker takes the public key everyone can fetch from the
// JWKS and uses its bytes as an HMAC secret. A verifier that honoured the
// token's own `alg` header would validate it.
func TestVerifyRejectsAlgorithmConfusion(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	publicDER, err := x509.MarshalPKIXPublicKey(h.key.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	// Same kid as the real signing key, so nothing but the algorithm check
	// stands between this token and acceptance.
	token := sign(t, jose.HS256, publicDER, testKeyID, h.claims())

	_, err = v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	valid := h.mint(h.claims())
	cases := map[string]string{
		"empty":              "",
		"whitespace":         "   ",
		"garbage":            "not-a-jwt-at-all",
		"two segments":       "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0",
		"truncated":          valid[:len(valid)/2],
		"tampered signature": valid[:len(valid)-4] + "AAAA",
		"json in the clear":  `{"sub":"admin","groups":["dfir-lead"]}`,
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), token)
			h.assertRejected(err, token)
		})
	}
}

func TestVerifyRejectsTokenWithoutSubject(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	claims := h.claims()
	delete(claims, "sub")
	token := h.mint(claims)

	// Nothing to attribute an audited call to, so the token is useless even
	// though it is cryptographically fine.
	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

// TestVerifyErrorsAreIndistinguishable is the anti-oracle test. If any of
// these failures produced a distinguishable error, a caller holding a
// token could binary-search its way to knowing whether it was genuine,
// whether it was for another service, or merely stale.
func TestVerifyErrorsAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()
	_, attacker := testKeys(t)

	expired := h.claims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	wrongAudience := h.claims()
	wrongAudience["aud"] = "some-other-internal-service"

	wrongIssuer := h.claims()
	wrongIssuer["iss"] = "https://not-our-idp.example"

	noSubject := h.claims()
	delete(noSubject, "sub")

	tokens := map[string]string{
		"expired":        h.mint(expired),
		"wrong audience": h.mint(wrongAudience),
		"wrong issuer":   h.mint(wrongIssuer),
		"unknown key":    sign(t, jose.RS256, attacker, attackerKID, h.claims()),
		"alg none":       unsignedToken(t, h.claims()),
		"garbage":        "not-a-jwt-at-all",
		"empty":          "",
		"no subject":     h.mint(noSubject),
	}

	seen := make(map[string][]string)
	for name, token := range tokens {
		_, err := v.Verify(context.Background(), token)
		h.assertRejected(err, token)
		seen[err.Error()] = append(seen[err.Error()], name)
	}

	if len(seen) != 1 {
		var distinct []string
		for message, causes := range seen {
			distinct = append(distinct, message+" <- "+strings.Join(causes, ", "))
		}
		slices.Sort(distinct)
		t.Fatalf("failure causes are distinguishable by their error text:\n%s", strings.Join(distinct, "\n"))
	}
}

// TestVerifySurvivesIdPOutageWhileKeysAreCached pins the behaviour
// documented on Verifier: a momentary IdP outage must not take the whole
// SOC down, because the JWKS is already cached...
func TestVerifySurvivesIdPOutageWhileKeysAreCached(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	if _, err := v.Verify(context.Background(), h.mint(h.claims())); err != nil {
		t.Fatalf("Verify before outage: %v", err)
	}

	h.server.Close() // the IdP falls over

	if _, err := v.Verify(context.Background(), h.mint(h.claims())); err != nil {
		t.Fatalf("Verify during outage should still succeed from the cached JWKS: %v", err)
	}
}

// ...and the other half of the same decision: once a token needs a key
// that is not cached, an unreachable IdP means rejection. Fail closed.
func TestVerifyFailsClosedWhenIdPIsUnreachableAndKeyIsUnknown(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()

	if _, err := v.Verify(context.Background(), h.mint(h.claims())); err != nil {
		t.Fatalf("Verify before outage: %v", err)
	}

	h.server.Close()

	_, attacker := testKeys(t)
	token := sign(t, jose.RS256, attacker, attackerKID, h.claims())

	_, err := v.Verify(context.Background(), token)
	h.assertRejected(err, token)
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	h := newHarness(t)

	cases := map[string]oidcadapter.Config{
		"no issuer":   {Audience: testAudience},
		"no audience": {Issuer: h.issuer},
		"symmetric signing algorithm": {
			Issuer:               h.issuer,
			Audience:             testAudience,
			SupportedSigningAlgs: []string{"HS256"},
		},
		"alg none": {
			Issuer:               h.issuer,
			Audience:             testAudience,
			SupportedSigningAlgs: []string{"none"},
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.HTTPClient = h.server.Client()
			cfg.Logger = slog.New(slog.NewTextHandler(h.logs, nil))
			if _, err := oidcadapter.New(context.Background(), cfg); err == nil {
				t.Fatal("expected New to refuse this configuration")
			}
		})
	}
}

func TestNewFailsWhenDiscoveryFails(t *testing.T) {
	h := newHarness(t)
	h.server.Close()

	_, err := oidcadapter.New(context.Background(), oidcadapter.Config{
		Issuer:     h.issuer,
		Audience:   testAudience,
		HTTPClient: h.server.Client(),
		Logger:     slog.New(slog.NewTextHandler(h.logs, nil)),
	})
	if err == nil {
		t.Fatal("expected New to fail when the IdP is unreachable")
	}
}

func TestDefaultSigningAlgsCannotBeMutatedByCallers(t *testing.T) {
	first := oidcadapter.DefaultSigningAlgs()
	if len(first) == 0 {
		t.Fatal("DefaultSigningAlgs returned nothing")
	}
	if slices.Contains(first, "HS256") || slices.Contains(first, "none") {
		t.Fatalf("DefaultSigningAlgs must be asymmetric only, got %v", first)
	}
	first[0] = "HS256"
	if slices.Contains(oidcadapter.DefaultSigningAlgs(), "HS256") {
		t.Fatal("mutating the returned slice changed the package defaults")
	}
}
