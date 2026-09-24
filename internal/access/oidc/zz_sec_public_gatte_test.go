package oidc_test

// Additional OIDC authn-bypass shapes (public Gatte), over the hermetic
// fake IdP in oidc_test.go. Those tests cover expired, wrong aud/iss,
// unknown key, alg none, HS256 confusion and malformed tokens; these add
// missing exp, future nbf, audience arrays, header-borne key injection
// (jwk/jku/x5u), the right kid with the wrong key, token substitution in
// the payload, and a JSON-serialised JWS.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestSecVerifyRejectsMissingOrHostileTimeClaims(t *testing.T) {
	cases := map[string]func(map[string]any){
		"exp missing":          func(c map[string]any) { delete(c, "exp") },
		"exp zero":             func(c map[string]any) { c["exp"] = 0 },
		"exp just past":        func(c map[string]any) { c["exp"] = time.Now().Add(-10 * time.Minute).Unix() },
		"nbf far in future":    func(c map[string]any) { c["nbf"] = time.Now().Add(24 * time.Hour).Unix() },
		"exp negative":         func(c map[string]any) { c["exp"] = -1 },
		"exp not a number":     func(c map[string]any) { c["exp"] = map[string]any{"x": 1} },
		"iss trailing slash":   nil, // filled below, needs h
		"aud array without us": func(c map[string]any) { c["aud"] = []any{"another-service", "mcp-gateway-x"} },
		"aud empty array":      func(c map[string]any) { c["aud"] = []any{} },
		"aud case changed":     func(c map[string]any) { c["aud"] = strings.ToUpper(testAudience) },
		"sub empty":            func(c map[string]any) { c["sub"] = "" },
		"sub not a string":     func(c map[string]any) { c["sub"] = 12345 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			v := h.verifier()
			claims := h.claims()
			if mutate == nil {
				claims["iss"] = h.issuer + "/"
			} else {
				mutate(claims)
			}
			token := h.mint(claims)
			_, err := v.Verify(context.Background(), token)
			h.assertRejected(err, token)
		})
	}
}

// TestSecVerifyAcceptsAudienceArrayContainingUs documents (not a finding)
// that a multi-audience token naming this gateway is accepted, per RFC
// 7519 4.1.3. The other audiences it names can replay it elsewhere; that
// is the IdP's scoping, not this adapter's.
func TestSecVerifyAcceptsAudienceArrayContainingUs(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()
	claims := h.claims()
	claims["aud"] = []any{"another-service", testAudience}
	if _, err := v.Verify(context.Background(), h.mint(claims)); err != nil {
		t.Fatalf("multi-audience token naming us was rejected: %v", err)
	}
}

// signWithHeaders signs claims with key, adding arbitrary protected headers.
func signWithHeaders(t *testing.T, alg jose.SignatureAlgorithm, key any, headers map[jose.HeaderKey]any, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	for k, v := range headers {
		opts = opts.WithHeader(k, v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSecVerifyIgnoresHeaderBorneKeys(t *testing.T) {
	_, attacker := testKeys(t)
	attackerJWK := jose.JSONWebKey{Key: attacker.Public(), KeyID: attackerKID, Algorithm: string(jose.RS256), Use: "sig"}
	cases := map[string]map[jose.HeaderKey]any{
		"embedded jwk":          {"jwk": attackerJWK, "kid": attackerKID},
		"embedded jwk, idp kid": {"jwk": attackerJWK, "kid": testKeyID},
		"jku to attacker":       {"jku": "https://attacker.invalid/jwks", "kid": attackerKID},
		"x5u to attacker":       {"x5u": "https://attacker.invalid/cert.pem", "kid": testKeyID},
		"idp kid, attacker key": {"kid": testKeyID},
		"no kid, attacker key":  {},
		"kid path traversal":    {"kid": "../../../../dev/null"},
		"kid sql-ish":           {"kid": "x' OR '1'='1"},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			v := h.verifier()
			token := signWithHeaders(t, jose.RS256, attacker, headers, h.claims())
			_, err := v.Verify(context.Background(), token)
			h.assertRejected(err, token)
		})
	}
}

// TestSecVerifyRejectsPayloadSubstitution: take a genuine token, swap in a
// payload granting another subject and the incident-lead group, keep the
// original signature.
func TestSecVerifyRejectsPayloadSubstitution(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()
	genuine := h.mint(h.claims())
	parts := strings.Split(genuine, ".")
	if len(parts) != 3 {
		t.Fatalf("minted token has %d parts", len(parts))
	}
	evil := h.claims()
	evil["sub"] = "someone-else"
	evil["groups"] = []any{"soc-dfir", "admins"}
	payload, _ := json.Marshal(evil)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
	_, err := v.Verify(context.Background(), forged)
	h.assertRejected(err, forged)

	// Signature stripped entirely, and header rewritten to alg none, with
	// the genuine payload.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + testKeyID + `"}`))
	for _, tok := range []string{
		parts[0] + "." + parts[1] + ".",
		parts[0] + "." + parts[1],
		noneHeader + "." + parts[1] + "." + parts[2],
		noneHeader + "." + parts[1] + ".",
		"NONE" + "." + parts[1] + "." + parts[2],
	} {
		_, err := v.Verify(context.Background(), tok)
		h.assertRejected(err, tok)
	}
}

// TestSecVerifyRejectsJSONSerialisedJWS: the Authorization header carries
// one b64token; a JWS in JSON serialisation (which go-jose's generic parser
// understands, and which can carry multiple signatures) must not verify.
func TestSecVerifyRejectsJSONSerialisedJWS(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()
	payload, _ := json.Marshal(h.claims())
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: h.key}, (&jose.SignerOptions{}).WithHeader("kid", testKeyID))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	full := obj.FullSerialize()
	// Fixed 24 set 2026 (oidc.go isCompactJWS); before, this verified.
	_, err = v.Verify(context.Background(), full)
	h.assertRejected(err, full)
}
