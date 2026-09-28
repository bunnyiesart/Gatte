package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	oidcadapter "github.com/bunnyiesart/Gatte/internal/access/oidc"
)

// TestForgedTokensDoNotTurnIntoJWKSFetches pins design/adr/0035's JWKS
// refetch limiter with a counting fake IdP. Before it, go-oidc refetched
// the key set on every unknown kid and every bad signature, so each forged
// token an anonymous caller sent became one request to the IdP.
func TestForgedTokensDoNotTurnIntoJWKSFetches(t *testing.T) {
	idp, attacker := testKeys(t)
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var fetches atomic.Int32
	var mu sync.Mutex
	published := []jose.JSONWebKey{{Key: idp.Public(), KeyID: testKeyID, Algorithm: string(jose.RS256), Use: "sig"}}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: published})
	})

	var clockMu sync.Mutex
	clock := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	advance := func(d time.Duration) { clockMu.Lock(); clock = clock.Add(d); clockMu.Unlock() }

	h := &harness{t: t, server: server, issuer: server.URL, key: idp, logs: nil}
	cfg := oidcadapter.Config{Issuer: server.URL, Audience: testAudience, HTTPClient: server.Client()}
	oidcadapter.SetClock(&cfg, now)
	v, err := oidcadapter.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	// The first genuine token fills the cache: one fetch.
	if _, err := v.Verify(ctx, h.mint(h.claims())); err != nil {
		t.Fatalf("genuine token: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches after the first token = %d, want 1", got)
	}

	// Forged tokens -- unknown kid, and a bad signature under the known
	// kid -- are refused without reaching the IdP.
	for range 20 {
		if _, err := v.Verify(ctx, sign(t, jose.RS256, attacker, attackerKID, h.claims())); err == nil {
			t.Fatal("a token with an unknown kid was accepted")
		}
		if _, err := v.Verify(ctx, sign(t, jose.RS256, attacker, testKeyID, h.claims())); err == nil {
			t.Fatal("a token with a bad signature was accepted")
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches after 40 forged tokens = %d, want still 1: each forged token became a request to the IdP", got)
	}

	// A genuine rotation is picked up once the window has passed.
	mu.Lock()
	published = append(published, jose.JSONWebKey{Key: rotated.Public(), KeyID: "rotated-key", Algorithm: string(jose.RS256), Use: "sig"})
	mu.Unlock()
	advance(31 * time.Second)
	if _, err := v.Verify(ctx, sign(t, jose.RS256, rotated, "rotated-key", h.claims())); err != nil {
		t.Fatalf("a token under the rotated key, after the window: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Errorf("fetches after the rotation = %d, want 2", got)
	}
	// Cached now: no further fetch.
	if _, err := v.Verify(ctx, sign(t, jose.RS256, rotated, "rotated-key", h.claims())); err != nil {
		t.Fatalf("the rotated key from cache: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Errorf("fetches for a cached key = %d, want 2", got)
	}
}

// TestARedirectingJWKSEndpointStillLoadsKeys: the limiter counts fetches,
// not round trips. http.Client follows a redirect by calling the transport
// again, and a limiter that refused that second hop left the key cache
// empty for good -- every token refused -- for any IdP whose jwks_uri
// answers 3xx (http to https, a trailing slash).
func TestARedirectingJWKSEndpointStillLoadsKeys(t *testing.T) {
	idp, attacker := testKeys(t)

	var fetches atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		http.Redirect(w, r, "/jwks/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/jwks/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: idp.Public(), KeyID: testKeyID, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})

	h := &harness{t: t, server: server, issuer: server.URL, key: idp, logs: nil}
	cfg := oidcadapter.Config{Issuer: server.URL, Audience: testAudience, HTTPClient: server.Client()}
	v, err := oidcadapter.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), h.mint(h.claims())); err != nil {
		t.Fatalf("a genuine token behind a redirecting jwks_uri: %v", err)
	}
	// The redirected fetch is still one fetch for the limiter: a forged
	// token right after it does not reach the IdP.
	if _, err := v.Verify(context.Background(), sign(t, jose.RS256, attacker, attackerKID, h.claims())); err == nil {
		t.Fatal("a token with an unknown kid was accepted")
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}
