package sopsage_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
)

// TestSecProviderFormattingDoesNotRevealTheStore: Provider keeps every
// decrypted value in an unexported map and had no String/GoString method,
// so %v/%+v/%#v of a *Provider (a config struct logged in a debug dump,
// say) printed the whole vault in clear. Ported from the internal tree's
// security pass of 24 Sep 2026.
func TestSecProviderFormattingDoesNotRevealTheStore(t *testing.T) {
	const marker = "sec-prov-fmt-2e2e"
	secretsFile, keyFile := newFixture(t, map[string]string{"TOKEN": marker})
	p, err := sopsage.New(context.Background(), secretsFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var leaks []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, p); strings.Contains(out, marker) {
			leaks = append(leaks, verb+" -> "+out)
		}
	}
	// Nested inside something a caller might dump.
	holder := struct{ Vault *sopsage.Provider }{p}
	if out := fmt.Sprintf("%+v %#v", holder, holder); strings.Contains(out, marker) {
		leaks = append(leaks, "holder -> "+out)
	}
	if len(leaks) > 0 {
		t.Fatalf("LEAK: formatting the Provider reveals the store:\n%s", strings.Join(leaks, "\n"))
	}
	var nilP *sopsage.Provider
	_ = fmt.Sprintf("%v %#v", nilP, nilP) // must not panic
}
