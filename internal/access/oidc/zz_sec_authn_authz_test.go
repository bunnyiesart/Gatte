package oidc_test

import (
	"context"
	"testing"
)

// TestSecOIDCWhitespaceSubjectIsRejected: the Verify doc says a token
// without `sub` is rejected because the audit trail has nothing to
// attribute a call to. A sub of only whitespace is, for attribution, no
// sub. httpapi re-checks it, but every other caller of Verify inherited
// the gap. Ported from the internal tree's security pass of 24 Sep 2026.
func TestSecOIDCWhitespaceSubjectIsRejected(t *testing.T) {
	h := newHarness(t)
	v := h.verifier()
	for _, sub := range []string{" ", "\t", "  \n "} {
		c := h.claims()
		c["sub"] = sub
		tok := h.mint(c)
		id, err := v.Verify(context.Background(), tok)
		if err == nil {
			t.Fatalf("oidc.Verify accepted whitespace-only sub (got Subject=%q)", id.Subject)
		}
		h.assertRejected(err, tok)
	}
}
