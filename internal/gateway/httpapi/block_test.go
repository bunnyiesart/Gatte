package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
)

// noBlocks is the blocklist of a gateway where nobody has been blocked.
type noBlocks struct{}

func (noBlocks) Blocked(context.Context, string) (bool, error) { return false, nil }

// brokenBlocks is a blocklist whose table cannot be read.
type brokenBlocks struct{}

func (brokenBlocks) Blocked(context.Context, string) (bool, error) {
	return false, errors.New("disk I/O error on blocked_subjects")
}

const toolsCallBody = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"casemgmt.list_cases","arguments":{}}}`

// TestBlockedSubjectIsRefusedOnTheNextRequest is ADR-0031 at the boundary:
// a token that verified a moment ago is refused on the very next request
// once the operator blocks its subject -- no restart, no session to expire
// -- with the constant 403 every forbidden answer carries and nothing that
// says why. Lifting the block restores the same token the same way.
func TestBlockedSubjectIsRefusedOnTheNextRequest(t *testing.T) {
	h := newHarness(t)
	bearer := "Bearer " + tokenAnalyst

	if res := h.post("/mcp", bearer, initializeBody); res.StatusCode != http.StatusOK {
		t.Fatalf("before the block: status %d, want 200", res.StatusCode)
	}

	if _, err := h.blocks.Block(context.Background(), access.Block{
		Subject: analyst.Subject, Reason: "laptop reported stolen", By: "operator1", At: time.Now(),
	}); err != nil {
		t.Fatalf("Block: %v", err)
	}

	for _, reqBody := range []string{initializeBody, toolsCallBody} {
		res := h.post("/mcp", bearer, reqBody)
		got := body(t, res)
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("blocked subject: status %d, want 403 (body %q)", res.StatusCode, got)
		}
		if got != msgForbidden+"\n" {
			t.Errorf("blocked subject: body %q, want exactly the constant %q", got, msgForbidden+"\n")
		}
		for _, leak := range []string{analyst.Subject, "block", "stolen", "operator1"} {
			if strings.Contains(strings.ToLower(got), strings.ToLower(leak)) {
				t.Errorf("the 403 body carries %q -- the caller learns why", leak)
			}
		}
		if res.Header.Get("WWW-Authenticate") != "" {
			t.Error("the 403 carries a WWW-Authenticate challenge, inviting the client to fetch a new token for a subject that is blocked whatever the token")
		}
	}
	if calls := h.dialer.upstream("casemgmt").calls; len(calls) != 0 {
		t.Fatalf("a blocked subject's tools/call reached the upstream: %v", calls)
	}

	var blockedRows []audit.Record
	for _, r := range h.auditRows() {
		if r.Reason == "subject blocked" {
			blockedRows = append(blockedRows, r)
		}
	}
	if len(blockedRows) != 2 {
		t.Fatalf("rows with reason %q = %d, want one per refused request: %+v", "subject blocked", len(blockedRows), h.auditRows())
	}
	for _, r := range blockedRows {
		if r.AnalystIdentity != analyst.Subject || r.Outcome != audit.OutcomeDenied {
			t.Errorf("refusal row %+v, want the verified subject and denied", r)
		}
	}

	if _, err := h.blocks.Unblock(context.Background(), analyst.Subject); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if res := h.post("/mcp", bearer, initializeBody); res.StatusCode != http.StatusOK {
		t.Fatalf("after the block was lifted: status %d, want 200", res.StatusCode)
	}
	// Somebody else was never affected.
	if names := h.toolNames(h.session(tokenResponder)); len(names) == 0 {
		t.Error("an unblocked colleague lost their tools")
	}
}

// TestUnreadableBlocklistIsAnInternalErrorNotAForbidden: the kill switch
// fails closed, and says so as the generic internal error -- a caller is
// not told which of the gateway's stores is unwell.
func TestUnreadableBlocklistIsAnInternalErrorNotAForbidden(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{blocklist: brokenBlocks{}})

	res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody)
	got := body(t, res)
	if res.StatusCode != http.StatusInternalServerError || got != msgInternal+"\n" {
		t.Fatalf("unreadable blocklist: %d %q, want 500 %q", res.StatusCode, got, msgInternal+"\n")
	}
}
