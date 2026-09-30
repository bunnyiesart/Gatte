package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
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
// -- with a constant 403 that says signing in again will not help
// (design/adr/0042 item 2) and nothing that says why. Lifting the block
// restores the same token the same way.
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
		if got != msgAccountRefused+"\n" {
			t.Errorf("blocked subject: body %q, want exactly the constant %q", got, msgAccountRefused+"\n")
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

// flippingBlocks counts reads and reports the subject blocked from read
// number `after` on -- a block the operator commits in the middle of a
// request, at exactly the point a test needs it.
type flippingBlocks struct {
	mu    sync.Mutex
	reads int
	after int // 0: never blocked
}

func (f *flippingBlocks) Blocked(context.Context, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.after > 0 && f.reads >= f.after, nil
}

func (f *flippingBlocks) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// TestOneBlocklistReadPerRequest: the blocklist is read once per HTTP
// request, at admission, and the tool list and the dispatch of that same
// request reuse the answer (design/adr/0031 §2). A tools/call used to read
// it three times.
func TestOneBlocklistReadPerRequest(t *testing.T) {
	bl := &flippingBlocks{}
	h := newHarnessWith(t, harnessOptions{blocklist: bl})
	res := h.post("/mcp", "Bearer "+tokenAnalyst, toolsCallBody)
	if got := body(t, res); res.StatusCode != http.StatusOK {
		t.Fatalf("tools/call: %d %q", res.StatusCode, got)
	}
	if n := bl.count(); n != 1 {
		t.Fatalf("blocklist reads for one tools/call = %d, want 1", n)
	}
}

// TestABlockLandingMidRequestNeverRefusesUnaudited: a block committed after
// this request was admitted takes effect on the NEXT request. The request
// already admitted is finished, not refused half-way -- a refusal there
// would be a 403 with no row on the trail, breaking "every refusal is
// audited exactly once".
func TestABlockLandingMidRequestNeverRefusesUnaudited(t *testing.T) {
	bl := &flippingBlocks{after: 2}
	h := newHarnessWith(t, harnessOptions{blocklist: bl})
	bearer := "Bearer " + tokenAnalyst

	res := h.post("/mcp", bearer, toolsCallBody)
	if got := body(t, res); res.StatusCode != http.StatusOK {
		t.Fatalf("request admitted before the block: %d %q, want 200 (the block applies from the next one)", res.StatusCode, got)
	}
	res = h.post("/mcp", bearer, toolsCallBody)
	if got := body(t, res); res.StatusCode != http.StatusForbidden {
		t.Fatalf("next request: %d %q, want 403", res.StatusCode, got)
	}
	refusals := 0
	for _, r := range h.auditRows() {
		if r.Outcome == audit.OutcomeDenied {
			refusals++
			if r.Reason != "subject blocked" {
				t.Errorf("unexpected refusal row %+v", r)
			}
		}
	}
	if refusals != 1 {
		t.Fatalf("denied rows = %d, want exactly 1 (one refused request): %+v", refusals, h.auditRows())
	}
}
