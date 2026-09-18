package httpapi

// The ADR-0014 result ceiling, seen from the only place that answers the
// question an operator actually asks about it: what does the CLIENT get?
//
// internal/gateway already proves the ceiling refuses rather than
// truncates (TestDispatch_OversizedResultIsRefusedNotTruncated and
// friends). Every one of those assertions stops at gateway.Dispatch's
// return value. Nothing carried the refusal across the HTTP boundary,
// which is where the two properties that matter to a caller live:
//
//  1. no byte of the oversized payload reaches them -- the ADR forbids
//     truncation precisely so a model is never handed a document cut off
//     mid-sentence with nothing saying so, and a refusal that leaked the
//     first megabyte in an error string would break that while passing
//     every test in the gateway package; and
//
//  2. the refusal is not an oracle. A result refused for size and a
//     backend that simply broke must be the same event from outside,
//     for the reason errors.go states: the class is what a client is
//     told, never the cause.
//
// The ceiling under test is the DEFAULT one. The harness builds its
// Gateway without MaxResultBytes, exactly as a configuration file that
// never mentions response.max_bytes does, so what this exercises is the
// number a deployment gets for free.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// errUpstreamBroke is the "something else went wrong entirely" control: a
// failure of a completely different class, whose client-facing answer must
// be byte-identical to the size refusal's.
var errUpstreamBroke = errors.New("backend closed the pipe mid-answer")

// oversizedContent builds a well-formed content-block array comfortably
// over gateway.DefaultMaxResultBytes, with a canary inside it.
//
// Well-formed on purpose: a payload that was merely invalid JSON could be
// refused for the wrong reason and this test would still pass. The only
// thing wrong with this result is its size.
func oversizedContent(canary string) json.RawMessage {
	filler := strings.Repeat("A", int(gateway.DefaultMaxResultBytes))
	block, err := json.Marshal([]map[string]string{{
		"type": "text",
		"text": canary + filler + canary,
	}})
	if err != nil {
		panic(err)
	}
	return block
}

func TestOversizedResultIsRefusedAndTheCallerIsToldNothingAboutIt(t *testing.T) {
	const canary = "OVERSIZE-CANARY-4b71"

	h := newHarness(t)
	payload := oversizedContent(canary)
	if int64(len(payload)) <= gateway.DefaultMaxResultBytes {
		t.Fatalf("precondition: the fixture is %d bytes, which is not over the %d-byte default ceiling",
			len(payload), gateway.DefaultMaxResultBytes)
	}

	// The positive control. Without it a green run could mean the ceiling
	// works OR that this tool never dispatched at all.
	if status, body := h.rawCall(toolListCases); status != http.StatusOK || !strings.Contains(body, "case 42") {
		t.Fatalf("control: an ordinary call did not succeed (status %d): %s", status, body)
	}

	h.dialer.upstream("casemgmt").result = gateway.Result{Content: payload}

	status, refused := h.rawCall(toolListCases)
	// Printed under -v: "what does the client see" is the question this
	// test exists to answer, and the answer is short enough to read.
	t.Logf("what the client sees for a %d-byte result against a %d-byte ceiling: %s",
		len(payload), gateway.DefaultMaxResultBytes, refused)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200: a tool-call failure travels as a JSON-RPC error, not an HTTP status", status)
	}

	// 1. Nothing of the payload came back. Not the canary, and not a
	//    truncated run of it either -- a thousand A's would mean something
	//    somewhere decided a partial answer was better than none.
	if strings.Contains(refused, canary) {
		t.Error("the refused payload's canary reached the client")
	}
	if strings.Contains(refused, strings.Repeat("A", 1024)) {
		t.Error("the client received a prefix of the oversized payload; ADR-0014 refuses, it does not truncate")
	}
	if len(refused) > 4096 {
		t.Errorf("the refusal body is %d bytes; a constant-message refusal cannot be that large:\n%.512s", len(refused), refused)
	}
	assertNoLeak(t, refused)

	// 2. Nor is the client told the ceiling exists. A caller who could
	//    tell "too large" from "the backend broke" could binary-search the
	//    limit, and more usefully could tell which queries return a lot --
	//    which is a fact about the SOC's data, obtained without ever
	//    receiving any of it.
	for _, telltale := range []string{"too large", "limit", "bytes", "max_bytes", "1048576"} {
		if strings.Contains(strings.ToLower(refused), telltale) {
			t.Errorf("the refusal names %q, so the caller can tell a size refusal from any other failure:\n%s", telltale, refused)
		}
	}

	// The same call, failing for a completely different internal reason,
	// must produce the same bytes. The tool name is the only caller-varying
	// value errors.go permits, and it is identical here anyway.
	h.dialer.upstream("casemgmt").result = gateway.Result{}
	h.dialer.upstream("casemgmt").callErr = errUpstreamBroke
	_, broke := h.rawCall(toolListCases)
	if refused != broke {
		t.Errorf("a result refused for size is distinguishable from a broken backend:\n  size:   %q\n  broken: %q", refused, broke)
	}
}

// TestOversizedResultIsOnTheTrailWithItsRealReason is the other half: the
// caller learns nothing, and the operator learns everything.
//
// ADR-0012's pair shape applies -- the call was allowed and forwarded, so
// there is an "allowed" row, and then it failed after the fact, so there
// is a second row carrying the reason. Both have to be there: an
// operator paged because an analyst says "the tool is broken" needs to
// find the size ceiling in the trail, because it is the one failure mode
// whose cause is a number in a config file rather than anything about the
// backend.
func TestOversizedResultIsOnTheTrailWithItsRealReason(t *testing.T) {
	h := newHarness(t)
	h.dialer.upstream("casemgmt").result = gateway.Result{Content: oversizedContent("OVERSIZE-CANARY-9c02")}

	if status, _ := h.rawCall(toolListCases); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	var allowed, failed []audit.Record
	for _, r := range h.auditRows() {
		if r.Tool != toolListCases {
			continue
		}
		switch r.Outcome {
		case audit.OutcomeAllowed:
			allowed = append(allowed, r)
		case audit.OutcomeFailed:
			failed = append(failed, r)
		}
	}

	if len(allowed) != 1 {
		t.Errorf("allowed rows = %d, want 1: the call did pass every gate and was forwarded", len(allowed))
	}
	if len(failed) != 1 {
		t.Fatalf("failed rows = %d, want 1 (ADR-0012's second row): %+v", len(failed), h.auditRows())
	}
	if failed[0].AnalystIdentity != analyst.Subject {
		t.Errorf("the failure is attributed to %q, want %q", failed[0].AnalystIdentity, analyst.Subject)
	}
	// The Reason is the whole point of the row. It must say size, and it
	// must be one of the closed set of operator-facing constants rather
	// than anything the upstream authored.
	if !strings.Contains(failed[0].Reason, "too large") {
		t.Errorf("Reason = %q, want it to name the size ceiling; without that the operator cannot tell this from a backend fault", failed[0].Reason)
	}
	if strings.Contains(failed[0].Reason, "CANARY") {
		t.Errorf("Reason = %q carries upstream-authored bytes", failed[0].Reason)
	}
}
