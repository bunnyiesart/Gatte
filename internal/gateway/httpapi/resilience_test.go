package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// Call-path resilience at the HTTP boundary
// (design/adr/0035-resiliencia-do-caminho-de-chamada.md).

// tokenThatPanics makes fakeVerifier panic: a verifier with a bug.
const tokenThatPanics = "token-that-panics-CANARY-3"

// panicCanary is the value every panic here carries, so a test can prove
// it reached neither the client nor the log.
const panicCanary = "panic-value-CANARY-5"

// TestAPanickingUpstreamIsOneFailedCallNotADeadProcess drives the panic
// through the SDK's own handler goroutine, which has no recover: before
// ADR-0035 this test binary died here.
func TestAPanickingUpstreamIsOneFailedCallNotADeadProcess(t *testing.T) {
	h := newHarness(t)
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.panicWith = panicCanary
	up.mu.Unlock()

	status, got := h.rawCall(toolListCases)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 carrying a JSON-RPC error", status)
	}
	if !strings.Contains(got, `"error"`) || !strings.Contains(got, msgInternal) {
		t.Errorf("body = %q, want a JSON-RPC error with the constant %q", got, msgInternal)
	}
	if strings.Contains(got, panicCanary) || strings.Contains(h.logs.String(), panicCanary) {
		t.Errorf("the panic value escaped:\nbody: %s\nlog: %s", got, h.logs.String())
	}

	var outcomes []string
	for _, r := range h.auditRows() {
		if r.Tool == toolListCases {
			outcomes = append(outcomes, string(r.Outcome)+"/"+r.Reason)
		}
	}
	want := []string{string(audit.OutcomeAllowed) + "/", string(audit.OutcomeFailed) + "/internal error"}
	if fmt.Sprint(outcomes) != fmt.Sprint(want) {
		t.Errorf("trail for the call = %v, want %v", outcomes, want)
	}

	// The process kept serving, the same analyst included.
	if status, got := h.rawCall(toolSearch); status != http.StatusOK || strings.Contains(got, `"error"`) {
		t.Errorf("a healthy call after the panic = %d %q, want a result", status, got)
	}
}

// TestAPanicBeforeAuthenticationIsTheGeneric500: nothing is attributed
// (there is no subject), the caller gets the constant 500 rather than a
// dropped connection, and the value is nowhere.
func TestAPanicBeforeAuthenticationIsTheGeneric500(t *testing.T) {
	h := newHarness(t)
	before := len(h.auditRows())

	res := h.post("/mcp", "Bearer "+tokenThatPanics, initializeBody)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if got := body(t, res); got != msgInternal+"\n" {
		t.Errorf("body = %q, want the constant %q", got, msgInternal+"\n")
	}
	if strings.Contains(h.logs.String(), tokenThatPanics) {
		t.Error("the presented token reached the log")
	}
	if got := len(h.auditRows()); got != before {
		t.Errorf("trail grew by %d rows for an unauthenticated panic, want 0", got-before)
	}
	if res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody); res.StatusCode != http.StatusOK {
		t.Errorf("a normal request after the panic = %d, want 200", res.StatusCode)
	}
}

// panickingQuarantine panics on Get once armed: a store with a bug, met
// while ServeHTTP builds the caller's tool list.
type panickingQuarantine struct {
	quarantine.Store
	armed atomic.Bool
}

func (q *panickingQuarantine) Get(ctx context.Context, server, tool string) (quarantine.Tool, error) {
	if q.armed.Load() {
		panic(panicCanary)
	}
	return q.Store.Get(ctx, server, tool)
}

// TestAPanicAfterAuthenticationIsAuditedToTheCaller: once there is a
// subject, the panic is a denial on the trail, attributed to them.
func TestAPanicAfterAuthenticationIsAuditedToTheCaller(t *testing.T) {
	var pq *panickingQuarantine
	h := newHarnessWith(t, harnessOptions{wrapQuarantine: func(s quarantine.Store) quarantine.Store {
		pq = &panickingQuarantine{Store: s}
		return pq
	}})
	pq.armed.Store(true)

	res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	if got := body(t, res); got != msgInternal+"\n" {
		t.Errorf("body = %q, want the constant %q", got, msgInternal+"\n")
	}
	if strings.Contains(h.logs.String(), panicCanary) {
		t.Error("the panic value reached the log")
	}
	rows := h.auditRows()
	if len(rows) == 0 {
		t.Fatal("no trail row for a panic in an authenticated request")
	}
	last := rows[len(rows)-1]
	if last.AnalystIdentity != analyst.Subject || last.Outcome != audit.OutcomeDenied || last.Reason != "internal error" {
		t.Errorf("row = %s/%s/%q, want %s/%s/%q", last.AnalystIdentity, last.Outcome, last.Reason,
			analyst.Subject, audit.OutcomeDenied, "internal error")
	}

	pq.armed.Store(false)
	if res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody); res.StatusCode != http.StatusOK {
		t.Errorf("a normal request after the panic = %d, want 200", res.StatusCode)
	}
}

// TestARequestBodyOverTheCapIsRefusedUnread pins the explicit body limit:
// 413, and the call never reaches the gateway.
func TestARequestBodyOverTheCapIsRefusedUnread(t *testing.T) {
	h := newHarness(t)
	pad := strings.Repeat("a", int(MaxRequestBodyBytes))
	req := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + toolListCases + `","arguments":{"q":"` + pad + `"}}}`

	res := h.post("/mcp", "Bearer "+tokenAnalyst, req)
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a body over %d bytes", res.StatusCode, MaxRequestBodyBytes)
	}
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.calls) != 0 {
		t.Errorf("the backend saw %v; an oversized body must not be dispatched", up.calls)
	}
}

// TestConcurrencyLimitedIsItsOwnClass mirrors TestQuotaExhaustedIsItsOwnClass:
// the caller's own cap, a constant message equal to the trail's reason.
func TestConcurrencyLimitedIsItsOwnClass(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", gateway.ErrConcurrencyLimited)
	class := classify(err)
	if class != classConcurrencyLimited {
		t.Fatalf("classify = %v, want classConcurrencyLimited", class)
	}
	if got := class.message(); got != "concurrency limited" {
		t.Errorf("message = %q, want %q", got, "concurrency limited")
	}
	var rpc interface{ Error() string }
	if rpc = jsonRPCError(class, toolListCases); !strings.Contains(rpc.Error(), "concurrency limited") {
		t.Errorf("client error = %q, want the constant message", rpc.Error())
	}
	if errors.Is(gateway.ErrInternal, gateway.ErrConcurrencyLimited) || classify(gateway.ErrInternal) != classInternal {
		t.Error("an internal error must stay the generic internal class")
	}
}
