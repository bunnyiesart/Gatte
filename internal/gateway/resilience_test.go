package gateway

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quota"
)

// Call-path resilience (design/adr/0035-resiliencia-do-caminho-de-chamada.md).

// TestDispatch_APanickingUpstreamIsAnAuditedFailure: a panic below
// Dispatch is one failed call, not a dead process. The SDK runs each tool
// handler in its own goroutine without a recover, so before ADR-0035 this
// panic took the gateway down for every analyst.
func TestDispatch_APanickingUpstreamIsAnAuditedFailure(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.serve("logsearch", def("search", "search"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("logsearch", "search")

	var logged lockedLog
	h.gw.log = slog.New(slog.NewTextHandler(&logged, nil))

	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.panicWith = "adapter bug: token=hunter2"
	up.mu.Unlock()

	// More panicking calls than there are concurrency slots: a slot that a
	// panic failed to release would turn the fifth into "concurrency
	// limited" and prove the leak.
	for i := range DefaultMaxConcurrentCallsPerAnalyst + 1 {
		_, err := h.gw.Dispatch(t.Context(), fromAnalyst, "casemgmt.list_cases", nil)
		if !errors.Is(err, ErrInternal) {
			t.Fatalf("panicking call %d = %v, want one wrapping ErrInternal", i+1, err)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("the panic value reached the caller: %v", err)
		}
	}

	rows := rowsFor(h.auditRows(), "casemgmt.list_cases")
	if len(rows) != 2*(DefaultMaxConcurrentCallsPerAnalyst+1) {
		t.Fatalf("audit rows = %d, want an allowed and a failed row per call: %+v", len(rows), rows)
	}
	for i := 0; i < len(rows); i += 2 {
		if rows[i].Outcome != audit.OutcomeAllowed {
			t.Errorf("row %d outcome = %q, want %q", i, rows[i].Outcome, audit.OutcomeAllowed)
		}
		failed := rows[i+1]
		if failed.Outcome != audit.OutcomeFailed || failed.Reason != reasonInternalError {
			t.Errorf("row %d = %q/%q, want %q/%q", i+1, failed.Outcome, failed.Reason, audit.OutcomeFailed, reasonInternalError)
		}
		if failed.TargetUpstream != "casemgmt" || failed.AnalystIdentity != analyst.Subject {
			t.Errorf("failed row %+v is not attributed to the call that panicked", failed)
		}
	}

	// The panic value is whatever the panicking code had in hand; it
	// reaches neither the caller nor the log.
	if strings.Contains(logged.String(), "hunter2") {
		t.Errorf("the panic value reached the log:\n%s", logged.String())
	}

	// The process kept serving.
	if _, err := h.gw.Dispatch(t.Context(), fromAnalyst, "logsearch.search", nil); err != nil {
		t.Fatalf("a call to a healthy upstream after the panic = %v, want nil", err)
	}
}

// TestDispatch_ConcurrencyCapRefusesFastWithoutSpendingQuota pins where the
// per-analyst cap sits: after admit, before the quota debit and before the
// allowed row. A call refused for concurrency must not spend quota (the
// debit is never reversed), must not claim it was dispatched, and must not
// wait in a queue.
func TestDispatch_ConcurrencyCapRefusesFastWithoutSpendingQuota(t *testing.T) {
	const tool = "casemgmt.list_cases"
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{virustotalOn("casemgmt", tool, 100)},
	}, tool)
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.waitForCtx = true
	up.mu.Unlock()

	n := DefaultMaxConcurrentCallsPerAnalyst
	holdCtx, release := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { _, _ = h.gw.Dispatch(holdCtx, fromAnalyst, tool, nil) })
	}
	t.Cleanup(func() { release(); wg.Wait() })
	waitUntil(t, func() bool { return len(up.callLog()) == n })

	// Bounded, so that a gateway with no cap -- where this call is admitted
	// and blocks like the others -- fails the assertion below instead of
	// hanging the test.
	overCtx, cancelOver := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancelOver()
	started := time.Now()
	_, err := h.gw.Dispatch(overCtx, fromAnalyst, tool, nil)
	if !errors.Is(err, ErrConcurrencyLimited) {
		t.Fatalf("call %d while %d are in flight = %v, want one wrapping ErrConcurrencyLimited", n+1, n, err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("the refusal took %s; the cap is fail-fast, with no queue", waited)
	}
	if got := len(up.callLog()); got != n {
		t.Errorf("the backend saw %d calls, want %d: the refused call must not leave the process", got, n)
	}
	if got := h.used("virustotal"); got != n {
		t.Errorf("quota spent = %d, want %d: a call refused for concurrency must not debit", got, n)
	}
	rows := rowsFor(h.auditRows(), tool)
	last := rows[len(rows)-1]
	if last.Outcome != audit.OutcomeDenied || last.Reason != reasonConcurrencyLimited {
		t.Errorf("the refused call recorded %q/%q, want %q/%q", last.Outcome, last.Reason, audit.OutcomeDenied, reasonConcurrencyLimited)
	}
	allowed := 0
	for _, r := range rows {
		if r.Outcome == audit.OutcomeAllowed {
			allowed++
		}
	}
	if allowed != n {
		t.Errorf("allowed rows = %d, want %d: the refused call must not claim it was dispatched", allowed, n)
	}

	// The cap is per subject: another analyst is not refused.
	other := Caller{
		Identity:      access.Identity{Subject: "sub-analyst-2", Name: "Outra", Groups: []string{"soc-n1"}},
		SourceAddress: analystSource,
	}
	otherCtx, cancelOther := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancelOther()
	if _, err := h.gw.Dispatch(otherCtx, other, tool, nil); errors.Is(err, ErrConcurrencyLimited) {
		t.Errorf("a second analyst was refused by the first one's slots: %v", err)
	}

	// Slots come back when the calls end.
	release()
	wg.Wait()
	up.mu.Lock()
	up.waitForCtx = false
	up.mu.Unlock()
	if _, err := h.gw.Dispatch(t.Context(), fromAnalyst, tool, nil); err != nil {
		t.Errorf("a call after the in-flight ones ended = %v, want nil", err)
	}
}

func TestNew_ConcurrencyCapDefaultsWhenUnset(t *testing.T) {
	cfg := fullConfig(t)
	cfg.MaxConcurrentCallsPerAnalyst = 0
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if gw.slots.max != DefaultMaxConcurrentCallsPerAnalyst {
		t.Errorf("cap = %d, want the default %d: an unset value must not mean unlimited", gw.slots.max, DefaultMaxConcurrentCallsPerAnalyst)
	}
}

// waitUntil polls cond for up to five seconds.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// lockedLog is a log sink safe to read while handler goroutines write.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// panickingRecorder panics on Record: an audit store with a bug.
type panickingRecorder struct{ audit.Recorder }

func (panickingRecorder) Record(context.Context, audit.Record) error {
	panic("store bug: dsn=hunter2")
}

// TestDispatch_APanickingAuditStoreIsContained: when the store is what
// panicked, recording that panic panics again. The second one must not
// escape either: the call is refused with ErrInternal, nothing is written,
// the log says why, and the process keeps serving.
func TestDispatch_APanickingAuditStoreIsContained(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	var logged lockedLog
	h.gw.log = slog.New(slog.NewTextHandler(&logged, nil))
	healthy := h.gw.audit
	h.gw.audit = panickingRecorder{healthy}

	for i := range DefaultMaxConcurrentCallsPerAnalyst + 1 {
		_, err := h.gw.Dispatch(t.Context(), fromAnalyst, "casemgmt.list_cases", nil)
		if !errors.Is(err, ErrInternal) {
			t.Fatalf("call %d with a panicking store = %v, want ErrInternal", i+1, err)
		}
	}
	if strings.Contains(logged.String(), "hunter2") {
		t.Errorf("the panic value reached the log:\n%s", logged.String())
	}
	if !strings.Contains(logged.String(), "could not be audited") {
		t.Errorf("the unrecorded panic left no log line:\n%s", logged.String())
	}

	h.gw.audit = healthy
	if _, err := h.gw.Dispatch(t.Context(), fromAnalyst, "casemgmt.list_cases", nil); err != nil {
		t.Fatalf("a call after the store recovered = %v, want nil", err)
	}
}
