package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
)

// noBlocks is the blocklist of a gateway where nobody has been blocked.
type noBlocks struct{}

func (noBlocks) Blocked(context.Context, string) (bool, error) { return false, nil }

// brokenBlocks is a blocklist whose table cannot be read.
type brokenBlocks struct{}

func (brokenBlocks) Blocked(context.Context, string) (bool, error) {
	return false, errors.Join(access.ErrBlocklistUnavailable, errors.New("disk I/O error"))
}

var (
	_ access.Blocklist = noBlocks{}
	_ access.Blocklist = brokenBlocks{}
)

func (h *harness) block(subject string) {
	h.t.Helper()
	if _, err := h.blocks.Block(context.Background(), access.Block{Subject: subject, By: "operator1", At: fixedAt}); err != nil {
		h.t.Fatalf("Block(%q): %v", subject, err)
	}
}

func (h *harness) unblock(subject string) {
	h.t.Helper()
	if _, err := h.blocks.Unblock(context.Background(), subject); err != nil {
		h.t.Fatalf("Unblock(%q): %v", subject, err)
	}
}

// TestAdmitCaller_BlockedSubjectIsRefusedAndAudited is ADR-0031's core: a
// block placed through the console's port refuses the subject on the next
// request, with the constant forbidden class, a row in the trail, and no
// restart; lifting it restores them the same way.
func TestAdmitCaller_BlockedSubjectIsRefusedAndAudited(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")

	if _, err := h.gw.AdmitCaller(t.Context(), fromAnalyst); err != nil {
		t.Fatalf("AdmitCaller before any block: %v", err)
	}
	h.block(analyst.Subject)

	_, err := h.gw.AdmitCaller(t.Context(), fromAnalyst)
	if !errors.Is(err, access.ErrSubjectBlocked) || !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("AdmitCaller for a blocked subject = %v, want ErrSubjectBlocked wrapping ErrForbidden", err)
	}
	rows := h.auditRows()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1: the refusal must be on the trail", len(rows))
	}
	got := rows[0]
	if got.AnalystIdentity != analyst.Subject || got.Outcome != audit.OutcomeDenied ||
		got.Reason != reasonSubjectBlocked || got.SourceAddress != analystSource {
		t.Errorf("refusal recorded as %+v, want the subject, denied, %q, and the source", got, reasonSubjectBlocked)
	}

	h.unblock(analyst.Subject)
	if _, err := h.gw.AdmitCaller(t.Context(), fromAnalyst); err != nil {
		t.Fatalf("AdmitCaller after the block was lifted: %v", err)
	}
}

// TestListTools_BlockedSubjectSeesNothing is the second check ADR-0031
// names: building the analyst's tool list refuses a blocked subject too,
// rather than returning the list their role would give them.
func TestListTools_BlockedSubjectSeesNothing(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")

	if names := h.listNames(analyst); len(names) != 1 {
		t.Fatalf("tools before the block = %v, want one", names)
	}
	h.block(analyst.Subject)
	tools, err := h.gw.ListTools(t.Context(), analyst)
	if !errors.Is(err, access.ErrSubjectBlocked) || tools != nil {
		t.Fatalf("ListTools for a blocked subject = %v, %v; want nil, ErrSubjectBlocked", tools, err)
	}
	h.unblock(analyst.Subject)
	if names := h.listNames(analyst); len(names) != 1 {
		t.Fatalf("tools after the block was lifted = %v, want one", names)
	}
}

// TestDispatch_BlockedSubjectIsRefusedBeforeAnyOtherGate: a call from a
// blocked subject never reaches the upstream, and is refused as blocked
// whatever else is true of the tool it named -- a blocked caller learns
// nothing about which tools exist.
func TestDispatch_BlockedSubjectIsRefusedBeforeAnyOtherGate(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.block(analyst.Subject)

	for _, tool := range []string{"casemgmt.list_cases", "casemgmt.no_such_tool"} {
		if _, err := h.gw.Dispatch(t.Context(), fromAnalyst, tool, nil); !errors.Is(err, access.ErrSubjectBlocked) {
			t.Errorf("Dispatch(%q) for a blocked subject = %v, want ErrSubjectBlocked", tool, err)
		}
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
		t.Fatalf("a blocked subject's call reached the upstream: %v", calls)
	}
	for _, r := range h.auditRows() {
		if r.Outcome != audit.OutcomeDenied || r.Reason != reasonSubjectBlocked {
			t.Errorf("row %+v, want denied with %q", r, reasonSubjectBlocked)
		}
	}
}

// TestAdmitCaller_UnreadableBlocklistRefuses is the fail-closed half: a
// blocklist that cannot be read refuses everyone, as an internal error
// rather than a forbidden one, and says so in the trail.
func TestAdmitCaller_UnreadableBlocklistRefuses(t *testing.T) {
	cfg := fullConfig(t)
	cfg.Blocklist = brokenBlocks{}
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	_, err = gw.AdmitCaller(t.Context(), fromAnalyst)
	if !errors.Is(err, access.ErrBlocklistUnavailable) || errors.Is(err, access.ErrForbidden) {
		t.Fatalf("AdmitCaller over an unreadable blocklist = %v, want ErrBlocklistUnavailable and not ErrForbidden", err)
	}
	if _, err := gw.ListTools(t.Context(), analyst); !errors.Is(err, access.ErrBlocklistUnavailable) {
		t.Errorf("ListTools over an unreadable blocklist = %v, want ErrBlocklistUnavailable", err)
	}
	rows, err := cfg.Audit.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 || rows[0].Reason != reasonBlocklistUnavailable {
		t.Fatalf("audit rows = %+v, want one with %q", rows, reasonBlocklistUnavailable)
	}
}

// countingBlocks counts reads and answers from a set it is handed.
type countingBlocks struct {
	mu      sync.Mutex
	reads   int
	blocked map[string]bool
}

func (c *countingBlocks) Blocked(_ context.Context, subject string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	return c.blocked[subject], nil
}

// TestAdmitCaller_AdmissionCoversOnlyThisRequestAndThisSubject: the context
// AdmitCaller returns lets ListTools and Dispatch skip the second and third
// read for the SAME subject in the SAME request (ADR-0031 §2) -- and for
// nothing else: another subject on that context, or the admitted subject on
// a context that never went through AdmitCaller, is read again.
func TestAdmitCaller_AdmissionCoversOnlyThisRequestAndThisSubject(t *testing.T) {
	cfg := fullConfig(t)
	bl := &countingBlocks{blocked: map[string]bool{"sub-other": true}}
	cfg.Blocklist = bl
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	ctx, err := gw.AdmitCaller(t.Context(), fromAnalyst)
	if err != nil {
		t.Fatalf("AdmitCaller: %v", err)
	}
	if _, err := gw.ListTools(ctx, analyst); err != nil {
		t.Fatalf("ListTools on the admitted context: %v", err)
	}
	if bl.reads != 1 {
		t.Fatalf("reads after admission and list = %d, want 1", bl.reads)
	}
	other := access.Identity{Subject: "sub-other", Groups: analyst.Groups}
	if _, err := gw.ListTools(ctx, other); !errors.Is(err, access.ErrSubjectBlocked) {
		t.Fatalf("ListTools for another subject on the admitted context = %v, want ErrSubjectBlocked", err)
	}
	if _, err := gw.Dispatch(ctx, Caller{Identity: other, SourceAddress: analystSource}, "casemgmt.list_cases", nil); !errors.Is(err, access.ErrSubjectBlocked) {
		t.Fatalf("Dispatch for another subject on the admitted context = %v, want ErrSubjectBlocked", err)
	}
	before := bl.reads
	if _, err := gw.ListTools(t.Context(), analyst); err != nil {
		t.Fatalf("ListTools on a fresh context: %v", err)
	}
	if bl.reads != before+1 {
		t.Fatal("a context that never went through AdmitCaller skipped the blocklist")
	}
}

// TestAdmitCaller_CancelledRequestIsNotReportedAsABrokenBlocklist: a client
// that hangs up while its request is being admitted is refused -- nothing
// is served to it -- but it is not recorded as "blocklist unavailable" nor
// logged as an ERROR, which would be a false alarm about the kill switch's
// store that any caller could raise at will.
func TestAdmitCaller_CancelledRequestIsNotReportedAsABrokenBlocklist(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := h.gw.AdmitCaller(ctx, fromAnalyst); err == nil {
		t.Fatal("AdmitCaller on a cancelled request admitted it")
	} else if errors.Is(err, access.ErrBlocklistUnavailable) {
		t.Fatalf("AdmitCaller on a cancelled request = %v, reported as an unavailable blocklist", err)
	}
	for _, r := range h.auditRows() {
		if r.Reason == reasonBlocklistUnavailable {
			t.Fatalf("a cancelled request wrote %+v", r)
		}
	}
	if _, err := h.gw.Dispatch(ctx, fromAnalyst, "casemgmt.list_cases", nil); errors.Is(err, access.ErrBlocklistUnavailable) {
		t.Fatalf("Dispatch on a cancelled request = %v, reported as an unavailable blocklist", err)
	}
	for _, r := range h.auditRows() {
		if r.Reason == reasonBlocklistUnavailable {
			t.Fatalf("a cancelled dispatch wrote %+v", r)
		}
	}
}
