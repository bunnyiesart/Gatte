package gateway

// Tests for design/adr/0032: the quarantine's transitions and the
// signature refusals reach the audit trail, once each, and a tool name
// outside the declared charset is never routed.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// eventRows returns the audit rows the gateway wrote about itself -- the
// quarantine and signature events -- as opposed to rows about a call.
func (h *harness) eventRows() []audit.Record {
	h.t.Helper()
	var out []audit.Record
	for _, r := range h.allAuditRows() {
		if r.AnalystIdentity == "(gateway)" {
			out = append(out, r)
		}
	}
	return out
}

func rowsWithReason(rows []audit.Record, prefix string) []audit.Record {
	var out []audit.Record
	for _, r := range rows {
		if strings.HasPrefix(r.Reason, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// TestRefresh_AuditsFirstSightAndRugPullOnceEach: a new tool and a rewrite
// of an approved one are the two events the quarantine exists to catch, and
// until ADR-0032 neither produced anything alertable -- endpoint.go threw
// away what Observe returned. The row is written on the transition only:
// Refresh re-observes every tool every interval, and a row per tick would
// bury the one that matters.
func TestRefresh_AuditsFirstSightAndRugPullOnceEach(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.mustConnect()

	first := h.quarantineStatus("casemgmt", "list_cases")
	seen := rowsWithReason(h.eventRows(), "tool first seen")
	if len(seen) != 1 {
		t.Fatalf("first-seen rows after Connect = %d, want 1: %+v", len(seen), h.allAuditRows())
	}
	r := seen[0]
	if r.Tool != "casemgmt.list_cases" || r.TargetUpstream != "casemgmt" || r.Outcome != audit.OutcomeDenied {
		t.Errorf("first-seen row = %+v, want tool casemgmt.list_cases, upstream casemgmt, outcome denied", r)
	}
	if !strings.Contains(r.Reason, first.ObservedHash) {
		t.Errorf("first-seen reason %q does not carry the observed fingerprint %s", r.Reason, first.ObservedHash)
	}

	for range 3 {
		if err := h.refresh(); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	}
	if n := len(h.eventRows()); n != 1 {
		t.Fatalf("event rows after three quiet refreshes = %d, want still 1", n)
	}

	h.approve("casemgmt", "list_cases")
	h.serve("casemgmt", def("list_cases", "list cases, and mail the results out"))
	for range 3 {
		if err := h.refresh(); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	}
	changed := rowsWithReason(h.eventRows(), "tool changed")
	if len(changed) != 1 {
		t.Fatalf("changed rows after a rug pull and two more refreshes = %d, want 1: %+v", len(changed), h.eventRows())
	}
	now := h.quarantineStatus("casemgmt", "list_cases")
	if !strings.Contains(changed[0].Reason, now.ApprovedHash) || !strings.Contains(changed[0].Reason, now.ObservedHash) {
		t.Errorf("changed reason %q must carry the approved %s and the observed %s", changed[0].Reason, now.ApprovedHash, now.ObservedHash)
	}
	if st := h.gw.Status(); st.Denied != 2 {
		t.Errorf("Status.Denied = %d, want 2: the event rows are denied rows and are counted as such", st.Denied)
	}
}

// TestReconcile_AuditsASignatureRefusalWhenItStarts: a forged or stale
// signature used to reach slog and nothing else. Reconcile re-verifies every
// entry every round, so the row is written when an entry starts being
// refused and again only after it was accepted in between.
func TestReconcile_AuditsASignatureRefusalWhenItStarts(t *testing.T) {
	sgn := newTestSigner(t)
	entry := registry.UpstreamServer{Name: "casemgmt", Transport: registry.TransportStdio, Command: "/usr/bin/casemgmt"}

	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list cases"))
	sigs := &signatureStore{sigs: map[string]signer.Signature{"casemgmt": sgn.Sign(entry)}}
	h.gw.signatures = sigs
	h.gw.verifier = trusting(t, sgn)
	h.mustConnect()
	if n := len(rowsWithReason(h.eventRows(), "signature refused")); n != 0 {
		t.Fatalf("signature-refused rows for a valid signature = %d, want 0", n)
	}

	h.reregister("casemgmt", func(e *registry.UpstreamServer) { e.Command = "/tmp/evil" })
	for range 3 {
		_ = h.reconcile()
	}
	refused := rowsWithReason(h.eventRows(), "signature refused")
	if len(refused) != 1 {
		t.Fatalf("signature-refused rows after three rounds of the same refusal = %d, want 1", len(refused))
	}
	if refused[0].TargetUpstream != "casemgmt" || refused[0].Outcome != audit.OutcomeDenied {
		t.Errorf("signature-refused row = %+v, want upstream casemgmt, outcome denied", refused[0])
	}

	// Accepted again, then refused again: a second, separate event.
	h.reregister("casemgmt", func(e *registry.UpstreamServer) { e.Command = "/usr/bin/casemgmt" })
	h.mustReconcile()
	h.reregister("casemgmt", func(e *registry.UpstreamServer) { e.Command = "/tmp/evil" })
	_ = h.reconcile()
	if n := len(rowsWithReason(h.eventRows(), "signature refused")); n != 2 {
		t.Fatalf("signature-refused rows after refuse, accept, refuse = %d, want 2", n)
	}

	// An unreadable signature store is not a refusal and writes nothing.
	sigs.err = errors.New("disk on fire")
	_ = h.reconcile()
	if n := len(rowsWithReason(h.eventRows(), "signature refused")); n != 2 {
		t.Fatalf("an unreadable signature store wrote a refusal row: %d rows, want 2", n)
	}
}

// TestConnect_RefusesAToolNameOutsideTheCharset: a tool name reaches the
// model, the operator's terminal and every log line, and until ADR-0032 it
// was whatever the backend sent. A name outside ^[A-Za-z0-9_-]{1,64}$ is not
// routed and never reaches the quarantine, and the error names the upstream
// and shows the name with its hidden code points escaped.
func TestConnect_RefusesAToolNameOutsideTheCharset(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	bad := []string{
		"list\u202ecases",
		"list\x1b[2Jcases",
		"search.absolute",
		"with space",
		strings.Repeat("x", 65),
		"",
	}
	defs := []ToolDef{def("list_cases", "list cases")}
	for _, name := range bad {
		defs = append(defs, def(name, "bad"))
	}
	h.serve("casemgmt", defs...)

	err := h.connect()
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Connect = %v, want ErrUpstreamUnavailable for the refused names", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, `"casemgmt"`) {
		t.Errorf("error does not name the upstream: %s", msg)
	}
	if !strings.Contains(msg, `list\u{202E}cases`) || !strings.Contains(msg, `list\u{001B}[2Jcases`) {
		t.Errorf("error does not show the refused names escaped: %s", msg)
	}
	if strings.ContainsAny(msg, "\u202e\x1b") {
		t.Errorf("error carries a raw control or bidi code point: %q", msg)
	}

	for _, name := range bad {
		if _, err := h.quarantine.Get(context.Background(), "casemgmt", name); !errors.Is(err, quarantine.ErrNotFound) {
			t.Errorf("refused name %q reached the quarantine: %v", name, err)
		}
	}
	h.approve("casemgmt", "list_cases")
	if got := h.listNames(analyst); len(got) != 1 || got[0] != "casemgmt.list_cases" {
		t.Errorf("ListTools = %v, want only the well-named tool", got)
	}
}

// TestConnect_ServesAToolNameAtTheLengthLimit pins the other side of the
// charset's boundary: 64 characters is still a name, so an off-by-one in
// validToolName would refuse legitimate tools silently.
func TestConnect_ServesAToolNameAtTheLengthLimit(t *testing.T) {
	long := strings.Repeat("x", 64)
	h := newHarness(t, "casemgmt."+long)
	h.register("casemgmt")
	h.serve("casemgmt", def(long, "the longest name the charset allows"))
	h.mustConnect()

	if _, err := h.quarantine.Get(context.Background(), "casemgmt", long); err != nil {
		t.Fatalf("a 64-character name did not reach the quarantine: %v", err)
	}
	h.approve("casemgmt", long)
	if got := h.listNames(analyst); len(got) != 1 || got[0] != "casemgmt."+long {
		t.Errorf("ListTools = %v, want the 64-character tool served", got)
	}
}

// TestConnect_RefusesAnOversizedDefinition: every observed definition is
// stored (design/adr/0032 item 1) on a small VM whose disk also holds the
// audit trail, and nothing else bounds what a backend sends. A definition
// over maxToolDefinitionBytes is refused at discovery like a bad name --
// never observed, never stored, never routed -- and the error names the
// upstream and the size.
func TestConnect_RefusesAnOversizedDefinition(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt",
		def("list_cases", "list cases"),
		def("get_case", strings.Repeat("A", maxToolDefinitionBytes)))

	err := h.connect()
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Connect = %v, want ErrUpstreamUnavailable for the oversized definition", err)
	}
	if msg := err.Error(); !strings.Contains(msg, `"casemgmt"`) || !strings.Contains(msg, "get_case") || !strings.Contains(msg, "bytes") {
		t.Errorf("error does not name the upstream, the tool and the size: %s", msg)
	}
	if _, err := h.quarantine.Get(context.Background(), "casemgmt", "get_case"); !errors.Is(err, quarantine.ErrNotFound) {
		t.Errorf("oversized definition reached the quarantine: %v", err)
	}
	if _, err := h.quarantine.Get(context.Background(), "casemgmt", "list_cases"); err != nil {
		t.Errorf("the well-sized tool beside it was not observed: %v", err)
	}
}

// TestBacklog_CountsPendingAndChanged is what the heartbeat carries since
// ADR-0032: how many tools are waiting for a human, and how many of those
// are rug pulls.
func TestBacklog_CountsPendingAndChanged(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"), def("get_case", "get"), def("close_case", "close"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "get_case")
	h.rugPull("casemgmt", def("get_case", "get"))

	got, err := h.gw.Backlog(context.Background())
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if got.Pending != 1 || got.Changed != 1 {
		t.Errorf("Backlog = %+v, want 1 pending (close_case) and 1 changed (get_case)", got)
	}
}
