package gateway

// Security tests (lens: audit-quota), end to end through Connect and
// Dispatch with the real SQLite audit trail and the real SQLite quota
// counter. Each decision Dispatch can reach must leave an attributed row;
// the quota must hold under concurrency, across the tool names that spend
// one account, and exactly at the window boundary.

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasql "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func secAQCall(h *harness, c Caller, tool string) error {
	_, err := h.gw.Dispatch(context.Background(), c, tool, json.RawMessage(`{}`))
	return err
}

// secAQFileDB opens a real on-disk database (WAL + busy_timeout, the
// production shape) with the audit and quota tables, so concurrency tests
// exercise real writer contention rather than :memory:'s single pinned
// connection.
func secAQFileDB(t *testing.T) (audit.Recorder, *quotasql.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "gw.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := auditsql.Migrate(db); err != nil {
		t.Fatalf("audit migrate: %v", err)
	}
	if err := quotasql.Migrate(db); err != nil {
		t.Fatalf("quota migrate: %v", err)
	}
	return auditsql.New(db), quotasql.New(db)
}

func secAQUsed(t *testing.T, r quota.Reader, subject, account string) int {
	t.Helper()
	rows, err := r.Usage(context.Background())
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	n := 0
	for _, u := range rows {
		if u.Analyst == subject && u.Provider == account {
			n += u.Used
		}
	}
	return n
}

// Every decision Dispatch can reach -- allowed, quota exhausted, forbidden,
// quarantined, unknown, and dispatched-then-failed -- writes a row that
// carries the caller's subject and source, the exact tool asked for, a
// non-empty upstream, the right outcome and (for every non-allowed row) a
// reason. (The internal tree also compared a telemetry sink here; in this
// gateway telemetry is a decorator on the audit recorder, wired in
// cmd/mcp-gateway and tested there, so the trail is the whole record.)
func TestSecDispatch_EveryDecisionIsAttributedInTheTrail(t *testing.T) {
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{{
			Name: "vt", Upstream: "casemgmt", Limit: 1, Window: 24 * time.Hour,
			Tools: []string{"casemgmt.list_cases"},
		}},
		freeTools: []string{"casemgmt.delete_case", "casemgmt.pending_tool"},
	}, "casemgmt.list_cases", "casemgmt.pending_tool", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list"), def("delete_case", "delete"), def("pending_tool", "never approved"))
	h.serve("logsearch", def("search", "search"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approve("casemgmt", "delete_case")
	h.approve("logsearch", "search")
	up := h.dialer.upstream("logsearch")
	up.mu.Lock()
	up.callErr = errors.New("backend exploded")
	up.mu.Unlock()

	type want struct {
		tool     string
		upstream string
		outcome  audit.Outcome
		reason   string // "" = any non-empty for non-allowed
	}
	steps := []struct {
		tool    string
		wantErr bool
		rows    []want
	}{
		{"casemgmt.list_cases", false, []want{{"casemgmt.list_cases", "casemgmt", audit.OutcomeAllowed, ""}}},
		{"casemgmt.list_cases", true, []want{{"casemgmt.list_cases", "casemgmt", audit.OutcomeDenied, reasonQuotaExhausted}}},
		{"casemgmt.delete_case", true, []want{{"casemgmt.delete_case", "casemgmt", audit.OutcomeDenied, "forbidden"}}},
		{"casemgmt.pending_tool", true, []want{{"casemgmt.pending_tool", "casemgmt", audit.OutcomeDenied, "quarantined"}}},
		{"casemgmt.no_such_tool", true, []want{{"casemgmt.no_such_tool", "casemgmt", audit.OutcomeDenied, "unknown tool"}}},
		{"garbage-without-namespace", true, []want{{"garbage-without-namespace", unknownUpstream, audit.OutcomeDenied, "unknown tool"}}},
		{"logsearch.search", true, []want{
			{"logsearch.search", "logsearch", audit.OutcomeAllowed, ""},
			{"logsearch.search", "logsearch", audit.OutcomeFailed, ""},
		}},
	}

	var expected []want
	for _, s := range steps {
		err := secAQCall(h, fromAnalyst, s.tool)
		if (err != nil) != s.wantErr {
			t.Fatalf("Dispatch(%q) err=%v, wantErr=%v", s.tool, err, s.wantErr)
		}
		expected = append(expected, s.rows...)
	}

	rows := h.auditRows()
	if len(rows) != len(expected) {
		t.Fatalf("audit holds %d rows, want %d: %+v", len(rows), len(expected), rows)
	}
	for i, w := range expected {
		r := rows[i]
		if r.AnalystIdentity != analyst.Subject {
			t.Errorf("row %d (%s) identity %q, want %q", i, w.tool, r.AnalystIdentity, analyst.Subject)
		}
		if r.SourceAddress != analystSource {
			t.Errorf("row %d (%s) source %q, want %q", i, w.tool, r.SourceAddress, analystSource)
		}
		if r.Tool != w.tool || r.TargetUpstream != w.upstream || r.Outcome != w.outcome {
			t.Errorf("row %d = {%q %q %q}, want {%q %q %q}", i, r.Tool, r.TargetUpstream, r.Outcome, w.tool, w.upstream, w.outcome)
		}
		if w.outcome != audit.OutcomeAllowed {
			if r.Reason == "" {
				t.Errorf("row %d (%s, %s) has no reason", i, w.tool, w.outcome)
			}
			if w.reason != "" && r.Reason != w.reason {
				t.Errorf("row %d (%s) reason %q, want %q", i, w.tool, r.Reason, w.reason)
			}
		}
	}

	// No refused call reached a backend other than the one dispatched.
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 1 {
		t.Errorf("casemgmt saw %d calls, want exactly the one allowed call", len(calls))
	}
}

// 64 concurrent Dispatches by one analyst against a limit of 10, on a real
// WAL database shared by the audit trail and the counter: exactly 10 reach
// the backend, exactly 10 allowed rows and 54 "quota exhausted" rows are
// written, and the counter reads 10. Run under -race.
func TestSecQuota_ConcurrentDispatchNeverOverGrantsAndAuditsEveryAttempt(t *testing.T) {
	const limit, callers = 10, 64
	rec, qs := secAQFileDB(t)
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{{
			Name: "vt", Upstream: "threatintel", Limit: limit, Window: 24 * time.Hour,
			Tools: []string{"threatintel.lookup_ip", "threatintel.lookup_hash"},
		}},
		store: qs,
	}, "threatintel.lookup_ip", "threatintel.lookup_hash")
	h.gw.audit = rec
	h.audit = rec
	h.register("threatintel")
	h.serve("threatintel", def("lookup_ip", "ip"), def("lookup_hash", "hash"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")
	h.approve("threatintel", "lookup_hash")

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, exhausted, other := 0, 0, 0
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		tool := "threatintel.lookup_ip"
		if i%2 == 1 {
			tool = "threatintel.lookup_hash"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := secAQCall(h, fromAnalyst, tool)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, quota.ErrExhausted):
				exhausted++
			default:
				other++
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if ok != limit || exhausted != callers-limit || other != 0 {
		t.Fatalf("ok=%d exhausted=%d other=%d, want %d/%d/0", ok, exhausted, other, limit, callers-limit)
	}
	if n := len(h.dialer.upstream("threatintel").callLog()); n != limit {
		t.Fatalf("backend saw %d calls, want %d", n, limit)
	}
	if used := secAQUsed(t, qs, analyst.Subject, "vt"); used != limit {
		t.Fatalf("counter = %d, want %d (a refused reservation must debit nothing)", used, limit)
	}
	rows := h.auditRows()
	allowed, denied := 0, 0
	for _, r := range rows {
		if r.AnalystIdentity != analyst.Subject || r.SourceAddress != analystSource {
			t.Errorf("row not attributed: %+v", r)
		}
		switch {
		case r.Outcome == audit.OutcomeAllowed:
			allowed++
		case r.Outcome == audit.OutcomeDenied && r.Reason == reasonQuotaExhausted:
			denied++
		default:
			t.Errorf("unexpected row %+v", r)
		}
	}
	if allowed != limit || denied != callers-limit {
		t.Fatalf("trail allowed=%d denied=%d, want %d/%d (every attempt, exactly once)", allowed, denied, limit, callers-limit)
	}
}

// One account spent by several tools is one budget: alternating between
// the tool names that spend it buys nothing, and spelling a charged tool
// differently (case, padding, doubled separator) never routes -- so it can
// neither reach the backend uncharged nor escape the trail.
func TestSecQuota_ToolNameVariantsCannotBypassTheAccount(t *testing.T) {
	const limit = 3
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{{
			Name: "vt", Upstream: "threatintel", Limit: limit, Window: 24 * time.Hour,
			Tools: []string{"threatintel.lookup_ip", "threatintel.lookup_hash", "threatintel.enrich"},
		}},
		freeTools: []string{"threatintel.decode"},
	}, "threatintel.lookup_ip", "threatintel.lookup_hash", "threatintel.enrich", "threatintel.decode")
	h.register("threatintel")
	h.serve("threatintel", def("lookup_ip", "ip"), def("lookup_hash", "hash"), def("enrich", "e"), def("decode", "d"))
	h.mustConnect()
	for _, n := range []string{"lookup_ip", "lookup_hash", "enrich", "decode"} {
		h.approve("threatintel", n)
	}

	names := []string{"threatintel.lookup_ip", "threatintel.lookup_hash", "threatintel.enrich"}
	ok := 0
	for i := 0; i < 3*limit; i++ {
		if err := secAQCall(h, fromAnalyst, names[i%len(names)]); err == nil {
			ok++
		} else if !errors.Is(err, quota.ErrExhausted) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if ok != limit {
		t.Fatalf("%d charged calls admitted across three tool names, want %d", ok, limit)
	}

	variants := []string{
		"THREATINTEL.lookup_ip", "threatintel.LOOKUP_IP", "threatintel.lookup_ip ", " threatintel.lookup_ip",
		"threatintel..lookup_ip", "threatintel.lookup_ip\x00", "threatintel.lookup_ip\n", "threatintel/lookup_ip",
		"threatintel.lookupıp",
	}
	before := len(h.dialer.upstream("threatintel").callLog())
	rowsBefore := len(h.auditRows())
	for _, v := range variants {
		err := secAQCall(h, fromAnalyst, v)
		if err == nil {
			t.Errorf("variant %q was dispatched", v)
		}
	}
	if after := len(h.dialer.upstream("threatintel").callLog()); after != before {
		t.Fatalf("a name variant reached the backend (%d -> %d calls)", before, after)
	}
	rows := h.auditRows()[rowsBefore:]
	if len(rows) != len(variants) {
		t.Fatalf("%d variant attempts left %d rows, want one each", len(variants), len(rows))
	}
	for i, r := range rows {
		if r.Outcome != audit.OutcomeDenied || r.Tool != variants[i] || r.AnalystIdentity != analyst.Subject {
			t.Errorf("variant %q recorded as %+v", variants[i], r)
		}
	}
	// The free tool is still free once the account is spent.
	if err := secAQCall(h, fromAnalyst, "threatintel.decode"); err != nil {
		t.Fatalf("free tool refused after the account was spent: %v", err)
	}
}

// The window resets exactly at its end and not a nanosecond before, and
// the clock's zone offset does not open a second counter within one UTC
// window.
func TestSecQuota_WindowBoundaryIsExactAndOffsetIndependent(t *testing.T) {
	const limit = 2
	window := time.Hour
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{{
			Name: "vt", Upstream: "threatintel", Limit: limit, Window: window,
			Tools: []string{"threatintel.lookup_ip"},
		}},
	}, "threatintel.lookup_ip")
	h.register("threatintel")
	h.serve("threatintel", def("lookup_ip", "ip"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")

	windowStart := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	set := func(t0 time.Time) { h.gw.now = func() time.Time { return t0 } }

	// First unit in UTC at the start, second from a clock in -03:00 at the
	// same UTC window, third a nanosecond before the end: exhausted.
	set(windowStart)
	if err := secAQCall(h, fromAnalyst, "threatintel.lookup_ip"); err != nil {
		t.Fatalf("1st: %v", err)
	}
	set(windowStart.Add(30 * time.Minute).In(time.FixedZone("BRT", -3*3600)))
	if err := secAQCall(h, fromAnalyst, "threatintel.lookup_ip"); err != nil {
		t.Fatalf("2nd: %v", err)
	}
	set(windowStart.Add(window - time.Nanosecond).In(time.FixedZone("IST", 5*3600+1800)))
	if err := secAQCall(h, fromAnalyst, "threatintel.lookup_ip"); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("3rd one nanosecond before the boundary: err=%v, want ErrExhausted (an offset must not open a new counter)", err)
	}
	// Exactly at the boundary: the next window.
	set(windowStart.Add(window))
	if err := secAQCall(h, fromAnalyst, "threatintel.lookup_ip"); err != nil {
		t.Fatalf("at the boundary: %v", err)
	}
	if n := len(h.dialer.upstream("threatintel").callLog()); n != limit+1 {
		t.Fatalf("backend saw %d calls, want %d", n, limit+1)
	}
}

// A shared credential -- the only kind this gateway has -- is one upstream
// credential for everyone, and one counter per analyst SUBJECT. The same subject arriving from a second
// address (a stolen token) does not get a fresh budget, and a second
// analyst's spending does not move the first's.
func TestSecQuota_SharedCredentialCountsPerSubjectNotPerSource(t *testing.T) {
	const limit = 2
	h := newQuotaHarness(t, quotaSetup{
		providers: []quota.Provider{{
			Name: "vt", Upstream: "threatintel", Limit: limit, Window: 24 * time.Hour,
			Tools: []string{"threatintel.lookup_ip"},
		}},
	}, "threatintel.lookup_ip")
	h.register("threatintel")
	h.serve("threatintel", def("lookup_ip", "ip"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")

	thief := Caller{Identity: analyst, SourceAddress: "203.0.113.9"}
	other := Caller{Identity: access.Identity{Subject: "sub-analyst-2", Groups: analyst.Groups}, SourceAddress: "198.51.100.8"}

	if err := secAQCall(h, fromAnalyst, "threatintel.lookup_ip"); err != nil {
		t.Fatal(err)
	}
	if err := secAQCall(h, thief, "threatintel.lookup_ip"); err != nil {
		t.Fatal(err)
	}
	if err := secAQCall(h, thief, "threatintel.lookup_ip"); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("same subject from a second source got a fresh budget: err=%v", err)
	}
	for i := 0; i < limit; i++ {
		if err := secAQCall(h, other, "threatintel.lookup_ip"); err != nil {
			t.Fatalf("second analyst call %d: %v", i, err)
		}
	}
	if err := secAQCall(h, other, "threatintel.lookup_ip"); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("second analyst over limit: err=%v", err)
	}
	if u := h.used("vt"); u != limit {
		t.Fatalf("analyst-1 counter = %d, want %d", u, limit)
	}

	// The trail tells the two sources apart for the same subject.
	sources := map[string]int{}
	for _, r := range h.auditRows() {
		if r.AnalystIdentity == analyst.Subject {
			sources[r.SourceAddress]++
		}
	}
	if sources[analystSource] != 1 || sources["203.0.113.9"] != 2 {
		t.Fatalf("per-source rows for analyst-1 = %v", sources)
	}
}
