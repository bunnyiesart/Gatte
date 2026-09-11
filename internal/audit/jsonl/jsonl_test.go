package jsonl_test

// Test doubles policy, stated once:
//
//   - The inner recorder is the REAL sqlite adapter over an in-memory
//     store. The properties under test are "the hash on the line is the
//     hash on disk" and "the SIEM's newest hash detects a truncated local
//     tail"; a fake that invents hashes would be testing the fake.
//
//   - The sink is the REAL FileSink over t.TempDir() wherever the bytes
//     matter, so assertions are against what a shipper would actually
//     read. A hand-written failing sink appears only where a sink failure
//     has to be forced, which the real one offers no honest way to do.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/audit/jsonl"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// schemaKeys is the v1 schema, written out by hand rather than derived
// from the struct. Deriving it would make the test agree with whatever the
// struct says, including a field somebody added yesterday that carries an
// upstream error string -- which is the exact failure this test exists to
// catch. The list is duplicated on purpose; the duplication is the check.
var schemaKeys = []string{
	"v", "ts", "chain", "caller", "backend", "tool",
	"verdict", "rule", "src", "prev_hash", "hash",
}

const testChain = "gatte-jail-01"

// ---------------------------------------------------------------- fakes

// failingSink is the only fake here: a real FileSink offers no honest way
// to fail on command without chmodding a directory mid-test.
type failingSink struct {
	mu   sync.Mutex
	err  error
	seen int
}

func (s *failingSink) Emit(context.Context, jsonl.Line) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen++
	return s.err
}

func (s *failingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen
}

var _ jsonl.Sink = (*failingSink)(nil)

// -------------------------------------------------------------- harness

type harness struct {
	t    *testing.T
	db   *sql.DB
	sql  *auditsql.Recorder
	rec  *jsonl.Recorder
	path string
	logs *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarnessWithSink(t, nil)
	return h
}

// newHarnessWithSink builds the decorator over the real sqlite adapter. A
// nil sink means "use a real FileSink in a temp dir", which is the normal
// case; a non-nil one is for forcing a sink failure.
func newHarnessWithSink(t *testing.T, sink jsonl.Sink) *harness {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := auditsql.Migrate(db); err != nil {
		t.Fatalf("audit migrate: %v", err)
	}

	h := &harness{t: t, db: db, sql: auditsql.New(db), logs: &bytes.Buffer{}}
	h.path = filepath.Join(t.TempDir(), "audit.jsonl")
	if sink == nil {
		fs, err := jsonl.OpenFile(h.path)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		t.Cleanup(func() { fs.Close() })
		sink = fs
	}

	rec, err := jsonl.New(h.sql, sink, testChain, slog.New(slog.NewJSONHandler(h.logs, nil)))
	if err != nil {
		t.Fatalf("jsonl.New: %v", err)
	}
	h.rec = rec
	return h
}

// lines returns the emitted file split into non-empty lines.
func (h *harness) lines() []string {
	h.t.Helper()
	raw, err := os.ReadFile(h.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		h.t.Fatalf("read sink: %v", err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// decoded returns each emitted line as a generic map, which is how a log
// pipeline sees it -- and therefore the only honest way to assert on the
// key set.
func (h *harness) decoded() []map[string]any {
	h.t.Helper()
	var out []map[string]any
	for i, l := range h.lines() {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			h.t.Fatalf("line %d is not valid JSON (%v): %s", i, err, l)
		}
		out = append(out, m)
	}
	return out
}

func (h *harness) rowCount() int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM audit_records`).Scan(&n); err != nil {
		h.t.Fatalf("count rows: %v", err)
	}
	return n
}

func (h *harness) head() string {
	h.t.Helper()
	check, err := h.sql.VerifyChain(context.Background())
	if err != nil {
		h.t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() {
		h.t.Fatalf("chain is broken at position %d; the test setup is wrong, not the code", check.FirstBreak.Position)
	}
	return check.Head
}

func rec(tool string, outcome audit.Outcome, reason string) audit.Record {
	return audit.Record{
		AnalystIdentity: "sub-analyst-1",
		Tool:            tool,
		TargetUpstream:  "casemgmt",
		// A non-UTC zone on purpose: the line normalizes to UTC and the
		// chain does not, and a test fixed at UTC would hide that.
		Timestamp:     time.Date(2026, 9, 11, 10, 30, 45, 123456789, time.FixedZone("BRT", -3*3600)),
		Outcome:       outcome,
		Reason:        reason,
		SourceAddress: "198.51.100.77",
	}
}

// --------------------------------------------------------------- tests

// TestEmittedLineCarriesExactlyTheDeclaredSchema is the structural guard
// ADR-0017 names: a future field carrying an upstream error string, a
// token, or a tool argument fails here rather than shipping to Graylog and
// being noticed by whoever reads the stream.
//
// It asserts the key set is EXACTLY the declared one -- both directions,
// so neither adding nor dropping a key passes.
func TestEmittedLineCarriesExactlyTheDeclaredSchema(t *testing.T) {
	h := newHarness(t)

	if err := h.rec.Record(context.Background(), rec("casemgmt.list_cases", audit.OutcomeAllowed, "")); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got := h.decoded()
	if len(got) != 1 {
		t.Fatalf("emitted %d lines, want 1", len(got))
	}

	keys := make([]string, 0, len(got[0]))
	for k := range got[0] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := slices.Sorted(slices.Values(schemaKeys))
	if !slices.Equal(keys, want) {
		t.Fatalf("line key set = %v, want exactly %v", keys, want)
	}
}

// TestEmittedLineFieldsMapToTheRecord pins each field to the audit.Record
// field it is supposed to carry. Without this, a line whose `caller` held
// the upstream name would still pass the schema test above.
func TestEmittedLineFieldsMapToTheRecord(t *testing.T) {
	h := newHarness(t)

	r := rec("casemgmt.get_case", audit.OutcomeDenied, "forbidden")
	if err := h.rec.Record(context.Background(), r); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got := h.decoded()[0]
	want := map[string]any{
		"v":       float64(jsonl.Version),
		"ts":      "2026-09-11T13:30:45.123456789Z", // 10:30:45-03:00, normalized
		"chain":   testChain,
		"caller":  "sub-analyst-1",
		"backend": "casemgmt",
		"tool":    "casemgmt.get_case",
		"verdict": "denied",
		"rule":    "forbidden",
		"src":     "198.51.100.77",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("line[%q] = %#v, want %#v", k, got[k], w)
		}
	}
	if got["prev_hash"] != "" {
		t.Errorf("prev_hash = %q, want empty for the first record in a chain", got["prev_hash"])
	}
	if got["hash"] == "" {
		t.Error("hash is empty; the line's whole reason for existing is the pair of hashes")
	}
}

// TestEmittedHashesAreTheHashesOnDisk is the claim ADR-0017 rests on: the
// pair on the line is the pair the sqlite adapter actually stored, not a
// recomputation that could drift from it.
//
// It also pins the links: each line's prev_hash is the previous line's
// hash, and the last line's hash is the chain head VerifyChain reports.
func TestEmittedHashesAreTheHashesOnDisk(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for i := range 4 {
		r := rec(fmt.Sprintf("casemgmt.tool_%d", i), audit.OutcomeAllowed, "")
		if err := h.rec.Record(ctx, r); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	lines := h.decoded()
	if len(lines) != 4 {
		t.Fatalf("emitted %d lines, want 4", len(lines))
	}

	prev := audit.GenesisHash
	for i, l := range lines {
		if l["prev_hash"] != prev {
			t.Fatalf("line %d prev_hash = %q, want %q -- the emitted links do not chain", i, l["prev_hash"], prev)
		}
		prev, _ = l["hash"].(string)
		if prev == "" {
			t.Fatalf("line %d has no hash", i)
		}
	}

	if head := h.head(); head != prev {
		t.Fatalf("newest emitted hash = %q, but the stored chain head is %q -- the line does not anchor the trail", prev, head)
	}
}

// TestTruncatedLocalTailIsVisibleAgainstTheEmittedHead is the load-bearing
// test for ADR-0015's open item 6 and the reason this package exists.
//
// ADR-0015 is explicit that cutting the last N records leaves a shorter
// chain that verifies perfectly -- and that test exists in
// internal/audit/sqlite, asserting the gap. What was missing was anywhere
// to keep the expected head. Here the SIEM copy holds it: after deleting
// the last two rows the chain still verifies, and the ONLY thing that says
// something is wrong is that the stored head no longer matches the newest
// hash the sink shipped.
func TestTruncatedLocalTailIsVisibleAgainstTheEmittedHead(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for i := range 5 {
		if err := h.rec.Record(ctx, rec(fmt.Sprintf("casemgmt.tool_%d", i), audit.OutcomeAllowed, "")); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	lines := h.decoded()
	shippedHead, _ := lines[len(lines)-1]["hash"].(string)
	if shippedHead == "" {
		t.Fatal("no head was shipped; nothing below would prove anything")
	}
	if h.head() != shippedHead {
		t.Fatalf("precondition: stored head %q != shipped head %q", h.head(), shippedHead)
	}

	// The attacker with write access to the jail's filesystem cuts the
	// tail. ADR-0015 item 6: this leaves a valid chain.
	if _, err := h.db.Exec(`DELETE FROM audit_records WHERE id > (SELECT MIN(id) + 2 FROM audit_records)`); err != nil {
		t.Fatalf("truncate tail: %v", err)
	}

	check, err := h.sql.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() {
		t.Fatal("truncating the tail broke the chain -- ADR-0015 item 6 says it does not, so either the ADR or this test is now wrong")
	}
	if check.Count != 3 {
		t.Fatalf("after truncation the trail has %d records, want 3", check.Count)
	}

	if check.Head == shippedHead {
		t.Fatal("the stored head still matches the shipped head after truncation; the anchor detects nothing")
	}
	// And the head the SIEM holds is still one of the hashes this trail
	// once had -- which is what tells an operator this is truncation and
	// not a different database.
	var shippedStillPresent bool
	for _, l := range lines {
		if l["hash"] == check.Head {
			shippedStillPresent = true
		}
	}
	if !shippedStillPresent {
		t.Fatal("the truncated head is not among the shipped hashes; the SIEM copy could not identify where the trail was cut")
	}
}

// TestFailedCallEmitsTwoLines pins the cost ADR-0012 accepted, at the
// sink: a failure appends a second line rather than correcting the first,
// so counting lines over-counts attempts. Documented in the package doc;
// asserted here so the documentation cannot quietly stop being true.
func TestFailedCallEmitsTwoLines(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.rec.Record(ctx, rec("threatintel.lookup", audit.OutcomeAllowed, "")); err != nil {
		t.Fatalf("Record allowed: %v", err)
	}
	if err := h.rec.Record(ctx, rec("threatintel.lookup", audit.OutcomeFailed, "upstream unavailable")); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	lines := h.decoded()
	if len(lines) != 2 {
		t.Fatalf("one failed call emitted %d lines, want 2", len(lines))
	}
	if lines[0]["verdict"] != "allowed" || lines[1]["verdict"] != "failed" {
		t.Fatalf("verdicts = %q, %q; want allowed then failed", lines[0]["verdict"], lines[1]["verdict"])
	}
	// The allowed line is not rewritten: its hash is untouched by the
	// second record, which is what makes the pair evidence rather than
	// state.
	if lines[1]["prev_hash"] != lines[0]["hash"] {
		t.Error("the failed line does not chain from the allowed one")
	}
}

// TestSinkFailureIsLoudButNotADenial is rule 2 of ADR-0017: the
// dispatch-refusal rule covers the durable write and stops there.
//
// If this ever starts returning an error, gateway.Dispatch will refuse an
// analyst's call because a log file could not be appended to -- an
// availability fault turned into a denial.
func TestSinkFailureIsLoudButNotADenial(t *testing.T) {
	sink := &failingSink{err: errors.New("no space left on device")}
	h := newHarnessWithSink(t, sink)

	if err := h.rec.Record(context.Background(), rec("casemgmt.list_cases", audit.OutcomeAllowed, "")); err != nil {
		t.Fatalf("Record returned %v; a sink failure must not refuse the call", err)
	}
	if got := h.rowCount(); got != 1 {
		t.Fatalf("stored %d rows, want 1 -- the durable write must still have happened", got)
	}
	if sink.count() != 1 {
		t.Fatalf("sink saw %d emits, want 1", sink.count())
	}
	if !strings.Contains(h.logs.String(), `"level":"ERROR"`) {
		t.Fatalf("sink failure was not logged at ERROR; log was: %s", h.logs.String())
	}
	if !strings.Contains(h.logs.String(), "no space left on device") {
		t.Fatalf("the sink's own error was not reported; log was: %s", h.logs.String())
	}
}

// TestNothingIsEmittedWhenTheDurableWriteFails is the ordering guarantee
// stated the other way round. A line in Graylog with no row in SQLite
// would break the one-directional divergence the whole design rests on:
// the SIEM must only ever hold records that were durable locally first.
func TestNothingIsEmittedWhenTheDurableWriteFails(t *testing.T) {
	h := newHarness(t)

	// An invalid record is the honest way to make the inner recorder
	// refuse: it is rejected before any SQL runs, exactly as a real
	// validation failure would be.
	bad := rec("casemgmt.list_cases", audit.OutcomeAllowed, "")
	bad.AnalystIdentity = ""

	err := h.rec.Record(context.Background(), bad)
	if !errors.Is(err, audit.ErrInvalid) {
		t.Fatalf("Record err = %v, want audit.ErrInvalid", err)
	}
	if got := h.rowCount(); got != 0 {
		t.Fatalf("stored %d rows, want 0", got)
	}
	if got := h.lines(); len(got) != 0 {
		t.Fatalf("emitted %d lines for a record that was never stored: %v", len(got), got)
	}
}

// TestRecordChainedReturnsZeroLinkOnFailure pins the contract the port
// documents: a caller that ignores the error must not be handed a link
// whose empty Prev reads as GenesisHash.
func TestRecordChainedReturnsZeroLinkOnFailure(t *testing.T) {
	h := newHarness(t)

	bad := rec("casemgmt.list_cases", audit.OutcomeAllowed, "")
	bad.Outcome = ""

	link, err := h.rec.RecordChained(context.Background(), bad)
	if err == nil {
		t.Fatal("RecordChained accepted a record with no outcome")
	}
	if link != (audit.ChainLink{}) {
		t.Fatalf("link = %+v, want the zero value on error", link)
	}
}

// TestNewRejectsAnIncompleteRecorder covers the three ways to build a
// decorator that looks like it ships to the SIEM and does not.
func TestNewRejectsAnIncompleteRecorder(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := auditsql.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	inner := auditsql.New(db)
	sink := &failingSink{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name  string
		inner audit.ChainedRecorder
		sink  jsonl.Sink
		chain string
	}{
		{"no inner recorder", nil, sink, testChain},
		{"no sink", inner, nil, testChain},
		{"no chain name", inner, sink, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := jsonl.New(c.inner, c.sink, c.chain, log); err == nil {
				t.Fatal("New accepted it")
			}
		})
	}
}

// TestFileSinkAppendsWholeLinesUnderConcurrency guards the single-Write
// discipline. Two writes per line -- JSON then newline -- would let
// concurrent emits interleave and produce lines a log pipeline would
// index as garbage, which is worse than a dropped line because it looks
// like data.
func TestFileSinkAppendsWholeLinesUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := jsonl.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer sink.Close()

	const n = 200
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			line := jsonl.Line{
				Version: jsonl.Version,
				Chain:   testChain,
				Tool:    fmt.Sprintf("casemgmt.tool_%03d", i),
				Hash:    strings.Repeat("a", 64),
			}
			if err := sink.Emit(context.Background(), line); err != nil {
				t.Errorf("Emit: %v", err)
			}
		}()
	}
	wg.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	got := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(got) != n {
		t.Fatalf("file has %d lines, want %d", len(got), n)
	}
	seen := map[string]bool{}
	for i, l := range got {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line %d is not whole JSON (%v): %q", i, err, l)
		}
		tool, _ := m["tool"].(string)
		if seen[tool] {
			t.Fatalf("tool %q appears twice", tool)
		}
		seen[tool] = true
	}
}

// TestFileSinkAppendsToAnExistingFile: a restart must not truncate what
// the shipper has not read yet.
func TestFileSinkAppendsToAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("{\"v\":1}\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	sink, err := jsonl.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := sink.Emit(context.Background(), jsonl.Line{Version: jsonl.Version, Tool: "casemgmt.x"}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	if !strings.HasPrefix(string(raw), "{\"v\":1}\n") {
		t.Fatalf("opening the sink discarded existing content: %q", raw)
	}
	if !strings.Contains(string(raw), "casemgmt.x") {
		t.Fatalf("the new line was not appended: %q", raw)
	}
}

// TestFileSinkEmitAfterCloseIsAnErrorNotAPanic: a shutdown race must not
// take the gateway down.
func TestFileSinkEmitAfterCloseIsAnErrorNotAPanic(t *testing.T) {
	sink, err := jsonl.OpenFile(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sink.Emit(context.Background(), jsonl.Line{}); err == nil {
		t.Fatal("Emit after Close returned nil")
	}
}

// TestFileSinkModeIsNotWorldReadable: the trail names which analyst
// touched which case. No credentials, but not public either.
func TestFileSinkModeIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := jsonl.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer sink.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("sink file mode is %v, want no group or other access", info.Mode().Perm())
	}
}

// TestOpenFile_NarrowsAnExistingWideFile: the mode argument to os.OpenFile
// applies only on creation, so a sink file that already exists kept
// whatever permissions it had while the package doc promised 0600. A
// rotation that recreates the file with the shipper's umask is the
// ordinary way this happens.
func TestOpenFile_NarrowsAnExistingWideFile(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s, err := jsonl.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != jsonl.DefaultFileMode {
		t.Errorf("sink mode = %#o, want %#o -- an existing file keeps its own mode unless this is enforced", got, jsonl.DefaultFileMode)
	}
}
