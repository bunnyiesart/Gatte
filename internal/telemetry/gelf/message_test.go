package gelf

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// testEncoder is the encoder every test in this file uses, with the two
// static fields set to values no record field could produce by accident.
func testEncoder() encoder {
	return encoder{host: "mcp-gateway-01", clienteSOC: "example-client"}
}

// decode renders b back into a map so a test can assert on keys rather
// than on substrings of JSON. Substring assertions on a serialized
// message pass for the wrong reasons -- a value in the wrong field still
// matches.
func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("message is not valid JSON: %v\nbytes: %s", err, b)
	}
	return m
}

// TestMessageCarriesEveryRecordField puts a distinct sentinel in each of
// audit.Record's seven fields and requires each one to come out under its
// exact GELF key.
//
// This is the positive control for the mapping, and the real failure mode
// of message.go: a field silently forgotten or renamed produces a message
// that is still well-formed GELF, still indexes fine, and is missing the
// one thing an incident needed.
func TestMessageCarriesEveryRecordField(t *testing.T) {
	r := audit.Record{
		AnalystIdentity: "sentinel-analyst",
		Tool:            "sentinel.tool",
		TargetUpstream:  "sentinel-upstream",
		Timestamp:       time.Date(2026, 9, 14, 3, 11, 7, 500000000, time.UTC),
		Outcome:         audit.OutcomeDenied,
		Reason:          "sentinel-reason",
		SourceAddress:   "203.0.113.77",
	}

	b, err := testEncoder().encode(r)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	m := decode(t, b)

	want := map[string]string{
		"_analyst_identity": "sentinel-analyst",
		"_tool":             "sentinel.tool",
		"_target_upstream":  "sentinel-upstream",
		"_outcome":          "denied",
		"_reason":           "sentinel-reason",
		"_source_address":   "203.0.113.77",
	}
	for key, value := range want {
		got, ok := m[key]
		if !ok {
			t.Errorf("key %q is missing from the message", key)
			continue
		}
		if got != value {
			t.Errorf("%s = %v, want %q", key, got, value)
		}
	}

	// The seventh field is the timestamp, asserted numerically below and
	// in TestLevelAndTimestampComeFromTheRecord.
	if got := m["timestamp"].(float64); math.Abs(got-1789355467.5) > 1e-6 {
		t.Errorf("timestamp = %f, want 1789355467.5", got)
	}

	// short_message is composed only of the closed outcome vocabulary
	// and the tool name.
	if got, want := m["short_message"], "mcp-gateway denied sentinel.tool"; got != want {
		t.Errorf("short_message = %q, want %q", got, want)
	}
	if got, want := m["_cliente_soc"], "example-client"; got != want {
		t.Errorf("_cliente_soc = %q, want %q", got, want)
	}
	if got, want := m["_event_kind"], "audit"; got != want {
		t.Errorf("_event_kind = %q, want %q", got, want)
	}
}

// TestMessageOmitsEmptyOptionalFields asserts on the ABSENCE of the two
// optional keys, not on their text.
//
// An empty SourceAddress is valid and honest -- a surface with no network
// peer, or a row that predates the column. Sending "" would put "there
// was no address" and "the address was empty" in the same bucket of any
// aggregation, which is a wrong answer rather than a missing one.
func TestMessageOmitsEmptyOptionalFields(t *testing.T) {
	r := audit.Record{
		AnalystIdentity: "ana",
		Tool:            "threatintel.virustotal",
		TargetUpstream:  "threatintel",
		Timestamp:       time.Now(),
		Outcome:         audit.OutcomeAllowed,
		// Reason and SourceAddress deliberately empty.
	}

	m := decode(t, mustEncode(t, r))

	for _, key := range []string{"_reason", "_source_address"} {
		if v, present := m[key]; present {
			t.Errorf("%s is present as %#v -- it must be absent, not empty", key, v)
		}
	}
}

// TestMessageIsValidGELF11 checks the format rules Graylog enforces, one
// of which it enforces by silently discarding the message.
func TestMessageIsValidGELF11(t *testing.T) {
	m := decode(t, mustEncode(t, sampleRecord()))

	if got, want := m["version"], "1.1"; got != want {
		t.Errorf("version = %v, want %q", got, want)
	}
	if m["host"] == "" {
		t.Error("host must not be empty")
	}
	if m["short_message"] == "" {
		t.Error("short_message must not be empty")
	}
	if _, present := m["_id"]; present {
		t.Error("_id is present -- GELF 1.1 reserves the key and Graylog DROPS the whole message " +
			"that carries one, so the telemetry would vanish with no error anywhere")
	}
	if _, present := m["full_message"]; present {
		t.Error("full_message is present -- there is no second body to put there that is not " +
			"backend-authored text")
	}
	if _, ok := m["timestamp"].(float64); !ok {
		t.Errorf("timestamp is %T, want a JSON number", m["timestamp"])
	}

	// Every additional field carries the underscore prefix GELF 1.1
	// requires; anything else is silently ignored by the input.
	standard := map[string]bool{"version": true, "host": true, "short_message": true,
		"level": true, "timestamp": true}
	for key := range m {
		if standard[key] {
			continue
		}
		if !strings.HasPrefix(key, "_") {
			t.Errorf("extra field %q has no underscore prefix", key)
		}
	}
}

// TestLevelIsAClosedMapOverOutcome checks the three mappings AND that
// there are exactly three.
//
// Without the second half this test passes against a silent default that
// maps anything at all to Warning, which is precisely the bug the closed
// map exists to prevent: a new outcome would ship as "some warning" and
// nobody would learn it existed.
func TestLevelIsAClosedMapOverOutcome(t *testing.T) {
	cases := []struct {
		outcome audit.Outcome
		level   float64
	}{
		{audit.OutcomeAllowed, 6}, // Informational
		{audit.OutcomeDenied, 5},  // Notice -- a denied call is the gateway WORKING
		{audit.OutcomeFailed, 4},  // Warning
	}
	for _, tc := range cases {
		t.Run(string(tc.outcome), func(t *testing.T) {
			r := sampleRecord()
			r.Outcome = tc.outcome
			m := decode(t, mustEncode(t, r))
			if got := m["level"]; got != tc.level {
				t.Errorf("level = %v, want %v", got, tc.level)
			}
		})
	}

	if len(levelForOutcome) != 3 {
		t.Errorf("levelForOutcome has %d entries, want exactly 3 -- the map is closed over "+
			"audit.Outcome, and an entry added here without an argument in the ADR is a severity "+
			"nobody decided", len(levelForOutcome))
	}

	// And a miss must fail rather than default.
	r := sampleRecord()
	r.Outcome = audit.Outcome("quarantined-someday")
	if _, err := testEncoder().encode(r); err == nil {
		t.Error("encode accepted an outcome outside the closed map -- it must refuse, not default")
	}
}

// TestLevelAndTimestampComeFromTheRecord is the assertion that the
// timestamp is the gateway's injected clock at the instant of the event,
// and not the wall clock of the send.
//
// It would fail the day someone stamps time.Now() in the writer
// goroutine, which is the change that makes a reconnection reorder a
// Graylog stream and is invisible in every other test here.
func TestLevelAndTimestampComeFromTheRecord(t *testing.T) {
	// Deliberately far in the past: no wall clock can produce it.
	recorded := time.Date(2020, 1, 2, 3, 4, 5, 123456000, time.UTC)

	r := sampleRecord()
	r.Timestamp = recorded
	r.Outcome = audit.OutcomeFailed

	m := decode(t, mustEncode(t, r))

	want := float64(recorded.UnixNano()) / 1e9
	got, ok := m["timestamp"].(float64)
	if !ok {
		t.Fatalf("timestamp is %T, want a JSON number", m["timestamp"])
	}
	if math.Abs(got-want) > 1e-6 {
		t.Errorf("timestamp = %f, want %f (Record.Timestamp, not the send clock)", got, want)
	}
	if time.Since(time.Unix(0, int64(got*1e9))) < time.Hour {
		t.Error("timestamp is close to now -- it is being stamped at send time instead of taken " +
			"from the record")
	}
	if got := m["level"]; got != float64(4) {
		t.Errorf("level = %v, want 4 for a failed outcome", got)
	}
}

// TestOversizeMessageIsDroppedNotTruncated proves the ceiling refuses
// rather than cuts, with the just-under case as the positive control --
// without it, an encoder that refused everything would pass.
func TestOversizeMessageIsDroppedNotTruncated(t *testing.T) {
	base := sampleRecord()

	oversize := base
	oversize.SourceAddress = strings.Repeat("x", MaxMessageBytes)

	b, err := testEncoder().encode(oversize)
	if err == nil {
		t.Fatalf("encode accepted a %d-byte message, want it refused above %d", len(b), MaxMessageBytes)
	}
	if !errors.Is(err, errOversize) {
		t.Errorf("error is %v, want it to wrap errOversize so the writer can count it separately", err)
	}
	if b != nil {
		t.Errorf("encode returned %d bytes alongside the error -- cut JSON is invalid JSON, and a "+
			"caller that writes it puts unparseable evidence on the wire", len(b))
	}

	// Positive control: the same record just below the ceiling encodes
	// and parses.
	fits := base
	fits.SourceAddress = strings.Repeat("x", MaxMessageBytes/2)
	small, err := testEncoder().encode(fits)
	if err != nil {
		t.Fatalf("encode refused a message below the ceiling: %v", err)
	}
	if len(small) > MaxMessageBytes {
		t.Fatalf("control message is %d bytes, which is above the ceiling -- the control is not one", len(small))
	}
	decode(t, small)
}

// TestGapMessageCarriesTheRecoveryCommand covers the one message this
// sink authors itself: the numbers have to reconcile and the recovery
// command has to be assembled inside the message, not left for the reader
// to construct from a timestamp.
func TestGapMessageCarriesTheRecoveryCommand(t *testing.T) {
	g := gap{
		start:           time.Date(2026, 9, 14, 3, 11, 7, 0, time.UTC),
		end:             time.Date(2026, 9, 14, 3, 20, 12, 500000000, time.UTC),
		droppedFull:     800,
		droppedWrite:    12,
		droppedOversize: 0,
	}

	b, err := testEncoder().gapMessage(g)
	if err != nil {
		t.Fatalf("gapMessage: %v", err)
	}
	m := decode(t, b)

	if got, want := m["_event_kind"], "telemetry_gap"; got != want {
		t.Errorf("_event_kind = %v, want %q -- without it the gap is indistinguishable from an "+
			"audited event", got, want)
	}
	if got, want := m["_dropped"], float64(812); got != want {
		t.Errorf("_dropped = %v, want %v", got, want)
	}
	if got, want := m["short_message"], "mcp-gateway telemetry gap: 812 audit events were not sent"; got != want {
		t.Errorf("short_message = %q, want %q", got, want)
	}
	if got, want := m["_gap_start"], "2026-09-14T03:11:07Z"; got != want {
		t.Errorf("_gap_start = %v, want %q", got, want)
	}
	if got, want := m["_recover_with"], "mcp-gateway audit --since 2026-09-14T03:11:07Z"; got != want {
		t.Errorf("_recover_with = %v, want %q", got, want)
	}
	if _, present := m["_id"]; present {
		t.Error("_id is present -- Graylog would discard the very message that explains the gap")
	}
}

// mustEncode fails the test rather than returning an error, for the cases
// where encoding is a precondition and not the thing under test.
func mustEncode(t *testing.T, r audit.Record) []byte {
	t.Helper()
	b, err := testEncoder().encode(r)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

// sampleRecord is an ordinary allowed call: every required field set,
// nothing unusual.
func sampleRecord() audit.Record {
	return audit.Record{
		AnalystIdentity: "ana@example.org",
		Tool:            "threatintel.virustotal",
		TargetUpstream:  "threatintel",
		Timestamp:       time.Date(2026, 9, 14, 18, 30, 0, 0, time.UTC),
		Outcome:         audit.OutcomeAllowed,
		Reason:          "",
		SourceAddress:   "10.20.0.9",
	}
}
