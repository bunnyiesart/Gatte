package gelf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// This file is the telemetry half of the question
// internal/vault/sopsage/leak_test.go asks about the vault: this
// component is the first thing in the module that takes audit data and
// puts it on a network, and project invariant 1 says no credential value
// may appear in a log line, a GELF field, an error message or argv --
// only the NAMES of environment variables may.
//
// The structure is deliberately the same as sopsage's: an assertion that
// the secret is absent, and in the same function an assertion that
// something that SHOULD be there is present. Without the second half the
// absence is trivially true, and a sink that sent nothing at all would
// pass.

// wireKeys is the exact set of top-level keys a GELF audit message may
// carry. It is a KEY SET and not a substring scan on purpose: a substring
// scan only catches the leak somebody thought to plant a sentinel for,
// while the key set catches the field nobody planted -- a latency, a
// correlation id, a result size, an args blob -- the day someone widens
// the message without widening the trail first.
var wireKeys = []string{
	"version",
	"host",
	"short_message",
	"level",
	"timestamp",
	"_event_kind",
	"_cliente_soc",
	"_analyst_identity",
	"_tool",
	"_target_upstream",
	"_outcome",
	"_reason",
	"_source_address",
}

// TestOnlyTheSevenAuditFieldsReachTheWire pins the shape of what leaves
// the process: the two static fields from the file, and the seven fields
// of audit.Record, and nothing else at all.
func TestOnlyTheSevenAuditFieldsReachTheWire(t *testing.T) {
	addr, msgs := fakeUDP(t)
	s := newSink(t, baseConfig(addr, TransportUDP))

	// Every optional field populated, so a missing key is a real
	// omission and not just an empty value.
	s.Emit(audit.Record{
		AnalystIdentity: "ana@example.org",
		Tool:            "threatintel.virustotal",
		TargetUpstream:  "threatintel",
		Timestamp:       time.Now(),
		Outcome:         audit.OutcomeDenied,
		Reason:          "quarantined",
		SourceAddress:   "10.20.0.9",
	})

	var got map[string]any
	if err := json.Unmarshal(waitMsg(t, msgs, 3*time.Second), &got); err != nil {
		t.Fatalf("the datagram is not JSON: %v", err)
	}

	want := make(map[string]bool, len(wireKeys))
	for _, k := range wireKeys {
		want[k] = true
		if _, present := got[k]; !present {
			t.Errorf("key %q is missing from the wire message", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("key %q is on the wire and is not in the agreed set -- widening what leaves "+
				"this process is a change to the audit trail first (design/adr/0029)", k)
		}
	}
}

// TestNoPlantedSecretReachesTheWire plants a secret-shaped value
// everywhere it could plausibly be picked up by an implementation that
// went looking for context -- the process environment, the way the vault
// hands one to a spawned upstream, and the upstream's own error text,
// which is the one piece of backend-authored prose this system already
// refuses to put in the trail (endpoint.go:1780) -- then drives the five
// event shapes the gateway actually produces and reads every byte that
// left the socket.
func TestNoPlantedSecretReachesTheWire(t *testing.T) {
	const secretValue = "vt-l3ak-check-9f8e7d6c5b4a"

	// The vault resolves a value like this and injects it into the
	// upstream's environment. This process therefore has it in its own
	// environment at the moment the sink is running.
	t.Setenv("THREATINTEL_VT_KEY", secretValue)

	// And this is what the upstream said when it failed. classifyFailure
	// reduces it to a closed-set reason; the text itself goes to the log
	// and only to the log. If it ever reached a Record it would reach the
	// wire, which is why the record below carries the reason constant and
	// not this.
	cause := fmt.Errorf("threatintel upstream: 401 from api.virustotal.com using key %s", secretValue)
	if !strings.Contains(cause.Error(), secretValue) {
		t.Fatal("the planted cause does not contain the secret -- the fixture is wrong")
	}

	logs := newSyncBuffer()
	addr, msgs := fakeUDP(t)
	cfg := baseConfig(addr, TransportUDP)
	cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
	s := newSink(t, cfg)

	now := time.Now()
	records := []audit.Record{
		// allowed, before dispatch
		{AnalystIdentity: "ana@example.org", Tool: "threatintel.virustotal", TargetUpstream: "threatintel",
			Timestamp: now, Outcome: audit.OutcomeAllowed, SourceAddress: "10.20.0.9"},
		// denied by policy
		{AnalystIdentity: "ana@example.org", Tool: "threatintel.virustotal", TargetUpstream: "threatintel",
			Timestamp: now, Outcome: audit.OutcomeDenied, Reason: "forbidden", SourceAddress: "10.20.0.9"},
		// failed, the record written after the cause above
		{AnalystIdentity: "ana@example.org", Tool: "threatintel.virustotal", TargetUpstream: "threatintel",
			Timestamp: now, Outcome: audit.OutcomeFailed, Reason: "upstream failed", SourceAddress: "10.20.0.9"},
		// authentication failure: no identity, no tool, no token anywhere
		{AnalystIdentity: "(unauthenticated)", Tool: "(authentication)", TargetUpstream: "(gateway)",
			Timestamp: now, Outcome: audit.OutcomeDenied, Reason: "authentication failed", SourceAddress: "10.20.0.9"},
		// refused probe of a tool the caller cannot see
		{AnalystIdentity: "ana@example.org", Tool: "casemgmt.list_cases", TargetUpstream: "(unknown)",
			Timestamp: now, Outcome: audit.OutcomeDenied, Reason: "not visible to caller", SourceAddress: "10.20.0.9"},
	}
	for _, r := range records {
		s.Emit(r)
	}

	waitFor(t, 3*time.Second, "every event to leave the socket", func() bool {
		return s.Stats().Written == uint64(len(records))
	})

	// Drain everything the socket received into one buffer and search it
	// whole: a leak in any single datagram is a leak.
	var wire bytes.Buffer
	deadline := time.After(2 * time.Second)
	for range records {
		select {
		case b := <-msgs:
			wire.Write(b)
			wire.WriteByte('\n')
		case <-deadline:
			t.Fatalf("only %d of %d datagrams arrived", bytes.Count(wire.Bytes(), []byte("\n")), len(records))
		}
	}

	// The decisive assertion.
	if strings.Contains(wire.String(), secretValue) {
		t.Fatalf("LEAK: the raw secret is on the wire:\n%s", wire.String())
	}
	// And it must not be in this component's own log either -- the log is
	// the other thing that leaves the process.
	if strings.Contains(logs.String(), secretValue) {
		t.Fatalf("LEAK: the raw secret is in the sink's log:\n%s", logs.String())
	}

	// POSITIVE CONTROL, in the same function and for the same reason as
	// sopsage's ReceivedExpectedSecret check: without it, "the secret is
	// absent" would be satisfied by a sink that sent nothing at all.
	if !strings.Contains(wire.String(), "ana@example.org") {
		t.Fatal("the analyst identity is not on the wire -- nothing was delivered, so the absence " +
			"of the secret above proves nothing")
	}
	if !strings.Contains(wire.String(), "(unauthenticated)") {
		t.Fatal("the authentication-failure record did not reach the wire")
	}
}

// TestTheEnvironmentIsNeverConsulted is the structural half of the same
// invariant: this component reads no credential map and no environment
// variable, so the taint analysis in internal/fitness/argv_test.go covers
// it for free, with no allowlist entry. The test proves the property that
// makes that true -- an environment variable whose NAME matches a GELF
// field changes nothing about what is sent.
func TestTheEnvironmentIsNeverConsulted(t *testing.T) {
	t.Setenv("HOSTNAME", "some-container-id-that-changes-every-restart")
	t.Setenv("THREATINTEL_VT_KEY", "vt-should-never-appear")

	addr, msgs := fakeUDP(t)
	s := newSink(t, baseConfig(addr, TransportUDP))
	s.Emit(sampleRecord())

	m := decode(t, waitMsg(t, msgs, 3*time.Second))
	if got, want := m["host"], "mcp-gateway-01"; got != want {
		t.Errorf("host = %v, want %q -- host comes from the file, never from the environment and "+
			"never from os.Hostname(), whose value in a container changes on every restart and "+
			"shatters every dashboard's grouping", got, want)
	}
	if os.Getenv("THREATINTEL_VT_KEY") == "" {
		t.Fatal("the fixture did not set the variable")
	}
}

// TestEncodeFailureLogsNoRecordContent guards the log line that names a
// dropped message: it may name the tool and the outcome, which are the
// gateway's own closed vocabulary, and nothing else from the record.
func TestEncodeFailureLogsNoRecordContent(t *testing.T) {
	const planted = "s3cret-in-the-source-address"

	logs := newSyncBuffer()
	cfg := baseConfig(reservedAddr(t), TransportTCP)
	cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
	s := newSink(t, cfg)

	r := sampleRecord()
	// Oversize, and carrying a planted value in the field that made it
	// oversize.
	r.SourceAddress = planted + strings.Repeat("x", MaxMessageBytes)

	if _, err := s.enc.encode(r); !errors.Is(err, errOversize) {
		t.Fatalf("the fixture record is not oversize: %v", err)
	}
	s.countEncodeFailure(r, fmt.Errorf("%w: %d bytes", errOversize, MaxMessageBytes+1))

	out := logs.String()
	if !strings.Contains(out, "threatintel.virustotal") {
		t.Errorf("the log line does not name the tool, so the operator cannot find the row in the "+
			"trail:\n%s", out)
	}
	if strings.Contains(out, planted) {
		t.Errorf("LEAK: the log line echoes record content:\n%s", out)
	}
}
