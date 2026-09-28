// Package telemetry_test is an external test package so that the
// positive control below can use a REAL sink from the gelf adapter.
//
// The domain package itself must never import its own adapter, and
// internal/fitness enforces exactly that -- over the package's imports,
// which is what ports & adapters is about. An external test binary is not
// the package: nothing in the shipped dependency graph gains an edge, and
// what is bought is a control that a hand-written fake cannot give,
// because a fake reporting Configured == true would be asserting on
// itself.
package telemetry_test

import (
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/telemetry"
	"github.com/bunnyiesart/Gatte/internal/telemetry/gelf"
)

// TestDiscardIsNotConfiguredAndCountsNothing pins the distinction Discard
// exists to make: "nobody configured this" and "this is configured and
// nothing has happened" must never collapse into the same observable
// state, because the first is a gateway shipping no telemetry at all and
// the second is a quiet Tuesday.
func TestDiscardIsNotConfiguredAndCountsNothing(t *testing.T) {
	st := telemetry.Discard.Stats()

	if st.Configured {
		t.Error("Discard reports Configured == true")
	}
	if st.Destination != "" {
		t.Errorf("Destination = %q, want empty -- there is no destination", st.Destination)
	}
	if st.Emitted != 0 || st.Written != 0 || st.DroppedFull != 0 || st.DroppedWrite != 0 ||
		st.DroppedOversize != 0 || st.DroppedClosing != 0 || st.Queued != 0 || st.Capacity != 0 {
		t.Errorf("Discard reports non-zero counters: %+v", st)
	}

	// Emit must be safe on the request path, including with a zero
	// record: the whole point of the value is that wiring it is never a
	// second thing to get right.
	telemetry.Discard.Emit(audit.Record{})
	telemetry.Discard.Emit(audit.Record{
		AnalystIdentity: "ana@example.org",
		Tool:            "threatintel.virustotal",
		TargetUpstream:  "threatintel",
		Timestamp:       time.Now(),
		Outcome:         audit.OutcomeAllowed,
	})

	if got := telemetry.Discard.Stats(); got.Emitted != 0 {
		t.Errorf("Emitted = %d after two Emits, want 0 -- Discard counts nothing, which is what "+
			"makes Configured the only field that means anything about it", got.Emitted)
	}
	if err := telemetry.Discard.Close(); err != nil {
		t.Errorf("Close = %v, want nil -- nothing was queued and nothing was lost", err)
	}

	// POSITIVE CONTROL: a real sink reports the other state, so the two
	// can never be read as the same thing. Without this half, a Sink
	// implementation that reported Configured == false unconditionally
	// would pass.
	live, err := gelf.New(gelf.Config{
		// Nothing listens here and nothing needs to: New does not touch
		// the network, which is the property this also exercises.
		Address:    "127.0.0.1:1",
		Transport:  gelf.TransportUDP,
		Host:       "mcp-gateway-01",
		ClienteSOC: "example-client",
		Buffer:     64,
	})
	if err != nil {
		t.Fatalf("gelf.New on a well-formed configuration: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })

	got := live.Stats()
	if !got.Configured {
		t.Error("a configured sink reports Configured == false")
	}
	if got.Destination == "" {
		t.Error("a configured sink reports an empty Destination")
	}
	if got.Capacity != 64 {
		t.Errorf("Capacity = %d, want 64", got.Capacity)
	}
}

// TestDiscardSatisfiesTheSamePortAsTheAdapter is the compile-time claim
// made explicit: "switched off" has a spelling, and it is a value of the
// same type as a working sink -- never a nil field somebody forgot.
func TestDiscardSatisfiesTheSamePortAsTheAdapter(t *testing.T) {
	var sinks []telemetry.Sink

	sinks = append(sinks, telemetry.Discard)

	live, err := gelf.New(gelf.Config{
		Address:    "127.0.0.1:1",
		Transport:  gelf.TransportTCP,
		Host:       "mcp-gateway-01",
		ClienteSOC: "example-client",
		Buffer:     64,
	})
	if err != nil {
		t.Fatalf("gelf.New: %v", err)
	}
	sinks = append(sinks, live)

	for _, s := range sinks {
		s.Emit(audit.Record{
			AnalystIdentity: "ana@example.org",
			Tool:            "threatintel.virustotal",
			TargetUpstream:  "threatintel",
			Timestamp:       time.Now(),
			Outcome:         audit.OutcomeAllowed,
		})
		_ = s.Stats()
		_ = s.Close()
		// Idempotent for both.
		_ = s.Close()
	}
}
