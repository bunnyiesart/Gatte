package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/telemetry"
)

type fakeRecorder struct {
	err error
	got []audit.Record
}

func (f *fakeRecorder) Record(_ context.Context, r audit.Record) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, r)
	return nil
}
func (f *fakeRecorder) List(context.Context) ([]audit.Record, error) { return f.got, nil }

type fakeSink struct {
	mu  sync.Mutex
	got []audit.Record
}

func (s *fakeSink) Emit(r audit.Record)    { s.mu.Lock(); s.got = append(s.got, r); s.mu.Unlock() }
func (s *fakeSink) Stats() telemetry.Stats { return telemetry.Stats{} }
func (s *fakeSink) Close() error           { return nil }

// Only a record the trail accepted is copied: a copy of something the
// trail does not hold would have the SIEM asserting a call the evidence
// does not.
func TestTelemetryRecorder_CopiesOnlyWhatTheTrailAccepted(t *testing.T) {
	sink := &fakeSink{}
	ok := &fakeRecorder{}
	if err := (telemetryRecorder{Recorder: ok, sink: sink}).Record(context.Background(), wiringRecord("casemgmt.list_cases")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(sink.got) != 1 || len(ok.got) != 1 {
		t.Fatalf("accepted record: trail %d, sink %d; want 1 and 1", len(ok.got), len(sink.got))
	}

	refused := &fakeRecorder{err: errors.New("disk full")}
	err := (telemetryRecorder{Recorder: refused, sink: sink}).Record(context.Background(), wiringRecord("casemgmt.get_case"))
	if err == nil || err.Error() != "disk full" {
		t.Fatalf("Record over a refusing trail = %v, want the trail's own error", err)
	}
	if len(sink.got) != 1 {
		t.Fatalf("a record the trail refused reached the sink (%d emitted)", len(sink.got))
	}
}

// End to end through the real GELF adapter: [telemetry] over UDP to a local
// listener, one accepted record, one datagram carrying the tool name.
func TestTelemetryRecorder_ShipsGELFOverUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	cfg := &config.Config{Telemetry: config.Telemetry{
		Address: pc.LocalAddr().String(), Transport: "udp",
		Host: "gatte-test", ClienteSOC: "example-client",
	}}
	sink, err := newTelemetrySink(cfg, discardLogger())
	if err != nil {
		t.Fatalf("newTelemetrySink: %v", err)
	}
	defer sink.Close()
	if st := sink.Stats(); !st.Configured {
		t.Fatalf("Stats().Configured = false with an address written")
	}

	rec := telemetryRecorder{Recorder: &fakeRecorder{}, sink: sink}
	if err := rec.Record(context.Background(), wiringRecord("casemgmt.list_cases")); err != nil {
		t.Fatalf("Record: %v", err)
	}

	buf := make([]byte, 65536)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no GELF datagram arrived: %v", err)
	}
	msg := string(buf[:n])
	for _, want := range []string{"casemgmt.list_cases", "example-client", "gatte-test"} {
		if !strings.Contains(msg, want) {
			t.Errorf("datagram %q does not carry %q", msg, want)
		}
	}
}

func TestNewTelemetrySink_NoSectionIsDiscard(t *testing.T) {
	sink, err := newTelemetrySink(&config.Config{}, discardLogger())
	if err != nil || sink.Stats().Configured {
		t.Fatalf("no [telemetry]: sink configured=%v err=%v, want the discard sink", sink.Stats().Configured, err)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
