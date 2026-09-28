package main

import (
	"context"
	"log/slog"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/telemetry"
	"github.com/bunnyiesart/Gatte/internal/telemetry/gelf"
)

// newTelemetrySink builds the GELF copy of the Audit Trail, or
// telemetry.Discard when the file has no [telemetry] section
// (design/adr/0029-telemetria-gelf.md). The error is a LOCAL mistake only
// (an unreadable CA file, say): gelf.New does not touch the network, so a
// SIEM that is merely down is never a boot failure.
//
// The mapping from config.Telemetry to gelf.Config lives here, in the
// composition root, because gelf.Config belongs to an adapter and the
// config package converts only into domain types.
func newTelemetrySink(cfg *config.Config, logger *slog.Logger) (telemetry.Sink, error) {
	if !cfg.Telemetry.Enabled() {
		return telemetry.Discard, nil
	}
	return gelf.New(gelf.Config{
		Address:    cfg.Telemetry.Address,
		Transport:  gelf.Transport(cfg.Telemetry.Transport),
		TLS:        cfg.Telemetry.TLS,
		TLSCAFile:  cfg.Telemetry.TLSCAFile,
		Host:       cfg.Telemetry.Host,
		ClienteSOC: cfg.Telemetry.ClienteSOC,
		Buffer:     cfg.Telemetry.BufferSize(),
		Logger:     logger,
	})
}

// telemetryRecorder copies every record the trail ACCEPTED to the sink.
//
// It decorates the outermost recorder -- after SQLite and after the JSONL
// sink -- so the order is the one ADR-0029 requires: the source of truth is
// written first, and only a record it accepted is copied. A record the
// trail refused is not emitted, because a copy of something the trail does
// not hold would be the SIEM asserting a call the evidence does not. Emit
// never blocks and never fails the call (telemetry.Sink), so wrapping the
// recorder adds no way for a request to be refused.
//
// The gateway package does not know this exists; the internal line wired
// the sink as a gateway.Config field, and doing it here instead keeps one
// audit port in the domain.
type telemetryRecorder struct {
	audit.Recorder
	sink telemetry.Sink
}

func (r telemetryRecorder) Record(ctx context.Context, rec audit.Record) error {
	if err := r.Recorder.Record(ctx, rec); err != nil {
		return err
	}
	r.sink.Emit(rec)
	return nil
}

// logTelemetry says at every boot where the copy goes, or that it goes
// nowhere: an optional thing that is silently absent is an optional thing
// somebody will believe is present.
func logTelemetry(logger *slog.Logger, cfg *config.Config, st telemetry.Stats) {
	if st.Configured {
		logger.Info("mcp-gateway: telemetry",
			slog.String("destination", st.Destination),
			slog.String("host", cfg.Telemetry.Host),
			slog.String("cliente_soc", cfg.Telemetry.ClienteSOC),
			slog.Int("buffer", st.Capacity),
		)
		return
	}
	logger.Info("mcp-gateway: telemetry",
		slog.String("destination", "none"),
		slog.String("detail", "no [telemetry] section -- no audit event is sent over GELF; the SQLite trail is unaffected"),
	)
}
