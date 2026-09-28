// Package telemetry is the domain package for the additional audit sink
// (design/adr/0029-telemetria-gelf.md): one event per record the Audit
// Trail accepted, shipped out of the process so the SOC analyst with
// Graylog open sees what the trail already knows.
//
// It exists because design/adr/0012-audit-completeness.md closed the
// substance of the record and nothing else: every event lives in a SQLite
// file on one host, readable by whoever has a shell on the gateway host and runs
// `mcp-gateway audit`. OWASP MCP08 is not about having the data, it is
// about the data arriving where the SOC looks.
//
// # This is a copy, never the evidence
//
// The trail remains the source of truth. Losing an event here loses a
// COPY, and that single property is what authorizes every cheap choice in
// the port below: a bounded queue, no disk spool, no retry, and a drop
// that is counted rather than waited on. Recovery is manual and is named
// in the log line that admits the loss: `mcp-gateway audit --since`.
//
// Per the ports & adapters split this project follows, this package
// contains no wire format, no socket and no encoding. The gelf subpackage
// is the adapter. It does import internal/audit, which is domain
// importing domain and deliberate -- see Sink.Emit.
package telemetry

import (
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// Sink receives one event per record the Audit Trail ACCEPTED. It is an
// additional sink: the SQLite trail is still the source of truth
// (design/adr/0012-audit-completeness.md), and losing an event here loses
// a copy, never the evidence.
type Sink interface {
	// Emit hands r off for sending and RETURNS IMMEDIATELY.
	//
	// It takes no ctx and returns no error, and both absences are the
	// contract: no condition -- destination down, DNS failing, socket
	// full, queue full -- may delay or alter the request path. An event
	// that does not fit is DROPPED and COUNTED, never waited for. Safe
	// for concurrent use.
	//
	// The parameter is audit.Record and not a telemetry-owned event type,
	// and that is the control rather than a convenience. With its own
	// type, someone adds latency, args or result_size to it without
	// touching the trail, and the gateway starts emitting out of the
	// process a datum the source of truth does not have -- in the case of
	// args, a client-controlled datum that in practice may hold a
	// credential an analyst pasted. With audit.Record in the signature,
	// widening what can leave requires changing the trail first.
	Emit(r audit.Record)

	// Stats is the answer to "telemetry stopped, and how many events were
	// lost". Always coherent, never blocks.
	Stats() Stats

	// Close drains what fits in its own short budget and reports what it
	// discarded. Idempotent.
	Close() error
}

// Stats is a coherent snapshot of what a Sink has done and is doing.
//
// The counters satisfy one accounting invariant, which is a test
// assertion and not prose:
//
//	Emitted == Written + DroppedFull + DroppedWrite + DroppedOversize + DroppedClosing + Queued
//
// (after Close, Queued == 0). It is what makes "how many events did we
// lose" answerable with a number instead of a shrug, and it is why every
// drop has its own bucket: a total without attribution tells an operator
// that something is wrong and nothing about what.
type Stats struct {
	// Configured is false when no destination was written in the file.
	// "Nobody configured this" and "this is configured and nothing
	// happened" are not the same fact, and reporting zero sent for both
	// would collapse them.
	Configured bool
	// Destination is the human-readable target, e.g.
	// "udp 192.0.2.11:12201". Host and port only -- this component never
	// holds a credential, and nothing here may become the first place one
	// is printed.
	Destination string
	// Healthy is false once a delivery attempt has failed and until one
	// succeeds again. A sink that has just been built is healthy because
	// nothing has gone wrong yet, not because something has gone right --
	// Written is the field that says anything arrived.
	Healthy bool
	// Queued is how many events are waiting in the queue right now.
	Queued int
	// Capacity is the queue's size, so Queued reads as a fraction
	// without a second lookup.
	Capacity int

	// Emitted counts every record handed to Emit.
	Emitted uint64
	// Written counts messages the socket accepted. It is deliberately
	// NOT called Delivered: under UDP it means the datagram left the
	// socket and says nothing about arrival; under TCP it means the
	// bytes were accepted by the connection and still does not say
	// Graylog indexed them. Calling it "delivered" would make an
	// operator trust a number that does not exist.
	Written uint64
	// DroppedFull counts events refused because the queue was full.
	DroppedFull uint64
	// DroppedWrite counts events lost because dialing or writing failed
	// (or, rarely, because the record could not be encoded at all --
	// same observable outcome: it never reached the socket).
	DroppedWrite uint64
	// DroppedOversize counts events above MaxMessageBytes, which are
	// dropped whole rather than truncated: cut JSON is invalid JSON, and
	// evidence that does not parse is worse than evidence that is absent.
	DroppedOversize uint64
	// DroppedClosing counts events that did not fit in Close's budget.
	DroppedClosing uint64

	// ConsecutiveFailures is how many delivery attempts have failed in a
	// row; zero once one succeeds.
	ConsecutiveFailures uint64
	// LastError is the text of the last network error, truncated. Never
	// a credential -- none reaches this component.
	LastError string
	// LastErrorAt is when LastError happened.
	LastErrorAt time.Time
	// LastWriteAt is when the socket last accepted a message.
	LastWriteAt time.Time
	// GapStart is the beginning of the current gap, and zero while
	// healthy. It is the argument to `mcp-gateway audit --since`, which
	// is this design's entire recovery plan.
	GapStart time.Time
}

// Discard is the Sink of a gateway with no destination written in the
// file. It counts nothing, sends nothing, and says out loud that it is
// not configured (Stats().Configured == false) instead of reporting zero
// sent, because "nobody configured this" and "this is configured and
// nothing happened" are not the same fact.
//
// It is a value and not an exported struct type so that it cannot be
// constructed with fields, and so that the wiring site reads as a
// destination rather than as a placeholder somebody forgot to replace.
var Discard Sink = discard{}

// discard is the no-op Sink behind Discard.
type discard struct{}

func (discard) Emit(audit.Record) {}

// Stats reports Configured false and nothing else. Every counter stays
// zero because none of them ever happened -- which is exactly the
// distinction Configured exists to preserve.
func (discard) Stats() Stats { return Stats{} }

// Close is nil because there is nothing to drain and nothing was lost.
func (discard) Close() error { return nil }
