package gelf

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// gelfVersion is the only value GELF 1.1 accepts in the `version` field.
const gelfVersion = "1.1"

const (
	// eventKindAudit marks a message that mirrors one audit record.
	eventKindAudit = "audit"
	// eventKindGap marks the one message this sink authors itself. It
	// exists so a reader can tell "the gateway said something happened"
	// from "the gateway said it lost track", which is the difference
	// between evidence and an apology.
	eventKindGap = "telemetry_gap"
)

// MaxMessageBytes is the hard ceiling on one encoded message, applied to
// BOTH transports.
//
// 8192 is the Graylog GELF UDP input's default chunk size, so below it a
// plain datagram is always accepted without chunking. It is applied to
// TCP as well -- where no such limit exists -- so that switching
// transports never changes what arrives; a ceiling that moves with the
// transport is a ceiling nobody can reason about at 03:00.
//
// Above it a message is DROPPED and counted, never truncated (cut JSON is
// invalid JSON, and evidence that does not parse is worse than absent)
// and never fragmented (chunking is a reassembly protocol with failure
// modes of its own, for a message that should never have been this big).
const MaxMessageBytes = 8192

// maxErrorBytes caps the network error text kept in Stats.LastError. TLS
// errors in particular are verbose enough to turn one log line into a
// paragraph, and the operator needs the class of failure, not the essay.
const maxErrorBytes = 256

// errOversize is returned by encode when a message exceeds
// MaxMessageBytes. It is a distinct error because the writer loop has a
// distinct counter for it: "too big to send" and "the socket refused it"
// are different problems with different fixes.
var errOversize = errors.New("gelf: message exceeds MaxMessageBytes")

// levelForOutcome maps an outcome to a GELF (syslog) severity. It is a
// CLOSED map with exactly three entries, and encode fails on a miss
// rather than falling back.
//
// The mapping is 6/5/4 and not 6/4/3 on purpose. A denied call is the
// gateway WORKING -- it is the control doing the thing it exists to do --
// and mapping it to Error would say the opposite. Keeping Error (3)
// unused by this component means an Error in this stream is never normal
// behaviour of this gateway, which is a property worth more than a finer
// gradation.
//
// The field the SOC alerts on is _outcome, not this: _outcome is a closed
// set that does not change meaning the day a new outcome appears, while
// severity is one person's opinion about how loud to be.
var levelForOutcome = map[audit.Outcome]int{
	audit.OutcomeAllowed: 6, // Informational
	audit.OutcomeDenied:  5, // Notice
	audit.OutcomeFailed:  4, // Warning
}

// gapLevel is the severity of the synthetic gap message: Warning, the
// same as a failed call, because a hole in the stream deserves at least
// as much attention as one broken call.
const gapLevel = 4

// encoder turns audit records into GELF 1.1 messages. It holds the two
// static fields, which are the only values in a message that do not come
// from the record.
type encoder struct {
	host       string
	clienteSOC string
}

// encode renders r as one GELF 1.1 JSON message, with no compression and
// no framing byte (the transport adds framing, because only it knows
// which one).
//
// The key set is closed and small on purpose, and each omission is an
// argument made elsewhere: no full_message, because there is no second
// body to put there that is not backend-authored text; no _id, because
// GELF 1.1 reserves the key and Graylog DROPS the whole message that
// carries one; no latency, no correlation id, no args and no result --
// none of them exists in audit.Record, and that is the point of taking
// audit.Record as the parameter.
//
// On failure it returns nil bytes, never a partial buffer: a caller that
// writes what it got on error would put invalid JSON on the wire.
func (e encoder) encode(r audit.Record) ([]byte, error) {
	level, ok := levelForOutcome[r.Outcome]
	if !ok {
		// Unreachable through the gateway, which only emits records the
		// trail validated. Refusing here rather than defaulting is what
		// keeps the map closed: a silent default would map a future
		// outcome to Warning and nobody would ever learn it existed.
		return nil, fmt.Errorf("gelf: outcome %q has no level", r.Outcome)
	}

	m := map[string]any{
		"version": gelfVersion,
		"host":    e.host,
		// Composed only of the closed outcome vocabulary and the tool
		// name the gateway itself routed. Never third-party text.
		"short_message": "mcp-gateway " + string(r.Outcome) + " " + r.Tool,
		"level":         level,
		"timestamp":     epochSeconds(r.Timestamp),

		"_event_kind":  eventKindAudit,
		"_cliente_soc": e.clienteSOC,
		// Named identically to the CLI's auditJSON keys
		// (cmd/mcp-gateway/audit.go). Not aesthetics: at 03:00 the
		// operator writes a Graylog query and then runs the CLI on the
		// host, and translating field names between the two is where the
		// mistake happens. The trail's external vocabulary was published
		// once; this does not invent a second one.
		"_analyst_identity": r.AnalystIdentity,
		"_tool":             r.Tool,
		"_target_upstream":  r.TargetUpstream,
		"_outcome":          string(r.Outcome),
	}
	// Omitted when empty, never sent as "". An empty SourceAddress is
	// valid and honest -- a surface with no network peer, or a row that
	// predates the column -- and sending "" would put "there was no
	// address" and "the address was empty" in the same bucket of an
	// aggregation. Mirrors the CLI's omitempty.
	if r.Reason != "" {
		m["_reason"] = r.Reason
	}
	if r.SourceAddress != "" {
		// Passed through byte for byte, never re-parsed. The leftmost
		// X-Forwarded-For entry is client-controlled (nginx appends with
		// $proxy_add_x_forwarded_for), internal/gateway/httpapi already
		// resolved that question by taking the rightmost, and a second
		// opinion on the same question is how the wrong one gets shipped.
		m["_source_address"] = r.SourceAddress
	}

	return marshalCapped(m)
}

// gap is what the writer loop knows about an outage once it ends.
type gap struct {
	start           time.Time
	end             time.Time
	droppedFull     uint64
	droppedWrite    uint64
	droppedOversize uint64
}

// total is how many audit events the gap swallowed.
func (g gap) total() uint64 {
	return g.droppedFull + g.droppedWrite + g.droppedOversize
}

// recoverWith is the command that recovers the gap from the source of
// truth, composed of nothing but a timestamp. It is the reason this
// design does not need a disk spool, and it travels inside the message
// and inside every log line about the gap, so that the admission of loss
// and the instruction to recover are never two lookups apart.
func (g gap) recoverWith() string {
	return "mcp-gateway audit --since " + g.start.UTC().Format(time.RFC3339)
}

// gapMessage renders the one message this sink authors: the first thing
// written on a recovered connection, and only when something was
// actually lost.
//
// Without it an outage appears in Graylog as a silent hole,
// indistinguishable from a quiet period, and whoever looks afterwards
// concludes everything was fine. It is the only channel that speaks to
// someone who only ever looks at the SIEM.
func (e encoder) gapMessage(g gap) ([]byte, error) {
	m := map[string]any{
		"version":       gelfVersion,
		"host":          e.host,
		"short_message": fmt.Sprintf("mcp-gateway telemetry gap: %d audit events were not sent", g.total()),
		"level":         gapLevel,
		"timestamp":     epochSeconds(g.end),

		"_event_kind":       eventKindGap,
		"_cliente_soc":      e.clienteSOC,
		"_dropped":          g.total(),
		"_dropped_full":     g.droppedFull,
		"_dropped_write":    g.droppedWrite,
		"_dropped_oversize": g.droppedOversize,
		"_gap_start":        g.start.UTC().Format(time.RFC3339),
		"_gap_end":          g.end.UTC().Format(time.RFC3339),
		"_recover_with":     g.recoverWith(),
	}
	return marshalCapped(m)
}

// marshalCapped is the single place a GELF message becomes bytes, so the
// ceiling cannot be enforced on one message kind and forgotten on the
// other.
func marshalCapped(m map[string]any) ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("gelf: encoding message: %w", err)
	}
	if len(b) > MaxMessageBytes {
		return nil, fmt.Errorf("%w: %d bytes", errOversize, len(b))
	}
	return b, nil
}

// epochSeconds renders t the way GELF 1.1 wants a timestamp: seconds
// since the epoch with a fraction.
//
// t is Record.Timestamp -- the gateway's injected clock at the instant of
// the event, the same instant the SQLite row carries -- and never the
// moment the goroutine managed to send. That is what keeps a delay or a
// reconnection from reordering the stream in Graylog.
//
// The admitted cost: float64 holds about six decimal places at present-day
// epoch values, i.e. microseconds, while the trail stores RFC3339Nano. To
// order two events inside the same microsecond the answer is the trail --
// the source of truth, again.
//
// UTC() changes nothing about the value (an instant has no offset); it is
// written so a reader does not have to stop and work that out.
func epochSeconds(t time.Time) float64 {
	return float64(t.UTC().UnixNano()) / 1e9
}

// truncate caps operator-facing error text at n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
