// Package audit is the domain package for the Audit Trail component
// (design/02-components.md): one record per tool call -- analyst identity,
// tool, target upstream, timestamp. It defines the Record entity, its
// validation rules, and the Recorder port that any storage adapter must
// implement.
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter.
//
// Record's schema was who/what/where/when for Phase 1, with outcome
// deliberately deferred. That deferral ended in Phase 5: once the Gateway
// Endpoint could *refuse* a call, a trail that could not tell a refusal
// from a completion answered the wrong question, and CONCEPTS.md §2.5 is
// blunt that without outcome alongside the other four "the log is
// decoration, not evidence". Outcome and Reason are now required fields.
//
// SourceAddress arrived last, in GAB-24
// (design/adr/0012-audit-completeness.md), for the other half of the same
// argument: with who/what/where/when/outcome but no origin, a stolen
// token used from the attacker's machine writes a record identical to the
// legitimate analyst's, and the trail cannot answer the question an
// incident actually asks.
//
// Records are hash-chained (design/adr/0015-audit-tamper-evidence.md):
// each carries a hash over its own fields and its predecessor's, so a
// record edited or removed from the trail stops verifying -- as long as
// whoever changed it did not also recompute the hashes that follow.
//
// That qualifier is the whole of it, and this comment used to leave it
// out. The chain is an UNKEYED SHA-256, stored in prev_hash/hash columns
// of the very table it authenticates, computed by ChainHash, which is
// exported. So the actor ADR-0015 names -- whoever can write the database
// file -- edits a record, walks the remaining rows recomputing (prev,
// hash) forward, and VerifyChain reports Intact. The same goes for
// deleting a middle record, or inserting a fabricated one. A hash kept
// beside what it authenticates is not an anchor
// (design/adr/0010-signature-trust-anchor.md), and that applies here too.
// What the chain catches unaided is tampering that did NOT re-chain: a
// careless edit, a partial write, anything that could not or did not run
// this code.
//
// There is therefore no "middle covered, tail open" split, and this
// comment should not be read back into one. Truncating the END leaves a
// shorter chain that verifies; so does a re-chained edit anywhere. Every
// case collapses into the same single residue -- the HEAD changes -- so
// the head recorded somewhere this process cannot write is not an extra
// for the tail, it is the only detection there is against an attacker who
// re-chains; with no such anchor, all that is left is the careless case
// above. ChainVerifier reports the head so
// that comparison can be made outside this package (audit -verify
// -expect-head). Do not describe this trail as tamper-proof, and do not
// read an intact chain as "these records are what was written"; the
// difference matters to whoever reads it during an incident.
//
// The jsonl subpackage is what makes that external head reachable in this
// deployment (design/adr/0017-audit-jsonl-siem-sink.md): it emits each
// record's Prev and Hash to a local file a shipper forwards to Graylog,
// so the newest hash the SIEM holds is a head value the gateway cannot
// retroactively edit. That closes the gap only when the sink is actually
// wired and the shipper is actually running -- a gateway built without it
// has no anchor at all, which by the paragraph above means no detection at
// all against an attacker who re-chains. ChainedRecorder is the seam, not
// the guarantee.
//
// Still out of scope, and genuinely so: operational metrics and
// telemetry (AGENTS.md §2, "Telemetry/observability"). This is a record
// of what was attempted and what happened to it, not a monitoring
// system.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrInvalid is returned when a Record fails Validate.
var ErrInvalid = errors.New("audit: invalid record")

// Record is one entry in the audit trail: who called which tool, which
// upstream server served it, and when.
type Record struct {
	// AnalystIdentity identifies who made the call.
	AnalystIdentity string
	// Tool identifies which tool was invoked, e.g. "casemgmt.list_cases".
	Tool string
	// TargetUpstream identifies which backend server served the call,
	// e.g. "casemgmt".
	TargetUpstream string
	// Timestamp is when the call was made. Record does not decide how
	// "now" is obtained -- the caller supplies it, keeping this component
	// trivially testable without a Clock dependency.
	Timestamp time.Time
	// Outcome says whether the call was allowed, refused, or attempted
	// and failed. See the Outcome type.
	Outcome Outcome
	// Reason is an optional short, operator-facing classification of a
	// refusal or failure, e.g. "forbidden" or "quarantined".
	//
	// This deliberately holds the distinction the *caller* is not told.
	// The gateway returns an opaque error to a client so it cannot probe
	// which tools exist or which are currently under suspicion; the audit
	// trail is read by the operator, who needs exactly that distinction to
	// answer "why was this blocked". Free text, never parsed for a
	// decision -- it is evidence, not control flow.
	Reason string
	// SourceAddress is where the call came from, as the gateway's own
	// front door saw it (design/adr/0012-audit-completeness.md item 3).
	//
	// It exists because without it a stolen token used from an attacker's
	// machine produces a record byte for byte identical to the legitimate
	// analyst's, and "was that really Ana?" has to be answered by
	// correlating timestamps against the reverse proxy's log -- a second
	// source, kept by a different process, which is exactly the
	// arrangement that makes a trail hard to trust.
	//
	// # What it must and must not be
	//
	// This field is only worth having if it is not client-controlled. The
	// serving adapter is responsible for that, and internal/gateway/httpapi
	// documents how: the RIGHTMOST X-Forwarded-For entry -- the one the
	// co-located reverse proxy wrote from the TCP peer it actually saw --
	// never the leftmost, which the client sent and the proxy merely
	// preserved. A record holding the leftmost entry is a spoofable field
	// filed as evidence, which is worse than no field at all.
	//
	// # Why it is not required
	//
	// Unlike Outcome, an empty SourceAddress is honest rather than a lie.
	// A record written by a surface with no network peer has no address to
	// state, and a row that predates this column genuinely has none
	// (internal/audit/sqlite stores it with DEFAULT ''). Refusing such a
	// record would mean an unauditable -- and therefore refused -- call,
	// on account of a field that says nothing about the call itself. See
	// Validate.
	SourceAddress string
}

// Outcome is what happened to a call.
//
// This field exists because an audit trail that cannot distinguish a
// refused call from a completed one answers the wrong question. CONCEPTS.md
// §2.5 names outcome as one of five things a useful record needs -- who,
// what, when, target, outcome -- and is blunt that without them together
// "the log is decoration, not evidence". For a SOC, "was this blocked?" is
// the first question asked of the trail, and it was unanswerable until
// this field existed.
type Outcome string

const (
	// OutcomeAllowed means the call passed every gate and was forwarded to
	// its upstream.
	OutcomeAllowed Outcome = "allowed"
	// OutcomeDenied means the gateway refused the call: no such tool, not
	// approved by Tool Quarantine, or not permitted by the caller's role.
	// The specific reason belongs in Reason.
	OutcomeDenied Outcome = "denied"
	// OutcomeFailed means the call was allowed and forwarded, but the
	// upstream did not complete it. Distinct from OutcomeDenied because
	// "the gateway said no" and "the backend broke" are different
	// incidents with different responses.
	//
	// # A failed call costs TWO rows, and counting rows will mislead you
	//
	// The allowed record is written *before* the call leaves the process,
	// deliberately -- see gateway.Dispatch, which refuses any call it
	// cannot audit first, because the attempts most worth investigating
	// are the ones that never came back. So by the time the failure is
	// known, the allowed row is already on disk, and
	// design/adr/0012-audit-completeness.md decides to APPEND rather than
	// rewrite it: a record that can be edited after the fact is state, not
	// evidence, and the pair (allowed at T, failed at T+n) carries more
	// than the corrected row would -- it says the call really was
	// dispatched, and how long it ran before breaking.
	//
	// The price is that one failed call is two rows. Anyone counting rows
	// to answer "how many calls were there" will over-count by exactly the
	// number of failures. Count OutcomeAllowed rows for attempts and treat
	// an OutcomeFailed row as an annotation on the allowed one that
	// precedes it.
	OutcomeFailed Outcome = "failed"
)

// Valid reports whether o is one of the defined outcomes.
func (o Outcome) Valid() bool {
	switch o {
	case OutcomeAllowed, OutcomeDenied, OutcomeFailed:
		return true
	}
	return false
}

// Validate checks that r satisfies the audit trail's entry contract:
//
//   - AnalystIdentity must be non-empty.
//   - Tool must be non-empty.
//   - TargetUpstream must be non-empty.
//   - Timestamp must not be the zero value (time.Time{}).
//
// SourceAddress is deliberately not on that list; see the field.
//
// Validate returns ErrInvalid, wrapped with a description of every rule
// that failed (not just the first one encountered), on any violation; it
// returns nil when r is well-formed.
func (r Record) Validate() error {
	var errs []error

	if r.AnalystIdentity == "" {
		errs = append(errs, errors.New("analyst identity must not be empty"))
	}
	if r.Tool == "" {
		errs = append(errs, errors.New("tool must not be empty"))
	}
	if r.TargetUpstream == "" {
		errs = append(errs, errors.New("target upstream must not be empty"))
	}
	if r.Timestamp.IsZero() {
		errs = append(errs, errors.New("timestamp must not be the zero value"))
	}
	// Required, with no default. A zero-value Outcome would silently
	// record every call as the same thing, which is the failure this
	// field was added to prevent -- so an unset Outcome is a rejected
	// record, not an "unknown" one.
	if !r.Outcome.Valid() {
		errs = append(errs, fmt.Errorf("outcome %q is not one of %q, %q, %q",
			r.Outcome, OutcomeAllowed, OutcomeDenied, OutcomeFailed))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalid}, errs...)...)
}

// Recorder is the port through which the domain durably stores and
// retrieves Records. Implementations are adapters (e.g. the sqlite
// subpackage) and must honor the contracts documented on each method.
type Recorder interface {
	// Record durably stores r. It returns ErrInvalid if r.Validate()
	// fails, and nothing is written in that case. There is no return
	// value beyond error on success -- this port only ever appends, so
	// there is no ID to hand back in this phase. ("Only ever appends"
	// says what implementations do; it is not a constraint the storage
	// enforces on anyone else holding the file. See the package doc.)
	Record(ctx context.Context, r Record) error

	// List returns every recorded Record in chronological order by
	// Timestamp, oldest first. This ordering is guaranteed: the Operator
	// Console reads this trail and relies on it. When nothing has been
	// recorded yet, List returns an empty, non-nil slice and a nil
	// error -- an empty audit trail is not an error condition.
	List(ctx context.Context) ([]Record, error)
}

// chainTag is a domain-separation prefix, length-prefixed like every other
// field, so canonical bytes produced here can never be mistaken for -- or
// replayed into -- another context that happens to use the same TLV shape.
// The signer package carries its own tag for the same reason.
const chainTag = "mcp-gateway/audit/chain/v1"

// GenesisHash is the previous-hash value the first record in a chain links
// from. It is the empty string rather than a hash of nothing, so "this
// record starts the chain" is distinguishable from "this record links to
// something whose hash happened to be all zeroes".
const GenesisHash = ""

// Canonical returns the bytes a record's chain hash is computed over
// (design/adr/0015-audit-tamper-evidence.md, item 1).
//
// # Why the encoding is length-prefixed
//
// Every string is written as an 8-byte big-endian length followed by its
// raw bytes. Naive concatenation would make Tool "ab" + Reason "c" and
// Tool "a" + Reason "bc" hash identically, so a record could be rewritten
// into a different one that chains just as well -- which is the whole
// property this is here to provide. With lengths in front, no byte string
// spans a field boundary and no boundary is ambiguous.
//
// The timestamp is encoded as RFC3339 with nanoseconds, matching how the
// sqlite adapter stores it, so a record hashes the same before it is
// written and after it is read back.
func Canonical(r Record) []byte {
	var buf []byte
	buf = appendField(buf, chainTag)
	buf = appendField(buf, r.AnalystIdentity)
	buf = appendField(buf, r.Tool)
	buf = appendField(buf, r.TargetUpstream)
	buf = appendField(buf, r.Timestamp.Format(time.RFC3339Nano))
	buf = appendField(buf, string(r.Outcome))
	buf = appendField(buf, r.Reason)
	buf = appendField(buf, r.SourceAddress)
	return buf
}

// ChainHash returns the hex-encoded SHA-256 over r's canonical bytes
// followed by prev, the hash of the record before it. prev is
// GenesisHash for the first record in a chain.
//
// It is unkeyed, and exported, so anyone holding a record can recompute
// its hash -- the storage adapter, the backfill, a verifier, and equally
// an attacker rewriting the table. That is a stated property of the
// design, not an oversight (ADR-0015 and its 11 Sep 2026 correction): a
// key the gateway must hold to write records is a key an attacker who can
// write those records can generally read, so the chain buys linkage and
// the external head anchor buys the detection. Read the package doc
// before writing anything that treats an intact chain as authentication.
//
// prev is length-prefixed too: without that, a short prev followed by a
// long one could be confused for the reverse, which would defeat the
// point of prefixing the fields.
func ChainHash(prev string, r Record) string {
	buf := Canonical(r)
	buf = appendField(buf, prev)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// appendField appends the 8-byte big-endian length of v followed by v.
func appendField(buf []byte, v string) []byte {
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(v)))
	return append(buf, v...)
}

// ChainBreak describes the first place a chain stops verifying.
type ChainBreak struct {
	// Position is the 1-based position of the offending record in
	// insertion order.
	Position int
	// Record is the record as it currently reads on disk.
	Record Record
	// Want is the hash the record should carry, recomputed from its own
	// fields and its predecessor's hash.
	Want string
	// Got is the hash stored alongside it.
	Got string
}

// ChainCheck is the result of verifying the audit chain.
type ChainCheck struct {
	// Count is how many records were examined.
	Count int
	// Head is the hash of the last record, or GenesisHash when the trail
	// is empty. This is the value worth recording somewhere the gateway
	// cannot reach -- and the only one: every form of tampering changes
	// it, and nothing else reliably shows any of them. See FirstBreak.
	Head string
	// FirstBreak is nil when every record verifies.
	//
	// A nil FirstBreak means no record was edited or removed WITHOUT the
	// hashes after it being recomputed. It does not mean the trail is
	// unaltered: the chain is unkeyed and stored beside the records it
	// authenticates, so an edit, a deletion or an insertion followed by a
	// forward re-chain verifies cleanly, and so does truncation of the end
	// (ADR-0015 item 6 and its 11 Sep 2026 correction). Detecting any of
	// those needs Head to have been recorded externally beforehand.
	FirstBreak *ChainBreak
	// RetroactivelyChained is how many of the leading records were
	// hashed during migration rather than when they were written
	// (ADR-0015 item 4). Those records verify against each other, which
	// says nothing about whether they were already altered before the
	// migration ran. Zero for a trail that has only ever been chained.
	RetroactivelyChained int
}

// Intact reports whether every record verified. See ChainCheck.FirstBreak
// for what this does not cover.
func (c ChainCheck) Intact() bool { return c.FirstBreak == nil }

// ChainLink is where one stored record sits in the hash chain: the hash of
// the record before it, and its own.
//
// Both are hex, and Prev is GenesisHash for the first record in a chain.
// The pair is what an external anchor is built out of
// (design/adr/0017-audit-jsonl-siem-sink.md): Hash of the newest record
// held somewhere the gateway cannot write is the value ChainCheck.Head is
// compared against, which is the only way tail truncation -- or any other
// rewrite the attacker re-chained after, see this package's doc -- becomes
// visible.
type ChainLink struct {
	// Prev is the hash of the preceding record, or GenesisHash.
	Prev string
	// Hash is this record's own hash, as stored.
	Hash string
}

// ChainedRecorder is a Recorder that can also say where the record it just
// wrote landed in the chain.
//
// # Why this is a second port instead of a wider Recorder
//
// Recorder.Record returns only an error, and that is right for its one
// caller that matters: gateway.Dispatch refuses a call it cannot audit,
// and it needs to know whether the write happened, not what it hashed to.
// Widening Recorder would push a return value nobody reads onto every
// implementation and every call site.
//
// The hash is nevertheless needed by exactly one consumer -- the JSONL
// sink that ships each record to the SIEM, where prev/hash are the whole
// point of the line -- and it is computed inside the storage adapter,
// where the chain head is read under the same transaction as the insert
// (ADR-0015 item 3). It cannot be recomputed outside without re-reading
// the head, which would race.
//
// So: a narrow second interface, embedding Recorder, implemented by the
// sqlite adapter and by the JSONL decorator that wraps it. Anything that
// only stores records keeps implementing Recorder alone.
type ChainedRecorder interface {
	Recorder

	// RecordChained durably stores r and returns the link it was written
	// at. It returns ErrInvalid if r.Validate() fails, and nothing is
	// written in that case.
	//
	// On any error the returned ChainLink is the zero value and must not
	// be read: a zero Prev is indistinguishable from GenesisHash, so a
	// caller that ignores the error would treat a failed write as the
	// first record of a chain.
	RecordChained(ctx context.Context, r Record) (ChainLink, error)
}

// ChainVerifier is the port for checking a stored trail's internal
// consistency, and for reading the head that an external anchor is
// compared against. It is separate from Recorder because verifying is an
// operator action against a storage adapter, not something the gateway's
// hot path needs; an adapter may implement one without the other.
//
// "Has this trail been edited" is a question it can only half answer; see
// ChainCheck.FirstBreak and this package's doc before wording a report
// around it.
type ChainVerifier interface {
	// VerifyChain walks the trail in insertion order, recomputing each
	// record's hash from its own fields and its predecessor's, and
	// reports the first mismatch.
	VerifyChain(ctx context.Context) (ChainCheck, error)
}
