// Package jsonl is the SIEM-facing adapter for the Audit Trail: one JSON
// object per line, appended to a local file, for a shipper to forward to
// Graylog (design/adr/0017-audit-jsonl-siem-sink.md).
//
// # It is a second sink, not a second stream
//
// [Recorder] decorates an [audit.ChainedRecorder] -- in practice the
// sqlite adapter. Every write goes to SQLite FIRST and is emitted only
// after that write committed. There is one audit.Record and one
// serialization of it, so the SIEM and the local trail cannot disagree
// about what a record SAYS; the only thing that can differ is whether a
// record is present at both ends, and the ordering makes that
// one-directional. Nothing reaches the SIEM that is not already durable
// locally. A line in Graylog with no row in SQLite is therefore evidence
// of the row having been removed, which is precisely the property this
// exists for.
//
// # The log sink does NOT extend the dispatch-refusal rule
//
// gateway.Dispatch refuses any call it cannot audit first, because an
// unrecorded call is the one worth investigating. That rule covers the
// DURABLE write and stops there. A sink failure -- a full disk, a
// permission change, a rotated file -- is reported loudly through slog and
// then swallowed: [Recorder.Record] returns nil, the call proceeds, the
// analyst is served.
//
// Extending the refusal to this sink would convert an availability fault
// into a denial: a SOC that cannot query its case-management backend
// because a log file is unwritable is a SOC this gateway broke. That is
// also why the sink is a LOCAL FILE and never a network client. Shipping
// is a separate process's problem, on purpose -- the gateway must not have
// a remote dependency in its request path at all, not even a swallowed
// one, because a hung TCP connect is a latency fault that no amount of
// error-swallowing hides.
//
// # What a line is for, and what it is not
//
// The line carries prev_hash and hash. That is the external anchor
// ADR-0015 item 6 left open: with the newest hash readable from a SIEM the
// gateway cannot write to, a local trail that was truncated -- or edited
// and re-chained, which the chain alone cannot tell from an honest one
// (internal/audit's package doc) -- shows up as `mcp-gateway audit
// -verify` reporting a head that is not the head Graylog last saw, and
// `-expect-head` can take its expected value from a SIEM query instead of
// from an operator's notebook. It is the detection, not a supplement to
// one.
//
// A line is NOT self-verifying, and this must not be overstated. `ts` is
// the record's timestamp normalized to UTC for the SIEM's benefit, while
// the chain hashes the timestamp in whatever offset the gateway's clock
// produced; when that clock yields UTC the two renderings are identical
// and when it does not they are the same instant written differently. So
// a reader can compare hashes across the two stores, and can walk
// prev/hash links within the SIEM's own copy, but recomputing a hash from
// a line alone is not a supported operation. Verification of the record
// content against its hash happens where the record is stored.
//
// # Counting lines over-counts calls
//
// verdict has three values, and a failed call emits TWO lines -- `allowed`
// when the call was dispatched and `failed` when it did not come back
// (design/adr/0012-audit-completeness.md). Count `allowed` lines for
// attempts and read a `failed` line as an annotation on the one before it.
// A Graylog dashboard counting all lines over-reports by exactly the
// number of failures.
//
// # What can never appear in a line
//
// Not the bearer token, whole or truncated. Not a vault-resolved
// credential. Not tool arguments or results -- those carry indicators and
// PII and are the reason this gateway exists rather than four laptops with
// their own copies of production keys. Not upstream error text, which is
// backend-controlled. Not IdP group claims.
//
// This is enforced structurally rather than by review. [Line] has a fixed
// set of typed string and int fields, [Recorder.line] is its only
// constructor, and that constructor's inputs are an audit.Record and an
// audit.ChainLink -- no map, no any, no error parameter, no variadic
// escape hatch. audit.Record itself holds none of the forbidden values
// (access.Identity carries no token by construction, and a reflection test
// in internal/access fails the build if one is added). Leaking any of them
// through this package therefore requires editing Line, which is a compile
// error away from every existing call site and a diff nobody can miss.
package jsonl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// Version is the schema version stamped into every line's `v` field.
//
// It exists so a Graylog extractor can refuse a shape it does not know
// rather than silently mis-parsing it. Adding a field is a version bump;
// so is removing or renaming one. The field set is asserted exactly in
// this package's tests, so a new field cannot arrive without the test that
// pins the schema being updated in the same change -- which is where
// somebody has to think about whether the new field is one of the things
// the package doc says can never appear.
const Version = 1

// Line is one record as the SIEM receives it.
//
// Every field is always present -- no omitempty anywhere. An absent key
// and an empty value are different things to a log pipeline, and "this
// call had no rule" should not be indistinguishable from "this gateway
// version did not emit rule at all". A fixed key set is also what makes
// the structural test in this package a real check rather than a
// spot-check.
//
// The field set is closed by design; see the package doc for what must
// never join it and why adding anything is a compile-scale change rather
// than a review-scale one.
type Line struct {
	// Version is the schema version, so a consumer can fail loudly on a
	// shape it does not know.
	Version int `json:"v"`
	// Time is the record's timestamp, RFC3339 with nanoseconds, normalized
	// to UTC. See the package doc: this is NOT necessarily byte-identical
	// to the encoding the chain hashed.
	Time string `json:"ts"`
	// Chain names which gateway's chain this line belongs to. Hashes from
	// two gateways shipping into one Graylog stream are otherwise
	// interleaved with no way to tell which trail a head belongs to, and
	// `-expect-head` against the wrong chain's head is a false alarm during
	// an incident.
	Chain string `json:"chain"`
	// Caller is audit.Record.AnalystIdentity: the IdP's stable subject, or
	// the gateway's own marker for a request that never authenticated.
	// Never a display name, never a token.
	Caller string `json:"caller"`
	// Backend is audit.Record.TargetUpstream.
	Backend string `json:"backend"`
	// Tool is the namespaced tool name.
	Tool string `json:"tool"`
	// Verdict is audit.Record.Outcome: allowed, denied or failed. Three
	// values, and a failed call produces two lines -- see the package doc
	// before counting anything.
	Verdict string `json:"verdict"`
	// Rule is audit.Record.Reason: the operator-facing classification of a
	// refusal or failure, drawn from the gateway's own closed set. It is
	// never upstream text and never an error message.
	Rule string `json:"rule"`
	// Src is audit.Record.SourceAddress as the serving adapter resolved it
	// -- for HTTP, the rightmost X-Forwarded-For entry. Empty when the
	// surface had no network peer.
	Src string `json:"src"`
	// PrevHash is the hash of the preceding record in the chain, or empty
	// for the first.
	PrevHash string `json:"prev_hash"`
	// Hash is this record's own chain hash. This field and PrevHash are
	// why the line exists.
	Hash string `json:"hash"`
}

// Sink is where a Line goes.
//
// It takes a Line, not bytes and not a map, so the typed shape survives
// all the way to the writer and no implementation can decide to enrich a
// line on its way out.
type Sink interface {
	// Emit writes one line. An implementation must make the write atomic
	// with respect to other concurrent Emits: a half-written line is worse
	// than a missing one, because a log pipeline will happily index the
	// half.
	Emit(ctx context.Context, line Line) error
}

// FileSink appends lines to a local file.
//
// Local is the whole point (see the package doc): the gateway's request
// path gets no network dependency, and a shipper -- filebeat, vector,
// whatever the deployment already runs -- reads this file and forwards it.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

var _ Sink = (*FileSink)(nil)

// DefaultFileMode is the mode a newly created sink file gets: readable and
// writable by the gateway's own user and nobody else. The audit trail
// names which analyst called which tool on which case, which is not
// world-readable material even though it holds no credentials.
const DefaultFileMode os.FileMode = 0o600

// OpenFile opens (or creates) path for appending.
//
// O_APPEND is not an optimization: it is what lets a shipper, a log
// rotator and this process coexist without a lock file, since every write
// lands at the current end of the file as seen by the kernel rather than
// at an offset this process remembers.
func OpenFile(path string) (*FileSink, error) {
	if path == "" {
		return nil, errors.New("audit/jsonl: sink path must not be empty")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, DefaultFileMode)
	if err != nil {
		return nil, fmt.Errorf("audit/jsonl: open sink: %w", err)
	}
	return &FileSink{f: f}, nil
}

// Emit implements Sink.
//
// The line is marshalled, the newline appended, and the whole thing handed
// to a SINGLE Write under the mutex. Two writes -- one for the JSON, one
// for the newline -- would let a concurrent Emit interleave between them
// and produce two corrupt lines out of two good ones.
func (s *FileSink) Emit(_ context.Context, line Line) error {
	buf, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("audit/jsonl: marshal line: %w", err)
	}
	buf = append(buf, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errors.New("audit/jsonl: sink is closed")
	}
	if _, err := s.f.Write(buf); err != nil {
		return fmt.Errorf("audit/jsonl: write line: %w", err)
	}
	return nil
}

// Close closes the underlying file. Emitting after Close is an error, not
// a panic: a shutdown race must not take the process down.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	if err != nil {
		return fmt.Errorf("audit/jsonl: close sink: %w", err)
	}
	return nil
}

// Recorder is the decorator: it stores through inner, then emits.
//
// It satisfies both audit.Recorder (so it drops straight into
// gateway.Config.Audit) and audit.ChainedRecorder (so wrapping it again --
// a second sink, a test spy -- stays possible without unwrapping).
type Recorder struct {
	inner audit.ChainedRecorder
	sink  Sink
	chain string
	log   *slog.Logger
}

var (
	_ audit.Recorder        = (*Recorder)(nil)
	_ audit.ChainedRecorder = (*Recorder)(nil)
)

// New returns a Recorder that writes through inner and then emits to sink.
//
// chain names this gateway's chain and must not be empty: a line whose
// chain is blank is a hash with no statement about which trail it belongs
// to, which makes it useless as an anchor the moment a second gateway
// ships into the same stream. log is optional and defaults to
// slog.Default().
//
// There is no "sink optional" mode. A Recorder with no sink is a
// pass-through that still looks like it ships to the SIEM at every call
// site, which is the shape of mistake this project keeps finding; build
// the undecorated recorder instead.
func New(inner audit.ChainedRecorder, sink Sink, chain string, log *slog.Logger) (*Recorder, error) {
	if inner == nil {
		return nil, errors.New("audit/jsonl: inner recorder is required")
	}
	if sink == nil {
		return nil, errors.New("audit/jsonl: sink is required")
	}
	if chain == "" {
		return nil, errors.New("audit/jsonl: chain name is required")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{inner: inner, sink: sink, chain: chain, log: log}, nil
}

// Record implements audit.Recorder.
func (r *Recorder) Record(ctx context.Context, rec audit.Record) error {
	_, err := r.RecordChained(ctx, rec)
	return err
}

// RecordChained implements audit.ChainedRecorder: durable write first,
// emit second, and the error from each treated differently on purpose.
//
// A failure from inner is returned unchanged and NOTHING is emitted. That
// keeps gateway.Dispatch's refusal rule exactly as strict as it was -- an
// unauditable call is still refused -- and it keeps the SIEM from ever
// holding a line for a record that is not on disk, which would invert the
// one-directional divergence this design depends on.
//
// A failure from the sink is logged at ERROR and swallowed. The record is
// durable; the analyst is served; the gap is loud. See the package doc for
// why refusing here would be the wrong trade.
func (r *Recorder) RecordChained(ctx context.Context, rec audit.Record) (audit.ChainLink, error) {
	link, err := r.inner.RecordChained(ctx, rec)
	if err != nil {
		return audit.ChainLink{}, err
	}

	if err := r.sink.Emit(ctx, r.line(rec, link)); err != nil {
		// Deliberately loud, and deliberately not fatal. The attributes
		// here are the same closed set the line carries plus the sink's own
		// error, which is local operational text about a file -- it never
		// leaves this host and it never enters the line.
		r.log.ErrorContext(ctx, "audit/jsonl: record stored locally but NOT emitted to the SIEM sink -- the external anchor is now behind",
			slog.String("chain", r.chain),
			slog.String("tool", rec.Tool),
			slog.String("verdict", string(rec.Outcome)),
			slog.String("hash", link.Hash),
			slog.String("detail", err.Error()),
		)
	}
	return link, nil
}

// List implements audit.Recorder by delegating. The JSONL file is a sink,
// not a store: reading the trail is still the database's job.
func (r *Recorder) List(ctx context.Context) ([]audit.Record, error) {
	return r.inner.List(ctx)
}

// line is the ONLY place a Line is built.
//
// Its inputs are an audit.Record and an audit.ChainLink and nothing else.
// There is no parameter through which arbitrary text could arrive -- no
// map, no any, no error -- so the set of values that can reach the SIEM is
// exactly the set of fields on those two structs, and widening it is a
// change to this signature.
func (r *Recorder) line(rec audit.Record, link audit.ChainLink) Line {
	return Line{
		Version: Version,
		// UTC for the SIEM's benefit; see the package doc on what this
		// costs in re-derivability.
		Time:    rec.Timestamp.UTC().Format(time.RFC3339Nano),
		Chain:   r.chain,
		Caller:  rec.AnalystIdentity,
		Backend: rec.TargetUpstream,
		Tool:    rec.Tool,
		Verdict: string(rec.Outcome),
		Rule:    rec.Reason,
		Src:     rec.SourceAddress,

		PrevHash: link.Prev,
		Hash:     link.Hash,
	}
}
