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
	"io"
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
//
// 2 (design/adr/0021, 15 Sep 2026): every line declares its `type`, and a
// second shape -- [Heartbeat] -- joined the file. A consumer written
// against 1 may assume every line has a `hash`, which is no longer true.
const Version = 2

// Line and Heartbeat type discriminators, as they appear in the `type`
// field. They are a declared interface: a SIEM query filters on them, so
// rewording one silently breaks a saved search somewhere (the same
// argument the gateway's audit reason constants carry).
const (
	// TypeRecord marks a line carrying one audit.Record.
	TypeRecord = "record"
	// TypeHeartbeat marks a line carrying this process's operational
	// state. It is NOT an audit record: no analyst did anything to cause
	// it, it is not in the hash chain, and it must never be counted as
	// activity.
	TypeHeartbeat = "heartbeat"
)

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
	// Type is always TypeRecord here. It exists so a consumer discriminates
	// on a declared field rather than on the absence of another one: "no
	// hash, so it must be the other shape" stops being true the moment a
	// third shape exists (design/adr/0021 item 1).
	Type string `json:"type"`
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

// Heartbeat is the second shape in the file: what this process is, and
// what it has done since it started (design/adr/0021).
//
// # Why it shares the file with the audit lines
//
// So that its absence proves something. A heartbeat on its own path --
// its own file, its own shipper -- would keep arriving while the audit
// path was dead, which is the one failure the alert exists to catch. This
// one crosses the same tail, the same shipper and the same output, so
// "no heartbeat for this chain in N minutes" means the gateway stopped,
// the shipper stopped, or the jail went away.
//
// # What it is not
//
// It is not an audit record. It is not in the hash chain, it has no hash
// of its own, nothing an analyst did causes one, and counting heartbeats
// as activity would be a category error with an obvious wrong answer.
//
// It is also not evidence against anybody who controls this host. The
// lines are unsigned -- the package doc says that about audit lines and it
// is no less true here -- so whoever can write the file can write
// heartbeats. What it detects is the operational failure: a dead process,
// a dead shipper, a full disk.
//
// # The counters
//
// Cumulative since Boot, never deltas: a heartbeat that never arrived then
// costs visibility for one interval rather than losing the events it would
// have carried, and Boot is what explains a counter that went backwards.
// Rates are the dashboard's job, where the window is chosen.
//
// Every field is always present, like [Line]'s, and for the same reason.
type Heartbeat struct {
	// Version is the schema version, shared with Line: the two shapes
	// version together because they travel together.
	Version int `json:"v"`
	// Type is always TypeHeartbeat.
	Type string `json:"type"`
	// Time is when this heartbeat was emitted, RFC3339 with nanoseconds,
	// UTC -- like Line.Time.
	Time string `json:"ts"`
	// Chain is the chain this process writes, so a heartbeat and the audit
	// lines it vouches for are queried by the same key.
	Chain string `json:"chain"`
	// Boot is when this process started, UTC. It identifies the run: two
	// heartbeats with different Boot values are two processes, which is
	// how a restart becomes visible -- and a restart is what makes a
	// rotated credential take effect (GAB-20).
	Boot string `json:"boot"`
	// Head is the chain hash of the last audit line THIS PROCESS emitted,
	// or empty when it has emitted none.
	//
	// Empty is a real answer, not a missing one: a gateway that booted and
	// served nobody has no head of its own to report, and inventing one by
	// reading the database would make the field mean something different
	// on quiet nights than on busy ones.
	//
	// # It is the LAST LINE EMITTED, which under concurrency is not always
	// the chain's head
	//
	// RecordChained updates this after its own Emit returns, and two
	// concurrent calls can commit in one order and emit in the other. When
	// that happens the field carries the hash of the record that was
	// emitted last rather than the one that is last in the chain, so it can
	// appear to go backwards between two heartbeats on a busy gateway.
	//
	// That is a property and not a bug to fix here, and the alternative was
	// weighed: making it a true head means a total order the sink can
	// compare, which means widening audit.ChainLink with a sequence number
	// -- a port kept deliberately narrow (see audit.ChainLink's own doc).
	// Not worth it, because nothing depends on this field being the head:
	// the anchor derives the true head from the shipped lines themselves
	// (deploy/gatte-anchor-verify.sh), which is set arithmetic over
	// prev/hash links and is unaffected by emission order.
	//
	// So read it as "the last line this process shipped", which is a
	// liveness signal -- a value that stops changing while `records` keeps
	// climbing is a sink that stopped anchoring -- and not as an integrity
	// one. This comment said "a way to watch the head advance" until
	// 15 Sep 2026, which invited exactly the reading it cannot support.
	Head string `json:"head"`
	// Records is how many audit lines this process has emitted since Boot.
	Records uint64 `json:"records"`
	// Allowed, Denied and Failed are the audit records the gateway wrote,
	// by outcome, since Boot. A failed call produces an allowed AND a
	// failed record, so these are line counts and not call counts -- see
	// the package doc's counting note, which applies here identically.
	//
	// If these ever disagree with the trail, the trail is right. These are
	// integers in memory that die with the process.
	Allowed uint64 `json:"allowed"`
	Denied  uint64 `json:"denied"`
	Failed  uint64 `json:"failed"`
	// Upstreams is how many backends are connected right now, and Tools
	// how many routes the table holds.
	Upstreams int `json:"upstreams"`
	Tools     int `json:"tools"`
	// Suspended reports that the Upstream Registry could not be read and
	// nothing is being served (design/adr/0020). A gateway can be up,
	// shipping heartbeats, and serving nobody; this is the field that says
	// so.
	Suspended bool `json:"suspended"`
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
	// EmitHeartbeat writes one heartbeat, under the same atomicity rule.
	//
	// It is a second method rather than a widened parameter on Emit for
	// the reason Emit takes a Line and not a map: the typed shape has to
	// survive to the writer, so no implementation can decide what a line
	// of either kind contains.
	EmitHeartbeat(ctx context.Context, hb Heartbeat) error
}

// FileSink appends lines to a local file.
//
// Local is the whole point (see the package doc): the gateway's request
// path gets no network dependency, and a shipper -- filebeat, vector,
// whatever the deployment already runs -- reads this file and forwards it.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
	// w is what Emit actually writes to, and is f on every sink this
	// package builds. It exists as a seam because the one failure mode
	// that matters here -- a write that stops partway -- cannot be
	// provoked through a real file without filling a disk.
	w io.Writer
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

	// The mode argument above applies ONLY when OpenFile creates the file.
	// On a file that already exists it is ignored entirely, so a sink
	// reopened after a rotation -- or created by hand, or left behind by a
	// previous deployment with a wider mode -- kept whatever permissions it
	// already had while this package's doc promised 0600. The promise is
	// enforced here instead of asserted above.
	//
	// Narrowing rather than refusing: a gateway that will not start because
	// its log file is group-readable turns a permissions wart into an
	// outage, and the fix (tighten it) is the same either way.
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit/jsonl: stat sink: %w", err)
	}
	if perm := info.Mode().Perm(); perm&^DefaultFileMode != 0 {
		if err := f.Chmod(DefaultFileMode); err != nil {
			f.Close()
			return nil, fmt.Errorf("audit/jsonl: sink %s is mode %#o and could not be narrowed to %#o: %w",
				path, perm, DefaultFileMode, err)
		}
	}
	return &FileSink{f: f, w: f}, nil
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
	return s.write(buf)
}

// EmitHeartbeat implements Sink. It is Emit for the other shape, and goes
// through the same single-write path: a torn heartbeat would corrupt the
// audit line that follows it in exactly the same way.
func (s *FileSink) EmitHeartbeat(_ context.Context, hb Heartbeat) error {
	buf, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("audit/jsonl: marshal heartbeat: %w", err)
	}
	return s.write(buf)
}

// write appends one marshalled object plus its newline.
func (s *FileSink) write(buf []byte) error {
	buf = append(buf, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	// Liveness is a property of the writer Emit uses, not of the file
	// handle beside it: those are the same thing on every sink this
	// package builds, and only the writer is the thing being written to.
	if s.w == nil {
		return errors.New("audit/jsonl: sink is closed")
	}
	n, err := s.w.Write(buf)
	if err != nil {
		// A write that stopped partway has left a headless JSON stump at
		// the end of the file, and O_APPEND means the NEXT record starts
		// exactly where it stopped -- merging a good record onto a broken
		// one and losing both. Terminating the stump costs one byte and
		// turns silent loss into one corrupt line a parser will reject
		// loudly, with every record after it intact.
		//
		// Best effort by construction: if the first write failed there is
		// every chance this one does too, and there is nothing further to
		// try. What matters is that the attempt is made before the next
		// Emit runs.
		if n > 0 && n < len(buf) {
			_, _ = s.w.Write([]byte("\n"))
		}
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
	s.f, s.w = nil, nil
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

	// mu guards what a heartbeat reports about this sink's own history.
	// It is not on the durable path: RecordChained takes it only after
	// inner has committed and the line has been emitted.
	mu sync.Mutex
	// head is the hash of the last line this process actually EMITTED --
	// not the last one stored. A record that was written durably and then
	// failed to reach the sink has not been anchored anywhere, and saying
	// it had would be the one lie this file cannot afford.
	head string
	// emitted counts lines that reached the sink, by the same rule.
	emitted uint64
}

// Stats is the part of a heartbeat that only the caller knows: the
// process's own identity in time and what the gateway has counted.
//
// It exists so that [Recorder.Heartbeat] fills in everything about the
// sink (chain, head, emitted lines, schema) and nothing about the gateway,
// which keeps this package's rule intact -- the set of values that can
// reach the SIEM is the set of fields on a declared struct.
type Stats struct {
	// Boot is when the process started and Now when this heartbeat is
	// being emitted. Both are normalized to UTC on the way out.
	Boot time.Time
	Now  time.Time
	// Allowed, Denied and Failed are audit records written since Boot, by
	// outcome. See Heartbeat for why they are line counts, not call counts.
	Allowed uint64
	Denied  uint64
	Failed  uint64
	// Upstreams is connected backends and Tools is routes in the table.
	Upstreams int
	Tools     int
	// Suspended reports a fleet serving nothing because the registry
	// cannot be read (design/adr/0020).
	Suspended bool
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

	if err := r.sink.Emit(ctx, r.line(rec, link)); err == nil {
		r.mu.Lock()
		r.head, r.emitted = link.Hash, r.emitted+1
		r.mu.Unlock()
	} else {
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

// Heartbeat emits one heartbeat line and returns what it emitted, so a
// caller can log the same numbers it shipped rather than assembling them
// twice (design/adr/0021).
//
// The returned Heartbeat is filled in whether or not the sink accepted it:
// on failure the caller still has the state to log locally, which is the
// half of the signal that does not depend on the file being writable.
//
// A sink failure here is returned rather than swallowed, and that is the
// opposite of RecordChained's rule on purpose. Nothing is being denied to
// anybody: no analyst is waiting on a heartbeat, so there is no
// availability fault to trade against, and the caller -- the maintenance
// loop -- is exactly the place that can say so at ERROR once per round.
func (r *Recorder) Heartbeat(ctx context.Context, st Stats) (Heartbeat, error) {
	r.mu.Lock()
	head, emitted := r.head, r.emitted
	r.mu.Unlock()

	hb := Heartbeat{
		Version:   Version,
		Type:      TypeHeartbeat,
		Time:      st.Now.UTC().Format(time.RFC3339Nano),
		Chain:     r.chain,
		Boot:      st.Boot.UTC().Format(time.RFC3339Nano),
		Head:      head,
		Records:   emitted,
		Allowed:   st.Allowed,
		Denied:    st.Denied,
		Failed:    st.Failed,
		Upstreams: st.Upstreams,
		Tools:     st.Tools,
		Suspended: st.Suspended,
	}
	if err := r.sink.EmitHeartbeat(ctx, hb); err != nil {
		return hb, fmt.Errorf("audit/jsonl: emit heartbeat: %w", err)
	}
	return hb, nil
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
		Type:    TypeRecord,
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
