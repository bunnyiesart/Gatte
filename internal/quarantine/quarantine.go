// Package quarantine is the domain package for the Tool Quarantine
// component (design/02-components.md, design/adr/0003-security-controls.md
// item 2): per-tool approval state for every tool exposed by every
// registered upstream MCP server.
//
// Why this component exists at all: an MCP tool's *description* and input
// schema are handed to an LLM as trusted operational context that it acts
// on. That has no REST-gateway equivalent. Two concrete attacks follow --
// tool poisoning (adversarial instructions hidden in a description of a
// newly-onboarded server) and the "rug pull" (a previously-approved tool's
// description silently changing afterwards, OWASP MCP03). The defence,
// copied in behavior from mcpproxy-go (not in code -- see AGENTS.md's
// license note), is to fingerprint each tool's definition and refuse to
// expose or dispatch anything a human operator has not approved at exactly
// that fingerprint.
//
// Granularity is per *tool*, not per server: a fifty-tool server can have
// one tool's description rewritten while the other forty-nine are
// untouched, and blocking the whole server (or worse, letting the changed
// tool through with its siblings) would be the wrong answer either way.
//
// Per the ports & adapters split this project follows
// (context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter. The state-transition rules
// live here, as pure functions on Tool -- deliberately not in SQL, so they
// are unit-testable without a database and so there is exactly one place
// where "is this tool allowed" is decided.
package quarantine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"slices"
	"strings"
	"time"
)

// Sentinel errors returned by Store implementations. Callers should check
// these with errors.Is, since adapters wrap them with additional context.
var (
	// ErrNotFound is returned when no quarantine entry exists for the
	// requested (server name, tool name) pair.
	ErrNotFound = errors.New("quarantine: tool not found")
	// ErrInvalidStatus is returned when a Tool carries a Status that is
	// not one of StatusPending, StatusApproved or StatusChanged. It is a
	// defensive error: a stored row whose status column has been
	// corrupted or hand-edited must fail loudly rather than be treated as
	// some default state, since the default a bug would most likely reach
	// for ("") is not usable but also not visibly wrong.
	ErrInvalidStatus = errors.New("quarantine: invalid status")
	// ErrInvalidClass is ErrInvalidStatus for the Class column: a Tool whose
	// Class is neither ClassSafe nor ClassSensitive. Same reasoning -- a
	// corrupted or hand-edited row must fail loudly, since a class the
	// domain does not define would otherwise be served as whichever branch
	// of Usable it happened to fall through.
	ErrInvalidClass = errors.New("quarantine: invalid security class")
	// ErrNotApproved is returned by Tool.Cleared and Store.Clear for a tool
	// that is not approved: clearance is a judgement about an approved
	// definition, and there is nothing to clear before a baseline exists.
	ErrNotApproved = errors.New("quarantine: only an approved tool can be cleared")
	// ErrNotSensitive is returned by Tool.Cleared and Store.Clear for a
	// ClassSafe tool. See Tool.Cleared for why it is refused rather than
	// accepted as a harmless no-op.
	ErrNotSensitive = errors.New("quarantine: a safe tool has nothing to clear")
	// ErrChangedIsNotRevocable is returned by Revoke and Tool.Revoked for a
	// tool whose status is StatusChanged. See Tool.Revoked for why that is
	// refused rather than allowed as a no-op.
	ErrChangedIsNotRevocable = errors.New("quarantine: a changed tool cannot be revoked")
	// ErrFingerprintMoved is returned by ApproveFingerprint and
	// Tool.ApprovedFingerprint when the observed fingerprint is no longer
	// the one the operator reviewed. See Tool.ApprovedFingerprint.
	ErrFingerprintMoved = errors.New("quarantine: the observed fingerprint changed since it was reviewed")
	// ErrDefinitionNotKept is returned by Store.Definition for a
	// fingerprint no stored definition answers to. The expected case is a
	// baseline approved before definitions were kept (design/adr/0032):
	// its hash survives, and what it stood for was never written down.
	ErrDefinitionNotKept = errors.New("quarantine: definition not kept")
	// ErrDefinitionMismatch is returned by Store.Definition when the stored
	// definition does not hash to the fingerprint it is filed under: the
	// row was edited after it was written. It is refused rather than shown,
	// because showing it would present an edited text as the approved one.
	ErrDefinitionMismatch = errors.New("quarantine: stored definition does not match its fingerprint")
	// ErrReviewSetMoved is returned by ApprovedSet and
	// Store.ApproveReviewSet when a backend's review set -- which of its
	// tools wait for review, at which fingerprints -- no longer hashes to
	// the manifest the operator was shown (design/adr/0043). Nothing is
	// approved: one tool moving refuses the whole set.
	ErrReviewSetMoved = errors.New("quarantine: the backend's review set changed since it was reviewed")
	// ErrReviewSetEmpty is returned by ApprovedSet and
	// Store.ApproveReviewSet when nothing on the backend waits for review.
	ErrReviewSetEmpty = errors.New("quarantine: nothing on this backend is waiting for review")
)

// hashDomainTag is mixed into every Hash as its first length-prefixed
// field. It scopes the digest to this component and this encoding version:
// a hash produced here can never be confused with, or replayed as, a
// digest computed elsewhere in the project (the Definition Signer hashes
// registry entries with its own scheme), and changing the encoding later
// means bumping the version here rather than silently producing digests
// that collide with the old scheme's.
const hashDomainTag = "mcp-gateway/quarantine/tool-identity/v1"

// hashDomainTagOutput is the tag of the identity that also covers the
// tool's declared OutputSchema (28 Sep 2026). Used only for a tool that
// declares one, so a tool without an output schema keeps its v1 fingerprint
// and its approval. Before it, the output schema was outside the
// fingerprint: a backend that dropped or loosened it kept the tool approved
// while its results silently stopped being validated (ADR-0014).
const hashDomainTagOutput = "mcp-gateway/quarantine/tool-identity/v2-output"

// ToolIdentity is the part of an upstream tool's definition that the
// quarantine fingerprints: everything that, if changed, changes what the
// tool tells an LLM to do or what it accepts.
//
// InputSchema holds the tool's JSON input schema as the raw bytes received
// from the upstream server. They are hashed verbatim -- there is no JSON
// canonicalization step. That is deliberate and fail-closed: a
// re-serialized or reordered schema hashes differently and therefore
// requires re-approval, which costs an operator one approval click, where
// canonicalizing would mean trusting a parser to decide that two byte
// sequences "mean the same thing" before a human ever looks at them. A nil
// and an empty InputSchema hash identically; both mean "no schema."
type ToolIdentity struct {
	// Name is the tool's name as advertised by the upstream server.
	Name string
	// Description is the tool's description as advertised by the upstream
	// server -- the field that is fed to the LLM as instructions and is
	// therefore the primary tool-poisoning vector.
	Description string
	// InputSchema is the tool's raw JSON input schema bytes, hashed as-is.
	InputSchema []byte
	// OutputSchema is the tool's raw JSON output schema bytes, or empty
	// when it declares none. It decides whether results are validated
	// (ADR-0014), so changing, loosening or dropping it is a change to what
	// was approved.
	OutputSchema []byte
}

// Hash returns the hex-encoded SHA-256 fingerprint of t: the identity of
// one specific version of one specific tool definition.
//
// The encoding is unambiguous. Each field is written as an 8-byte
// big-endian length followed by its bytes, preceded by a domain tag field
// (hashDomainTag). Without length prefixing, concatenating the fields
// would let different identities produce the same digest -- for instance a
// tool named "ab" described as "c" and a tool named "a" described as "bc"
// -- which would let an attacker rename and re-describe a tool into the
// fingerprint of an already-approved one. TestHash_IsUnambiguous pins
// exactly that case.
func Hash(t ToolIdentity) string {
	h := sha256.New()
	if len(t.OutputSchema) == 0 {
		writeField(h, []byte(hashDomainTag))
	} else {
		writeField(h, []byte(hashDomainTagOutput))
	}
	writeField(h, []byte(t.Name))
	writeField(h, []byte(t.Description))
	writeField(h, t.InputSchema)
	if len(t.OutputSchema) != 0 {
		writeField(h, t.OutputSchema)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeField writes b to h prefixed by its length, so that field
// boundaries are recoverable from the byte stream and no two distinct
// field tuples can produce the same input to the digest.
func writeField(h hash.Hash, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	// hash.Hash's Write never returns an error (documented on the
	// interface), so the returns are deliberately unchecked.
	h.Write(n[:])
	h.Write(b)
}

// Status is a tool's quarantine state.
//
// Status exists for the *operator's* benefit -- it is what the Operator
// Console renders so a human can see what is waiting for approval and what
// changed under them. It is not the gate. Never decide whether to list or
// dispatch a tool by comparing Status; call Tool.Usable instead, and read
// the reasoning in that method's doc comment.
type Status string

const (
	// StatusPending is a tool seen for the first time and never approved.
	StatusPending Status = "pending"
	// StatusApproved is a tool an operator approved, at the fingerprint
	// recorded in Tool.ApprovedHash.
	StatusApproved Status = "approved"
	// StatusChanged is a previously-approved tool whose observed
	// fingerprint no longer matches the approved baseline -- a rug pull
	// until an operator says otherwise.
	StatusChanged Status = "changed"
)

// Valid reports whether s is one of the three defined states.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusChanged:
		return true
	default:
		return false
	}
}

// Class is a tool's security class (design/adr/0048 Decisão 5): whether the
// operation behind it can only read, or can also act.
//
// It is ORTHOGONAL to Status, deliberately not a fourth state. Status is
// the quarantine's own judgement about a definition (did a human vet these
// bytes); Class is metadata the operation carries in from the registry --
// derived from its HTTP method at register time, signed as part of the
// frozen operation set (ADR-0048 Decisão 2) -- and it answers a different
// question: given that the definition is vetted, may it be served on an
// approval alone, or does it need a second, explicit clearance? Folding it
// into Status would make "approved" mean two things, and every switch on
// Status in the operator console would grow a branch.
//
// It is NOT part of the fingerprint: it never enters ToolIdentity or Hash
// (ADR-0048 Decisão 5, "Correção factual"). A tool whose method changes
// keeps its fingerprint and its approval; what changes is the extra
// condition Usable imposes, and that is enough, because the change lands
// on the next observation.
//
// This package never learns what an HTTP method is. The gateway decides
// the class from the operation's metadata and hands it to Store.Observe;
// here it is a label with exactly two values.
type Class string

const (
	// ClassSafe is the zero value: an operation that only reads (GET, HEAD,
	// OPTIONS in the adapter's terms, and every MCP tool of a stdio or oci
	// upstream, which have no method to derive a class from). A safe tool
	// is usable on an approval alone, exactly as every tool was before
	// ADR-0048 -- which is why the zero value is the safe class and not the
	// other way round: a row retrofitted from a pre-v3 file reads "" and
	// keeps serving as it did.
	ClassSafe Class = ""
	// ClassSensitive is an operation that can act (every other method: the
	// `POST /submit` that ADR-0047's Contexto names as the exfiltration
	// path). A sensitive tool is default-deny: approved is not enough, an
	// operator must also clear it (Tool.Cleared) at the approved
	// fingerprint.
	ClassSensitive Class = "sensitive"
)

// Valid reports whether c is one of the two defined classes. It mirrors
// Status.Valid and is read by the sqlite adapter for the same reason.
func (c Class) Valid() bool {
	switch c {
	case ClassSafe, ClassSensitive:
		return true
	default:
		return false
	}
}

// Tool is the stored quarantine state of one tool on one upstream server.
type Tool struct {
	// ServerName is the registry name of the upstream server exposing the
	// tool (e.g. "casemgmt").
	ServerName string
	// ToolName is the tool's name as advertised by that server (e.g.
	// "list_cases"). ServerName plus ToolName is the entry's identity.
	ToolName string
	// Status is the operator-facing state. It is not the gate -- see
	// Usable.
	Status Status
	// ApprovedHash is the fingerprint an operator approved. Empty until
	// the first approval.
	ApprovedHash string
	// ObservedHash is the fingerprint most recently seen during
	// discovery.
	ObservedHash string
	// Class is the tool's security class, as last observed. Metadata, not
	// part of the fingerprint -- see Class.
	Class Class
	// SensitiveClearedHash is the approved fingerprint an operator cleared
	// for serving as a sensitive tool (Cleared), or empty. Invariant kept
	// by every transition here: it is either empty or equal to the
	// ApprovedHash it was granted for -- Approved drops it when the
	// baseline moves, Revoked drops it with the baseline -- so a clearance
	// can never outlive the approval it was a clearance of. Meaningless
	// for a ClassSafe tool, and Cleared refuses to set it on one.
	SensitiveClearedHash string
	// FirstSeenAt is when this tool was first observed.
	FirstSeenAt time.Time
	// UpdatedAt is when this entry last changed (observation or
	// approval).
	UpdatedAt time.Time
}

// Usable reports whether the gateway may expose and serve this tool.
//
// This method is the single gate. It answers *both* questions the gateway
// ever asks about a quarantined tool -- whether the tool appears in the
// aggregated tool list the gateway advertises to clients, and whether an
// incoming call to that tool is dispatched to its upstream -- and callers
// MUST NOT make either decision by inspecting Status (or any other field)
// directly.
//
// The reason is a security property, not tidiness. Two separate predicates
// can drift apart, and both drift directions are exploitable: a tool that
// is indexed but uncallable is a confusing but merely broken gateway,
// while a tool that is callable but hidden is an invisible execution path
// -- precisely what a poisoned or rug-pulled tool wants to be. One
// predicate, consulted at both sites, makes that class of inconsistency
// unrepresentable rather than merely discouraged. WORKFLOW.md's Phase 3
// states the constraint as "one field gating both index visibility and
// callability together"; this is that field's accessor.
//
// A tool is usable only when an operator approved it AND the fingerprint
// last observed still matches the fingerprint that was approved. Pending
// and changed tools are never usable, and neither is a tool whose
// approved baseline is somehow empty. Note that being unusable does not
// mean being invisible to the *operator*: List returns pending and changed
// tools precisely so a human can see and approve them. Visibility to an
// operator and usability by a caller are different questions; only the
// second is Usable's.
//
// A ClassSensitive tool has ONE condition more (design/adr/0048 Decisão 5,
// "default-deny"): its SensitiveClearedHash must equal its ApprovedHash.
// That is the whole of the default-deny mechanism -- because Usable is the
// one gate both admit and the listing read, a sensitive tool that was
// approved but not cleared is invisible and uncallable at once, with no
// new branch anywhere on the call path. Only ClassSafe is exempt: a class
// this package does not define is treated as sensitive, and since Cleared
// refuses to clear it, it is unreachable until the row is fixed.
//
// Usable is role-blind by design, and that is a known half: a cleared
// sensitive tool is reachable by any role that names it, and ADR-0048's
// other half -- the class-aware gate at the dispatch edge, which refuses
// GrantAll coverage of a sensitive tool -- lives in the gateway, not here.
// This predicate decides servability; who may call is the access
// component's question, asked by name.
func (t Tool) Usable() bool {
	if !t.ApprovedAsAdvertised() {
		return false
	}
	if t.Class != ClassSafe {
		return t.SensitiveClearedHash != "" && t.SensitiveClearedHash == t.ApprovedHash
	}
	return true
}

// ApprovedAsAdvertised reports whether the definition the tool advertises
// now is the one an operator approved: approved, with a baseline, and the
// observed fingerprint equal to it. It is the class-blind half of Usable --
// for a ClassSafe tool the two are the same answer; for a ClassSensitive
// tool this is true while the clearance is still missing.
//
// It exists for the gateway's class gate (design/adr/0048 Decisão 5),
// which has to tell "approved and held for clearance" from every other
// unusable state without re-deriving the rule from the fields: the first
// is the one state in which a read-role caller must be answered forbidden
// rather than unknown, so that a cleared and an uncleared sensitive tool
// read the same from outside. It is NOT a gate: nothing is listed or served
// on this alone, and callers deciding servability use Usable.
func (t Tool) ApprovedAsAdvertised() bool {
	return t.Status == StatusApproved && t.ApprovedHash != "" && t.ObservedHash == t.ApprovedHash
}

// NewTool returns the quarantine state of a tool being seen for the very
// first time: pending, with observedHash and class recorded and no
// approved baseline. A tool never starts usable -- onboarding a new
// upstream server means every one of its tools waits for explicit human
// approval (design/adr/0003, "servidor novo -> toda tool nasce pending").
//
// class is recorded as given, even when invalid: NewTool cannot fail, and
// an undefined class is fail-closed anyway (Usable treats it as sensitive,
// Cleared refuses it, and the sqlite adapter refuses to write it).
func NewTool(serverName, toolName, observedHash string, class Class, now time.Time) Tool {
	return Tool{
		ServerName:   serverName,
		ToolName:     toolName,
		Status:       StatusPending,
		ApprovedHash: "",
		ObservedHash: observedHash,
		Class:        class,
		FirstSeenAt:  now,
		UpdatedAt:    now,
	}
}

// Observed returns the state t transitions to when observedHash is seen
// for it during discovery. It is a pure function: the whole state machine
// lives here, so adapters only persist the result and never re-derive the
// rules in SQL.
//
// The rules, by current status:
//
//   - pending: stays pending. A tool nobody has approved yet does not
//     become more or less trustworthy by being re-advertised, whatever its
//     new fingerprint.
//   - approved, observedHash == ApprovedHash: stays approved. This is the
//     normal path -- every discovery cycle re-observes an unchanged tool.
//   - approved, observedHash != ApprovedHash: becomes changed. This is the
//     rug pull: the definition an operator vetted is not the definition
//     being served now, so the tool leaves the usable set immediately,
//     before the next call rather than after an incident.
//   - changed: stays changed, even if observedHash matches ApprovedHash
//     again. Deliberately fail-closed: a definition that flips to a
//     poisoned variant and back must not silently re-enter the usable set
//     on the next discovery cycle, because that is exactly how an attacker
//     would hide the window in which the poisoned version was live. Only
//     Approve clears a change, and only a human calls Approve.
//
// The class is re-observed along with the hash and simply recorded: it is
// metadata from the registry, not something the quarantine judges, and the
// latest observation is the operation's current method. It never touches
// Status. What it touches is the extra condition Usable imposes: a tool
// that turns sensitive is held until cleared, UNLESS it was already cleared
// at this very approved hash while it was sensitive before; and one that
// turns safe is served on its approval alone. Neither direction edits
// SensitiveClearedHash -- a clearance is tied to the approved hash, which
// an observation never moves -- so a clearance given to the sensitive form
// of a definition survives that definition flipping to safe and back, and
// the tool is served again on the flip back without a second clearance.
// That is deliberate: the bytes being served are exactly the bytes the
// operator cleared as able to act, and the flip itself changed nothing an
// operator was asked to judge (TestObserved_AClearanceSurvivesAClassFlipAndBack
// pins it). A tool that was never cleared while sensitive has an empty
// SensitiveClearedHash -- Cleared refuses a safe tool precisely so the flip
// cannot be used to manufacture one -- and is held. A re-advertisement
// that DOES change the hash invalidates the clearance for the same reason
// it invalidates the approval: the tool becomes changed, and the next
// approval baselines a hash the clearance does not name (Approved drops
// it).
//
// UpdatedAt is advanced to now on every observation; FirstSeenAt never
// moves. Observed returns ErrInvalidStatus if t.Status is not one of the
// three defined states, and ErrInvalidClass if class is not one of the two
// defined classes.
func (t Tool) Observed(observedHash string, class Class, now time.Time) (Tool, error) {
	if !t.Status.Valid() {
		return Tool{}, ErrInvalidStatus
	}
	if !class.Valid() {
		return Tool{}, ErrInvalidClass
	}

	next := t
	next.ObservedHash = observedHash
	next.Class = class
	next.UpdatedAt = now

	if t.Status == StatusApproved && observedHash != t.ApprovedHash {
		next.Status = StatusChanged
	}
	return next, nil
}

// Event names the transition one observation caused, for the audit trail
// (design/adr/0032 item 4). It is what makes "a tool appeared" and "an
// approved tool was rewritten" alertable, and it is reported only on the
// transition: a refresh re-observes every tool every interval, and an
// event per tick would bury the one that matters.
type Event string

const (
	// EventNone is every observation that changed no status.
	EventNone Event = ""
	// EventFirstSeen is the first observation of (server, tool): it was
	// born pending. After Forget the next observation is a first sight
	// again, which is correct -- a deregistered upstream's approvals went
	// with it.
	EventFirstSeen Event = "first-seen"
	// EventChanged is an approved tool becoming changed: the rug pull.
	// The observation's ApprovedHash is the vetted fingerprint and its
	// ObservedHash the new one. A changed tool that moves again stays
	// changed and reports nothing, since nothing it is allowed to do
	// changed.
	EventChanged Event = "changed"
)

// EventOf returns the event of the transition from before to after, for a
// tool that was already known. First sight has no before and is reported
// by the adapter's insert path as EventFirstSeen.
func EventOf(before, after Tool) Event {
	if before.Status == StatusApproved && after.Status == StatusChanged {
		return EventChanged
	}
	return EventNone
}

// Observation is what Store.Observe returns: the resulting state, and the
// transition that produced it. Tool is embedded so the state reads exactly
// as it did before the event was reported alongside it.
type Observation struct {
	Tool
	// Event is the transition this observation caused, if any.
	Event Event
}

// Approved returns the state t transitions to when an operator approves
// it: status approved, with the currently-observed fingerprint recorded as
// the new baseline. Re-approving a changed tool is the supported way to
// accept a legitimate upstream update -- the new definition becomes the
// baseline the next rug pull is detected against.
//
// Approval never clears a sensitive tool. If the baseline moves, the
// clearance that named the old baseline is dropped rather than left as a
// stale value: it would already be inert (Usable compares it with the new
// ApprovedHash) but a definition flipping back to the old hash and being
// re-approved would otherwise find it matching again, and serve a
// sensitive tool on a clearance nobody renewed. Re-approving the SAME
// hash -- a changed tool whose definition reverted -- keeps its
// clearance, because the operator cleared exactly these bytes.
func (t Tool) Approved(now time.Time) Tool {
	next := t
	next.Status = StatusApproved
	next.ApprovedHash = t.ObservedHash
	if next.ApprovedHash != t.ApprovedHash {
		next.SensitiveClearedHash = ""
	}
	next.UpdatedAt = now
	return next
}

// Cleared returns the state t transitions to when an operator clears a
// sensitive tool for serving (design/adr/0048 Decisão 5): the approved
// fingerprint is recorded as SensitiveClearedHash, which is the one
// condition Usable still waited on. It is the second human decision a
// sensitive tool needs, separate from approval on purpose -- approval
// says "this definition is not poisoned", clearance says "this backend
// may act on our behalf through this operation", and the batch path
// (ApprovedSet) must be able to give the first to a whole backend without
// anyone having given the second.
//
// Preconditions, each refused with its own error and no new state:
//
//   - t must be approved with a non-empty baseline (ErrNotApproved). A
//     clearance is of an approved fingerprint; before one exists there is
//     nothing to name, and clearing a pending tool "in advance" would make
//     the next approval also a clearance, which is what the two steps
//     exist to keep apart.
//   - t.Class must be ClassSensitive (ErrNotSensitive). A safe tool is
//     refused, not accepted as a harmless no-op, because it would not be
//     harmless: SensitiveClearedHash would hold the approved hash, and an
//     operation re-registered as sensitive with the same definition would
//     then be served without anyone having cleared its sensitive form.
//     A class this package does not define is refused with
//     ErrInvalidClass.
//
// Clearing an already-cleared tool is idempotent, like Revoked on a
// pending tool: the operator asked for a state they already have.
func (t Tool) Cleared(now time.Time) (Tool, error) {
	if !t.Class.Valid() {
		return Tool{}, ErrInvalidClass
	}
	if t.Class == ClassSafe {
		return Tool{}, ErrNotSensitive
	}
	if t.Status != StatusApproved || t.ApprovedHash == "" {
		return Tool{}, ErrNotApproved
	}
	next := t
	next.SensitiveClearedHash = t.ApprovedHash
	next.UpdatedAt = now
	return next, nil
}

// ApprovedFingerprint is Approved with a precondition: the fingerprint
// being baselined must be reviewedHash, the one the operator actually
// looked at. Otherwise it returns ErrFingerprintMoved and no new state.
//
// It closes a review-then-approve race. Observed leaves a pending tool
// pending while it replaces ObservedHash, so a discovery cycle landing
// between the operator's review and the approval used to have the approval
// baseline a definition no human saw -- and since the quarantine kept
// fingerprints, not definitions, nothing afterwards would show the switch.
// (Since ADR-0032 it keeps the definitions too, and the console shows the
// one being approved; the precondition is what ties that display to the
// write.)
// An upstream alternating a benign and a poisoned definition across
// refreshes could aim for exactly that window.
func (t Tool) ApprovedFingerprint(reviewedHash string, now time.Time) (Tool, error) {
	if t.ObservedHash != reviewedHash {
		return Tool{}, ErrFingerprintMoved
	}
	return t.Approved(now), nil
}

// NeedsReview reports whether t waits for a human: pending (never
// approved) or changed (approved, then rewritten). It is what the approval
// queue lists and what a review set is made of; it is not the gate --
// Usable is.
func (t Tool) NeedsReview() bool { return t.Status != StatusApproved }

// manifestDomainTag scopes a review-set manifest the way hashDomainTag
// scopes a tool fingerprint: a manifest can never be confused with, or
// replayed as, a fingerprint.
const manifestDomainTag = "mcp-gateway/quarantine/review-set/v1"

// ReviewSet returns the entries of tools that need review (NeedsReview),
// ordered by tool name: one backend's review set when tools are that
// backend's entries (design/adr/0043). It never returns nil.
func ReviewSet(tools []Tool) []Tool {
	set := []Tool{}
	for _, t := range tools {
		if t.NeedsReview() {
			set = append(set, t)
		}
	}
	slices.SortFunc(set, func(a, b Tool) int { return strings.Compare(a.ToolName, b.ToolName) })
	return set
}

// Manifest is the hex SHA-256 of serverName's review set: the backend name,
// the number of entries and, for each entry in tool-name order, its name,
// its status, the fingerprint it is advertising and the approved baseline
// it is compared against. It is what a bulk approval names instead of one
// fingerprint, and it changes when anything the operator was shown
// changes: a tool joining or leaving the set, any observed fingerprint,
// a status, or the baseline a diff was drawn against.
//
// Every field is length-prefixed (writeField), like Hash, so no two sets
// encode to the same bytes. set must be what ReviewSet returned; Manifest
// sorts its own copy anyway, so an unsorted slice cannot produce a
// different manifest for the same set.
func Manifest(serverName string, set []Tool) string {
	sorted := slices.Clone(set)
	slices.SortFunc(sorted, func(a, b Tool) int { return strings.Compare(a.ToolName, b.ToolName) })
	h := sha256.New()
	writeField(h, []byte(manifestDomainTag))
	writeField(h, []byte(serverName))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(sorted)))
	writeField(h, n[:])
	for _, t := range sorted {
		writeField(h, []byte(t.ToolName))
		writeField(h, []byte(t.Status))
		writeField(h, []byte(t.ObservedHash))
		writeField(h, []byte(t.ApprovedHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Approval is one entry of an approved review set: its state before and
// after.
type Approval struct {
	Before, After Tool
}

// ApprovedSet approves serverName's whole review set, drawn from tools,
// on the condition that it still hashes to manifest -- the one the
// operator was shown. It is ApprovedFingerprint for a set: either every
// entry of the set is approved at the fingerprint it had when reviewed,
// or ErrReviewSetMoved and nothing is. An empty set is ErrReviewSetEmpty:
// there is nothing an approval could be of.
//
// Entries of tools that belong to another server are ignored, so a caller
// cannot widen the set by passing more than one backend's entries.
func ApprovedSet(serverName string, tools []Tool, manifest string, now time.Time) ([]Approval, error) {
	var mine []Tool
	for _, t := range tools {
		if !t.Status.Valid() {
			return nil, ErrInvalidStatus
		}
		if t.ServerName == serverName {
			mine = append(mine, t)
		}
	}
	set := ReviewSet(mine)
	if len(set) == 0 {
		return nil, ErrReviewSetEmpty
	}
	if Manifest(serverName, set) != manifest {
		return nil, ErrReviewSetMoved
	}
	out := make([]Approval, 0, len(set))
	for _, t := range set {
		after, err := t.ApprovedFingerprint(t.ObservedHash, now)
		if err != nil {
			return nil, err
		}
		out = append(out, Approval{Before: t, After: after})
	}
	return out, nil
}

// Revoked returns the state t transitions to when an operator withdraws
// their own approval: back to pending, with the approved baseline cleared
// and the last observation kept.
//
// This is the other half of Approve, and ADR-0013 adds it because without
// it approval was a one-way door -- the only route back to pending was
// deleting the database, which is not an incident-response action. The
// obvious move during an incident is "I no longer trust this tool, stop
// serving it", and Usable is re-read on every list and every dispatch, so
// the effect lands on the very next call rather than at the next restart.
//
// Three details, each of them deliberate:
//
//   - ApprovedHash is cleared, not kept. A leftover baseline is what a
//     later observation would match against, and a revoked tool that
//     re-entered the usable set because its definition still hashed to the
//     withdrawn baseline would make the withdrawal meaningless.
//   - ObservedHash and FirstSeenAt survive. Revoking withdraws a judgement;
//     it does not un-see the tool, and pretending the gateway never
//     observed it would lose the discovery history an operator reads.
//   - A `changed` tool is REFUSED, with ErrChangedIsNotRevocable.
//   - SensitiveClearedHash goes with the baseline (ADR-0048). The natural
//     behaviour -- the clearance no longer matching an empty baseline --
//     would already make the tool unusable, but a kept clearance is what a
//     later re-approval at the same hash would match against, and a
//     revoked sensitive tool that came back usable on its old clearance
//     would make the withdrawal half-meaningless. Same argument as the
//     first bullet, one field over.
//
// That third one is the one worth arguing, because "revoke returns a tool to
// pending" reads as though it should apply to any state. It must not apply
// here. `changed` is not merely "not approved": under ADR-0007 rule 1 it is
// the standing record that a definition a human vetted was replaced
// afterwards, and it is what makes `mcp-gateway tool list` print its own
// alarm block. Moving it to pending would relabel a rug pull as a tool
// nobody has looked at yet -- erasing exactly the evidence rule 1 exists to
// preserve -- and it would buy nothing operationally, since a changed tool
// is already unusable. Refusing costs an operator nothing they wanted.
//
// Revoking a tool that is already pending is a no-op, not an error: an
// operator asking for a state they already have has not made a mistake.
func (t Tool) Revoked(now time.Time) (Tool, error) {
	if !t.Status.Valid() {
		return Tool{}, ErrInvalidStatus
	}
	if t.Status == StatusChanged {
		return Tool{}, ErrChangedIsNotRevocable
	}

	next := t
	next.Status = StatusPending
	next.ApprovedHash = ""
	next.SensitiveClearedHash = ""
	next.UpdatedAt = now
	return next, nil
}

// Store is the port through which the domain persists and retrieves
// quarantine state. Implementations are adapters (e.g. the sqlite
// subpackage) and must honor the contracts documented on each method.
//
// Implementations must not reimplement the state machine: Observe, Approve,
// Clear and Revoke are required to derive their result through NewTool,
// Tool.Observed, Tool.Approved, Tool.Cleared and Tool.Revoked, so the rules
// stay in one place.
type Store interface {
	// Observe records that tool t, of security class class, was seen on
	// serverName during discovery and returns the resulting state.
	//
	// class is metadata the caller derives from the operation (the
	// gateway's ToolDef, ADR-0048 Decisão 5); it is not part of t and not
	// part of the fingerprint. It is recorded on insert and re-recorded on
	// every later observation, per Tool.Observed. An undefined class is
	// refused with ErrInvalidClass and nothing is written.
	//
	// This is the method carrying the real logic. Its contract:
	//
	//   - If (serverName, t.Name) has never been seen, a new entry is
	//     inserted as pending with Hash(t) as the observed fingerprint and
	//     no approved baseline. Returned Tool.Usable() is false.
	//   - If it has been seen, the stored entry transitions per
	//     Tool.Observed: an approved tool whose hash still matches stays
	//     approved (and usable); an approved tool whose hash differs
	//     becomes changed (and not usable); a pending tool stays pending;
	//     a changed tool stays changed even if the hash reverts to the
	//     approved baseline.
	//   - The observed fingerprint is always updated to Hash(t), whatever
	//     the resulting status.
	//   - Observe is idempotent for an unchanged tool: calling it twice
	//     with the same identity leaves the same state.
	//   - Observe never approves anything and never clears anything. The
	//     only transition it can make into approved is none; only Approve
	//     does that, and only Clear clears. The one way an observation can
	//     widen the usable set is a class moving from sensitive to safe on
	//     an approved, uncleared tool -- and the class is registry metadata
	//     an operator registered and signed (ADR-0048 Decisão 2), not
	//     something the backend advertises at runtime.
	//
	//   - The definition t itself is kept, keyed by Hash(t), in the same
	//     transaction (design/adr/0032). A kept definition is never
	//     rewritten, and it stays for as long as some entry names it as its
	//     approved or observed fingerprint -- so an approved baseline can
	//     always be shown next to what replaced it -- and is dropped in the
	//     transaction that moves the last reference away. That bounds the
	//     store at two definitions per (server, tool).
	//   - The returned Observation carries the transition, per EventOf:
	//     EventFirstSeen for an insert, EventChanged for approved becoming
	//     changed, EventNone otherwise. It is decided on the row read inside
	//     the write transaction, so two concurrent observations cannot both
	//     report the same transition.
	//
	// It returns ErrInvalidStatus if the stored entry's status is not one
	// of the three defined states.
	Observe(ctx context.Context, serverName string, t ToolIdentity, class Class) (Observation, error)

	// Definition returns the definition that was observed with fingerprint
	// hash. It returns ErrDefinitionNotKept when none is stored -- a
	// baseline approved before definitions were kept -- and
	// ErrDefinitionMismatch when the stored one no longer hashes to hash.
	Definition(ctx context.Context, hash string) (ToolIdentity, error)

	// Approve records the currently-observed fingerprint of
	// (serverName, toolName) as its approved baseline and sets the status
	// to approved, returning the resulting state. It returns ErrNotFound
	// if no entry exists for that pair -- a tool must have been observed
	// before it can be approved, so an operator can only ever approve a
	// definition the gateway has actually seen, never one typed from
	// memory.
	Approve(ctx context.Context, serverName, toolName string) (Tool, error)

	// ApproveFingerprint is Approve with a compare-and-approve
	// precondition, checked in the same transaction as the write: it
	// approves only if the currently-observed fingerprint is still
	// reviewedHash, and otherwise returns ErrFingerprintMoved and changes
	// nothing. It is what the operator console uses, so that what gets
	// baselined is what the operator was shown (see
	// Tool.ApprovedFingerprint).
	ApproveFingerprint(ctx context.Context, serverName, toolName, reviewedHash string) (Tool, error)

	// ApproveReviewSet approves every entry of serverName's review set in
	// one transaction, per ApprovedSet, and only if the set read inside
	// that transaction still hashes to manifest. Otherwise it returns
	// ErrReviewSetMoved (or ErrReviewSetEmpty) and changes nothing
	// (design/adr/0043). The approvals come back in tool-name order.
	ApproveReviewSet(ctx context.Context, serverName, manifest string) ([]Approval, error)

	// Clear records the approved fingerprint of (serverName, toolName) as
	// its sensitive clearance and returns the resulting state, per
	// Tool.Cleared -- the second operator decision a ClassSensitive tool
	// needs before Usable answers true (design/adr/0048 Decisão 5).
	//
	// It returns ErrNotFound if no entry exists for that pair, and
	// Tool.Cleared's errors otherwise: ErrNotApproved for a tool with no
	// approved baseline, ErrNotSensitive for a ClassSafe tool,
	// ErrInvalidClass for a class the domain does not define. The read and
	// the write share one transaction, so a discovery cycle that moves the
	// tool to changed in between cannot have its new fingerprint cleared.
	//
	// Clear is the only transition that can take a sensitive tool into the
	// usable set, and it can only do so for a tool that Approve already
	// baselined. Whether a role may reach the tool is not its question;
	// the gateway asks that on every call (ADR-0048, the other half).
	Clear(ctx context.Context, serverName, toolName string) (Tool, error)

	// Revoke returns (serverName, toolName) to pending and returns the
	// resulting state, per Tool.Revoked -- an operator withdrawing an
	// approval they themselves gave.
	//
	// It returns ErrNotFound if no entry exists for that pair, and
	// ErrChangedIsNotRevocable for a tool whose status is StatusChanged.
	// Read Tool.Revoked for why a changed tool is refused; the short
	// version is that `changed` is evidence of a rug pull, revoking it
	// would relabel that evidence as "never reviewed", and the tool is
	// already not being served.
	//
	// Revoke never widens the usable set: every state it can produce is
	// pending, and pending is never usable.
	Revoke(ctx context.Context, serverName, toolName string) (Tool, error)

	// Forget removes every quarantine entry belonging to serverName and
	// returns how many were removed.
	//
	// It exists for one caller -- `mcp-gateway upstream deregister` -- and
	// for one reason: quarantine state is keyed by upstream *name*, so
	// without this it outlives the entry it describes and a replacement
	// registered under the same name inherits approvals a human gave to
	// something else. That was reproduced on the live deployment: an
	// upstream removed and re-registered with a different command, a
	// different credential list and a new signature had all three of its
	// tools still approved and servable the moment it came up. It is the
	// same lesson as ADR-0006 item 3 (the stored signature is deleted with
	// the entry for exactly this reason) and this is the same fix.
	//
	// Note what it does NOT protect against: the fingerprint cannot tell a
	// replacement advertising byte-identical definitions from the original,
	// because it is a hash of those definitions and they are identical.
	// Removal, not detection, is what covers that case -- which is why the
	// test for this is written with identical definitions.
	//
	// Removing entries for a server that has none is not an error: it
	// returns 0. Deregistering an upstream the gateway never connected to
	// is an ordinary thing to do, and an error there would put a scary line
	// in front of a routine action.
	//
	// Forget is destructive and irreversible: it discards approvals,
	// baselines, first-seen timestamps and any standing `changed` verdict.
	// Everything the deregistered upstream advertises next is seen for the
	// first time again, and starts pending.
	Forget(ctx context.Context, serverName string) (int, error)

	// Get returns the quarantine entry for (serverName, toolName). It
	// returns ErrNotFound if no entry exists for that pair,
	// ErrInvalidStatus if the stored status is not one of the three
	// defined states, and ErrInvalidClass if the stored class is not one
	// of the two defined classes.
	Get(ctx context.Context, serverName, toolName string) (Tool, error)

	// List returns quarantine entries ordered by server name then tool
	// name. When serverName is non-empty, only that server's entries are
	// returned; when it is empty, entries across all servers are.
	//
	// List returns every entry regardless of status, including pending
	// and changed ones -- an operator has to be able to see what is
	// waiting for approval in order to approve it. Callers that are
	// serving a *client* rather than the operator must filter the result
	// by Tool.Usable; List deliberately does not do it for them, because a
	// List that silently hid unusable tools would give the Operator
	// Console no way to show them.
	//
	// When nothing matches, List returns an empty, non-nil slice and a nil
	// error -- an empty quarantine is not an error condition.
	List(ctx context.Context, serverName string) ([]Tool, error)
}
