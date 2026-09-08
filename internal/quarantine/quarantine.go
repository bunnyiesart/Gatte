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
// (docs/context/05-testabilidade-e-contratos.md), this package
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
)

// hashDomainTag is mixed into every Hash as its first length-prefixed
// field. It scopes the digest to this component and this encoding version:
// a hash produced here can never be confused with, or replayed as, a
// digest computed elsewhere in the project (the Definition Signer hashes
// registry entries with its own scheme), and changing the encoding later
// means bumping the version here rather than silently producing digests
// that collide with the old scheme's.
const hashDomainTag = "mcp-gateway/quarantine/tool-identity/v1"

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
	writeField(h, []byte(hashDomainTag))
	writeField(h, []byte(t.Name))
	writeField(h, []byte(t.Description))
	writeField(h, t.InputSchema)
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
func (t Tool) Usable() bool {
	return t.Status == StatusApproved &&
		t.ApprovedHash != "" &&
		t.ObservedHash == t.ApprovedHash
}

// NewTool returns the quarantine state of a tool being seen for the very
// first time: pending, with observedHash recorded and no approved
// baseline. A tool never starts usable -- onboarding a new upstream server
// means every one of its tools waits for explicit human approval
// (design/adr/0003, "servidor novo -> toda tool nasce pending").
func NewTool(serverName, toolName, observedHash string, now time.Time) Tool {
	return Tool{
		ServerName:   serverName,
		ToolName:     toolName,
		Status:       StatusPending,
		ApprovedHash: "",
		ObservedHash: observedHash,
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
// UpdatedAt is advanced to now on every observation; FirstSeenAt never
// moves. Observed returns ErrInvalidStatus if t.Status is not one of the
// three defined states.
func (t Tool) Observed(observedHash string, now time.Time) (Tool, error) {
	if !t.Status.Valid() {
		return Tool{}, ErrInvalidStatus
	}

	next := t
	next.ObservedHash = observedHash
	next.UpdatedAt = now

	if t.Status == StatusApproved && observedHash != t.ApprovedHash {
		next.Status = StatusChanged
	}
	return next, nil
}

// Approved returns the state t transitions to when an operator approves
// it: status approved, with the currently-observed fingerprint recorded as
// the new baseline. Re-approving a changed tool is the supported way to
// accept a legitimate upstream update -- the new definition becomes the
// baseline the next rug pull is detected against.
func (t Tool) Approved(now time.Time) Tool {
	next := t
	next.Status = StatusApproved
	next.ApprovedHash = t.ObservedHash
	next.UpdatedAt = now
	return next
}

// Store is the port through which the domain persists and retrieves
// quarantine state. Implementations are adapters (e.g. the sqlite
// subpackage) and must honor the contracts documented on each method.
//
// Implementations must not reimplement the state machine: Observe and
// Approve are required to derive their result through NewTool,
// Tool.Observed and Tool.Approved, so the rules stay in one place.
type Store interface {
	// Observe records that tool t was seen on serverName during discovery
	// and returns the resulting state.
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
	//   - Observe never approves anything and never widens the usable set.
	//     The only transition it can make into approved is none; only
	//     Approve does that.
	//
	// It returns ErrInvalidStatus if the stored entry's status is not one
	// of the three defined states.
	Observe(ctx context.Context, serverName string, t ToolIdentity) (Tool, error)

	// Approve records the currently-observed fingerprint of
	// (serverName, toolName) as its approved baseline and sets the status
	// to approved, returning the resulting state. It returns ErrNotFound
	// if no entry exists for that pair -- a tool must have been observed
	// before it can be approved, so an operator can only ever approve a
	// definition the gateway has actually seen, never one typed from
	// memory.
	Approve(ctx context.Context, serverName, toolName string) (Tool, error)

	// Get returns the quarantine entry for (serverName, toolName). It
	// returns ErrNotFound if no entry exists for that pair, and
	// ErrInvalidStatus if the stored status is not one of the three
	// defined states.
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
