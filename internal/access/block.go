package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// The per-analyst kill switch (design/adr/0031-bloqueio-imediato-por-analista.md).
//
// A token stays valid until its `exp`, and the IdP decides how long that
// is. Revoking an analyst at the IdP therefore reaches this gateway only
// when the token they already hold expires -- up to its whole lifetime for
// a laptop that was stolen with a live session. A block is the operator's
// answer that does not wait: a row naming the subject, read on every
// request, effective on the next one, no restart.
//
// It is deliberately only a subject. Not a role and not an upstream: those
// already have their own reversible, reviewed levers (roles in the file,
// `tool revoke`, `upstream deregister`), and a second way to disable them
// would be a second answer to "why can nobody call this".

var (
	// ErrSubjectBlocked means the operator has blocked this subject. It
	// wraps ErrForbidden, so every surface that maps ErrForbidden to its
	// one constant "forbidden" answer maps this one to the same bytes: the
	// caller is told they may not, and never that it is a block, who
	// placed it or why.
	ErrSubjectBlocked = fmt.Errorf("%w: subject blocked", ErrForbidden)

	// ErrBlocklistUnavailable means the blocklist could not be read. The
	// request is refused, never waved through: a kill switch that turns
	// into a free pass when its table is unreadable is off exactly when
	// somebody has a reason to make it unreadable. It deliberately does
	// NOT wrap ErrForbidden -- which of this gateway's stores is unwell is
	// none of the caller's business, so it surfaces as an internal error.
	ErrBlocklistUnavailable = errors.New("access: blocklist unavailable")

	// ErrInvalidBlock is returned by ValidateBlock.
	ErrInvalidBlock = errors.New("access: invalid block")
)

// Block is one blocked subject, as the operator placed it.
type Block struct {
	// Subject is the IdP's `sub` claim, compared exactly against
	// Identity.Subject -- the value the audit trail's ANALYST column
	// carries, which is where an operator reads it from.
	Subject string
	// Reason is the operator's free-text note. Optional. Never shown to
	// the caller.
	Reason string
	// By is who placed the block: the operating-system user that ran the
	// console command. Attribution, not authentication -- see ADR-0031.
	By string
	// At is when the block was placed.
	At time.Time
	// Until, when set, is when the block stops being enforced by itself
	// (design/adr/0046 item 3). Zero is a block with no end: it holds
	// until an operator lifts it. From Until on, Blocked reports the
	// subject as not blocked; the row stays, listed as expired, until the
	// gateway records the expiry and removes it, or an operator unblocks.
	Until time.Time
}

// ActiveAt reports whether the block is enforced at t: it has no end, or
// its end is still after t.
func (b Block) ActiveAt(t time.Time) bool { return b.Until.IsZero() || t.Before(b.Until) }

// Blocklist is the port the request path holds: it can ask whether a
// subject is blocked, and nothing else. The Gateway cannot place or lift a
// block, for the same reason the quota split its ports -- the surface that
// serves analysts must not be one call away from changing who is served.
type Blocklist interface {
	// Blocked reports whether subject is currently blocked. An error means
	// the answer is unknown, and the caller must refuse.
	Blocked(ctx context.Context, subject string) (bool, error)
}

// BlockStore is the Operator Console's port: place, lift and read blocks.
type BlockStore interface {
	Blocklist
	// Block places b. It reports false, and changes nothing, when the
	// subject is already blocked -- the existing block, with its original
	// author and time, is what stays on record. A block that has expired
	// is not "already blocked": b replaces it.
	Block(ctx context.Context, b Block) (placed bool, err error)
	// Unblock lifts the block on subject. It reports false when there was
	// none.
	Unblock(ctx context.Context, subject string) (lifted bool, err error)
	// Blocks returns every stored block, oldest first, expired ones
	// included (Block.ActiveAt tells them apart).
	Blocks(ctx context.Context) ([]Block, error)
}

// BlockReplacer is a BlockStore that can also say, in the same step as the
// placement, which ended block the new one replaced (design/adr/0046,
// correction of 30 Sep 2026): a replaced block is never seen by the
// gateway's expiry round, so the row of the new block is the only place
// its end can be kept. replaced is nil when nothing was replaced.
type BlockReplacer interface {
	BlockReplacing(ctx context.Context, b Block) (placed bool, replaced *Block, err error)
}

// maxBlockText bounds a subject and a reason. Generous for any IdP's `sub`
// and for a sentence of context; small enough that the audit row and the
// console table stay legible.
const maxBlockText = 256

// ValidateSubject checks a subject an operator typed -- and, in the oidc
// adapter, the `sub` of every verified token, so that no identity gets in
// that `access block` could not name (design/adr/0031 §4).
//
// Whitespace at either end, control characters and invisible format
// characters (Unicode Cf: U+200B, a BOM, bidi overrides) are refused rather
// than trimmed: a block on "ana " or on "ana" plus a zero-width space
// pasted from a chat window would never match the token's "ana", and the
// operator would believe a subject blocked that is not. Control characters
// would also reach the operator's terminal through `audit` and `access
// list` verbatim.
func ValidateSubject(subject string) error {
	switch {
	case subject == "":
		return fmt.Errorf("%w: subject must not be empty", ErrInvalidBlock)
	case strings.TrimSpace(subject) != subject:
		return fmt.Errorf("%w: subject %q has leading or trailing whitespace", ErrInvalidBlock, subject)
	case len(subject) > maxBlockText:
		return fmt.Errorf("%w: subject is longer than %d bytes", ErrInvalidBlock, maxBlockText)
	case strings.IndexFunc(subject, unicode.IsControl) >= 0:
		return fmt.Errorf("%w: subject %q contains a control character", ErrInvalidBlock, subject)
	case strings.IndexFunc(subject, func(r rune) bool { return unicode.Is(unicode.Cf, r) }) >= 0:
		return fmt.Errorf("%w: subject %q contains an invisible format character", ErrInvalidBlock, subject)
	}
	return nil
}

// ValidateBlock checks b before it is stored.
func ValidateBlock(b Block) error {
	var errs []error
	if err := ValidateSubject(b.Subject); err != nil {
		errs = append(errs, err)
	}
	if len(b.Reason) > maxBlockText {
		errs = append(errs, fmt.Errorf("%w: reason is longer than %d bytes", ErrInvalidBlock, maxBlockText))
	}
	if strings.IndexFunc(b.Reason, unicode.IsControl) >= 0 {
		errs = append(errs, fmt.Errorf("%w: reason contains a control character", ErrInvalidBlock))
	}
	if strings.TrimSpace(b.By) == "" {
		errs = append(errs, fmt.Errorf("%w: a block must name who placed it", ErrInvalidBlock))
	}
	if b.At.IsZero() {
		errs = append(errs, fmt.Errorf("%w: a block must carry the time it was placed", ErrInvalidBlock))
	}
	if !b.Until.IsZero() && !b.Until.After(b.At) {
		errs = append(errs, fmt.Errorf("%w: a block's end must be after the time it was placed", ErrInvalidBlock))
	}
	return errors.Join(errs...)
}
