package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// ListBlocks returns the blocklist.
func (s *Service) ListBlocks(ctx context.Context) (adminapi.BlockList, error) {
	if err := need(s.d.Blocks != nil, "blocklist"); err != nil {
		return adminapi.BlockList{}, err
	}
	bs, err := s.d.Blocks.Blocks(ctx)
	if err != nil {
		return adminapi.BlockList{}, s.storeErr("blocklist", err)
	}
	out := adminapi.BlockList{Blocks: []adminapi.Block{}}
	now := s.d.Now()
	for _, b := range bs {
		out.Blocks = append(out.Blocks, BlockOf(b, now))
	}
	return out, nil
}

// BlockOf is the contract's view of a block at now: its end, when it has
// one, and whether that end has passed (design/adr/0046).
func BlockOf(b access.Block, now time.Time) adminapi.Block {
	v := adminapi.Block{Subject: b.Subject, BlockedBy: b.By, BlockedAt: b.At, Reason: b.Reason}
	if !b.Until.IsZero() {
		until := b.Until.UTC()
		v.Until, v.Expired = &until, !b.ActiveAt(now)
	}
	return v
}

// activeBlocks is the subjects blocked at now; an expired block blocks
// nobody and is not counted.
func activeBlocks(bs []access.Block, now time.Time) map[string]bool {
	out := map[string]bool{}
	for _, b := range bs {
		if b.ActiveAt(now) {
			out[b.Subject] = true
		}
	}
	return out
}

// BlockNote is the note a block carries, and the blocklist's REASON: the
// actor's tag, then the operator's reason. Its length is what the
// blocklist bounds, so an early check validates this, not the raw reason.
func BlockNote(a Actor, reason string) string {
	note := a.Tag()
	if r := strings.TrimSpace(reason); r != "" {
		note += " " + r
	}
	return note
}

// BlockReason is an operator row's Reason for a block or an unblock: the
// subject acted on, quoted so a subject that looks like prose cannot be
// misread, then the note.
func BlockReason(subject, note string) string {
	return BlockReasonUntil(subject, time.Time{}, note)
}

// BlockReasonUntil is BlockReason for a block with an end, which the row
// states (design/adr/0046): the expiry is on the trail from the moment the
// block is placed.
func BlockReasonUntil(subject string, until time.Time, note string) string {
	r := fmt.Sprintf("subject %q", subject)
	if !until.IsZero() {
		r += " until " + until.UTC().Format(time.RFC3339)
	}
	if note != "" {
		r += ": " + note
	}
	return r
}

// ReplacedBlockReason is the (access block) row's Reason when the block
// replaces one that had ended but was not yet recorded as expired
// (design/adr/0046): the end of that block, who placed it and when, so the
// trail keeps its end.
func ReplacedBlockReason(reason string, old access.Block) string {
	return fmt.Sprintf("%s [replaces the expired block placed by %s at %s, ended %s]", reason,
		old.By, old.At.UTC().Format(time.RFC3339), old.Until.UTC().Format(time.RFC3339))
}

// expiredBlockOf is the stored block on subject when it has ended at now,
// or nil when there is none or it is still in force.
func (s *Service) expiredBlockOf(ctx context.Context, subject string, now time.Time) (*access.Block, error) {
	var bs []access.Block
	if err := s.retryBusy(ctx, func() (err error) {
		bs, err = s.d.Blocks.Blocks(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	for _, b := range bs {
		if b.Subject == subject && !b.ActiveAt(now) {
			return &b, nil
		}
	}
	return nil, nil
}

// validateBlock validates a request before anything is opened, so a typo
// costs nothing and is never recorded.
func (s *Service) validateBlock(a Actor, req adminapi.BlockRequest) (string, error) {
	if err := checkActor(a); err != nil {
		return "", err
	}
	if err := access.ValidateSubject(req.Subject); err != nil {
		return "", adminapi.NewError(adminapi.CodeInvalidArgument, "%v", err).With("field", "subject")
	}
	note := BlockNote(a, req.Reason)
	if err := access.ValidateBlock(access.Block{Subject: req.Subject, Reason: note, By: a.Name, At: s.d.Now()}); err != nil {
		return "", adminapi.NewError(adminapi.CodeInvalidArgument, "%v", err).With("field", "reason")
	}
	if req.Until != nil && !req.Until.After(s.d.Now()) {
		return "", adminapi.NewError(adminapi.CodeInvalidArgument, "until %s is not in the future; a block that ended before it began would block nobody",
			req.Until.UTC().Format(time.RFC3339)).With("field", "until")
	}
	return note, nil
}

// Block places the block FIRST and records it second (design/adr/0031): if
// the row cannot be written the block stays, and the answer says so.
// Writes (access block).
func (s *Service) Block(ctx context.Context, a Actor, req adminapi.BlockRequest) (adminapi.BlockResult, error) {
	res := adminapi.BlockResult{ActionResult: newResult(), Subject: req.Subject}
	note, err := s.validateBlock(a, req)
	if err != nil {
		return res, err
	}
	if err := need(s.d.Blocks != nil, "blocklist"); err != nil {
		return res, err
	}
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := blockOutcome{ActionResult: res.ActionResult}
	s.placeBlock(ctx, cfg, a, req, note, &out)
	res.ActionResult = out.ActionResult
	return res, out.err
}

// placeBlock is Block under the lock: place, then record, then check the
// trail for the subject. A failure to place is res.err, and nothing else
// happened.
func (s *Service) placeBlock(ctx context.Context, cfg *config.Config, a Actor, req adminapi.BlockRequest, note string, res *blockOutcome) {
	now := s.d.Now().UTC()
	b := access.Block{Subject: req.Subject, Reason: note, By: a.Name, At: now}
	if req.Until != nil {
		b.Until = req.Until.UTC()
	}
	// A block that has ended and not yet been recorded as expired is
	// replaced by this one (BlockStore.Block), and then the gateway's round
	// never sees it: without a word here, the trail would show a block
	// with an end and then a second block, and never the end of the first
	// (measured on the test bed, 30 Sep 2026). The new row names the block
	// it replaces.
	replaced, err := s.expiredBlockOf(ctx, req.Subject, now)
	if err != nil {
		res.err = s.storeErr("blocklist", err)
		return
	}
	var placed bool
	if err := s.retryBusy(ctx, func() (err error) {
		placed, err = s.d.Blocks.Block(ctx, b)
		return err
	}); err != nil {
		res.err = s.storeErr("blocklist", err)
		return
	}
	if !placed {
		msg := fmt.Sprintf("%s is already blocked; nothing changed and nothing was recorded.", req.Subject)
		if req.Until != nil {
			msg += " The block in force keeps its own end; to give it another, unblock and block again."
		}
		res.Messages = append(res.Messages, msg)
		return
	}
	res.Changed = true
	msg := fmt.Sprintf("Blocked %s. The running gateway refuses it from its next request, whatever token it carries; no restart is needed. This does not revoke anything at the IdP: revoke the session there too.", req.Subject)
	if !b.Until.IsZero() {
		msg += fmt.Sprintf(" The block ends by itself at %s: from then on the gateway serves %s again, and records the expiry as %s at its next round.",
			b.Until.Format(time.RFC3339), req.Subject, AccessBlockExpired)
	}
	res.Messages = append(res.Messages, msg)
	reason := BlockReasonUntil(req.Subject, b.Until, note)
	if replaced != nil {
		reason = ReplacedBlockReason(reason, *replaced)
		res.Messages = append(res.Messages, fmt.Sprintf("This replaces a block on %s that had ended at %s and was not yet recorded as expired; the row says so.",
			req.Subject, replaced.Until.UTC().Format(time.RFC3339)))
	}
	row := s.operatorRow(a, AccessBlock, reason, now)
	s.record(ctx, cfg, &res.ActionResult, row)
	if res.Recorded {
		res.row = res.Audit
	}
	if s.d.Trail != nil {
		seen, err := s.d.Trail.HasAnalyst(ctx, req.Subject)
		switch {
		case err != nil:
			res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnNeverSeen, Message: "Could not check the trail for this subject: " + err.Error()})
		case !seen:
			res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnNeverSeen,
				Message: "No request from this subject is on record; check the spelling against the audit trail. The block is in force either way."})
		}
	}
}

// blockOutcome is what placeBlock leaves: the answer's ActionResult, the
// row it wrote (nil if none), and the error that stopped it before
// anything changed.
type blockOutcome struct {
	adminapi.ActionResult
	row *adminapi.OperatorRow
	err error
}

// Unblock records FIRST and lifts second -- the reverse of Block, for the
// same reason: the subject stays blocked on every failure. An unblock the
// trail cannot record is not performed. Writes (access unblock).
func (s *Service) Unblock(ctx context.Context, a Actor, req adminapi.BlockRequest) (adminapi.BlockResult, error) {
	res := adminapi.BlockResult{ActionResult: newResult(), Subject: req.Subject}
	note, err := s.validateBlock(a, req)
	if err != nil {
		return res, err
	}
	if err := need(s.d.Blocks != nil, "blocklist"); err != nil {
		return res, err
	}
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Present, not enforced: an expired block (design/adr/0046) is still a
	// row an operator may clear before the gateway's round does.
	bs, err := s.d.Blocks.Blocks(ctx)
	if err != nil {
		return res, s.storeErr("blocklist", err)
	}
	blocked := false
	for _, b := range bs {
		blocked = blocked || b.Subject == req.Subject
	}
	if !blocked {
		res.Messages = append(res.Messages, fmt.Sprintf("%s is not blocked; nothing changed and nothing was recorded.", req.Subject))
		return res, nil
	}
	now := s.d.Now().UTC()
	rec := s.operatorRow(a, AccessUnblock, BlockReason(req.Subject, note), now)
	if err := s.retryBusy(ctx, func() error { return s.d.Record(ctx, cfg, rec) }); err != nil {
		e := s.storeErr("audit trail", err)
		if ae, ok := e.(*adminapi.Error); ok {
			ae.Message = "not unblocked: the audit trail could not record it (" + ae.Message + "); " + req.Subject + " stays blocked"
		}
		return res, e
	}
	if err := s.retryBusy(ctx, func() error {
		_, err := s.d.Blocks.Unblock(ctx, req.Subject)
		return err
	}); err != nil {
		return res, adminapi.NewError(adminapi.CodeInternal, "blocklist: %v; the trail records an unblock that did not take effect: %s is STILL blocked", err, req.Subject)
	}
	res.Changed, res.Recorded = true, true
	res.Audit = &adminapi.OperatorRow{Identity: rec.AnalystIdentity, Tool: rec.Tool, Reason: rec.Reason, Timestamp: rec.Timestamp}
	res.Messages = append(res.Messages, fmt.Sprintf("Unblocked %s. The running gateway serves it again from its next request.", req.Subject),
		fmt.Sprintf("Recorded in the audit trail as %s by %s.", rec.Tool, rec.AnalystIdentity))
	return res, nil
}
