package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/access"
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
	for _, b := range bs {
		out.Blocks = append(out.Blocks, adminapi.Block{Subject: b.Subject, BlockedBy: b.By, BlockedAt: b.At, Reason: b.Reason})
	}
	return out, nil
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
	r := fmt.Sprintf("subject %q", subject)
	if note != "" {
		r += ": " + note
	}
	return r
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
	now := s.d.Now().UTC()
	var placed bool
	if err := s.retryBusy(ctx, func() (err error) {
		placed, err = s.d.Blocks.Block(ctx, access.Block{Subject: req.Subject, Reason: note, By: a.Name, At: now})
		return err
	}); err != nil {
		return res, s.storeErr("blocklist", err)
	}
	if !placed {
		res.Messages = append(res.Messages, fmt.Sprintf("%s is already blocked; nothing changed and nothing was recorded.", req.Subject))
		return res, nil
	}
	res.Changed = true
	res.Messages = append(res.Messages, fmt.Sprintf("Blocked %s. The running gateway refuses it from its next request, whatever token it carries; no restart is needed. This does not revoke anything at the IdP: revoke the session there too.", req.Subject))
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, AccessBlock, BlockReason(req.Subject, note), now))
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
	return res, nil
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
	blocked, err := s.d.Blocks.Blocked(ctx, req.Subject)
	if err != nil {
		return res, s.storeErr("blocklist", err)
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
