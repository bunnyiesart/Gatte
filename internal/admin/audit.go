package admin

import (
	"context"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Audit limits.
const (
	DefaultAuditLimit = 200
	MaxAuditLimit     = 5000
)

// RecordOf is the contract's view of a record at a chain position.
func RecordOf(pos int, r audit.Record) adminapi.AuditRecord {
	return adminapi.AuditRecord{Position: pos, Timestamp: r.Timestamp, AnalystIdentity: r.AnalystIdentity, AnalystName: r.AnalystName,
		Tool: r.Tool, TargetUpstream: r.TargetUpstream, Outcome: string(r.Outcome), Reason: r.Reason, SourceAddress: r.SourceAddress}
}

// Audit returns the newest q.Limit records matching q, oldest first, each
// with its chain position; More and NextBefore walk further back. Subject
// matches analyst_identity only, never the display name (design/adr/0037).
func (s *Service) Audit(ctx context.Context, q adminapi.AuditQuery) (adminapi.AuditPage, error) {
	if err := need(s.d.Trail != nil, "audit trail"); err != nil {
		return adminapi.AuditPage{}, err
	}
	if q.Outcome != "" && !audit.Outcome(q.Outcome).Valid() {
		return adminapi.AuditPage{}, adminapi.NewError(adminapi.CodeBadRequest, "outcome must be allowed, denied or failed").With("field", "outcome")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultAuditLimit
	}
	limit = min(limit, MaxAuditLimit)
	recs, more, err := s.d.Trail.Page(ctx, audit.TrailQuery{Before: q.Before, Since: q.Since, Subject: q.Subject, Outcome: q.Outcome, Source: q.Source, Limit: limit})
	if err != nil {
		return adminapi.AuditPage{}, s.storeErr("audit trail", err)
	}
	page := adminapi.AuditPage{Records: []adminapi.AuditRecord{}, Limit: limit, More: more}
	for i := len(recs) - 1; i >= 0; i-- {
		page.Records = append(page.Records, RecordOf(recs[i].Position, recs[i].Record))
	}
	if page.More && len(page.Records) > 0 {
		page.NextBefore = page.Records[0].Position
	}
	return page, nil
}

// VerifyAudit walks the chain and, when given, compares the head. It
// writes nothing: a new row would move the head it just compared.
func (s *Service) VerifyAudit(ctx context.Context, req adminapi.VerifyRequest) (adminapi.VerifyResult, error) {
	if err := need(s.d.Trail != nil, "audit trail"); err != nil {
		return adminapi.VerifyResult{}, err
	}
	cfg, err := s.config()
	if err != nil {
		return adminapi.VerifyResult{}, err
	}
	check, err := s.d.Trail.VerifyChain(ctx)
	if err != nil {
		return adminapi.VerifyResult{}, s.storeErr("audit trail", err)
	}
	res := adminapi.VerifyResult{Intact: check.FirstBreak == nil, Count: check.Count, Head: check.Head,
		Empty: check.Head == audit.GenesisHash, RetroactivelyChained: check.RetroactivelyChained}
	if b := check.FirstBreak; b != nil {
		res.FirstBreak = &adminapi.ChainBreak{Position: b.Position, Record: RecordOf(b.Position, b.Record), HashExpected: b.Want, HashStored: b.Got}
		res.Messages = append(res.Messages, "TAMPERED: a record at or before this position was edited or removed. Records after it are not re-verified against it, so this is the earliest damage, not necessarily the only damage.")
	} else {
		res.Messages = append(res.Messages, "An intact chain rules out an edit that did not recompute the hashes after it. It does NOT rule out an edit followed by a re-chain: compare the head against a value recorded where this gateway cannot write.")
	}
	if want := strings.TrimSpace(req.ExpectHead); want != "" {
		m := strings.EqualFold(want, check.Head)
		res.HeadMatches = &m
		if !m {
			res.Messages = append(res.Messages, "TRUNCATED OR REWRITTEN: the head does not match the expected value.")
		}
	}
	if cfg.Audit.SIEM.Enabled() {
		res.SIEM = &adminapi.SIEMAnchor{Path: cfg.Audit.SIEM.Path, Chain: cfg.Audit.SIEM.Chain}
	}
	return res, nil
}
