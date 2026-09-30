package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Review sets (design/adr/0043): one backend's pending and changed tools,
// reviewed on one page and approved in one act. The act names a manifest,
// the hash of exactly the set that was shown (quarantine.Manifest), the way
// a single approval names a fingerprint; the store approves all of it in
// one transaction only while the set still hashes to it. There is no
// "approve everything" without a manifest, and a manifest is only ever
// handed out next to every definition it covers.

// NormalizeManifest drops the "sha256:" prefix and surrounding space.
func NormalizeManifest(m string) string { return NormalizeFingerprint(m) }

// listServer reads every entry of one backend, refusing an empty name and
// a backend the quarantine has never seen.
func (s *Service) listServer(ctx context.Context, server string) ([]quarantine.Tool, error) {
	if err := need(s.d.Tools != nil, "tool quarantine"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(server) == "" {
		return nil, adminapi.NewError(adminapi.CodeInvalidArgument, "server is required: a review set is one backend's").With("field", "server")
	}
	tools, err := s.d.Tools.List(ctx, server)
	if err != nil {
		return nil, s.storeErr("quarantine", err)
	}
	if len(tools) == 0 {
		return nil, adminapi.NewError(adminapi.CodeNotFound, "no tool has been observed on backend %q", visible.Escape(server))
	}
	return tools, nil
}

// ReviewToolSet is every tool of server that waits for review, each as
// ReviewTool shows it, from ONE read of the backend's entries, and the
// manifest of that set. Definitions are content-addressed, so reading them
// after the entries cannot show anything but what the entries name.
func (s *Service) ReviewToolSet(ctx context.Context, server string) (adminapi.ToolReviewSet, error) {
	out := adminapi.ToolReviewSet{Server: server, Tools: []adminapi.ToolReview{}}
	cfg, err := s.config()
	if err != nil {
		return out, err
	}
	tools, err := s.listServer(ctx, server)
	if err != nil {
		return out, err
	}
	set := quarantine.ReviewSet(tools)
	unkept := []string{}
	for _, t := range set {
		rv, err := s.reviewOf(ctx, cfg, t)
		if err != nil {
			return out, err
		}
		switch t.Status {
		case quarantine.StatusChanged:
			out.Changed++
		default:
			out.Pending++
		}
		out.HiddenCodePoints += rv.Observed.HiddenCodePoints
		if !rv.Observed.Kept {
			unkept = append(unkept, visible.Escape(t.ToolName))
		}
		out.Tools = append(out.Tools, rv)
	}
	if len(set) == 0 {
		out.Reason = fmt.Sprintf("Nothing on %s is waiting for review.", visible.Escape(server))
		return out, nil
	}
	out.Manifest = quarantine.Manifest(server, set)
	out.Approvable = len(unkept) == 0
	if !out.Approvable {
		out.Reason = fmt.Sprintf("The definition %s %s advertising was not kept, so it cannot be shown and the set cannot be approved; the next discovery stores it.",
			strings.Join(unkept, ", "), plural(len(unkept), "is", "are"))
	}
	return out, nil
}

// ApproveToolSet approves server's review set -- every pending and changed
// tool of it -- if and only if it is still the set req.Manifest names,
// in one transaction. One tool joining, leaving or moving since the review
// refuses all of them. Writes one (tool approve) row per tool and one
// (tool approve set) row for the act.
func (s *Service) ApproveToolSet(ctx context.Context, a Actor, req adminapi.ApproveSetRequest) (adminapi.ApproveSetResult, error) {
	res := adminapi.ApproveSetResult{ActionResult: newResult(), Server: req.Server, Approved: []adminapi.ApprovedTool{}, Rows: []adminapi.OperatorRow{}}
	if err := checkActor(a); err != nil {
		return res, err
	}
	reviewed := NormalizeManifest(req.Manifest)
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tools, err := s.listServer(ctx, req.Server)
	if err != nil {
		return res, err
	}
	backend := visible.Escape(req.Server)
	set := quarantine.ReviewSet(tools)
	current := ""
	if len(set) > 0 {
		current = quarantine.Manifest(req.Server, set)
	}
	if reviewed == "" {
		e := adminapi.NewError(adminapi.CodeManifestRequired, "approving a review set needs the manifest of the set that was reviewed")
		if current != "" {
			e = e.With("manifest", current)
		}
		return res, e
	}
	if len(set) == 0 {
		res.Messages = append(res.Messages, fmt.Sprintf("Nothing on %s is waiting for review. Nothing was approved.", backend))
		return res, nil
	}
	if reviewed != current {
		return res, adminapi.NewError(adminapi.CodeManifestMismatch, "the tools of %s waiting for review are not the set that was reviewed: they hash to sha256:%s, not sha256:%s; review them again", backend, current, visible.Escape(reviewed)).
			With("manifest", current)
	}
	for _, t := range set {
		if _, err := s.d.Tools.Definition(ctx, t.ObservedHash); err != nil {
			if errors.Is(err, quarantine.ErrDefinitionNotKept) {
				return res, adminapi.NewError(adminapi.CodeDefinitionUnavailable, "the definition %s is advertising was not kept, so it cannot be shown and the set cannot be approved; the next discovery stores it",
					visible.Escape(t.ServerName+"."+t.ToolName))
			}
			return res, s.storeErr("quarantine definition", err)
		}
	}

	var approvals []quarantine.Approval
	err = s.retryBusy(ctx, func() (err error) {
		approvals, err = s.d.Tools.ApproveReviewSet(ctx, req.Server, current)
		return err
	})
	if errors.Is(err, quarantine.ErrReviewSetMoved) || errors.Is(err, quarantine.ErrReviewSetEmpty) {
		return res, adminapi.NewError(adminapi.CodeManifestMismatch, "the tools of %s waiting for review changed while they were being approved; nothing was approved; review them again", backend)
	}
	if err != nil {
		return res, s.storeErr("approving the review set of "+backend, err)
	}
	res.Changed = true
	res.Manifest = current

	var pending, changed int
	var uncovered []string
	wildcard := ""
	for _, ap := range approvals {
		if !ap.After.Usable() {
			return res, adminapi.NewError(adminapi.CodeInternal, "%s is still not usable after approval (status %s); this is a bug",
				visible.Escape(ap.After.ServerName+"."+ap.After.ToolName), ap.After.Status)
		}
		item := adminapi.ApprovedTool{PreviousStatus: string(ap.Before.Status), Tool: ToolOf(ap.After),
			CallableBy: CallableBy(cfg.Roles, ap.After.ServerName, ap.After.ToolName)}
		if ap.Before.Status == quarantine.StatusChanged {
			changed++
			item.PreviousBaseline = ap.Before.ApprovedHash
		} else {
			pending++
		}
		if len(item.CallableBy) == 0 {
			uncovered = append(uncovered, visible.Escape(ap.After.ToolName))
		}
		for _, c := range item.CallableBy {
			if c.Wildcard && wildcard == "" {
				wildcard = c.Role
			}
		}
		res.Approved = append(res.Approved, item)
	}
	n := len(approvals)
	res.Messages = append(res.Messages, fmt.Sprintf("Approved %d %s of %s at exactly the definitions shown (review set sha256:%s): %d new, %d changed. A later change to any of them marks it changed and stops it being served.",
		n, plural(n, "tool", "tools"), backend, current, pending, changed))
	if changed > 0 {
		res.Messages = append(res.Messages, fmt.Sprintf("%d of them %s approved at a NEW definition; the previous baselines are no longer accepted.", changed, plural(changed, "was", "were")))
	}
	if len(uncovered) > 0 {
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnNoRoleGrants,
			Message: "No configured role covers " + strings.Join(uncovered, ", ") + ": approving made them servable, not callable by anyone."})
	}
	if wildcard != "" {
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnWildcardGrant,
			Message: "A \"*\" grant covers these tools: this approval is the only human act between them and every analyst in role " + wildcard + " (design/adr/0016)."})
	}

	now := s.d.Now().UTC()
	var lost []string
	for _, ap := range approvals {
		reason := fmt.Sprintf("tool %q approved at sha256:%s", ap.After.ServerName+"."+ap.After.ToolName, ap.After.ApprovedHash)
		if ap.Before.ApprovedHash != "" && ap.Before.ApprovedHash != ap.After.ApprovedHash {
			reason += " (was sha256:" + ap.Before.ApprovedHash + ")"
		}
		reason += " in review set sha256:" + current + " " + a.Tag()
		rec := s.operatorRow(a, ToolApprove, reason, now)
		if err := s.retryBusy(ctx, func() error { return s.d.Record(ctx, cfg, rec) }); err != nil {
			lost = append(lost, err.Error())
			continue
		}
		res.Rows = append(res.Rows, adminapi.OperatorRow{Identity: rec.AnalystIdentity, Tool: rec.Tool, Reason: rec.Reason, Timestamp: rec.Timestamp})
	}
	summary := fmt.Sprintf("review set sha256:%s of backend %q approved: %d %s (%d pending, %d changed) %s",
		current, req.Server, n, plural(n, "tool", "tools"), pending, changed, a.Tag())
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, ToolApproveSet, summary, now))
	if len(lost) > 0 {
		res.Recorded = false
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnAuditWriteFailed,
			Message: fmt.Sprintf("The approvals are in force and %d of the %d per-tool rows are not in the audit trail: %s", len(lost), n, lost[0])})
		res.Messages = append(res.Messages, "The approvals were made, but the audit trail could not record all of them. Record them by hand before anything else.")
		s.d.Log.Warn("admin: per-tool approval rows not recorded", "server", req.Server, "lost", len(lost), "detail", lost[0])
	}
	return res, nil
}
