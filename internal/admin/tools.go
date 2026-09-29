package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// ToolOf is the contract's view of a quarantine entry. Usable is its own
// field: nothing re-derives that decision from the status.
func ToolOf(t quarantine.Tool) adminapi.Tool {
	return adminapi.Tool{Server: t.ServerName, Tool: t.ToolName, Status: string(t.Status), Usable: t.Usable(),
		ApprovedHash: t.ApprovedHash, ObservedHash: t.ObservedHash, FirstSeenAt: t.FirstSeenAt, UpdatedAt: t.UpdatedAt}
}

// ListTools returns the quarantine, filtered by server and show ("all",
// "review", "approved"); counts are over every entry of the server.
func (s *Service) ListTools(ctx context.Context, server, show string) (adminapi.ToolList, error) {
	if err := need(s.d.Tools != nil, "tool quarantine"); err != nil {
		return adminapi.ToolList{}, err
	}
	switch show {
	case "", "all", "review", "approved":
	default:
		return adminapi.ToolList{}, adminapi.NewError(adminapi.CodeBadRequest, "show must be all, review or approved").With("field", "show")
	}
	tools, err := s.d.Tools.List(ctx, server)
	if err != nil {
		return adminapi.ToolList{}, s.storeErr("quarantine", err)
	}
	out := adminapi.ToolList{Tools: []adminapi.Tool{}}
	for _, t := range tools {
		review := t.Status != quarantine.StatusApproved
		if review {
			out.Counts.Review++
		} else {
			out.Counts.Approved++
		}
		if show == "review" && !review || show == "approved" && review {
			continue
		}
		out.Tools = append(out.Tools, ToolOf(t))
	}
	out.Counts.All = len(tools)
	return out, nil
}

// getTool reads one entry, mapping the store's refusals.
func (s *Service) getTool(ctx context.Context, server, tool string) (quarantine.Tool, error) {
	if err := need(s.d.Tools != nil, "tool quarantine"); err != nil {
		return quarantine.Tool{}, err
	}
	if server == "" || tool == "" {
		return quarantine.Tool{}, adminapi.NewError(adminapi.CodeInvalidArgument, "server and tool are required").With("field", "server")
	}
	t, err := s.d.Tools.Get(ctx, server, tool)
	switch {
	case errors.Is(err, quarantine.ErrNotFound):
		return t, adminapi.NewError(adminapi.CodeNotFound, "no quarantine entry for tool %q on server %q: the gateway has never observed it", visible.Escape(tool), visible.Escape(server))
	case err != nil:
		return t, s.storeErr("quarantine", err)
	}
	return t, nil
}

// definitionOf is the contract's view of one stored definition.
func (s *Service) definitionOf(ctx context.Context, hash string) (adminapi.Definition, []Line, error) {
	d := adminapi.Definition{Fingerprint: hash}
	id, err := s.d.Tools.Definition(ctx, hash)
	if errors.Is(err, quarantine.ErrDefinitionNotKept) {
		return d, nil, nil
	}
	if err != nil {
		return d, nil, s.storeErr("quarantine definition", err)
	}
	lines, hidden := DefinitionLines(id)
	d.Kept = true
	d.Name = TextOf(id.Name)
	d.Description = MultilineTextOf(id.Description)
	d.InputSchema = rawJSON(id.InputSchema)
	d.OutputSchema = rawJSON(id.OutputSchema)
	d.HiddenCodePoints = hidden
	for _, l := range lines {
		d.Lines = append(d.Lines, adminapi.ReviewLine{Depth: l.Depth, Segments: Segments(l.Text)})
	}
	return d, lines, nil
}

// rawJSON is a schema exactly as advertised: the JSON value when it is
// JSON, its text otherwise, nothing when absent.
func rawJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	return string(b)
}

// ReviewTool is everything an approval decides on, read in one read of the
// entry: definitions, diff, hidden code points and the roles that can call
// the tool once approved.
func (s *Service) ReviewTool(ctx context.Context, server, tool string) (adminapi.ToolReview, error) {
	cfg, err := s.config()
	if err != nil {
		return adminapi.ToolReview{}, err
	}
	t, err := s.getTool(ctx, server, tool)
	if err != nil {
		return adminapi.ToolReview{}, err
	}
	rv := adminapi.ToolReview{Tool: ToolOf(t), CallableBy: CallableBy(cfg.Roles, t.ServerName, t.ToolName)}
	var text, errText bytes.Buffer
	WriteReview(ctx, s.d.Tools, &text, &errText, t)
	rv.ReviewText = strings.TrimRight(text.String()+errText.String(), "\n")

	obs, obsLines, err := s.definitionOf(ctx, t.ObservedHash)
	if err != nil {
		return rv, err
	}
	rv.Observed = obs
	if t.ApprovedHash != "" && t.ApprovedHash != t.ObservedHash {
		app, appLines, err := s.definitionOf(ctx, t.ApprovedHash)
		if err != nil {
			return rv, err
		}
		rv.Approved = &app
		if app.Kept && obs.Kept {
			if diff, err := LineDiff(appLines, obsLines); err == nil {
				rv.Diff = DiffHunks(diff, 1)
			}
		}
	}
	return rv, nil
}

// NormalizeFingerprint drops the "sha256:" prefix and surrounding space.
func NormalizeFingerprint(fp string) string {
	return strings.TrimPrefix(strings.TrimSpace(fp), "sha256:")
}

// ApproveTool approves server.tool at the fingerprint the operator was
// shown, and only at that one (design/adr/0032, 0040 §3). The write is
// compare-and-approve against the fingerprint this read saw, so a
// discovery landing between the read and the write cannot get a
// definition baselined that nobody was shown. Writes (tool approve).
func (s *Service) ApproveTool(ctx context.Context, a Actor, req adminapi.ApproveRequest) (adminapi.ApproveResult, error) {
	res := adminapi.ApproveResult{ActionResult: newResult()}
	if err := checkActor(a); err != nil {
		return res, err
	}
	reviewed := NormalizeFingerprint(req.Fingerprint)
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	before, err := s.getTool(ctx, req.Server, req.Tool)
	if err != nil {
		return res, err
	}
	res.PreviousStatus = string(before.Status)
	res.Tool = ToolOf(before)
	name := visible.Escape(before.ServerName + "." + before.ToolName)
	if reviewed == "" {
		return res, adminapi.NewError(adminapi.CodeFingerprintRequired, "approving needs the fingerprint of the definition that was reviewed").
			With("observed_fingerprint", before.ObservedHash)
	}
	if reviewed != before.ObservedHash {
		return res, adminapi.NewError(adminapi.CodeFingerprintMismatch, "%s is advertising sha256:%s, not the sha256:%s that was reviewed; review it again", name, before.ObservedHash, visible.Escape(reviewed)).
			With("observed_fingerprint", before.ObservedHash).With("status", string(before.Status))
	}
	res.CallableBy = CallableBy(cfg.Roles, before.ServerName, before.ToolName)
	if before.Status == quarantine.StatusApproved && before.Usable() {
		res.Messages = append(res.Messages, fmt.Sprintf("%s was already approved at exactly this definition (sha256:%s). Nothing to do; it is usable.", name, before.ObservedHash))
		return res, nil
	}
	if _, err := s.d.Tools.Definition(ctx, before.ObservedHash); err != nil {
		if errors.Is(err, quarantine.ErrDefinitionNotKept) {
			// A definition that is gone may have been replaced since the
			// read: that is the definition moving, not one never kept.
			if now, gerr := s.d.Tools.Get(ctx, before.ServerName, before.ToolName); gerr == nil && now.ObservedHash != before.ObservedHash {
				return res, adminapi.NewError(adminapi.CodeFingerprintMoved, "%s changed while it was being approved: it no longer advertises sha256:%s; review it again", name, before.ObservedHash).
					With("observed_fingerprint", now.ObservedHash)
			}
			return res, adminapi.NewError(adminapi.CodeDefinitionUnavailable, "the definition %s is advertising was not kept, so it cannot be shown and cannot be approved; the next discovery stores it", name)
		}
		return res, s.storeErr("quarantine definition", err)
	}

	var after quarantine.Tool
	err = s.retryBusy(ctx, func() (err error) {
		after, err = s.d.Tools.ApproveFingerprint(ctx, before.ServerName, before.ToolName, before.ObservedHash)
		return err
	})
	if errors.Is(err, quarantine.ErrFingerprintMoved) {
		return res, adminapi.NewError(adminapi.CodeFingerprintMoved, "%s changed while it was being approved: it no longer advertises sha256:%s; review it again", name, before.ObservedHash).
			With("observed_fingerprint", before.ObservedHash)
	}
	if err != nil {
		return res, s.storeErr("approving "+name, err)
	}
	res.Changed = true
	res.Tool = ToolOf(after)
	switch before.Status {
	case quarantine.StatusPending:
		res.Messages = append(res.Messages, fmt.Sprintf("Approved %s. sha256:%s is now the baseline; a change to its name, description or schemas marks it changed and stops it being served.", name, after.ApprovedHash))
	case quarantine.StatusChanged:
		res.PreviousBaseline = before.ApprovedHash
		res.Messages = append(res.Messages, fmt.Sprintf("Approved %s at its NEW definition. The previous baseline sha256:%s is no longer accepted.", name, before.ApprovedHash))
	default:
		res.Messages = append(res.Messages, fmt.Sprintf("Re-approved %s at sha256:%s.", name, after.ApprovedHash))
	}
	if len(res.CallableBy) == 0 {
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnNoRoleGrants,
			Message: "No configured role covers this tool: approving makes it servable, not callable by anyone."})
	}
	for _, c := range res.CallableBy {
		if c.Wildcard {
			res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnWildcardGrant,
				Message: "A \"*\" grant covers this tool: this approval is the only human act between it and every analyst in role " + c.Role + " (design/adr/0016)."})
			break
		}
	}
	if !after.Usable() {
		return res, adminapi.NewError(adminapi.CodeInternal, "%s is still not usable after approval (status %s); this is a bug", name, after.Status)
	}
	reason := fmt.Sprintf("tool %q approved at sha256:%s", before.ServerName+"."+before.ToolName, after.ApprovedHash)
	if before.ApprovedHash != "" && before.ApprovedHash != after.ApprovedHash {
		reason += " (was sha256:" + before.ApprovedHash + ")"
	}
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, ToolApprove, reason+" "+a.Tag(), s.d.Now().UTC()))
	return res, nil
}

// RevokeTool returns an approved tool to pending: a running gateway stops
// serving it on its next call. A changed tool is refused -- revoking it
// would erase the record of a definition replaced after approval. Writes
// (tool revoke).
func (s *Service) RevokeTool(ctx context.Context, a Actor, req adminapi.ToolRef) (adminapi.RevokeResult, error) {
	res := adminapi.RevokeResult{ActionResult: newResult()}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.getTool(ctx, req.Server, req.Tool)
	if err != nil {
		return res, err
	}
	res.Tool = ToolOf(before)
	name := visible.Escape(before.ServerName + "." + before.ToolName)
	if before.Status == quarantine.StatusPending {
		res.Messages = append(res.Messages, fmt.Sprintf("%s was not approved -- it is already pending, and already not being served. Nothing to do.", name))
		return res, nil
	}
	var after quarantine.Tool
	err = s.retryBusy(ctx, func() (err error) {
		after, err = s.d.Tools.Revoke(ctx, before.ServerName, before.ToolName)
		return err
	})
	if errors.Is(err, quarantine.ErrChangedIsNotRevocable) {
		return res, adminapi.NewError(adminapi.CodeChangedNotRevocable, "%s is CHANGED: it is already not served, and revoking would erase the record that its approved definition was replaced; approve the new definition or leave it as it is", name)
	}
	if err != nil {
		return res, s.storeErr("revoking "+name, err)
	}
	res.Changed = true
	res.Tool = ToolOf(after)
	res.WasApprovedAt = before.ApprovedHash
	res.Messages = append(res.Messages, fmt.Sprintf("Revoked %s. It is no longer served, from the next call on; the upstream was not told and the observed definition is kept.", name))
	if after.Usable() {
		return res, adminapi.NewError(adminapi.CodeInternal, "%s is still usable after being revoked (status %s); this is a bug", name, after.Status)
	}
	reason := fmt.Sprintf("tool %q revoked, was approved at sha256:%s", before.ServerName+"."+before.ToolName, before.ApprovedHash)
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, ToolRevoke, reason+" "+a.Tag(), s.d.Now().UTC()))
	return res, nil
}

// Overview is what needs attention: changed tools first, then pending,
// then unsigned backends; the counts; and the latest refusals. A part that
// cannot be read is a problem, and the rest is still returned.
func (s *Service) Overview(ctx context.Context) (adminapi.Overview, error) {
	cfg, err := s.config()
	if err != nil {
		return adminapi.Overview{}, err
	}
	ov := adminapi.Overview{Attention: []adminapi.Attention{}, RecentDenied: []adminapi.AuditRecord{}}
	problem := func(part string, err error) {
		code := adminapi.CodeInternal
		var ae *adminapi.Error
		if errors.As(s.storeErr(part, err), &ae) {
			code = ae.Code
		}
		ov.Problems = append(ov.Problems, adminapi.Problem{Code: code, Part: part, Message: err.Error()})
	}
	var pending []adminapi.Attention
	if tools, err := s.ListTools(ctx, "", ""); err != nil {
		problem("tools", err)
	} else {
		ov.Counts.Tools = tools.Counts.All
		ov.Counts.Review = tools.Counts.Review
		for _, t := range tools.Tools {
			switch t.Status {
			case adminapi.StatusChanged:
				ov.Attention = append(ov.Attention, adminapi.Attention{Kind: adminapi.AttentionChanged, Title: t.Server + "." + t.Tool,
					Detail: "Changed since it was approved. Not served until reviewed.", Server: t.Server, Tool: t.Tool})
			case adminapi.StatusPending:
				pending = append(pending, adminapi.Attention{Kind: adminapi.AttentionPending, Title: t.Server + "." + t.Tool,
					Detail: "New tool, waiting for review.", Server: t.Server, Tool: t.Tool})
			default:
				if t.Usable {
					ov.Counts.ApprovedUsable++
				}
			}
		}
	}
	ov.Attention = append(ov.Attention, pending...)
	var names []string
	upstreamsRead := s.d.Upstreams == nil
	if s.d.Upstreams != nil {
		if ups, err := s.d.Upstreams(ctx, cfg); err != nil {
			problem("upstreams", err)
		} else {
			upstreamsRead = true
			ov.Counts.Upstreams = len(ups)
			for _, u := range ups {
				names = append(names, u.Name)
				if u.Signature != "yes" {
					ov.Attention = append(ov.Attention, adminapi.Attention{Kind: adminapi.AttentionUnsigned, Title: u.Name, Upstream: u.Name,
						Detail: "Backend not signed, so none of its tools are served. Sign it in the terminal."})
				}
			}
		}
	}
	// Health (design/adr/0041 item 7) is per registered backend, so it
	// needs the registry; without it, it is a problem too.
	if s.d.Health != nil {
		switch h, part, err := s.health(ctx, names); {
		case !upstreamsRead:
			problem("health", errors.New("the backends are not known: the registry could not be read"))
		case err != nil:
			problem(part, err)
		default:
			ov.Health = h
			first, backends, last := healthAttention(h)
			ov.Attention = append(append(first, ov.Attention...), backends...)
			ov.Attention = append(ov.Attention, last...)
		}
	}
	if s.d.Blocks != nil {
		if bs, err := s.d.Blocks.Blocks(ctx); err != nil {
			problem("blocks", err)
		} else {
			ov.Counts.Blocked = len(bs)
		}
	}
	if page, err := s.Audit(ctx, adminapi.AuditQuery{Limit: 5, Outcome: string(audit.OutcomeDenied)}); err != nil {
		problem("audit", err)
	} else {
		ov.RecentDenied = page.Records
	}
	return ov, nil
}
