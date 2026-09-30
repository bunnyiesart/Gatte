// serve's side of design/adr/0044: on SIGHUP, take the operator's pending
// requests from the database -- reload the reloadable part of the
// configuration, re-dial one backend -- and answer each on its own row,
// with an operator row on the trail.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/control"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/internal/reload"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// maxReloadReason bounds the reason of a (config reload) row; the full
// diff is in the request's answer.
const maxReloadReason = 4000

// signalActor is who a SIGHUP with no pending request is attributed to:
// the gateway itself, because the signal does not say who sent it.
const signalActor = "(gateway)"

// announce is what serve does once it is built and before it serves: every
// request still pending from a previous process is answered as superseded
// by this restart -- which read the whole file and dials every backend --
// and this process records its pid, so the next request rings it.
func (s *serveStack) announce(ctx context.Context, logger *slog.Logger) {
	if s.control == nil {
		return
	}
	if pending, err := s.control.Pending(ctx); err != nil {
		logger.Error("mcp-gateway: the pending operator requests could not be read", slog.String("detail", err.Error()))
	} else {
		for _, r := range pending {
			res := adminapi.ServeRequest{Refusal: adminapi.RefusalSuperseded, Messages: []string{
				"The gateway restarted before answering this request. The restart read the whole configuration file and dials every backend, so there is nothing left to do."}}
			s.finish(ctx, logger, r, control.OutcomeRefused, res, "")
		}
	}
	p := control.Process{PID: os.Getpid(), Boot: s.boot, StartToken: processStartToken(os.Getpid())}
	if err := s.control.RecordProcess(ctx, p); err != nil {
		logger.Error("mcp-gateway: this process could not record its pid; `mcp-gateway reload` and `upstream redial` will not reach it (SIGHUP still reloads)",
			slog.String("detail", err.Error()))
	}
}

// handleControl answers every pending request, or reloads on behalf of
// the signal when there is none. It reports stop when the Gateway closed.
func (s *serveStack) handleControl(ctx context.Context, logger *slog.Logger) (stop bool) {
	var pending []control.Request
	if s.control != nil {
		var err error
		if pending, err = s.control.Pending(ctx); err != nil {
			logger.Error("mcp-gateway: SIGHUP: the pending operator requests could not be read; reloading on behalf of the signal",
				slog.String("detail", err.Error()))
		}
	}
	if len(pending) == 0 {
		pending = []control.Request{{Kind: control.KindReload, Actor: signalActor, Tag: "[signal]"}}
	}

	roundNeeded := false
	var redials []control.Request
	redialed := map[int64]bool{}
	for _, r := range pending {
		switch r.Kind {
		case control.KindReload:
			outcome, res, reason := s.reloadConfig(ctx, logger)
			roundNeeded = roundNeeded || outcome == control.OutcomeApplied
			s.finish(ctx, logger, r, outcome, res, reason)
		case control.KindRedial:
			connected, err := s.gateway.Redial(ctx, r.Target)
			if err != nil {
				refusal := adminapi.RefusalNotServable
				switch {
				case errors.Is(err, gateway.ErrQuotaMisconfigured):
					refusal = adminapi.RefusalHeldBack
				case errors.Is(err, gateway.ErrClosed):
					return true
				}
				res := adminapi.ServeRequest{Refusal: refusal, Messages: []string{"Nothing was dropped: " + err.Error()}}
				s.finish(ctx, logger, r, control.OutcomeRefused, res, fmt.Sprintf("refused (%s): %v", refusal, err))
				continue
			}
			redialed[r.ID] = connected
			redials = append(redials, r)
			roundNeeded = true
		default:
			res := adminapi.ServeRequest{Refusal: "unknown_kind", Messages: []string{fmt.Sprintf("This gateway does not know requests of kind %q.", r.Kind)}}
			s.finish(ctx, logger, r, control.OutcomeRefused, res, "refused: unknown kind")
		}
	}

	if roundNeeded {
		// One round out of turn: it re-dials what was marked, lists it
		// before it takes a call, and withholds what a new quota plan
		// leaves undeclared, as every round does.
		if _, stop = s.round(ctx, logger); stop {
			return true
		}
	}
	for _, r := range redials {
		live, cause, _ := s.gateway.BackendState(r.Target)
		out := &adminapi.RedialOutcome{WasConnected: redialed[r.ID], Live: live, Cause: string(cause)}
		res := adminapi.ServeRequest{Redial: out}
		switch {
		case live:
			res.Messages = append(res.Messages, fmt.Sprintf("%s was dropped and dialled again, with the vault as it is now, and it is live.", r.Target))
		case !out.WasConnected:
			res.Messages = append(res.Messages, fmt.Sprintf("%s had no live connection; it was dialled and is not live yet (%s). The next round tries again.", r.Target, opDash(out.Cause)))
		default:
			res.Messages = append(res.Messages, fmt.Sprintf("%s was dropped; it is not live again yet (%s). The next round tries again, and its calls are answered as reconnecting meanwhile.", r.Target, opDash(out.Cause)))
		}
		reason := fmt.Sprintf("was connected: %t; live after the round: %t", out.WasConnected, live)
		if !live && out.Cause != "" {
			reason += " (" + out.Cause + ")"
		}
		s.finish(ctx, logger, r, control.OutcomeApplied, res, reason)
	}
	return false
}

// reloadConfig re-reads the file serve was started with and applies its
// reloadable part: the whole file is loaded and validated first, and
// nothing changes unless all of it is good.
func (s *serveStack) reloadConfig(ctx context.Context, logger *slog.Logger) (outcome string, res adminapi.ServeRequest, reason string) {
	refuse := func(refusal string, changes *adminapi.ReloadChanges, err error) (string, adminapi.ServeRequest, string) {
		logger.Error("mcp-gateway: configuration reload REFUSED; the policy in force is kept",
			slog.String("refusal", refusal), slog.String("detail", err.Error()))
		return control.OutcomeRefused, adminapi.ServeRequest{Refusal: refusal, Reload: changes,
			Messages: []string{"Nothing changed; the roles, groups and quota in force are kept: " + err.Error()}}, fmt.Sprintf("refused (%s): %v", refusal, err)
	}
	if s.configPath == "" {
		return refuse(adminapi.RefusalInvalidConfig, nil, errors.New("this process has no configuration file path to re-read"))
	}
	next, err := config.Load(s.configPath)
	if err != nil {
		return refuse(adminapi.RefusalInvalidConfig, nil, err)
	}
	policy, err := next.ToAccessPolicy()
	if err != nil {
		return refuse(adminapi.RefusalInvalidConfig, nil, err)
	}
	plan, err := next.ToQuotaPlan()
	if err != nil {
		return refuse(adminapi.RefusalInvalidConfig, nil, err)
	}
	gate, err := quota.NewGate(plan, s.quotaStore)
	if err != nil {
		return refuse(adminapi.RefusalInvalidConfig, nil, err)
	}
	diff := reload.Diff(s.cfg, next, s.gateway.RoutedTools())
	changes := toAPIChanges(diff)
	if err := s.gateway.ApplyPolicy(ctx, policy, gate); err != nil {
		switch {
		case errors.Is(err, gateway.ErrQuotaMisconfigured):
			return refuse(adminapi.RefusalQuotaMismatch, changes, err)
		case errors.Is(err, gateway.ErrRegistryUnavailable):
			return refuse(adminapi.RefusalRegistryUnavailable, changes, err)
		default:
			return refuse(adminapi.RefusalInvalidConfig, changes, err)
		}
	}
	// Only the reloadable part moves: the rest stays what this process
	// booted with, so the next reload still says what needs a restart.
	applied := *s.cfg
	applied.Roles, applied.GroupToRole, applied.Quota = next.Roles, next.GroupToRole, next.Quota
	s.cfg = &applied

	res = adminapi.ServeRequest{Reload: changes}
	if diff.Empty() {
		res.Messages = append(res.Messages, "The file was re-read and validated; nothing in [[role]], [group_to_role] or [quota] changed what anyone reaches.")
	} else {
		res.Messages = append(res.Messages, "Applied from the next call on. Clients that already listed their tools keep that list until they reconnect (Claude Code: /mcp); a call to a tool a role lost is refused at once.")
	}
	if len(diff.NotReloaded) > 0 {
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: "not_reloaded",
			Message: "These keys differ from the file this process started with and are NOT in effect until a restart: " + strings.Join(diff.NotReloaded, ", ")})
		res.Messages = append(res.Messages, "NOT applied until a restart: "+strings.Join(diff.NotReloaded, ", ")+".")
	}
	logger.Info("mcp-gateway: configuration reloaded", slog.String("changes", reload.Summary(diff, maxReloadReason)))
	return control.OutcomeApplied, res, "applied: " + reload.Summary(diff, maxReloadReason)
}

// finish writes the operator row of r, then r's answer. r.ID zero is the
// signal's own reload: it has a row and no request to answer.
func (s *serveStack) finish(ctx context.Context, logger *slog.Logger, r control.Request, outcome string, res adminapi.ServeRequest, reason string) {
	now := time.Now().UTC()
	tool, target := admin.ConfigReload, admin.OperatorTarget
	if r.Kind == control.KindRedial {
		tool, target = admin.UpstreamRedial, r.Target
	}
	if reason == "" {
		reason = outcome
	}
	if r.Tag != "" {
		reason = r.Tag + " " + reason
	}
	if len(reason) > maxReloadReason+100 {
		n := maxReloadReason
		for n > 0 && !utf8.RuneStart(reason[n]) {
			n--
		}
		reason = reason[:n] + " ... (truncated)"
	}
	rec := audit.Record{AnalystIdentity: r.Actor, Tool: tool, TargetUpstream: target, Timestamp: now, Outcome: audit.OutcomeAllowed, Reason: reason}
	if outcome != control.OutcomeApplied {
		rec.Outcome = audit.OutcomeDenied
	}
	if s.audit != nil && r.Actor != "" {
		if err := retryBusy(ctx, func() error { return s.audit.Record(ctx, rec) }); err != nil {
			res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnAuditWriteFailed,
				Message: "The audit trail has no row for this: " + err.Error()})
			logger.Error("mcp-gateway: the operator row of a request was not recorded", slog.String("tool", tool), slog.String("detail", err.Error()))
		} else {
			res.Recorded = true
			res.Audit = &adminapi.OperatorRow{Identity: rec.AnalystIdentity, Tool: rec.Tool, Reason: rec.Reason, Timestamp: rec.Timestamp}
		}
	}
	if r.ID == 0 || s.control == nil {
		return
	}
	if res.Messages == nil {
		res.Messages = []string{}
	}
	body, err := json.Marshal(res)
	if err == nil {
		err = retryBusy(ctx, func() error { return s.control.Finish(ctx, r.ID, outcome, body, s.boot, now) })
	}
	if err != nil {
		logger.Error("mcp-gateway: the answer to an operator request could not be written; it stays pending until the next SIGHUP or restart",
			slog.Int64("request", r.ID), slog.String("detail", err.Error()))
	}
}

func toAPIChanges(c reload.Changes) *adminapi.ReloadChanges {
	out := &adminapi.ReloadChanges{Roles: []adminapi.RoleChange{}, Groups: []adminapi.GroupChange{}, Quota: []adminapi.QuotaChange{},
		FreeToolsChanged: c.FreeToolsChanged, NotReloaded: append([]string{}, c.NotReloaded...)}
	for _, r := range c.Roles {
		out.Roles = append(out.Roles, adminapi.RoleChange{Role: r.Role, Added: r.Added, Removed: r.Removed,
			Gained: append([]string{}, r.Gained...), Lost: append([]string{}, r.Lost...)})
	}
	for _, g := range c.Groups {
		out.Groups = append(out.Groups, adminapi.GroupChange{Group: g.Group, From: g.From, To: g.To})
	}
	for _, q := range c.Quota {
		out.Quota = append(out.Quota, adminapi.QuotaChange{Account: q.Account, Change: q.Change, From: q.From, To: q.To})
	}
	return out
}
