package admin

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The Tool of a maintenance operator row (design/adr/0041 item 7).
// Declared interface strings: a SIEM rule matches on them.
const (
	MaintenanceOn  = "(maintenance on)"
	MaintenanceOff = "(maintenance off)"
)

// MaintenanceReason is an operator row's Reason for a maintenance start:
// what it is for, the actor's tag, the announced end, and the message
// quoted Go-style so that no message can read as more of the row.
func MaintenanceReason(scope, upstream string, a Actor, until time.Time, message string) string {
	end := "no announced end"
	if !until.IsZero() {
		end = "until " + until.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s: %s %s: %s", maintenanceSubject(scope, upstream), a.Tag(), end, strconv.Quote(message))
}

func maintenanceSubject(scope, upstream string) string {
	if scope == adminapi.ScopeGateway {
		return "gateway"
	}
	return fmt.Sprintf("upstream %q", upstream)
}

// maintenanceTarget checks scope and upstream and returns the row's key.
func maintenanceTarget(scope, upstream string) (string, error) {
	switch scope {
	case adminapi.ScopeGateway:
		if upstream != "" {
			return "", adminapi.NewError(adminapi.CodeInvalidArgument, "scope gateway takes no upstream").With("field", "upstream")
		}
		return health.GatewayTarget, nil
	case adminapi.ScopeUpstream:
		if upstream == "" {
			return "", adminapi.NewError(adminapi.CodeInvalidArgument, "scope upstream needs the backend's name").With("field", "upstream")
		}
		return upstream, nil
	default:
		return "", adminapi.NewError(adminapi.CodeInvalidArgument, "scope must be %q or %q", adminapi.ScopeUpstream, adminapi.ScopeGateway).With("field", "scope")
	}
}

func toAPIMaintenance(m health.Maintenance, now time.Time) *adminapi.Maintenance {
	out := &adminapi.Maintenance{Message: m.Message, StartedAt: m.StartedAt.UTC(), SetBy: m.SetBy, SetAt: m.SetAt.UTC(), UntilPassed: m.UntilPassed(now)}
	if !m.Until.IsZero() {
		u := m.Until.UTC()
		out.Until = &u
	}
	return out
}

// ListMaintenance returns the maintenance in force.
func (s *Service) ListMaintenance(ctx context.Context) (adminapi.MaintenanceList, error) {
	if err := need(s.d.Maintenance != nil, "maintenance store"); err != nil {
		return adminapi.MaintenanceList{}, err
	}
	rows, err := s.d.Maintenance.Maintenance(ctx)
	if err != nil {
		return adminapi.MaintenanceList{}, s.storeErr("maintenance", err)
	}
	now := s.d.Now()
	out := adminapi.MaintenanceList{Upstreams: []adminapi.UpstreamMaintenance{}}
	for _, m := range rows {
		if m.Target == health.GatewayTarget {
			out.Gateway = toAPIMaintenance(m, now)
			continue
		}
		out.Upstreams = append(out.Upstreams, adminapi.UpstreamMaintenance{Maintenance: *toAPIMaintenance(m, now), Upstream: m.Target})
	}
	return out, nil
}

// StartMaintenance opens, or updates, a maintenance. It writes FIRST and
// records second (design/adr/0041 item 6): a maintenance is a notice, not
// a widening of access, so a trail that fails leaves it in force and the
// answer says so. The same message and until again changes nothing and
// writes nothing. Writes (maintenance on).
func (s *Service) StartMaintenance(ctx context.Context, a Actor, req adminapi.MaintenanceRequest) (adminapi.MaintenanceResult, error) {
	res := adminapi.MaintenanceResult{ActionResult: newResult(), Scope: req.Scope, Upstream: req.Upstream}
	if err := checkActor(a); err != nil {
		return res, err
	}
	target, err := maintenanceTarget(req.Scope, req.Upstream)
	if err != nil {
		return res, err
	}
	msg, err := health.ValidateMessage(req.Message)
	if err != nil {
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "%v", err).With("field", "message")
	}
	now := s.d.Now().UTC()
	var until time.Time
	if req.Until != nil {
		until = req.Until.UTC()
	}
	if err := health.ValidateUntil(until, now); err != nil {
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "%v", err).With("field", "until")
	}
	if err := need(s.d.Maintenance != nil, "maintenance store"); err != nil {
		return res, err
	}
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	if req.Scope == adminapi.ScopeUpstream {
		if err := s.checkRegistered(ctx, req.Upstream); err != nil {
			return res, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var started health.StartResult
	if err := s.retryBusy(ctx, func() (err error) {
		started, err = s.d.Maintenance.Start(ctx, health.Maintenance{Target: target, Message: msg, Until: until, SetBy: a.Identity(), SetAt: now})
		return err
	}); err != nil {
		return res, s.storeErr("maintenance", err)
	}
	res.Maintenance = toAPIMaintenance(started.Stored, now)
	if started.Previous != nil {
		res.Previous = toAPIMaintenance(*started.Previous, now)
	}
	if !started.Changed {
		res.Messages = append(res.Messages, fmt.Sprintf("The %s is already in maintenance with this message and end; nothing changed and nothing was recorded.", maintenanceSubject(req.Scope, req.Upstream)))
		return res, nil
	}
	res.Changed = true
	if req.Scope == adminapi.ScopeGateway {
		res.Messages = append(res.Messages, "The gateway is in planned maintenance: calls are still served, text results and gatte.status carry the notice from the next call on.")
	} else {
		res.Messages = append(res.Messages, fmt.Sprintf("%s is in planned maintenance: from the next call on, its calls are answered with your message and not sent to it. It stays in maintenance until you end it; the end time is only announced.", req.Upstream))
	}
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, MaintenanceOn, MaintenanceReason(req.Scope, req.Upstream, a, until, msg), now))
	return res, nil
}

// EndMaintenance ends a maintenance, first, and records second. A backend
// no longer registered is accepted, so a row left behind can be cleared.
// Writes (maintenance off).
func (s *Service) EndMaintenance(ctx context.Context, a Actor, req adminapi.MaintenanceTarget) (adminapi.MaintenanceResult, error) {
	res := adminapi.MaintenanceResult{ActionResult: newResult(), Scope: req.Scope, Upstream: req.Upstream}
	if err := checkActor(a); err != nil {
		return res, err
	}
	target, err := maintenanceTarget(req.Scope, req.Upstream)
	if err != nil {
		return res, err
	}
	if err := need(s.d.Maintenance != nil, "maintenance store"); err != nil {
		return res, err
	}
	cfg, err := s.config()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.d.Now().UTC()
	var ended *health.Maintenance
	if err := s.retryBusy(ctx, func() (err error) {
		ended, err = s.d.Maintenance.End(ctx, target)
		return err
	}); err != nil {
		return res, s.storeErr("maintenance", err)
	}
	if ended == nil {
		res.Messages = append(res.Messages, fmt.Sprintf("The %s is not in maintenance; nothing changed and nothing was recorded.", maintenanceSubject(req.Scope, req.Upstream)))
		return res, nil
	}
	res.Changed = true
	res.Previous = toAPIMaintenance(*ended, now)
	res.Messages = append(res.Messages, fmt.Sprintf("The maintenance of the %s ended; the next call is served normally.", maintenanceSubject(req.Scope, req.Upstream)))
	reason := fmt.Sprintf("%s: %s", maintenanceSubject(req.Scope, req.Upstream), a.Tag())
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, MaintenanceOff, reason, now))
	return res, nil
}

// checkRegistered answers not_found for a backend the registry does not
// name.
func (s *Service) checkRegistered(ctx context.Context, name string) error {
	list, err := s.Upstreams(ctx)
	if err != nil {
		var ae *adminapi.Error
		if errors.As(err, &ae) {
			return ae
		}
		return s.storeErr("upstream registry", err)
	}
	for _, u := range list.Upstreams {
		if u.Name == name {
			return nil
		}
	}
	return adminapi.NewError(adminapi.CodeNotFound, "no registered backend is named %q", name).With("upstream", name)
}
