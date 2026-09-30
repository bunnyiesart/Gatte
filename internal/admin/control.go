package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/control"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The Tool of the operator rows the gateway process writes for a request
// (design/adr/0044). Declared interface strings: a SIEM rule matches on
// them. Written by serve, not here: serve is where the change happens.
const (
	ConfigReload   = "(config reload)"
	UpstreamRedial = "(upstream redial)"
)

// DefaultServeWait is how long Reload and Redial wait for serve by
// default: inside the API's request deadline (25 s).
const DefaultServeWait = 20 * time.Second

// Reload asks the running gateway process to re-read its configuration
// file and apply [[role]], [group_to_role] and [quota]. The file is
// validated here first, as every operation does; serve reads and
// validates it again, its own copy, and that is the one applied.
func (s *Service) Reload(ctx context.Context, a Actor) (adminapi.ServeRequest, error) {
	if err := checkActor(a); err != nil {
		return adminapi.ServeRequest{}, err
	}
	if _, err := s.config(); err != nil {
		return adminapi.ServeRequest{}, err
	}
	return s.fileRequest(ctx, a, control.Request{Kind: control.KindReload})
}

// Redial asks the running gateway process to drop its connection to one
// registered backend and dial it again, with the vault as it is now.
func (s *Service) Redial(ctx context.Context, a Actor, req adminapi.RedialRequest) (adminapi.ServeRequest, error) {
	if err := checkActor(a); err != nil {
		return adminapi.ServeRequest{}, err
	}
	if req.Upstream == "" {
		return adminapi.ServeRequest{}, adminapi.NewError(adminapi.CodeInvalidArgument, "a redial names the backend").With("field", "upstream")
	}
	if _, err := s.config(); err != nil {
		return adminapi.ServeRequest{}, err
	}
	if err := s.checkRegistered(ctx, req.Upstream); err != nil {
		return adminapi.ServeRequest{}, err
	}
	return s.fileRequest(ctx, a, control.Request{Kind: control.KindRedial, Target: req.Upstream})
}

// ServeRequest reads a request back.
func (s *Service) ServeRequest(ctx context.Context, id int64) (adminapi.ServeRequest, error) {
	if err := need(s.d.Control != nil, "control store"); err != nil {
		return adminapi.ServeRequest{}, err
	}
	q, err := s.d.Control.Get(ctx, id)
	switch {
	case errors.Is(err, control.ErrNotFound):
		return adminapi.ServeRequest{}, adminapi.NewError(adminapi.CodeNotFound, "no request %d", id)
	case err != nil:
		return adminapi.ServeRequest{}, s.storeErr("serve requests", err)
	}
	return toAPIRequest(q), nil
}

// fileRequest files r, rings serve, and waits for its answer.
func (s *Service) fileRequest(ctx context.Context, a Actor, r control.Request) (adminapi.ServeRequest, error) {
	if err := need(s.d.Control != nil && s.d.Ring != nil, "control store"); err != nil {
		return adminapi.ServeRequest{}, err
	}
	p, err := s.d.Control.Process(ctx)
	switch {
	case errors.Is(err, control.ErrNoProcess):
		return adminapi.ServeRequest{}, adminapi.NewError(adminapi.CodeServeNotRunning,
			"no gateway process has recorded itself in this database: is serve running, on this database? Nothing was filed")
	case err != nil:
		return adminapi.ServeRequest{}, s.storeErr("serve requests", err)
	}
	r.Actor, r.Tag, r.RequestedAt = a.Identity(), a.Tag(), s.d.Now().UTC()
	var id int64
	if err := s.retryBusy(ctx, func() (err error) {
		id, err = s.d.Control.Submit(ctx, r)
		return err
	}); err != nil {
		return adminapi.ServeRequest{}, s.storeErr("serve requests", err)
	}
	if err := s.d.Ring(p); err != nil {
		abandoned, _ := json.Marshal(adminapi.ServeRequest{Refusal: adminapi.RefusalNotRung, Messages: []string{"serve could not be rung: " + err.Error()}})
		if aerr := s.d.Control.Abandon(context.WithoutCancel(ctx), id, abandoned, s.d.Now().UTC()); aerr != nil {
			s.d.Log.Warn("admin: a request serve could not be rung for is still pending", "id", id, "detail", aerr.Error())
		}
		return adminapi.ServeRequest{}, adminapi.NewError(adminapi.CodeServeNotRunning,
			"the gateway process recorded as pid %d could not be rung (%v); nothing changed. If serve is running, run this as its service account", p.PID, err).
			With("pid", p.PID)
	}
	return s.await(ctx, id)
}

// await polls request id until it is done, ServeWait passes or ctx ends,
// whichever is first, and answers what it read last.
func (s *Service) await(ctx context.Context, id int64) (adminapi.ServeRequest, error) {
	wait := s.d.ServeWait
	if wait <= 0 {
		wait = DefaultServeWait
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Add(-time.Second).Before(deadline) {
		deadline = d.Add(-time.Second)
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		q, err := s.d.Control.Get(ctx, id)
		if err != nil && ctx.Err() == nil {
			return adminapi.ServeRequest{}, s.storeErr("serve requests", err)
		}
		if err == nil && (q.State == control.StateDone || !time.Now().Before(deadline)) {
			out := toAPIRequest(q)
			if q.State != control.StateDone {
				out.Messages = append(out.Messages, fmt.Sprintf("serve has not answered request %d yet; it was rung and will take it. Read it again with GET /v1/serve-requests/%d, or look for its operator row in the audit trail.", id, id))
			}
			return out, nil
		}
		select {
		case <-ctx.Done():
			if q.ID != 0 {
				return toAPIRequest(q), nil
			}
			return adminapi.ServeRequest{}, adminapi.NewError(adminapi.CodeInternal, "the request %d was filed and rung; its answer could not be read: %v", id, ctx.Err())
		case <-tick.C:
		}
	}
}

// toAPIRequest is the row, with the answer serve wrote into it.
func toAPIRequest(q control.Request) adminapi.ServeRequest {
	var out adminapi.ServeRequest
	if len(q.Result) > 0 {
		_ = json.Unmarshal(q.Result, &out)
	}
	out.ID, out.Kind, out.Upstream = q.ID, q.Kind, q.Target
	out.RequestedBy, out.RequestedAt, out.State = q.Actor, q.RequestedAt.UTC(), q.State
	out.Outcome, out.DoneAt = "", nil
	if q.State == control.StateDone {
		out.Outcome = q.Outcome
		d := q.DoneAt.UTC()
		out.DoneAt = &d
	}
	if out.Messages == nil {
		out.Messages = []string{}
	}
	return out
}
