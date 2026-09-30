package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/control"
	controlsqlite "github.com/bunnyiesart/Gatte/internal/control/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func newControlService(t *testing.T, ring func(control.Process) error, wait time.Duration) (*admin.Service, *controlsqlite.Store) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := controlsqlite.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctl := controlsqlite.New(db)
	cfg := &config.Config{}
	svc, err := admin.New(admin.Deps{
		Config:    func() (*config.Config, error) { return cfg, nil },
		Record:    func(context.Context, *config.Config, audit.Record) error { return nil },
		Control:   ctl,
		Ring:      ring,
		ServeWait: wait,
		Upstreams: func(context.Context, *config.Config) ([]adminapi.Upstream, error) {
			return []adminapi.Upstream{{Name: "casemgmt"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, ctl
}

var op = admin.Actor{Name: "alice", Front: "ui"}

func code(err error) string {
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// TestServeControl_AnUnansweredRequestIsPendingAndCanBeReadBack: serve may
// be mid-round; the operator gets the id, not an error.
func TestServeControl_AnUnansweredRequestIsPendingAndCanBeReadBack(t *testing.T) {
	rung := 0
	svc, ctl := newControlService(t, func(control.Process) error { rung++; return nil }, 100*time.Millisecond)
	ctx := context.Background()
	if _, err := svc.Reload(ctx, op); code(err) != adminapi.CodeServeNotRunning {
		t.Fatalf("Reload before any serve = %v", err)
	}
	if err := ctl.RecordProcess(ctx, control.Process{PID: 4242, Boot: time.Now()}); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Reload(ctx, op)
	if err != nil || res.State != adminapi.ServeStatePending || res.ID == 0 || rung != 1 || res.RequestedBy != "(operator:alice)" {
		t.Fatalf("Reload = %+v, %v (rung %d)", res, err, rung)
	}
	if len(res.Messages) == 0 {
		t.Fatal("a pending answer says nothing")
	}
	pending, _ := ctl.Pending(ctx)
	if len(pending) != 1 || pending[0].Tag != "[ui]" {
		t.Fatalf("pending = %+v", pending)
	}
	if err := ctl.Finish(ctx, res.ID, control.OutcomeApplied, []byte(`{"recorded":true,"messages":["done"],"reload":{"roles":[],"groups":[],"quota":[],"free_tools_changed":false,"not_reloaded":["listen"]}}`), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := svc.ServeRequest(ctx, res.ID)
	if err != nil || got.State != adminapi.ServeStateDone || got.Outcome != adminapi.ServeOutcomeApplied || !got.Recorded || got.Reload == nil || got.Reload.NotReloaded[0] != "listen" || got.DoneAt == nil {
		t.Fatalf("ServeRequest = %+v, %v", got, err)
	}
	if _, err := svc.ServeRequest(ctx, 999); code(err) != adminapi.CodeNotFound {
		t.Fatalf("ServeRequest(999) = %v", err)
	}
}

// TestServeControl_ARequestThatCannotBeRungIsNotLeftPending: otherwise it
// would be performed, surprisingly, at the next unrelated SIGHUP.
func TestServeControl_ARequestThatCannotBeRungIsNotLeftPending(t *testing.T) {
	svc, ctl := newControlService(t, func(control.Process) error { return errors.New("no such process") }, time.Second)
	ctx := context.Background()
	if err := ctl.RecordProcess(ctx, control.Process{PID: 4242, Boot: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Redial(ctx, op, adminapi.RedialRequest{Upstream: "casemgmt"}); code(err) != adminapi.CodeServeNotRunning {
		t.Fatalf("Redial with serve gone = %v", err)
	}
	if p, _ := ctl.Pending(ctx); len(p) != 0 {
		t.Fatalf("pending = %+v", p)
	}
	got, err := ctl.Get(ctx, 1)
	if err != nil || got.Outcome != control.OutcomeRefused {
		t.Fatalf("the abandoned request = %+v, %v", got, err)
	}
	if _, err := svc.Redial(ctx, op, adminapi.RedialRequest{}); code(err) != adminapi.CodeInvalidArgument {
		t.Fatalf("Redial without a name = %v", err)
	}
	if _, err := svc.Redial(ctx, op, adminapi.RedialRequest{Upstream: "nosuch"}); code(err) != adminapi.CodeNotFound {
		t.Fatalf("Redial of an unregistered backend = %v", err)
	}
	if _, err := svc.Reload(ctx, admin.Actor{}); code(err) != adminapi.CodePeerUnattributable {
		t.Fatalf("Reload with no actor = %v", err)
	}
}
