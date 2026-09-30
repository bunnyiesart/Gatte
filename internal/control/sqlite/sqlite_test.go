package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/control"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate is not idempotent: %v", err)
	}
	return New(db)
}

var at = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func TestProcess_RoundTripAndAbsence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.Process(ctx); !errors.Is(err, control.ErrNoProcess) {
		t.Fatalf("Process before any = %v, want ErrNoProcess", err)
	}
	if err := s.RecordProcess(ctx, control.Process{PID: 0, Boot: at}); !errors.Is(err, control.ErrInvalid) {
		t.Fatalf("pid 0 = %v, want ErrInvalid", err)
	}
	for _, p := range []control.Process{{PID: 41, Boot: at, StartToken: "a"}, {PID: 42, Boot: at.Add(time.Hour), StartToken: "b"}} {
		if err := s.RecordProcess(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Process(ctx)
	if err != nil || got.PID != 42 || !got.Boot.Equal(at.Add(time.Hour)) || got.StartToken != "b" {
		t.Fatalf("Process = %+v, %v; want the last one recorded", got, err)
	}
}

func TestRequests_SubmitPendingFinish(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, bad := range []control.Request{
		{Kind: "restart", Actor: "(operator:alice)", RequestedAt: at},
		{Kind: control.KindRedial, Actor: "(operator:alice)", RequestedAt: at},
		{Kind: control.KindReload, Target: "casemgmt", Actor: "(operator:alice)", RequestedAt: at},
		{Kind: control.KindReload, RequestedAt: at},
	} {
		if _, err := s.Submit(ctx, bad); !errors.Is(err, control.ErrInvalid) {
			t.Errorf("Submit(%+v) = %v, want ErrInvalid", bad, err)
		}
	}
	a, err := s.Submit(ctx, control.Request{Kind: control.KindReload, Actor: "(operator:alice)", Tag: "[cli]", RequestedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Submit(ctx, control.Request{Kind: control.KindRedial, Target: "casemgmt", Actor: "(operator:bob)", Tag: "[ui]", RequestedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.Pending(ctx)
	if err != nil || len(pending) != 2 || pending[0].ID != a || pending[1].ID != b || pending[1].Target != "casemgmt" || pending[1].Tag != "[ui]" {
		t.Fatalf("Pending = %+v, %v", pending, err)
	}
	if err := s.Finish(ctx, a, "maybe", nil, at, at); !errors.Is(err, control.ErrInvalid) {
		t.Fatalf("Finish with an unknown outcome = %v", err)
	}
	if err := s.Finish(ctx, a, control.OutcomeApplied, []byte(`{"x":1}`), at, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// The first answer stands.
	if err := s.Finish(ctx, a, control.OutcomeRefused, []byte(`{}`), at, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, a)
	if err != nil || got.State != control.StateDone || got.Outcome != control.OutcomeApplied || string(got.Result) != `{"x":1}` || !got.DoneAt.Equal(at.Add(time.Second)) || !got.Boot.Equal(at) {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	pending, _ = s.Pending(ctx)
	if len(pending) != 1 || pending[0].ID != b {
		t.Fatalf("Pending after one finished = %+v", pending)
	}
	if _, err := s.Get(ctx, 999); !errors.Is(err, control.ErrNotFound) {
		t.Fatalf("Get(999) = %v", err)
	}
	if err := s.Finish(ctx, 999, control.OutcomeApplied, nil, at, at); !errors.Is(err, control.ErrNotFound) {
		t.Fatalf("Finish(999) = %v", err)
	}
}
