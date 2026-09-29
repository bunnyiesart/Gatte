package admin_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	healthsqlite "github.com/bunnyiesart/Gatte/internal/health/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

var maintNow = time.Date(2026, 9, 29, 13, 0, 0, 0, time.UTC)

type maintHarness struct {
	svc   *admin.Service
	trail *auditsqlite.Recorder
	fail  error
}

func newMaintHarness(t *testing.T) *maintHarness {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := auditsqlite.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := healthsqlite.Migrate(db); err != nil {
		t.Fatal(err)
	}
	h := &maintHarness{trail: auditsqlite.New(db)}
	cfg := &config.Config{Database: ":memory:"}
	svc, err := admin.New(admin.Deps{
		Config:      func() (*config.Config, error) { return cfg, nil },
		Maintenance: healthsqlite.New(db),
		Upstreams: func(context.Context, *config.Config) ([]adminapi.Upstream, error) {
			return []adminapi.Upstream{{Name: "casemgmt"}, {Name: "logsearch"}}, nil
		},
		Record: func(ctx context.Context, _ *config.Config, rec audit.Record) error {
			if h.fail != nil {
				return h.fail
			}
			return h.trail.Record(ctx, rec)
		},
		IsBusy: store.IsBusy,
		Now:    func() time.Time { return maintNow },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

func (h *maintHarness) rows(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := h.trail.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func codeOf(err error) (string, map[string]any) {
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae.Code, ae.Details
	}
	return "", nil
}

func TestMaintenance_OnOffWithOperatorRows(t *testing.T) {
	h := newMaintHarness(t)
	ctx := context.Background()
	until := maintNow.Add(2 * time.Hour)
	ui := admin.Actor{Name: "alice", Front: "ui"}

	res, err := h.svc.StartMaintenance(ctx, ui, adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: "casemgmt", Message: `Troca de versão do "casemgmt"`, Until: &until})
	if err != nil || !res.Changed || !res.Recorded || res.Maintenance == nil || res.Previous != nil {
		t.Fatalf("on = %+v, %v", res, err)
	}
	if res.Maintenance.SetBy != "(operator:alice)" || !res.Maintenance.StartedAt.Equal(maintNow) {
		t.Errorf("row = %+v", res.Maintenance)
	}
	rows := h.rows(t)
	last := rows[len(rows)-1]
	wantReason := `upstream "casemgmt": [ui] until 2026-09-29T15:00:00Z: "Troca de versão do \"casemgmt\""`
	if last.Tool != admin.MaintenanceOn || last.Reason != wantReason || last.AnalystIdentity != "(operator:alice)" || last.TargetUpstream != admin.OperatorTarget {
		t.Errorf("operator row = %+v, want reason %q", last, wantReason)
	}

	// The same again: nothing changes and nothing is written.
	res, err = h.svc.StartMaintenance(ctx, ui, adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: "casemgmt", Message: `Troca de versão do "casemgmt"`, Until: &until})
	if err != nil || res.Changed || len(h.rows(t)) != len(rows) {
		t.Errorf("repeated on = %+v, %v; want changed false and no row", res, err)
	}

	// The whole gateway, with no end.
	res, err = h.svc.StartMaintenance(ctx, admin.Actor{Name: "bob", Front: "cli"}, adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: "Atualização"})
	if err != nil || !res.Changed {
		t.Fatalf("gateway on = %+v, %v", res, err)
	}
	if got := h.rows(t)[len(h.rows(t))-1].Reason; got != `gateway: [cli] no announced end: "Atualização"` {
		t.Errorf("gateway row reason = %q", got)
	}

	list, err := h.svc.ListMaintenance(ctx)
	if err != nil || list.Gateway == nil || len(list.Upstreams) != 1 || list.Upstreams[0].Upstream != "casemgmt" {
		t.Fatalf("list = %+v, %v", list, err)
	}

	off, err := h.svc.EndMaintenance(ctx, ui, adminapi.MaintenanceTarget{Scope: adminapi.ScopeUpstream, Upstream: "casemgmt"})
	if err != nil || !off.Changed || off.Previous == nil || off.Maintenance != nil {
		t.Fatalf("off = %+v, %v", off, err)
	}
	if last := h.rows(t)[len(h.rows(t))-1]; last.Tool != admin.MaintenanceOff || !strings.HasPrefix(last.Reason, `upstream "casemgmt": [ui]`) {
		t.Errorf("off row = %+v", last)
	}
	off, err = h.svc.EndMaintenance(ctx, ui, adminapi.MaintenanceTarget{Scope: adminapi.ScopeUpstream, Upstream: "casemgmt"})
	if err != nil || off.Changed {
		t.Errorf("second off = %+v, %v; want changed false", off, err)
	}
}

func TestMaintenance_RefusesWhatItCannotPutInFrontOfAModel(t *testing.T) {
	h := newMaintHarness(t)
	ctx := context.Background()
	past := maintNow.Add(-time.Minute)
	far := maintNow.AddDate(1, 0, 0)
	for label, tc := range map[string]struct {
		req   adminapi.MaintenanceRequest
		code  string
		field string
	}{
		"newline":             {adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: "casemgmt", Message: "a\nb"}, adminapi.CodeInvalidArgument, "message"},
		"empty":               {adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: " "}, adminapi.CodeInvalidArgument, "message"},
		"until in the past":   {adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: "x", Until: &past}, adminapi.CodeInvalidArgument, "until"},
		"until a year ahead":  {adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: "x", Until: &far}, adminapi.CodeInvalidArgument, "until"},
		"unknown scope":       {adminapi.MaintenanceRequest{Scope: "fleet", Message: "x"}, adminapi.CodeInvalidArgument, "scope"},
		"gateway with a name": {adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Upstream: "casemgmt", Message: "x"}, adminapi.CodeInvalidArgument, "upstream"},
		"upstream no name":    {adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Message: "x"}, adminapi.CodeInvalidArgument, "upstream"},
		"not registered":      {adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: "docsearch", Message: "x"}, adminapi.CodeNotFound, ""},
	} {
		_, err := h.svc.StartMaintenance(ctx, admin.Actor{Name: "alice"}, tc.req)
		code, details := codeOf(err)
		if code != tc.code || (tc.field != "" && details["field"] != tc.field) {
			t.Errorf("%s: err = %v (code %q, details %v), want %s field %q", label, err, code, details, tc.code, tc.field)
		}
	}
	if n := len(h.rows(t)); n != 0 {
		t.Errorf("refused requests wrote %d rows", n)
	}
}

func TestMaintenance_TheRowIsInForceEvenWhenTheTrailFails(t *testing.T) {
	h := newMaintHarness(t)
	h.fail = errors.New("disk full")
	res, err := h.svc.StartMaintenance(context.Background(), admin.Actor{Name: "alice"}, adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: "x"})
	if err != nil || !res.Changed || res.Recorded || !res.HasWarning(adminapi.WarnAuditWriteFailed) {
		t.Fatalf("on with the trail failing = %+v, %v; want in force, recorded false, audit_write_failed", res, err)
	}
	list, _ := h.svc.ListMaintenance(context.Background())
	if list.Gateway == nil {
		t.Error("the maintenance is not in force")
	}
}
