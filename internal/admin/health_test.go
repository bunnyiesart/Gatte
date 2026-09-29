package admin_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/health"
	healthsqlite "github.com/bunnyiesart/Gatte/internal/health/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The management backend is another process than serve and reads what
// serve wrote (design/adr/0041 item 7). These tests write that state the
// way serve does, through the adapter, and read it back through the
// service.

const healthGrace = 60 * time.Second

func newHealthHarness(t *testing.T) (*admin.Service, *healthsqlite.Store) {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, m := range []func(*sql.DB) error{auditsqlite.Migrate, healthsqlite.Migrate} {
		if err := m(db); err != nil {
			t.Fatal(err)
		}
	}
	hs := healthsqlite.New(db)
	trail := auditsqlite.New(db)
	cfg := &config.Config{Database: ":memory:"}
	svc, err := admin.New(admin.Deps{
		Config:      func() (*config.Config, error) { return cfg, nil },
		Maintenance: hs,
		Health:      hs,
		ServeGrace:  healthGrace,
		Trail:       trail,
		Upstreams: func(context.Context, *config.Config) ([]adminapi.Upstream, error) {
			return []adminapi.Upstream{{Name: "casemgmt", Signature: "yes"}, {Name: "docsearch", Signature: "yes"},
				{Name: "logsearch", Signature: "yes"}, {Name: "threatintel", Signature: "yes"}}, nil
		},
		Record: func(ctx context.Context, _ *config.Config, rec audit.Record) error { return trail.Record(ctx, rec) },
		IsBusy: store.IsBusy,
		Now:    func() time.Time { return maintNow },
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, hs
}

// writeServeState is one round of serve: casemgmt up, logsearch
// reconnecting, docsearch held back (down); threatintel was registered
// after the round and has no row.
func writeServeState(t *testing.T, hs *healthsqlite.Store, lastRound time.Time) {
	t.Helper()
	boot := maintNow.Add(-6 * time.Hour)
	err := hs.WriteState(context.Background(), health.Snapshot{
		Backends: []health.BackendRecord{
			{Backend: "casemgmt", Live: true, Since: boot, LastAttempt: boot, UpdatedAt: lastRound},
			{Backend: "logsearch", Live: false, Since: maintNow.Add(-10 * time.Minute), LastAttempt: lastRound,
				NextAttempt: lastRound.Add(30 * time.Second), Cause: health.CauseProcessGone, UpdatedAt: lastRound},
			{Backend: "docsearch", Live: false, Since: maintNow.Add(-time.Hour), LastAttempt: maintNow.Add(-time.Hour),
				Cause: health.CauseHeldBack, UpdatedAt: lastRound},
			// Not registered any more: a front never sees it.
			{Backend: "retired", Live: true, Since: boot, UpdatedAt: lastRound},
		},
		Serve: &health.ServeStatus{Boot: boot, LastRoundAt: lastRound, RoundInterval: 30 * time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func byName(h *adminapi.Health) map[string]adminapi.BackendHealth {
	out := map[string]adminapi.BackendHealth{}
	for _, b := range h.Backends {
		out[b.Name] = b
	}
	return out
}

func TestOverview_CarriesTheHealthServeWrote(t *testing.T) {
	svc, hs := newHealthHarness(t)
	ctx := context.Background()
	writeServeState(t, hs, maintNow.Add(-20*time.Second))
	until := maintNow.Add(time.Hour)
	if _, err := svc.StartMaintenance(ctx, admin.Actor{Name: "alice", Front: "ui"}, adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: "threatintel", Message: "Troca de chave", Until: &until}); err != nil {
		t.Fatal(err)
	}

	ov, err := svc.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Health == nil {
		t.Fatalf("overview has no health; problems %+v", ov.Problems)
	}
	if ov.Health.Serve.State != adminapi.ServeRunning || ov.Health.Serve.RoundIntervalSeconds != 30 || ov.Health.Serve.LastRoundAt == nil {
		t.Errorf("serve = %+v, want running every 30 s", ov.Health.Serve)
	}
	if ov.Health.GatewayMaintenance != nil {
		t.Errorf("gateway maintenance = %+v, want none", ov.Health.GatewayMaintenance)
	}
	got := byName(ov.Health)
	if len(got) != 4 {
		t.Fatalf("backends = %+v; want exactly the four registered ones", ov.Health.Backends)
	}
	for name, want := range map[string]string{"casemgmt": adminapi.BackendUp, "logsearch": adminapi.BackendReconnecting,
		"docsearch": adminapi.BackendDown, "threatintel": adminapi.BackendMaintenance} {
		if got[name].State != want {
			t.Errorf("%s state = %q, want %q", name, got[name].State, want)
		}
	}
	if l := got["logsearch"]; l.Cause != string(health.CauseProcessGone) || l.NextAttempt == nil || l.Since == nil || l.Live {
		t.Errorf("logsearch = %+v; want not live, since, next attempt and the cause for the operator", l)
	}
	if c := got["casemgmt"]; !c.Live || c.Cause != "" || c.NextAttempt != nil {
		t.Errorf("casemgmt = %+v", c)
	}
	if ti := got["threatintel"]; ti.Maintenance == nil || ti.Maintenance.Message != "Troca de chave" || ti.Maintenance.SetBy != "(operator:alice)" || ti.Since != nil {
		t.Errorf("threatintel = %+v; want the maintenance row and no since (serve never reported it)", ti)
	}

	var kinds []string
	for _, a := range ov.Attention {
		kinds = append(kinds, a.Kind+":"+a.Upstream)
	}
	want := []string{"backend_unavailable:docsearch", "backend_unavailable:logsearch", "backend_maintenance:threatintel"}
	if len(kinds) != len(want) {
		t.Fatalf("attention = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Errorf("attention[%d] = %s, want %s", i, kinds[i], want[i])
		}
	}
}

func TestOverview_AServeThatStoppedReportingIsFirstAndItsBackendsAreUnknown(t *testing.T) {
	svc, hs := newHealthHarness(t)
	ctx := context.Background()
	// 30 s rounds: twice that plus the grace is two minutes.
	writeServeState(t, hs, maintNow.Add(-3*time.Minute))
	if _, err := svc.StartMaintenance(ctx, admin.Actor{Name: "alice"}, adminapi.MaintenanceRequest{Scope: adminapi.ScopeGateway, Message: "Atualização do binário"}); err != nil {
		t.Fatal(err)
	}
	ov, err := svc.Overview(ctx)
	if err != nil || ov.Health == nil {
		t.Fatalf("overview = %+v, %v", ov, err)
	}
	if ov.Health.Serve.State != adminapi.ServeNotReporting {
		t.Errorf("serve = %+v, want not_reporting", ov.Health.Serve)
	}
	for _, b := range ov.Health.Backends {
		if b.State != adminapi.BackendUnknown || b.Since != nil {
			t.Errorf("%s = %+v; a serve that is not reporting says nothing current about its backends", b.Name, b)
		}
	}
	if ov.Health.GatewayMaintenance == nil || ov.Health.GatewayMaintenance.Message != "Atualização do binário" {
		t.Errorf("gateway maintenance = %+v", ov.Health.GatewayMaintenance)
	}
	if len(ov.Attention) < 2 || ov.Attention[0].Kind != adminapi.AttentionServeNotReporting || ov.Attention[len(ov.Attention)-1].Kind != adminapi.AttentionGatewayMaintenance {
		t.Errorf("attention = %+v; want serve_not_reporting first and gateway_maintenance last", ov.Attention)
	}
}

func TestOverview_ADatabaseNoServeReportedIsNeverReported(t *testing.T) {
	svc, _ := newHealthHarness(t)
	ov, err := svc.Overview(context.Background())
	if err != nil || ov.Health == nil {
		t.Fatalf("overview = %+v, %v", ov, err)
	}
	if ov.Health.Serve.State != adminapi.ServeNeverReported || ov.Health.Serve.Boot != nil {
		t.Errorf("serve = %+v, want never_reported", ov.Health.Serve)
	}
	for _, b := range ov.Health.Backends {
		if b.State != adminapi.BackendUnknown {
			t.Errorf("%s = %q, want unknown", b.Name, b.State)
		}
	}
}

func TestUpstreams_EachEntryCarriesItsHealth(t *testing.T) {
	svc, hs := newHealthHarness(t)
	writeServeState(t, hs, maintNow.Add(-20*time.Second))
	list, err := svc.Upstreams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range list.Upstreams {
		if u.Health == nil || u.Health.Name != u.Name {
			t.Errorf("%s has health %+v; want its own", u.Name, u.Health)
		}
	}
	if list.Upstreams[0].Name != "casemgmt" || list.Upstreams[0].Health.State != adminapi.BackendUp {
		t.Errorf("casemgmt = %+v", list.Upstreams[0])
	}
}
