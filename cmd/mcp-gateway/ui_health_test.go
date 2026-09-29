//go:build !nofront

package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/health"
	healthsqlite "github.com/bunnyiesart/Gatte/internal/health/sqlite"
)

// The console's side of design/adr/0041: backend health on the Backends
// page and the Overview, and planned maintenance as a form, through the
// management API like every other action.

func TestUI_BackendsShowHealthAndMaintenanceIsAnAuditedOperatorAction(t *testing.T) {
	e, s, cookie := newUITest(t)
	mustRegister(t, e, stdioEntry("casemgmt"))
	hs := healthsqlite.New(e.db)
	now := time.Now().UTC()
	if err := hs.WriteState(context.Background(), health.Snapshot{
		Backends: []health.BackendRecord{{Backend: "casemgmt", Live: false, Since: now.Add(-5 * time.Minute), LastAttempt: now,
			NextAttempt: now.Add(30 * time.Second), Cause: health.CauseNotBroughtUp, UpdatedAt: now}},
		Serve: &health.ServeStatus{Boot: now.Add(-time.Hour), LastRoundAt: now, RoundInterval: 30 * time.Second},
	}); err != nil {
		t.Fatal(err)
	}

	page := uiDo(s, "GET", "/upstreams", nil, cookie, nil).Body.String()
	for _, want := range []string{"Reconnecting", "not_brought_up", `action="` + s.session + `/upstreams/maintenance/on"`, `name="csrf"`} {
		if !strings.Contains(page, want) {
			t.Errorf("Backends page lacks %q", want)
		}
	}

	on := url.Values{"scope": {"upstream"}, "upstream": {"casemgmt"}, "message": {`<b>Troca</b> de versão`}, "until": {"2h"}}
	if w := uiDo(s, "POST", "/upstreams/maintenance/on", on, cookie, samePost); w.Code != http.StatusForbidden {
		t.Fatalf("maintenance on without the form token: %d, want 403", w.Code)
	}
	if m, _ := hs.Maintenance(context.Background()); len(m) != 0 {
		t.Fatalf("a POST without the form token opened a maintenance: %+v", m)
	}
	on.Set("csrf", s.csrf)
	if w := uiDo(s, "POST", "/upstreams/maintenance/on", on, cookie, samePost); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "planned maintenance") {
		t.Fatalf("maintenance on: %d\n%s", w.Code, w.Body)
	}
	m, err := hs.Maintenance(context.Background())
	if err != nil || len(m) != 1 || m[0].Target != "casemgmt" || m[0].Message != `<b>Troca</b> de versão` || m[0].Until.IsZero() {
		t.Fatalf("maintenance after the form: %+v, %v", m, err)
	}

	page = uiDo(s, "GET", "/upstreams", nil, cookie, nil).Body.String()
	if !strings.Contains(page, "&lt;b&gt;Troca&lt;/b&gt; de versão") || strings.Contains(page, "<b>Troca") {
		t.Error("the Backends page does not escape the operator's message")
	}
	if !strings.Contains(page, "End maintenance") || !strings.Contains(page, "In maintenance") {
		t.Error("the Backends page does not offer to end the maintenance")
	}
	overview := uiDo(s, "GET", "/", nil, cookie, nil).Body.String()
	for _, want := range []string{"casemgmt", "In maintenance", "&lt;b&gt;Troca&lt;/b&gt; de versão"} {
		if !strings.Contains(overview, want) {
			t.Errorf("Overview lacks %q", want)
		}
	}

	off := url.Values{"scope": {"upstream"}, "upstream": {"casemgmt"}, "csrf": {s.csrf}}
	if w := uiDo(s, "POST", "/upstreams/maintenance/off", off, cookie, samePost); w.Code != http.StatusOK {
		t.Fatalf("maintenance off: %d\n%s", w.Code, w.Body)
	}
	if m, _ := hs.Maintenance(context.Background()); len(m) != 0 {
		t.Fatalf("maintenance after off: %+v", m)
	}
	recs, err := e.auditTrail().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	for _, r := range recs {
		if r.AnalystIdentity == "(operator:ana.ops)" && strings.Contains(r.Reason, "[ui]") {
			tools = append(tools, r.Tool)
		}
	}
	if strings.Join(tools, ",") != admin.MaintenanceOn+","+admin.MaintenanceOff {
		t.Fatalf("operator rows %v, want the on then the off, from [ui]", tools)
	}
}

func TestUI_OverviewShowsTheGatewayMaintenanceBannerAndAServeNotReporting(t *testing.T) {
	e, s, cookie := newUITest(t)
	mustRegister(t, e, stdioEntry("casemgmt"))
	hs := healthsqlite.New(e.db)
	now := time.Now().UTC()
	if err := hs.WriteState(context.Background(), health.Snapshot{
		Backends: []health.BackendRecord{{Backend: "casemgmt", Live: true, Since: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Hour)}},
		Serve:    &health.ServeStatus{Boot: now.Add(-2 * time.Hour), LastRoundAt: now.Add(-time.Hour), RoundInterval: 30 * time.Second},
	}); err != nil {
		t.Fatal(err)
	}
	gw := url.Values{"scope": {"gateway"}, "message": {"Atualização do binário"}, "csrf": {s.csrf}}
	if w := uiDo(s, "POST", "/upstreams/maintenance/on", gw, cookie, samePost); w.Code != http.StatusOK {
		t.Fatalf("gateway maintenance on: %d\n%s", w.Code, w.Body)
	}
	overview := uiDo(s, "GET", "/", nil, cookie, nil).Body.String()
	for _, want := range []string{"Gatte is in planned maintenance", "Atualização do binário", "not reporting"} {
		if !strings.Contains(overview, want) {
			t.Errorf("Overview lacks %q", want)
		}
	}
	page := uiDo(s, "GET", "/upstreams", nil, cookie, nil).Body.String()
	if !strings.Contains(page, "End gateway maintenance") {
		t.Error("the Backends page does not offer to end the gateway maintenance")
	}
}
