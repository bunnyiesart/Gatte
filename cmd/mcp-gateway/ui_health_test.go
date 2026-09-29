//go:build !nofront

package main

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
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

// A maintenance in force can be updated from the page, as from the CLI and
// the API: the form comes filled with the current message and end, so
// fixing one does not erase the other.
func TestUI_AMaintenanceInForceCanBeUpdated(t *testing.T) {
	e, s, cookie := newUITest(t)
	mustRegister(t, e, stdioEntry("casemgmt"))
	hs := healthsqlite.New(e.db)
	for _, form := range []url.Values{
		{"scope": {"upstream"}, "upstream": {"casemgmt"}, "message": {`<b>Troca</b> de versão`}, "until": {"2h"}, "csrf": {s.csrf}},
		{"scope": {"gateway"}, "message": {"Atualização do binário"}, "until": {"3h"}, "csrf": {s.csrf}},
	} {
		if w := uiDo(s, "POST", "/upstreams/maintenance/on", form, cookie, samePost); w.Code != http.StatusOK {
			t.Fatalf("maintenance on: %d\n%s", w.Code, w.Body)
		}
	}
	rows, err := hs.Maintenance(context.Background())
	if err != nil || len(rows) != 2 {
		t.Fatalf("maintenance: %+v, %v", rows, err)
	}
	page := uiDo(s, "GET", "/upstreams", nil, cookie, nil).Body.String()
	for _, m := range rows {
		for _, want := range []string{`value="` + template.HTMLEscapeString(m.Message) + `"`, `value="` + m.Until.UTC().Format(time.RFC3339) + `"`} {
			if !strings.Contains(page, want) {
				t.Errorf("the Backends page has no update form filled with %s", want)
			}
		}
	}
	if strings.Count(page, "Update maintenance") < 1 || !strings.Contains(page, "Update gateway maintenance") {
		t.Error("the Backends page offers no update of a maintenance in force")
	}

	// The update keeps when it started.
	up := url.Values{"scope": {"upstream"}, "upstream": {"casemgmt"}, "message": {"Troca de versão do casemgmt"}, "csrf": {s.csrf}}
	if w := uiDo(s, "POST", "/upstreams/maintenance/on", up, cookie, samePost); w.Code != http.StatusOK {
		t.Fatalf("maintenance update: %d\n%s", w.Code, w.Body)
	}
	after, _ := hs.Maintenance(context.Background())
	for _, m := range after {
		for _, b := range rows {
			if m.Target == "casemgmt" && b.Target == "casemgmt" && (m.Message != "Troca de versão do casemgmt" || !m.StartedAt.Equal(b.StartedAt)) {
				t.Errorf("after the update: %+v, want the new message and the same start", m)
			}
		}
	}
}

// A console over a backend that does not list the maintenance feature
// neither shows the forms nor forwards their POSTs.
func TestUI_MaintenancePostsAreRefusedWithoutTheFeature(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	sock := filepath.Join(uiSocketDir(t), "op.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/whoami":
			fmt.Fprint(w, `{"operator":"ana.ops","features":[]}`)
		case "/v1/upstreams":
			fmt.Fprint(w, `{"upstreams":[]}`)
		default:
			fmt.Fprint(w, `{}`)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	s := newUIFrontOn(t, sock)
	cookie := uiLogin(t, s)

	for _, path := range []string{"/upstreams/maintenance/on", "/upstreams/maintenance/off"} {
		form := url.Values{"scope": {"gateway"}, "message": {"x"}, "csrf": {s.csrf}}
		if w := uiDo(s, "POST", path, form, cookie, samePost); w.Code != http.StatusNotFound {
			t.Errorf("POST %s without the feature: %d, want 404", path, w.Code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, c := range calls {
		if strings.Contains(c, "/maintenance") {
			t.Errorf("the console forwarded %s to a backend without the feature", c)
		}
	}
}
