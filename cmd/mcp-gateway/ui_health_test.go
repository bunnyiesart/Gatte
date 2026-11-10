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

// The console's side of design/adr/0041 and 0055: backend health on the MCP
// Servers / APIs list, and planned maintenance of one backend as a panel on its
// own page, through the management API like every other action. The
// gateway-wide maintenance is not a console action (design/adr/0055 §2).

func TestUI_ServersShowHealthAndMaintenanceIsAnAuditedOperatorAction(t *testing.T) {
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

	list := uiDo(s, "GET", "/servers", nil, cookie, nil).Body.String()
	for _, want := range []string{"Reconnecting", "not_brought_up"} {
		if !strings.Contains(list, want) {
			t.Errorf("the servers list lacks %q", want)
		}
	}
	page := uiDo(s, "GET", "/servers/casemgmt", nil, cookie, nil).Body.String()
	for _, want := range []string{"Planned maintenance", `action="` + s.session + `/servers/casemgmt/maintenance/on"`, `name="csrf"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the server page lacks %q", want)
		}
	}
	if strings.Contains(page, `name="scope"`) {
		t.Error("the server page offers a gateway-wide maintenance")
	}

	on := url.Values{"message": {`<b>Troca</b> de versão`}, "until": {"2h"}}
	if w := uiDo(s, "POST", "/servers/casemgmt/maintenance/on", on, cookie, samePost); w.Code != http.StatusForbidden {
		t.Fatalf("maintenance on without the form token: %d, want 403", w.Code)
	}
	if m, _ := hs.Maintenance(context.Background()); len(m) != 0 {
		t.Fatalf("a POST without the form token opened a maintenance: %+v", m)
	}
	on.Set("csrf", s.csrf)
	if w := uiDo(s, "POST", "/servers/casemgmt/maintenance/on", on, cookie, samePost); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "planned maintenance") {
		t.Fatalf("maintenance on: %d\n%s", w.Code, w.Body)
	}
	m, err := hs.Maintenance(context.Background())
	if err != nil || len(m) != 1 || m[0].Target != "casemgmt" || m[0].Message != `<b>Troca</b> de versão` || m[0].Until.IsZero() {
		t.Fatalf("maintenance after the form: %+v, %v", m, err)
	}

	page = uiDo(s, "GET", "/servers/casemgmt", nil, cookie, nil).Body.String()
	if !strings.Contains(page, "&lt;b&gt;Troca&lt;/b&gt; de versão") || strings.Contains(page, "<b>Troca") {
		t.Error("the server page does not escape the operator's message")
	}
	if !strings.Contains(page, "End maintenance") || !strings.Contains(page, "In maintenance") {
		t.Error("the server page does not offer to end the maintenance")
	}
	if list := uiDo(s, "GET", "/servers", nil, cookie, nil).Body.String(); !strings.Contains(list, "In maintenance") {
		t.Error("the servers list does not show the backend in maintenance")
	}

	off := url.Values{"csrf": {s.csrf}}
	if w := uiDo(s, "POST", "/servers/casemgmt/maintenance/off", off, cookie, samePost); w.Code != http.StatusOK {
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

// What needs the operator and names no backend -- a gateway maintenance opened
// in the terminal, a gateway process that stopped reporting -- is shown above
// the servers list, with where to end the maintenance.
func TestUI_ServersShowTheGatewayMaintenanceAndAServeNotReporting(t *testing.T) {
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
	if _, err := hs.Start(context.Background(), health.Maintenance{Target: health.GatewayTarget, Message: "Atualização do binário",
		StartedAt: now, SetBy: "ana.ops", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	list := uiDo(s, "GET", "/servers", nil, cookie, nil).Body.String()
	for _, want := range []string{"The gateway is in planned maintenance", "mcp-gateway maintenance off", "not reporting"} {
		if !strings.Contains(list, want) {
			t.Errorf("the servers list lacks %q", want)
		}
	}
}

// A maintenance in force can be updated from the page, as from the CLI and
// the API: the form comes filled with the current message and end, so
// fixing one does not erase the other.
func TestUI_AMaintenanceInForceCanBeUpdated(t *testing.T) {
	e, s, cookie := newUITest(t)
	mustRegister(t, e, stdioEntry("casemgmt"))
	hs := healthsqlite.New(e.db)
	form := url.Values{"message": {`<b>Troca</b> de versão`}, "until": {"2h"}, "csrf": {s.csrf}}
	if w := uiDo(s, "POST", "/servers/casemgmt/maintenance/on", form, cookie, samePost); w.Code != http.StatusOK {
		t.Fatalf("maintenance on: %d\n%s", w.Code, w.Body)
	}
	rows, err := hs.Maintenance(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("maintenance: %+v, %v", rows, err)
	}
	page := uiDo(s, "GET", "/servers/casemgmt", nil, cookie, nil).Body.String()
	for _, want := range []string{`value="` + template.HTMLEscapeString(rows[0].Message) + `"`, `value="` + rows[0].Until.UTC().Format(time.RFC3339) + `"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the server page has no update form filled with %s", want)
		}
	}
	if !strings.Contains(page, "Update maintenance") {
		t.Error("the server page offers no update of a maintenance in force")
	}

	// The update keeps when it started.
	up := url.Values{"message": {"Troca de versão do casemgmt"}, "csrf": {s.csrf}}
	if w := uiDo(s, "POST", "/servers/casemgmt/maintenance/on", up, cookie, samePost); w.Code != http.StatusOK {
		t.Fatalf("maintenance update: %d\n%s", w.Code, w.Body)
	}
	after, _ := hs.Maintenance(context.Background())
	if len(after) != 1 || after[0].Message != "Troca de versão do casemgmt" || !after[0].StartedAt.Equal(rows[0].StartedAt) {
		t.Errorf("after the update: %+v, want the new message and the same start", after)
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

	for _, path := range []string{"/servers/casemgmt/maintenance/on", "/servers/casemgmt/maintenance/off"} {
		form := url.Values{"message": {"x"}, "csrf": {s.csrf}}
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
