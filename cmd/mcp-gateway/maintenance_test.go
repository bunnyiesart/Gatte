package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/health"
	healthsqlite "github.com/bunnyiesart/Gatte/internal/health/sqlite"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Planned maintenance from the terminal (design/adr/0041 item 6): the same
// service the API uses, so the same validation and the same operator rows.

// maintenanceConfig is a configuration file with one registered backend.
func maintenanceConfig(t *testing.T) string {
	t.Helper()
	cfg := accessConfig(t, "")
	code, out, errText := runCLI("upstream", "register", "-config", cfg, "-name", "casemgmt", "-transport", "stdio", "-command", "/usr/local/bin/casemgmt-mcp")
	requireExit(t, code, exitOK, "register: "+out+errText)
	return cfg
}

func TestUpstreamMaintenance_OnAndOffAreAuditedOperatorActions(t *testing.T) {
	cfg := maintenanceConfig(t)
	t.Setenv("SUDO_USER", "operator1")

	// Flags after the name, as an operator types them.
	code, out, errText := runCLI("upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", `Troca de versão do "casemgmt"`, "-until", "2h")
	requireExit(t, code, exitOK, "maintenance on: "+out+errText)
	requireContains(t, out, "casemgmt", "maintenance on")

	code, out, _ = runCLI("maintenance", "list", "-config", cfg)
	requireExit(t, code, exitOK, "maintenance list")
	for _, want := range []string{"casemgmt", `Troca de versão do "casemgmt"`, "(operator:operator1)"} {
		requireContains(t, out, want, "maintenance list")
	}

	code, out, _ = runCLI("maintenance", "list", "-config", cfg, "-json")
	requireExit(t, code, exitOK, "maintenance list -json")
	var list adminapi.MaintenanceList
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Upstreams) != 1 || list.Upstreams[0].Until == nil {
		t.Fatalf("maintenance list -json = %s (%v)", out, err)
	}
	if d := time.Until(*list.Upstreams[0].Until); d < 110*time.Minute || d > 2*time.Hour {
		t.Errorf("-until 2h stored %v from now", d)
	}

	// The same again is no change and no row.
	code, out, _ = runCLI("upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", `Troca de versão do "casemgmt"`, "-until", list.Upstreams[0].Until.Format(time.RFC3339Nano))
	requireExit(t, code, exitOK, "maintenance on, again")
	requireContains(t, out, "nothing changed", "maintenance on, again")

	code, out, errText = runCLI("upstream", "maintenance", "off", "-config", cfg, "casemgmt")
	requireExit(t, code, exitOK, "maintenance off: "+out+errText)
	code, _, _ = runCLI("upstream", "maintenance", "off", "-config", cfg, "casemgmt")
	requireExit(t, code, exitProblem, "maintenance off of a backend not in maintenance")

	rows, check := trailOf(t, cfg)
	var tools []string
	for _, r := range rows {
		if r.AnalystIdentity == "(operator:operator1)" {
			tools = append(tools, r.Tool)
		}
	}
	if strings.Join(tools, ",") != admin.MaintenanceOn+","+admin.MaintenanceOff {
		t.Fatalf("operator rows %v, want one on and one off", tools)
	}
	if !check.Intact() {
		t.Fatal("the chain is broken after the console's rows")
	}
}

func TestMaintenance_TheWholeGatewayOnListOff(t *testing.T) {
	cfg := maintenanceConfig(t)
	t.Setenv("SUDO_USER", "operator1")
	code, out, errText := runCLI("maintenance", "on", "-config", cfg, "-message", "Atualização do binário", "-until", "2026-01-01T00:00:00Z")
	requireExit(t, code, exitCannotRun, "gateway maintenance with an until in the past: "+out+errText)

	code, out, errText = runCLI("maintenance", "on", "-config", cfg, "-message", "Atualização do binário")
	requireExit(t, code, exitOK, "gateway maintenance on: "+out+errText)
	code, out, _ = runCLI("maintenance", "list", "-config", cfg)
	requireExit(t, code, exitOK, "maintenance list")
	requireContains(t, out, "(gateway)", "maintenance list")
	requireContains(t, out, "Atualização do binário", "maintenance list")
	code, out, errText = runCLI("maintenance", "off", "-config", cfg)
	requireExit(t, code, exitOK, "gateway maintenance off: "+out+errText)
	code, out, _ = runCLI("maintenance", "list", "-config", cfg)
	requireExit(t, code, exitOK, "maintenance list, empty")
	requireContains(t, out, "Nothing is in maintenance", "maintenance list, empty")
}

// A message the gateway could not put in front of a model is refused
// before anything is opened or recorded, and so is a backend nobody
// registered.
func TestUpstreamMaintenance_RefusesWhatTheServiceRefuses(t *testing.T) {
	cfg := maintenanceConfig(t)
	t.Setenv("SUDO_USER", "operator1")
	for label, args := range map[string][]string{
		"newline":        {"upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", "a\nb"},
		"no message":     {"upstream", "maintenance", "on", "-config", cfg, "casemgmt"},
		"bad until":      {"upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", "x", "-until", "tomorrow"},
		"too far":        {"upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", "x", "-until", "2400h"},
		"not registered": {"upstream", "maintenance", "on", "-config", cfg, "docsearch", "-message", "x"},
		"no name":        {"upstream", "maintenance", "on", "-config", cfg, "-message", "x"},
		"unknown verb":   {"upstream", "maintenance", "pause", "-config", cfg, "casemgmt"},
	} {
		if code, out, errText := runCLI(args...); code != exitCannotRun {
			t.Errorf("%s: exit %d, want %d\n%s%s", label, code, exitCannotRun, out, errText)
		}
	}
	if rows, _ := trailOf(t, cfg); len(rows) != 0 {
		t.Fatalf("refused requests wrote rows: %+v", rows)
	}
}

// deregister removes the maintenance, health and last listing of the name
// with everything else keyed by it: a backend registered again under that
// name inherits no state (design/adr/0041 item 6).
func TestRunUpstreamDeregister_ForgetsHealthAndMaintenance(t *testing.T) {
	e := newOpTestEnv(t)
	mustRegister(t, e, stdioEntry("casemgmt"))
	hs := healthsqlite.New(e.db)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := hs.Start(ctx, health.Maintenance{Target: "casemgmt", Message: "x", StartedAt: now, SetBy: "(operator:a)", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := hs.WriteState(ctx, health.Snapshot{Backends: []health.BackendRecord{{Backend: "casemgmt", Live: true, Since: now, UpdatedAt: now}},
		Listings: map[string][]health.ListedTool{"casemgmt": {{Tool: "list_cases", Hash: "abc"}}}, ListedAt: now}); err != nil {
		t.Fatal(err)
	}

	requireExit(t, runUpstreamDeregister(e.opEnv, "casemgmt"), exitOK, "deregister")

	if m, _ := hs.Maintenance(ctx); len(m) != 0 {
		t.Errorf("maintenance after deregister: %+v", m)
	}
	if b, _ := hs.Backends(ctx); len(b) != 0 {
		t.Errorf("backend health after deregister: %+v", b)
	}
	if l, _ := hs.Listings(ctx); len(l) != 0 {
		t.Errorf("last listing after deregister: %+v", l)
	}
}

// Running "on" again to fix the message keeps the end analysts were told;
// "-until none" is how the end is taken back.
func TestUpstreamMaintenance_OnAgainWithoutUntilKeepsTheAnnouncedEnd(t *testing.T) {
	cfg := maintenanceConfig(t)
	t.Setenv("SUDO_USER", "operator1")
	stored := func() *adminapi.UpstreamMaintenance {
		t.Helper()
		code, out, _ := runCLI("maintenance", "list", "-config", cfg, "-json")
		requireExit(t, code, exitOK, "maintenance list -json")
		var list adminapi.MaintenanceList
		if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Upstreams) != 1 {
			t.Fatalf("maintenance list -json = %s (%v)", out, err)
		}
		return &list.Upstreams[0]
	}
	code, out, errText := runCLI("upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", "Troca de versão", "-until", "2h")
	requireExit(t, code, exitOK, "maintenance on: "+out+errText)
	first := stored()
	if first.Until == nil {
		t.Fatal("-until 2h stored no end")
	}

	code, out, errText = runCLI("upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", "Troca de versão do casemgmt")
	requireExit(t, code, exitOK, "maintenance on, new message: "+out+errText)
	second := stored()
	if second.Message != "Troca de versão do casemgmt" || second.Until == nil || !second.Until.Equal(*first.Until) || !second.StartedAt.Equal(first.StartedAt) {
		t.Fatalf("after a new message without -until: %+v, want the message changed and until %v kept", second.Maintenance, *first.Until)
	}

	code, out, errText = runCLI("upstream", "maintenance", "on", "-config", cfg, "casemgmt", "-message", "Troca de versão do casemgmt", "-until", "none")
	requireExit(t, code, exitOK, "maintenance on -until none: "+out+errText)
	if third := stored(); third.Until != nil {
		t.Fatalf("after -until none: until %v, want none", *third.Until)
	}
}
