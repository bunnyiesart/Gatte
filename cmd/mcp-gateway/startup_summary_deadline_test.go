package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// ---------------------------------------------------------------------------
// The startup summary must survive the connect deadline it is handed.
//
// These need no vault and no issuer, so they never skip.
// ---------------------------------------------------------------------------

// summaryDB returns an in-memory database with the two schemas the startup
// summary reads, migrated the way openStore does it.
func summaryDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open(:memory:): %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for name, migrate := range map[string]func(*sql.DB) error{
		"upstream registry": registrysqlite.Migrate,
		"tool quarantine":   quarantinesqlite.Migrate,
	} {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate %s: %v", name, err)
		}
	}
	return db
}

// TestNewStartupSummary_SurvivesASpentConnectDeadline is the whole defect.
//
// buildServer bounds gw.Connect with config.DefaultConnectTimeout and hands
// the SAME context to newStartupSummary. gateway.Connect walks its entries
// sequentially on that one context with no per-entry sub-timeout, so a
// single upstream that accepts the spawn and never answers tools/list
// consumes the entire budget -- and the context that reaches the summary is
// already expired. Every read then fails, and the diagnostic an operator
// needs most (WHICH upstream did not come up, which role now reaches
// nothing, which grant addresses nothing) is precisely the one that goes
// silent, exactly when a backend hung.
//
// The summary's own doc calls every read best-effort. Best-effort means it
// tries; a read on a context that expired before the function was called
// has not tried.
func TestNewStartupSummary_SurvivesASpentConnectDeadline(t *testing.T) {
	db := summaryDB(t)
	reg := registrysqlite.New(db)
	quar := quarantinesqlite.New(db)

	ctx := context.Background()
	for _, name := range []string{"casemgmt", "logsearch"} {
		entry := registry.UpstreamServer{
			Name:      name,
			Transport: registry.TransportStdio,
			Command:   "/usr/bin/true",
		}
		if err := reg.Register(ctx, entry); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}

	startedAt := time.Now()
	if _, err := quar.Observe(ctx, "casemgmt", quarantine.ToolIdentity{
		Name:        "list_cases",
		Description: "list open cases",
		InputSchema: []byte(`{"type":"object"}`),
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}

	cfg := &config.Config{
		Roles: []config.Role{
			// Reaches the one tool observed this boot.
			{Name: "n1-triage", Tools: []string{"casemgmt.list_cases"}},
			// Reaches nothing: logsearch is the upstream that hung.
			{Name: "dfir-lead", Grants: map[string][]string{"logsearch": {"*"}}},
			// Reaches nothing because nobody registered docsearch.
			{Name: "researcher", Grants: map[string][]string{"docsearch": {"*"}}},
		},
	}

	// The shape gateway.Connect produces for an upstream that did not come
	// up: the entry named with %q.
	connErr := errors.New(`upstream "logsearch" unavailable: context deadline exceeded`)

	// A context whose deadline is already in the past -- what buildServer
	// hands over after Connect burned the whole 30s on one hung upstream.
	spent, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()

	// The positive control for everything below: the store really does
	// refuse a read on this context. Without it, a passing test could mean
	// the summary was fixed OR that an expired deadline never cost
	// anything, and the second reading would make the assertions vacuous.
	if _, err := reg.List(spent); err == nil {
		t.Fatal("reg.List on an expired context returned no error, so this test proves nothing about the deadline")
	}
	if _, err := quar.List(spent, ""); err == nil {
		t.Fatal("quar.List on an expired context returned no error, so this test proves nothing about the deadline")
	}

	got := newStartupSummary(spent, cfg, "127.0.0.1:8080", reg, quar, startedAt, connErr)

	if got.UpstreamsRegistered != 2 {
		t.Errorf("UpstreamsRegistered = %d, want 2 -- the registry is readable; only the caller's deadline was spent", got.UpstreamsRegistered)
	}
	if len(got.UpstreamsFailed) != 1 || got.UpstreamsFailed[0] != "logsearch" {
		t.Errorf("UpstreamsFailed = %v, want [logsearch] -- the one upstream that hung is the one the operator must be told about", got.UpstreamsFailed)
	}
	if got.ToolsDiscovered != 1 {
		t.Errorf("ToolsDiscovered = %d, want 1", got.ToolsDiscovered)
	}
	if len(got.Roles) != 3 {
		t.Errorf("Roles = %+v, want one entry per configured role -- without them there is no `role reach` line and no dead-role warning", got.Roles)
	}
	if len(got.UnregisteredGrants) != 1 || got.UnregisteredGrants[0].Backend != "docsearch" {
		t.Errorf("UnregisteredGrants = %+v, want the docsearch gap (ADR-0016's integration half)", got.UnregisteredGrants)
	}
}

// TestStartupSummary_UnreadableRegistryDoesNotClaimZeroFailures pins the
// second half: when the registry read did not happen, upstreams_failed is
// not a count of anything, and printing len(nil) states "no upstream
// failed" on the strength of a read that never returned. Every other
// counter from that read degrades to the documented -1; this one must too,
// and the summary must say out loud that it could not be built.
func TestStartupSummary_UnreadableRegistryDoesNotClaimZeroFailures(t *testing.T) {
	logger, logs := serveTestLogger()
	// Exactly what newStartupSummary returns when reg.List and quar.List
	// both fail: the three documented -1s, and nil for everything else.
	startupSummary{
		Addr:                "127.0.0.1:8080",
		Loopback:            true,
		UpstreamsRegistered: -1,
		ToolsDiscovered:     -1,
		ToolsServable:       -1,
		RequireSigned:       true,
	}.log(logger)

	out := logs.String()
	if strings.Contains(out, "upstreams_failed=0") {
		t.Errorf("the startup log states upstreams_failed=0 from a registry read that never returned:\n%s", out)
	}
	if !strings.Contains(out, "upstreams_failed=-1") {
		t.Errorf("upstreams_failed does not degrade to the documented -1 (unknown):\n%s", out)
	}

	var warned bool
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN") && strings.Contains(line, "startup summary") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("nothing warns that the startup diagnostic itself could not be built, so the -1s read as counts:\n%s", out)
	}
}
