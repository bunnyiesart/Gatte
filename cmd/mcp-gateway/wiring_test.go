package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditjsonl "github.com/bunnyiesart/Gatte/internal/audit/jsonl"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// ---------------------------------------------------------------------------
// [audit.siem] -- the JSONL sink (ADR-0017) at the composition root.
//
// These tests exercise auditRecorder against a real database and a real
// file, because everything they are about is what happens between the two.
// They need no vault and no issuer, so they never skip.
// ---------------------------------------------------------------------------

// wiringDB returns an in-memory database with every schema migrated, the
// way openStore does it.
func wiringDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open(:memory:): %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for name, migrate := range map[string]func(*sql.DB) error{
		"audit trail":     auditsqlite.Migrate,
		"tool quarantine": quarantinesqlite.Migrate,
	} {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate %s: %v", name, err)
		}
	}
	return db
}

// wiringRecord is one well-formed audit record.
func wiringRecord(tool string) audit.Record {
	return audit.Record{
		AnalystIdentity: "sub-42",
		Tool:            tool,
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Now(),
		Outcome:         audit.OutcomeAllowed,
		Reason:          "",
		SourceAddress:   "127.0.0.1",
	}
}

// readJSONLines parses every line of the sink file.
func readJSONLines(t *testing.T, path string) []auditjsonl.Line {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open sink file: %v", err)
	}
	defer f.Close()

	var lines []auditjsonl.Line
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		if strings.TrimSpace(scan.Text()) == "" {
			continue
		}
		var line auditjsonl.Line
		if err := json.Unmarshal(scan.Bytes(), &line); err != nil {
			t.Fatalf("sink line is not the v1 schema: %v (%q)", err, scan.Text())
		}
		lines = append(lines, line)
	}
	if err := scan.Err(); err != nil {
		t.Fatalf("reading sink file: %v", err)
	}
	return lines
}

// TestAuditRecorder_SinkIsWiredWhenConfigured is the whole of ADR-0017 as
// the composition root is responsible for it: with the block present, a
// record written through the port the gateway is handed lands in SQLite
// AND in the file, and the emitted line carries the configured chain plus
// the hash that write actually produced.
//
// The chain is asserted from the file rather than from the config, because
// the failure this catches is the one that is silent: a recorder built with
// the wrong chain name, or with the block read but ignored, still records
// perfectly and leaves `-expect-head` anchored to nothing.
func TestAuditRecorder_SinkIsWiredWhenConfigured(t *testing.T) {
	db := wiringDB(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := &config.Config{Audit: config.Audit{SIEM: config.SIEM{Path: path, Chain: "gatte-test-01"}}}
	logger, _ := serveTestLogger()

	rec, closeSink, err := auditRecorder(cfg, db, logger)
	if err != nil {
		t.Fatalf("auditRecorder: %v", err)
	}
	defer closeSink()

	if err := rec.Record(context.Background(), wiringRecord("casemgmt.list_cases")); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Durable first: the record is in SQLite whether or not the sink saw
	// it, and nothing in this wiring may weaken that.
	stored, err := rec.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("the durable trail holds %d records, want 1", len(stored))
	}

	lines := readJSONLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("the sink file holds %d lines, want 1 -- the JSONL sink is not wired", len(lines))
	}
	got := lines[0]
	if got.Chain != "gatte-test-01" {
		t.Errorf("line chain = %q, want %q (audit.siem.chain is not reaching the recorder)", got.Chain, "gatte-test-01")
	}
	if got.Tool != "casemgmt.list_cases" || got.Caller != "sub-42" {
		t.Errorf("line = %+v, does not describe the record that was written", got)
	}
	if got.Hash == "" {
		t.Error("line carries no hash, so it anchors nothing -- the whole point of ADR-0017 item 3")
	}
	if got.Version != auditjsonl.Version {
		t.Errorf("line version = %d, want %d", got.Version, auditjsonl.Version)
	}
}

// TestAuditRecorder_WithoutTheBlockNothingIsShipped pins the other half of
// the contract: no [audit.siem], no file, no decorator, and a trail that
// behaves exactly as it did before ADR-0017.
//
// The path is handed to the test but never to the config, so a recorder
// that shipped anyway would have had to invent a destination -- which is
// the failure worth catching, since an audit file appearing somewhere
// nobody chose is an analyst-attributed record written to an unreviewed
// location.
func TestAuditRecorder_WithoutTheBlockNothingIsShipped(t *testing.T) {
	db := wiringDB(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, _ := serveTestLogger()

	rec, closeSink, err := auditRecorder(&config.Config{}, db, logger)
	if err != nil {
		t.Fatalf("auditRecorder: %v", err)
	}
	defer closeSink()

	if err := rec.Record(context.Background(), wiringRecord("casemgmt.list_cases")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	stored, err := rec.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("the durable trail holds %d records, want 1", len(stored))
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a sink file exists at %s with no [audit.siem] block (stat err = %v)", path, err)
	}
}

// TestAuditRecorder_UnopenableSinkIsAStartupFailure: the operator asked
// for the sink and it is unavailable, and startup is the one moment
// somebody can act on that. The request-path half of this rule -- an Emit
// that fails is logged and swallowed -- is jsonl.Recorder's own and is
// tested there.
func TestAuditRecorder_UnopenableSinkIsAStartupFailure(t *testing.T) {
	db := wiringDB(t)
	missing := filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")
	cfg := &config.Config{Audit: config.Audit{SIEM: config.SIEM{Path: missing, Chain: "gatte-test-01"}}}
	logger, _ := serveTestLogger()

	rec, closeSink, err := auditRecorder(cfg, db, logger)
	if err == nil {
		closeSink()
		t.Fatal("auditRecorder accepted a sink path it cannot open; the gateway would serve with the SIEM silently absent")
	}
	if rec != nil || closeSink != nil {
		t.Error("auditRecorder returned an error together with something to clean up; the caller has no way to know it must")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("the failure does not name the path that could not be opened: %v", err)
	}
}

// TestBuildServer_SIEMSinkIsWired is the same wiring seen from the place
// it has to actually be called. auditRecorder can be perfect and unused;
// this fails if buildServer does not use it.
//
// The unopenable case is the assertion that cannot be satisfied by
// accident: with the block ignored, a path under a directory that does not
// exist is not a startup failure at all and the process serves.
func TestBuildServer_SIEMSinkIsWired(t *testing.T) {
	t.Run("the file is opened at boot", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.jsonl")
		fx := newServeFixture(t, func(b *strings.Builder) {
			fmt.Fprintf(b, "[audit.siem]\npath = %q\nchain = %q\n", path, "gatte-test-01")
		})
		logger, _ := serveTestLogger()

		stack, err := buildServer(context.Background(), fx.cfg, logger)
		if err != nil {
			t.Fatalf("buildServer: %v", err)
		}
		defer stack.close()

		if _, err := os.Stat(path); err != nil {
			t.Errorf("the sink file was not opened at boot: %v", err)
		}
		if stack.summary.SIEMChain != "gatte-test-01" {
			t.Errorf("startup summary chain = %q, want %q", stack.summary.SIEMChain, "gatte-test-01")
		}
	})

	t.Run("an unopenable sink refuses to start", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")
		fx := newServeFixture(t, func(b *strings.Builder) {
			fmt.Fprintf(b, "[audit.siem]\npath = %q\nchain = %q\n", path, "gatte-test-01")
		})
		logger, _ := serveTestLogger()

		stack, err := buildServer(context.Background(), fx.cfg, logger)
		if err == nil {
			stack.close()
			t.Fatal("buildServer started with a sink it could not open")
		}
		if stack != nil {
			t.Error("buildServer returned both an error and a stack")
		}
	})
}

// TestStartupSummary_SIEMSinkIsVisible: whether the trail leaves this host
// decides whether ADR-0015's truncation detection has an anchor at all,
// and an operator must not have to infer that from a missing line.
func TestStartupSummary_SIEMSinkIsVisible(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		logger, logs := serveTestLogger()
		startupSummary{
			Addr: "127.0.0.1:8080", Loopback: true, RequireSigned: true,
			SIEMChain: "gatte-jail-01", SIEMPath: "/var/log/mcp-gateway/audit.jsonl",
		}.log(logger)

		out := logs.String()
		for _, want := range []string{"gatte-jail-01", "/var/log/mcp-gateway/audit.jsonl"} {
			if !strings.Contains(out, want) {
				t.Errorf("the startup log does not state %q:\n%s", want, out)
			}
		}
	})

	t.Run("absent", func(t *testing.T) {
		logger, logs := serveTestLogger()
		startupSummary{Addr: "127.0.0.1:8080", Loopback: true, RequireSigned: true}.log(logger)

		if out := logs.String(); !strings.Contains(out, "audit.siem") {
			t.Errorf("the startup log does not say the trail is anchored nowhere:\n%s", out)
		}
	})
}

// ---------------------------------------------------------------------------
// [role.grants] naming a backend nobody registered (ADR-0016).
// ---------------------------------------------------------------------------

// TestUnregisteredGrants is the arithmetic: a grant key is compared
// against the registry's own names, exactly, because that is the string
// gateway.Namespaced puts in front of every tool of that upstream.
func TestUnregisteredGrants(t *testing.T) {
	entries := []registry.UpstreamServer{{Name: "casemgmt"}, {Name: "threatintel"}}
	roles := []config.Role{
		{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {"get_case"}}},
		{Name: "dfir-lead", Grants: map[string][]string{
			"threatintel": {"*"},
			"logsearch":   {"search_keyword"},
			"docsearch":   {"*"},
		}},
		// The flat form names no backend key at all and is not this
		// diagnostic's business: roleReach already reports a tool name that
		// matches nothing observed.
		{Name: "flat", Tools: []string{"nowhere.list_cases"}},
	}

	want := []grantGap{
		{Role: "dfir-lead", Backend: "docsearch"},
		{Role: "dfir-lead", Backend: "logsearch"},
	}
	if got := unregisteredGrants(roles, entries); !reflect.DeepEqual(got, want) {
		t.Errorf("unregisteredGrants = %+v, want %+v", got, want)
	}

	if got := unregisteredGrants(roles, nil); len(got) != 4 {
		t.Errorf("with an empty registry every grant is unreachable; got %d gaps, want 4: %+v", len(got), got)
	}
}

// TestUnregisteredGrants_WildcardOverAPrefixOfARegisteredNameIsNotAGap puts
// the gate and the diagnostic side by side on one grant.
//
// access.Role.Allows matches a grant key as a prefix up to the namespace
// separator, so `threatintel = ["*"]` addresses every tool of an upstream
// registered as `threatintel.staging`, while an exact-equality lookup
// finds no entry called `threatintel` and reports the grant as authorizing
// nothing -- printed in the operator's startup log two lines under a `role
// reach` computed from Allows, which says the same role observed tools.
//
// The entry is built as a struct literal on purpose: registry
// UpstreamServer.Validate refuses a name containing the separator and
// gateway.Connect re-checks that on rows the store hands back, so an entry
// shaped like this cannot serve tools today. That is a different package's
// rule, and this diagnostic states its own sentence -- "no upstream
// registered for this, so it authorizes nothing" -- about a registry that
// holds one. It must be read the way the gate reads it, not left true by
// an invariant enforced elsewhere.
//
// The Allows assertion is the premise, not decoration: if the gate ever
// stops reaching across the separator this test must fail loudly rather
// than quietly guard nothing.
func TestUnregisteredGrants_WildcardOverAPrefixOfARegisteredNameIsNotAGap(t *testing.T) {
	entries := []registry.UpstreamServer{{Name: "threatintel.staging"}}
	role := config.Role{Name: "hunter", Grants: map[string][]string{"threatintel": {access.GrantAll}}}

	tool := gateway.Namespaced("threatintel.staging", "lookup_ip")
	domain := access.Role{Name: role.Name, Tools: role.Tools, Grants: role.Grants}
	if !domain.Allows(tool) {
		t.Fatalf("premise gone: the gate no longer authorizes %q under grant threatintel = [%q]", tool, access.GrantAll)
	}

	if gaps := unregisteredGrants([]config.Role{role}, entries); len(gaps) != 0 {
		t.Errorf("unregisteredGrants = %+v, want none -- this grant addresses every tool of the registered %q, so the startup log would say there is no upstream registered for it while the gate reads it as covering one", gaps, entries[0].Name)
	}
}

// TestUnregisteredGrants_NamedGrantDoesNotReachAPrefixedUpstream is the
// other half, and the reason the fix cannot be "prefix match and be done".
//
// A named id may not contain the separator (access.ValidateRole refuses
// one), so under `threatintel = ["lookup_ip"]` the remainder of
// `threatintel.staging.lookup_ip` is `staging.lookup_ip`, which is not the
// id named. Only a wildcard crosses the separator. This grant really does
// authorize nothing, and must keep its warning.
func TestUnregisteredGrants_NamedGrantDoesNotReachAPrefixedUpstream(t *testing.T) {
	entries := []registry.UpstreamServer{{Name: "threatintel.staging"}}
	role := config.Role{Name: "hunter", Grants: map[string][]string{"threatintel": {"lookup_ip"}}}

	domain := access.Role{Name: role.Name, Tools: role.Tools, Grants: role.Grants}
	for _, tool := range []string{
		gateway.Namespaced("threatintel.staging", "lookup_ip"),
		gateway.Namespaced("threatintel.staging", "staging.lookup_ip"),
	} {
		if domain.Allows(tool) {
			t.Fatalf("premise gone: the gate authorizes %q under a named grant on threatintel", tool)
		}
	}

	want := []grantGap{{Role: "hunter", Backend: "threatintel"}}
	if got := unregisteredGrants([]config.Role{role}, entries); !reflect.DeepEqual(got, want) {
		t.Errorf("unregisteredGrants = %+v, want %+v -- a named grant cannot cross the separator, so this one does authorize nothing", got, want)
	}
}

// TestUnregisteredGrants_EmptyGrantListOnARegisteredBackendIsNotAGap
// pins the one case the reachability question would get wrong if it were
// asked only of the ids: `casemgmt = []` authorizes no tool, but the
// backend it names IS registered, and the warning this feeds says "no
// upstream registered for". Warning here would be a second false claim in
// place of the one being fixed.
func TestUnregisteredGrants_EmptyGrantListOnARegisteredBackendIsNotAGap(t *testing.T) {
	entries := []registry.UpstreamServer{{Name: "casemgmt"}}
	role := config.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {}}}

	if gaps := unregisteredGrants([]config.Role{role}, entries); len(gaps) != 0 {
		t.Errorf("unregisteredGrants = %+v, want none -- casemgmt is registered; the grant granting no tool is a different complaint", gaps)
	}
}

// TestStartupSummary_UnregisteredGrantIsWarned: the warning must NAME the
// pair. "1 grant is unreachable" sends an operator diffing a file against
// `mcp-gateway upstream list` by hand, which is the work the line exists to
// save.
func TestStartupSummary_UnregisteredGrantIsWarned(t *testing.T) {
	logger, logs := serveTestLogger()
	startupSummary{
		Addr: "127.0.0.1:8080", Loopback: true, RequireSigned: true,
		UpstreamsRegistered: 2,
		UnregisteredGrants: []grantGap{
			{Role: "dfir-lead", Backend: "logsearch"},
			{Role: "n1-triage", Backend: "docsearch"},
		},
	}.log(logger)

	out := logs.String()
	var warned string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN") && strings.Contains(line, "no upstream registered") {
			warned = line
		}
	}
	if warned == "" {
		t.Fatalf("a grant naming an unregistered backend was not warned about:\n%s", out)
	}
	for _, want := range []string{"dfir-lead", "logsearch", "n1-triage", "docsearch"} {
		if !strings.Contains(warned, want) {
			t.Errorf("the warning does not name %q:\n%s", want, warned)
		}
	}
}

// failingRegistry is a registry.Repository whose List is broken. Only List
// is reached by newStartupSummary; the rest exist to satisfy the port.
type failingRegistry struct{ err error }

func (f failingRegistry) Register(context.Context, registry.UpstreamServer) error { return f.err }
func (f failingRegistry) Get(context.Context, string) (registry.UpstreamServer, error) {
	return registry.UpstreamServer{}, f.err
}
func (f failingRegistry) List(context.Context) ([]registry.UpstreamServer, error) { return nil, f.err }
func (f failingRegistry) Deregister(context.Context, string) error                { return f.err }

// TestNewStartupSummary_UnregisteredGrantsAreSuppressedWhenTheRegistryIsUnreadable
// is the same suppression the dead-role warning applies, for the same
// reason: with no entries to compare against, every grant looks
// unregistered, and a diagnostic that shouts loudest when its own input is
// missing is one people learn to ignore.
func TestNewStartupSummary_UnregisteredGrantsAreSuppressedWhenTheRegistryIsUnreadable(t *testing.T) {
	db := wiringDB(t)
	cfg := &config.Config{Roles: []config.Role{
		{Name: "dfir-lead", Grants: map[string][]string{"logsearch": {"search_keyword"}}},
	}}

	s := newStartupSummary(
		context.Background(), cfg, "127.0.0.1:8080",
		failingRegistry{err: errors.New("no such table: upstream_servers")},
		quarantinesqlite.New(db), time.Now(), nil,
	)
	if len(s.UnregisteredGrants) != 0 {
		t.Errorf("gaps reported from a registry that could not be read: %+v", s.UnregisteredGrants)
	}
	if s.UpstreamsRegistered != -1 {
		t.Errorf("UpstreamsRegistered = %d, want -1 (unknown)", s.UpstreamsRegistered)
	}
}

// TestNewStartupSummary_UnregisteredGrantsAreReported is the positive
// control for the test above: the same role, against a registry that reads
// cleanly, must produce the gap. Without it, "no gaps" would be the
// confident answer a broken lookup also gives.
func TestNewStartupSummary_UnregisteredGrantsAreReported(t *testing.T) {
	db := wiringDB(t)
	cfg := &config.Config{Roles: []config.Role{
		{Name: "dfir-lead", Grants: map[string][]string{"logsearch": {"search_keyword"}}},
	}}

	s := newStartupSummary(
		context.Background(), cfg, "127.0.0.1:8080",
		stubRegistry{entries: []registry.UpstreamServer{{Name: "casemgmt"}}},
		quarantinesqlite.New(db), time.Now(), nil,
	)
	want := []grantGap{{Role: "dfir-lead", Backend: "logsearch"}}
	if !reflect.DeepEqual(s.UnregisteredGrants, want) {
		t.Errorf("UnregisteredGrants = %+v, want %+v", s.UnregisteredGrants, want)
	}
}

// stubRegistry answers List from a fixed set of entries.
type stubRegistry struct{ entries []registry.UpstreamServer }

func (s stubRegistry) Register(context.Context, registry.UpstreamServer) error { return nil }
func (s stubRegistry) Get(context.Context, string) (registry.UpstreamServer, error) {
	return registry.UpstreamServer{}, registry.ErrNotFound
}
func (s stubRegistry) List(context.Context) ([]registry.UpstreamServer, error) {
	return s.entries, nil
}
func (s stubRegistry) Deregister(context.Context, string) error { return nil }

// ---------------------------------------------------------------------------
// role reach, once a role can be composed per backend.
// ---------------------------------------------------------------------------

// TestRoleReaches_CountsGrants is the under-reporting ADR-0016 left
// behind: before it, Granted was len(r.Tools), so a role written entirely
// as [role.grants] reported 0/0 -- indistinguishable from an empty role,
// and excluded from the dead-role warning by the very same number.
func TestRoleReaches_CountsGrants(t *testing.T) {
	observed := map[string]bool{
		"casemgmt.list_cases":       true,
		"casemgmt.get_case":         true,
		"threatintel.lookup_ip":     true,
		"threatintel.lookup_domain": true,
		"threatintel.virustotal":    true,
		// Deliberately adjacent, to pin the boundary access.Role.Allows
		// draws: a wildcard on "threatintel" must not reach this.
		"threatintelx.lookup_ip": true,
	}
	roles := []config.Role{
		{
			Name:   "grants-only",
			Grants: map[string][]string{"casemgmt": {"get_case", "add_note"}},
		},
		{
			Name:   "wildcard",
			Grants: map[string][]string{"threatintel": {"*"}},
		},
		{
			Name:   "both",
			Tools:  []string{"casemgmt.list_cases"},
			Grants: map[string][]string{"threatintel": {"lookup_ip"}},
		},
		{
			Name:   "granted-nothing-registered",
			Grants: map[string][]string{"logsearch": {"*"}},
		},
	}

	want := []roleReach{
		// add_note was never observed: 1 of 2.
		{Name: "grants-only", Granted: 2, Observed: 1},
		// Three threatintel tools observed, and threatintelx is not one of
		// them. No finite granted count, so the backend is named instead.
		{Name: "wildcard", Granted: 0, Wildcards: []string{"threatintel:*"}, Observed: 3},
		{Name: "both", Granted: 2, Observed: 2},
		{Name: "granted-nothing-registered", Granted: 0, Wildcards: []string{"logsearch:*"}, Observed: 0},
	}
	if got := roleReaches(roles, observed); !reflect.DeepEqual(got, want) {
		t.Errorf("roleReaches = %+v, want %+v", got, want)
	}
}

// TestStartupSummary_WildcardReachIsNamedNotCounted: a wildcard grant has
// no finite granted count, so the line names the backend. And a wildcard
// that reaches nothing is the loudest version of the dead role -- it must
// not fall out of the warning just because its denominator is zero.
func TestStartupSummary_WildcardReachIsNamedNotCounted(t *testing.T) {
	logger, logs := serveTestLogger()
	startupSummary{
		Addr: "127.0.0.1:8080", Loopback: true, RequireSigned: true,
		ToolsDiscovered: 4, ToolsServable: 4,
		Roles: []roleReach{
			{Name: "wildcard", Granted: 0, Wildcards: []string{"threatintel:*"}, Observed: 3},
			{Name: "dead-wildcard", Granted: 0, Wildcards: []string{"logsearch:*"}, Observed: 0},
		},
	}.log(logger)

	out := logs.String()
	if !strings.Contains(out, "threatintel:*") {
		t.Errorf("the role reach line does not name the wildcard backend:\n%s", out)
	}
	var warned string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN") && strings.Contains(line, "dead-wildcard") {
			warned = line
		}
	}
	if warned == "" {
		t.Errorf("a role whose only grant is a wildcard over nothing observed was not warned about:\n%s", out)
	}
	if strings.Contains(warned, "\"wildcard\"") {
		t.Errorf("a wildcard role that does reach tools was reported as dead:\n%s", warned)
	}
}

// TestRoleReaches_MatchesTheGate is the anti-second-opinion check. It
// walks a table of names through roleReaches and through access.Role.Allows
// as the request path reaches it -- config.Config.ToAccessPolicy, then
// Policy.Authorize -- and requires the two to agree on every one.
//
// A count computed by a looser rule than the gate is not a smaller bug
// than a wrong gate: it is what tells the operator the gate is fine.
func TestRoleReaches_MatchesTheGate(t *testing.T) {
	role := config.Role{
		Name:  "mixed",
		Tools: []string{"casemgmt.list_cases"},
		Grants: map[string][]string{
			"threatintel": {"*"},
			"logsearch":   {"search_relative"},
		},
	}
	names := []string{
		"casemgmt.list_cases",
		"casemgmt.get_case",
		"threatintel.lookup_ip",
		"threatintel.anything_new",
		"threatintelx.lookup_ip",
		"logsearch.search_relative",
		"logsearch.search_keyword",
	}

	cfg := &config.Config{
		Roles:       []config.Role{role},
		GroupToRole: map[string]string{"g": "mixed"},
	}
	policy, err := cfg.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	id := access.Identity{Subject: "sub-1", Groups: []string{"g"}}

	allowed := 0
	for _, name := range names {
		if policy.Authorize(id, name) == nil {
			allowed++
		}
	}

	observed := make(map[string]bool, len(names))
	for _, name := range names {
		observed[name] = true
	}
	reach := roleReaches([]config.Role{role}, observed)
	if len(reach) != 1 {
		t.Fatalf("roleReaches returned %d rows, want 1", len(reach))
	}
	if reach[0].Observed != allowed {
		t.Errorf("role reach says %d of these names are reachable, the gate allows %d -- the summary is a second opinion",
			reach[0].Observed, allowed)
	}
}

// ---------------------------------------------------------------------------
// `tool approve` says who the approval authorizes (ADR-0016 named debt).
// ---------------------------------------------------------------------------

// approveFixture observes one tool so that it can be approved, and points
// the environment's config at roles.
func approveFixture(t *testing.T, e opTestEnv, roles []config.Role) {
	t.Helper()
	e.cfg.Roles = roles
	mustObserve(t, e, "casemgmt", irisListCases)
}

// TestRunToolApprove_NamesTheRolesItAuthorizes pays the debt ADR-0016
// records in those words: under a "*" grant, approving a definition is the
// SOLE remaining human act between that tool and every analyst in that
// role, and the operator at this prompt believes they are answering a
// question about the definition only.
func TestRunToolApprove_NamesTheRolesItAuthorizes(t *testing.T) {
	e := newOpTestEnv(t)
	approveFixture(t, e, []config.Role{
		{Name: "n1-triage", Tools: []string{"casemgmt.list_cases"}},
		{Name: "dfir-lead", Grants: map[string][]string{"casemgmt": {"*"}}},
		{Name: "unrelated", Grants: map[string][]string{"threatintel": {"*"}}},
	})

	if code := runToolApprove(e.opEnv, "casemgmt", "list_cases"); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}

	out := e.stdoutText()
	for _, want := range []string{"n1-triage", "dfir-lead"} {
		if !strings.Contains(out, want) {
			t.Errorf("approving casemgmt.list_cases did not name role %q, which can now call it:\n%s", want, out)
		}
	}
	if strings.Contains(out, "unrelated") {
		t.Errorf("a role that does not cover this tool was named as though it did:\n%s", out)
	}
	if !strings.Contains(out, "0016") {
		t.Errorf("the wildcard notice does not cite the ADR that records the trade:\n%s", out)
	}
	if !strings.Contains(out, "ONLY remaining human act") {
		t.Errorf("the output does not say what a wildcard grant makes this approval mean:\n%s", out)
	}
}

// TestRunToolApprove_SaysWhenNoRoleCoversIt: the other answer is worth as
// much. An operator who approves a tool and sees nothing happen for the
// analyst who asked for it should be told the second edit exists.
func TestRunToolApprove_SaysWhenNoRoleCoversIt(t *testing.T) {
	e := newOpTestEnv(t)
	approveFixture(t, e, []config.Role{
		{Name: "n1-triage", Tools: []string{"casemgmt.get_case"}},
	})

	if code := runToolApprove(e.opEnv, "casemgmt", "list_cases"); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}

	out := e.stdoutText()
	if !strings.Contains(out, "No configured role covers casemgmt.list_cases") {
		t.Errorf("approving a tool no role grants did not say so:\n%s", out)
	}
	if strings.Contains(out, "ONLY remaining human act") {
		t.Errorf("the wildcard notice was printed for a tool no wildcard covers:\n%s", out)
	}
}

// TestRunToolApprove_NamesTheGrantThatCovers checks the explanation beside
// each role, which is what makes the block actionable: the operator has to
// know WHICH line of the file to go and read.
func TestRunToolApprove_NamesTheGrantThatCovers(t *testing.T) {
	e := newOpTestEnv(t)
	approveFixture(t, e, []config.Role{
		{Name: "named-grant", Grants: map[string][]string{"casemgmt": {"list_cases"}}},
	})

	if code := runToolApprove(e.opEnv, "casemgmt", "list_cases"); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}
	out := e.stdoutText()
	if !strings.Contains(out, "[role.grants] casemgmt") {
		t.Errorf("the output does not name the grant that covers the tool:\n%s", out)
	}
	if strings.Contains(out, "wildcard") {
		t.Errorf("a named grant was described as a wildcard:\n%s", out)
	}
}

// TestRunToolApprove_ChangedToolStillWarnsFirst: the coverage block is
// additional output on the rug-pull path, not a replacement for it.
func TestRunToolApprove_ChangedToolStillWarnsFirst(t *testing.T) {
	e := newOpTestEnv(t)
	approveFixture(t, e, []config.Role{
		{Name: "dfir-lead", Grants: map[string][]string{"casemgmt": {"*"}}},
	})
	mustApprove(t, e, "casemgmt", "list_cases")
	mustObserve(t, e, "casemgmt", changedIrisListCases)

	if code := runToolApprove(e.opEnv, "casemgmt", "list_cases"); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}
	out := e.stdoutText()
	if !strings.Contains(out, "CHANGED TOOL") {
		t.Errorf("the rug-pull warning is gone:\n%s", out)
	}
	warn := strings.Index(out, "CHANGED TOOL")
	cover := strings.Index(out, "dfir-lead")
	if cover < 0 {
		t.Fatalf("the coverage block did not print on the changed path:\n%s", out)
	}
	if warn > cover {
		t.Errorf("the coverage block printed before the rug-pull warning:\n%s", out)
	}
}

// quarantineStatusIsApproved is a sanity helper: the tests above assert on
// output, and a command that printed the right prose while approving
// nothing would pass them all.
func quarantineStatusIsApproved(t *testing.T, e opTestEnv, server, tool string) {
	t.Helper()
	got, err := e.tools().Get(context.Background(), server, tool)
	if err != nil {
		t.Fatalf("reading %s.%s back: %v", server, tool, err)
	}
	if got.Status != quarantine.StatusApproved || !got.Usable() {
		t.Errorf("%s.%s is %s (usable=%t) after approval", server, tool, got.Status, got.Usable())
	}
}

// TestRunToolApprove_StillApproves is that sanity check.
func TestRunToolApprove_StillApproves(t *testing.T) {
	e := newOpTestEnv(t)
	approveFixture(t, e, []config.Role{{Name: "dfir-lead", Grants: map[string][]string{"casemgmt": {"*"}}}})

	if code := runToolApprove(e.opEnv, "casemgmt", "list_cases"); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}
	quarantineStatusIsApproved(t, e, "casemgmt", "list_cases")
}

// ---------------------------------------------------------------------------
// `audit -verify` says where the expected head comes from (ADR-0017 item 3).
// ---------------------------------------------------------------------------

// TestRunAuditVerify_NamesTheChainToAnchorAgainst. -expect-head has existed
// since ADR-0015 with nothing to hang on it: the operator was told to
// record the head "somewhere this gateway cannot write" and left to invent
// that somewhere. With [audit.siem] configured, the command knows exactly
// which chain to ask Graylog for, and saying so is the difference between
// a hook and a procedure.
func TestRunAuditVerify_NamesTheChainToAnchorAgainst(t *testing.T) {
	e := newOpTestEnv(t)
	mustRecord(t, e, wiringRecord("casemgmt.list_cases"))

	if code := runAuditVerify(e.opEnv, ""); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}
	if out := e.stdoutText(); strings.Contains(out, "gatte-jail-01") {
		t.Fatalf("a chain was named with no [audit.siem] configured:\n%s", out)
	}

	e.out.Reset()
	e.cfg.Audit = config.Audit{SIEM: config.SIEM{Path: "/var/log/mcp-gateway/audit.jsonl", Chain: "gatte-jail-01"}}
	if code := runAuditVerify(e.opEnv, ""); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, e.bothText())
	}
	out := e.stdoutText()
	for _, want := range []string{`chain:"gatte-jail-01"`, "/var/log/mcp-gateway/audit.jsonl", "shipper"} {
		if !strings.Contains(out, want) {
			t.Errorf("`audit -verify` does not say %q:\n%s", want, out)
		}
	}
}

// TestReportCredentialDrift_RefusesAnExpiredContextLoudly is the safety net
// under a bug that produced no symptom.
//
// The refresh loop cancelled its context the moment Refresh returned and
// then handed that same dead context to the drift check. Nothing broke,
// because the vault in use does not consult the context -- so the check
// would have reported "no drift" forever, indistinguishably from having
// found none, the day any ctx-honouring Provider replaced it.
//
// "No drift reported" and "drift never looked for" must not be the same
// silence. The guard runs before the gateway is touched, which is also why
// this test needs no gateway.
func TestReportCredentialDrift_RefusesAnExpiredContextLoudly(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// No gateway: reaching one would be the bug. A panic here is a failure.
	(&serveStack{}).reportCredentialDrift(ctx, logger)

	out := logged.String()
	if !strings.Contains(out, "NOT checked") {
		t.Errorf("an expired context produced no warning; the check's silence is indistinguishable "+
			"from finding no drift:\n%s", out)
	}
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("reported below Error: a rotation going unnoticed is what the loop exists to prevent:\n%s", out)
	}
}
