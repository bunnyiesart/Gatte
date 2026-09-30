package main

// Process-level tests of design/adr/0044: a running serve takes a reload
// and a redial from the operator's row and a SIGHUP, answers each on the
// row, and writes an operator row -- through the real composition root,
// the real database and a real signal.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/admin"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/control"
	controlsqlite "github.com/bunnyiesart/Gatte/internal/control/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// runningServe is a built stack whose loop is running, with SIGHUP routed
// to it the way cmdServe routes it.
type runningServe struct {
	fx    serveFixture
	stack *serveStack
	log   *syncBuf
	stop  func()
}

func startServe(t *testing.T, tweak func(*strings.Builder)) *runningServe {
	t.Helper()
	fx := newServeFixture(t, tweak)
	sink := &syncBuf{}
	logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	stack.hup = hup
	stack.configPath = fx.configPath
	stack.refreshEvery = time.Hour // only out-of-turn rounds in these tests
	stack.announce(context.Background(), logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		stack.refreshLoop(ctx, logger)
	}()
	rs := &runningServe{fx: fx, stack: stack, log: sink}
	rs.stop = func() {
		cancel()
		<-done
		signal.Stop(hup)
		stack.close()
	}
	t.Cleanup(rs.stop)
	return rs
}

// operatorEnv is the CLI's side of the same database.
func (rs *runningServe) operatorEnv(t *testing.T) *opEnv {
	t.Helper()
	cfg, err := config.Load(rs.fx.configPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &opEnv{cfg: cfg, db: db, stdout: io.Discard, stderr: io.Discard, configPath: rs.fx.configPath}
}

func (rs *runningServe) rewriteConfig(t *testing.T, edit func(string) string) {
	t.Helper()
	b, err := os.ReadFile(rs.fx.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rs.fx.configPath, []byte(edit(string(b))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rowsOf(t *testing.T, e *opEnv, tool string) []string {
	t.Helper()
	recs, err := auditsqlite.New(e.db).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		if r.Tool == tool {
			out = append(out, fmt.Sprintf("%s|%s|%s|%s", r.AnalystIdentity, r.TargetUpstream, r.Outcome, r.Reason))
		}
	}
	return out
}

var alice = admin.Actor{Name: "alice", Front: "cli"}

// TestReload_AppliesRolesWithoutARestartAndSaysWhatNeedsOne is item 1 of
// ADR-0044 end to end: the file changes, the operator reloads, the next
// call is decided by the new roles, and the keys that were not applied are
// named.
func TestReload_AppliesRolesWithoutARestartAndSaysWhatNeedsOne(t *testing.T) {
	rs := startServe(t, nil)
	e := rs.operatorEnv(t)
	svc, err := e.service()
	if err != nil {
		t.Fatal(err)
	}
	hunter := access.Identity{Subject: "sub-1", Groups: []string{"soc-hunt"}}
	if roles := rs.stack.gateway.Policy().RolesFor(hunter); len(roles) != 0 {
		t.Fatalf("precondition: soc-hunt maps to %v", roles)
	}

	rs.rewriteConfig(t, func(s string) string {
		s = strings.Replace(s, `listen = "127.0.0.1:0"`, `listen = "127.0.0.1:1"`, 1)
		return s + "\n[[role]]\nname = \"hunt\"\ntools = [\"logsearch.search\"]\n"
	})
	// [group_to_role] is a table and must stay the file's last one.
	rs.rewriteConfig(t, func(s string) string {
		return strings.Replace(s, "\"soc-n1\" = \"n1-triage\"\n", "\"soc-n1\" = \"n1-triage\"\n\"soc-hunt\" = \"hunt\"\n", 1)
	})
	if _, err := config.Load(rs.fx.configPath); err != nil {
		t.Fatalf("the edited fixture does not load: %v", err)
	}

	res, err := svc.Reload(context.Background(), alice)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res.State != adminapi.ServeStateDone || res.Outcome != adminapi.ServeOutcomeApplied || res.Reload == nil {
		t.Fatalf("Reload = %+v", res)
	}
	if !slices.Equal(res.Reload.NotReloaded, []string{"listen"}) {
		t.Errorf("not_reloaded = %v, want [listen]", res.Reload.NotReloaded)
	}
	if len(res.Reload.Groups) != 1 || res.Reload.Groups[0] != (adminapi.GroupChange{Group: "soc-hunt", To: "hunt"}) {
		t.Errorf("groups = %+v", res.Reload.Groups)
	}
	if len(res.Reload.Roles) != 1 || res.Reload.Roles[0].Role != "hunt" || !res.Reload.Roles[0].Added {
		t.Errorf("roles = %+v", res.Reload.Roles)
	}
	if roles := rs.stack.gateway.Policy().RolesFor(hunter); len(roles) != 1 || roles[0].Name != "hunt" {
		t.Fatalf("after the reload soc-hunt maps to %v, want hunt", roles)
	}
	if !res.Recorded || res.Audit == nil || res.Audit.Identity != "(operator:alice)" || res.Audit.Tool != admin.ConfigReload {
		t.Fatalf("the reload's operator row = %+v, recorded %v", res.Audit, res.Recorded)
	}
	rows := rowsOf(t, e, admin.ConfigReload)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "(operator:alice)|(gateway)|allowed|[cli] applied: ") ||
		!strings.Contains(rows[0], "NOT applied until restart: listen") || !strings.Contains(rows[0], `group "soc-hunt": (none) -> "hunt"`) {
		t.Fatalf("(config reload) rows = %q", rows)
	}

	// The same file again: applied, nothing changed, and listen still
	// named, because this process still listens where it started.
	res, err = svc.Reload(context.Background(), alice)
	if err != nil || res.Outcome != adminapi.ServeOutcomeApplied || len(res.Reload.Roles)+len(res.Reload.Groups) != 0 || !slices.Equal(res.Reload.NotReloaded, []string{"listen"}) {
		t.Fatalf("second Reload = %+v, %v", res, err)
	}
}

// TestReload_AnInvalidFileChangesNothingAndIsRecordedAsRefused: parse and
// validate the whole file first, keep the old policy, say so.
func TestReload_AnInvalidFileChangesNothingAndIsRecordedAsRefused(t *testing.T) {
	rs := startServe(t, nil)
	e := rs.operatorEnv(t)
	svc, err := e.service()
	if err != nil {
		t.Fatal(err)
	}
	before := rs.stack.gateway.Policy()
	rs.rewriteConfig(t, func(s string) string {
		return strings.Replace(s, `name = "n1-triage"`, `name = "n1-triage"`+"\nnot_a_key = 1", 1)
	})
	res, err := svc.Reload(context.Background(), alice)
	// The management service loads its own copy of the file first; the
	// CLI's service was built from the file as it was, so the request
	// reaches serve, which refuses.
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res.Outcome != adminapi.ServeOutcomeRefused || res.Refusal != adminapi.RefusalInvalidConfig {
		t.Fatalf("Reload of an invalid file = %+v", res)
	}
	if rs.stack.gateway.Policy() != before {
		t.Fatal("a refused reload swapped the policy")
	}
	rows := rowsOf(t, e, admin.ConfigReload)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "(operator:alice)|(gateway)|denied|[cli] refused (invalid_config): ") {
		t.Fatalf("rows = %q", rows)
	}
	if !strings.Contains(rs.log.String(), "configuration reload REFUSED") {
		t.Fatalf("the refusal is not in the log:\n%s", rs.log.String())
	}
}

// TestReload_AQuotaRefusalReadsAsSeparateSentences: the quota check joins
// its problems with newlines, and the CLI prints a message on one line, so
// the refusal read "quota misconfiguredquota account ...". It is one line
// with its parts apart, in the answer and in the row.
func TestReload_AQuotaRefusalReadsAsSeparateSentences(t *testing.T) {
	rs := startServe(t, nil)
	e := rs.operatorEnv(t)
	svc, err := e.service()
	if err != nil {
		t.Fatal(err)
	}
	rs.rewriteConfig(t, func(s string) string {
		return s + "[[quota.provider]]\nname = \"lookups\"\nupstream = \"threatintel\"\nlimit = 10\nwindow = \"1h\"\ntools = [\"threatintel.lookup_ip\"]\n"
	})
	res, err := svc.Reload(context.Background(), alice)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res.Outcome != adminapi.ServeOutcomeRefused || res.Refusal != adminapi.RefusalQuotaMismatch {
		t.Fatalf("Reload with a quota account on an unregistered backend = %+v", res)
	}
	var out bytes.Buffer
	printServeRequest(&out, res)
	for _, text := range append([]string{out.String()}, rowsOf(t, e, admin.ConfigReload)...) {
		if strings.Contains(text, "misconfiguredquota") || !strings.Contains(text, "quota misconfigured; quota account \"lookups\"") {
			t.Errorf("the refusal runs its parts together or lost one:\n%s", text)
		}
	}
	if rows := rowsOf(t, e, admin.ConfigReload); len(rows) != 1 || strings.Contains(rows[0], "\n") {
		t.Fatalf("rows = %q", rows)
	}
}

// TestReload_ABareSIGHUPReloadsAndIsAttributedToTheSignal is what
// `systemctl reload` or `kill -HUP` does with no request filed.
func TestReload_ABareSIGHUPReloadsAndIsAttributedToTheSignal(t *testing.T) {
	rs := startServe(t, nil)
	e := rs.operatorEnv(t)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows := rowsOf(t, e, admin.ConfigReload)
		if len(rows) == 1 {
			if !strings.HasPrefix(rows[0], "(gateway)|(gateway)|allowed|[signal] applied: ") {
				t.Fatalf("row = %q", rows[0])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no (config reload) row after SIGHUP; log:\n%s", rs.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRedial_ThroughServeIsAnsweredAndRecorded: a registered backend that
// does not come up is dialled again and reported not live; an unknown one
// is refused before anything is filed.
func TestRedial_ThroughServeIsAnsweredAndRecorded(t *testing.T) {
	rs := startServe(t, nil)
	e := rs.operatorEnv(t)
	if err := registrysqlite.New(e.db).Register(context.Background(), registry.UpstreamServer{
		Name: "casemgmt", Transport: registry.TransportStdio, Command: filepath.Join(t.TempDir(), "no-such-binary"),
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := e.service()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Redial(context.Background(), alice, adminapi.RedialRequest{Upstream: "nosuch"}); !isCode(err, adminapi.CodeNotFound) {
		t.Fatalf("Redial(nosuch) = %v, want not_found", err)
	}
	// The registry entry is not servable yet for serve (no round ran), so
	// serve refuses; after a round it is servable and down, and is dialled.
	res, err := svc.Redial(context.Background(), alice, adminapi.RedialRequest{Upstream: "casemgmt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != adminapi.ServeOutcomeRefused || res.Refusal != adminapi.RefusalNotServable {
		t.Fatalf("Redial before serve knew the entry = %+v", res)
	}
	if _, stop := rs.stack.round(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil))); stop {
		t.Fatal("round stopped")
	}
	res, err = svc.Redial(context.Background(), alice, adminapi.RedialRequest{Upstream: "casemgmt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != adminapi.ServeOutcomeApplied || res.Redial == nil || res.Redial.WasConnected || res.Redial.Live || res.Redial.Cause == "" {
		t.Fatalf("Redial of a registered backend that does not start = %+v", res)
	}
	rows := rowsOf(t, e, admin.UpstreamRedial)
	if len(rows) != 2 || !strings.HasPrefix(rows[0], "(operator:alice)|casemgmt|denied|[cli] refused (not_servable)") ||
		!strings.HasPrefix(rows[1], "(operator:alice)|casemgmt|allowed|[cli] was connected: false; live after the round: false") {
		t.Fatalf("rows = %q", rows)
	}
}

// TestReload_WithoutServeNothingIsFiled, and a request left pending by a
// process that died is answered by the next one's announce.
func TestReload_WithoutServeNothingIsFiledAndAStaleRequestIsSuperseded(t *testing.T) {
	fx := newServeFixture(t, nil)
	cfg := fx.cfg
	db, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := &opEnv{cfg: cfg, db: db, stdout: io.Discard, stderr: io.Discard, configPath: fx.configPath}
	svc, err := e.service()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reload(context.Background(), alice); !isCode(err, adminapi.CodeServeNotRunning) {
		t.Fatalf("Reload with no serve = %v, want serve_not_running", err)
	}
	ctl := controlsqlite.New(db)
	if err := ctl.RecordProcess(context.Background(), control.Process{PID: 1 << 22, Boot: time.Now(), StartToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reload(context.Background(), alice); !isCode(err, adminapi.CodeServeNotRunning) {
		t.Fatalf("Reload with a dead pid = %v, want serve_not_running", err)
	}
	if p, _ := ctl.Pending(context.Background()); len(p) != 0 {
		t.Fatalf("a request that could not be rung is still pending: %+v", p)
	}
	id, err := ctl.Submit(context.Background(), control.Request{Kind: control.KindReload, Actor: "(operator:alice)", Tag: "[cli]", RequestedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	stack, err := buildServer(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer stack.close()
	stack.announce(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	got, err := svc.ServeRequest(context.Background(), id)
	if err != nil || got.State != adminapi.ServeStateDone || got.Refusal != adminapi.RefusalSuperseded {
		t.Fatalf("the stale request after a restart = %+v, %v", got, err)
	}
	if p, err := ctl.Process(context.Background()); err != nil || p.PID != os.Getpid() {
		t.Fatalf("announce recorded %+v, %v", p, err)
	}
}

// TestRingServe_SignalsOnlyTheProcessThatRecordedItself.
func TestRingServe_SignalsOnlyTheProcessThatRecordedItself(t *testing.T) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	me := control.Process{PID: os.Getpid(), StartToken: processStartToken(os.Getpid())}
	if err := ringServe(me); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hup:
	case <-time.After(5 * time.Second):
		t.Fatal("no SIGHUP arrived")
	}
	if err := ringServe(control.Process{PID: 1 << 22}); !errors.Is(err, errServeGone) {
		t.Fatalf("ring of a pid nobody holds = %v, want errServeGone", err)
	}
	if err := ringServe(control.Process{PID: 1}); err == nil {
		t.Fatal("ring of pid 1 was attempted")
	}
	// Root does not ring a pid the service account's database names.
	ringGeteuid = func() int { return 0 }
	t.Cleanup(func() { ringGeteuid = os.Geteuid })
	if err := ringServe(me); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("ring as root = %v, want a refusal", err)
	}
	select {
	case <-hup:
		t.Fatal("root rang the recorded pid")
	case <-time.After(200 * time.Millisecond):
	}
	ringGeteuid = os.Geteuid
	if runtime.GOOS == "linux" {
		if me.StartToken == "" {
			t.Fatal("no start token on Linux")
		}
		if err := ringServe(control.Process{PID: os.Getpid(), StartToken: me.StartToken + "0"}); !errors.Is(err, errServeGone) {
			t.Fatalf("ring of our pid under another start token = %v, want errServeGone", err)
		}
	}
}

// TestCmdReload_PrintsTheAnswerAndExitsByOutcome drives the command itself.
func TestCmdReload_PrintsTheAnswerAndExitsByOutcome(t *testing.T) {
	rs := startServe(t, nil)
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "alice")
	cliLoginUIDBefore := cliLoginUID
	cliLoginUID = func() (uint32, bool) { return 0, false }
	defer func() { cliLoginUID = cliLoginUIDBefore }()

	var out, errb bytes.Buffer
	if code := run([]string{"reload", "-config", rs.fx.configPath, "-wait", "20s"}, &out, &errb); code != exitOK {
		t.Fatalf("reload = %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "): applied.") || !strings.Contains(out.String(), "Recorded in the audit trail as (config reload) by (operator:alice).") {
		t.Fatalf("stdout:\n%s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"upstream", "redial", "-config", rs.fx.configPath, "nosuch"}, &out, &errb); code != exitProblem || !strings.Contains(errb.String(), `no registered backend is named "nosuch"`) {
		t.Fatalf("redial nosuch = %d\n%s%s", code, out.String(), errb.String())
	}
	if code := run([]string{"reload", "-config", rs.fx.configPath, "extra"}, &out, &errb); code != exitCannotRun {
		t.Fatalf("reload with an argument = %d", code)
	}
}

func isCode(err error, code string) bool {
	var ae *adminapi.Error
	return errors.As(err, &ae) && ae.Code == code
}

// A reload builds a new quota gate. It must be joined to the same
// caller's-own-use reader as the one built at startup, or gatte.status
// (design/adr/0042 item 3) would report every budget's use as unknown
// after the first reload, with no error to log.
func TestReload_TheNewQuotaGateStillReadsTheCallersOwnUse(t *testing.T) {
	rs := startServe(t, nil)
	cfg := *rs.stack.cfg
	cfg.Quota = config.Quota{Providers: []config.QuotaProvider{
		{Name: "lookups", Upstream: "threatintel", Limit: 10, Window: time.Hour, Tools: []string{"threatintel.lookup_ip"}},
	}}
	plan, err := cfg.ToQuotaPlan()
	if err != nil {
		t.Fatal(err)
	}
	gate, err := rs.stack.quotaGate(plan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gate.Standing(context.Background(), "sub-1", []string{"threatintel.lookup_ip"}, time.Now())
	if err != nil || len(got) != 1 || got[0].Used != 0 {
		t.Fatalf("Standing = %+v, %v; want one budget with Used 0 (read, not unknown)", got, err)
	}
}

// TestReload_ARequestThatNamesNobodyStillGetsItsRow: a request row with no
// actor -- one the management service never writes -- is applied like any
// other and recorded as (unknown), never applied without a row.
func TestReload_ARequestThatNamesNobodyStillGetsItsRow(t *testing.T) {
	rs := startServe(t, nil)
	e := rs.operatorEnv(t)
	// The store refuses such a request, so it is written the way only
	// something else holding the database would write it.
	if _, err := e.db.Exec(`INSERT INTO serve_request (kind, target, actor, tag, requested_at, state) VALUES (?, '', '', '', ?, ?)`,
		control.KindReload, time.Now().UTC().Format(time.RFC3339Nano), control.StatePending); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		rows := rowsOf(t, e, admin.ConfigReload)
		if len(rows) == 1 {
			if !strings.HasPrefix(rows[0], "(unknown)|(gateway)|allowed|applied: ") {
				t.Fatalf("row = %q", rows[0])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no (config reload) row for a request that names nobody; log:\n%s", rs.log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
