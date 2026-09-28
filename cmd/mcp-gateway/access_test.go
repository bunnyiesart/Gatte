package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
)

// The console as a second writer of the audit chain (design/adr/0031).
// These tests drive the real binary's dispatch -- run() -- against a real
// configuration file and a real SQLite file, because what is under test is
// exactly what an operator types at 03:00 and what the file then holds.

// cliHelperEnv switches this test binary into a helper process that runs
// the console, so a test can have a SECOND PROCESS append to the chain
// while this one does -- the arrangement a running `serve` and an operator's
// `access block` are in. Two handles in one process would share a lock
// table and prove less.
const (
	cliHelperEnv    = "GATTE_TEST_CLI_HELPER"
	cliHelperConfig = "GATTE_TEST_CLI_CONFIG"
	cliHelperRounds = "GATTE_TEST_CLI_ROUNDS"
)

func TestMain(m *testing.M) {
	if os.Getenv(cliHelperEnv) == "1" {
		os.Exit(cliHelper())
	}
	os.Exit(m.Run())
}

// cliHelper blocks and unblocks a fresh subject per round, each through a
// separate run() -- a separate open, migrate and append, as a separate
// command invocation would be -- and exits non-zero on the first failure.
func cliHelper() int {
	cfg := os.Getenv(cliHelperConfig)
	rounds, err := strconv.Atoi(os.Getenv(cliHelperRounds))
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: bad rounds:", err)
		return 3
	}
	for i := range rounds {
		sub := fmt.Sprintf("sub-helper-%d", i)
		for _, args := range [][]string{
			{"access", "block", "-config", cfg, "-reason", "concurrency proof", sub},
			{"access", "unblock", "-config", cfg, sub},
		} {
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != exitOK {
				fmt.Fprintf(os.Stderr, "helper: %v exited %d\n%s%s", args, code, out.String(), errBuf.String())
				return 4
			}
		}
	}
	return 0
}

// runCLI runs one console command and returns its exit code and output.
func runCLI(args ...string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// accessConfig is writeOperatorConfig with a trusted signing key, which a
// file needs in order to load at all now that require_signed defaults to
// true.
func accessConfig(t *testing.T, extra string) string {
	t.Helper()
	return writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600))+extra)
}

// trailOf reads the whole audit trail from the database a config names.
func trailOf(t *testing.T, cfgPath string) ([]audit.Record, audit.ChainCheck) {
	t.Helper()
	var why bytes.Buffer
	cfg, ok := loadConfig(cfgPath, &why)
	if !ok {
		t.Fatalf("loading %s: %s", cfgPath, why.String())
	}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer db.Close()
	rec := auditsqlite.New(db)
	rows, err := rec.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	check, err := rec.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	return rows, check
}

// TestAccessBlock_IsAnAuditedOperatorActionAttributedToTheOSUser is the
// console half of ADR-0031: block, list and unblock through the binary,
// each change a row in the chained trail naming the operating-system user
// who ran it -- SUDO_USER first, because the console runs as the service
// account through sudo and USER is then that account, not the person.
func TestAccessBlock_IsAnAuditedOperatorActionAttributedToTheOSUser(t *testing.T) {
	cfg := accessConfig(t, "")
	t.Setenv("SUDO_USER", "operator1")
	t.Setenv("USER", "mcpgw")

	code, out, errText := runCLI("access", "block", "-config", cfg, "-reason", "laptop reported stolen", "sub-analyst-1")
	requireExit(t, code, exitOK, "access block: "+out+errText)

	code, out, _ = runCLI("access", "list", "-config", cfg)
	requireExit(t, code, exitOK, "access list")
	for _, want := range []string{"sub-analyst-1", "operator1", "laptop reported stolen"} {
		requireContains(t, out, want, "access list")
	}

	// Blocking again changes nothing and writes nothing.
	code, out, _ = runCLI("access", "block", "-config", cfg, "sub-analyst-1")
	requireExit(t, code, exitOK, "access block, again")
	requireContains(t, out, "already blocked", "access block, again")

	code, out, errText = runCLI("access", "unblock", "-config", cfg, "sub-analyst-1")
	requireExit(t, code, exitOK, "access unblock: "+out+errText)

	// Unblocking somebody who is not blocked is a problem, and unrecorded.
	t.Setenv("SUDO_USER", "")
	code, _, _ = runCLI("access", "unblock", "-config", cfg, "sub-analyst-1")
	requireExit(t, code, exitProblem, "access unblock of an unblocked subject")

	rows, check := trailOf(t, cfg)
	if len(rows) != 2 {
		t.Fatalf("trail has %d rows, want 2 (one block, one unblock, nothing for the no-ops): %+v", len(rows), rows)
	}
	for i, want := range []string{accessBlockTool, accessUnblockTool} {
		r := rows[i]
		if r.Tool != want || r.AnalystIdentity != "(operator:operator1)" || r.TargetUpstream != "(gateway)" ||
			r.Outcome != audit.OutcomeAllowed || !strings.Contains(r.Reason, `"sub-analyst-1"`) {
			t.Errorf("row %d = %+v, want %s by (operator:operator1) naming the subject", i, r, want)
		}
	}
	if !strings.Contains(rows[0].Reason, "laptop reported stolen") {
		t.Errorf("the block row does not carry the operator's reason: %q", rows[0].Reason)
	}
	if !check.Intact() || check.Count != 2 {
		t.Fatalf("chain after console writes: intact=%v count=%d", check.Intact(), check.Count)
	}
	code, out, _ = runCLI("audit", "-verify", "-config", cfg)
	requireExit(t, code, exitOK, "audit -verify after console writes: "+out)
}

// TestAccessBlock_FallsBackToUSER: with no SUDO_USER -- the command was
// run directly, not through sudo -- the row names USER.
func TestAccessBlock_FallsBackToUSER(t *testing.T) {
	cfg := accessConfig(t, "")
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "operator2")

	code, out, errText := runCLI("access", "block", "-config", cfg, "sub-analyst-2")
	requireExit(t, code, exitOK, "access block: "+out+errText)
	rows, _ := trailOf(t, cfg)
	if len(rows) != 1 || rows[0].AnalystIdentity != "(operator:operator2)" {
		t.Fatalf("rows = %+v, want one attributed to (operator:operator2)", rows)
	}
}

// TestAccessBlock_RefusesAMalformedSubject: a subject with padding or a
// control character is refused before anything is stored or recorded --
// a block on "ana " would never match "ana", and the operator would believe
// a subject blocked that is not.
func TestAccessBlock_RefusesAMalformedSubject(t *testing.T) {
	cfg := accessConfig(t, "")
	t.Setenv("SUDO_USER", "operator1")
	for _, sub := range []string{"sub-analyst-1 ", "sub\x1b]0;x\x07", ""} {
		code, _, _ := runCLI("access", "block", "-config", cfg, sub)
		requireExit(t, code, exitCannotRun, fmt.Sprintf("access block %q", sub))
	}
	code, _, _ := runCLI("access", "block", "-config", cfg)
	requireExit(t, code, exitCannotRun, "access block with no subject")
	if rows, _ := trailOf(t, cfg); len(rows) != 0 {
		t.Fatalf("a refused block was recorded: %+v", rows)
	}
}

// TestAccessBlock_ReachesTheSIEMCopySoTheShippedChainHasNoGap: with
// [audit.siem] configured, the console's row goes to the JSONL file too.
// Otherwise the next line `serve` ships would name, as its prev_hash, a
// record the SIEM never received -- the DANGLING case
// deploy/gatte-anchor-verify.sh alarms on.
func TestAccessBlock_ReachesTheSIEMCopySoTheShippedChainHasNoGap(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := accessConfig(t, "\n[audit.siem]\npath = \""+sink+"\"\nchain = \"gatte-test-01\"\n")
	t.Setenv("SUDO_USER", "operator1")

	code, out, errText := runCLI("access", "block", "-config", cfg, "sub-analyst-1")
	requireExit(t, code, exitOK, "access block: "+out+errText)

	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatalf("reading the SIEM copy: %v", err)
	}
	var line struct {
		Tool   string `json:"tool"`
		Caller string `json:"caller"`
		Hash   string `json:"hash"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &line); err != nil {
		t.Fatalf("SIEM copy is not one JSON line: %v\n%s", err, data)
	}
	_, check := trailOf(t, cfg)
	if line.Tool != accessBlockTool || line.Caller != "(operator:operator1)" || line.Hash != check.Head {
		t.Fatalf("SIEM line = %+v, want the block row at the chain head %s", line, check.Head)
	}
}

// TestAccessBlock_ConcurrentWithServeKeepsTheChainIntact is the proof
// ADR-0031 owes for making the console a second writer. A separate process
// runs `access block` and `access unblock` in a loop while this one appends
// the way `serve` does, through the same recorder serve builds, for as long
// as the other process is running. Every append reads the head inside its
// own BEGIN IMMEDIATE, so the file's write lock -- not either process's
// memory -- orders them: the chain must verify, and nothing may be lost.
//
// The serve side is paced and bounded, like a real analyst load: four
// writers each appending back to back with no pause starved the console
// past busy_timeout on a loaded machine (SQLite's busy handler is not
// fair), which made this proof flaky rather than wrong. What it proves is
// the ordering; how long a starved writer waits is
// TestAccessBlock_OutlastsAWriterThatHoldsTheLockPastBusyTimeout's.
func TestAccessBlock_ConcurrentWithServeKeepsTheChainIntact(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "audit.jsonl")
	cfgPath := accessConfig(t, "\n[audit.siem]\npath = \""+sink+"\"\nchain = \"gatte-test-01\"\n")
	cfg, ok := loadConfig(cfgPath, io.Discard)
	if !ok {
		t.Fatal("loading config")
	}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer db.Close()
	rec, _, closeRec, err := auditRecorder(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("auditRecorder: %v", err)
	}
	defer closeRec()

	const (
		rounds         = 15
		servePerWriter = 2000
		servePace      = 2 * time.Millisecond
	)
	helper := exec.Command(os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(),
		cliHelperEnv+"=1", cliHelperConfig+"="+cfgPath, cliHelperRounds+"="+strconv.Itoa(rounds),
		"SUDO_USER=operator1")
	var helperOut bytes.Buffer
	helper.Stdout, helper.Stderr = &helperOut, &helperOut
	if err := helper.Start(); err != nil {
		t.Fatalf("starting the console process: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()

	var (
		written atomic.Int64
		stop    atomic.Bool
		wg      sync.WaitGroup
		errs    = make(chan error, 4)
	)
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; !stop.Load() && i < servePerWriter; i++ {
				if i > 0 {
					time.Sleep(servePace)
				}
				err := rec.Record(context.Background(), audit.Record{
					AnalystIdentity: "sub-analyst-1",
					Tool:            "casemgmt.list_cases",
					TargetUpstream:  "casemgmt",
					Timestamp:       time.Now(),
					Outcome:         audit.OutcomeAllowed,
					SourceAddress:   fmt.Sprintf("198.51.100.%d", w+1),
				})
				if err != nil {
					errs <- err
					return
				}
				written.Add(1)
			}
		}()
	}
	helperErr := <-done
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("serve-side append failed beside the console: %v", err)
	}
	if helperErr != nil {
		t.Fatalf("console process failed: %v\n%s", helperErr, helperOut.String())
	}

	rows, check := trailOf(t, cfgPath)
	want := int(written.Load()) + 2*rounds
	if !check.Intact() {
		t.Fatalf("two writers forked the chain: first break at position %d", check.FirstBreak.Position)
	}
	if check.Count != want {
		t.Fatalf("chain holds %d records, want %d (%d from serve, %d from the console): a write was lost",
			check.Count, want, written.Load(), 2*rounds)
	}
	console := 0
	for _, r := range rows {
		if r.AnalystIdentity == "(operator:operator1)" {
			console++
		}
	}
	if console != 2*rounds {
		t.Fatalf("console rows = %d, want %d", console, 2*rounds)
	}
	// Concurrency, not two writers taking turns: some serve row landed
	// between the console's first and last rows.
	first, last, between := -1, -1, 0
	for i, r := range rows {
		if r.AnalystIdentity == "(operator:operator1)" {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	for _, r := range rows[max(first, 0) : last+1] {
		if r.AnalystIdentity == "sub-analyst-1" {
			between++
		}
	}
	t.Logf("serve rows %d, console rows %d, serve rows interleaved with the console's %d", written.Load(), console, between)
	if between == 0 {
		t.Fatal("no serve row landed between the console's rows, so nothing was concurrent")
	}
	// And the SIEM copy holds every record, in a file both processes
	// appended to: one line per record, each parseable.
	lines := strings.Split(strings.TrimSpace(readFileString(t, sink)), "\n")
	if len(lines) != want {
		t.Fatalf("SIEM copy has %d lines, want %d", len(lines), want)
	}
	for i, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Fatalf("SIEM line %d is not JSON -- two writers interleaved a line: %q", i+1, l)
		}
	}
	if code, out, _ := runCLI("audit", "-verify", "-config", cfgPath); code != exitOK {
		t.Fatalf("audit -verify after concurrent writers = %d:\n%s", code, out)
	}
	// The blocks themselves were all lifted.
	if blocks, err := accesssqlite.New(db).Blocks(context.Background()); err != nil || len(blocks) != 0 {
		t.Fatalf("blocks left behind: %v, %v", blocks, err)
	}
}

// TestBuildServer_AccessBlockReachesARunningGateway is ADR-0031 through
// this binary's own composition root: a token the REAL verifier accepts is
// served, `access block` runs as a separate command against the same file,
// and the very next request with the same token is the constant 403 --
// with no restart, no reload and no signal. Unblocking restores it.
func TestBuildServer_AccessBlockReachesARunningGateway(t *testing.T) {
	dir := t.TempDir()
	secretsFile, ageKeyFile := newServeVaultFixture(t, map[string]string{"MOCK_SECRET": "not-a-real-secret"})
	issuer := newServeIssuerWithKeys(t)
	const audience = "https://gw.test.internal/mcp"

	var body strings.Builder
	fmt.Fprintf(&body, "listen = %q\n", "127.0.0.1:0")
	fmt.Fprintf(&body, "database = %q\n", filepath.Join(dir, "gateway.db"))
	fmt.Fprintf(&body, "[oidc]\nissuer = %q\naudience = %q\n", issuer.url, audience)
	fmt.Fprintf(&body, "[vault]\nsecrets_file = %q\nage_key_file = %q\n", secretsFile, ageKeyFile)
	fmt.Fprintf(&body, "[signer]\nrequire_signed = false\n")
	fmt.Fprintf(&body, "[[role]]\nname = %q\ntools = [%q]\n", "n1-triage", "casemgmt.list_cases")
	fmt.Fprintf(&body, "[group_to_role]\n%q = %q\n", "soc-n1", "n1-triage")
	configPath := filepath.Join(dir, "mcp-gateway.toml")
	if err := os.WriteFile(configPath, []byte(body.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	logs := &syncBuf{}
	stack, err := buildServer(context.Background(), cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatalf("buildServer: %v\n%s", err, logs.String())
	}
	defer stack.close()
	srv := httptest.NewServer(stack.server.Handler)
	defer srv.Close()

	token := issuer.mint(audience, "sub-analyst-1", "soc-n1")
	post := func() (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	if code, got := post(); code != http.StatusOK {
		t.Fatalf("before the block: %d %s\n%s", code, got, logs.String())
	}
	t.Setenv("SUDO_USER", "operator1")
	if code, out, errText := runCLI("access", "block", "-config", configPath, "sub-analyst-1"); code != exitOK {
		t.Fatalf("access block = %d\n%s%s", code, out, errText)
	}
	if code, got := post(); code != http.StatusForbidden || got != "forbidden\n" {
		t.Fatalf("after the block, same token: %d %q, want 403 \"forbidden\\n\"", code, got)
	}
	if code, out, errText := runCLI("access", "unblock", "-config", configPath, "sub-analyst-1"); code != exitOK {
		t.Fatalf("access unblock = %d\n%s%s", code, out, errText)
	}
	if code, got := post(); code != http.StatusOK {
		t.Fatalf("after the unblock: %d %s", code, got)
	}

	rows, check := trailOf(t, configPath)
	var reasons []string
	for _, r := range rows {
		reasons = append(reasons, r.Tool+"/"+r.Reason)
	}
	joined := strings.Join(reasons, "\n")
	for _, want := range []string{accessBlockTool + `/subject "sub-analyst-1"`, "(authentication)/subject blocked", accessUnblockTool} {
		requireContains(t, joined, want, "audit trail")
	}
	if !check.Intact() {
		t.Fatalf("chain broken after serve and the console both wrote: %+v", check.FirstBreak)
	}
}

// TestAccessBlock_OutlastsAWriterThatHoldsTheLockPastBusyTimeout: the kill
// switch is an incident command, run while serve is busy writing. SQLite's
// busy handler is not fair, so a second writer can wait out the whole
// busy_timeout and get SQLITE_BUSY; `access block` retries rather than fail
// the operator (ADR-0031 §5). Here another connection holds the write lock
// for longer than busy_timeout, then lets go.
func TestAccessBlock_OutlastsAWriterThatHoldsTheLockPastBusyTimeout(t *testing.T) {
	cfgPath := accessConfig(t, "")
	cfg, ok := loadConfig(cfgPath, io.Discard)
	if !ok {
		t.Fatal("loading config")
	}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer db.Close()
	holder, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore (holder): %v", err)
	}
	defer holder.Close()
	conn, err := holder.Conn(context.Background())
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("taking the write lock: %v", err)
	}
	released := make(chan struct{})
	go func() {
		defer close(released)
		time.Sleep(5500 * time.Millisecond) // busy_timeout is 5000 ms
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
	}()

	var out, errBuf bytes.Buffer
	e := &opEnv{cfg: cfg, db: db, stdout: &out, stderr: &errBuf}
	code := runAccessBlock(e, "operator1", "sub-analyst-1", "laptop reported stolen")
	<-released
	if code != exitOK {
		t.Fatalf("access block beside a writer holding the lock = %d, want %d\n%s%s", code, exitOK, out.String(), errBuf.String())
	}
	rows, check := trailOf(t, cfgPath)
	if len(rows) != 1 || rows[0].Tool != accessBlockTool || !check.Intact() {
		t.Fatalf("trail after a contended block: %+v intact=%v", rows, check.Intact())
	}
}

// TestAccessBlock_WarnsWhenTheSubjectIsNotOnRecord: matching is exact, so
// "sub-analyst-l" (letter l) for "sub-analyst-1" blocks nobody. The block
// is still placed -- the command must fail closed -- but the operator is
// told that no request from that subject is on the trail.
func TestAccessBlock_WarnsWhenTheSubjectIsNotOnRecord(t *testing.T) {
	cfgPath := accessConfig(t, "")
	t.Setenv("SUDO_USER", "operator1")
	cfg, ok := loadConfig(cfgPath, io.Discard)
	if !ok {
		t.Fatal("loading config")
	}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	if err := auditsqlite.New(db).Record(context.Background(), audit.Record{
		AnalystIdentity: "sub-analyst-1", Tool: "casemgmt.list_cases", TargetUpstream: "casemgmt",
		Timestamp: time.Now(), Outcome: audit.OutcomeAllowed, SourceAddress: "198.51.100.7",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	db.Close()

	code, out, errText := runCLI("access", "block", "-config", cfgPath, "sub-analyst-l")
	requireExit(t, code, exitOK, "access block of a subject never seen: "+out+errText)
	requireContains(t, errText, "no request from this subject is on record", "access block of a subject never seen")
	code, out, _ = runCLI("access", "list", "-config", cfgPath)
	requireExit(t, code, exitOK, "access list")
	requireContains(t, out, "sub-analyst-l", "the block stays in force")

	code, out, errText = runCLI("access", "block", "-config", cfgPath, "sub-analyst-1")
	requireExit(t, code, exitOK, "access block of a known subject: "+out+errText)
	if strings.Contains(errText+out, "no request from this subject") {
		t.Errorf("warned about a subject the trail knows:\n%s%s", out, errText)
	}
}

// TestAccessUsage_NamesEveryFlag: the usage text lists each flag the
// access subcommands accept.
func TestAccessUsage_NamesEveryFlag(t *testing.T) {
	var buf bytes.Buffer
	accessUsageText(&buf)
	for _, want := range []string{"list    [-config FILE] [-json]", "[-reason TEXT] SUBJECT"} {
		requireContains(t, buf.String(), want, "access usage")
	}
}
