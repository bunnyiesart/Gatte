package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/signer"
	signersqlite "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// The Operator Console's commands are thin: they parse flags, call a port,
// and render. Faking the stores would therefore test the rendering against
// a fixture of itself and prove nothing about whether the commands drive
// the domain correctly -- so every test here runs against a real
// store.Open(":memory:") and the real SQLite adapters, exactly as the
// binary wires them.

// opTestEnv is an opEnv plus the buffers its output lands in.
type opTestEnv struct {
	*opEnv
	out *bytes.Buffer
	err *bytes.Buffer
}

// stdoutText returns everything the command wrote to stdout.
func (e opTestEnv) stdoutText() string { return e.out.String() }

// stderrText returns everything the command wrote to stderr.
func (e opTestEnv) stderrText() string { return e.err.String() }

// bothText returns stdout and stderr together, for assertions that care
// about what the operator saw rather than which stream carried it.
func (e opTestEnv) bothText() string { return e.out.String() + e.err.String() }

// newOpTestEnv returns an environment backed by a real in-memory database
// with every component's schema migrated, the way openStore does it.
func newOpTestEnv(t *testing.T) opTestEnv {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open(:memory:): %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for name, migrate := range map[string]func(*sql.DB) error{
		"upstream registry": registrysqlite.Migrate,
		"audit trail":       auditsqlite.Migrate,
		"tool quarantine":   quarantinesqlite.Migrate,
		"entry signatures":  signersqlite.Migrate,
	} {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate %s: %v", name, err)
		}
	}

	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	return opTestEnv{
		opEnv: &opEnv{
			cfg:    &config.Config{Database: ":memory:"},
			db:     db,
			stdout: out,
			stderr: errBuf,
		},
		out: out,
		err: errBuf,
	}
}

// stdioEntry is the shape of a typical registered upstream: a container
// spawned over stdio, needing two credentials it names but does not hold.
func stdioEntry(name string) registry.UpstreamServer {
	return registry.UpstreamServer{
		Name:        name,
		Transport:   registry.TransportStdio,
		Command:     "docker",
		Args:        []string{"run", "--rm", name + "-mcp"},
		EnvVarNames: []string{strings.ToUpper(name) + "_URL", strings.ToUpper(name) + "_API_KEY"},
	}
}

// mustRegister puts an entry in the registry, failing the test if it
// cannot.
func mustRegister(t *testing.T, e opTestEnv, entry registry.UpstreamServer) {
	t.Helper()
	if err := e.upstreams().Register(context.Background(), entry); err != nil {
		t.Fatalf("registering %q: %v", entry.Name, err)
	}
}

// mustObserve records a tool sighting, the way discovery would.
func mustObserve(t *testing.T, e opTestEnv, server string, id quarantine.ToolIdentity) quarantine.Tool {
	t.Helper()
	tool, err := e.tools().Observe(context.Background(), server, id)
	if err != nil {
		t.Fatalf("observing %s.%s: %v", server, id.Name, err)
	}
	return tool
}

// mustApprove approves a quarantined tool through the port, for tests that
// need an approved baseline as a *precondition* rather than as the thing
// under test.
func mustApprove(t *testing.T, e opTestEnv, server, tool string) quarantine.Tool {
	t.Helper()
	approved, err := e.tools().Approve(context.Background(), server, tool)
	if err != nil {
		t.Fatalf("approving %s.%s: %v", server, tool, err)
	}
	return approved
}

// mustRecord appends one audit record.
func mustRecord(t *testing.T, e opTestEnv, r audit.Record) {
	t.Helper()
	if err := e.auditTrail().Record(context.Background(), r); err != nil {
		t.Fatalf("recording audit entry: %v", err)
	}
}

// writeSigningKey writes a fresh Ed25519 key with the given mode and
// returns its path. Mode is a parameter because LoadKey's refusal of a
// group-readable key is itself under test.
func writeSigningKey(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.key")
	key, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if err := signer.WriteKey(path, key); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	return path
}

// writeOperatorConfig writes a minimal valid configuration file and
// returns its path, for the tests that exercise a cmd* entry point end to
// end rather than its run* half. The vault paths need not exist: nothing
// an operator command does reads the vault.
func writeOperatorConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-gateway.toml")
	body := `listen = "127.0.0.1:8080"
database = "` + filepath.Join(dir, "gateway.db") + `"

[oidc]
issuer = "https://idp.example.internal"
audience = "https://gw.example.internal/mcp"

[vault]
secrets_file = "` + filepath.Join(dir, "secrets.json") + `"
age_key_file = "` + filepath.Join(dir, "age.key") + `"
` + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func requireContains(t *testing.T, got, want, what string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("%s: output does not contain %q\n--- output ---\n%s", what, want, got)
	}
}

func requireExit(t *testing.T, got, want int, what string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: exit code = %d, want %d", what, got, want)
	}
}

// TestOperatorCommands_NeverPrintASecretValue is the cheap version of the
// rule the whole console is built around. It puts a value that looks like
// a credential everywhere a value could plausibly reach the console --
// the vault-resolved env var *names*, the config, an audit reason -- and
// asserts none of the commands ever echo it.
//
// The registry has no field capable of holding a secret, so this test can
// only ever fail if a future change starts reading one from somewhere
// else. That is exactly the change it exists to catch.
func TestOperatorCommands_NeverPrintASecretValue(t *testing.T) {
	// An earlier version of this line named the constant after a
	// credential and gave it a quoted throwaway value, and the
	// repository's DLP pre-commit hook blocked the commit -- correctly.
	// Its `senha em atribuicao` rule matches a credential-ish name
	// assigned a quoted value of 8+ characters, which is exactly the
	// shape this fixture had; a hook that could tell that apart from a
	// real leak by intent alone would not be a hook. (The rule reads
	// comments too, so this note describes the shape rather than
	// reproducing it -- the second block, earned the same way.)
	//
	// The fix is the hook's own designed path for fixtures, not a way
	// around it: the ISCA_FALSA decoy list in .githooks/pre-commit clears
	// a match whose text says it is bait, and "fake" is on that list.
	// --no-verify would have passed too, and would have taught the reflex
	// the hardening manual explicitly warns against.
	const fakeValue = "fake-credential-value-never-printed"

	// The value really exists in this process, under exactly the name the
	// registered entry declares. A command that resolved a declared name
	// to its value -- "helpfully" showing whether a credential is present,
	// say -- would leak it here and nowhere else in the suite.
	t.Setenv("CASEMGMT_API_KEY", fakeValue)

	e := newOpTestEnv(t)
	useSigningKey(t, e)

	mustRegister(t, e, registry.UpstreamServer{
		Name:        "casemgmt",
		Transport:   registry.TransportStdio,
		Command:     "docker",
		Args:        []string{"run", "--rm", "casemgmt-mcp"},
		EnvVarNames: []string{"CASEMGMT_URL", "CASEMGMT_API_KEY"},
	})
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{
		Name:        "list_cases",
		Description: "List CASEMGMT cases.",
		InputSchema: []byte(`{"type":"object"}`),
	})
	mustRecord(t, e, audit.Record{
		AnalystIdentity: "analyst@soc.example",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 8, 9, 15, 0, 0, time.UTC),
		Outcome:         audit.OutcomeAllowed,
	})

	// Every read-and-render path in the console, in one pass.
	commands := []struct {
		name string
		run  func() int
	}{
		{"upstream list", func() int { return runUpstreamList(e.opEnv, false) }},
		{"upstream list -json", func() int { return runUpstreamList(e.opEnv, true) }},
		{"tool list", func() int { return runToolList(e.opEnv, "", false) }},
		{"tool list -json", func() int { return runToolList(e.opEnv, "", true) }},
		{"tool approve", func() int { return runToolApprove(e.opEnv, "casemgmt", "list_cases") }},
		{"sign", func() int { return runSign(e.opEnv, "casemgmt") }},
		{"audit", func() int { return runAudit(e.opEnv, auditFilter{Limit: 10}, false) }},
		{"audit -json", func() int { return runAudit(e.opEnv, auditFilter{Limit: 10}, true) }},
	}
	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			e.out.Reset()
			e.err.Reset()
			if code := c.run(); code != exitOK {
				t.Fatalf("%s: exit code = %d, want %d\n%s", c.name, code, exitOK, e.bothText())
			}
			if strings.Contains(e.bothText(), fakeValue) {
				t.Errorf("%s printed the secret value\n--- output ---\n%s", c.name, e.bothText())
			}
			// The env var names must still be there: hiding them would be
			// the wrong fix for this rule, and the operator needs them.
			if c.name == "upstream list" {
				requireContains(t, e.stdoutText(), "CASEMGMT_API_KEY", "upstream list")
			}
		})
	}

	// The signing key's bytes are the other secret in reach. sign prints a
	// fingerprint of the *public* half; nothing PEM-shaped may appear.
	e.out.Reset()
	e.err.Reset()
	if code := runSign(e.opEnv, "casemgmt"); code != exitOK {
		t.Fatalf("sign: exit = %d\n%s", code, e.bothText())
	}
	if strings.Contains(e.bothText(), "PRIVATE KEY") {
		t.Errorf("sign printed something PEM-shaped\n%s", e.bothText())
	}
	keyBytes, err := os.ReadFile(e.cfg.Signer.KeyFile)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(keyBytes)), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(e.bothText(), line) {
			t.Errorf("sign printed a line of the key file\n%s", e.bothText())
		}
	}
}

// TestUpstreamRegister_DoesNotEchoAValuePassedToEnv covers the one place
// an operator can hand a secret to the console by mistake. The command
// must refuse -- and must not repeat the value back into the terminal,
// the scrollback, or a session recording while refusing.
func TestUpstreamRegister_DoesNotEchoAValuePassedToEnv(t *testing.T) {
	const secret = "hunter2"
	var out, errBuf bytes.Buffer

	code := cmdUpstream([]string{
		"register", "-name", "casemgmt", "-transport", "stdio", "-command", "docker",
		"-env", "CASEMGMT_API_KEY=" + secret,
	}, &out, &errBuf)

	requireExit(t, code, exitCannotRun, "register with NAME=value")
	both := out.String() + errBuf.String()
	if strings.Contains(both, secret) {
		t.Errorf("the rejected value was echoed back\n--- output ---\n%s", both)
	}
	requireContains(t, both, "CASEMGMT_API_KEY", "register with NAME=value")
	requireContains(t, both, "not echoed", "register with NAME=value")
}

// TestHelpIsNotBadUsage is GAB-25(c). Exit code 2 means "could not run --
// bad usage" (see main.go's package doc), and asking for help is neither:
// the binary was asked to print its usage and did exactly that. A script
// that treats 2 as a failure -- which is what the convention tells it to do
// -- sees a failure that did not happen.
//
// Driven through run() rather than each cmd* function, because the dispatch
// is part of what is being pinned.
func TestHelpIsNotBadUsage(t *testing.T) {
	for _, args := range [][]string{
		{"-h"}, {"--help"}, {"help"},
		{"serve", "-h"}, {"serve", "--help"},
		{"audit", "-h"}, {"audit", "--help"},
		{"sign", "-h"},
		{"upstream", "-h"},
		{"upstream", "list", "-h"},
		{"upstream", "register", "-h"},
		{"upstream", "deregister", "-h"},
		{"tool", "-h"},
		{"tool", "list", "-h"},
		{"tool", "approve", "-h"},
		{"tool", "revoke", "-h"},
	} {
		name := strings.Join(args, " ")
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			requireExit(t, run(args, &out, &errBuf), exitOK, name)
			if out.Len()+errBuf.Len() == 0 {
				t.Errorf("%s: exited 0 without printing any usage text", name)
			}
		})
	}
}

// TestHelpGoesToStdout is the other half of GAB-25(c). Fixing the exit code
// left the streams inconsistent: `mcp-gateway -h`, `upstream -h` and
// `tool -h` are dispatched by hand and print to stdout, while every
// flag-parsed subcommand printed the same text to stderr, because
// opFlagSet hands the whole FlagSet's output to stderr and the flag
// package renders -h through it.
//
// Exit code 0 and output on stderr is a contradiction: the convention this
// binary documents says 0 means the command did what was asked, and
// stderr is where a command says it could not. It also breaks the obvious
// thing to do with help -- `mcp-gateway audit -h | less` came back empty.
//
// Bad usage still goes to stderr, and that pairing is the actual rule:
// asked-for output on stdout, complaints on stderr.
func TestHelpGoesToStdout(t *testing.T) {
	for _, args := range [][]string{
		{"-h"},
		{"serve", "-h"},
		{"audit", "-h"},
		{"sign", "-h"},
		{"upstream", "-h"},
		{"upstream", "list", "-h"},
		{"upstream", "register", "-h"},
		{"upstream", "deregister", "-h"},
		{"tool", "-h"},
		{"tool", "list", "-h"},
		{"tool", "approve", "-h"},
		{"tool", "revoke", "-h"},
	} {
		name := strings.Join(args, " ")
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			requireExit(t, run(args, &out, &errBuf), exitOK, name)

			if out.Len() == 0 {
				t.Errorf("%s: exited 0 but wrote nothing to stdout\n--- stderr ---\n%s", name, errBuf.String())
			}
			if errBuf.Len() != 0 {
				t.Errorf("%s: a successful help request wrote to stderr:\n%s", name, errBuf.String())
			}
			if !strings.Contains(out.String(), "Usage") {
				t.Errorf("%s: stdout does not look like usage text:\n%s", name, out.String())
			}
		})
	}
}

// TestBadUsageGoesToStderr is the pair of the test above: the rule is not
// "help on stdout", it is "what was asked for on stdout, complaints on
// stderr". Moving help without checking this would just invert the bug.
func TestBadUsageGoesToStderr(t *testing.T) {
	for _, args := range [][]string{
		{"audit", "-nosuchflag"},
		{"sign", "-nosuchflag"},
		{"upstream", "list", "-nosuchflag"},
		{"tool", "list", "-nosuchflag"},
		{"serve", "-nosuchflag"},
		{"upstream", "list", "stray-argument"},
	} {
		name := strings.Join(args, " ")
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			requireExit(t, run(args, &out, &errBuf), exitCannotRun, name)

			if errBuf.Len() == 0 {
				t.Errorf("%s: bad usage said nothing on stderr", name)
			}
			if out.Len() != 0 {
				t.Errorf("%s: bad usage wrote to stdout:\n%s", name, out.String())
			}
		})
	}
}

// failingWriter refuses every write, standing in for the full filesystem or
// closed pipe a tabwriter Flush actually fails on.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("no space left on device")
}

// TestTableFlushFailureIsAProblemNotAFailureToRun is the other half of
// GAB-25(c). A Flush fails after the command has read its data, decided
// what to say, and printed most of it; reporting exitCannotRun there tells
// a caller the command never ran, which is the one thing that is certainly
// false by that point.
func TestTableFlushFailureIsAProblemNotAFailureToRun(t *testing.T) {
	commands := map[string]func(e opTestEnv) int{
		"upstream list": func(e opTestEnv) int { return runUpstreamList(e.opEnv, false) },
		"tool list":     func(e opTestEnv) int { return runToolList(e.opEnv, "", false) },
		"tool approve":  func(e opTestEnv) int { return runToolApprove(e.opEnv, "casemgmt", "list_cases") },
		"audit":         func(e opTestEnv) int { return runAudit(e.opEnv, auditFilter{Limit: 10}, false) },
		"sign":          func(e opTestEnv) int { return runSign(e.opEnv, "casemgmt") },
	}
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			e := newOpTestEnv(t)
			useSigningKey(t, e)
			mustRegister(t, e, stdioEntry("casemgmt"))
			mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{
				Name:        "list_cases",
				Description: "List CASEMGMT cases.",
				InputSchema: []byte(`{"type":"object"}`),
			})
			mustRecord(t, e, audit.Record{
				AnalystIdentity: "analyst@soc.example",
				Tool:            "casemgmt.list_cases",
				TargetUpstream:  "casemgmt",
				Timestamp:       time.Date(2026, 9, 8, 9, 15, 0, 0, time.UTC),
				Outcome:         audit.OutcomeAllowed,
			})

			// Only stdout fails: stderr must stay usable, or the operator
			// is told nothing at all.
			e.opEnv.stdout = failingWriter{}
			requireExit(t, run(e), exitProblem, name)
			requireContains(t, e.stderrText(), "writing table", name)
		})
	}
}

// TestToolApprove_ChangedToolIsNotApprovedIfTheWarningWasNotPrinted: the
// Flush in printChangedWarning used to be discarded, so the block
// explaining what approving a rug-pulled tool does could be lost and the
// approval would go through anyway. Approving a CHANGED tool is the one
// operation in this console that re-baselines a definition somebody
// rewrote after a human vetted it; an approval recorded without the
// operator having been shown the case for it is the console deciding on
// their behalf.
func TestToolApprove_ChangedToolIsNotApprovedIfTheWarningWasNotPrinted(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", irisListCases)
	mustApprove(t, e, "casemgmt", "list_cases")
	changed := mustObserve(t, e, "casemgmt", changedIrisListCases)
	if changed.Status != quarantine.StatusChanged {
		t.Fatalf("precondition: status is %q, want %q", changed.Status, quarantine.StatusChanged)
	}

	e.opEnv.stdout = failingWriter{}
	requireExit(t, runToolApprove(e.opEnv, "casemgmt", "list_cases"), exitProblem, "approve changed")
	requireContains(t, e.stderrText(), "NOT approved", "approve changed")

	after, err := e.tools().Get(context.Background(), "casemgmt", "list_cases")
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if after.Status != quarantine.StatusChanged || after.Usable() {
		t.Errorf("the tool was re-baselined anyway: %+v", after)
	}
}

// TestOperatorCommands_UnreadableConfigCannotRun pins the exit-code
// contract's second half: a command that cannot read its configuration
// has not run, and must be distinguishable from one that ran and found
// nothing.
func TestOperatorCommands_UnreadableConfigCannotRun(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.toml")

	commands := map[string]func(args []string, stdout, stderr *bytes.Buffer) int{
		"upstream list": func(args []string, o, e *bytes.Buffer) int {
			return cmdUpstream(append([]string{"list"}, args...), o, e)
		},
		"tool list": func(args []string, o, e *bytes.Buffer) int { return cmdTool(append([]string{"list"}, args...), o, e) },
		"sign":      func(args []string, o, e *bytes.Buffer) int { return cmdSign(append(args, "casemgmt"), o, e) },
		"audit":     func(args []string, o, e *bytes.Buffer) int { return cmdAudit(args, o, e) },
	}
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run([]string{"-config", missing}, &out, &errBuf)
			requireExit(t, code, exitCannotRun, name)
			requireContains(t, errBuf.String(), "config", name)
		})
	}
}
