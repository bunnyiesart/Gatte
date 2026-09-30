// Operator Console -- shared plumbing.
//
// This file and its siblings (upstream.go, tool.go, sign.go, audit.go)
// implement the Operator Console of design/02-components.md: the one
// surface the single operator uses for everything that is not automatic --
// register and deregister an upstream, work the tool approval queue, sign
// a registry entry, read the audit trail. It is subcommands of this
// binary rather than a separate service, and that is a decision, not an
// economy: one operator, one small surface.
//
// Two rules run through every command here.
//
//   - **Nothing ever prints a secret value.** The registry is incapable of
//     holding one -- registry.UpstreamServer keeps env var *names* and
//     resolving a name is the Credential Vault's job -- and this package
//     keeps it that way: `upstream register` refuses a NAME=value
//     argument with the value elided rather than echoed back to the
//     terminal, and no command reads the vault at all.
//   - **The reader is a person at 03:00.** Aligned columns, no JSON
//     unless asked. Where a command changes the gateway's security
//     posture -- registering an entry the gateway will not trust,
//     re-baselining a tool whose definition changed under us -- it says so
//     in full sentences instead of printing "ok".
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	healthsqlite "github.com/bunnyiesart/Gatte/internal/health/sqlite"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/signer"
	signersqlite "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
)

// opTimeLayout renders timestamps for humans: sortable, unambiguous, and
// always UTC. An operator correlating the audit trail with a SIEM at 03:00
// should never have to work out which zone a line is in.
const opTimeLayout = "2006-01-02 15:04:05Z"

// opEnv is everything an operator subcommand needs to do its work: the
// validated configuration, an open database, and where to write.
//
// It exists as a seam. Each subcommand is split into a thin outer half
// that parses flags and a run* half that takes an opEnv, so tests can
// drive the real logic against a real store.Open(":memory:") and the real
// adapters without a config file on disk -- which matters because these
// commands are thin enough that faking the stores would test nothing.
type opEnv struct {
	cfg    *config.Config
	db     *sql.DB
	stdout io.Writer
	stderr io.Writer
	// configPath is the -config value this command actually loaded,
	// made absolute. Empty only in tests that build an opEnv by hand.
	configPath string
	// actor, when set, is who this command's operator rows are attributed
	// to; otherwise cliActor decides.
	actor admin.Actor
	// signingKey and signingKeyFile are the key `sign` read as root before
	// it dropped to the database's owner (design/adr/0044); nil otherwise.
	signingKey     ed25519.PrivateKey
	signingKeyFile string
}

// cmd renders the command an operator should run next, for the hints this
// console prints: "mcp-gateway SUB -config PATH". The -config goes right
// after the subcommand because the flag package stops at the first
// positional argument.
//
// Before 24 Sep 2026 every hint omitted -config. Pasted as shown, "mcp-gateway
// sign NAME" loaded mcp-gateway.toml from the current directory rather than
// the file the operator had just used -- refused when there was none, and
// acting on a different gateway when there was one.
func (e *opEnv) cmd(sub string) string {
	if e.configPath == "" {
		return "mcp-gateway " + sub
	}
	return "mcp-gateway " + sub + " -config " + opShellQuote(e.configPath)
}

// opShellQuote returns s unchanged when it is safe to paste into a POSIX
// shell as one word, and single-quoted otherwise.
func opShellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@%=,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// upstreams returns the Upstream Registry port, wired to SQLite.
//
// These four accessors return the *port* interface, not the adapter type.
// This is the composition root, the one package allowed to name an
// adapter (internal/fitness enforces it), but naming one is not a reason
// for the command bodies to depend on it.
func (e *opEnv) upstreams() registry.Repository { return registrysqlite.New(e.db) }

// tools returns the Tool Quarantine port, wired to SQLite.
func (e *opEnv) tools() quarantine.Store { return quarantinesqlite.New(e.db) }

// health returns the maintenance and backend health store (design/adr/0041),
// wired to SQLite. The concrete type, for its Forget.
func (e *opEnv) health() *healthsqlite.Store { return healthsqlite.New(e.db) }

// signatures returns the Definition Signer's signature store, wired to
// SQLite. Signatures live in their own table, not as a column of the
// registry (design/adr/0006 item 2).
func (e *opEnv) signatures() signer.Store { return signersqlite.New(e.db) }

// quotaCounters returns the per-analyst quota's READ port, wired to
// SQLite (design/adr/0030-quota-por-analista.md decision 10).
//
// Note which port: quota.Reader, not quota.Store. The same adapter value
// satisfies both, and which one a caller is handed decides what it can do
// -- the console reads counters and cannot debit one, while the Gateway
// holds the Store, debits, and cannot read. Handing this side to the
// serving process would put "what has this analyst been looking up" one
// call away from the request path; handing the other side to the console
// would make `quota list` able to spend somebody's allowance.
func (e *opEnv) quotaCounters() quota.Reader { return quotasqlite.New(e.db) }

// blocks returns the blocklist's console port, wired to SQLite
// (design/adr/0031). The Gateway holds the same adapter as an
// access.Blocklist, which can only ask.
func (e *opEnv) blocks() access.BlockStore { return accesssqlite.New(e.db) }

// auditTrail returns the Audit Trail port, wired to SQLite, for READING.
//
// Deliberately NOT decorated with the JSONL sink, even when [audit.siem]
// is configured: `audit` only calls List, and the decorator emits on write.
// Wrapping it here would attach the sink file to every operator subcommand
// for a code path that never writes a record. The one console path that
// does write -- an operator action, ADR-0031 -- goes through
// recordOperatorAction, which is decorated.
func (e *opEnv) auditTrail() audit.Recorder { return auditsqlite.New(e.db) }

// recordOperatorAction appends one operator action to the trail through
// the same recorder `serve` builds: SQLite first, then the JSONL copy and
// the GELF copy when the file configures them (design/adr/0031).
//
// The console is a second writer of the chain. SQLite orders the two:
// every append reads the head inside its own BEGIN IMMEDIATE, so the lock
// on the file -- not either process's memory -- decides which record links
// to which. The JSONL copy is not optional here for a different reason: a
// row in SQLite that never reached the SIEM leaves the next line `serve`
// ships with a prev_hash the SIEM has never seen, which is the DANGLING
// alarm of deploy/gatte-anchor-verify.sh raised by an operator's own
// action. Both processes append to that file with O_APPEND and one write
// per line.
func (e *opEnv) recordOperatorAction(rec audit.Record) error {
	logger := newLogger(e.stderr)
	aud, _, closeAudit, err := auditRecorder(e.cfg, e.db, logger)
	if err != nil {
		return err
	}
	defer closeAudit()
	sink, err := newTelemetrySink(e.cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := sink.Close(); err != nil {
			logger.Warn("mcp-gateway: telemetry close", "detail", err.Error())
		}
	}()
	return telemetryRecorder{Recorder: aud, sink: sink}.Record(e.ctx(), rec)
}

// auditChain returns the port for checking the stored trail's internal
// consistency and reading its head (design/adr/0015-audit-tamper-evidence.md,
// including the 11 Sep 2026 correction: an intact chain is not a statement
// that the trail was not edited -- the head compared against an external
// anchor is). It is a separate port from Recorder because verifying is an
// operator action, not something the gateway's dispatch path performs.
func (e *opEnv) auditChain() audit.ChainVerifier { return auditsqlite.New(e.db) }

// ctx returns the context operator commands run under. A console command
// is a foreground, single-shot action: it inherits the process lifetime
// and is cancelled by the operator pressing Ctrl-C, not by a deadline
// invented here.
func (e *opEnv) ctx() context.Context { return context.Background() }

// opRun loads the configuration, opens and migrates the database, and
// hands both to fn.
//
// Both failures are exitCannotRun rather than exitProblem: a command that
// cannot read its config or reach its database has not run at all, and
// telling the difference matters to whatever is calling this in a script.
func opRun(configPath string, stdout, stderr io.Writer, fn func(*opEnv) int) int {
	cfg, ok := loadConfig(configPath, stderr)
	if !ok {
		return exitCannotRun
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "database: %v\n", err)
		return exitCannotRun
	}
	defer db.Close()

	abs, err := filepath.Abs(configPath)
	if err != nil {
		abs = configPath
	}
	return fn(&opEnv{cfg: cfg, db: db, stdout: stdout, stderr: stderr, configPath: abs})
}

// opFlagSet returns a flag set for subcommand name, already carrying the
// -config flag every operator command accepts, plus the pointer its value
// lands in.
func opFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("mcp-gateway "+name, flag.ContinueOnError)
	// The flag package renders BOTH a -h request and a parse error through
	// this one writer, and calls fs.Usage for both -- so whichever stream
	// is wired here, one of the two ends up on the wrong one. Pointing it
	// at stderr is what sent successful help there (`mcp-gateway audit -h |
	// less` came back empty while the command exited 0).
	//
	// Both are silenced here and re-rendered by opParse, which is the one
	// place that knows which of the two happened. Nothing is lost: opParse
	// prints the parse error itself, so "flag provided but not defined"
	// still reaches the operator.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	// defaultConfigPath is shared with serve: every subcommand of this
	// binary must read the same file when -config is omitted, or an
	// operator ends up administering a different gateway than the one
	// running.
	configPath := fs.String("config", defaultConfigPath, "path to the TOML configuration file")
	return fs, configPath
}

// opParse parses args, mapping the flag package's two outcomes onto this
// project's exit codes AND onto the right stream: -h is a successful
// request for help, anything else is bad usage. The bool reports whether
// parsing succeeded; when it is false the int is the exit code to return.
//
// usage renders this subcommand's help to a writer, and taking it as a
// parameter is the point. Help that was asked for is output and belongs on
// stdout; help printed alongside a complaint is part of the complaint and
// belongs on stderr. The flag package cannot make that distinction -- it
// has one output writer and calls Usage for both cases -- so the decision
// is made here, where the two are already told apart for the exit code.
//
// The pairing is the rule, not "help goes to stdout": a command exiting 0
// with its only output on stderr is as wrong as one exiting 2 with its
// complaint on stdout.
func opParse(fs *flag.FlagSet, args []string, stdout, stderr io.Writer, usage func(io.Writer)) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK, false
		}
		// Printed here because opFlagSet discarded the flag package's own
		// copy; without this the operator would see the usage text and no
		// hint of which flag was rejected.
		fmt.Fprintf(stderr, "%v\n\n", err)
		usage(stderr)
		return exitCannotRun, false
	}
	return exitOK, true
}

// opNoArgs reports whether fs consumed every positional argument,
// complaining to stderr if it did not. A stray argument is usually a
// misspelled flag, and silently ignoring it is how an operator ends up
// believing a filter was applied when it was not.
//
// Takes usage rather than calling fs.Usage: opFlagSet makes that a no-op
// so that opParse can choose the stream, and a helper that quietly printed
// nothing would be worse than one that never tried.
func opNoArgs(fs *flag.FlagSet, stderr io.Writer, usage func(io.Writer)) bool {
	if fs.NArg() == 0 {
		return true
	}
	fmt.Fprintf(stderr, "unexpected argument %q\n\n", fs.Arg(0))
	usage(stderr)
	return false
}

// opStringList collects a repeatable string flag, in the order given.
type opStringList []string

// String implements flag.Value.
func (l *opStringList) String() string { return strings.Join(*l, ",") }

// Set implements flag.Value, appending rather than replacing so the flag
// can be repeated.
func (l *opStringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

// opTable returns a tabwriter for the aligned column output every list
// command produces. Callers must Flush before writing anything that is
// not part of the table.
func opTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

// opFlushTable flushes a table and reports whether all of it reached the
// operator, complaining to stderr if it did not.
//
// It exists so the exit code for this failure is decided once. A Flush
// fails after the command has read its data, decided what to say, and
// written most of it -- so exitCannotRun, which every caller used to
// return here, asserts the one thing that is certainly false by then. The
// caller is told "this command never ran" about a command that ran, did
// its work, and lost part of its output on the way to a full disk or a
// closed pipe. That is exitProblem: it ran, and it found a problem.
//
// What it does not do is un-print the partial table. There is no undo for
// bytes already on a terminal, which is precisely why the exit code has to
// carry the truth.
func opFlushTable(tw *tabwriter.Writer, stderr io.Writer) bool {
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "writing table: %v\n", err)
		return false
	}
	return true
}

// opJSON writes v as indented JSON, the machine-readable alternative the
// -json flag selects on the list commands.
func opJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// opTime renders t for a human, or "-" if it was never set.
func opTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(opTimeLayout)
}

// opDash renders an empty string as "-", so an empty column reads as
// "nothing here" rather than as a rendering bug.
func opDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// opShortHash abbreviates a hex fingerprint for a table column. The full
// value is always available in -json output and in the detail blocks the
// approve and sign commands print, so nothing an operator might need to
// compare exactly is only ever shown truncated.
func opShortHash(h string) string {
	const shown = 12
	if len(h) <= shown {
		return opDash(h)
	}
	return h[:shown] + "..."
}

// opCommandLine renders what an entry actually runs or calls: the URL for
// an HTTP upstream, the command and its arguments for a stdio one.
// Arguments containing whitespace are quoted, so a single argument with a
// space in it cannot be misread as two.
func opCommandLine(s registry.UpstreamServer) string {
	if s.Transport == registry.TransportHTTP {
		return opDash(s.URL)
	}
	// For oci the first token is the image rather than a command: an oci
	// entry has no Command, and its Args are the signed container wrapper
	// -- the network policy above all, which is the difference between a
	// backend that can reach the internet and one that cannot.
	head := s.Command
	if s.Transport == registry.TransportOCI {
		head = opImageRef(s.Image)
	}
	parts := make([]string, 0, 1+len(s.Args))
	for _, p := range append([]string{head}, s.Args...) {
		if strings.ContainsAny(p, " \t") {
			p = strconv.Quote(p)
		}
		parts = append(parts, p)
	}
	return opDash(strings.TrimSpace(strings.Join(parts, " ")))
}

// opImageRef abbreviates a digest-pinned image reference for a table
// column: the name in full, the hex shortened to twelve digits. The full
// reference is in `upstream list -json` and in what `sign` prints. A
// reference that is not pinned is printed whole: Validate refuses to store
// one, so seeing it means the row was written past the domain, and
// abbreviating that evidence would hide the one thing worth seeing.
func opImageRef(image string) string {
	const shown = 12
	name, digest, ok := strings.Cut(image, "@sha256:")
	if !ok || len(digest) <= shown {
		return opDash(image)
	}
	return name + "@sha256:" + digest[:shown] + "..."
}

// opPlural picks the singular or plural form for n. Grammar is not
// decoration here: these messages are counts of unsigned entries and
// changed tools, and "1 entries have" reads like a bug in the tool
// reporting them, which is the last thing to be doubting at 03:00.
func opPlural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
