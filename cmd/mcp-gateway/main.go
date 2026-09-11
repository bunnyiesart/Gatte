// Command mcp-gateway is the gateway binary: one MCP endpoint in front of
// every registered upstream, plus the operator surface that administers
// it.
//
// This is the composition root. Per the fitness function in
// internal/fitness, it is the *only* package permitted to wire a concrete
// adapter -- everything else depends on a port interface. That rule is
// what makes this file the single place the system stops being libraries
// and becomes a program.
//
// Subcommands:
//
//	serve                     run the gateway
//	upstream list|register|deregister
//	tool list|approve|revoke  Tool Quarantine
//	sign                      sign a registry entry
//	audit                     read the Audit Trail
//	version
//
// Exit codes follow the convention the rest of this project's tooling
// uses (harden.py, jm, lab/probe): 0 ok, 1 the command ran and found a
// problem, 2 the command could not run -- bad usage, unreadable config,
// unreachable dependency.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	signersqlite "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// Exit codes. See the package doc.
const (
	exitOK        = 0
	exitProblem   = 1
	exitCannotRun = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's testable body: it returns an exit code rather than
// calling os.Exit, so the whole dispatch can be exercised by tests.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitCannotRun
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest, stdout, stderr)
	case "upstream":
		return cmdUpstream(rest, stdout, stderr)
	case "tool":
		return cmdTool(rest, stdout, stderr)
	case "sign":
		return cmdSign(rest, stdout, stderr)
	case "audit":
		return cmdAudit(rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version())
		return exitOK
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return exitCannotRun
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `mcp-gateway -- one authenticated MCP endpoint in front of the SOC's backends

Usage:
  mcp-gateway <command> [flags]

Commands:
  serve        Run the gateway.
  upstream     Register, list or deregister a backend MCP server.
  tool         List quarantined tools; approve one, or revoke an approval.
  sign         Sign a registry entry so the gateway will serve it.
  audit        Read the audit trail.
  version      Print the build version.

Every command takes -config (default: mcp-gateway.toml). See
config.example.toml for a documented configuration file.

Exit codes: 0 ok, 1 ran and found a problem, 2 could not run.
`)
}

// openStore opens the SQLite file named by the config and migrates every
// component's schema.
//
// All four migrations live here, together, deliberately: a component
// whose table is missing fails at the first query, deep inside a request,
// rather than at startup. Running them all from the composition root
// means an operator learns about a broken database when they start the
// process.
func openStore(cfg *config.Config) (*sql.DB, error) {
	db, err := store.Open(cfg.Database)
	if err != nil {
		return nil, err
	}
	for name, migrate := range map[string]func(*sql.DB) error{
		"upstream registry": registrysqlite.Migrate,
		"audit trail":       auditsqlite.Migrate,
		"tool quarantine":   quarantinesqlite.Migrate,
		"entry signatures":  signersqlite.Migrate,
	} {
		if err := migrate(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate %s: %w", name, err)
		}
	}
	return db, nil
}

// loadConfig reads and validates the configuration file.
func loadConfig(path string, stderr io.Writer) (*config.Config, bool) {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "config: %v\n", err)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "\nNo configuration file at %q. Copy config.example.toml and edit it.\n", path)
		}
		return nil, false
	}
	return cfg, true
}

// newLogger builds the structured logger. Text rather than JSON by
// default: the first reader of these lines is a person tailing a log
// during an incident, not a shipper.
func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// signalContext returns a context cancelled on SIGINT or SIGTERM, so a
// shutdown closes upstream connections rather than orphaning
// subprocesses.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// version is the build identity. Overridden at link time with -ldflags
// "-X main.buildVersion=...".
var buildVersion = "dev"

func version() string { return "mcp-gateway " + buildVersion }
