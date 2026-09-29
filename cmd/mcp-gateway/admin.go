// Operator Console -- "admin": the management API (design/adr/0040).
//
// The backend every front talks to: the same service the CLI commands
// call (internal/admin), answered as versioned JSON over a UNIX socket and
// nothing else. Two sockets, two processes:
//
//   - `admin` serves the operator socket, as the service account;
//   - `admin -accounts` serves the accounts socket, as root, and never
//     opens a file of the service account: the audit row of an account
//     action is written by a short-lived child, `admin -audit-writer`,
//     running as the database's owner.
//
// Under systemd each is socket-activated (LISTEN_FDS) and exits after
// -idle with no request; elsewhere it runs in the foreground with -socket.

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// adminGeteuid is os.Geteuid, a variable so the root checks are testable
// from a test that is not root.
var adminGeteuid = os.Geteuid

func adminUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway admin [-config FILE] [-socket PATH] [-socket-group GROUP] [-socket-mode 0660] [-idle 5m]
  mcp-gateway admin -accounts [-config FILE] [-socket PATH] [-socket-group GROUP] [-socket-mode 0660] [-idle 5m]

Serves the management API (api/admin.openapi.yaml, docs/admin-api.md) that
the web console and any other front call. It listens on a UNIX socket and
on nothing else; the operator is whoever the kernel says connected.

Without -accounts it serves the operator socket and runs as the gateway's
service account (root is refused): overview, tools, access, audit,
backends, quota, people, connect. With -accounts it serves the identity
provider's accounts and runs only as root; it re-checks before every
request that config.toml, [idp] users_file and every directory above them
are root's and closed to group and others.

Under systemd the socket comes from the .socket unit (examples/systemd/)
and the process exits after -idle with no request. Elsewhere give -socket;
its directory, and every one above it, must be root's and not writable by
group or others (the operator socket's own directory may be the service
account's). Default -socket-mode is 0600, or 0660 with -socket-group.

Default sockets:
  operator  `+adminapi.DefaultOperatorSocket+`
  accounts  `+adminapi.DefaultAccountsSocket+`
`)
}

func cmdAdmin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("admin", stderr)
	accounts := fs.Bool("accounts", false, "serve the accounts socket (root only)")
	writer := fs.Bool("audit-writer", false, "internal: append the one operator row read from standard input, as the database's owner")
	socket := fs.String("socket", "", "socket path, in the foreground (default: the one for the mode)")
	group := fs.String("socket-group", "", "the socket file's group")
	modeFlag := fs.String("socket-mode", "", "the socket file's mode: 0600, or 0660 with -socket-group")
	idle := fs.Duration("idle", adminhttp.DefaultIdle, "exit after this long with no request; 0 never exits")
	if code, ok := opParse(fs, args, stdout, stderr, adminUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, adminUsage) {
		return exitCannotRun
	}
	if *writer {
		return runAuditWriter(*configPath, stdin, stderr)
	}
	if *accounts && adminGeteuid() != 0 {
		fmt.Fprint(stderr, "admin -accounts edits the identity provider's accounts, so it runs only as root.\n"+
			"The service account is deliberately unable to create accounts (design/adr/0038, 0040).\n")
		return exitCannotRun
	}
	if !*accounts && adminGeteuid() == 0 {
		fmt.Fprint(stderr, "admin serves the operator socket as the gateway's service account, not as root:\n"+
			"a root process would leave root-owned database files the gateway cannot write.\n"+
			"Run it as the service account (sudo -u SERVICE mcp-gateway admin ...), or use -accounts.\n")
		return exitCannotRun
	}
	policy, err := adminSocketPolicy(*group, *modeFlag, !*accounts)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	abs, err := filepath.Abs(*configPath)
	if err != nil {
		abs = *configPath
	}
	logger := newLogger(stderr)
	if *accounts {
		return runAdminAccounts(abs, *socket, policy, *idle, logger, stderr)
	}
	return runAdminOperator(abs, *socket, policy, *idle, logger, stderr)
}

// adminSocketPolicy builds the foreground socket policy from the flags.
func adminSocketPolicy(group, mode string, operator bool) (adminhttp.SocketPolicy, error) {
	p := adminhttp.SocketPolicy{Group: -1, Mode: 0o600, SelfUID: uint32(adminGeteuid()), OwnDirOK: operator, Trusted: adminhttp.RootOnly}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return p, fmt.Errorf("-socket-group %q: %v", group, err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		p.Group, p.Mode = gid, 0o660
	}
	if mode != "" {
		m, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return p, fmt.Errorf("-socket-mode %q is not an octal mode", mode)
		}
		p.Mode = os.FileMode(m)
	}
	return p, nil
}

// adminListener is the socket systemd passed, or one made at path.
func adminListener(path, def string, p adminhttp.SocketPolicy) (net.Listener, error) {
	ls, err := adminhttp.Activated()
	if err != nil {
		return nil, err
	}
	switch len(ls) {
	case 0:
	case 1:
		return ls[0], nil
	default:
		for _, l := range ls {
			_ = l.Close()
		}
		return nil, fmt.Errorf("systemd passed %d sockets; one unit serves one socket", len(ls))
	}
	if path == "" {
		path = def
	}
	return adminhttp.Listen(path, p)
}

// groupID resolves a configured group name, nil when none is configured.
func groupID(name string) (*uint32, error) {
	if name == "" {
		return nil, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	id := uint32(n)
	return &id, nil
}

func runAdminOperator(configPath, socket string, p adminhttp.SocketPolicy, idle time.Duration, logger *slog.Logger, stderr io.Writer) int {
	cfg, ok := loadConfig(configPath, stderr)
	if !ok {
		return exitCannotRun
	}
	opGID, err := groupID(cfg.Admin.OperatorGroup)
	if err != nil {
		fmt.Fprintf(stderr, "[admin] operator_group %q: %v\n", cfg.Admin.OperatorGroup, err)
		return exitCannotRun
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "database: %v\n", err)
		return exitCannotRun
	}
	defer db.Close()
	svc, err := newAdminService(db, func() (*config.Config, error) { return config.Load(configPath) }, stderr, configPath, logger)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	ln, err := adminListener(socket, adminapi.DefaultOperatorSocket, p)
	if err != nil {
		fmt.Fprintf(stderr, "admin: %v\n", err)
		return exitCannotRun
	}
	return serveAdmin(ln, adminhttp.Options{Socket: adminapi.SocketOperator, Service: svc, ServiceUID: uint32(adminGeteuid()),
		OperatorGID: opGID, Idle: idle, Log: logger, ConfigPath: configPath, GatewayVersion: version()}, logger, stderr)
}

func runAdminAccounts(configPath, socket string, p adminhttp.SocketPolicy, idle time.Duration, logger *slog.Logger, stderr io.Writer) int {
	loadCfg := admin.RootConfig(configPath, adminhttp.RootOnly, config.Load)
	cfg, err := loadCfg()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	if cfg.IdP.UsersFile == "" {
		fmt.Fprint(stderr, "admin -accounts needs [idp] users_file in the configuration file: the identity provider's users database.\n")
		return exitCannotRun
	}
	serviceUID, serviceGID, err := databaseOwner(cfg.Database)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	accGID, err := groupID(cfg.Admin.AccountGroup)
	if err != nil {
		fmt.Fprintf(stderr, "[admin] account_group %q: %v\n", cfg.Admin.AccountGroup, err)
		return exitCannotRun
	}
	svc, err := admin.New(admin.Deps{
		Config:   loadCfg,
		Record:   spawnAuditWriter(configPath, serviceUID, serviceGID),
		Accounts: openDirectory,
		IsBusy:   store.IsBusy,
		Log:      logger,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	ln, err := adminListener(socket, adminapi.DefaultAccountsSocket, p)
	if err != nil {
		fmt.Fprintf(stderr, "admin: %v\n", err)
		return exitCannotRun
	}
	gid, mode, path, err := adminhttp.SocketFileOf(ln)
	if err == nil {
		err = adminhttp.CheckAccountsFile(gid, mode, accGID)
	}
	if err != nil {
		_ = ln.Close()
		fmt.Fprintf(stderr, "admin -accounts: %s: %v\n", path, err)
		return exitCannotRun
	}
	return serveAdmin(ln, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: svc, ServiceUID: serviceUID,
		Idle: idle, Log: logger, ConfigPath: configPath, GatewayVersion: version()}, logger, stderr)
}

func serveAdmin(ln net.Listener, o adminhttp.Options, logger *slog.Logger, stderr io.Writer) int {
	srv, err := adminhttp.New(o)
	if err != nil {
		_ = ln.Close()
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	ctx, stop := signalContext()
	defer stop()
	logger.Info("admin: serving", "socket", o.Socket, "path", ln.Addr().String(), "idle", o.Idle.String())
	if err := srv.Serve(ctx, ln); err != nil {
		fmt.Fprintf(stderr, "admin: %v\n", err)
		return exitCannotRun
	}
	return exitOK
}

// databaseOwner is the uid and gid of the database's directory: the
// service account. It must be a directory and not root's.
func databaseOwner(dbPath string) (uint32, uint32, error) {
	dir := filepath.Dir(dbPath)
	fi, err := os.Lstat(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("the database directory: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok {
		return 0, 0, fmt.Errorf("the database directory %s is not a directory", dir)
	}
	if st.Uid == 0 {
		return 0, 0, fmt.Errorf("the database directory %s belongs to root; it must be the service account's, which the audit writer runs as", dir)
	}
	return st.Uid, st.Gid, nil
}

// openDirectory opens the IdP's users file named by cfg.
func openDirectory(cfg *config.Config) (idp.Directory, error) {
	if cfg.IdP.UsersFile == "" {
		return nil, errors.New("no [idp] users_file is configured")
	}
	dir := autheliafile.New(cfg.IdP.UsersFile)
	if _, err := dir.Accounts(); err != nil {
		return nil, err
	}
	return dir, nil
}

// auditWriterInput is one operator row as the root process hands it to
// the audit writer. It never carries a password: the rows do not.
type auditWriterInput struct {
	Identity  string    `json:"identity"`
	Tool      string    `json:"tool"`
	Target    string    `json:"target"`
	Timestamp time.Time `json:"timestamp"`
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason"`
}

func auditWriterRecord(r audit.Record) auditWriterInput {
	return auditWriterInput{Identity: r.AnalystIdentity, Tool: r.Tool, Target: r.TargetUpstream, Timestamp: r.Timestamp, Outcome: string(r.Outcome), Reason: r.Reason}
}

// accountTools are the only rows the audit writer appends.
var accountTools = map[string]bool{admin.AccountAdd: true, admin.AccountGroups: true, admin.AccountDisable: true, admin.AccountEnable: true, admin.AccountReset: true}

// spawnAuditWriter is the accounts backend's Record: a child that runs as
// the database's owner, with no supplementary groups and an empty
// environment, receives the row on standard input, appends it and exits.
func spawnAuditWriter(configPath string, uid, gid uint32) func(context.Context, *config.Config, audit.Record) error {
	return func(ctx context.Context, _ *config.Config, rec audit.Record) error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		body, err := json.Marshal(auditWriterRecord(rec))
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, exe, "admin", "-audit-writer", "-config", configPath) // #nosec G204 -- this binary
		cmd.Env = []string{}
		cmd.Dir = "/"
		cmd.Stdin = bytes.NewReader(body)
		var errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = io.Discard, &errb
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("audit writer: %v: %s", err, strings.TrimSpace(errb.String()))
		}
		return nil
	}
}

// runAuditWriter appends one operator row read from stdin. It refuses to
// run as root: its reason to exist is that root never opens the service
// account's database.
func runAuditWriter(configPath string, stdin io.Reader, stderr io.Writer) int {
	if adminGeteuid() == 0 {
		fmt.Fprint(stderr, "admin -audit-writer runs as the database's owner, never as root.\n")
		return exitCannotRun
	}
	data, err := io.ReadAll(io.LimitReader(stdin, adminhttp.MaxBody+1))
	if err != nil || len(data) > adminhttp.MaxBody {
		fmt.Fprint(stderr, "admin -audit-writer: unreadable or oversized input\n")
		return exitCannotRun
	}
	var in auditWriterInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		fmt.Fprintf(stderr, "admin -audit-writer: %v\n", err)
		return exitCannotRun
	}
	if !strings.HasPrefix(in.Identity, "(operator:") || in.Target != admin.OperatorTarget || !accountTools[in.Tool] || in.Outcome != string(audit.OutcomeAllowed) {
		fmt.Fprint(stderr, "admin -audit-writer: only an account action's operator row is appended here\n")
		return exitProblem
	}
	if in.Timestamp.IsZero() {
		in.Timestamp = time.Now().UTC()
	}
	rec := audit.Record{AnalystIdentity: in.Identity, Tool: in.Tool, TargetUpstream: in.Target, Timestamp: in.Timestamp, Outcome: audit.OutcomeAllowed, Reason: in.Reason}
	return opRun(configPath, io.Discard, stderr, func(e *opEnv) int {
		if err := retryBusy(e.ctx(), func() error { return e.recordOperatorAction(rec) }); err != nil {
			fmt.Fprintf(stderr, "audit trail: %v\n", err)
			return exitProblem
		}
		return exitOK
	})
}

// newAdminService builds the management service over db, reading the
// configuration with loadCfg for every operation. The CLI builds one per
// command; `admin` builds one per process.
func newAdminService(db *sql.DB, loadCfg func() (*config.Config, error), stderr io.Writer, configPath string, logger *slog.Logger) (*admin.Service, error) {
	envFor := func(cfg *config.Config) *opEnv {
		return &opEnv{cfg: cfg, db: db, stdout: io.Discard, stderr: stderr, configPath: configPath}
	}
	base := envFor(nil)
	return admin.New(admin.Deps{
		Config: loadCfg,
		Tools:  base.tools(),
		Blocks: base.blocks(),
		Trail:  auditsqlite.New(db),
		Quota:  base.quotaCounters(),
		Upstreams: func(ctx context.Context, cfg *config.Config) ([]adminapi.Upstream, error) {
			return opUpstreams(envFor(cfg))
		},
		Record: func(_ context.Context, cfg *config.Config, rec audit.Record) error {
			return envFor(cfg).recordOperatorAction(rec)
		},
		Accounts: openDirectory,
		IsBusy:   store.IsBusy,
		Log:      logger,
	})
}
