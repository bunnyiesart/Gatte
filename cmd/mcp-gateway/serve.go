package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access/oidc"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/httpapi"
	gwstdio "github.com/bunnyiesart/Gatte/internal/gateway/stdio"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/signer"
	signersqlite "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
)

// defaultConfigPath is where -config looks when the operator does not say.
// Relative on purpose: the deployment passes an absolute path explicitly
// (see config.example.toml's header), and a default that silently found a
// file in /usr/local/etc would make "which file is in effect?" ambiguous.
const defaultConfigPath = "mcp-gateway.toml"

// shutdownTimeout bounds the graceful HTTP shutdown.
//
// It is deliberately short. Everything after it -- gateway.Close, which
// reaps the upstream subprocesses -- must still run, and a service manager
// that gives up on us and sends SIGKILL is the one outcome that orphans
// those children. Better to cut an in-flight tool call than to leak a
// process per restart.
const shutdownTimeout = 15 * time.Second

// readHeaderTimeout bounds how long a client may take to send its request
// headers. Set, unlike ReadTimeout and WriteTimeout, because MCP over
// streamable HTTP legitimately holds a response open for the length of a
// tool call, while no legitimate client takes ten seconds to send a header
// line.
const readHeaderTimeout = 10 * time.Second

// cmdServe runs the gateway: it builds every adapter from the
// configuration file, brings the registered upstreams up, and serves the
// MCP endpoint until a signal arrives.
//
// It returns exitCannotRun for any failure before the listener is serving
// (unreadable config, undecryptable vault, unreachable IdP, unreadable
// registry, an address already in use) and exitOK for a clean shutdown.
func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "path to the TOML configuration file")
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: mcp-gateway serve [-config path]\n\nRuns the gateway until SIGINT or SIGTERM.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitCannotRun
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "serve: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitCannotRun
	}

	cfg, ok := loadConfig(*configPath, stderr)
	if !ok {
		return exitCannotRun
	}

	// The operator log goes to stderr so that stdout stays free for the
	// subcommands that print data a person or a script consumes.
	logger := newLogger(stderr)

	// Installed before anything is built, so a signal during a slow
	// startup (an IdP that accepts the connection and stalls, twenty
	// upstreams being dialed) cancels it instead of being ignored until
	// the listener is up.
	ctx, stop := signalContext()
	defer stop()

	stack, err := buildServer(ctx, cfg, logger)
	if err != nil {
		// The message, not the config: nothing here prints the parsed
		// configuration, and the errors below are written by components
		// whose contracts already forbid echoing a credential.
		fmt.Fprintf(stderr, "serve: %v\n", err)
		return exitCannotRun
	}
	defer stack.close()

	return stack.run(ctx, logger)
}

// serveStack is one fully wired gateway process: the HTTP server, the
// listener it was given, the Gateway behind it, what an operator should be
// told at startup, and the teardown for everything acquired along the way.
//
// It exists so that cmdServe -- which blocks until a signal and is
// therefore awkward to test -- contains no wiring, and every wiring
// decision is reachable from a test through buildServer.
type serveStack struct {
	server   *http.Server
	listener net.Listener
	gateway  *gateway.Gateway
	summary  startupSummary

	// closers release what buildServer acquired, and are run in reverse.
	closers []func()
}

// close releases every resource the stack holds. It is safe to call more
// than once and after run: gateway.Close is idempotent by contract, and
// closing an already-closed database or listener is a no-op error this
// path has nothing to do with.
func (s *serveStack) close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}

// buildServer wires the whole system from cfg and returns it ready to
// serve. Nothing is listening for requests yet -- the listener is bound
// (so that a busy port is a startup failure rather than a surprise a
// second later) but not being served.
//
// ctx bounds startup only: the vault's sops subprocess, OIDC discovery,
// and the connect to every upstream. Cancelling it after buildServer
// returns does not disable the verifier (see oidc.New) and does not close
// the upstreams (see gwstdio.Dialer.Dial).
//
// On any error it releases whatever it had already acquired and returns
// nil, so a caller that gets an error has nothing to clean up.
func buildServer(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*serveStack, error) {
	stack := &serveStack{}
	fail := func(err error) (*serveStack, error) {
		stack.close()
		return nil, err
	}

	// First line, before anything can fail: an operator reading a log that
	// stops three lines down still learns which address this process was
	// told to expose and whether signature enforcement is on.
	logger.Info("mcp-gateway: starting",
		slog.String("version", buildVersion),
		slog.String("listen", cfg.Listen),
		slog.Bool("require_signed", cfg.Signer.SignaturesRequired()),
	)
	// Before anything is opened, spawned or connected: if this process must
	// not be reachable, finding that out after building the whole stack
	// would mean spawning every upstream subprocess only to exit.
	if err := requireLoopbackBind(cfg.Listen); err != nil {
		return fail(err)
	}

	db, err := openStore(cfg)
	if err != nil {
		return fail(err)
	}
	stack.closers = append(stack.closers, func() { _ = db.Close() })

	reg := registrysqlite.New(db)
	aud := auditsqlite.New(db)
	quar := quarantinesqlite.New(db)
	sigs := signersqlite.New(db)

	// Credential Vault. sopsage deliberately discards sops's stderr and
	// never wraps the decrypted bytes into an error, because both can echo
	// fragments of the plaintext; the error is passed through here
	// unchanged rather than being "improved" with anything from the file.
	credentials, err := sopsage.New(ctx, cfg.Vault.SecretsFile, cfg.Vault.AgeKeyFile)
	if err != nil {
		return fail(fmt.Errorf("credential vault: %w", err))
	}

	// Discovery happens here, once, so an unreachable or misconfigured IdP
	// is a loud startup failure rather than a 401 for every analyst in the
	// middle of an incident.
	verifier, err := oidc.New(ctx, oidc.Config{
		Issuer:      cfg.OIDC.Issuer,
		Audience:    cfg.OIDC.Audience,
		GroupsClaim: cfg.OIDC.GroupsClaim,
		Logger:      logger,
	})
	if err != nil {
		return fail(err)
	}

	policy, err := cfg.ToAccessPolicy()
	if err != nil {
		return fail(err)
	}

	// The trust anchor. Config.Validate has already decoded these once and
	// refused a malformed entry, so a failure here is a wiring bug rather
	// than an operator's typo -- but it is still reported instead of
	// dropped, because the alternative is a gateway that starts with an
	// emptier trusted set than the file says.
	trusted, err := cfg.Signer.TrustedPublicKeys()
	if err != nil {
		return fail(fmt.Errorf("signer: %w", err))
	}
	sigVerifier, err := signer.NewVerifier(trusted)
	if err != nil {
		return fail(fmt.Errorf("signer: %w", err))
	}

	gw, err := gateway.New(gateway.Config{
		Registry:   reg,
		Vault:      credentials,
		Quarantine: quar,
		Audit:      aud,
		Policy:     policy,
		Dialer:     gwstdio.New(gwstdio.WithClientInfo("mcp-gateway", buildVersion)),
		// Wiring these is ISSUE-18 plus ADR-0010, and they are the reason
		// gateway.verifyEntry exists: without a Store the gateway checks no
		// entry's integrity at all, and without a Verifier it would check
		// each signature against the key that arrived with it, which checks
		// nothing.
		Signatures:    sigs,
		Verifier:      sigVerifier,
		RequireSigned: cfg.Signer.SignaturesRequired(),
		Logger:        logger,
	})
	if err != nil {
		return fail(err)
	}
	stack.gateway = gw
	stack.closers = append(stack.closers, func() { _ = gw.Close() })

	connectCtx, cancelConnect := context.WithTimeout(ctx, config.DefaultConnectTimeout)
	defer cancelConnect()

	// Taken before Connect and used to tell this boot's tool observations
	// from the ones already in the database. See countTools.
	startedAt := time.Now()

	connErr := gw.Connect(connectCtx)
	if errors.Is(connErr, gateway.ErrRegistryUnavailable) {
		// Fatal, and the one Connect failure that is. ADR-0004's
		// fail-closed rule means the routing table is empty and will stay
		// empty; a process that listens on the port and serves nothing to
		// everybody is worse than one that refuses to start, because only
		// the second is visible to whoever restarted it.
		return fail(fmt.Errorf("upstream registry unreadable, so nothing can be served: %w", connErr))
	}
	// Everything else Connect reports is partial by construction: some
	// backends are up, some are not, and taking the whole SOC's gateway
	// offline for one broken backend would be a self-inflicted outage.
	// gateway.Connect has already logged each failure with its detail; the
	// summary below names them together so the count is legible.

	handler, err := httpapi.New(httpapi.Config{
		Gateway:  gw,
		Verifier: verifier,
		Policy:   policy,
		// The gateway's resource identifier is its OIDC audience. httpapi
		// cannot check that the two agree -- Verifier is an opaque
		// interface -- so passing the same value from one config field is
		// what makes them agree.
		Resource:             cfg.OIDC.Audience,
		AuthorizationServers: cfg.OIDC.AuthorizationServers,
		ServerName:           "mcp-gateway",
		ServerVersion:        buildVersion,
		Logger:               logger,
		// Left at false: an http:// resource identifier is an instruction
		// to clients to put bearer tokens on the wire in cleartext, and
		// there is deliberately no config key to switch that off.
	})
	if err != nil {
		return fail(err)
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail(fmt.Errorf("listen on %s: %w", cfg.Listen, err))
	}
	stack.listener = listener
	stack.closers = append(stack.closers, func() { _ = listener.Close() })

	stack.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       2 * time.Minute,
		// net/http's own logger would otherwise write to the standard
		// logger, bypassing the structured handler entirely.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	stack.summary = newStartupSummary(connectCtx, cfg, listener.Addr().String(), reg, quar, startedAt, connErr)
	return stack, nil
}

// run serves until ctx is cancelled by a signal, then shuts down.
//
// The shutdown order is the point of this function: stop accepting and
// drain in-flight requests first, then close the Gateway. Closing the
// Gateway first would kill the upstream a request in flight is talking to;
// not closing it at all would leave one orphaned subprocess per registered
// stdio upstream per restart, which is the kind of leak that stays
// invisible until the host runs out of processes.
func (s *serveStack) run(ctx context.Context, logger *slog.Logger) int {
	s.summary.log(logger)

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.server.Serve(s.listener) }()

	select {
	case err := <-serveErr:
		// The server stopped without being asked to. Nothing is being
		// served, so this is "could not run", not "ran and found a
		// problem".
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("mcp-gateway: stopped serving", slog.String("detail", err.Error()))
			return exitCannotRun
		}
		return exitOK
	case <-ctx.Done():
	}

	logger.Info("mcp-gateway: signal received, shutting down",
		slog.Duration("grace", shutdownTimeout))

	// context.Background, not ctx: ctx is already cancelled -- that is why
	// we are here -- and a shutdown context derived from it would expire
	// immediately, turning every graceful shutdown into an abrupt one.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	code := exitOK
	if err := s.server.Shutdown(shutdownCtx); err != nil {
		logger.Error("mcp-gateway: HTTP shutdown did not complete; connections were cut",
			slog.String("detail", err.Error()))
		code = exitProblem
	}
	// Unconditional, even when the shutdown above failed: the subprocesses
	// exist either way and this is the only thing that reaps them.
	if err := s.gateway.Close(); err != nil {
		logger.Error("mcp-gateway: closing upstreams", slog.String("detail", err.Error()))
		code = exitProblem
	}

	logger.Info("mcp-gateway: stopped")
	return code
}

// startupSummary is what an operator is told once the process is about to
// serve: enough to answer "is this thing actually working, and how
// exposed is it?" without reading the configuration file.
type startupSummary struct {
	// Addr is the bound address, resolved -- so a configured port 0 shows
	// the port actually in use.
	Addr string
	// Loopback reports whether Addr is reachable only from this host.
	Loopback bool
	// UpstreamsRegistered is how many entries the Upstream Registry holds.
	UpstreamsRegistered int
	// UpstreamsFailed names the upstreams Connect reported a problem with.
	UpstreamsFailed []string
	// ToolsDiscovered is how many tools were observed during this boot's
	// Connect, and ToolsServable how many of those Tool Quarantine allows
	// to be listed and called.
	ToolsDiscovered int
	ToolsServable   int
	// RequireSigned mirrors the config setting. Reported prominently
	// because it is ADR-0006's declared debt: its state should be visible
	// in the log rather than only in a file.
	RequireSigned bool
	// TrustedKeys is how many public keys signatures are checked against
	// (ADR-0010). Reported alongside RequireSigned because the two only
	// mean anything together: "signatures required" says nothing until you
	// know required *by whom*, and a list that shrank to one during a
	// rotation is worth seeing before the last key is retired.
	TrustedKeys int
}

// newStartupSummary gathers the counts. Every read here is best-effort:
// a summary that cannot be built must not stop a gateway that can serve,
// so a failing count is logged as unknown (-1) rather than returned.
func newStartupSummary(
	ctx context.Context,
	cfg *config.Config,
	addr string,
	reg registry.Repository,
	quar quarantine.Store,
	startedAt time.Time,
	connErr error,
) startupSummary {
	s := startupSummary{
		Addr:                addr,
		Loopback:            isLoopbackAddr(addr),
		UpstreamsRegistered: -1,
		ToolsDiscovered:     -1,
		ToolsServable:       -1,
		RequireSigned:       cfg.Signer.SignaturesRequired(),
		TrustedKeys:         len(cfg.Signer.TrustedKeys),
	}

	if entries, err := reg.List(ctx); err == nil {
		s.UpstreamsRegistered = len(entries)
		s.UpstreamsFailed = failedUpstreams(entries, connErr)
	}
	if discovered, servable, err := countTools(ctx, quar, startedAt); err == nil {
		s.ToolsDiscovered, s.ToolsServable = discovered, servable
	}
	return s
}

// log writes the summary. It is several lines rather than one because the
// two facts an operator most needs -- that this process is network
// reachable, and whether unsigned registry entries are being served -- are
// warnings, and a warning buried as a field of an info line is a warning
// nobody greps for.
func (s startupSummary) log(logger *slog.Logger) {
	connected := s.UpstreamsRegistered - len(s.UpstreamsFailed)
	if s.UpstreamsRegistered < 0 {
		connected = -1
	}
	logger.Info("mcp-gateway: serving",
		slog.String("listen", s.Addr),
		slog.Int("upstreams_registered", s.UpstreamsRegistered),
		slog.Int("upstreams_connected", connected),
		slog.Int("upstreams_failed", len(s.UpstreamsFailed)),
		slog.Int("tools_discovered", s.ToolsDiscovered),
		slog.Int("tools_servable", s.ToolsServable),
		slog.Bool("require_signed", s.RequireSigned),
		slog.Int("trusted_keys", s.TrustedKeys),
	)

	if len(s.UpstreamsFailed) > 0 {
		logger.Error("mcp-gateway: some upstreams did not come up; the rest are being served",
			slog.Any("upstreams", s.UpstreamsFailed),
			slog.Int("failed", len(s.UpstreamsFailed)),
			slog.Int("of", s.UpstreamsRegistered),
		)
	}
	if !s.Loopback {
		logger.Warn("mcp-gateway: listening on a NON-LOOPBACK address -- this process is reachable from the network, and it holds every backend credential",
			slog.String("listen", s.Addr))
	}
	if s.RequireSigned {
		logger.Info("mcp-gateway: require_signed=true -- a registry entry without a valid signature is refused",
			slog.Int("trusted_keys", s.TrustedKeys))
	} else {
		logger.Warn("mcp-gateway: require_signed=false -- a registry entry with NO signature is accepted and served (ADR-0006 declared debt); an INVALID signature is always refused regardless",
			slog.Int("trusted_keys", s.TrustedKeys))
	}
	if s.ToolsDiscovered > 0 && s.ToolsServable == 0 {
		logger.Warn("mcp-gateway: no discovered tool is approved in Tool Quarantine, so every analyst will see an empty tool list until an operator approves one",
			slog.Int("awaiting_approval", s.ToolsDiscovered))
	}
}

// countTools reports how many tools this boot's Connect observed and how
// many of those are servable.
//
// "This boot" is decided by UpdatedAt: gateway.Connect hands every tool of
// every upstream it brought up to quarantine.Store.Observe, and
// quarantine.Tool.Observed advances UpdatedAt on every observation,
// including the no-op one for an unchanged approved tool. Rows left over
// from an upstream that has since been deregistered, or from one that did
// not come up this time, are therefore older than startedAt and are not
// counted -- which is the whole point, since counting them would tell an
// operator that tools are being served when they are not.
//
// Servability is read through Tool.Usable and never from Status: that is
// the single gate ADR-0007 rule 3 requires, and a second opinion here
// would be a second implementation of it, free to drift from the one the
// gateway enforces.
func countTools(ctx context.Context, quar quarantine.Store, startedAt time.Time) (discovered, servable int, err error) {
	tools, err := quar.List(ctx, "")
	if err != nil {
		return 0, 0, err
	}
	for _, t := range tools {
		if t.UpdatedAt.Before(startedAt) {
			continue
		}
		discovered++
		if t.Usable() {
			servable++
		}
	}
	return discovered, servable, nil
}

// failedUpstreams names the registered upstreams that Connect reported a
// failure for.
//
// It reads the names out of the error text rather than from a structured
// result because there is no structured result: Connect returns a joined
// error, and every element it can produce wraps
// gateway.ErrUpstreamUnavailable and names its entry with %q -- refused
// signature, unresolvable credential, failed dial, failed tool listing,
// unrecordable observation, colliding tool name. Matching registered names
// against that text is therefore exact for the names, at the cost of one
// deliberate over-report: a *per-tool* failure (a colliding name, an
// unusable input schema) also names its upstream, so an upstream that came
// up and lost one tool is counted here as failed. Over-reporting is the
// right side to err on -- it points an operator at a backend that really
// did have a startup problem.
func failedUpstreams(entries []registry.UpstreamServer, connErr error) []string {
	if connErr == nil || len(entries) == 0 {
		return nil
	}
	msg := connErr.Error()
	var failed []string
	for _, entry := range entries {
		if strings.Contains(msg, strconv.Quote(entry.Name)) {
			failed = append(failed, entry.Name)
		}
	}
	return failed
}

// requireLoopbackBind refuses to start on anything but loopback
// (design/adr/0011-network-exposure-and-tls-termination.md item 1).
//
// This used to warn and continue. It does not any more, and the change is
// the control: under ADR-0011 the gateway terminates no TLS and holds no
// certificate, so a non-loopback bind is not a slightly weaker deployment
// -- it is every analyst's bearer token crossing the network in cleartext,
// along with the case data and IOCs behind it. A warning hands that
// decision to whoever is in a hurry at the time.
//
// Reaching this gateway from another machine is a job for something in
// front of it: a TLS-terminating reverse proxy sharing this jail, itself
// reachable only over the VPN. That is why the message names the fix
// rather than just the problem.
//
// There is deliberately no override flag. An `allow_insecure_bind` would
// be switched on once "just to test" and never switched off -- the exact
// mechanism by which require_signed would have rotted had ADR-0006 not
// written its trigger down. If terminating TLS here ever becomes right,
// that is an amendment to ADR-0011 with a real listen_tls, not a flag that
// disables a check.
func requireLoopbackBind(listen string) error {
	if isLoopbackAddr(listen) {
		return nil
	}
	// Note this also refuses an address that cannot be parsed: isLoopbackAddr
	// returns false when SplitHostPort fails. "Cannot tell" must not read as
	// "loopback" -- the same fail-closed reading ADR-0004 applies to a
	// registry it cannot read.
	return fmt.Errorf(
		"listen: %q is not a loopback address, and this gateway refuses to be network-reachable directly (design/adr/0011)\n"+
			"It terminates no TLS, so binding here would put every analyst's bearer token on the wire in cleartext.\n"+
			"Set listen to 127.0.0.1:PORT and put a TLS-terminating reverse proxy in front of it, in this same jail.",
		listen)
}

// isLoopbackAddr reports whether a host:port address is reachable only
// from this machine. An address it cannot parse, and the wildcard bind, are
// reported as not loopback: the fail-loud reading, since the cost of a
// spurious warning is one log line and the cost of a missed one is an
// unnoticed exposure.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
