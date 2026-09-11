package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/access/oidc"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditjsonl "github.com/bunnyiesart/Gatte/internal/audit/jsonl"
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

// refreshTimeout bounds one round of periodic re-observation: a
// `tools/list` against each connected upstream (gateway.Refresh).
//
// It is the same order as the startup connect and for the same reason -- a
// backend that accepts the request and then stalls must not hold the loop
// forever. If it is exceeded, the upstreams that did answer are refreshed
// and the ones that did not keep their previous observation, which is
// exactly what Refresh does with any other listing failure.
//
// Ticks that arrive while a refresh is still running are dropped rather
// than queued (the loop is a single goroutine calling Refresh
// synchronously), so a refresh interval shorter than this cannot pile
// overlapping rounds onto the backends.
const refreshTimeout = 30 * time.Second

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
	// Discarded and Usage neutered for the reason opFlagSet gives: the flag
	// package renders -h and a parse error through the same writer, and
	// opParse is where the two are told apart.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	configPath := fs.String("config", defaultConfigPath, "path to the TOML configuration file")
	// serve builds its own flag set rather than using opFlagSet -- it takes
	// no other operator flags -- so its usage renderer is written out here.
	// It still goes through opParse, which is what maps -h onto exit 0 and
	// onto stdout.
	usage := func(w io.Writer) {
		fmt.Fprint(w, "Usage: mcp-gateway serve [-config path]\n\nRuns the gateway until SIGINT or SIGTERM.\n\nFlags:\n")
		fs.SetOutput(w)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	if code, ok := opParse(fs, args, stdout, stderr, usage); !ok {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "serve: unexpected argument %q\n", fs.Arg(0))
		usage(stderr)
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

	// refreshEvery is how often the connected upstreams are re-observed.
	// Always positive -- config.Validate refuses anything else, because
	// there is deliberately no value that turns re-observation off.
	refreshEvery time.Duration

	// maxResultBytes is the ceiling on one tool result, as the Gateway was
	// built with it. Always positive, for the same reason and by the same
	// rule as refreshEvery (design/adr/0014).
	maxResultBytes int64

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
	stack.maxResultBytes = cfg.Response.MaxResultBytes()
	logger.Info("mcp-gateway: starting",
		slog.String("version", buildVersion),
		slog.String("listen", cfg.Listen),
		slog.Bool("require_signed", cfg.Signer.SignaturesRequired()),
		// Stated at boot because a result refused for size looks, from the
		// analyst's side, exactly like a backend that broke. Whoever is
		// paged needs the number it hit, and the alternative is reading it
		// out of a config file they may not have in front of them.
		slog.Int64("max_result_bytes", stack.maxResultBytes),
	)
	// Before anything is opened, spawned or connected: if this process must
	// not be reachable, finding that out after building the whole stack
	// would mean spawning every upstream subprocess only to exit.
	//
	// config.Validate applies the same predicate, so a file that loaded has
	// already passed it; this is the composition root refusing to act on a
	// Config nobody validated rather than a second opinion about the rule.
	if err := config.RequireLoopbackBind(cfg.Listen); err != nil {
		return fail(err)
	}

	db, err := openStore(cfg)
	if err != nil {
		return fail(err)
	}
	stack.closers = append(stack.closers, func() { _ = db.Close() })

	reg := registrysqlite.New(db)
	quar := quarantinesqlite.New(db)
	sigs := signersqlite.New(db)

	// Opened here rather than lazily on the first record: the operator who
	// asked for the sink is present at startup and absent at 03:00, and a
	// sink that cannot be opened is something only they can fix. See
	// auditRecorder for why this one failure is fatal while every failure
	// of the same sink at request time is not.
	aud, closeAudit, err := auditRecorder(cfg, db, logger)
	if err != nil {
		return fail(fmt.Errorf("audit trail: %w", err))
	}
	stack.closers = append(stack.closers, closeAudit)

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
		// Wiring these is GAB-18 plus ADR-0010, and they are the reason
		// gateway.verifyEntry exists: without a Store the gateway checks no
		// entry's integrity at all, and without a Verifier it would check
		// each signature against the key that arrived with it, which checks
		// nothing.
		Signatures:    sigs,
		Verifier:      sigVerifier,
		RequireSigned: cfg.Signer.SignaturesRequired(),
		// design/adr/0014. The Gateway resolves a missing or nonsensical
		// value to its own default, so this cannot switch the ceiling off;
		// passing it explicitly is what makes the configured number the one
		// in effect rather than the one in the file.
		MaxResultBytes: stack.maxResultBytes,
		Logger:         logger,
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

	stack.refreshEvery = cfg.Quarantine.RefreshEvery()
	// ctx, not connectCtx: connectCtx's budget belongs to Connect and is
	// routinely all of it -- one upstream that never answers tools/list
	// spends the lot -- so a summary built on it went silent in exactly the
	// case it is for. newStartupSummary bounds its own reads either way;
	// passing the startup context rather than the spent one keeps the
	// argument honest about what it is.
	stack.summary = newStartupSummary(ctx, cfg, listener.Addr().String(), reg, quar, startedAt, connErr)
	return stack, nil
}

// auditRecorder returns the Audit Trail port, plus the teardown for
// whatever it had to open.
//
// It returns the PORT, audit.Recorder, and never an adapter type. This is
// the one package allowed to name an adapter (internal/fitness enforces
// it), and naming one is not a reason for the rest of the wiring to depend
// on which one it is -- which is the same rule opEnv's accessors in
// operator.go follow, and the reason gateway.Config did not have to change
// for any of this.
//
// Without [audit.siem] this is exactly the recorder it has always been:
// the SQLite adapter, handed over unwrapped. Nothing else moves, and the
// trail has no external anchor -- which, per ADR-0015's correction of
// 11 Sep 2026, leaves more open than the tail item 6 named: an edit that
// re-chains forward verifies clean too.
//
// With it, the SQLite recorder is decorated: every record is written
// durably FIRST and emitted to the local JSONL file only after that write
// committed (design/adr/0017 item 1). The order is what makes the two
// copies diverge in one direction only -- a line in the SIEM with no row
// on disk means the row was removed, while a row with no line means the
// shipper is behind.
//
// # Why a failure here is fatal and the same failure later is not
//
// The two are the same file and deliberately not the same event. An
// operator asked for this sink and, at startup, is the person who can act
// on it being unavailable -- a typo in the path, a directory that does not
// exist, a jail without the mount. At request time nobody is: the disk
// filled at 03:00, the analyst is mid-incident, and refusing the call
// would convert an availability fault into a denial. jsonl.Recorder
// guarantees that second half itself (it logs at ERROR and returns nil);
// this function is only responsible for the first.
func auditRecorder(cfg *config.Config, db *sql.DB, logger *slog.Logger) (audit.Recorder, func(), error) {
	// *auditsqlite.Recorder, which satisfies audit.ChainedRecorder -- the
	// narrow second port ADR-0017 item 3 added so the decorator can read
	// the hash the write actually produced without re-reading the head
	// outside the transaction that computed it.
	inner := auditsqlite.New(db)
	if !cfg.Audit.SIEM.Enabled() {
		return inner, func() {}, nil
	}

	sink, err := auditjsonl.OpenFile(cfg.Audit.SIEM.Path)
	if err != nil {
		return nil, nil, err
	}
	rec, err := auditjsonl.New(inner, sink, cfg.Audit.SIEM.Chain, logger)
	if err != nil {
		// Closed rather than leaked: the caller gets an error and nothing
		// to clean up, which is buildServer's contract for every other
		// resource too.
		_ = sink.Close()
		return nil, nil, err
	}
	return rec, func() { _ = sink.Close() }, nil
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

	// Started before the listener accepts anything: the first analyst call
	// and the first re-observation are independent, and there is no reason
	// to serve for one interval with the loop not yet running.
	//
	// Its own cancel, derived from ctx, so that both ways out of this
	// function stop it -- the signal path cancels ctx, and the
	// server-died path below cancels this. Waiting for it to exit before
	// returning is not tidiness: run's caller closes the database on the
	// way out, and a refresh still writing observations into a closed
	// database is a confusing error at the worst possible moment.
	refreshCtx, stopRefresh := context.WithCancel(ctx)
	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		s.refreshLoop(refreshCtx, logger)
	}()
	defer func() {
		stopRefresh()
		<-refreshDone
	}()

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

// refreshLoop re-observes the connected upstreams every refreshEvery until
// ctx is cancelled.
//
// This loop is the whole of GAB-23's fix at the process level, and what it
// exists to prevent is worth stating where somebody will read it while
// deciding whether to keep it. Before it, quarantine.Store.Observe was
// reachable only from gateway.Connect, and Connect ran once, at boot: a
// backend that rewrote an approved tool's description was re-measured only
// when a human restarted the process, which for a SOC gateway can be weeks.
// The control built to catch rug pulls (OWASP MCP03) could not fire while
// the gateway was doing its job.
//
// **The window is not closed, only bounded.** Between two ticks a tool
// poisoned upstream is still served under its old approval, for up to
// quarantine.refresh_interval. Shortening it means lowering the interval
// and paying one `tools/list` per upstream more often. That is the trade
// ADR-0013 makes explicitly; it is not a bug and there is no version of
// this that reaches zero.
//
// A failed round changes nothing and brings nothing down -- see
// gateway.Refresh -- so this loop never stops on an error. It logs and
// waits for the next tick, because the alternative (a loop that gives up
// after a bad night) is a security control that silently stopped.
func (s *serveStack) refreshLoop(ctx context.Context, logger *slog.Logger) {
	logger.Info("mcp-gateway: re-observing upstream tool definitions periodically",
		slog.Duration("every", s.refreshEvery),
		slog.Duration("timeout", refreshTimeout),
	)

	ticker := time.NewTicker(s.refreshEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Bounded, and derived from ctx so a shutdown cuts a round in
		// flight rather than waiting for a stalled backend to answer.
		refreshCtx, cancel := context.WithTimeout(ctx, refreshTimeout)
		err := s.gateway.Refresh(refreshCtx)
		cancel()

		switch {
		case err == nil:
		case errors.Is(err, gateway.ErrClosed):
			// Shutdown won the race with this tick. Nothing to report and
			// nothing left to refresh.
			return
		default:
			// Partial by construction: gateway.Refresh has already logged
			// each upstream's own failure with its detail, and every
			// upstream that did answer has been re-observed. One line here
			// so the failure is visible as a recurring event rather than
			// only as scattered per-upstream errors.
			logger.Error("mcp-gateway: some upstreams were not re-observed; their previous tool definitions and quarantine state stand",
				slog.String("detail", err.Error()))
		}

		// Rides the same tick as the re-observation, and for the same
		// reason: both answer "is what we are serving still what we
		// think?", and both bound a window rather than closing one.
		//
		// Run even when Refresh above failed. The two are independent --
		// a backend that would not answer `tools/list` says nothing about
		// whether its credential was rotated underneath it -- and a
		// rotation is exactly the kind of thing somebody does during the
		// incident that also makes a backend flaky.
		// Its OWN context, derived from ctx. refreshCtx was cancelled the
		// moment Refresh returned, a dozen lines above, so passing it here
		// handed the drift check a context that was already dead. Nothing
		// failed visibly only because the vault in use does not consult
		// it -- the check was one ctx-honouring vault.Provider away from
		// reporting no drift, forever, while looking like it ran.
		driftCtx, driftCancel := context.WithTimeout(ctx, refreshTimeout)
		s.reportCredentialDrift(driftCtx, logger)
		driftCancel()
	}
}

// reportCredentialDrift says, once per tick, which connected upstreams are
// still running on a credential the vault no longer holds.
//
// It is a Warn and not an Error because nothing is broken: the upstream is
// serving fine, on the old value. That is precisely the problem -- see
// gateway.CredentialDrift. The operator's remedy today is a restart; there
// is deliberately no automatic reconnect here, because silently re-dialing
// a backend during an incident is a bigger decision than this loop is
// entitled to make (the reconnect command is the other half of GAB-20).
func (s *serveStack) reportCredentialDrift(ctx context.Context, logger *slog.Logger) {
	// A dead context here means the check cannot have run, and the danger
	// is that "no drift reported" and "drift never looked for" are the same
	// silence. Say which one happened, and say it at Error: a rotation
	// going unnoticed is what this whole loop exists to prevent.
	if err := ctx.Err(); err != nil {
		logger.Error("mcp-gateway: credential drift was NOT checked this tick -- the check was handed an expired context, "+
			"so a rotated credential still in use would go unreported",
			slog.String("detail", err.Error()))
		return
	}

	drift := s.gateway.CredentialDrift(ctx)
	if len(drift) == 0 {
		return
	}

	// Upstream name and variable name only. Neither is a secret, and
	// nothing derived from a value appears here or anywhere else.
	pairs := make([]string, 0, len(drift))
	for _, d := range drift {
		pairs = append(pairs, d.Upstream+"."+d.VarName)
	}
	logger.Warn("mcp-gateway: a credential was rotated in the vault but the connected upstream is STILL USING THE OLD VALUE -- rotation takes effect at the next dial, so restart the gateway to make it real",
		slog.Any("credentials", pairs),
		slog.Int("count", len(pairs)),
	)
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
	// UpstreamsRegistered is how many entries the Upstream Registry holds,
	// or -1 when that read did not return.
	UpstreamsRegistered int
	// UpstreamsFailed names the upstreams Connect reported a problem with.
	//
	// Empty carries TWO meanings and cannot tell them apart on its own:
	// none failed, and the registry read this list is derived from never
	// happened. UpstreamsRegistered < 0 is what separates them, and log
	// reports the second as -1 rather than as a count of zero -- see there.
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
	// Roles is what each configured role reaches at this boot. See
	// roleReach.
	Roles []roleReach
	// UnregisteredGrants are the [role.grants] keys that address no entry
	// the Upstream Registry holds. See grantGap.
	UnregisteredGrants []grantGap
	// EmptyGrants are [role.grants] entries written with no tools. Legal,
	// reaching nothing, and reported by nothing until this field existed.
	EmptyGrants []grantGap
	// SIEMChain is the chain name lines are emitted under, empty when no
	// sink is configured, and SIEMPath the file they are appended to.
	//
	// Reported for the reason RequireSigned is: whether the audit trail
	// leaves this host at all decides whether the chain has an anchor --
	// and therefore whether tampering is detectable at all, not merely
	// whether truncation is (ADR-0015's 11 Sep 2026 correction). That is
	// not something an operator should have to infer from the absence of a
	// log line.
	SIEMChain string
	SIEMPath  string
}

// grantGap is one [role.grants] key that reaches no registered upstream --
// "reaches" as grantReaches defines it, which is not the same as "is not
// the name of one".
//
// It cannot be a load-time error. Upstreams live in the SQLite registry
// (ADR-0001) and opRun calls loadConfig -- and so Config.Validate --
// BEFORE openStore, deliberately, so that a wrong file fails without
// depending on the database opening at all. So this is a startup
// diagnostic, in the one place that holds both the file and the registry.
type grantGap struct {
	// Role is the role as the file names it.
	Role string
	// Backend is the grant key no registered upstream's tools fall under.
	Backend string
}

// unregisteredGrants finds every (role, backend) pair whose grant reaches
// no entry in the registry at all.
//
// Roles keep file order and backends are sorted, so two runs over one
// unchanged file produce the same list -- the same reason
// access.validateGrants sorts.
// emptyGrants lists the [role.grants] entries written with no tools.
//
// An empty list is LEGAL: the access package treats a staged grant as a
// deliberate shape, and refusing it would break a config someone wrote on
// purpose. But it reaches nothing, and it fell between every diagnostic
// here -- unregisteredGrants asks whether the backend is registered, and it
// is; the "role authorizes nothing" check counts roles with no grants, and
// this role has one. A grant that reaches nothing was the one kind nobody
// reported, which is the whole complaint.
//
// Its own function rather than a flag on grantGap, because it is a
// different complaint with a different fix: that one says "register the
// backend or drop the grant", this one says "the list is empty and you may
// have meant to fill it".
func emptyGrants(roles []config.Role) []grantGap {
	var gaps []grantGap
	for _, r := range roles {
		for _, backend := range slices.Sorted(maps.Keys(r.Grants)) {
			if len(r.Grants[backend]) == 0 {
				gaps = append(gaps, grantGap{Role: r.Name, Backend: backend})
			}
		}
	}
	return gaps
}

func unregisteredGrants(roles []config.Role, entries []registry.UpstreamServer) []grantGap {
	var gaps []grantGap
	for _, r := range roles {
		for _, backend := range slices.Sorted(maps.Keys(r.Grants)) {
			reaches := slices.ContainsFunc(entries, func(e registry.UpstreamServer) bool {
				return grantReaches(backend, r.Grants[backend], e.Name)
			})
			if !reaches {
				gaps = append(gaps, grantGap{Role: r.Name, Backend: backend})
			}
		}
	}
	return gaps
}

// grantReaches reports whether one [role.grants] entry can address any
// tool of the registered upstream called entry.
//
// It is not string equality on the name, and that distinction is the whole
// of this function. access.Role.Allows matches a grant key as a prefix up
// to the namespace separator, so the grant `threatintel = ["*"]` addresses
// every tool of an upstream registered as `threatintel.staging`: the
// namespaced name `threatintel.staging.lookup_ip` begins with
// `threatintel.`. Comparing the key to entry names exactly finds no
// `threatintel` and reports a gap, and the warning this feeds then tells
// the operator, of a registry that holds an entry that key addresses, that
// there is "no upstream registered for" it.
//
// registry.UpstreamServer.Validate now refuses a name containing the
// separator, and gateway.Connect re-checks that contract on rows the
// store hands back, so such an entry cannot serve tools -- which is why
// the wrong reading no longer costs an operator a live grant they believe
// inert. It is still the wrong reading, and this diagnostic must not lean
// on a rule enforced in another package to make its own sentence true:
// the question is put to access.Role.Allows, the request path's own
// predicate, for the reason roleReaches gives. A diagnostic computed by a
// looser or narrower rule than the gate is a second opinion, free to
// disagree with the thing it reports on -- and this one disagreed in the
// same log line, printing "authorizes nothing" beside a `role reach` that
// counted those same tools as observed.
func grantReaches(backend string, ids []string, entry string) bool {
	if entry == backend {
		// Said first and without asking Allows, because it holds whatever
		// the list contains. An empty grant (`casemgmt = []`) addresses no
		// tool, but the backend it names IS registered, and the warning
		// this feeds says the opposite of that.
		return true
	}

	// Beyond an exact name only the gate can say, and it is asked with the
	// ids the grant actually names. A named id may not contain the
	// separator (access.ValidateRole refuses one), so `threatintel =
	// ["lookup_ip"]` genuinely cannot reach threatintel.staging, whose
	// remainder after the key is "staging.lookup_ip": only a wildcard
	// crosses the separator, and asking with access.GrantAll as the tool
	// id is how that is put to Allows -- any non-empty remainder answers
	// for a grant that covers every id its backend may ever advertise.
	probe := access.Role{Grants: map[string][]string{backend: ids}}
	for _, id := range ids {
		if probe.Allows(gateway.Namespaced(entry, id)) {
			return true
		}
	}
	return false
}

// roleReach is one role's answer to "does this actually grant anything?".
//
// It exists because a role can be perfectly well-formed and grant nothing
// at all. In the flat `tools` list matching is exact with no wildcard, so
// a role naming tools no connected upstream advertises authorizes an empty
// set -- no error, no log line, and the first report of it is an analyst
// denied mid-incident (GAB-30 item 3). config.Validate now refuses the
// common way to write that (an un-namespaced name), but it cannot refuse a
// correctly shaped name for a tool that is simply not there: a renamed
// backend tool, an upstream that did not come up, a typo inside the
// namespace.
//
// [role.grants] adds a second way to reach nothing and does not remove
// this one. A named grant misses the same way a flat name does; a `["*"]`
// grant over a backend that is not registered, or did not come up, reaches
// nothing while looking like the broadest permission in the file. See
// Wildcards and grantGap, which answer those two separately.
type roleReach struct {
	// Name is the role as the file names it.
	Name string
	// Granted is how many tools the file names for this role: the flat
	// `tools` list plus every tool id written under [role.grants].
	//
	// It counts only the FINITE half. A `["*"]` grant is not a number and
	// is deliberately not turned into one -- see Wildcards.
	Granted int
	// Wildcards are the backends this role granted with "*", rendered as
	// "backend:*".
	//
	// They are reported instead of counted. A wildcard grants every tool
	// its backend advertises now and later, so any count would be a
	// snapshot presented as a grant -- and this file already learned, from
	// AllowedTools, that pretending to enumerate a wildcard is the claim
	// without backing this project keeps refusing.
	Wildcards []string
	// Observed is how many of the tool names this gateway actually saw on a
	// connected upstream during this boot the role allows.
	//
	// With a wildcard grant it can exceed Granted, and that is the honest
	// reading rather than a bug: the role reaches more tools than the file
	// names, which is exactly what the wildcard was written to do.
	//
	// It is NOT how many are callable. Tool Quarantine approval is a
	// separate gate, and a tool that was observed but is still pending
	// counts here -- the question this answers is "do these names refer to
	// anything", not "may anyone call them".
	Observed int
}

// roleReaches resolves each role against the namespaced tool names this
// boot observed.
//
// Observation is decided by access.Role.Allows -- the very predicate the
// request path gates on -- rather than by a rule restated here. That
// matters more now than it did when a role was a flat list: a count
// computed by a looser (or narrower) rule than the gate would be a second
// opinion, free to disagree with the thing it is reporting on, and the
// per-backend form gives it far more room to disagree in.
//
// Before ADR-0016 this counted r.Tools and nothing else, so a role
// composed entirely of [role.grants] reported 0/0 -- indistinguishable
// from an empty role, invisible in the `role reach` line, and excluded
// from the dead-role warning that line exists to raise.
func roleReaches(roles []config.Role, observed map[string]bool) []roleReach {
	names := slices.Sorted(maps.Keys(observed))

	out := make([]roleReach, 0, len(roles))
	for _, r := range roles {
		reach := roleReach{Name: r.Name, Granted: len(r.Tools)}
		for _, backend := range slices.Sorted(maps.Keys(r.Grants)) {
			// "*" alongside names is refused by access.ValidateRole, so a
			// list holding it holds nothing else worth counting -- and if
			// one ever did, "*" already covers every name beside it.
			if slices.Contains(r.Grants[backend], access.GrantAll) {
				reach.Wildcards = append(reach.Wildcards, backend+":"+access.GrantAll)
				continue
			}
			reach.Granted += len(r.Grants[backend])
		}

		// The domain type, queried directly. config.Role mirrors it field
		// for field precisely so this conversion is the whole of the
		// translation, and Allows is then the same code the gate runs.
		domain := access.Role{Name: r.Name, Tools: r.Tools, Grants: r.Grants}
		for _, name := range names {
			if domain.Allows(name) {
				reach.Observed++
			}
		}
		out = append(out, reach)
	}
	return out
}

// startupSummaryReadTimeout bounds the two local reads the summary makes.
// Small, because both are SQLite queries against a database this process
// already has open: a value long enough to matter would only ever be spent
// waiting for a store that is not going to answer, and the summary is a
// diagnostic that must not delay serving.
const startupSummaryReadTimeout = 5 * time.Second

// newStartupSummary gathers the counts. Every read here is best-effort:
// a summary that cannot be built must not stop a gateway that can serve,
// so a failing count is logged as unknown (-1) rather than returned.
//
// # Why the reads do not run on ctx
//
// Best-effort means the read is attempted, and an already-expired context
// is not an attempt. The caller is buildServer, which has just spent a
// deadline-bounded context on gw.Connect -- and Connect walks its entries
// sequentially on that one context with no per-entry sub-timeout, so a
// single upstream that accepts the spawn and never answers tools/list
// consumes the whole budget. Running these reads on that context made
// every one of them fail in exactly the situation the summary exists for:
// the operator was told upstreams_registered=-1 and nothing else -- not
// WHICH upstream hung, not that a role now reaches nothing, not that a
// grant addresses nothing. So the reads get their own small budget.
//
// ctx's cancellation is deliberately not inherited with it. The reads are
// two local queries bounded by startupSummaryReadTimeout, and a signal
// arriving mid-startup does not make "which backend did not come up" a
// less useful thing to have printed -- buildServer goes on to bind and
// return regardless. Values still pass through, so anything carried on
// ctx for tracing reaches the store.
func newStartupSummary(
	ctx context.Context,
	cfg *config.Config,
	addr string,
	reg registry.Repository,
	quar quarantine.Store,
	startedAt time.Time,
	connErr error,
) startupSummary {
	readCtx, cancelRead := context.WithTimeout(context.WithoutCancel(ctx), startupSummaryReadTimeout)
	defer cancelRead()

	s := startupSummary{
		Addr:                addr,
		Loopback:            config.IsLoopbackAddr(addr),
		UpstreamsRegistered: -1,
		ToolsDiscovered:     -1,
		ToolsServable:       -1,
		RequireSigned:       cfg.Signer.SignaturesRequired(),
		TrustedKeys:         len(cfg.Signer.TrustedKeys),
	}
	if cfg.Audit.SIEM.Enabled() {
		s.SIEMChain, s.SIEMPath = cfg.Audit.SIEM.Chain, cfg.Audit.SIEM.Path
	}

	if entries, err := reg.List(readCtx); err == nil {
		s.UpstreamsRegistered = len(entries)
		s.UpstreamsFailed = failedUpstreams(entries, connErr)
		// Inside this block, so a registry that could not be read reports
		// no gaps at all. With no entries to compare against, EVERY grant
		// would look unregistered -- the same reason the dead-role warning
		// below is suppressed when nothing was observed: a diagnostic that
		// fires hardest when its own input is missing teaches people to
		// ignore it.
		s.UnregisteredGrants = unregisteredGrants(cfg.Roles, entries)
	}
	// OUTSIDE the block above, deliberately: an empty grant list is a fact
	// about the config file alone. It needs no registry to detect, so a
	// registry that could not be read must not also hide this.
	s.EmptyGrants = emptyGrants(cfg.Roles)
	if boot, err := countTools(readCtx, quar, startedAt); err == nil {
		s.ToolsDiscovered, s.ToolsServable = boot.Discovered, boot.Servable
		s.Roles = roleReaches(cfg.Roles, boot.Names)
	}
	return s
}

// log writes the summary. It is several lines rather than one because the
// two facts an operator most needs -- that this process is network
// reachable, and whether unsigned registry entries are being served -- are
// warnings, and a warning buried as a field of an info line is a warning
// nobody greps for.
func (s startupSummary) log(logger *slog.Logger) {
	connected, failed := s.UpstreamsRegistered-len(s.UpstreamsFailed), len(s.UpstreamsFailed)
	if s.UpstreamsRegistered < 0 {
		// Both unknown, for the same reason: UpstreamsFailed is filled in
		// from the registry read that did not return, so a nil slice here
		// means "not read", never "none failed". Printing len(nil) as 0
		// was an affirmative claim that every registered upstream came up,
		// made beside a registered count that admits it counted nothing --
		// the loudest possible version of this project's defect class, in
		// the one line an operator reads after a restart.
		connected, failed = -1, -1
	}
	logger.Info("mcp-gateway: serving",
		slog.String("listen", s.Addr),
		slog.Int("upstreams_registered", s.UpstreamsRegistered),
		slog.Int("upstreams_connected", connected),
		slog.Int("upstreams_failed", failed),
		slog.Int("tools_discovered", s.ToolsDiscovered),
		slog.Int("tools_servable", s.ToolsServable),
		slog.Bool("require_signed", s.RequireSigned),
		slog.Int("trusted_keys", s.TrustedKeys),
	)

	if s.UpstreamsRegistered < 0 || s.ToolsDiscovered < 0 {
		// Said once, and said as a warning, because every diagnostic below
		// that depends on those reads is silent rather than reassuring: no
		// failed-upstream line, no `role reach`, no dead-role warning, no
		// unregistered-grant warning. Without this line their absence
		// reads as "nothing to report".
		logger.Warn("mcp-gateway: the startup summary could not be built -- a -1 above is UNKNOWN, not zero, and the upstream, role-reach and grant checks below did not run; `mcp-gateway upstream list` and `tool list` are the way to see what is actually registered",
			slog.Bool("registry_read", s.UpstreamsRegistered >= 0),
			slog.Bool("quarantine_read", s.ToolsDiscovered >= 0),
		)
	}

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
	if s.SIEMChain != "" {
		logger.Info("mcp-gateway: audit records are also emitted as JSONL for the SIEM (ADR-0017); a shipper must forward this file, and `audit -verify -expect-head` takes its expected value from the newest hash Graylog holds for this chain",
			slog.String("chain", s.SIEMChain),
			slog.String("path", s.SIEMPath),
		)
	} else {
		// Info, not Warn: no sink is the documented default and the shape
		// every deployment had before ADR-0017. What it costs is stated
		// anyway, because the thing it costs -- the only detection of a
		// rewritten trail there is -- is invisible precisely when it
		// matters.
		logger.Info("mcp-gateway: no audit.siem sink configured, so the trail stays in SQLite only, where a truncated tail verifies and so does an edit whose hashes were recomputed (ADR-0015 item 6 and its 11 Sep 2026 correction); set audit.siem.path and audit.siem.chain to anchor the chain head outside this host")
	}
	if s.ToolsDiscovered > 0 && s.ToolsServable == 0 {
		logger.Warn("mcp-gateway: no discovered tool is approved in Tool Quarantine, so every analyst will see an empty tool list until an operator approves one",
			slog.Int("awaiting_approval", s.ToolsDiscovered))
	}

	if len(s.Roles) > 0 {
		// One line for all of them: with two to four roles this is a
		// sentence, and a line per role would push the warning below off
		// the top of a small terminal.
		parts := make([]string, 0, len(s.Roles))
		var dead []string
		for _, r := range s.Roles {
			part := fmt.Sprintf("%s %d/%d", r.Name, r.Observed, r.Granted)
			if len(r.Wildcards) > 0 {
				// Appended rather than folded into the denominator: a
				// wildcard has no finite granted count, and inventing one
				// would report a snapshot as though it were the grant.
				part += "+" + strings.Join(r.Wildcards, "+")
			}
			parts = append(parts, part)
			// Only a role that asks for tools and reaches none. A role
			// granting nothing on purpose (config.example.toml ships one,
			// for someone who may authenticate but may not act) is a
			// documented shape, and warning about it is how a warning
			// stops being read. A wildcard counts as asking: `threatintel
			// = ["*"]` reaching nothing is the loudest version of this.
			if r.Observed == 0 && (r.Granted > 0 || len(r.Wildcards) > 0) {
				dead = append(dead, r.Name)
			}
		}
		logger.Info("mcp-gateway: role reach (observed/granted tools per role; observed counts tools seen this boot, approved or not; a `backend:*` suffix is a wildcard grant, which has no finite granted count)",
			slog.String("roles", strings.Join(parts, ", ")))
		if len(dead) > 0 && s.ToolsDiscovered > 0 {
			// Suppressed when nothing was observed at all: with no
			// upstream up, every role reaches nothing and the line above
			// about failed upstreams is the real news.
			logger.Warn("mcp-gateway: a role grants tools that match nothing this gateway observed, so it authorizes nothing -- check the names against `mcp-gateway tool list` (in `tools` matching is exact and namespaced, with no wildcard)",
				slog.Any("roles", dead))
		}
	}

	if len(s.EmptyGrants) > 0 {
		pairs := make([]string, 0, len(s.EmptyGrants))
		for _, g := range s.EmptyGrants {
			pairs = append(pairs, g.Role+" -> "+g.Backend)
		}
		logger.Warn("mcp-gateway: a role grants a backend an EMPTY tool list, which is legal and reaches nothing -- "+
			"working as written if that is staging; a missing list if it was meant to grant something",
			slog.String("grants", strings.Join(pairs, ", ")))
	}
	if len(s.UnregisteredGrants) > 0 {
		// One line for every pair, and deliberately NOT fatal. Writing a
		// grant before registering the backend it is for is the normal
		// order of work, and a gateway that refused to start because one
		// upstream had been deregistered would be an outage manufactured by
		// a diagnostic.
		pairs := make([]string, 0, len(s.UnregisteredGrants))
		for _, g := range s.UnregisteredGrants {
			pairs = append(pairs, g.Role+" -> "+g.Backend)
		}
		logger.Warn("mcp-gateway: a role grants a backend this gateway has no upstream registered for, so it authorizes nothing -- register it (`mcp-gateway upstream register`) or drop the grant; the file reads as a permission and applies none",
			slog.Any("grants", pairs),
			slog.Int("count", len(pairs)),
		)
	}
}

// bootTools is what the Tool Quarantine holds for this boot: the counts the
// summary reports, and the namespaced names the roles are resolved against.
//
// Names carries every tool observed this boot, servable or not, because the
// question it answers is whether a role's tool names refer to anything real
// -- see roleReach.Observed.
type bootTools struct {
	Discovered int
	Servable   int
	Names      map[string]bool
}

// countTools reports how many tools this boot's Connect observed, how many
// of those are servable, and what they are called.
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
func countTools(ctx context.Context, quar quarantine.Store, startedAt time.Time) (bootTools, error) {
	tools, err := quar.List(ctx, "")
	if err != nil {
		return bootTools{}, err
	}
	boot := bootTools{Names: map[string]bool{}}
	for _, t := range tools {
		if t.UpdatedAt.Before(startedAt) {
			continue
		}
		boot.Discovered++
		boot.Names[gateway.Namespaced(t.ServerName, t.ToolName)] = true
		if t.Usable() {
			boot.Servable++
		}
	}
	return boot, nil
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

// The loopback rule (ADR-0011 item 1) used to live here, as
// requireLoopbackBind and isLoopbackAddr. It moved to
// config.RequireLoopbackBind and config.IsLoopbackAddr: the set of
// acceptable listen addresses is part of the configuration contract, and
// while the predicate lived only in this file, `listen = "0.0.0.0:9443"`
// passed config.Validate, worked in every operator subcommand, and killed
// serve at the next restart -- the fourth instance of the GAB-30 shape.
// Read that function for the reasoning; this file only applies it.
