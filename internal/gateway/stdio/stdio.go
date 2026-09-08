// Package stdio is the stdio adapter for [gateway.Dialer]: it spawns a
// backend MCP server as a child process and speaks MCP to it over that
// process's stdin/stdout, using the official Go SDK's
// [mcp.CommandTransport].
//
// This is the component that puts a real credential into a real process
// environment, so it is written to a stricter standard than the rest of
// the tree. Three rules govern everything below.
//
//  1. The child's environment is *built*, never *inherited*. The gateway's
//     own process environment may hold anything -- in a dev shell, other
//     teams' tokens; in production, whatever the supervisor exported -- and
//     an upstream has no business seeing any of it. See [Dialer.childEnv].
//
//  2. The resolved environment is never persisted, never logged, and never
//     quoted in an error. Note that [Dialer] and the returned upstream have
//     no field to hold it: that absence is load-bearing, not an oversight.
//     The assembled []string lives on the [exec.Cmd] for exactly as long as
//     the spawn takes and is dropped immediately afterwards.
//
//  3. Close reaps the child. A gateway that leaks one process per reconnect
//     dies slowly, in a way that looks like a memory problem for weeks
//     before anyone finds the zombies.
//
// # Residual risk this adapter cannot close
//
// An upstream that already holds the credential can choose to echo it back
// -- in a tool description, in a tool result, in a JSON-RPC error message
// during the handshake. No dialer can prevent that, and this one does not
// pretend to: it does not scrub upstream-authored text, because a dialer
// that quietly rewrote what a backend said would also hide exactly the
// evidence Tool Quarantine and the Audit Trail exist to catch. What this
// package guarantees is narrower and checkable: the leak never originates
// *here*. lab/probe checks the same property one layer down, at the wire.
package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TransportStdio is the only value of [gateway.UpstreamSpec.Transport] this
// dialer serves.
const TransportStdio = "stdio"

// Sentinel errors.
var (
	// ErrUnsupportedTransport means the spec asked for a transport this
	// dialer does not implement (today, anything but "stdio"). HTTP
	// upstreams are a separate adapter; a half-built one here would be a
	// second, less-reviewed path for a credential to travel.
	ErrUnsupportedTransport = errors.New("stdio: unsupported transport")
	// ErrNoCommand means a stdio spec arrived without a command to spawn.
	ErrNoCommand = errors.New("stdio: no command to spawn")
	// ErrClosed means a method was called on an upstream that has already
	// been closed. Returned instead of blocking: a caller that raced Close
	// against a dispatch gets an error it can act on, not a hang.
	ErrClosed = errors.New("stdio: upstream connection is closed")
	// ErrInvalidEnv means the caller's env map held a name or value that
	// cannot be passed to a process safely -- see validateEnvEntry.
	ErrInvalidEnv = errors.New("stdio: invalid environment entry")
)

// defaultShutdownGrace is how long Close waits, after closing the child's
// stdin, for it to exit on its own before escalating to SIGTERM and then
// SIGKILL. A well-behaved MCP server exits as soon as stdin closes, so this
// budget is only ever spent on a wedged one.
const defaultShutdownGrace = 5 * time.Second

// defaultInheritedEnv is the set of variables the child is allowed to
// inherit from the gateway's own environment, and it is deliberately as
// short as it is:
//
//   - PATH, because a child is frequently an interpreter that shells out
//     (a Python MCP server invoking git, say), and because a spec whose
//     Command is a bare name has to be resolvable at all. Note that
//     [exec.Command] resolves a bare Command against the *gateway's* PATH
//     when the Cmd is built, independently of what we set here; this entry
//     is about what the child itself can resolve once it is running.
//   - HOME, because a startlingly large number of runtimes (Python, Node,
//     Go, any tool with a cache directory) either fail outright or write
//     into "/" when HOME is unset. This is a robustness concession, not a
//     security one, and it is the only one.
//
// Everything else -- every other variable in the gateway's environment,
// including any credential belonging to some *other* upstream -- is
// dropped. The default is intentionally not configurable per-upstream:
// widening it is a deployment-wide decision (see [WithInheritedEnv]), so it
// is visible in one place rather than buried in a registry row.
var defaultInheritedEnv = []string{"PATH", "HOME"}

// DefaultInheritedEnv returns a copy of the variable names a child inherits
// from the gateway process unless [WithInheritedEnv] says otherwise. It
// returns a copy so that a caller reading the policy cannot accidentally
// widen it.
func DefaultInheritedEnv() []string {
	return append([]string(nil), defaultInheritedEnv...)
}

// Dialer spawns stdio upstreams. It implements [gateway.Dialer].
//
// A Dialer is stateless with respect to any single dial: it holds policy
// (which variables a child may inherit, how long shutdown may take, how
// this gateway identifies itself to backends) and nothing else. In
// particular it holds no credential material, and there is no field on it
// that could.
//
// A Dialer is safe for concurrent use.
type Dialer struct {
	clientName    string
	clientVersion string
	inherited     []string
	shutdownGrace time.Duration
}

var _ gateway.Dialer = (*Dialer)(nil)

// Option configures a [Dialer].
type Option func(*Dialer)

// WithClientInfo sets the name and version this gateway reports to
// upstreams in the MCP initialize handshake. Backends log it; making it
// identifiable is worth doing.
func WithClientInfo(name, version string) Option {
	return func(d *Dialer) {
		if name != "" {
			d.clientName = name
		}
		d.clientVersion = version
	}
}

// WithInheritedEnv replaces the set of variable names a child inherits from
// the gateway's own environment (default: see [DefaultInheritedEnv]).
//
// This widens the blast radius of a compromised or merely curious upstream,
// so it exists to be used sparingly and explicitly -- for a backend that
// genuinely needs, say, SSL_CERT_FILE. Passing no names at all is valid and
// gives the child an environment consisting solely of what the caller
// injected.
func WithInheritedEnv(names ...string) Option {
	return func(d *Dialer) {
		d.inherited = append([]string(nil), names...)
	}
}

// WithShutdownGrace sets how long Close waits for a child to exit after its
// stdin is closed, before escalating to SIGTERM and then SIGKILL. Values
// <= 0 select the default.
func WithShutdownGrace(grace time.Duration) Option {
	return func(d *Dialer) {
		d.shutdownGrace = grace
	}
}

// New returns a Dialer with the default environment policy, adjusted by
// opts.
func New(opts ...Option) *Dialer {
	d := &Dialer{
		clientName:    "mcp-gateway",
		inherited:     DefaultInheritedEnv(),
		shutdownGrace: defaultShutdownGrace,
	}
	for _, opt := range opts {
		opt(d)
	}
	if d.shutdownGrace <= 0 {
		d.shutdownGrace = defaultShutdownGrace
	}
	return d
}

// Dial implements [gateway.Dialer]. It spawns spec.Command with spec.Args
// in the environment described by [Dialer.childEnv] and completes the MCP
// initialize handshake with it over stdin/stdout.
//
// ctx bounds the spawn and the handshake only. It deliberately does *not*
// bound the resulting connection's lifetime: the returned [gateway.Upstream]
// outlives the dial, and its child process is killed by Close, not by the
// dial context expiring. (This is why [exec.Command] is used rather than
// [exec.CommandContext] -- the latter would kill the upstream the moment
// the caller cancelled the context it dialed with.)
//
// env is used and then dropped. No value from it reaches a log line, the
// returned Upstream, or any error this function returns.
func (d *Dialer) Dial(ctx context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	if spec.Transport != TransportStdio {
		return nil, fmt.Errorf("%w: upstream %q declares transport %q, this dialer serves %q only",
			ErrUnsupportedTransport, spec.Name, spec.Transport, TransportStdio)
	}
	if spec.Command == "" {
		return nil, fmt.Errorf("%w: upstream %q", ErrNoCommand, spec.Name)
	}

	childEnv, err := d.childEnv(env)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}

	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = childEnv
	// cmd.Stderr is left nil, which connects the child's stderr to the null
	// device. Two independent reasons, either sufficient:
	//
	//  1. An upstream's stderr is outside the MCP protocol and is the single
	//     likeliest place for a sloppy backend to dump its own configuration
	//     -- including the credential this gateway just injected -- on
	//     startup. Capturing that into a buffer the gateway might log, or
	//     splicing it into the gateway's own stderr, would turn a backend's
	//     bad habit into this gateway's leak.
	//  2. os/exec copies a non-*os.File Stderr on a background goroutine for
	//     the whole life of the child, which is both a lifetime to manage
	//     and, if the destination is shared, a data race. lab/probe hit
	//     exactly this and made the same call.

	// captureTransport exists only so the failure path below can reach the
	// connection -- and therefore the process -- that client.Connect opened.
	transport := &captureTransport{
		inner: &mcp.CommandTransport{Command: cmd, TerminateDuration: d.shutdownGrace},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: d.clientName, Version: d.clientVersion}, nil)
	session, connErr := client.Connect(ctx, transport, nil)

	// Drop the gateway's reference to the assembled environment the instant
	// the kernel has it: by now exec has either handed these strings to the
	// child via execve or failed to start at all, and nothing in os/exec
	// reads Cmd.Env after Start. Best-effort defence in depth, in the same
	// spirit as sopsage's zero(): Go strings are immutable so the bytes
	// cannot be scrubbed in place, but dropping the reference means the
	// plaintext is collectable in the next GC cycle instead of being pinned
	// on the Cmd for the entire life of the connection.
	cmd.Env = nil

	if connErr != nil {
		// Reap whatever did start. The SDK closes the connection itself on
		// most handshake failures, and its connection Close is once-guarded,
		// so this is safe to call unconditionally -- but it is not
		// redundant: the SDK has error paths (an unsupported negotiated
		// protocol version, for one) that return without closing, and each
		// of those would otherwise leave a live child behind.
		if conn := transport.connection(); conn != nil {
			_ = conn.Close()
		}
		// The error names the command, not the environment: "what failed",
		// never "with what". spec.Args are omitted for the same reason --
		// this design puts secrets in the environment, but an operator can
		// still put one on a command line, and an error message is not the
		// place to find out.
		return nil, fmt.Errorf("stdio: upstream %q: connect to %q: %w", spec.Name, spec.Command, connErr)
	}

	return &upstream{name: spec.Name, session: session}, nil
}

// childEnv assembles the exact environment the child process will run with:
// the inherited allowlist, read from the gateway's own environment, plus
// every entry of env.
//
// It is built from nothing rather than appended to [os.Environ], and that
// difference is the point of this component. os.Environ() in a gateway
// process can hold the operator's shell history of exports, a CI runner's
// injected tokens, or another upstream's credential resolved for a
// different dial; none of it belongs to this child, and "append to
// os.Environ" is how every one of those ends up in a backend's `/proc/self/environ`.
//
// Entries from env come last on purpose: os/exec de-duplicates Cmd.Env by
// name and keeps the *last* occurrence, so an explicitly injected value
// always beats an inherited one of the same name. That ordering means the
// caller cannot be silently overruled by the gateway's own environment.
//
// The returned slice is the caller's to own and drop; childEnv retains no
// reference to it and the Dialer stores nothing.
func (d *Dialer) childEnv(env map[string]string) ([]string, error) {
	out := make([]string, 0, len(d.inherited)+len(env))
	for _, name := range d.inherited {
		if value, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+value)
		}
	}
	for name, value := range env {
		if err := validateEnvEntry(name, value); err != nil {
			return nil, err
		}
		out = append(out, name+"="+value)
	}
	return out, nil
}

// validateEnvEntry rejects environment entries that would not mean what
// they appear to mean once glued into a "NAME=VALUE" string.
//
// A name containing "=" smuggles a second variable into the child (the name
// "A=B" with value "c" becomes "A=B=c", which most runtimes read as A="B=c"
// -- but a name of "PATH=/tmp/evil\x00OTHER" style is a real trick against
// naive assemblers). A NUL anywhere truncates the entry at the syscall
// boundary. Neither can happen with a well-formed registry row; both are
// cheap to refuse, and refusing means this function's output is always
// exactly as many variables as it has entries.
//
// The error text is written so it cannot echo a secret: a value is never
// quoted, and a malformed *name* is quoted only up to the offending byte --
// because a name containing "=" is, by construction, a name with a value
// glued onto it, and that value may be the credential.
func validateEnvEntry(name, value string) error {
	if name == "" {
		return fmt.Errorf("%w: empty environment variable name", ErrInvalidEnv)
	}
	if i := strings.IndexAny(name, "=\x00"); i >= 0 {
		return fmt.Errorf("%w: environment variable name %q contains a forbidden character", ErrInvalidEnv, name[:i])
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%w: value of environment variable %q contains a NUL byte", ErrInvalidEnv, name)
	}
	return nil
}

// upstream is a live stdio connection to one backend, implementing
// [gateway.Upstream].
//
// It holds the session and the upstream's name -- used only to attribute
// errors -- and nothing else. There is deliberately no field here for the
// environment the child was spawned with: once Dial returns, this side of
// the gateway has no copy of the credential at all.
type upstream struct {
	name    string
	session *mcp.ClientSession

	// closed is checked by ListTools and CallTool so a call after Close
	// fails immediately rather than blocking on a connection that is gone.
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

var _ gateway.Upstream = (*upstream)(nil)

// ListTools implements [gateway.Upstream]. It walks every page of the
// upstream's tools/list.
//
// Pagination is followed rather than truncated at the first page on
// purpose. A tool that the gateway failed to list but would still dispatch
// is precisely the "callable yet invisible" state design/adr/0007 makes
// unrepresentable inside Tool Quarantine; silently dropping page two here
// would recreate it one layer up.
func (u *upstream) ListTools(ctx context.Context) ([]gateway.ToolDef, error) {
	if u.closed.Load() {
		return nil, fmt.Errorf("%w: upstream %q", ErrClosed, u.name)
	}

	var defs []gateway.ToolDef
	for tool, err := range u.session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("stdio: upstream %q: list tools: %w", u.name, err)
		}
		schema, err := rawSchema(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("stdio: upstream %q: tool %q: input schema is not representable as JSON: %w",
				u.name, tool.Name, err)
		}
		defs = append(defs, gateway.ToolDef{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: schema,
		})
	}
	return defs, nil
}

// CallTool implements [gateway.Upstream]. tool is the upstream's own name
// for it, not the namespaced one.
//
// args is forwarded as raw JSON: [json.RawMessage] marshals to itself, so
// the bytes the caller supplied are the bytes on the wire. Empty args are
// left unset so the SDK sends an empty object rather than a literal null,
// which some servers reject.
func (u *upstream) CallTool(ctx context.Context, tool string, args json.RawMessage) (gateway.Result, error) {
	if u.closed.Load() {
		return gateway.Result{}, fmt.Errorf("%w: upstream %q", ErrClosed, u.name)
	}

	params := &mcp.CallToolParams{Name: tool}
	if len(args) > 0 {
		params.Arguments = args
	}

	res, err := u.session.CallTool(ctx, params)
	if err != nil {
		return gateway.Result{}, fmt.Errorf("stdio: upstream %q: call tool %q: %w", u.name, tool, err)
	}

	// A result with no content is rendered as an empty JSON array rather
	// than null, so downstream code can treat Content as "always a JSON
	// array of content blocks" without a special case.
	content := json.RawMessage("[]")
	if len(res.Content) > 0 {
		encoded, err := json.Marshal(res.Content)
		if err != nil {
			return gateway.Result{}, fmt.Errorf("stdio: upstream %q: call tool %q: result content is not representable as JSON: %w",
				u.name, tool, err)
		}
		content = encoded
	}

	return gateway.Result{Content: content, IsError: res.IsError}, nil
}

// Close implements [gateway.Upstream]: it shuts the session down, which
// closes the child's stdin, waits for it to exit, and escalates to SIGTERM
// and then SIGKILL if it does not. When Close returns, the child has been
// waited on -- it is not a zombie.
//
// Close is safe to call more than once and from more than one goroutine;
// repeat calls return the first call's result without touching the process
// again. The closed flag is set *before* the session is torn down so that a
// concurrent ListTools or CallTool fails fast instead of racing a
// half-closed connection.
func (u *upstream) Close() error {
	u.closeOnce.Do(func() {
		u.closed.Store(true)
		if err := u.session.Close(); err != nil {
			u.closeErr = fmt.Errorf("stdio: upstream %q: close: %w", u.name, err)
		}
	})
	return u.closeErr
}

// rawSchema returns a tool's input schema as raw JSON bytes, per
// design/adr/0007: no reformatting, no canonicalization, no key
// reordering of our own. The bytes returned here are hashed by Tool
// Quarantine, so any normalization applied on this path is a change a human
// would never be shown.
//
// Known limitation, recorded because it bounds the guarantee above: the MCP
// SDK decodes a tool's inputSchema into a map[string]any before this
// package ever sees it, so the upstream's literal bytes are already gone by
// this point. What we do here is the single re-marshal of that decoded
// value and nothing more -- but a purely cosmetic change upstream (added
// whitespace, reordered keys) will therefore not move the quarantine hash.
// Closing that gap means reading tools/list off the wire ourselves rather
// than through the SDK; it is not worth doing inside this adapter, and it
// is not something a future reader should assume is already handled.
func rawSchema(schema any) (json.RawMessage, error) {
	switch typed := schema.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		// Already raw: copy so the caller cannot alias SDK-owned memory.
		return bytes.Clone(typed), nil
	case []byte:
		return bytes.Clone(typed), nil
	}
	return json.Marshal(schema)
}

// captureTransport wraps an [mcp.Transport] and remembers the
// [mcp.Connection] it produced.
//
// It exists for one reason: [mcp.Client.Connect] does not hand back the
// connection when the handshake fails, and without a reference to it Dial
// cannot close -- and so cannot reap -- a child that started successfully
// but never completed initialize.
type captureTransport struct {
	inner mcp.Transport

	mu   sync.Mutex
	conn mcp.Connection
}

// Connect implements [mcp.Transport].
func (t *captureTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	return conn, nil
}

// connection returns the connection Connect produced, or nil if the
// transport never connected (in which case there is no child to reap).
func (t *captureTransport) connection() mcp.Connection {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn
}
