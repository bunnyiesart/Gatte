// Package oci is the container adapter for [gateway.Dialer]: it runs a
// backend MCP server as an ephemeral container and speaks MCP to it over
// that container's stdin and stdout.
//
// It is a composition on top of the stdio adapter rather than a second
// implementation of it (design/adr/0028-transporte-oci.md).
// The child process becomes
//
//	podman run --rm -i --log-driver=none --pull=never \
//	           --read-only --read-only-tmpfs=false --tmpfs=/tmp \
//	           --name NAME --network=POLICY \
//	           --env VAR [--env VAR...] IMAGE@sha256:DIGEST
//
// CORRECTION -- 22 Sep 2026. Until today this line omitted
// --read-only, --read-only-tmpfs=false and --tmpfs=/tmp, so the
// package documentation of the adapter that emits design/adr/0028 §B
// item 3 did not mention emitting it. The flags are not optional and
// not new: mandatoryWrapper in invocation.go is the source of truth
// and TestBuildPlanAssemblesTheWrapperInOrder pins this argv token by
// token. --read-only-tmpfs=false is the one that is easy to drop and
// the one that matters most: without it podman mounts its own
// writable /run and /var/tmp beside the /tmp named here, and the root
// is read-only except for three paths -- which is what
// deploy/image-contract-verify.sh caught on all four real images on
// 18 Sep 2026.
//
// and every rule in internal/gateway/stdio's package documentation still
// governs the spawn, because that package still performs it: this dialer
// is constructed with a [gateway.Dialer] and hands it the assembled
// command line. That indirection is not ceremony. The fitness functions in
// internal/fitness make one adapter importing another a build failure
// (design/adr/0001), and the rule is right: stdio is not this package's
// infrastructure, it is its sibling. Depending on the port instead means
// the environment a credential travels in is still built by exactly one
// function in this tree, reviewed once, and a change to it cannot miss
// this path.
//
// Four rules govern everything below.
//
//  1. No secret value ever reaches argv. This is a new rule, not an
//     inherited one, and it exists because this is the first component of
//     this project whose command line is security-relevant:
//     /proc/<pid>/environ is readable by its owner and root, while
//     /proc/<pid>/cmdline is readable by every user on the machine. The
//     mechanism is `--env NAME` with no "=value" -- podman then reads NAME
//     from its own environment, which is the environment the stdio adapter
//     builds from scratch a moment later. argv carries variable names,
//     which the registry already stores in the clear and the entry's
//     signature already covers (design/adr/0028 §D, decision 2).
//
//  2. The wrapper is closed, and the entry cannot open it. The flags in
//     mandatoryWrapper are emitted on every dial with no option to change
//     them, and an entry's Args may set the network policy and restate
//     those flags -- nothing else. An unrecognized flag fails the dial.
//     Splicing an operator-signed string into `podman run` unread is how
//     `-v .../podman.sock:/...` becomes one registry edit from the
//     credential (design/adr/0028 §D, decision 5).
//
//  3. Close kills the container, not merely the client. `podman run` is a
//     supervisor process, so the stdio adapter's third rule -- "Close
//     reaps the child" -- now reaps the wrong thing on its own: a podman
//     killed at the end of its grace period can leave a live container
//     behind, and that container's configuration holds the resolved
//     credential (design/adr/0028 §D, path 7). Close therefore removes the
//     container by name and reports whether that worked. What it does and
//     does not guarantee is written out on [upstream.Close]; read it
//     before relying on it.
//
//  4. The container's identity is a digest, checked here and not only
//     upstream. An image reference that is not pinned to sha256 fails the
//     dial even though the registry refuses to store one, because the
//     instant the container starts is the instant that decides which bytes
//     run (design/adr/0028 §C).
//
// # Residual risk this adapter cannot close
//
// The stdio adapter's residual risk is inherited whole: an upstream that
// holds the credential can echo it back through MCP, in a tool
// description, a result or a handshake error, and nothing here rewrites
// what a backend says. On top of it, the container runtime adds four this
// package cannot close and does not pretend to.
//
// While the container exists, `podman inspect` prints the resolved value
// in Config.Env, and the state behind that is a file under the gateway
// user's container storage rather than a page of kernel memory. Running
// podman rootless keeps the set of readers equal to what could already
// read /proc/<pid>/environ -- the gateway's user and root -- and --rm plus
// rule 3 keep the window equal to the life of the connection, but the
// secret now exists on disk, which it did not before. That is the priced
// loss of this transport (design/adr/0028 §D, path 2).
//
// If the gateway process dies without calling Close -- SIGKILL, OOM, a
// panic in a supervisor -- nothing in this package runs, and the container
// can survive with that state. The answer is a sweep when the unit starts,
// which is deployment and not code (design/adr/0028 §D, path 7).
//
// podman reads ~/.config/containers/containers.conf, found through the
// HOME the child inherits, and no signature covers that file. It can
// change the log driver, the runtime and the log level -- including a
// debug level that prints resolved container configuration. It is the one
// input to a spawn that the entry's signature does not describe
// (design/adr/0028 §D, path 6).
//
// The wrapper carries the container policy the ADRs decided and no more.
// The root filesystem is read-only with one named tmpfs, because
// design/adr/0028 §B item 3 decided that and says in as many words that it is
// a property of the run flags rather than of the image -- so an image
// built to that contract has it only if this package emits it. What the
// wrapper does not do is drop capabilities or pin a seccomp profile beyond
// podman's default: no ADR has decided those, and an adapter is the wrong
// place to invent container policy that operators would then find only by
// reading Go source.
package oci

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// TransportOCI is the only value of [gateway.UpstreamSpec.Transport] this
// dialer serves.
const TransportOCI = "oci"

// Sentinel errors.
var (
	// ErrUnsupportedTransport means the spec asked for a transport this
	// dialer does not implement. Every dialer in this tree refuses the
	// transports it does not serve rather than guessing, so that a
	// misrouted entry fails loudly at dial time instead of being run by
	// whichever adapter happened to be wired.
	ErrUnsupportedTransport = errors.New("oci: unsupported transport")
	// ErrNoImage means an oci spec arrived without an image to run.
	ErrNoImage = errors.New("oci: no image to run")
	// ErrUnpinnedImage means the image reference is not pinned to an
	// exact sha256 digest, so it names a moving pointer rather than
	// bytes.
	ErrUnpinnedImage = errors.New("oci: image is not pinned to a digest")
	// ErrUnsupportedWrapperFlag means the entry's Args hold something
	// this adapter will not place on a podman command line.
	ErrUnsupportedWrapperFlag = errors.New("oci: unsupported wrapper flag")
	// ErrAmbiguousNetwork means the entry declared its network policy
	// more than once, so which one is in force would depend on the order
	// of a list nothing guarantees the order of.
	ErrAmbiguousNetwork = errors.New("oci: ambiguous network policy")
	// ErrInvalidNetwork means the declared network policy is not a single
	// option token.
	ErrInvalidNetwork = errors.New("oci: invalid network policy")
	// ErrNetworkNotAllowed means the declared network policy is one token
	// but not one of the values design/adr/0033 admits: none, slirp4netns,
	// pasta, or a podman network name.
	ErrNetworkNotAllowed = errors.New("oci: network policy outside the allowlist")
	// ErrInvalidEnvName means a variable name could not be written to
	// argv as one token naming one variable -- see validateEnvName.
	ErrInvalidEnvName = errors.New("oci: invalid environment variable name")
	// ErrRuntimeDirectingEnvName means the entry named a variable that
	// configures the container runtime rather than the backend. It is a
	// separate sentinel from ErrInvalidEnvName because the name is
	// well-formed: what is wrong with it is what it would do.
	ErrRuntimeDirectingEnvName = errors.New("oci: environment variable name steers the container runtime")
	// ErrInvalidContainerName means the name chosen for the container
	// would not be safe to hand back to the runtime.
	ErrInvalidContainerName = errors.New("oci: invalid container name")
	// ErrNoContainerName means the system's random source failed, so no
	// unique container name could be minted. A dial without one is
	// refused rather than run under a guessable name.
	ErrNoContainerName = errors.New("oci: cannot mint a container name")
	// ErrContainerNotReaped means Close could not confirm the container
	// is gone. It is the loudest thing this package says, because the
	// state it describes holds the resolved credential.
	ErrContainerNotReaped = errors.New("oci: container may still exist")
	// ErrNoInnerDialer means this dialer was constructed without the
	// dialer that performs the spawn.
	ErrNoInnerDialer = errors.New("oci: no inner dialer")
)

// defaultCleanupGrace bounds the removal command Close runs. It is a
// ceiling on a command that is asked to kill immediately (see sweepArgs),
// not a grace period: the graceful shutdown already happened one layer
// down, when stdin was closed and the client was given its own budget to
// exit. Spending a second grace period here would double the time a
// gateway takes to shut down for no additional chance of a clean exit.
const defaultCleanupGrace = 10 * time.Second

// defaultProbeGrace bounds the one question this package asks the runtime
// that is not an instruction: whether the image exists, asked only after a
// dial has already failed (see imagePresence).
//
// Shorter than the removal's ceiling on purpose. This runs on the boot
// path, once per failed upstream, and its whole value is turning one
// unreadable failure into one of two readable ones; a runtime that cannot
// answer "do you have this image" within five seconds has already answered
// the question the probe was asked.
const defaultProbeGrace = 5 * time.Second

// defaultCleanupEnv is the set of variables the cleanup command inherits
// from the gateway's own environment. It carries no credential -- removing
// a container needs none -- and it is short for the same reason the stdio
// adapter's allowlist is short.
//
// It must be kept equal to the inherited allowlist of the dialer doing the
// spawning, and that coupling is the sharp edge of this file. podman
// rootless locates its own state through the environment; if `podman run`
// can see XDG_RUNTIME_DIR and `podman rm` cannot, the cleanup looks for
// the container in a different state directory, finds nothing, and reports
// success having removed nothing at all. Whatever the composition root
// passes to the spawning dialer's inherited-environment option, it must
// pass to [WithCleanupEnv] as well (design/adr/0028 §A, Consequences).
var defaultCleanupEnv = []string{"PATH", "HOME"}

// DefaultCleanupEnv returns a copy of the variable names the cleanup
// command inherits unless [WithCleanupEnv] says otherwise. It returns a
// copy so a caller reading the policy cannot widen it.
func DefaultCleanupEnv() []string {
	return append([]string(nil), defaultCleanupEnv...)
}

// Dialer runs oci upstreams as ephemeral containers. It implements
// [gateway.Dialer].
//
// It holds the policy for turning an entry into a container invocation and
// the dialer that performs the spawn, and nothing else. In particular it
// holds no credential material, and there is no field on it that could --
// the resolved environment is passed straight through to the inner dialer
// and is never copied, stored or inspected for its values here.
//
// A Dialer is safe for concurrent use.
type Dialer struct {
	inner        gateway.Dialer
	podman       string
	cleanupEnv   []string
	cleanupGrace time.Duration
}

var _ gateway.Dialer = (*Dialer)(nil)

// Option configures a [Dialer].
type Option func(*Dialer)

// WithPodmanPath sets the container runtime binary to exec (default:
// "podman", resolved against the gateway's PATH).
//
// This is a path, not a policy: there is no option in this package that
// changes what the runtime is asked to do. Left configurable because a
// deployment may install podman outside PATH, and because the tests need a
// runtime they can observe.
func WithPodmanPath(path string) Option {
	return func(d *Dialer) {
		if path != "" {
			d.podman = path
		}
	}
}

// WithCleanupEnv replaces the variable names the container-removal command
// inherits from the gateway's environment (default: see
// [DefaultCleanupEnv]). See defaultCleanupEnv for why this has to match
// the spawning dialer's allowlist.
func WithCleanupEnv(names ...string) Option {
	return func(d *Dialer) {
		d.cleanupEnv = append([]string(nil), names...)
	}
}

// WithCleanupGrace bounds the container-removal command Close runs. Values
// <= 0 select the default.
func WithCleanupGrace(grace time.Duration) Option {
	return func(d *Dialer) {
		d.cleanupGrace = grace
	}
}

// New returns a Dialer that assembles container invocations and hands them
// to inner, which performs the spawn and speaks MCP over the resulting
// process's stdin and stdout. In production inner is the stdio dialer,
// wired by cmd/mcp-gateway; this package deliberately cannot name it.
//
// A nil inner panics, here, at wiring time. The alternative is a nil
// dereference or a refused dial at 3am on the first connection of a
// deployment, which is the same bug found later and further from the line
// that caused it.
func New(inner gateway.Dialer, opts ...Option) *Dialer {
	if inner == nil {
		panic("oci.New: " + ErrNoInnerDialer.Error() + " (wire it with the stdio dialer in cmd/mcp-gateway)")
	}
	d := &Dialer{
		inner:        inner,
		podman:       defaultPodman,
		cleanupEnv:   DefaultCleanupEnv(),
		cleanupGrace: defaultCleanupGrace,
	}
	for _, opt := range opts {
		opt(d)
	}
	if d.cleanupGrace <= 0 {
		d.cleanupGrace = defaultCleanupGrace
	}
	return d
}

// Dial implements [gateway.Dialer]. It assembles the container invocation
// for spec, spawns it through the inner dialer with env, and returns an
// upstream whose Close also removes the container.
//
// ctx bounds the spawn and the handshake only, exactly as it does one
// layer down: the returned upstream outlives the dial, and its container
// is removed by Close rather than by this context expiring.
//
// env is used and then dropped. Only its keys are read here -- they become
// `--env NAME` -- and no value from it reaches the assembled command line,
// a log line, the returned upstream, or any error this function returns.
func (d *Dialer) Dial(ctx context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	if spec.Transport != TransportOCI {
		return nil, fmt.Errorf("%w: upstream %q declares transport %q, this dialer serves %q only",
			ErrUnsupportedTransport, spec.Name, spec.Transport, TransportOCI)
	}

	containerName, err := newContainerName(spec.Name)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}
	p, err := buildPlan(spec, env, planOptions{Podman: d.podman, ContainerName: containerName})
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}

	// The inner dialer is handed a stdio spec because that is what it is:
	// a process to spawn and talk to over a pipe. It builds the child's
	// environment from its own allowlist plus env, which is precisely the
	// environment `--env NAME` reads from.
	inner, err := d.inner.Dial(ctx, gateway.UpstreamSpec{
		Name:      spec.Name,
		Transport: innerTransport,
		Command:   p.Path,
		Args:      p.Args,
	}, env)
	if err != nil {
		// The handshake can fail after the container is running -- an
		// image whose entrypoint is not an MCP server is the ordinary
		// case -- and the inner dialer kills the client without knowing
		// there is a container behind it. Sweep before returning, or a
		// backend that fails to start leaks one container per retry, each
		// holding the credential in its configuration.
		sweepErr := d.sweep(p.ContainerName)
		// The error names the image, which is a content address and never
		// a secret, and the network policy, because "it dialed but cannot
		// reach anything" is the first question an operator asks. It does
		// not quote the assembled command line: that is this package's
		// output, not the failure, and printing it on every dial error is
		// how a command line ends up in a ticket.
		//
		// It also names whether this host has the image, because without
		// that the message is unreadable. Under stdio a failed spawn came
		// back as an operating-system error with a meaning in it -- "no
		// such file or directory", "permission denied". Under oci the
		// runtime binary always exists and always execs, so a missing
		// image, a rootless service that is not up, a denied mount and a
		// backend that is not an MCP server all arrive here as EOF and an
		// exit status, and they need four different repairs.
		wrapped := fmt.Errorf("oci: upstream %q: run %s (network=%s): %s: %w",
			spec.Name, spec.Image, p.Network, d.imagePresence(spec.Image), err)
		if sweepErr != nil {
			return nil, errors.Join(wrapped, sweepErr)
		}
		return nil, wrapped
	}

	if inner == nil {
		// A Dialer that returns neither a connection nor an error is
		// broken, and this package is handed whichever one the
		// composition root wired. Refusing here, after sweeping, turns
		// that into a dial failure instead of a nil dereference on the
		// first call -- and, more to the point, instead of a container
		// nobody holds a reference to.
		sweepErr := d.sweep(p.ContainerName)
		broken := fmt.Errorf("oci: upstream %q: the inner dialer returned no connection and no error", spec.Name)
		if sweepErr != nil {
			return nil, errors.Join(broken, sweepErr)
		}
		return nil, broken
	}

	return &upstream{
		Upstream:      inner,
		name:          spec.Name,
		containerName: p.ContainerName,
		sweep:         d.sweep,
	}, nil
}

// sweep removes the container by name, forcing it dead if it is still
// running and treating "no such container" as success.
//
// It runs with an environment built from the cleanup allowlist and nothing
// else: no credential is needed to remove a container, so none is present
// on this path at all.
func (d *Dialer) sweep(containerName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.cleanupGrace)
	defer cancel()

	cmd := exec.CommandContext(ctx, d.podman, sweepArgs(containerName)...)
	cmd.Env = d.cleanupEnvironment()
	// Output() collects stdout and stderr rather than letting them reach
	// the gateway's own streams; both are then discarded, see below.
	if _, err := cmd.Output(); err != nil {
		// The runtime's own output is deliberately not quoted. `podman rm`
		// reads the container's configuration, and that configuration
		// holds the resolved credential in Config.Env: a runtime error
		// that dumped the spec it was working on would become this
		// gateway's log line. What an operator needs is here without it --
		// which container, and the command to run by hand.
		//
		// A timeout is named as one, because it and a refusal call for
		// different repairs and exec reports the first as "signal:
		// killed", which reads like the second.
		detail := err.Error()
		if ctx.Err() != nil {
			detail += ", after " + d.cleanupGrace.String()
		}
		return fmt.Errorf("%w: upstream container %q was not removed (%s); "+
			"remove it by hand: podman rm --force --ignore %s",
			ErrContainerNotReaped, containerName, detail, containerName)
	}
	return nil
}

// imagePresence asks the runtime whether this host has the image, and
// renders the answer as a clause for a dial error. It is called only after
// a dial has already failed, never on the path that works.
//
// `podman image exists REF` is the whole probe: it prints nothing, it
// takes no configuration of the container, and its exit status is the
// tri-state that matters -- 0 the image is here, 1 it is not, anything
// else the runtime could not answer at all. That third case is the one
// worth the subprocess: "podman is not up for this user" and "this image
// was never built here" look identical from inside a failed handshake and
// are repaired in completely different places.
//
// It runs with the cleanup environment for the same reason the removal
// does -- no credential is needed to ask this, so none is present on this
// path -- and it discards the runtime's own output for the same reason
// too: `podman image exists` is quiet, but a runtime that decided to
// explain itself would be explaining about an image spec, and this string
// goes into a log line.
func (d *Dialer) imagePresence(image string) string {
	ctx, cancel := context.WithTimeout(context.Background(), defaultProbeGrace)
	defer cancel()

	cmd := exec.CommandContext(ctx, d.podman, "image", "exists", image)
	cmd.Env = d.cleanupEnvironment()
	if _, err := cmd.Output(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return "this host does not have that image (nothing is ever pulled: --pull=never, design/adr/0028 §B), so build it or check the digest"
		}
		// Not "the image is missing": the runtime did not say that, and
		// guessing here is how an operator spends an afternoon rebuilding
		// an image that was always there while podman was not running.
		detail := err.Error()
		if ctx.Err() != nil {
			detail += ", after " + defaultProbeGrace.String()
		}
		return "could not ask the container runtime whether this host has that image (" + detail +
			"), so the runtime itself may be the failure -- check that podman is working for this user"
	}
	return "this host does have that image, so the failure is after the container started"
}

// cleanupEnvironment builds the environment for the removal command: the
// allowlist, read from the gateway's own environment, and nothing else.
// Built from nothing rather than appended to [os.Environ] for the same
// reason the stdio adapter builds a child environment from nothing -- the
// gateway's own environment may hold another upstream's credential, and a
// podman subprocess has no business seeing it.
func (d *Dialer) cleanupEnvironment() []string {
	out := make([]string, 0, len(d.cleanupEnv))
	for _, name := range d.cleanupEnv {
		if value, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+value)
		}
	}
	return out
}

// upstream is a live connection to one backend running in a container.
//
// It embeds the connection the inner dialer returned and adds exactly one
// thing: the container's lifetime. ListTools and CallTool are the inner
// upstream's, unwrapped and unmodified -- a decorator that re-implemented
// them would be a second place for MCP results to be reshaped, and
// design/adr/0007 and 0014 both depend on there being only one.
//
// There is no field here for the environment the container was spawned
// with, for the same reason there is none one layer down.
type upstream struct {
	gateway.Upstream

	name          string
	containerName string
	// sweep removes the container. It is a function rather than a
	// reference to the Dialer so that this type cannot reach anything else
	// of the dialer's.
	sweep func(containerName string) error

	closeOnce sync.Once
	closeErr  error
}

var _ gateway.Upstream = (*upstream)(nil)

// Close shuts the session down and then removes the container.
//
// # What this guarantees
//
// When Close returns nil: the connection was closed, the podman client
// process was waited on and is not a zombie, and `podman rm --force
// --ignore` returned success for this container's name -- meaning that at
// that instant the runtime *this command reached* held no container under
// that name, running or exited. Since the container is what holds the
// resolved credential in its configuration, that state is gone too.
//
// "The runtime this command reached" is the precise claim, not a hedge.
// podman rootless finds its own state through the environment, and the
// removal runs with the cleanup allowlist while the container was created
// with that allowlist plus the entry's resolved variables. An entry that
// named a variable steering the runtime would therefore be swept in a
// different state directory from the one it was started in, and --ignore
// turns "not here" into success. That is why validateEnvName refuses those
// names outright: it is the only way this sentence can be about the same
// runtime twice.
//
// The removal runs even when the session teardown reports an error, and
// both errors are returned joined. Skipping the removal because the
// session misbehaved would abandon a container in exactly the case that
// most likely produced one.
//
// Close is safe to call more than once and from more than one goroutine;
// repeat calls return the first call's result without touching the
// container again.
//
// # What this does not guarantee
//
// It does not guarantee anything if Close is never called. A gateway that
// is SIGKILLed, OOM-killed or panics past its shutdown path leaves
// whatever podman left; the container and its configuration can survive,
// and the answer is a sweep when the unit starts (design/adr/0028 §D, path 7).
//
// It does not guarantee removal when the error is non-nil. The error names
// the container and the command to remove it by hand precisely because
// this package cannot finish the job for an operator whose container
// runtime is not answering.
//
// It does not guarantee anything about a container this gateway did not
// name. The removal is by the name minted at dial time, so a runtime that
// ignored --name, or a second gateway on the same host, is outside what
// this can see.
//
// And it is not a security boundary against the workload. It removes a
// container; it does not follow a process that escaped one.
func (u *upstream) Close() error {
	u.closeOnce.Do(func() {
		var sessionErr error
		if err := u.Upstream.Close(); err != nil {
			sessionErr = fmt.Errorf("oci: upstream %q: close: %w", u.name, err)
		}
		if err := u.sweep(u.containerName); err != nil {
			u.closeErr = errors.Join(sessionErr, fmt.Errorf("oci: upstream %q: %w", u.name, err))
			return
		}
		u.closeErr = sessionErr
	})
	return u.closeErr
}
