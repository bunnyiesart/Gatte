package oci

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// Defaults for the pieces of the invocation that are not the registry
// entry's to choose.
const (
	// defaultPodman is how the container runtime is named on the command
	// line. Left as a bare name so exec resolves it against the gateway's
	// own PATH, exactly as a bare stdio Command is resolved.
	defaultPodman = "podman"

	// networkNone is the network policy an entry gets when it declares
	// none. It is a value of podman's --network flag, not an invention of
	// this package: the container is placed in an empty network namespace
	// with no interface but loopback.
	networkNone = "none"

	// containerNamePrefix marks every container this gateway creates, so
	// an operator sweeping leftovers by hand (design/adr/0028 §D, path 7) can
	// tell ours from anything else the user is running.
	containerNamePrefix = "mcp-gw"

	// innerTransport is the transport of the spec handed to the inner
	// dialer. It must stay equal to stdio.TransportStdio; it is written
	// out rather than imported because the fitness functions forbid one
	// adapter importing another (see the package documentation), and
	// because the value is part of the port's own vocabulary --
	// [gateway.UpstreamSpec.Transport] enumerates it.
	innerTransport = "stdio"
)

// digestPinned matches an image reference pinned to an exact sha256
// digest -- NAME@sha256:<64 lowercase hex>.
//
// This duplicates registry.UpstreamServer.Validate's rule on purpose, and
// the duplication is the control. The registry gate runs when an entry is
// written; this one runs at the instant the container is started, which is
// the only moment that decides which bytes execute. A dialer that trusted
// its caller to have validated would be the "second, less-reviewed path"
// the stdio adapter's ErrUnsupportedTransport comment refuses to build --
// here the cost of not trusting is one regexp
// (design/adr/0028-transporte-oci.md §C).
var digestPinned = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// safeContainerName is podman's own name grammar, narrowed: an initial
// alphanumeric followed by alphanumerics, underscore, dot or dash. The
// narrowing matters because this name is later passed to `podman rm
// --force`; a name that could begin with "-" would be read as a flag by
// that command, and a name carrying whitespace would not round-trip
// through the process table an operator greps.
var safeContainerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// mandatoryWrapper is the part of the podman invocation that is this
// adapter's, not the entry's: emitted on every dial, in this order, with
// no option anywhere in this package to drop or change any of it.
//
// Each flag is here for a reason that is about the credential, not about
// operating containers:
//
//   - --rm, so the container's configuration -- which holds the resolved
//     value in Config.Env while the container exists -- does not outlive
//     the connection (design/adr/0028 §D, path 2).
//   - -i, because stdin is the transport. Never -t: a pty would rewrite
//     the byte stream MCP is framed on.
//   - --log-driver=none, so the backend's stderr keeps going to the null
//     device instead of being captured into journald or a file under the
//     user's container storage. The stdio adapter drops stderr
//     deliberately, calling it "the single likeliest place for a sloppy
//     backend to dump its own configuration"; without this flag the
//     container runtime would quietly undo that decision and persist it
//     (design/adr/0028 §D, decision 3 and path 6).
//   - --pull=never, because there is no OCI registry in this deployment:
//     images are built on the VM and nothing is ever fetched
//     (design/adr/0028 §B). Without it, an image this host does not have
//     sends podman to a public registry at dial time -- a network fetch
//     nobody asked for, on the gateway's critical path, for an artefact
//     that is supposed to exist locally. With it, a digest this host has
//     never built fails immediately and says so.
//   - --read-only and --tmpfs=/tmp, which are design/adr/0028 §B item 3. That
//     ADR is explicit that a read-only root "depende inteiramente da flag
//     de execução" -- it is not a property an image can have -- so this is
//     the only place in the system where that decision can become true.
//     Without it the ADR's Consequences describe a compromised upstream as
//     confined to "um container efêmero, não-root, com raiz somente-leitura"
//     while nothing anywhere emits the flag. The writable path is named
//     explicitly rather than left to podman's --read-only-tmpfs default,
//     for the same reason none of the four above are left to a default:
//     a control that exists because a default currently says so is a
//     control that disappears when the default changes.
//   - --read-only-tmpfs=false, which is what makes the line above TRUE and
//     was missing until 18 Sep 2026. Naming /tmp does not stop podman from
//     adding its own: measured against this exact wrapper, --read-only
//     mounts a writable tmpfs on /run AND on /var/tmp, so the root was
//     read-only except for three paths while the ADR promised one. The
//     contract verifier caught it on all four images at once
//     (deploy/image-contract-verify.sh item 3, "gravavel fora de /tmp sob
//     --read-only: /var/tmp"), which is the first time that script had ever
//     run against a real image. With the flag: /tmp writable, /var/tmp and
//     /run read-only. The paragraph above had the reasoning right and the
//     implementation short -- it disabled nothing, it just also named /tmp.
//   - --cap-drop=all and --security-opt=no-new-privileges, which are
//     design/adr/0034 item 1. A backend speaks MCP over a pipe; it needs no
//     capability at all, and podman's default set (CHOWN, SETUID,
//     NET_BIND_SERVICE, ...) is a set of things a compromised backend could
//     do that it has no reason to. no-new-privileges makes a setuid binary
//     left in an image inert. Neither is configurable: there is no backend
//     for which the answer differs.
//
// The uid and the resource limits are NOT in this list, because their
// values are the operator's ([oci] in the configuration); they are
// emitted by buildPlan from [Limits], on every dial, right after it. An
// entry may not restate them: a restatement that could disagree with the
// configuration would be two sources for one value.
//
// The single-token spelling --tmpfs=/tmp is not cosmetic. wrapperNetwork
// lets an entry restate the wrapper, and it compares whole tokens; a
// two-token "--tmpfs /tmp" would mean a bare "/tmp" had to be an
// acceptable argument anywhere in an entry's Args, which is a hole in the
// closed wrapper opened for a spelling.
//
// These are deliberately NOT read from the entry. An entry may restate
// them (see wrapperNetwork) but cannot omit them: a control that is only
// present when someone remembered to write it down is a control that will
// eventually be missing from one of four rows, with a valid signature over
// its absence.
var mandatoryWrapper = []string{"--rm", "-i", "--log-driver=none", "--pull=never", "--read-only", "--read-only-tmpfs=false", "--tmpfs=/tmp",
	"--cap-drop=all", "--security-opt=no-new-privileges"}

// Limits is the part of the container policy whose values an operator
// sets, in the [oci] section of the configuration (design/adr/0034). Every
// field is emitted on every dial; none of them has a value that means
// "off".
type Limits struct {
	// User is the numeric UID:GID the backend runs as, passed as --user.
	// Always emitted, whatever USER the image declares, so the uid is a
	// fact of this command line rather than a property of the image: an
	// image outside the contract of design/adr/0028 §B item 2 -- USER root,
	// or no USER at all -- still does not run as root. Numeric only: a
	// name is resolved through the image's own /etc/passwd, which the
	// image controls. Neither half may be 0.
	User string
	// PidsLimit is --pids-limit: a fork bomb stops at this many tasks.
	PidsLimit int
	// Memory is --memory, in podman's size syntax: digits and one unit of
	// b, k, m or g, at least 6m (podman's own floor).
	Memory string
	// CPUs is --cpus: the share of CPU time, in cores.
	CPUs float64
}

// DefaultLimits returns the limits a deployment gets when its [oci]
// section says nothing: nobody's uid, and a ceiling one backend cannot
// reach on a small VM without the others noticing. Conservative on
// purpose -- the four lab backends each run in well under half of it.
//
// 65534:65534 is "nobody" everywhere. An image whose files are readable
// only by its own USER (the deployment's images run as 10001) needs
// [oci] user set to that uid; the dial then fails loudly at the first
// open(), which is the direction a wrong uid should fail in.
func DefaultLimits() Limits {
	return Limits{User: "65534:65534", PidsLimit: 256, Memory: "512m", CPUs: 1.0}
}

// withDefaults fills every unset (zero) field of l from [DefaultLimits].
// Only zero is filled: an explicit bad value is left for ValidateLimits to
// refuse, never silently replaced.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.User == "" {
		l.User = d.User
	}
	if l.PidsLimit == 0 {
		l.PidsLimit = d.PidsLimit
	}
	if l.Memory == "" {
		l.Memory = d.Memory
	}
	if l.CPUs == 0 {
		l.CPUs = d.CPUs
	}
	return l
}

// numericUser is UID:GID, both decimal without a leading zero, neither 0.
// The range check is in ValidateLimits.
var numericUser = regexp.MustCompile(`^([1-9][0-9]{0,9}):([1-9][0-9]{0,9})$`)

// podmanSize is podman's --memory syntax, narrowed to whole numbers and
// one lowercase unit.
var podmanSize = regexp.MustCompile(`^([1-9][0-9]{0,12})([bkmg])$`)

// maxID is the largest uid/gid this accepts: 2^32-2, since 2^32-1 is
// (uid_t)-1, "no change", to every setresuid(2).
const maxID = 1<<32 - 2

// minMemory is podman's own floor for --memory.
const minMemory = 6 << 20

// ValidateLimits reports whether l is a container policy this adapter will
// run under. It is the rule buildPlan applies, exported so the
// composition root can refuse to start on it instead of refusing every oci
// dial afterwards.
func ValidateLimits(l Limits) error {
	m := numericUser.FindStringSubmatch(l.User)
	if m == nil {
		return fmt.Errorf("%w: user %q is not a numeric UID:GID with neither half 0 -- a name is resolved by the image's own "+
			"/etc/passwd, and 0 is root (design/adr/0034)", ErrInvalidLimits, l.User)
	}
	for _, id := range m[1:] {
		if n, err := strconv.ParseUint(id, 10, 64); err != nil || n > maxID {
			return fmt.Errorf("%w: user %q is out of range", ErrInvalidLimits, l.User)
		}
	}
	if l.PidsLimit <= 0 {
		return fmt.Errorf("%w: pids limit %d must be positive; there is no value that means unlimited", ErrInvalidLimits, l.PidsLimit)
	}
	if bytes, ok := memoryBytes(l.Memory); !ok || bytes < minMemory {
		return fmt.Errorf("%w: memory %q must be a whole number with one unit of b, k, m or g, at least 6m", ErrInvalidLimits, l.Memory)
	}
	if math.IsNaN(l.CPUs) || math.IsInf(l.CPUs, 0) || l.CPUs <= 0 {
		return fmt.Errorf("%w: cpus %v must be a positive number of cores", ErrInvalidLimits, l.CPUs)
	}
	return nil
}

// memoryBytes parses podmanSize into bytes.
func memoryBytes(size string) (uint64, bool) {
	m := podmanSize.FindStringSubmatch(size)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	shift := map[string]uint{"b": 0, "k": 10, "m": 20, "g": 30}[m[2]]
	if n > math.MaxUint64>>shift {
		return 0, false
	}
	return n << shift, true
}

// limitArgs renders l as the flags buildPlan emits after mandatoryWrapper.
func limitArgs(l Limits) []string {
	return []string{
		"--user=" + l.User,
		"--pids-limit=" + strconv.Itoa(l.PidsLimit),
		"--memory=" + l.Memory,
		"--cpus=" + strconv.FormatFloat(l.CPUs, 'f', -1, 64),
	}
}

// plan is one fully-assembled, not-yet-executed container invocation.
//
// There is no field here capable of holding a credential, and that absence
// is load-bearing in the same way the stdio dialer's is: the plan is what
// gets logged in a debugger, copied into an error, or printed by a future
// `--dry-run`, so the type itself has to be safe to show.
type plan struct {
	// Path is the container runtime binary, as exec will resolve it.
	Path string
	// Args is argv[1:] for that binary: the complete `run` invocation.
	Args []string
	// ContainerName is the --name this dial assigned, kept so Close can
	// address the container directly rather than hoping --rm ran.
	ContainerName string
	// Network is the resolved network policy, after the default was
	// applied. Reported so a caller can attribute a dial to the policy it
	// actually ran under, rather than re-parsing Args.
	Network string
}

// planOptions is the part of a plan that comes from the dialer's
// configuration rather than from the registry entry.
type planOptions struct {
	// Podman is the container runtime binary.
	Podman string
	// ContainerName is the name this dial will give the container. It is
	// an input rather than something buildPlan generates, so that
	// assembling an invocation stays a pure function of its arguments and
	// can be asserted byte for byte in a test.
	ContainerName string
	// Limits is the uid and resource policy. Taken as given: the zero
	// value is refused, not defaulted -- defaults are filled once, by New.
	Limits Limits
}

// buildPlan assembles the exact container invocation for one dial. It is
// the whole of this package's knowledge of podman, and it is a pure
// function: it reads no process state, starts nothing, and returns a value
// whose only effect is what the caller does with it. Everything that can
// be wrong about an invocation is therefore decided before anything runs.
//
// env is read for its *names* and never for its values. Each name becomes
// a bare `--env NAME` on the command line, which instructs podman to read
// that variable from its own process environment -- the environment the
// stdio adapter builds from scratch a moment later -- and copy it into the
// container. The two-token form is the mechanism, not a style choice: the
// alternative spelling, `--env NAME=VALUE`, would move the credential out
// of /proc/<pid>/environ, which only its owner and root can read, and into
// /proc/<pid>/cmdline, which every user on the machine can read
// (design/adr/0028 §D, decision 2 and path 1). buildPlan never copies a value
// out of env, and plan has no field that could hold one.
//
// The order of the names is sorted rather than map order, so that the same
// entry produces the same command line on every dial. An operator diffing
// `ps` output across a restart, or a test asserting an argv, should not
// have to reason about Go's map iteration.
func buildPlan(spec gateway.UpstreamSpec, env map[string]string, opts planOptions) (plan, error) {
	podman := opts.Podman
	if podman == "" {
		podman = defaultPodman
	}
	if !safeContainerName.MatchString(opts.ContainerName) {
		// Refused rather than repaired: this string is an argument to
		// `podman rm --force` later, and the failure mode of a
		// "repaired" name is removing a container that is not ours.
		return plan{}, fmt.Errorf("%w: container name %q is not a safe podman name", ErrInvalidContainerName, opts.ContainerName)
	}
	if err := validateImage(spec.Image); err != nil {
		return plan{}, err
	}
	// Checked here as well as at boot, for the reason digestPinned is: this
	// is the instant that decides what runs, and a uid of 0 is not a thing
	// to trust a caller about.
	if err := ValidateLimits(opts.Limits); err != nil {
		return plan{}, err
	}
	network, err := wrapperNetwork(spec.Args)
	if err != nil {
		return plan{}, err
	}
	names, err := envNames(env)
	if err != nil {
		return plan{}, err
	}

	limits := limitArgs(opts.Limits)
	args := make([]string, 0, 8+len(mandatoryWrapper)+len(limits)+2*len(names))
	args = append(args, "run")
	args = append(args, mandatoryWrapper...)
	args = append(args, limits...)
	args = append(args, "--name", opts.ContainerName)
	args = append(args, "--network="+network)
	for _, name := range names {
		// Two tokens, never "--env NAME=VALUE" and never "--env=NAME":
		// the flag and the bare variable name. See the doc comment above.
		args = append(args, "--env", name)
	}
	// The image goes last, where podman stops reading flags. Anything
	// after it would be argv for the workload, and this package passes
	// none: an oci entry's Args are the signed wrapper (wrapperNetwork),
	// not arguments to the program inside the container.
	args = append(args, spec.Image)

	return plan{Path: podman, Args: args, ContainerName: opts.ContainerName, Network: network}, nil
}

// sweepArgs is the invocation that makes Close's promise checkable:
// remove the container by name, killing it first if it is still running,
// and succeed if it is already gone.
//
// --ignore is what makes the normal case quiet: --rm has usually already
// removed the container by the time this runs, and "no such container" is
// then the expected answer, not a failure. --force covers the case this
// exists for -- a container still alive because the podman client that
// was supervising it was killed. --time=0 makes that kill immediate:
// the graceful path was already tried and already paid for one layer
// down, when stdin was closed and the client was given its grace period,
// so a second stop timeout here would only lengthen every shutdown.
func sweepArgs(containerName string) []string {
	return []string{"rm", "--force", "--ignore", "--time=0", containerName}
}

// validateImage refuses an image reference that does not name exact bytes.
//
// A tag is a mutable pointer: `podman build -t casemgmt-mcp:prod` moves it
// without touching the registry entry and without invalidating the entry's
// signature, so a signature over a tag attests to a name and the name
// resolves to whatever was built last. A digest is the content address,
// and it is the only field of an oci entry that says which code runs --
// Command is empty and the wrapper is identical everywhere
// (design/adr/0028-transporte-oci.md §C).
//
// What this proves and what it does not, stated because the gap is easy to
// oversell: with no OCI registry and no cosign in this deployment, the
// digest proves the bytes are the ones that existed when the operator
// signed the entry. It says nothing about whether those bytes are good.
func validateImage(image string) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("%w: an oci upstream needs an image reference", ErrNoImage)
	}
	if !digestPinned.MatchString(image) {
		return fmt.Errorf("%w: image %q is not pinned to a digest; the form is NAME@sha256:<64 hex> "+
			"(podman inspect --format '{{index .RepoDigests 0}}' NAME:TAG prints it)", ErrUnpinnedImage, image)
	}
	return nil
}

// ValidateWrapperArgs reports whether args are a container wrapper this
// adapter will run. It is exactly the rule the dial applies, exported for
// the same reason [ValidateEnvVarNames] is: an entry whose Args this
// package refuses is refused at every restart, forever, and the console
// that wrote it said "Registered" and then "The gateway will now serve it".
// Both of those were false, and the operator found out at the next boot,
// from a log line, about a decision they made at a prompt.
//
// It returns the error the dial would return, so the console does not
// paraphrase a rule it does not own.
func ValidateWrapperArgs(args []string) error {
	_, err := wrapperNetwork(args)
	return err
}

// wrapperNetwork reads the one policy decision an oci entry is allowed to
// make -- which network its container joins -- out of the entry's Args,
// and defaults it to none.
//
// # Why the policy lives in Args
//
// design/adr/0028 §A requires the network policy to be a field of the
// registry entry, per upstream, covered by the entry's signature, so that
// widening a backend's network is a signed, reviewable diff rather than a
// flag in a provisioning script. Args is that field: it is per entry, it
// is already covered by signer.Canonical, and design/adr/0028 §D decision 3
// writes the wrapper -- --rm, -i, --log-driver=none, --network=none -- as
// living there for exactly this reason. An entry may therefore state the
// wrapper in full, as that ADR spells it; the restated flags are accepted
// here and emitted once, by mandatoryWrapper.
//
// # Why anything else is refused
//
// Args is a free-form list of strings, and splicing it into `podman run`
// unread would put `-v /run/user/N/podman/podman.sock:/...`, --privileged
// and --pid=host one registry edit away from the credential, with an
// operator's attention as the only control. design/adr/0028 §D decision 5
// settled that the runtime socket is never mounted and that adding to the
// wrapper is an amendment to that ADR, not a deployment convenience; a
// closed set is what makes that decision true in code rather than true in
// prose. So an unrecognized flag fails the dial (design/adr/0004: an entry
// this adapter does not fully understand does not run), and adding one is
// a change here, reviewed where the rest of the wrapper is.
//
// The error names the flag but never anything after its "=", for the same
// reason the stdio adapter quotes a malformed variable name only up to the
// offending byte: an operator who has put something in Args that does not
// belong there may well have put a value in it.
func wrapperNetwork(args []string) (string, error) {
	network := ""
	declared := false
	for _, arg := range args {
		if slices.Contains(mandatoryWrapper, arg) {
			// A restatement of what this adapter emits anyway. Accepted so
			// that an entry written exactly as design/adr/0028 §D decision 3
			// spells it works, and dropped so the flag is not emitted
			// twice.
			continue
		}
		value, ok := networkValue(arg)
		if !ok {
			return "", fmt.Errorf("%w: %q is not part of the container wrapper; an oci entry's args may set "+
				"--network=VALUE and may restate %v, nothing else (design/adr/0028 §D decision 5)",
				ErrUnsupportedWrapperFlag, flagOf(arg), mandatoryWrapper)
		}
		if declared {
			return "", fmt.Errorf("%w: the entry declares a network policy more than once", ErrAmbiguousNetwork)
		}
		declared = true
		network = value
	}

	// Absent or empty means no network. The safe value is the one obtained
	// by omission: an entry that says nothing about egress gets none, and
	// an operator who wants a backend to reach the network has to say so
	// in a field that is signed (design/adr/0028 §A decision 3, item 2).
	if strings.TrimSpace(network) == "" {
		return networkNone, nil
	}
	if i := strings.IndexAny(network, " \t\r\n\x00"); i >= 0 {
		// Quoted only up to the offending byte, on the same reasoning as
		// the malformed-name rule below: a policy with whitespace in it is
		// a field somebody put more than one thing into, and the rest of
		// it is not this error's to republish.
		return "", fmt.Errorf("%w: network policy %q runs on past the end of one option token",
			ErrInvalidNetwork, network[:i])
	}
	if strings.HasPrefix(network, "-") {
		return "", fmt.Errorf("%w: network policy %q would be read as a flag, not a network", ErrInvalidNetwork, network)
	}
	// Which non-none values are legitimate is deliberately not decided
	// here. design/adr/0028 §A decision 3, item 3 leaves egress policy to an
	// ADR that does not exist yet, and until it does the four production
	// backends run with a network because they call APIs. An adapter that
	// picked the allowed values would be writing that policy in the wrong
	// file, and writing it where nobody would think to look for it.
	return network, nil
}

// networkValue extracts the value of a --network / --net flag in its
// single-token form. The two-token form ("--network", "none") is not
// accepted: it would make the meaning of an entry's Args depend on
// position, and an off-by-one in a hand-edited registry row would then
// silently change which network a backend joins rather than failing.
func networkValue(arg string) (string, bool) {
	for _, prefix := range []string{"--network=", "--net="} {
		if value, ok := strings.CutPrefix(arg, prefix); ok {
			return value, true
		}
	}
	return "", false
}

// flagOf returns the part of an argument before its first "=", so an error
// can name a rejected flag without echoing whatever was assigned to it.
func flagOf(arg string) string {
	name, _, _ := strings.Cut(arg, "=")
	return name
}

// runtimeDirectingEnvNames and runtimeDirectingEnvPrefixes are the
// variables an oci entry may not name, because they do not configure the
// backend: they configure the container runtime that is about to start it.
//
// The failure they prevent is specific and silent. `podman run` is spawned
// with the allowlist plus this entry's resolved variables -- the map wins
// on a name collision, by design, so that a caller cannot be overruled by
// the gateway's own environment (internal/gateway/stdio, childEnv). The
// removal command in Close is spawned with the allowlist alone, because no
// credential is needed to remove a container. An entry that names
// XDG_RUNTIME_DIR, HOME or CONTAINERS_STORAGE_CONF therefore creates the
// container in one state directory and looks for it in another; `podman rm
// --force --ignore` finds nothing, --ignore makes finding nothing a
// success, and Close returns nil over a live container holding the
// resolved credential in its configuration.
//
// Passing the resolved environment to the removal command would "fix" that
// by putting the credential on a path it is not on today, which is the
// wrong direction. Refusing the names is the fix: a variable that moves the
// runtime's state is not a backend credential, and an entry that declares
// one is not declaring what this field is for.
//
// The list is podman's own knobs, not a general deny-list. It has to be
// revisited whenever the composition root widens the inherited allowlist
// (design/adr/0028 §A anticipates that it must), because that is the other
// half of the same asymmetry.
//
// "_CONTAINERS_" was added 2026-09-24: containers/storage reads its own
// leading-underscore variables (_CONTAINERS_ROOTLESS_UID, _GID,
// _CONTAINERS_USERNS_CONFIGURED) to pick the rootless UID, and with
// XDG_RUNTIME_DIR unset -- as it is under the PATH+HOME allowlist -- derives
// the runtime directory /run/user/<uid> from it. That is the same
// create-here, sweep-there split, one prefix the list had missed.
var (
	runtimeDirectingEnvNames = []string{"HOME", "PATH", "TMPDIR", "TMP", "TEMP"}

	runtimeDirectingEnvPrefixes = []string{"XDG_", "CONTAINERS_", "_CONTAINERS_", "CONTAINER_", "PODMAN_", "STORAGE_"}
)

// The variables the dynamic loader, iconv or an interpreter read as code
// (LD_*, DYLD_*, GCONV_PATH, NODE_OPTIONS, PYTHONSTARTUP, ...) are refused
// too, through [gateway.IsCodeLoadingEnvName]. The entry's resolved map
// becomes the environment of the podman process itself (stdio childEnv)
// and, through --env, of the backend, and both hold every credential of the
// entry; a name on that list would turn an unsigned vault value into code
// in either. The list lived here until 28 Sep 2026 and moved to the port
// package so the stdio adapter applies the same one (design/adr/0034 item
// 3). It keeps this package's sentinel, ErrRuntimeDirectingEnvName.

// ValidateEnvVarNames reports whether every name an entry declares can be
// carried into a container by this adapter. It is the dial-time rule,
// exported so the operator console can apply it when an entry is written
// rather than leaving the first report of a bad one to a refused upstream
// at the next restart.
//
// It is the only thing this package exports that is not the dialer, and it
// exports a rule rather than a mechanism: no container knowledge crosses
// the boundary, only the answer to "would this be refused".
func ValidateEnvVarNames(names []string) error {
	for _, name := range names {
		if err := validateEnvName(name); err != nil {
			return err
		}
	}
	return nil
}

// validateEnvName refuses a name that would not survive the trip to argv
// as exactly one token meaning exactly one variable, or that would steer
// the runtime instead of the backend.
//
// The "=" rule is the second of the two independent barriers
// design/adr/0028 §D path 1 names, and it is the one that matters at the new
// boundary: the registry refuses "=" in EnvVarNames because a KEY=value
// pair must never be stored in the clear, and that same rule now also
// stops a value reaching the command line of the container runtime. The
// rule has two jobs; only one of them is checked where it is written. This
// is the other.
//
// A leading "-" is refused for a different reason: `--env` takes the next
// token as its value, and a "name" that looks like a flag is either a
// mistake or an attempt to smuggle an option into the invocation past the
// closed wrapper.
//
// "*" is refused for a third: podman documents `--env NAME*` -- a bare
// name ending in "*" -- as a prefix match that copies every variable in
// its own environment starting with NAME. That is one token naming an
// unknown number of variables, which is the exact opposite of this
// function's contract, and it would make the argv an entry produces depend
// on what happens to be in the gateway's environment. Nothing stops it
// being abused today only because that environment is built from a short
// allowlist in another package -- a containment this adapter neither owns
// nor was promised.
//
// No value is ever quoted in an error here, and a malformed name is quoted
// only up to the offending byte -- a name containing "=" is, by
// construction, a name with a value glued to it.
func validateEnvName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty environment variable name", ErrInvalidEnvName)
	}
	if i := strings.IndexAny(name, "= \t\r\n\x00"); i >= 0 {
		return fmt.Errorf("%w: environment variable name %q contains a forbidden character",
			ErrInvalidEnvName, name[:i])
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("%w: environment variable name %q looks like a command-line option",
			ErrInvalidEnvName, name)
	}
	if strings.Contains(name, "*") {
		return fmt.Errorf("%w: environment variable name %q contains \"*\", which the container runtime reads as "+
			"a prefix match over its own environment rather than as one variable", ErrInvalidEnvName, name)
	}
	if gateway.IsCodeLoadingEnvName(name) {
		return fmt.Errorf("%w: %q is read as code by the dynamic loader or an interpreter, in the container runtime "+
			"process and in the upstream; an entry that sets it would run an unsigned vault value beside every "+
			"credential of the entry (design/adr/0034)",
			ErrRuntimeDirectingEnvName, name)
	}
	if isRuntimeDirecting(name) {
		return fmt.Errorf("%w: %q configures the container runtime, not the upstream; an entry that sets it would "+
			"start its container under one runtime state directory and be swept under another, so the cleanup would "+
			"report success having removed nothing (design/adr/0028 §D, path 7)", ErrRuntimeDirectingEnvName, name)
	}
	return nil
}

// isRuntimeDirecting reports whether name is one of the container
// runtime's own knobs. Matching is exact for the plain names and by prefix
// for the families, because those families exist precisely so that podman
// can grow another one without asking anybody.
func isRuntimeDirecting(name string) bool {
	return hasNameOrPrefix(name, runtimeDirectingEnvNames, runtimeDirectingEnvPrefixes)
}

// hasNameOrPrefix reports whether name is exactly one of names or starts
// with one of prefixes.
func hasNameOrPrefix(name string, names, prefixes []string) bool {
	if slices.Contains(names, name) {
		return true
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// envNames returns the sorted names of the variables to propagate into the
// container, refusing any name validateEnvName refuses.
func envNames(env map[string]string) ([]string, error) {
	names := make([]string, 0, len(env))
	for name := range env {
		if err := validateEnvName(name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

// newContainerName mints the name one dial's container will be known by:
// the gateway's prefix, the upstream it serves, and 64 bits of randomness.
//
// The randomness is not decoration. The name is what Close later hands to
// `podman rm --force`, so it has to be unique across every dial this
// gateway makes and across whatever else the user is running: a
// predictable name is a container another process can create first, and
// then our cleanup kills theirs while ours survives. crypto/rand for the
// same reason the leak tests use it -- a collision has to be impossible,
// not merely unlikely -- and a failure to read it is a failure to dial
// rather than a fallback to something guessable.
func newContainerName(upstream string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("%w: %v", ErrNoContainerName, err)
	}
	return containerNamePrefix + "-" + sanitizeNameComponent(upstream) + "-" + hex.EncodeToString(buf[:]), nil
}

// sanitizeNameComponent reduces a registered upstream name to characters
// podman accepts in a container name. Collisions it might create are
// harmless -- the random suffix, not this component, is what makes the
// name unique -- so it is a readability measure for `podman ps` and
// nothing more.
func sanitizeNameComponent(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = "upstream"
	}
	return out
}
