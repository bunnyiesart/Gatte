// Command fakepodman is a stand-in for the container runtime, used only by
// the oci dialer's own tests (internal/gateway/oci).
//
// The dialer's job is to turn a registry entry into a command line and to
// make sure the container that command line creates is gone afterwards.
// Testing that against real podman would mean the assertions only run on a
// machine that has podman, rootless, with an image built -- which is to
// say: not in CI, and not on the laptop where the code is written. A
// runtime that is present everywhere and records what it was asked to do
// is what makes those assertions run on every build.
//
// What it emulates, and nothing more:
//
//   - `run`: the flags this adapter emits, the two-token `--env NAME`
//     propagation rule (read NAME from podman's own environment, set it
//     inside the container), `--name`, and the `--rm` lifecycle.
//   - `rm --force --ignore NAME`: remove a container, tolerate its absence.
//   - `image exists REF`: the tri-state probe the dialer runs after a
//     failed dial -- 0 present, 1 absent, anything else "the runtime could
//     not answer". Emulated because the difference between those three is
//     the whole reason that probe exists, and a fixture that could only
//     say "present" would let the two interesting branches rot.
//
// It refuses any flag it does not know, so an adapter that starts emitting
// something new fails these tests instead of silently drifting from what
// the ADRs decided the wrapper is.
//
// Like the stdio adapter's envfixture, it records variable *names* and
// never values. A fixture that wrote values to disk would be a way to
// exfiltrate whatever the test process was holding, and it would poison
// the very leak assertions it exists to support: the injected secret would
// legitimately appear in a recording, and a real leak would be
// indistinguishable from this program doing its job.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Control variables, read from this process's own environment. The dialer
// under test builds that environment from an allowlist, so a test opts in
// to each of these explicitly.
const (
	// stateDirVar names the directory recordings and container markers are
	// written to.
	stateDirVar = "FAKEPODMAN_STATE"
	// workloadVar names the binary to run as the container's process. An
	// empty value means "start nothing and exit successfully", which is
	// how a test produces an image that runs but never speaks MCP.
	workloadVar = "FAKEPODMAN_WORKLOAD"
	// keepVar makes `run` leave its container marker behind despite --rm,
	// emulating the case this adapter exists to handle: a podman client
	// that died before it could remove the container it was supervising.
	keepVar = "FAKEPODMAN_KEEP_CONTAINER"
	// failRemoveVar makes `rm` fail, so the dialer's own failure path can
	// be asserted.
	failRemoveVar = "FAKEPODMAN_RM_FAILS"
	// imageMissingVar makes `image exists` report absence (exit 1).
	imageMissingVar = "FAKEPODMAN_IMAGE_MISSING"
	// imageProbeFailsVar makes `image exists` fail the way a runtime that
	// is not running fails: an exit status that is neither 0 nor 1.
	imageProbeFailsVar = "FAKEPODMAN_IMAGE_PROBE_FAILS"
)

// record is what one `run` invocation writes down. Names only, never
// values -- see the package comment.
type record struct {
	// Argv is this process's whole command line, which is the artefact
	// the leak assertion searches.
	Argv []string `json:"argv"`
	// PodmanEnvNames is what the runtime process itself was spawned with.
	PodmanEnvNames []string `json:"podman_env_names"`
	// ContainerEnvNames is what `--env NAME` propagated into the
	// container.
	ContainerEnvNames []string `json:"container_env_names"`
	Name              string   `json:"name"`
	Image             string   `json:"image"`
	Network           string   `json:"network"`
}

func main() {
	if len(os.Args) < 2 {
		fail("fakepodman: no subcommand")
	}
	switch os.Args[1] {
	case "run":
		os.Exit(run(os.Args[2:]))
	case "rm":
		os.Exit(remove(os.Args[2:]))
	case "image":
		os.Exit(image(os.Args[2:]))
	default:
		fail("fakepodman: unsupported subcommand %q", os.Args[1])
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(64)
}

func stateDir() string {
	dir := os.Getenv(stateDirVar)
	if dir == "" {
		fail("fakepodman: %s is not set", stateDirVar)
	}
	return dir
}

func containerMarker(name string) string {
	return filepath.Join(stateDir(), "containers", name)
}

// run emulates `podman run`. It parses exactly the wrapper the adapter is
// allowed to emit, records it, "creates" the container, and executes the
// workload with the environment podman would have given it.
func run(args []string) int {
	var (
		rec      record
		envNames []string
		rm       bool
		image    string
	)
	rec.Argv = os.Args
	rec.PodmanEnvNames = envNamesOf(os.Environ())

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--rm":
			rm = true
		case arg == "-i", arg == "--log-driver=none", arg == "--pull=never",
			arg == "--read-only", arg == "--read-only-tmpfs=false", arg == "--tmpfs=/tmp":
			// Known and inert for this fixture. --read-only and --tmpfs are
			// the ones this program cannot emulate at all and still has to
			// know: their effect is in the kernel's mount table, not in
			// anything a Go fixture can observe, so what is asserted here is
			// only that the adapter emits them (design/adr/0017 item 3).
		case arg == "--name":
			i++
			if i >= len(args) {
				fail("fakepodman: --name with no value")
			}
			rec.Name = args[i]
		case arg == "--env":
			i++
			if i >= len(args) {
				fail("fakepodman: --env with no value")
			}
			name := args[i]
			if strings.Contains(name, "=") {
				// The property this whole fixture exists to police. Real
				// podman accepts NAME=VALUE here; refusing it means a
				// regression shows up as a failed test rather than as a
				// secret in a process table.
				// Quoted only up to the "=": everything after it is the
				// credential, and this message is written to stderr.
				bare, _, _ := strings.Cut(name, "=")
				fail("fakepodman: --env was given %q with a value glued to it; the adapter must pass a bare name", bare)
			}
			envNames = append(envNames, name)
		case strings.HasPrefix(arg, "--network="):
			rec.Network = strings.TrimPrefix(arg, "--network=")
		case strings.HasPrefix(arg, "-"):
			fail("fakepodman: unknown flag %q", arg)
		default:
			if image != "" {
				fail("fakepodman: two image arguments, %q and %q", image, arg)
			}
			image = arg
		}
	}
	if image == "" {
		fail("fakepodman: no image argument")
	}
	if rec.Name == "" {
		fail("fakepodman: no --name")
	}
	rec.Image = image
	rec.ContainerEnvNames = slices.Clone(envNames)
	slices.Sort(rec.ContainerEnvNames)
	writeRecord(rec)

	marker := containerMarker(rec.Name)
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		fail("fakepodman: %v", err)
	}
	if err := os.WriteFile(marker, []byte(image), 0o600); err != nil {
		fail("fakepodman: %v", err)
	}
	if rm && os.Getenv(keepVar) == "" {
		defer os.Remove(marker)
	}

	return execWorkload(envNames)
}

// execWorkload runs the container's process with the environment podman
// would have built for it: the variables `--env NAME` named, read from
// this process's own environment, plus a PATH standing in for the image's.
// Nothing else of this process's environment crosses, which is the
// behaviour that makes `--env NAME` a propagation rule rather than a
// passthrough.
func execWorkload(envNames []string) int {
	workload := os.Getenv(workloadVar)
	if workload == "" {
		// An image that runs and says nothing: the container starts, the
		// MCP handshake gets EOF, and the dial fails with the container
		// already created.
		return 0
	}

	env := []string{"PATH=/usr/bin:/bin"}
	for _, name := range envNames {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}

	cmd := exec.Command(workload)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	// Stderr is dropped, as the real thing's is under --log-driver=none.
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fail("fakepodman: run workload: %v", err)
	}
	return 0
}

// remove emulates `podman rm --force --ignore --time=0 NAME`.
func remove(args []string) int {
	var (
		name   string
		ignore bool
	)
	for _, arg := range args {
		switch {
		case arg == "--force", arg == "--time=0":
		case arg == "--ignore":
			ignore = true
		case strings.HasPrefix(arg, "-"):
			fail("fakepodman: unknown rm flag %q", arg)
		default:
			name = arg
		}
	}
	if name == "" {
		fail("fakepodman: rm with no container name")
	}

	appendLine(filepath.Join(stateDir(), "rm.log"), name)

	if os.Getenv(failRemoveVar) != "" {
		fmt.Fprintf(os.Stderr, "fakepodman: refusing to remove %q as instructed by %s\n", name, failRemoveVar)
		return 2
	}

	err := os.Remove(containerMarker(name))
	switch {
	case err == nil:
		return 0
	case errors.Is(err, os.ErrNotExist) && ignore:
		return 0
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(os.Stderr, "fakepodman: no container %q\n", name)
		return 1
	default:
		fail("fakepodman: %v", err)
		return 64
	}
}

// image emulates `podman image exists REF`, the only question the dialer
// asks this runtime rather than telling it. Exit 0 means present, 1 means
// absent, and anything else means the runtime could not answer -- which is
// what a rootless service that is not running looks like from outside.
func image(args []string) int {
	if len(args) < 1 || args[0] != "exists" {
		fail("fakepodman: unsupported image subcommand %q", strings.Join(args, " "))
	}
	if len(args) != 2 {
		fail("fakepodman: image exists takes exactly one reference")
	}
	switch {
	case os.Getenv(imageProbeFailsVar) != "":
		// 125 is what podman returns when it cannot do the thing at all,
		// as opposed to doing it and answering "no".
		return 125
	case os.Getenv(imageMissingVar) != "":
		return 1
	default:
		return 0
	}
}

func writeRecord(rec record) {
	encoded, err := json.Marshal(rec)
	if err != nil {
		fail("fakepodman: %v", err)
	}
	path := filepath.Join(stateDir(), "run-"+rec.Name+".json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		fail("fakepodman: %v", err)
	}
	// A stable name too, so a test that does not know the generated
	// container name can still find the last invocation.
	if err := os.WriteFile(filepath.Join(stateDir(), "last-run.json"), encoded, 0o600); err != nil {
		fail("fakepodman: %v", err)
	}
}

func appendLine(path, line string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fail("fakepodman: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		fail("fakepodman: %v", err)
	}
}

// envNamesOf reduces "NAME=VALUE" entries to sorted names, dropping every
// value before it can reach a file.
func envNamesOf(entries []string) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
