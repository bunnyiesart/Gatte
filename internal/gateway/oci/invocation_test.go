package oci

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// These tests are about the command line and nothing else. Assembling an
// invocation is a pure function precisely so that the properties that
// matter -- no value in argv, a closed wrapper, a network policy that
// defaults to none -- can be asserted on every build, on a machine with no
// container runtime installed. The tests that need a runtime live in
// oci_test.go and use a fixture.

// testImage is a realistic reference for an image built on the VM: no
// registry host, pinned to a digest.
const testImage = "localhost/casemgmt-mcp@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// testContainerName stands in for what newContainerName mints, so the
// assembled argv is comparable byte for byte.
const testContainerName = "mcp-gw-casemgmt-0123456789abcdef"

// newSecret returns a fresh, unpredictable value. crypto/rand rather than
// math/rand for the same reason the stdio adapter's tests use it: a leak
// assertion only means something if the value it searches for could not
// have appeared by coincidence.
func newSecret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	return hex.EncodeToString(buf)
}

func ociSpec() gateway.UpstreamSpec {
	return gateway.UpstreamSpec{Name: "casemgmt", Transport: TransportOCI, Image: testImage}
}

func testOptions() planOptions {
	return planOptions{Podman: "podman", ContainerName: testContainerName}
}

func TestBuildPlanAssemblesTheWrapperInOrder(t *testing.T) {
	p, err := buildPlan(ociSpec(), map[string]string{
		"MOCK_SECRET":      "s",
		"CASEMGMT_API_KEY": "k",
	}, testOptions())
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}

	want := []string{
		"run", "--rm", "-i", "--log-driver=none", "--pull=never",
		// design/adr/0028 §B item 3, which is a run flag and nothing else:
		// an image cannot have a read-only root, only be run with one.
		// --read-only-tmpfs=false is what keeps podman from adding its own
		// writable /run and /var/tmp beside the /tmp named here; without it
		// the root is read-only except for three paths, which the contract
		// verifier caught on all four real images on 18 Sep 2026.
		"--read-only", "--read-only-tmpfs=false", "--tmpfs=/tmp",
		"--name", testContainerName,
		"--network=none",
		// Sorted, not in map order: the same entry has to produce the same
		// command line on every dial.
		"--env", "CASEMGMT_API_KEY",
		"--env", "MOCK_SECRET",
		testImage,
	}
	if !slices.Equal(p.Args, want) {
		t.Errorf("argv =\n %v\nwant\n %v", p.Args, want)
	}
	if p.Path != "podman" {
		t.Errorf("path = %q, want podman", p.Path)
	}
	if p.ContainerName != testContainerName {
		t.Errorf("container name = %q, want %q", p.ContainerName, testContainerName)
	}
	if p.Network != networkNone {
		t.Errorf("network = %q, want %q", p.Network, networkNone)
	}
	// The image is last: anything after it would be argv for the workload,
	// and an entry does not get to supply that.
	if p.Args[len(p.Args)-1] != testImage {
		t.Errorf("image is not the last argument: %v", p.Args)
	}
}

// TestBuildPlanNeverWritesASecretValueToTheCommandLine is the reason this
// package assembles argv in a pure function at all.
//
// /proc/<pid>/environ is readable by its owner and root;
// /proc/<pid>/cmdline is readable by every user on the machine. A value
// that moves from the first to the second has left the narrowest
// compartment this project has for the widest one the system offers
// (design/adr/0028 §D, path 1). The check is a property over the whole
// command line rather than a comparison with an expected string, so an
// argv that grows a new flag cannot pass by accident.
func TestBuildPlanNeverWritesASecretValueToTheCommandLine(t *testing.T) {
	secrets := map[string]string{
		"CASEMGMT_API_KEY": newSecret(t),
		"LOGSEARCH_TOKEN":  newSecret(t),
		// A value shaped like the things that do belong on a command line:
		// if anything ever interpolates a value, this is the one most
		// likely to slip through a human's eye in a diff.
		"LOOKALIKE": "--network=" + newSecret(t),
	}

	p, err := buildPlan(ociSpec(), secrets, testOptions())
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}

	line := strings.Join(append([]string{p.Path}, p.Args...), " ")
	for name, value := range secrets {
		if strings.Contains(line, value) {
			// The command line itself is not printed: it holds the value,
			// and a CI log is exactly where that must not go.
			t.Errorf("LEAK: the value of %s appears in the assembled command line", name)
		}
	}

	// The names, by contrast, must be there: they are what podman reads
	// from its own environment, and they are not secret -- the registry
	// stores them in the clear and the entry's signature covers them.
	for name := range secrets {
		if !slices.Contains(p.Args, name) {
			t.Errorf("variable name %q is missing from argv, so podman would not propagate it", name)
		}
	}
}

// TestEveryEnvFlagCarriesABareName pins the mechanism itself, as a
// property over argv: design/adr/0028 §D's Compliance item 1.
func TestEveryEnvFlagCarriesABareName(t *testing.T) {
	p, err := buildPlan(ociSpec(), map[string]string{
		"CASEMGMT_API_KEY": newSecret(t),
		"MOCK_SECRET":      newSecret(t),
	}, testOptions())
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}

	var seen int
	for i, arg := range p.Args {
		if arg != "--env" {
			continue
		}
		seen++
		if i+1 >= len(p.Args) {
			t.Fatalf("--env is the last argument, with nothing after it: %v", p.Args)
		}
		value := p.Args[i+1]
		if strings.Contains(value, "=") {
			// Quoted only up to the "=": what follows it in a failing
			// run is the credential, and this message goes to a CI log.
			name, _, _ := strings.Cut(value, "=")
			t.Errorf("--env was given %q with a value glued to it; it must be a bare variable name", name)
		}
		if strings.HasPrefix(value, "-") {
			t.Errorf("--env was given %q, which podman would read as a flag", value)
		}
	}
	if seen != 2 {
		t.Errorf("found %d --env flags, want 2", seen)
	}
	// The single-token spelling would also keep the value out of argv, but
	// it is not what design/adr/0028 §D decision 2 wrote down, and the
	// deployment check that greps process lines was written against the
	// two-token form.
	if strings.Contains(strings.Join(p.Args, " "), "--env=") {
		t.Errorf("argv uses the --env=NAME spelling: %v", p.Args)
	}
}

func TestBuildPlanRefusesEnvNamesThatWouldNotSurviveArgv(t *testing.T) {
	secret := newSecret(t)

	cases := []struct {
		name string
		key  string
	}{
		// The one that matters: a KEY=value pair passed as a name would
		// become "--env TOKEN=<secret>" -- the value in the process table.
		{"name carrying a value", "TOKEN=" + secret},
		{"name that looks like a flag", "-v"},
		{"name with a space", "CASEMGMT KEY"},
		{"name with a tab", "CASEMGMT\tKEY"},
		{"name with a NUL", "CASEMGMT\x00KEY"},
		{"empty name", ""},
		// podman reads a trailing "*" on a bare --env name as a prefix
		// match over its own environment, so this token names an unknown
		// number of variables rather than one.
		{"name that is a glob", "CASEMGMT_*"},
		{"name that is only a glob", "*"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildPlan(ociSpec(), map[string]string{tc.key: secret}, testOptions())
			if err == nil {
				t.Fatalf("buildPlan accepted the environment variable name %q", tc.key)
			}
			if !errors.Is(err, ErrInvalidEnvName) {
				t.Errorf("error = %v, want ErrInvalidEnvName", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("LEAK: the rejection quoted the value glued onto the malformed name")
			}
		})
	}
}

// TestBuildPlanRefusesEnvNamesThatSteerTheContainerRuntime is about the
// one way a container can survive a Close that reported success.
//
// The container is created by a process whose environment is the allowlist
// plus this entry's resolved variables, with the map winning on a
// collision; it is removed by a process whose environment is the allowlist
// alone. A name like XDG_RUNTIME_DIR or HOME therefore puts `podman run`
// and `podman rm` in two different state directories, and --ignore turns
// "no such container" into exit 0 -- so Close returns nil over a live
// container whose configuration holds the resolved credential.
func TestBuildPlanRefusesEnvNamesThatSteerTheContainerRuntime(t *testing.T) {
	secret := newSecret(t)

	for _, name := range []string{
		"HOME", "PATH", "TMPDIR", "TMP", "TEMP",
		"XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
		"CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF",
		"CONTAINER_HOST", "PODMAN_CONNECTIONS_CONF", "STORAGE_DRIVER",
		"_CONTAINERS_ROOTLESS_UID", "_CONTAINERS_USERNS_CONFIGURED",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "GCONV_PATH", "DYLD_INSERT_LIBRARIES",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildPlan(ociSpec(), map[string]string{name: secret}, testOptions())
			if err == nil {
				t.Fatalf("buildPlan accepted %q, which configures the runtime rather than the upstream", name)
			}
			if !errors.Is(err, ErrRuntimeDirectingEnvName) {
				t.Errorf("error = %v, want ErrRuntimeDirectingEnvName", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("LEAK: the rejection quoted the resolved value")
			}
			// A well-formed name refused for what it would do, not for how
			// it is spelled: conflating the two would send an operator
			// looking for a typo.
			if errors.Is(err, ErrInvalidEnvName) {
				t.Error("a runtime-directing name is reported as a malformed name")
			}
		})
	}

	// The control: an ordinary backend credential, which has to stay
	// acceptable or the rule above would be a rule against everything.
	if _, err := buildPlan(ociSpec(), map[string]string{"CASEMGMT_API_KEY": secret}, testOptions()); err != nil {
		t.Errorf("buildPlan refused an ordinary credential name: %v", err)
	}
}

// TestValidateEnvVarNamesIsTheSameRuleTheDialApplies guards the exported
// half. The console calls it so a bad entry is refused where it is written
// rather than at every restart afterwards; if the two could drift, the
// console would be paraphrasing a rule it does not own, which is worse
// than not checking at all.
func TestValidateEnvVarNamesIsTheSameRuleTheDialApplies(t *testing.T) {
	for _, name := range []string{"XDG_RUNTIME_DIR", "CASEMGMT_*", "-v", "A=B", ""} {
		if err := ValidateEnvVarNames([]string{name}); err == nil {
			t.Errorf("ValidateEnvVarNames accepted %q", name)
		}
		if _, err := buildPlan(ociSpec(), map[string]string{name: "x"}, testOptions()); err == nil {
			t.Errorf("buildPlan accepted %q", name)
		}
	}
	if err := ValidateEnvVarNames([]string{"CASEMGMT_URL", "CASEMGMT_API_KEY"}); err != nil {
		t.Errorf("ValidateEnvVarNames refused ordinary names: %v", err)
	}
}

// TestValidateWrapperArgsIsTheSameRuleTheDialApplies: same argument, for
// the flag half. An entry carrying "-v /run/podman.sock:/..." is refused
// at every dial forever, so the console has no business printing
// "Registered" and "The gateway will now serve it" over it.
func TestValidateWrapperArgsIsTheSameRuleTheDialApplies(t *testing.T) {
	bad := [][]string{
		{"-v", "/run/user/1000/podman/podman.sock:/run/podman.sock"},
		{"--privileged"},
		{"--network=none", "--network=host"},
		{"--network=host"},
		{"--net=container:other"},
	}
	for _, args := range bad {
		if err := ValidateWrapperArgs(args); err == nil {
			t.Errorf("ValidateWrapperArgs accepted %v", args)
		}
		spec := ociSpec()
		spec.Args = args
		if _, err := buildPlan(spec, nil, testOptions()); err == nil {
			t.Errorf("buildPlan accepted %v", args)
		}
	}
	for _, args := range [][]string{nil, {"--network=slirp4netns"}, mandatoryWrapper} {
		if err := ValidateWrapperArgs(args); err != nil {
			t.Errorf("ValidateWrapperArgs refused %v: %v", args, err)
		}
	}
}

func TestBuildPlanDefaultsToNoNetwork(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--network="}, {"--rm", "-i"}} {
		spec := ociSpec()
		spec.Args = args

		p, err := buildPlan(spec, nil, testOptions())
		if err != nil {
			t.Fatalf("buildPlan(args=%v): %v", args, err)
		}
		if p.Network != networkNone {
			t.Errorf("buildPlan(args=%v) network = %q, want %q", args, p.Network, networkNone)
		}
		// Exactly once: two --network flags mean two networks to podman.
		var count int
		for _, arg := range p.Args {
			if strings.HasPrefix(arg, "--network=") {
				count++
			}
		}
		if count != 1 {
			t.Errorf("buildPlan(args=%v) emitted %d --network flags, want 1: %v", args, count, p.Args)
		}
	}
}

// TestBuildPlanCarriesTheDeclaredNetworkPolicy: a value inside the
// allowlist of design/adr/0033 reaches argv exactly as declared and is
// reported as the plan's policy.
func TestBuildPlanCarriesTheDeclaredNetworkPolicy(t *testing.T) {
	cases := map[string]string{
		"--network=none":          "none",
		"--network=slirp4netns":   "slirp4netns",
		"--network=pasta":         "pasta",
		"--net=pasta":             "pasta",
		"--network=upstreams-net": "upstreams-net",
		"--network=lab_net.0":     "lab_net.0",
	}

	for arg, want := range cases {
		spec := ociSpec()
		spec.Args = []string{arg}

		p, err := buildPlan(spec, nil, testOptions())
		if err != nil {
			t.Fatalf("buildPlan(args=[%s]): %v", arg, err)
		}
		if p.Network != want {
			t.Errorf("buildPlan(args=[%s]) network = %q, want %q", arg, p.Network, want)
		}
		if !slices.Contains(p.Args, "--network="+want) {
			t.Errorf("buildPlan(args=[%s]) argv lacks --network=%s: %v", arg, want, p.Args)
		}
	}
}

// TestBuildPlanRefusesANetworkOutsideTheAllowlist: design/adr/0033. host
// shares the gateway's own network namespace, loopback included; container:,
// ns: and private join namespaces this adapter did not create; an option
// after ':' (slirp4netns:allow_host_loopback=true, pasta:--map-gw) reopens
// the host from inside the namespace; a '/' is a path, not a network name.
func TestBuildPlanRefusesANetworkOutsideTheAllowlist(t *testing.T) {
	for _, arg := range []string{
		"--network=host",
		"--net=host",
		"--network=container:mcp-gw-other",
		"--network=ns:/proc/1/ns/net",
		"--network=private",
		"--network=slirp4netns:allow_host_loopback=true",
		"--network=pasta:--map-gw",
		"--network=a/b",
		"--network=Upstreams",
		"--network=_net",
		"--network=.",
		"--network=" + strings.Repeat("a", 64),
	} {
		spec := ociSpec()
		spec.Args = []string{arg}

		_, err := buildPlan(spec, nil, testOptions())
		if err == nil {
			t.Errorf("buildPlan accepted %q", arg)
			continue
		}
		if !errors.Is(err, ErrNetworkNotAllowed) {
			t.Errorf("buildPlan(args=[%q]) error = %v, want ErrNetworkNotAllowed", arg, err)
		}
		if err := ValidateWrapperArgs(spec.Args); !errors.Is(err, ErrNetworkNotAllowed) {
			t.Errorf("ValidateWrapperArgs(%q) = %v, want ErrNetworkNotAllowed", arg, err)
		}
	}
	// 63 characters is the longest name the grammar admits.
	spec := ociSpec()
	spec.Args = []string{"--network=" + strings.Repeat("a", 63)}
	if _, err := buildPlan(spec, nil, testOptions()); err != nil {
		t.Errorf("buildPlan refused a 63-character network name: %v", err)
	}
}

// TestNetworkRefusalQuotesOnlyTheRejectedHead: the wrapper never echoes
// what comes after a flag's '='. A refused network is quoted only up to its
// first ':', '/' or '=', which is the part the rule judges; the options or
// path behind it are not the error's to republish (register, sign, the dial
// log and network_error in `upstream list -json` all carry this text).
func TestNetworkRefusalQuotesOnlyTheRejectedHead(t *testing.T) {
	for arg, secret := range map[string]string{
		"--network=slirp4netns:allow_host_loopback=true": "allow_host_loopback",
		"--network=ns:/proc/1/ns/net":                    "/proc/1/ns/net",
		"--network=container:mcp-gw-other":               "mcp-gw-other",
		"--network=a/sekrit":                             "sekrit",
		"--network=--opt=sekrit":                         "sekrit",
	} {
		_, err := ResolveNetwork([]string{arg})
		if err == nil {
			t.Errorf("ResolveNetwork accepted %q", arg)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("ResolveNetwork(%q) error republishes %q: %v", arg, secret, err)
		}
	}
}

// TestResolveNetworkIsThePolicyTheDialRuns: `upstream list -json` reports
// an entry's network from this function, so it must be the value buildPlan
// puts on argv, default included.
func TestResolveNetworkIsThePolicyTheDialRuns(t *testing.T) {
	for _, args := range [][]string{nil, {"--network=pasta"}, {"--rm", "--net=upstreams-net"}} {
		spec := ociSpec()
		spec.Args = args
		p, err := buildPlan(spec, nil, testOptions())
		if err != nil {
			t.Fatalf("buildPlan(args=%v): %v", args, err)
		}
		got, err := ResolveNetwork(args)
		if err != nil {
			t.Fatalf("ResolveNetwork(%v): %v", args, err)
		}
		if got != p.Network {
			t.Errorf("ResolveNetwork(%v) = %q, dial runs %q", args, got, p.Network)
		}
	}
	if _, err := ResolveNetwork([]string{"--network=host"}); !errors.Is(err, ErrNetworkNotAllowed) {
		t.Errorf("ResolveNetwork(host) = %v, want ErrNetworkNotAllowed", err)
	}
}

// TestBuildPlanAcceptsTheWrapperRestatedByTheEntry: design/adr/0028 §D
// decision 3 writes the minimal wrapper as living in the entry's Args. An
// entry written exactly that way has to work, and has to produce the same
// command line as one that leaves the wrapper to the adapter -- not a
// command line with every flag twice.
func TestBuildPlanAcceptsTheWrapperRestatedByTheEntry(t *testing.T) {
	bare, err := buildPlan(ociSpec(), nil, testOptions())
	if err != nil {
		t.Fatalf("buildPlan(no args): %v", err)
	}

	restated := ociSpec()
	restated.Args = []string{"--rm", "-i", "--log-driver=none", "--pull=never", "--read-only", "--read-only-tmpfs=false", "--tmpfs=/tmp", "--network=none"}
	full, err := buildPlan(restated, nil, testOptions())
	if err != nil {
		t.Fatalf("buildPlan(wrapper restated): %v", err)
	}

	if !slices.Equal(bare.Args, full.Args) {
		t.Errorf("restating the wrapper changed the command line:\n got %v\nwant %v", full.Args, bare.Args)
	}
}

// TestBuildPlanRefusesFlagsOutsideTheWrapper is the closed-wrapper rule.
// An entry is signed by an operator, and an adapter that spliced a signed
// string into `podman run` unread would put container escape one registry
// edit away, with that operator's attention as the only control
// (design/adr/0028 §D decision 5).
func TestBuildPlanRefusesFlagsOutsideTheWrapper(t *testing.T) {
	cases := []string{
		"-v", "/run/user/1000/podman/podman.sock:/run/podman.sock",
		"--privileged",
		"--pid=host",
		"--user=0",
		"--log-driver=journald",
		"--pull=always",
		"--entrypoint=/bin/sh",
		"--env",
		// The two-token network spelling: refused so that the meaning of
		// an entry's args never depends on position.
		"--network",
		"none",
		"",
	}

	for _, arg := range cases {
		spec := ociSpec()
		spec.Args = []string{arg}

		_, err := buildPlan(spec, nil, testOptions())
		if err == nil {
			t.Errorf("buildPlan accepted %q in an entry's args", arg)
			continue
		}
		if !errors.Is(err, ErrUnsupportedWrapperFlag) {
			t.Errorf("buildPlan(args=[%q]) error = %v, want ErrUnsupportedWrapperFlag", arg, err)
		}
	}
}

// TestWrapperRejectionNamesTheFlagAndNotItsValue: an operator who put
// something in Args that does not belong there may well have put a value
// in it, so the refusal quotes up to the "=" and no further -- the same
// rule the stdio adapter applies to a malformed variable name.
func TestWrapperRejectionNamesTheFlagAndNotItsValue(t *testing.T) {
	secret := newSecret(t)
	spec := ociSpec()
	spec.Args = []string{"--secret-file=" + secret}

	_, err := buildPlan(spec, nil, testOptions())
	if err == nil {
		t.Fatal("buildPlan accepted an unknown flag")
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("LEAK: the rejection echoed what was assigned to the flag")
	}
	if !strings.Contains(err.Error(), "--secret-file") {
		t.Errorf("the rejection does not name the flag it refused: %v", err)
	}
}

func TestBuildPlanRefusesAnImageThatIsNotPinnedToADigest(t *testing.T) {
	cases := []struct {
		name  string
		image string
		want  error
	}{
		{"empty", "", ErrNoImage},
		{"blank", "   ", ErrNoImage},
		{"tag", "localhost/casemgmt-mcp:prod", ErrUnpinnedImage},
		{"bare name", "localhost/casemgmt-mcp", ErrUnpinnedImage},
		{"digest punctuation without a digest", "localhost/casemgmt-mcp@sha256:latest", ErrUnpinnedImage},
		{"truncated digest", "localhost/casemgmt-mcp@sha256:9f86d081", ErrUnpinnedImage},
		{"uppercase digest", "localhost/casemgmt-mcp@sha256:" + strings.ToUpper(strings.TrimPrefix(testImage, "localhost/casemgmt-mcp@sha256:")), ErrUnpinnedImage},
		{"other algorithm", "localhost/casemgmt-mcp@sha512:" + strings.Repeat("a", 64), ErrUnpinnedImage},
		{"digest with no name", "@sha256:" + strings.Repeat("a", 64), ErrUnpinnedImage},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := ociSpec()
			spec.Image = tc.image

			_, err := buildPlan(spec, nil, testOptions())
			if err == nil {
				t.Fatalf("buildPlan accepted image %q", tc.image)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}

	// And the shape that must be accepted, so the test above cannot pass
	// by refusing everything.
	if _, err := buildPlan(ociSpec(), nil, testOptions()); err != nil {
		t.Errorf("buildPlan refused a digest-pinned image: %v", err)
	}
}

func TestBuildPlanRefusesAnAmbiguousNetworkPolicy(t *testing.T) {
	spec := ociSpec()
	spec.Args = []string{"--network=none", "--network=host"}

	_, err := buildPlan(spec, nil, testOptions())
	if err == nil {
		t.Fatal("buildPlan accepted two network policies")
	}
	if !errors.Is(err, ErrAmbiguousNetwork) {
		t.Errorf("error = %v, want ErrAmbiguousNetwork", err)
	}
}

func TestBuildPlanRefusesANetworkPolicyThatIsNotOneToken(t *testing.T) {
	for _, arg := range []string{"--network=host --privileged", "--network=-v", "--network=a\tb"} {
		spec := ociSpec()
		spec.Args = []string{arg}

		_, err := buildPlan(spec, nil, testOptions())
		if err == nil {
			t.Errorf("buildPlan accepted %q", arg)
			continue
		}
		if !errors.Is(err, ErrInvalidNetwork) {
			t.Errorf("buildPlan(args=[%q]) error = %v, want ErrInvalidNetwork", arg, err)
		}
	}
}

// TestBuildPlanIsDeterministic: Go randomizes map iteration, so an
// unsorted implementation passes a single run of every other test here and
// still produces a different command line on each dial. That would defeat
// an operator diffing `ps` output across a restart, and it would make the
// deployment check that greps for the wrapper flaky rather than wrong.
func TestBuildPlanIsDeterministic(t *testing.T) {
	env := map[string]string{
		"A_TOKEN": "1", "B_TOKEN": "2", "C_TOKEN": "3", "D_TOKEN": "4", "E_TOKEN": "5",
	}

	first, err := buildPlan(ociSpec(), env, testOptions())
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	for range 50 {
		again, err := buildPlan(ociSpec(), env, testOptions())
		if err != nil {
			t.Fatalf("buildPlan: %v", err)
		}
		if !slices.Equal(first.Args, again.Args) {
			t.Fatalf("two identical entries produced different command lines:\n %v\n %v", first.Args, again.Args)
		}
	}
}

func TestBuildPlanRefusesAnUnsafeContainerName(t *testing.T) {
	for _, name := range []string{"", "-f", "has space", "has/slash", "has\x00nul", "-"} {
		opts := testOptions()
		opts.ContainerName = name

		_, err := buildPlan(ociSpec(), nil, opts)
		if err == nil {
			t.Errorf("buildPlan accepted container name %q, which is later an argument to `podman rm --force`", name)
			continue
		}
		if !errors.Is(err, ErrInvalidContainerName) {
			t.Errorf("buildPlan(name=%q) error = %v, want ErrInvalidContainerName", name, err)
		}
	}
}

func TestNewContainerNameIsSafeAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		// A registered name that is nothing like a container name: the
		// sanitizer, not the caller, is responsible for the result being
		// usable.
		name, err := newContainerName("casemgmt/teste node:1")
		if err != nil {
			t.Fatalf("newContainerName: %v", err)
		}
		if !safeContainerName.MatchString(name) {
			t.Fatalf("minted an unsafe container name: %q", name)
		}
		if !strings.HasPrefix(name, containerNamePrefix+"-") {
			t.Fatalf("container name %q does not carry the gateway prefix, so an operator sweeping leftovers cannot tell it is ours", name)
		}
		if seen[name] {
			t.Fatalf("newContainerName repeated %q; a shared name means one dial's cleanup kills another's container", name)
		}
		seen[name] = true
	}
}

func TestSweepArgsAddressesTheContainerByName(t *testing.T) {
	args := sweepArgs("mcp-gw-casemgmt-deadbeef")

	want := []string{"rm", "--force", "--ignore", "--time=0", "mcp-gw-casemgmt-deadbeef"}
	if !slices.Equal(args, want) {
		t.Errorf("sweepArgs = %v, want %v", args, want)
	}
	// --ignore is what makes the ordinary case quiet: --rm has usually
	// already removed the container, and its absence is then success.
	if !slices.Contains(args, "--ignore") {
		t.Error("sweepArgs without --ignore turns every clean shutdown into a reported failure")
	}
	// --force is what makes the case this exists for work at all.
	if !slices.Contains(args, "--force") {
		t.Error("sweepArgs without --force cannot remove a container that is still running")
	}
}

// TestNoTypeInThisPackageCanHoldAResolvedEnvironment is the structural
// half of rule 2 in the package documentation. The stdio adapter's
// guarantee rests on there being no field on its dialer or its upstream
// able to hold the credential; this package adds two types on the same
// path and must not be where that changes.
func TestNoTypeInThisPackageCanHoldAResolvedEnvironment(t *testing.T) {
	envMap := reflect.TypeOf(map[string]string{})

	check := func(label string, typ reflect.Type) {
		if typ.NumField() == 0 {
			t.Fatalf("%s has no fields; this test would pass vacuously", label)
		}
		for i := range typ.NumField() {
			field := typ.Field(i)
			if field.Type == envMap {
				t.Errorf("%s has field %q of type map[string]string: the resolved environment is passed "+
					"through to the inner dialer and must not be storable here", label, field.Name)
			}
			lower := strings.ToLower(field.Name)
			for _, bad := range []string{"secret", "token", "credential", "password"} {
				if strings.Contains(lower, bad) {
					t.Errorf("%s has field %q, whose name contains %q", label, field.Name, bad)
				}
			}
		}
	}

	check("oci.Dialer", reflect.TypeOf(Dialer{}))
	check("oci.upstream", reflect.TypeOf(upstream{}))
	check("oci.plan", reflect.TypeOf(plan{}))
	check("oci.planOptions", reflect.TypeOf(planOptions{}))

	// A canary, so the detector cannot rot into a no-op if it is ever
	// "simplified".
	type canary struct{ Env map[string]string }
	if reflect.TypeOf(canary{}).Field(0).Type != envMap {
		t.Fatal("the detector no longer recognizes a resolved environment")
	}
}
