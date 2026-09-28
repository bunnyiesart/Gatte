package oci

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/gateway/stdio"
	"github.com/bunnyiesart/Gatte/lab/mockutil"
)

// These tests dial through the real stdio adapter into a real child
// process, with a fixture standing in for the container runtime. The
// composition is the thing under test: this package's whole claim is that
// it adds a container's lifetime to a spawn it does not perform itself, so
// a test that mocked the spawn away would be testing the claim's less
// interesting half.
//
// The fixture is not there to make the tests convenient. It is there so
// the assertions run on a laptop and in CI, neither of which has podman,
// rootless, with an image built -- which is where a control that only runs
// on the production VM quietly stops running at all.

// fixtureBinaries holds the compiled fixtures, built once in TestMain.
//
//   - fakepodman is this package's container runtime stand-in
//     (testdata/fakepodman).
//   - casemgmt is the lab's fake CASEMGMT upstream (lab/servers/casemgmt), used
//     unmodified as the program inside the "container": it implements the
//     <name>_credcheck convention, which is how a test can ask the backend
//     whether the credential actually arrived.
var fixtureBinaries struct {
	fakepodman string
	casemgmt   string
}

func TestMain(m *testing.M) {
	os.Exit(func() int {
		tmp, err := os.MkdirTemp("", "oci-fixtures-")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(tmp)

		build := func(name, pkg string) string {
			out := filepath.Join(tmp, name)
			if combined, err := exec.Command("go", "build", "-o", out, pkg).CombinedOutput(); err != nil {
				panic("build " + pkg + ": " + err.Error() + "\n" + string(combined))
			}
			return out
		}

		fixtureBinaries.fakepodman = build("fakepodman", "./testdata/fakepodman")
		fixtureBinaries.casemgmt = build("casemgmt", "../../../lab/servers/casemgmt")

		return m.Run()
	}())
}

// testTimeout bounds every dial and call so a wedged fixture fails the
// test instead of hanging the suite.
const testTimeout = 30 * time.Second

// controlEnv are the variables the runtime fixture reads to know what to
// record and how to behave. They travel the same way a deployment's
// XDG_RUNTIME_DIR would: named on the spawning dialer's inherited
// allowlist and on this dialer's cleanup allowlist, which is exactly the
// pairing defaultCleanupEnv warns has to be kept in step.
var controlEnv = []string{
	"PATH", "HOME",
	"FAKEPODMAN_STATE", "FAKEPODMAN_WORKLOAD", "FAKEPODMAN_KEEP_CONTAINER", "FAKEPODMAN_RM_FAILS",
	"FAKEPODMAN_IMAGE_MISSING", "FAKEPODMAN_IMAGE_PROBE_FAILS",
}

// state is one test's private container runtime: a directory the fixture
// records into and "creates" containers in.
type state struct{ dir string }

// newState points the fixture at a fresh directory and gives it the lab
// casemgmt server as the program to run inside the container.
func newState(t *testing.T) state {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FAKEPODMAN_STATE", dir)
	t.Setenv("FAKEPODMAN_WORKLOAD", fixtureBinaries.casemgmt)
	return state{dir: dir}
}

// lastRun reads back what the fixture recorded for the most recent `run`.
func (s state) lastRun(t *testing.T) record {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, "last-run.json"))
	if err != nil {
		t.Fatalf("no container was run: %v", err)
	}
	var rec record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode fixture recording: %v", err)
	}
	return rec
}

func (s state) ranAnything() bool {
	_, err := os.Stat(filepath.Join(s.dir, "last-run.json"))
	return err == nil
}

func (s state) containerExists(name string) bool {
	_, err := os.Stat(filepath.Join(s.dir, "containers", name))
	return err == nil
}

// removalsRequested returns the container names the dialer asked the
// runtime to remove, in order.
func (s state) removalsRequested(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, "rm.log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read removal log: %v", err)
	}
	return strings.FieldsFunc(string(raw), func(r rune) bool { return r == '\n' })
}

// record mirrors the fixture's recording. It is redeclared here rather
// than shared with the fixture because testdata is not an importable
// package -- and, less accidentally, because a test that agreed with the
// fixture by construction would not notice the fixture changing shape.
type record struct {
	Argv              []string `json:"argv"`
	PodmanEnvNames    []string `json:"podman_env_names"`
	ContainerEnvNames []string `json:"container_env_names"`
	Name              string   `json:"name"`
	Image             string   `json:"image"`
	Network           string   `json:"network"`
}

// newDialer wires this package the way cmd/mcp-gateway will have to: the
// oci dialer in front, the stdio dialer performing the spawn.
func newDialer(t *testing.T, opts ...Option) *Dialer {
	t.Helper()
	inner := stdio.New(stdio.WithInheritedEnv(controlEnv...))
	opts = append([]Option{WithPodmanPath(fixtureBinaries.fakepodman), WithCleanupEnv(controlEnv...)}, opts...)
	return New(inner, opts...)
}

// dial dials spec and registers Close as a cleanup, failing the test if
// either reports a problem.
func dial(t *testing.T, d *Dialer, spec gateway.UpstreamSpec, env map[string]string) gateway.Upstream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := d.Dial(ctx, spec, env)
	if err != nil {
		t.Fatalf("Dial(%q): %v", spec.Name, err)
	}
	t.Cleanup(func() {
		if err := up.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	return up
}

// firstText decodes the first text content block of a result.
func firstText(t *testing.T, res gateway.Result) string {
	t.Helper()
	var blocks []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(res.Content, &blocks); err != nil {
		t.Fatalf("decode result content %s: %v", res.Content, err)
	}
	if len(blocks) == 0 {
		t.Fatalf("result had no content blocks: %s", res.Content)
	}
	return blocks[0].Text
}

// TestTheCredentialReachesTheContainerThroughTheEnvironmentAndNotArgv is
// the end-to-end statement of the mechanism this transport rests on
// (design/adr/0028 §D decision 2): the command line names variables, the
// environment carries their values, and the backend gets what it needs.
//
// All three halves are asserted at once on purpose. "The secret is not in
// argv" is satisfied by an adapter that never passes the secret at all,
// and "the backend got the secret" is satisfied by one that puts it on the
// command line; only together do they describe the design.
func TestTheCredentialReachesTheContainerThroughTheEnvironmentAndNotArgv(t *testing.T) {
	st := newState(t)
	secret := newSecret(t)

	// A variable in the gateway's own environment that nobody put on an
	// allowlist. It must not reach the runtime, let alone the container:
	// the environment is built, never inherited, and routing the spawn
	// through another dialer must not have quietly changed that.
	sentinel := "OCI_DIALER_SENTINEL_" + strings.ToUpper(newSecret(t)[:8])
	t.Setenv(sentinel, newSecret(t))

	up := dial(t, newDialer(t), ociSpec(), map[string]string{
		"MOCK_SECRET": secret,
		"MOCK_EXPECT": secret,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := up.CallTool(ctx, "casemgmt_credcheck", nil)
	if err != nil {
		t.Fatalf("CallTool(casemgmt_credcheck): %v", err)
	}
	var check mockutil.CredCheckResult
	if err := json.Unmarshal([]byte(firstText(t, res)), &check); err != nil {
		t.Fatalf("decode credcheck result: %v", err)
	}
	if !check.ReceivedExpectedSecret {
		t.Errorf("received_expected_secret = false (fingerprint %s): --env NAME did not propagate the value into the container",
			check.Fingerprint)
	}

	rec := st.lastRun(t)
	for _, arg := range rec.Argv {
		if strings.Contains(arg, secret) {
			t.Error("LEAK: the secret appeared in the container runtime's command line")
		}
	}
	if !slices.Equal(rec.ContainerEnvNames, []string{"MOCK_EXPECT", "MOCK_SECRET"}) {
		t.Errorf("container environment = %v, want exactly [MOCK_EXPECT MOCK_SECRET]", rec.ContainerEnvNames)
	}
	if !slices.Contains(rec.PodmanEnvNames, "MOCK_SECRET") {
		t.Error("the runtime process did not hold MOCK_SECRET, so --env NAME had nothing to read")
	}
	if slices.Contains(rec.PodmanEnvNames, sentinel) {
		t.Errorf("the runtime process inherited %s from the gateway; the environment was not built from scratch", sentinel)
	}
	// Tightest form of the same statement: the runtime's environment is
	// the allowlist that exists plus what the Vault resolved, and nothing
	// else.
	want := []string{"MOCK_SECRET", "MOCK_EXPECT"}
	for _, name := range controlEnv {
		if _, ok := os.LookupEnv(name); ok {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	if !slices.Equal(rec.PodmanEnvNames, want) {
		t.Errorf("runtime environment = %v, want exactly %v", rec.PodmanEnvNames, want)
	}

	if rec.Network != networkNone {
		t.Errorf("container ran with network %q, want %q -- an entry that declares no policy gets no network", rec.Network, networkNone)
	}
	if rec.Image != testImage {
		t.Errorf("container ran image %q, want %q", rec.Image, testImage)
	}
}

// TestCloseRemovesAContainerTheRuntimeLeftBehind is rule 3. The fixture is
// told to leave its container in place despite --rm, which is what a
// podman killed at the end of its grace period does (design/adr/0028 §D, path
// 7); Close has to notice that the client dying is not the same as the
// container dying.
func TestCloseRemovesAContainerThatOutlivedItsClient(t *testing.T) {
	st := newState(t)
	t.Setenv("FAKEPODMAN_KEEP_CONTAINER", "1")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := newDialer(t).Dial(ctx, ociSpec(), map[string]string{"MOCK_SECRET": newSecret(t)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	name := st.lastRun(t).Name
	if !st.containerExists(name) {
		t.Fatalf("the fixture did not leave container %q behind; this test would pass vacuously", name)
	}

	if err := up.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if st.containerExists(name) {
		t.Errorf("container %q survived Close: its configuration still holds the resolved credential", name)
	}
	if !slices.Contains(st.removalsRequested(t), name) {
		t.Errorf("Close did not ask the runtime to remove %q", name)
	}
}

// TestCloseIsIdempotent: the gateway closes upstreams from more than one
// path (refresh, shutdown, a failed call), and a second Close that
// re-ran the removal would at best waste a spawn and at worst report a
// failure for a container it had already removed itself.
func TestCloseIsIdempotentAndSweepsOnce(t *testing.T) {
	st := newState(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := newDialer(t).Dial(ctx, ociSpec(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := up.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := up.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if got := st.removalsRequested(t); len(got) != 1 {
		t.Errorf("the runtime was asked to remove %d times (%v), want exactly 1", len(got), got)
	}

	// After Close, calls must fail rather than block on a connection that
	// is gone. The upstream inherits that from the session it embeds; the
	// assertion is here because this package is what callers hold.
	if _, err := up.ListTools(ctx); err == nil {
		t.Error("ListTools after Close returned no error")
	}
	if _, err := up.CallTool(ctx, "casemgmt_credcheck", nil); err == nil {
		t.Error("CallTool after Close returned no error")
	}
}

// TestCloseReportsAContainerItCouldNotRemove: the one thing worse than a
// leftover container holding a credential is a leftover container holding
// a credential that nothing reported.
func TestCloseReportsAContainerItCouldNotRemove(t *testing.T) {
	st := newState(t)
	t.Setenv("FAKEPODMAN_RM_FAILS", "1")
	secret := newSecret(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := newDialer(t).Dial(ctx, ociSpec(), map[string]string{"MOCK_SECRET": secret})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	name := st.lastRun(t).Name

	err = up.Close()
	if err == nil {
		t.Fatal("Close reported success although the container was not removed")
	}
	if !errors.Is(err, ErrContainerNotReaped) {
		t.Errorf("error = %v, want ErrContainerNotReaped", err)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("the error does not name the container an operator has to clean up: %v", err)
	}
	if !strings.Contains(err.Error(), "podman rm --force --ignore") {
		t.Errorf("the error does not say how to remove it by hand: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("LEAK: the cleanup failure quoted the environment")
	}
	// The runtime's own output is not quoted: `podman rm` reads a
	// container configuration that holds the resolved credential, and a
	// runtime error that dumped what it was working on would become this
	// gateway's log line.
	if strings.Contains(err.Error(), "refusing to remove") {
		t.Errorf("the error repeats the container runtime's output: %v", err)
	}
}

// TestAFailedHandshakeLeavesNoContainerBehind: an image whose entrypoint
// is not an MCP server is the ordinary way this fails in production, and
// it fails after the container is already running. Without a sweep on this
// path, a backend that cannot start leaks one container per retry, each
// one holding the credential in its configuration.
func TestAFailedHandshakeLeavesNoContainerBehind(t *testing.T) {
	st := newState(t)
	// An image that runs and says nothing.
	t.Setenv("FAKEPODMAN_WORKLOAD", "")
	t.Setenv("FAKEPODMAN_KEEP_CONTAINER", "1")
	secret := newSecret(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := newDialer(t).Dial(ctx, ociSpec(), map[string]string{"MOCK_SECRET": secret})
	if err == nil {
		_ = up.Close()
		t.Fatal("Dial succeeded against an image that never speaks MCP")
	}
	if up != nil {
		t.Errorf("Dial returned a non-nil Upstream alongside an error: %#v", up)
	}

	name := st.lastRun(t).Name
	if st.containerExists(name) {
		t.Errorf("container %q survived a failed dial", name)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("LEAK: the dial failure quoted the environment")
	}
	// The failure names what an operator needs to act: which image, and
	// under which network policy it was run.
	if !strings.Contains(err.Error(), testImage) {
		t.Errorf("the dial failure does not name the image: %v", err)
	}
	if !strings.Contains(err.Error(), "network=none") {
		t.Errorf("the dial failure does not name the network policy: %v", err)
	}
}

// TestADialFailureSaysWhetherThisHostHasTheImage is the readability of the
// most likely day-one failure on the new VM.
//
// Under stdio a spawn that failed came back as an operating-system error
// with a meaning in it. Under oci the runtime binary always exists and
// always execs, so an image that was never built here, a rootless service
// that is not running, and a backend that is not an MCP server all arrive
// as EOF and an exit status -- and they are repaired in three different
// places. The probe splits the three, so the three readings are what this
// test pins.
func TestADialFailureSaysWhetherThisHostHasTheImage(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T)
		wants   string
		unwants string
	}{
		{
			name:    "image is present, so the failure is inside the container",
			setup:   func(t *testing.T) {},
			wants:   "does have that image",
			unwants: "does not have that image",
		},
		{
			name:    "image was never built on this host",
			setup:   func(t *testing.T) { t.Setenv("FAKEPODMAN_IMAGE_MISSING", "1") },
			wants:   "does not have that image",
			unwants: "could not ask",
		},
		{
			name:  "the runtime itself cannot answer",
			setup: func(t *testing.T) { t.Setenv("FAKEPODMAN_IMAGE_PROBE_FAILS", "1") },
			wants: "could not ask the container runtime",
			// The one thing this case must never say: a runtime that did
			// not answer has not told us the image is missing, and an
			// afternoon rebuilding an image that was always there is the
			// cost of guessing.
			unwants: "does not have that image",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newState(t)
			// An image that runs and says nothing, so the dial always
			// fails and the probe always runs.
			t.Setenv("FAKEPODMAN_WORKLOAD", "")
			tc.setup(t)
			secret := newSecret(t)

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			up, err := newDialer(t).Dial(ctx, ociSpec(), map[string]string{"MOCK_SECRET": secret})
			if err == nil {
				_ = up.Close()
				t.Fatal("Dial succeeded against an image that never speaks MCP")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the dial failure does not say %q: %v", tc.wants, err)
			}
			if strings.Contains(err.Error(), tc.unwants) {
				t.Errorf("the dial failure says %q, which it cannot know: %v", tc.unwants, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("LEAK: the dial failure quoted the environment")
			}
		})
	}
}

// TestTheContainerRunsWithAReadOnlyRoot: design/adr/0028 §B item 3 says in as
// many words that a read-only root "depende inteiramente da flag de
// execução", and its Consequences describe a compromised upstream as
// confined to one. Nothing in an image can deliver that, so this adapter
// is the only place it can be true -- and for a while it was true nowhere,
// with the ADR still claiming it. The assertion is on the recorded argv of
// a real spawn rather than on buildPlan, because what the ADR promises is
// about the container that ran.
func TestTheContainerRunsWithAReadOnlyRoot(t *testing.T) {
	st := newState(t)
	up := dial(t, newDialer(t), ociSpec(), map[string]string{"MOCK_SECRET": newSecret(t)})
	_ = up

	argv := st.lastRun(t).Argv
	for _, want := range []string{"--read-only", "--read-only-tmpfs=false", "--tmpfs=/tmp"} {
		if !slices.Contains(argv, want) {
			t.Errorf("the container was not run with %s (design/adr/0028 §B item 3): %v", want, argv)
		}
	}
}

func TestDialRejectsANonOCITransport(t *testing.T) {
	st := newState(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	for _, transport := range []string{"stdio", "http", "", "OCI"} {
		spec := ociSpec()
		spec.Transport = transport

		up, err := newDialer(t).Dial(ctx, spec, nil)
		if err == nil {
			_ = up.Close()
			t.Errorf("Dial(transport=%q) succeeded, want rejection", transport)
			continue
		}
		if !errors.Is(err, ErrUnsupportedTransport) {
			t.Errorf("Dial(transport=%q) error = %v, want ErrUnsupportedTransport", transport, err)
		}
	}
	if st.ranAnything() {
		t.Error("a rejected transport still started a container")
	}
}

// TestDialRefusesAnUnpinnedImageBeforeRunningAnything: the registry
// refuses to store one, so reaching this check means something bypassed
// the registry -- which is exactly when a second check earns its keep. The
// assertion that matters is that nothing ran.
func TestDialRefusesAnUnpinnedImageBeforeRunningAnything(t *testing.T) {
	st := newState(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	spec := ociSpec()
	spec.Image = "localhost/casemgmt-mcp:latest"

	if _, err := newDialer(t).Dial(ctx, spec, nil); !errors.Is(err, ErrUnpinnedImage) {
		t.Errorf("error = %v, want ErrUnpinnedImage", err)
	}
	if st.ranAnything() {
		t.Error("an unpinned image was run anyway")
	}
}

// fakeInnerDialer records what the oci dialer handed down, without
// spawning anything.
type fakeInnerDialer struct {
	spec gateway.UpstreamSpec
	env  map[string]string
	// returnNothing makes it break its contract: no connection and no
	// error.
	returnNothing bool
}

func (d *fakeInnerDialer) Dial(_ context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	d.spec = spec
	d.env = env
	if d.returnNothing {
		return nil, nil
	}
	return nil, errors.New("fake inner dialer does not spawn")
}

// TestTheInnerDialerIsHandedAProcessAndTheSameEnvironmentMap pins the
// composition itself.
//
// The identity check on the map is not pedantry. internal/gateway resolves
// the credential, dials, and clears the map on the way out; an adapter
// that copied it would leave a second copy of the plaintext alive with
// nothing to clear it, which is the failure the clear() one layer up
// exists to prevent.
func TestTheInnerDialerIsHandedAProcessAndTheSameEnvironmentMap(t *testing.T) {
	st := newState(t)
	inner := &fakeInnerDialer{}
	d := New(inner, WithPodmanPath(fixtureBinaries.fakepodman), WithCleanupEnv(controlEnv...))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	env := map[string]string{"MOCK_SECRET": newSecret(t)}
	if _, err := d.Dial(ctx, ociSpec(), env); err == nil {
		t.Fatal("Dial succeeded although the inner dialer refused")
	}

	if inner.spec.Transport != "stdio" {
		t.Errorf("inner spec transport = %q, want stdio: the inner dialer is being asked to spawn a process", inner.spec.Transport)
	}
	if inner.spec.Command != fixtureBinaries.fakepodman {
		t.Errorf("inner spec command = %q, want the container runtime", inner.spec.Command)
	}
	if inner.spec.Name != "casemgmt" {
		t.Errorf("inner spec name = %q, want casemgmt: the upstream's name attributes its audit records", inner.spec.Name)
	}
	if len(inner.spec.Args) == 0 || inner.spec.Args[0] != "run" {
		t.Errorf("inner spec args = %v, want a `run` invocation", inner.spec.Args)
	}
	if reflect.ValueOf(inner.env).Pointer() != reflect.ValueOf(env).Pointer() {
		t.Error("the resolved environment was copied on its way to the inner dialer; the copy outlives the caller's clear()")
	}

	// A dial that never reached the runtime must not have swept a
	// container that was never created -- but it must also not skip the
	// sweep on the path where it might have been. The fixture records
	// every removal it is asked for, so this documents which it was.
	if st.ranAnything() {
		t.Error("the fake inner dialer somehow ran a container")
	}
}

// TestAnInnerDialerThatReturnsNothingIsADialFailure: this package is
// handed whichever Dialer the composition root wired, so a broken one is
// an input, not an impossibility. The failure has to be a refused dial --
// not a nil dereference three calls later, and above all not a container
// nobody holds a reference to.
func TestAnInnerDialerThatReturnsNothingIsADialFailure(t *testing.T) {
	st := newState(t)
	d := New(&fakeInnerDialer{returnNothing: true},
		WithPodmanPath(fixtureBinaries.fakepodman), WithCleanupEnv(controlEnv...))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := d.Dial(ctx, ociSpec(), nil)
	if err == nil {
		t.Fatal("Dial returned no error although the inner dialer returned no connection")
	}
	if up != nil {
		t.Errorf("Dial returned a non-nil Upstream alongside an error: %#v", up)
	}
	// The container was swept even though nothing here knows whether one
	// was ever created: the fixture never ran, so the removal is a no-op,
	// but the call is what makes the path safe when the runtime did start
	// one.
	if len(st.removalsRequested(t)) != 1 {
		t.Errorf("the runtime was asked to remove %v, want exactly one container", st.removalsRequested(t))
	}
}

func TestNewPanicsWithoutAnInnerDialer(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("New(nil) did not panic; the failure would have surfaced as a nil dereference on the first dial")
		}
		if !strings.Contains(r.(string), "cmd/mcp-gateway") {
			t.Errorf("the panic does not say where the wiring belongs: %v", r)
		}
	}()
	New(nil)
}

// TestSecretNeverCrossesTheAPIBoundary is this package's own version of
// the stdio adapter's leak assertion, narrowed to what this package adds:
// every error string it authors, on every path, with a real credential in
// hand.
func TestSecretNeverCrossesTheAPIBoundary(t *testing.T) {
	newState(t)
	secret := newSecret(t)
	env := map[string]string{"MOCK_SECRET": secret, "MOCK_EXPECT": secret}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var surfaces []string
	note := func(label string, err error) {
		if err != nil {
			surfaces = append(surfaces, label+": "+err.Error())
		}
	}

	d := newDialer(t)

	// A dial that fails on the wrapper.
	badWrapper := ociSpec()
	badWrapper.Args = []string{"-v", "/run/user/1000/podman/podman.sock:/sock"}
	_, err := d.Dial(ctx, badWrapper, env)
	note("wrapper rejection", err)

	// A dial that fails on the image.
	badImage := ociSpec()
	badImage.Image = "localhost/casemgmt-mcp:latest"
	_, err = d.Dial(ctx, badImage, env)
	note("image rejection", err)

	// A dial that fails on a malformed variable name, with the value glued
	// to it.
	_, err = d.Dial(ctx, ociSpec(), map[string]string{"MOCK_SECRET=" + secret: secret})
	note("env name rejection", err)

	// A dial that fails because the runtime is not there at all.
	missing := New(stdio.New(stdio.WithInheritedEnv(controlEnv...)),
		WithPodmanPath(filepath.Join(t.TempDir(), "no-such-runtime")), WithCleanupEnv(controlEnv...))
	_, err = missing.Dial(ctx, ociSpec(), env)
	note("missing runtime", err)

	// A live upstream: its results, its tool-level errors, and its close.
	up := dial(t, d, ociSpec(), env)
	res, err := up.CallTool(ctx, "casemgmt_credcheck", nil)
	surfaces = append(surfaces, "credcheck content: "+string(res.Content))
	note("credcheck error", err)
	_, err = up.CallTool(ctx, "no_such_tool", nil)
	note("unknown tool error", err)
	note("close error", up.Close())

	if len(surfaces) < 5 {
		t.Fatalf("only %d surfaces were collected; the leak assertion checked almost nothing", len(surfaces))
	}
	for _, surface := range surfaces {
		if strings.Contains(surface, secret) {
			// The surface itself is not printed: it holds the secret.
			label, _, _ := strings.Cut(surface, ":")
			t.Errorf("LEAK: the injected secret appeared in %s", label)
		}
	}
}
