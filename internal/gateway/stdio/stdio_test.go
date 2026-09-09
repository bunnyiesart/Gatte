package stdio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/lab/mockutil"
)

// These tests dial real, separately-compiled MCP servers over a real pipe
// to a real child process. Nothing about the MCP protocol is mocked: the
// property under test -- that a credential goes into a child's environment
// and does not come back out -- is only meaningful against a genuine spawn.

// fixtureBinaries holds the compiled test servers, built once in TestMain.
//
//   - casemgmt is the lab's fake CASEMGMT upstream (lab/servers/casemgmt). It is a real
//     upstream of the shape this gateway serves in production, complete with
//     the <name>_credcheck tool the lab convention defines, and it is used
//     unmodified.
//   - envfixture is this package's own fixture (testdata/envfixture); it
//     reports the *names* of the variables the child was spawned with, which
//     is the only way to observe an inherited variable that credcheck knows
//     nothing about.
var fixtureBinaries struct {
	casemgmt       string
	envfixture string
}

func TestMain(m *testing.M) {
	os.Exit(func() int {
		tmp, err := os.MkdirTemp("", "stdio-fixtures-")
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

		fixtureBinaries.casemgmt = build("casemgmt", "../../../lab/servers/casemgmt")
		fixtureBinaries.envfixture = build("envfixture", "./testdata/envfixture")

		return m.Run()
	}())
}

// testTimeout bounds every dial and call so a wedged fixture fails the test
// instead of hanging the suite.
const testTimeout = 30 * time.Second

// newSecret returns a fresh, unpredictable secret. crypto/rand, not
// math/rand, for the same reason lab/probe uses it: a leak assertion is
// only meaningful if the value it searches for could not plausibly appear
// by coincidence.
func newSecret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	return hex.EncodeToString(buf)
}

// casemgmtSpec is the upstream spec for the compiled casemgmt mock.
func casemgmtSpec() gateway.UpstreamSpec {
	return gateway.UpstreamSpec{Name: "casemgmt", Transport: "stdio", Command: fixtureBinaries.casemgmt}
}

// dial dials spec and registers Close as a cleanup, failing the test if
// either the dial or the eventual close reports a problem.
func dial(t *testing.T, d *Dialer, spec gateway.UpstreamSpec, env map[string]string) gateway.Upstream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := d.Dial(ctx, spec, env)
	if err != nil {
		t.Fatalf("Dial(%q): %v", spec.Name, err)
	}
	t.Cleanup(func() {
		// A nil error from Close is not just tidiness: it means the child's
		// stdin was closed, the child exited on its own, and cmd.Wait
		// collected it. A leaked or force-killed process shows up here.
		if err := up.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	return up
}

// textBlock is the shape of an MCP text content block, for reading a
// fixture's JSON payload back out of a gateway.Result.
type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// firstText decodes the first text content block of a result.
func firstText(t *testing.T, res gateway.Result) string {
	t.Helper()
	var blocks []textBlock
	if err := json.Unmarshal(res.Content, &blocks); err != nil {
		t.Fatalf("decode result content %s: %v", res.Content, err)
	}
	if len(blocks) == 0 {
		t.Fatalf("result had no content blocks: %s", res.Content)
	}
	return blocks[0].Text
}

func TestDialListsToolsWithSchemasIntact(t *testing.T) {
	up := dial(t, New(), casemgmtSpec(), nil)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	defs, err := up.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	byName := make(map[string]gateway.ToolDef, len(defs))
	for _, def := range defs {
		byName[def.Name] = def
	}
	for _, want := range []string{"casemgmt_credcheck", "list_cases", "get_case"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("ListTools did not return %q; got %v", want, slices.Sorted(mapKeys(byName)))
		}
	}

	getCase, ok := byName["get_case"]
	if !ok {
		t.Fatal("casemgmt_get_case missing, cannot check its schema")
	}
	if getCase.Description == "" {
		t.Error("casemgmt_get_case has an empty description; the quarantine hash covers this field")
	}
	if len(getCase.InputSchema) == 0 {
		t.Fatal("casemgmt_get_case has no input schema")
	}
	// The schema must survive as usable JSON describing the tool's real
	// parameter -- not a placeholder and not something reshaped on the way
	// through.
	var schema struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(getCase.InputSchema, &schema); err != nil {
		t.Fatalf("casemgmt_get_case input schema is not valid JSON (%s): %v", getCase.InputSchema, err)
	}
	if schema.Type != "object" {
		t.Errorf("casemgmt_get_case schema type = %q, want \"object\"", schema.Type)
	}
	if _, ok := schema.Properties["case_id"]; !ok {
		t.Errorf("casemgmt_get_case schema is missing the case_id property: %s", getCase.InputSchema)
	}
	// design/adr/0007: nothing on this path may pretty-print or otherwise
	// reformat a schema, because these are the bytes Tool Quarantine
	// hashes. Indentation would be the most likely accidental change, so
	// assert its absence explicitly.
	if strings.ContainsAny(string(getCase.InputSchema), "\n\t") {
		t.Errorf("input schema contains formatting whitespace, it was reformatted somewhere: %s", getCase.InputSchema)
	}
}

func TestCallToolRoundTripsInjectedCredential(t *testing.T) {
	secret := newSecret(t)
	up := dial(t, New(), casemgmtSpec(), map[string]string{
		"MOCK_SECRET": secret,
		"MOCK_EXPECT": secret,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := up.CallTool(ctx, "casemgmt_credcheck", nil)
	if err != nil {
		t.Fatalf("CallTool(casemgmt_credcheck): %v", err)
	}
	if res.IsError {
		t.Fatalf("casemgmt_credcheck reported a tool error: %s", res.Content)
	}

	var check mockutil.CredCheckResult
	if err := json.Unmarshal([]byte(firstText(t, res)), &check); err != nil {
		t.Fatalf("decode credcheck result: %v", err)
	}
	if !check.ReceivedExpectedSecret {
		t.Errorf("received_expected_secret = false (fingerprint %s): the credential did not reach the child",
			check.Fingerprint)
	}
}

// TestSecretNeverCrossesTheAPIBoundary is the leak assertion. It is the
// reason this package exists.
//
// It is deliberately independent of what casemgmt_credcheck reports: a
// credcheck tool can say "yes I got it" while some entirely unrelated path
// -- a tool description, an error message, a result body -- carries the
// value back out. So the secret is injected, every method on the component
// is exercised including its failure paths, and every byte the component
// hands back is searched for the literal value.
func TestSecretNeverCrossesTheAPIBoundary(t *testing.T) {
	secret := newSecret(t)
	up := dial(t, New(), casemgmtSpec(), map[string]string{
		"MOCK_SECRET": secret,
		"MOCK_EXPECT": secret,
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Everything the component returns to its caller, collected in one
	// place: tool definitions, successful results, tool-level errors, and
	// transport/protocol errors.
	var surfaces []string
	record := func(label, value string) {
		if value != "" {
			surfaces = append(surfaces, label+": "+value)
		}
	}

	defs, err := up.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, def := range defs {
		record("tool name", def.Name)
		record("tool description", def.Description)
		record("tool schema", string(def.InputSchema))
	}

	// A successful call to the tool that actually holds the secret.
	res, err := up.CallTool(ctx, "casemgmt_credcheck", nil)
	record("credcheck content", string(res.Content))
	if err != nil {
		record("credcheck error", err.Error())
	}

	// A tool-level error (IsError result): casemgmt_get_case with an unknown id.
	res, err = up.CallTool(ctx, "get_case", json.RawMessage(`{"case_id":"no-such-case"}`))
	record("get_case content", string(res.Content))
	if err != nil {
		record("get_case error", err.Error())
	}

	// A protocol-level error: a tool that does not exist.
	res, err = up.CallTool(ctx, "no_such_tool", nil)
	record("unknown tool content", string(res.Content))
	if err == nil {
		t.Error("CallTool on a nonexistent tool returned no error")
	} else {
		record("unknown tool error", err.Error())
	}

	// An error from a method called on a closed upstream. Close is called
	// here rather than left to the cleanup so its error is scanned too;
	// Close is idempotent, so the cleanup's second call is harmless.
	if err := up.Close(); err != nil {
		record("close error", err.Error())
	}
	if _, err := up.ListTools(ctx); err != nil {
		record("post-close ListTools error", err.Error())
	}
	if _, err := up.CallTool(ctx, "casemgmt_credcheck", nil); err != nil {
		record("post-close CallTool error", err.Error())
	}

	// A dial that fails outright, with the secret in hand.
	if _, err := New().Dial(ctx, gateway.UpstreamSpec{
		Name:      "casemgmt",
		Transport: "stdio",
		Command:   filepath.Join(t.TempDir(), "definitely-not-a-binary"),
	}, map[string]string{"MOCK_SECRET": secret, "MOCK_EXPECT": secret}); err != nil {
		record("failed dial error", err.Error())
	} else {
		t.Error("Dial of a nonexistent command unexpectedly succeeded")
	}

	if len(surfaces) == 0 {
		t.Fatal("no surfaces were collected; the leak assertion checked nothing")
	}
	for _, surface := range surfaces {
		if strings.Contains(surface, secret) {
			// The surface itself is deliberately not printed: it holds the
			// secret, and a CI log is exactly where it should not go.
			label, _, _ := strings.Cut(surface, ":")
			t.Errorf("LEAK: the injected secret appeared in %s", label)
		}
	}
}

// TestChildDoesNotInheritGatewayEnvironment checks the property the whole
// component is built around from the child's side: a variable set in the
// gateway's own process must not reach the upstream.
func TestChildDoesNotInheritGatewayEnvironment(t *testing.T) {
	sentinelName := "STDIO_DIALER_SENTINEL_" + strings.ToUpper(newSecret(t)[:8])
	sentinelValue := newSecret(t)
	t.Setenv(sentinelName, sentinelValue)

	injected := map[string]string{"MOCK_SECRET": newSecret(t)}
	up := dial(t, New(), gateway.UpstreamSpec{
		Name:      "envfixture",
		Transport: "stdio",
		Command:   fixtureBinaries.envfixture,
	}, injected)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := up.CallTool(ctx, "env_names", nil)
	if err != nil {
		t.Fatalf("CallTool(env_names): %v", err)
	}
	var reported struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal([]byte(firstText(t, res)), &reported); err != nil {
		t.Fatalf("decode env_names result: %v", err)
	}

	if slices.Contains(reported.Names, sentinelName) {
		t.Errorf("child inherited %s from the gateway process; the environment was not built from scratch", sentinelName)
	}

	// Stronger than "the sentinel is absent": the child's environment must
	// be *exactly* the documented allowlist plus what the caller injected.
	// Anything else means something is inheriting that nobody decided to
	// inherit.
	want := []string{"MOCK_SECRET"}
	for _, name := range DefaultInheritedEnv() {
		if _, ok := os.LookupEnv(name); ok {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	got := slices.Clone(reported.Names)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("child environment = %v, want exactly %v", got, want)
	}
}

// TestEmptyInheritedEnvGivesChildOnlyInjectedValues checks the tightest
// configuration: with no passthrough at all, the child sees the caller's
// env and literally nothing else.
func TestEmptyInheritedEnvGivesChildOnlyInjectedValues(t *testing.T) {
	up := dial(t, New(WithInheritedEnv()), gateway.UpstreamSpec{
		Name:      "envfixture",
		Transport: "stdio",
		Command:   fixtureBinaries.envfixture,
	}, map[string]string{"ONLY_THIS": "x"})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := up.CallTool(ctx, "env_names", nil)
	if err != nil {
		t.Fatalf("CallTool(env_names): %v", err)
	}
	var reported struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal([]byte(firstText(t, res)), &reported); err != nil {
		t.Fatalf("decode env_names result: %v", err)
	}
	if !slices.Equal(reported.Names, []string{"ONLY_THIS"}) {
		t.Errorf("child environment = %v, want exactly [ONLY_THIS]", reported.Names)
	}
}

// TestInjectedEnvOverridesInheritedEnv pins the precedence documented on
// childEnv: what the Credential Vault resolved wins over whatever the
// gateway's own process happens to have under the same name.
func TestInjectedEnvOverridesInheritedEnv(t *testing.T) {
	t.Setenv("HOME", "/gateway-home-should-not-win")

	up := dial(t, New(WithInheritedEnv("HOME")), gateway.UpstreamSpec{
		Name:      "envfixture",
		Transport: "stdio",
		Command:   fixtureBinaries.envfixture,
	}, map[string]string{"HOME": "/injected-home"})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := up.CallTool(ctx, "env_names", nil)
	if err != nil {
		t.Fatalf("CallTool(env_names): %v", err)
	}
	var reported struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal([]byte(firstText(t, res)), &reported); err != nil {
		t.Fatalf("decode env_names result: %v", err)
	}
	// The fixture reports names only, so the check available here is that
	// HOME arrived exactly once -- os/exec de-duplicates keeping the last
	// entry, which is the injected one.
	var count int
	for _, name := range reported.Names {
		if name == "HOME" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("child saw HOME %d times, want exactly 1 (os/exec should have de-duplicated)", count)
	}
}

func TestDialNonexistentCommandFailsCleanly(t *testing.T) {
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	secret := newSecret(t)
	up, err := New().Dial(ctx, gateway.UpstreamSpec{
		Name:      "ghost",
		Transport: "stdio",
		Command:   filepath.Join(t.TempDir(), "no-such-binary"),
		Args:      []string{"--flag"},
	}, map[string]string{"MOCK_SECRET": secret})

	if err == nil {
		_ = up.Close()
		t.Fatal("Dial of a nonexistent command returned no error")
	}
	if up != nil {
		t.Errorf("Dial returned a non-nil Upstream alongside an error: %#v", up)
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error does not name the upstream that failed: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("LEAK: the spawn failure quoted the injected environment")
	}
	assertGoroutinesSettle(t, before)
}

func TestDialRejectsNonStdioTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	for _, transport := range []string{"http", "sse", "", "STDIO"} {
		up, err := New().Dial(ctx, gateway.UpstreamSpec{
			Name:      "remote",
			Transport: transport,
			URL:       "https://example.invalid/mcp",
			Command:   fixtureBinaries.casemgmt,
		}, map[string]string{"TOKEN": "unused"})
		if err == nil {
			_ = up.Close()
			t.Errorf("Dial(transport=%q) succeeded, want rejection", transport)
			continue
		}
		if !errors.Is(err, ErrUnsupportedTransport) {
			t.Errorf("Dial(transport=%q) error = %v, want ErrUnsupportedTransport", transport, err)
		}
	}
}

func TestDialRejectsEnvNameThatSmugglesAValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	secret := newSecret(t)
	up, err := New().Dial(ctx, casemgmtSpec(), map[string]string{"TOKEN=" + secret: "x"})
	if err == nil {
		_ = up.Close()
		t.Fatal("Dial accepted an environment variable name containing \"=\"")
	}
	if !errors.Is(err, ErrInvalidEnv) {
		t.Errorf("error = %v, want ErrInvalidEnv", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("LEAK: the rejection quoted the value glued onto the malformed name")
	}
}

func TestCloseIsIdempotentAndCallsFailAfterClose(t *testing.T) {
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	up, err := New().Dial(ctx, casemgmtSpec(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// A nil error means the child exited on its own after its stdin closed
	// and was collected by wait -- i.e. Close really reaped it rather than
	// abandoning it.
	if err := up.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := up.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}

	// After Close, calls must fail rather than hang. The deadline is what
	// makes this a real assertion: a call that blocked on a dead pipe would
	// otherwise just look slow.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := up.ListTools(ctx); !errors.Is(err, ErrClosed) {
			t.Errorf("ListTools after Close: error = %v, want ErrClosed", err)
		}
		if _, err := up.CallTool(ctx, "casemgmt_credcheck", nil); !errors.Is(err, ErrClosed) {
			t.Errorf("CallTool after Close: error = %v, want ErrClosed", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("calls after Close blocked instead of failing")
	}

	assertGoroutinesSettle(t, before)
}

// assertGoroutinesSettle waits for the goroutine count to fall back to
// before, failing if it does not. A dialer that abandons a child also
// abandons the SDK's read loop, so a stuck count is the cheapest available
// signal that something was left running.
func assertGoroutinesSettle(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		now := runtime.NumGoroutine()
		if now <= before {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			buf = buf[:runtime.Stack(buf, true)]
			t.Errorf("goroutines did not settle: %d before, %d after\n%s", before, now, buf)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// mapKeys is a tiny helper for readable failure messages.
func mapKeys[K comparable, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// TestRawSchemaPassesRawJSONThrough covers the branches of rawSchema that a
// live dial does not reach today (the SDK hands us a decoded map), so that
// a future SDK version that starts handing back json.RawMessage still gets
// byte-for-byte pass-through rather than a re-encode.
func TestRawSchemaPassesRawJSONThrough(t *testing.T) {
	// Deliberately non-canonical: keys out of alphabetical order, odd
	// spacing. Raw input must come out exactly as it went in.
	raw := json.RawMessage(`{"type":"object", "properties":{"b":{},"a":{}}}`)
	got, err := rawSchema(raw)
	if err != nil {
		t.Fatalf("rawSchema: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("rawSchema reformatted a raw schema:\n got %s\nwant %s", got, raw)
	}
	if &got[0] == &raw[0] {
		t.Error("rawSchema returned an alias of its input rather than a copy")
	}

	if got, err := rawSchema(nil); err != nil || got != nil {
		t.Errorf("rawSchema(nil) = %s, %v; want nil, nil", got, err)
	}
}

// TestNewAppliesOptions is a small guard on the constructor's defaults, in
// particular that the inherited-environment allowlist is what the package
// documentation claims it is.
func TestNewAppliesOptions(t *testing.T) {
	d := New()
	if !slices.Equal(d.inherited, []string{"PATH", "HOME"}) {
		t.Errorf("default inherited env = %v, want [PATH HOME]", d.inherited)
	}
	if d.shutdownGrace != defaultShutdownGrace {
		t.Errorf("default shutdown grace = %v, want %v", d.shutdownGrace, defaultShutdownGrace)
	}

	d = New(WithClientInfo("gw", "1.2.3"), WithInheritedEnv("PATH"), WithShutdownGrace(time.Second))
	if d.clientName != "gw" || d.clientVersion != "1.2.3" {
		t.Errorf("client info = %q/%q, want gw/1.2.3", d.clientName, d.clientVersion)
	}
	if !slices.Equal(d.inherited, []string{"PATH"}) {
		t.Errorf("inherited env = %v, want [PATH]", d.inherited)
	}
	if d.shutdownGrace != time.Second {
		t.Errorf("shutdown grace = %v, want 1s", d.shutdownGrace)
	}

	// DefaultInheritedEnv must hand out a copy: a caller that mutates what
	// it returns must not be able to widen the policy for everyone.
	names := DefaultInheritedEnv()
	names[0] = "MUTATED"
	if !slices.Equal(New().inherited, []string{"PATH", "HOME"}) {
		t.Error("DefaultInheritedEnv returned the package's own slice; mutating it changed the default policy")
	}
	_ = fmt.Sprint(names)
}
