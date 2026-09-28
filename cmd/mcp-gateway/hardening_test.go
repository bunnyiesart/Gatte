package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	gwoci "github.com/bunnyiesart/Gatte/internal/gateway/oci"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// design/adr/0034 at the composition root: a stdio backend runs as the
// gateway's own uid, where open() on the age key is the whole vault, so it
// is not handed credentials unless the configuration says so out loud.

// recordingDialer stands in for one adapter and records whether it was
// asked to dial.
type recordingDialer struct{ called bool }

func (d *recordingDialer) Dial(context.Context, gateway.UpstreamSpec, map[string]string) (gateway.Upstream, error) {
	d.called = true
	return nil, errors.New("recordingDialer does not spawn")
}

func TestTransportDialerRefusesACredentialedStdioEntry(t *testing.T) {
	stdio, oci := &recordingDialer{}, &recordingDialer{}
	d := transportDialer{stdio: stdio, oci: oci}
	creds := map[string]string{"CASEMGMT_API_KEY": "not-a-real-secret"}

	_, err := d.Dial(context.Background(), gateway.UpstreamSpec{Name: "casemgmt", Transport: "stdio", Command: "/bin/true"}, creds)
	if !errors.Is(err, errCredentialedStdio) {
		t.Fatalf("Dial(stdio, with credentials) error = %v, want errCredentialedStdio", err)
	}
	if stdio.called {
		t.Error("the stdio adapter was asked to spawn a credentialed process the policy refuses")
	}
	for _, want := range []string{"-transport oci", "allow_credentialed_stdio"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the way out %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "not-a-real-secret") {
		t.Error("LEAK: the refusal quoted a resolved value")
	}

	// A stdio entry with no credential has nothing to lose to the uid.
	if _, err := d.Dial(context.Background(), gateway.UpstreamSpec{Name: "ioc", Transport: "stdio", Command: "/bin/true"}, nil); errors.Is(err, errCredentialedStdio) || !stdio.called {
		t.Errorf("a stdio entry without credentials was refused by the policy: %v", err)
	}

	// An oci entry is what the policy points at.
	if _, err := d.Dial(context.Background(), gateway.UpstreamSpec{Name: "casemgmt", Transport: "oci"}, creds); errors.Is(err, errCredentialedStdio) || !oci.called {
		t.Errorf("an oci entry with credentials was refused by the stdio policy: %v", err)
	}

	// And the opt-in is exactly that.
	stdio.called = false
	d.allowCredentialedStdio = true
	if _, err := d.Dial(context.Background(), gateway.UpstreamSpec{Name: "casemgmt", Transport: "stdio", Command: "/bin/true"}, creds); errors.Is(err, errCredentialedStdio) || !stdio.called {
		t.Errorf("allow_credentialed_stdio = true did not let the stdio entry dial: %v", err)
	}
}

// TestDialTimeRefusalAppliesTheStdioEnvRules: the loader/interpreter names
// are refused at the prompt for stdio too, not only at every restart.
func TestDialTimeRefusalAppliesTheStdioEnvRules(t *testing.T) {
	entry := registry.UpstreamServer{Name: "casemgmt", Transport: registry.TransportStdio, Command: "/bin/true",
		EnvVarNames: []string{"CASEMGMT_API_KEY", "NODE_OPTIONS"}}
	if err := dialTimeRefusal(entry); err == nil {
		t.Error("dialTimeRefusal accepted a stdio entry naming NODE_OPTIONS")
	}
	entry.EnvVarNames = []string{"CASEMGMT_API_KEY"}
	if err := dialTimeRefusal(entry); err != nil {
		t.Errorf("dialTimeRefusal refused an ordinary stdio entry: %v", err)
	}
}

func TestUpstreamRegister_RefusesACredentialedStdioEntryWithoutTheOptIn(t *testing.T) {
	register := func(configPath, name string, extra ...string) (int, string) {
		var out, errBuf bytes.Buffer
		args := append([]string{"register", "-config", configPath, "-name", name,
			"-transport", "stdio", "-command", "/usr/local/bin/casemgmt-mcp"}, extra...)
		code := cmdUpstream(args, &out, &errBuf)
		return code, errBuf.String()
	}

	strict := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
	code, stderr := register(strict, "casemgmt", "-env", "CASEMGMT_API_KEY")
	if code == exitOK {
		t.Fatal("a credentialed stdio entry registered without [upstreams] allow_credentialed_stdio")
	}
	requireContains(t, stderr, "-transport oci", "refusal")
	requireContains(t, stderr, "allow_credentialed_stdio", "refusal")

	// No credential, no refusal.
	code, stderr = register(strict, "iocsweep")
	requireExit(t, code, exitOK, "register a stdio entry with no -env\n"+stderr)

	lab := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600))+"\n[upstreams]\nallow_credentialed_stdio = true\n")
	code, stderr = register(lab, "casemgmt", "-env", "CASEMGMT_API_KEY")
	requireExit(t, code, exitOK, "register with the opt-in\n"+stderr)
}

// TestSign_RefusesACredentialedStdioEntryWithoutTheOptIn: a row written
// past `upstream register` (by an older binary, or directly into the
// database) must not get a signature the serving process would refuse.
func TestSign_RefusesACredentialedStdioEntryWithoutTheOptIn(t *testing.T) {
	e := newOpTestEnv(t)
	useSigningKey(t, e)
	mustRegister(t, e, registry.UpstreamServer{
		Name: "casemgmt", Transport: registry.TransportStdio, Command: "/usr/local/bin/casemgmt-mcp",
		EnvVarNames: []string{"CASEMGMT_API_KEY"},
	})

	e.cfg.Upstreams.AllowCredentialedStdio = false
	if code := runSign(e.opEnv, "casemgmt"); code == exitOK {
		t.Fatalf("sign signed a credentialed stdio entry the gateway would refuse:\n%s", e.bothText())
	}
	requireContains(t, e.stderrText(), "allow_credentialed_stdio", "sign refusal")

	e.cfg.Upstreams.AllowCredentialedStdio = true
	e.out.Reset()
	e.err.Reset()
	requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign with the opt-in\n"+e.bothText())
}

// TestBuildServer_ACredentialedStdioEntryIsRefusedAndSaysWhy: without the
// opt-in the entry does not come up, the rest of the gateway serves, and
// the log names the way out.
func TestBuildServer_ACredentialedStdioEntryIsRefusedAndSaysWhy(t *testing.T) {
	fx := newServeFixture(t, nil)
	registerRaw(t, fx.dbPath, registry.UpstreamServer{
		Name: "casemgmt", Transport: registry.TransportStdio, Command: "/bin/true",
		EnvVarNames: []string{"MOCK_SECRET"},
	})

	logger, logs := serveTestLogger()
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	if got := stack.summary.UpstreamsFailed; len(got) != 1 || got[0] != "casemgmt" {
		t.Errorf("summary.UpstreamsFailed = %v, want [casemgmt]", got)
	}
	if !strings.Contains(logs.String(), "allow_credentialed_stdio") {
		t.Errorf("the log does not say why the credentialed stdio entry was refused:\n%s", logs.String())
	}
}

// TestBuildServer_TheOptInIsLoud: allow_credentialed_stdio = true is a WARN
// at every boot, so it cannot become the forgotten default of a
// deployment.
func TestBuildServer_TheOptInIsLoud(t *testing.T) {
	fx := newServeFixture(t, func(b *strings.Builder) {
		b.WriteString("[upstreams]\nallow_credentialed_stdio = true\n")
	})
	logger, logs := serveTestLogger()
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()

	var warned bool
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "allow_credentialed_stdio") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no WARN names allow_credentialed_stdio:\n%s", logs.String())
	}
}

// TestOCIConfigRuleIsTheDialRule: config.Validate cannot import the oci
// adapter (internal/fitness), so the [oci] rule is written twice. This is
// what keeps the two from drifting: every value one accepts the other
// accepts, and every value one refuses the other refuses.
func TestOCIConfigRuleIsTheDialRule(t *testing.T) {
	users := []string{"65534:65534", "10001:10001", "1:1", "0:0", "0", "root", "mcp", "10001", "10001:0", "00:1", "4294967296:1", "4294967295:1"}
	mems := []string{"512m", "6m", "1g", "6291456b", "64k", "5m", "512", "0m", "1.5g", "512mb", "1t"}
	pids := []int{1, 256, 0, -1, 1 << 22, 1<<22 + 1}
	cpus := []float64{1, 0.5, 0.01, 0.009, 1e-9, 0, -1, math.Inf(1)}

	check := func(l gwoci.Limits) {
		t.Helper()
		pid, cpu := l.PidsLimit, l.CPUs
		c := config.OCI{User: l.User, Memory: l.Memory, PidsLimit: &pid, CPUs: &cpu}
		cfgErr := c.Validate()
		dialErr := gwoci.ValidateLimits(l)
		if (cfgErr == nil) != (dialErr == nil) {
			t.Errorf("%+v: config says %v, the dial says %v", l, cfgErr, dialErr)
		}
	}
	d := gwoci.DefaultLimits()
	for _, u := range users {
		check(gwoci.Limits{User: u, PidsLimit: d.PidsLimit, Memory: d.Memory, CPUs: d.CPUs})
	}
	for _, m := range mems {
		check(gwoci.Limits{User: d.User, PidsLimit: d.PidsLimit, Memory: m, CPUs: d.CPUs})
	}
	for _, p := range pids {
		check(gwoci.Limits{User: d.User, PidsLimit: p, Memory: d.Memory, CPUs: d.CPUs})
	}
	for _, c := range cpus {
		check(gwoci.Limits{User: d.User, PidsLimit: d.PidsLimit, Memory: d.Memory, CPUs: c})
	}

	// And an [oci] section left out entirely is the adapter's defaults.
	if got := ociLimits(config.OCI{}); got != gwoci.DefaultLimits() {
		t.Errorf("ociLimits(empty) = %+v, want the defaults %+v", got, gwoci.DefaultLimits())
	}
}

// registerRaw writes an entry straight into the fixture's database, the
// way a row written past the console would arrive.
func registerRaw(t *testing.T, dbPath string, entry registry.UpstreamServer) {
	t.Helper()
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	if err := registrysqlite.Migrate(db); err != nil {
		t.Fatalf("migrate registry: %v", err)
	}
	if err := registrysqlite.New(db).Register(context.Background(), entry); err != nil {
		t.Fatalf("register %s: %v", filepath.Base(entry.Command), err)
	}
}
