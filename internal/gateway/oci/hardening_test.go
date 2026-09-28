package oci

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
)

// The container hardening of design/adr/0034: capabilities, privilege
// gain, uid, and resource limits. The argv order is pinned by
// TestBuildPlanAssemblesTheWrapperInOrder; these pin the rules.

// TestBuildPlanCarriesTheConfiguredLimits: the numbers are the operator's
// ([oci] in the configuration), the flags are not. A configured value
// changes a token; nothing configured removes one.
func TestBuildPlanCarriesTheConfiguredLimits(t *testing.T) {
	opts := testOptions()
	opts.Limits = Limits{User: "10001:10001", PidsLimit: 64, Memory: "1g", CPUs: 0.5}

	p, err := buildPlan(ociSpec(), nil, opts)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	for _, want := range []string{"--user=10001:10001", "--pids-limit=64", "--memory=1g", "--cpus=0.5",
		"--cap-drop=all", "--security-opt=no-new-privileges"} {
		if !slices.Contains(p.Args, want) {
			t.Errorf("argv lacks %s: %v", want, p.Args)
		}
	}
}

// TestBuildPlanRefusesARootOrSymbolicUser is what makes the uid a fact of
// the command line rather than a promise of the image. A user NAME is
// resolved through the image's own /etc/passwd, which the image controls,
// so "mcp" may be uid 0 there; only a number means one thing. Group 0 is
// refused for the reason uid 0 is.
func TestBuildPlanRefusesARootOrSymbolicUser(t *testing.T) {
	for _, user := range []string{"", "0", "0:0", "root", "mcp", "10001", "10001:0", "0:10001",
		"00:1", "010001:10001", "10001:10001:1", "-1:1", "10001:root", " 10001:10001", "4294967296:1"} {
		opts := testOptions()
		opts.Limits.User = user
		if _, err := buildPlan(ociSpec(), nil, opts); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("buildPlan(user=%q) error = %v, want ErrInvalidLimits", user, err)
		}
	}
}

// TestBuildPlanRefusesALimitThatIsNoLimit: zero, negative and unparsable
// values do not mean "unlimited" -- they are refused. A limit that a typo
// can switch off is a limit the next typo will.
func TestBuildPlanRefusesALimitThatIsNoLimit(t *testing.T) {
	cases := map[string]func(*Limits){
		"pids 0":          func(l *Limits) { l.PidsLimit = 0 },
		"pids -1":         func(l *Limits) { l.PidsLimit = -1 },
		"memory empty":    func(l *Limits) { l.Memory = "" },
		"memory 0":        func(l *Limits) { l.Memory = "0" },
		"memory 0m":       func(l *Limits) { l.Memory = "0m" },
		"memory bytes":    func(l *Limits) { l.Memory = "512" },
		"memory below 6m": func(l *Limits) { l.Memory = "5m" },
		"memory unit t":   func(l *Limits) { l.Memory = "1t" },
		"memory negative": func(l *Limits) { l.Memory = "-1g" },
		"memory fraction": func(l *Limits) { l.Memory = "1.5g" },
		"memory space":    func(l *Limits) { l.Memory = "512 m" },
		"memory mb":       func(l *Limits) { l.Memory = "512mb" },
		"cpus 0":          func(l *Limits) { l.CPUs = 0 },
		"cpus -1":         func(l *Limits) { l.CPUs = -1 },
		"cpus NaN":        func(l *Limits) { l.CPUs = math.NaN() },
		"cpus Inf":        func(l *Limits) { l.CPUs = math.Inf(1) },
	}
	for name, mutate := range cases {
		opts := testOptions()
		mutate(&opts.Limits)
		if _, err := buildPlan(ociSpec(), nil, opts); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("%s: buildPlan error = %v, want ErrInvalidLimits", name, err)
		}
	}
}

// TestEntryArgsCannotLoosenTheHardening: an entry's Args may restate the
// fixed wrapper and set the network, nothing else. None of the knobs that
// would undo design/adr/0034 can arrive through a signed row, and the
// configured values cannot be restated either: a restatement that could
// differ from the configuration would be two sources for one value.
func TestEntryArgsCannotLoosenTheHardening(t *testing.T) {
	for _, arg := range []string{
		"--user=0", "--user=65534:65534", "--cap-add=ALL", "--cap-add=SYS_ADMIN",
		"--security-opt=seccomp=unconfined", "--security-opt=label=disable",
		"--pids-limit=-1", "--pids-limit=256", "--memory=100g", "--cpus=64", "--userns=host",
		"--privileged",
	} {
		spec := ociSpec()
		spec.Args = []string{arg}
		if _, err := buildPlan(spec, nil, testOptions()); !errors.Is(err, ErrUnsupportedWrapperFlag) {
			t.Errorf("buildPlan(args=[%q]) error = %v, want ErrUnsupportedWrapperFlag", arg, err)
		}
	}
}

// TestValidateLimitsIsTheSameRuleTheDialApplies: the composition root
// refuses to start on limits the dial would refuse, so a bad [oci] section
// is one boot error instead of one refused container per upstream.
func TestValidateLimitsIsTheSameRuleTheDialApplies(t *testing.T) {
	if err := ValidateLimits(DefaultLimits()); err != nil {
		t.Fatalf("ValidateLimits refused the defaults: %v", err)
	}
	for _, l := range []Limits{
		{User: "0:0", PidsLimit: 256, Memory: "512m", CPUs: 1},
		{User: "10001:10001", PidsLimit: 0, Memory: "512m", CPUs: 1},
		{User: "10001:10001", PidsLimit: 256, Memory: "lots", CPUs: 1},
		{User: "10001:10001", PidsLimit: 256, Memory: "512m", CPUs: 0},
	} {
		if err := ValidateLimits(l); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("ValidateLimits(%+v) = %v, want ErrInvalidLimits", l, err)
		}
		opts := testOptions()
		opts.Limits = l
		if _, err := buildPlan(ociSpec(), nil, opts); err == nil {
			t.Errorf("buildPlan accepted %+v", l)
		}
	}
}

// TestTheContainerRunsHardened asserts on the recorded argv of a real
// spawn, as TestTheContainerRunsWithAReadOnlyRoot does: what the ADR
// promises is about the container that ran, not about buildPlan.
func TestTheContainerRunsHardened(t *testing.T) {
	st := newState(t)
	_ = dial(t, newDialer(t), ociSpec(), map[string]string{"MOCK_SECRET": newSecret(t)})

	argv := st.lastRun(t).Argv
	for _, want := range []string{"--cap-drop=all", "--security-opt=no-new-privileges", "--user=65534:65534",
		"--pids-limit=256", "--memory=512m", "--cpus=1"} {
		if !slices.Contains(argv, want) {
			t.Errorf("the container was not run with %s (design/adr/0034): %v", want, argv)
		}
	}
}

// TestWithLimitsFillsOnlyWhatWasLeftUnset: the composition root passes the
// [oci] section as read, and a key the operator did not write means the
// default -- never "no flag". The assertion is on what the inner dialer is
// handed, which is the argv that would run.
func TestWithLimitsFillsOnlyWhatWasLeftUnset(t *testing.T) {
	_ = newState(t)
	inner := &fakeInnerDialer{}
	d := New(inner, WithPodmanPath(fixtureBinaries.fakepodman), WithCleanupEnv(controlEnv...),
		WithLimits(Limits{Memory: "1g"}))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := d.Dial(ctx, ociSpec(), nil); err == nil {
		t.Fatal("Dial succeeded although the inner dialer refused")
	}
	for _, want := range []string{"--memory=1g", "--user=65534:65534", "--pids-limit=256", "--cpus=1",
		"--cap-drop=all", "--security-opt=no-new-privileges"} {
		if !slices.Contains(inner.spec.Args, want) {
			t.Errorf("the dial's argv lacks %s: %v", want, inner.spec.Args)
		}
	}
}
