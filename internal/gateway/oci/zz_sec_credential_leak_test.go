package oci

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Credential-leak lens (security test pass, 2026-09-24). Extends
// invocation_test.go's argv tests with hostile VALUES and with runtime- and
// loader-steering NAMES the existing denylist tests do not cover.

// TestSecArgvNeverCarriesHostileValues: values shaped like JSON, flags,
// "NAME=value" pairs, multi-line text and non-ASCII must never reach argv,
// and every --env must be followed by exactly one declared bare name.
func TestSecArgvNeverCarriesHostileValues(t *testing.T) {
	env := map[string]string{
		"JSON_TOKEN":     `{"api_key":"` + newSecret(t) + `","x":[1,2]}`,
		"MULTILINE":      "line1-" + newSecret(t) + "\nline2\r\n--privileged",
		"UNICODE":        "çãø€🔑-" + newSecret(t),
		"PAIR_LOOKALIKE": "CASEMGMT_API_KEY=" + newSecret(t),
		"FLAG_LOOKALIKE": "-v=/:/host-" + newSecret(t),
		"SPACEY":         " " + newSecret(t) + " ",
		"EMPTY_VALUE":    "",
	}
	p, err := buildPlan(ociSpec(), env, testOptions())
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	for i, arg := range append([]string{p.Path}, p.Args...) {
		for name, value := range env {
			if value != "" && strings.Contains(arg, strings.TrimSpace(value)) {
				t.Errorf("LEAK: argv[%d] carries the value of %s", i, name)
			}
		}
	}
	seen := map[string]bool{}
	for i, arg := range p.Args {
		if arg != "--env" {
			continue
		}
		name := p.Args[i+1]
		if _, ok := env[name]; !ok {
			t.Errorf("--env followed by %q, which is not a declared name", flagOf(name))
		}
		seen[name] = true
	}
	if len(seen) != len(env) {
		t.Errorf("argv names %d variables, want %d", len(seen), len(env))
	}
	if s := fmt.Sprintf("%+v %#v", p, p); func() bool {
		for _, v := range env {
			if v != "" && strings.Contains(s, strings.TrimSpace(v)) {
				return true
			}
		}
		return false
	}() {
		t.Error("LEAK: formatting the plan reveals a value")
	}
}

// TestSecEveryNameRejectionOmitsTheValue: for every way a name is refused,
// neither the value in the map nor any part of a value glued onto the name
// after "=" appears in the error.
func TestSecEveryNameRejectionOmitsTheValue(t *testing.T) {
	secret := newSecret(t)
	for _, name := range []string{
		"TOKEN=" + secret, "TOKEN =" + secret, "-v", "CASEMGMT_*",
		"PATH", "XDG_RUNTIME_DIR", "CONTAINERS_CONF", "TOKEN\n" + secret, "TOKEN\x00" + secret,
	} {
		_, err := buildPlan(ociSpec(), map[string]string{name: secret}, testOptions())
		if err == nil {
			t.Errorf("buildPlan accepted %q", flagOf(name))
			continue
		}
		_, verr := buildPlan(ociSpec(), map[string]string{"OK": "x", name: "v"}, testOptions())
		for _, e := range []error{err, verr} {
			if e != nil && strings.Contains(e.Error(), secret) {
				t.Errorf("LEAK: rejection of %q quotes the value: %s", flagOf(name), strings.ReplaceAll(e.Error(), secret, "<SECRET>"))
			}
		}
	}
}

// TestSecRefusesPodmanInternalRootlessKnobs pins the fix of 24 Sep 2026.
// The denylist's own stated rule is "podman's own knobs" that move runtime
// state between `podman run` (entry env) and `podman rm` in Close (allowlist
// only). The prefix CONTAINERS_ did not match podman's leading-underscore
// internal variables: containers/storage reads _CONTAINERS_ROOTLESS_UID to
// pick the rootless UID (pkg/unshare/unshare_linux.go:53-59) and derives
// the runtime dir /run/user/<uid> from it when XDG_RUNTIME_DIR is unset
// (pkg/homedir/homedir_unix.go:147-158) -- and XDG_RUNTIME_DIR IS unset
// here, because the inherited allowlist is PATH and HOME only.
func TestSecRefusesPodmanInternalRootlessKnobs(t *testing.T) {
	var accepted []string
	for _, name := range []string{"_CONTAINERS_ROOTLESS_UID", "_CONTAINERS_ROOTLESS_GID", "_CONTAINERS_USERNS_CONFIGURED"} {
		if _, err := buildPlan(ociSpec(), map[string]string{name: "4242"}, testOptions()); err == nil {
			accepted = append(accepted, name)
		} else if !errors.Is(err, ErrRuntimeDirectingEnvName) {
			t.Errorf("%s refused with %v, want ErrRuntimeDirectingEnvName", name, err)
		}
		if err := ValidateEnvVarNames([]string{name}); err == nil && !slices.Contains(accepted, name) {
			accepted = append(accepted, name+" (console)")
		}
	}
	if len(accepted) > 0 {
		t.Fatalf("buildPlan/ValidateEnvVarNames accepted podman-internal runtime knobs: %v", accepted)
	}
}

// TestSecRefusesLoaderInjectionNames pins the fix of 24 Sep 2026. The
// entry's resolved map becomes the environment of the podman process
// itself (stdio childEnv), which holds every credential of the entry. A
// name the dynamic loader honours turns a vault value into code loaded
// into that process.
func TestSecRefusesLoaderInjectionNames(t *testing.T) {
	var accepted []string
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GCONV_PATH"} {
		if _, err := buildPlan(ociSpec(), map[string]string{name: "/tmp/evil.so"}, testOptions()); err == nil {
			accepted = append(accepted, name)
		}
	}
	if len(accepted) > 0 {
		t.Fatalf("buildPlan accepted loader-steering names for podman's own environment: %v", accepted)
	}
}
