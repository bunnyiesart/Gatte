package main

// `upstream register` must refuse a name that could forge output or read
// as a flag. Ported from the internal tree's security pass of 24 Sep 2026.

import (
	"bytes"
	"testing"
)

// secRegister runs `upstream register` against configPath and returns the
// exit code.
func secRegister(t *testing.T, configPath, name string) int {
	t.Helper()
	var out, errBuf bytes.Buffer
	return cmdUpstream([]string{
		"register", "-config", configPath, "-name", name,
		"-transport", "stdio", "-command", "/usr/bin/true",
	}, &out, &errBuf)
}

// TestSecUpstreamRegisterRefusesUnsafeNames: the upstream name becomes the
// namespace prefix of every tool ("NAME.tool"), a signed field, a column in
// `upstream list`, and an argument operators paste into `sign NAME` /
// `deregister NAME`.
func TestSecUpstreamRegisterRefusesUnsafeNames(t *testing.T) {
	configPath := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
	names := map[string]string{
		"namespace separator": "casemgmt.v2",
		"slash":               "../casemgmt",
		"leading space":       " casemgmt",
		"trailing space":      "casemgmt ",
		"newline":             "casemgmt\nforged",
		"tab":                 "casemgmt\tforged",
		"ANSI escape":         "casemgmt\x1b[2K",
		"shell metachars":     "casemgmt;$(id)`id`",
		"leading dash":        "-casemgmt",
		"NUL":                 "casemgmt\x00x",
	}
	var accepted []string
	for label, name := range names {
		if secRegister(t, configPath, name) == exitOK {
			accepted = append(accepted, label)
		}
	}
	if len(accepted) > 0 {
		t.Fatalf("unsafe upstream names accepted: %v", accepted)
	}
	if code := secRegister(t, configPath, "casemgmt"); code != exitOK {
		t.Fatalf("register refused the ordinary name \"casemgmt\": exit %d", code)
	}
}

// TestSecUpstreamListCannotBeSpoofedByAName: a registered name carrying a
// newline and tabs could print a forged row in `upstream list`, e.g. make
// an unsigned entry appear next to a "valid" signature state.
// registry.Validate now refuses the name at register time, so the row can
// never exist; that refusal is the assertion.
func TestSecUpstreamListCannotBeSpoofedByAName(t *testing.T) {
	configPath := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
	forged := "x\nfakecase\tstdio\t/usr/bin/fakecase\t-\tvalid"
	if code := secRegister(t, configPath, forged); code == exitOK {
		t.Fatalf("register accepted a name with newline/tabs: %q", forged)
	}
}

// TestSecUpstreamRegisterRefusesADashName: no entry may exist that could
// only be removed with "--" or read as a flag by a later command.
func TestSecUpstreamRegisterRefusesADashName(t *testing.T) {
	configPath := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
	if code := secRegister(t, configPath, "-dash"); code == exitOK {
		t.Fatal("register accepted the leading-dash name \"-dash\"")
	}
}
