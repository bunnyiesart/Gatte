package main

import (
	"strings"
	"testing"
)

// TestOperatorHints_CarryTheConfigActuallyLoaded pins a correction made on
// 24 Sep 2026. Every "run this next" hint used to omit -config, so pasting
// it loaded mcp-gateway.toml from the current directory: refused when there
// was none, and acting on a different gateway's database when there was one.
func TestOperatorHints_CarryTheConfigActuallyLoaded(t *testing.T) {
	const cfgPath = "/etc/gatte test/config.toml"
	const quoted = "-config '/etc/gatte test/config.toml'"

	t.Run("upstream register -> sign", func(t *testing.T) {
		e := newOpTestEnv(t)
		e.configPath = cfgPath
		requireExit(t, runUpstreamRegister(e.opEnv, stdioEntry("casemgmt")), exitOK, "register")
		requireContains(t, e.stdoutText(), "mcp-gateway sign "+quoted+" casemgmt", "register")
	})

	t.Run("upstream list, empty -> register", func(t *testing.T) {
		e := newOpTestEnv(t)
		e.configPath = cfgPath
		runUpstreamList(e.opEnv, false)
		requireContains(t, e.stdoutText(), "mcp-gateway upstream register "+quoted+" -name NAME", "upstream list")
	})

	t.Run("tool list -> approve", func(t *testing.T) {
		e := newOpTestEnv(t)
		e.configPath = cfgPath
		mustObserve(t, e, "casemgmt", irisListCases)
		requireExit(t, runToolList(e.opEnv, "", false), exitOK, "tool list")
		requireContains(t, e.stdoutText(), "mcp-gateway tool approve "+quoted+" -fingerprint SHA256 SERVER TOOL", "tool list")
	})

	t.Run("no path known: the bare form, unchanged", func(t *testing.T) {
		e := newOpTestEnv(t)
		requireExit(t, runUpstreamRegister(e.opEnv, stdioEntry("casemgmt")), exitOK, "register")
		if strings.Contains(e.stdoutText(), "-config") {
			t.Errorf("a hint invented a -config value:\n%s", e.stdoutText())
		}
	})
}

func TestOpShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/etc/mcp-gateway/config.toml": "/usr/local/etc/mcp-gateway/config.toml",
		"/etc/a b.toml":                          "'/etc/a b.toml'",
		"/etc/it's.toml":                         `'/etc/it'\''s.toml'`,
		"/etc/100%.toml":                         "/etc/100%.toml",
		"":                                       "''",
	} {
		if got := opShellQuote(in); got != want {
			t.Errorf("opShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestStartupSummary_SIEMLineDoesNotSayNewest: the boot log is the other
// place an operator learns where -expect-head comes from. It said "the
// newest hash Graylog holds", the rule runAuditVerify was corrected away
// from on 12 Sep 2026.
func TestStartupSummary_SIEMLineDoesNotSayNewest(t *testing.T) {
	logger, logs := serveTestLogger()
	startupSummary{
		Addr: "127.0.0.1:8080", Loopback: true, RequireSigned: true,
		SIEMChain: "gatte-01", SIEMPath: "/var/log/mcp-gateway/audit.jsonl",
	}.log(logger)
	out := logs.String()
	for _, forbidden := range []string{"newest hash", "Graylog"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("startup log says %q:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(out, "prev_hash") {
		t.Errorf("startup log does not state how to pick the head:\n%s", out)
	}
}
