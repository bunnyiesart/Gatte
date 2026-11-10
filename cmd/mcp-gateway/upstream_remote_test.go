package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// TestCmdUpstream_RemoteRegisterListSign: a remote entry registers from the
// command line with streamable as its default kind, lists with its URL, and
// signs with the auth descriptor and remote kind in what `sign` prints.
func TestCmdUpstream_RemoteRegisterListSign(t *testing.T) {
	configPath := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
	var out, errb bytes.Buffer
	requireExit(t, cmdUpstream([]string{
		"register", "-config", configPath, "-name", "vendor", "-transport", "remote",
		"-url", "https://mcp.vendor.example/mcp", "-auth-kind", "bearer", "-env", "VENDOR_TOKEN",
	}, &out, &errb), exitOK, "register remote: "+errb.String())
	requireContains(t, out.String(), "remote kind", "register")
	requireContains(t, out.String(), "streamable", "register")

	out.Reset()
	errb.Reset()
	requireExit(t, cmdUpstream([]string{"list", "-config", configPath}, &out, &errb), exitOK, "list")
	requireContains(t, out.String(), "https://mcp.vendor.example/mcp", "list")

	out.Reset()
	errb.Reset()
	requireExit(t, cmdSign([]string{"-config", configPath, "vendor"}, &out, &errb), exitOK, "sign: "+errb.String())
	requireContains(t, out.String(), "bearer (Authorization: Bearer <secret>)", "sign")
	requireContains(t, out.String(), "streamable", "sign")
}

// TestCmdSignAll_PlanShowsTheRemoteDescriptor: the sign -all plan says each
// signature covers the fields shown, so a remote entry's plan row must show
// the auth descriptor and remote kind canonical/v4-remote signs.
func TestCmdSignAll_PlanShowsTheRemoteDescriptor(t *testing.T) {
	configPath := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
	var out, errb bytes.Buffer
	requireExit(t, cmdUpstream([]string{
		"register", "-config", configPath, "-name", "vendor", "-transport", "remote",
		"-url", "https://mcp.vendor.example/mcp", "-auth-kind", "header", "-auth-name", "X-Api-Key", "-env", "VENDOR_TOKEN",
	}, &out, &errb), exitOK, "register remote: "+errb.String())

	out.Reset()
	errb.Reset()
	requireExit(t, cmdSign([]string{"-config", configPath, "-all", "-dry-run"}, &out, &errb), exitOK, "sign -all -dry-run: "+errb.String())
	requireContains(t, out.String(), "header X-Api-Key: <secret>", "sign -all plan")
	requireContains(t, out.String(), "remote kind", "sign -all plan")
	requireContains(t, out.String(), "streamable", "sign -all plan")
}

// TestCmdUpstream_RemoteRefusals: what the console refuses for a remote
// entry before the database is opened.
func TestCmdUpstream_RemoteRefusals(t *testing.T) {
	base := []string{"register", "-name", "vendor", "-transport", "remote"}
	cases := map[string]struct {
		args []string
		want string
	}{
		"metadata literal": {[]string{"-url", "http://169.254.169.254/mcp"}, "egress refused"},
		"sse deferred":     {[]string{"-url", "https://mcp.vendor.example/mcp", "-remote-kind", "sse"}, "deferred, not a typo"},
		"openapi":          {[]string{"-url", "https://mcp.vendor.example/mcp", "-openapi", "x.json"}, "-openapi applies to -transport http only"},
		"query auth":       {[]string{"-url", "https://mcp.vendor.example/mcp", "-auth-kind", "query", "-auth-name", "k", "-env", "K"}, "auth kind"},
		"secret, no kind":  {[]string{"-url", "https://mcp.vendor.example/mcp", "-env", "K"}, "keyless"},
		"remote-kind on stdio": {
			[]string{"-transport", "stdio", "-command", "/bin/x", "-remote-kind", "streamable"},
			"-remote-kind applies to -transport remote only",
		},
	}
	for name, tc := range cases {
		var out, errb bytes.Buffer
		requireExit(t, cmdUpstream(append(append([]string{}, base...), tc.args...), &out, &errb), exitCannotRun, name)
		if !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%s: stderr = %q, want it to mention %q", name, errb.String(), tc.want)
		}
	}
}

// TestTransportDialer_RoutesRemote: the composition root sends a remote
// entry to the remote adapter -- refused here by its egress guard, which
// only that adapter applies to a remote URL -- and names all four
// transports when it refuses an unknown one.
func TestTransportDialer_RoutesRemote(t *testing.T) {
	d := newTransportDialer(&config.Config{}, nil)
	_, err := d.Dial(context.Background(), gateway.UpstreamSpec{
		Name: "vendor", Transport: string(registry.TransportRemote),
		URL: "http://127.0.0.1:1/mcp", RemoteKind: string(registry.RemoteStreamable),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "remotemcp") || !strings.Contains(err.Error(), "egress refused") {
		t.Fatalf("remote dial = %v, want the remote adapter's egress refusal", err)
	}
	_, err = d.Dial(context.Background(), gateway.UpstreamSpec{Name: "x", Transport: "websocket"}, nil)
	if err == nil || !strings.Contains(err.Error(), `"remote"`) {
		t.Fatalf("unknown transport = %v, want the four transports named", err)
	}
}
