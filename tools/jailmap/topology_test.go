package main

import (
	"strings"
	"testing"
)

// labTopology is the real jailmachine layout: the host, one classic jail
// on a loopback-clone alias, and one VNET jail with its own stack.
func labTopology() *Topology {
	host := Participant{
		JID: 0, Name: "host", Kind: KindHost,
		Addrs: []Address{
			{Addr: "192.168.127.2", Iface: "vtnet0"},
			{Addr: "127.0.0.1", Iface: "lo0", Loopback: true},
			{Addr: "10.17.89.20", Iface: "bastille0", Loopback: true},
			{Addr: "10.8.0.1", Iface: "tun0"},
			{Addr: "10.17.90.1", Iface: "socbr0"},
		},
	}
	jails := []Participant{
		{
			JID: 1, Name: "authelia", Kind: KindClassic,
			Addrs: []Address{{Addr: "10.17.89.20", Iface: "bastille0"}},
		},
		{
			JID: 5, Name: "mcp-gateway-test", Kind: KindVNET,
			Addrs: []Address{
				{Addr: "127.0.0.1", Iface: "lo0", Loopback: true},
				{Addr: "10.17.90.10", Iface: "vnet0"},
			},
		},
	}
	return NewTopology(host, jails)
}

// This is the test the whole design turns on.
//
// 127.0.0.1 is not a global fact. The same string means the VNET jail's
// private loopback when a socket carrying it was observed under jid 5, and
// the host's loopback when it was observed under jid 0. Resolving it from a
// global table would file the nginx -> mcp-gateway hop inside
// mcp-gateway-test -- the hop ADR-0011 exists to force -- as host traffic,
// and the tool would be confidently, silently wrong about the one edge it
// was built to show.
func TestVNETJailLoopbackResolvesToTheJailNotTheHost(t *testing.T) {
	topo := labTopology()

	inJail := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "8080"}, 5)
	if inJail.Name != "mcp-gateway-test" {
		t.Errorf("127.0.0.1:8080 under jid 5 resolved to %q, want mcp-gateway-test", inJail.Name)
	}
	if !inJail.Loopback {
		t.Error("the resolution must be marked as loopback")
	}
	if inJail.Unknown {
		t.Error("the jail's own loopback is not unknown")
	}

	onHost := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "8080"}, 0)
	if onHost.Name != "host" {
		t.Errorf("127.0.0.1:8080 under jid 0 resolved to %q, want host", onHost.Name)
	}

	if inJail.Name == onHost.Name {
		t.Fatal("the same loopback address resolved to the same participant from two different stacks")
	}
}

// The mirror image: a classic jail's address lives on the host's bastille0
// as a /32 alias, so it is in the host's own ifconfig. The jail still owns
// it, and traffic to it is traffic to the jail.
func TestClassicJailAddressBeatsTheHostAlias(t *testing.T) {
	topo := labTopology()
	r := topo.Resolve(Endpoint{Addr: "10.17.89.20", Port: "9091"}, 1)
	if r.Name != "authelia" {
		t.Errorf("10.17.89.20 resolved to %q, want authelia", r.Name)
	}
	// And from any other observer, too: the address book is global for
	// routable addresses.
	if r2 := topo.Resolve(Endpoint{Addr: "10.17.89.20", Port: "9091"}, 5); r2.Name != "authelia" {
		t.Errorf("10.17.89.20 seen from jid 5 resolved to %q, want authelia", r2.Name)
	}
}

func TestHostOwnAddressesResolveToHost(t *testing.T) {
	topo := labTopology()
	for _, addr := range []string{"192.168.127.2", "10.8.0.1", "10.17.90.1"} {
		if r := topo.Resolve(Endpoint{Addr: addr, Port: "1"}, 0); r.Name != "host" {
			t.Errorf("%s resolved to %q, want host", addr, r.Name)
		}
	}
}

func TestUnknownAddressIsNeverGuessed(t *testing.T) {
	topo := labTopology()
	// A VPN client and the workstation behind the VM's NAT. Both are
	// plausible to label and must not be labelled.
	for _, addr := range []string{"10.8.0.6", "192.168.127.1", "8.8.8.8"} {
		r := topo.Resolve(Endpoint{Addr: addr, Port: "51775"}, 0)
		if !r.Unknown {
			t.Errorf("%s was resolved to %q; it belongs to nobody in the address book", addr, r.Name)
		}
		if r.Name != "" {
			t.Errorf("%s got a name %q despite being unknown", addr, r.Name)
		}
		if displayName(r) != addr {
			t.Errorf("an unknown end must display as its address, got %q", displayName(r))
		}
	}
}

func TestWildcardResolvesToTheObserver(t *testing.T) {
	topo := labTopology()
	r := topo.Resolve(Endpoint{Addr: "*", Port: "22"}, 0)
	if r.Name != "host" || !r.Wildcard {
		t.Errorf("*:22 under jid 0 = %+v, want host/wildcard", r)
	}
}

func TestResolveUnknownObserverDoesNotPanic(t *testing.T) {
	topo := labTopology()
	// A jail that appeared between the topology refresh and the socket
	// sample. Degrade, do not crash.
	r := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "1"}, 99)
	if !r.Unknown {
		t.Errorf("loopback under an unknown observer = %+v, want unknown", r)
	}
}

func TestClassifyExposure(t *testing.T) {
	topo := labTopology()

	// The two that must be obvious: Authelia's cleartext HTTP on an address
	// the VPN can route to.
	for _, port := range []string{"80", "9091"} {
		r := topo.Resolve(Endpoint{Addr: "10.17.89.20", Port: port}, 1)
		if got := classifyExposure(r, port, KindClassic); got != ExposurePlaintext {
			t.Errorf("10.17.89.20:%s classified %q, want %q", port, got, ExposurePlaintext)
		}
	}

	// nginx on 443: reachable, but not in the clear.
	r443 := topo.Resolve(Endpoint{Addr: "10.17.90.10", Port: "443"}, 5)
	if got := classifyExposure(r443, "443", KindVNET); got != ExposureEncrypted {
		t.Errorf("10.17.90.10:443 classified %q, want %q", got, ExposureEncrypted)
	}

	// The gateway on a VNET jail's real loopback: genuinely local.
	rgw := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "8080"}, 5)
	if got := classifyExposure(rgw, "8080", KindVNET); got != ExposureLocal {
		t.Errorf("127.0.0.1:8080 in a VNET jail classified %q, want %q", got, ExposureLocal)
	}

	// The same bind inside a CLASSIC jail is not local at all -- the kernel
	// rewrites it to the routable address. If it is ever observed, say so.
	rclassic := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "8080"}, 1)
	if got := classifyExposure(rclassic, "8080", KindClassic); got != ExposureRewritten {
		t.Errorf("127.0.0.1:8080 in a classic jail classified %q, want %q", got, ExposureRewritten)
	}

	// Wildcard binds: syslog in the clear, ssh not.
	rsys := topo.Resolve(Endpoint{Addr: "*", Port: "514"}, 0)
	if got := classifyExposure(rsys, "514", KindHost); got != ExposurePlaintext {
		t.Errorf("*:514 classified %q, want %q", got, ExposurePlaintext)
	}
	rssh := topo.Resolve(Endpoint{Addr: "*", Port: "22"}, 0)
	if got := classifyExposure(rssh, "22", KindHost); got != ExposureEncrypted {
		t.Errorf("*:22 classified %q, want %q", got, ExposureEncrypted)
	}
}

func TestClassifyScope(t *testing.T) {
	topo := labTopology()

	client := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "26702"}, 5)
	server := topo.Resolve(Endpoint{Addr: "127.0.0.1", Port: "8080"}, 5)
	if got := classifyScope(client, server); got != ScopeInJail {
		t.Errorf("the in-jail hop classified %q, want %q", got, ScopeInJail)
	}

	hostSide := topo.Resolve(Endpoint{Addr: "10.17.90.1", Port: "51217"}, 5)
	jailSide := topo.Resolve(Endpoint{Addr: "10.17.90.10", Port: "443"}, 5)
	if got := classifyScope(hostSide, jailSide); got != ScopeInternal {
		t.Errorf("host -> jail classified %q, want %q", got, ScopeInternal)
	}

	outside := topo.Resolve(Endpoint{Addr: "192.168.127.1", Port: "51775"}, 0)
	sshd := topo.Resolve(Endpoint{Addr: "192.168.127.2", Port: "22"}, 0)
	if got := classifyScope(outside, sshd); got != ScopeExternal {
		t.Errorf("outside -> host classified %q, want %q", got, ScopeExternal)
	}
}

// ---------------------------------------------------------------------------
// The MCP process tree.
// ---------------------------------------------------------------------------

func mustRows(t *testing.T, out string) []ProcRow {
	t.Helper()
	rows, warns := parsePS(out)
	if len(warns) != 0 {
		t.Fatalf("fixture did not parse cleanly: %v", warns)
	}
	return rows
}

func TestFindGatewaysAnchorsOnTheExecutableNotASubstring(t *testing.T) {
	gws := findGateways(mustRows(t, psFixture), DefaultGatewayCommand)
	if len(gws) != 1 {
		t.Fatalf("got %d gateways, want 1: %+v", len(gws), gws)
	}
	g := gws[0]
	// 63089 is `daemon: /usr/local/bin/mcp-gateway[63090] (daemon)`. Its
	// argv contains the gateway's path, so a substring match would pick it
	// -- and then hang no upstreams off it, because the four real children
	// belong to 63090. Matching argv[0]'s basename gets the right one.
	if g.PID != 63090 {
		t.Fatalf("gateway pid = %d, want 63090", g.PID)
	}
	if len(g.Upstreams) != 4 {
		t.Fatalf("got %d upstreams, want 4: %+v", len(g.Upstreams), g.Upstreams)
	}
	if g.Upstreams[0].Name != "lab-logsearch" || g.Upstreams[3].Name != "lab-threatintel" {
		t.Errorf("upstreams = %+v (must be sorted by pid)", g.Upstreams)
	}
	// Everything else in the same jail -- nginx, cron, syslogd -- is not a
	// child of the gateway and must not be listed as an upstream.
	for _, u := range g.Upstreams {
		if u.Name == "nginx:" || u.Name == "nginx" {
			t.Errorf("a jail neighbour was reported as an MCP upstream: %+v", u)
		}
	}
}

func TestFindGatewaysIgnoresChildrenInAnotherJail(t *testing.T) {
	const out = `  PID  PPID JID USER     ELAPSED COMMAND
  100     1   5 mcpgw   01:00:00 /usr/local/bin/mcp-gateway serve
  101   100   5 mcpgw   01:00:00 /usr/local/libexec/mcp-gateway/lab-casemgmt
  102   100   9 mcpgw   01:00:00 /usr/local/libexec/other/thing
`
	gws := findGateways(mustRows(t, out), DefaultGatewayCommand)
	if len(gws) != 1 || len(gws[0].Upstreams) != 1 || gws[0].Upstreams[0].PID != 101 {
		t.Errorf("gateways = %+v; a child in another jail is not a stdio upstream of this one", gws)
	}
}

func TestFindGatewaysReportsAGatewayWithNoChildren(t *testing.T) {
	const out = `  PID  PPID JID USER     ELAPSED COMMAND
  100     1   5 mcpgw   00:00:04 /usr/local/bin/mcp-gateway serve
`
	gws := findGateways(mustRows(t, out), DefaultGatewayCommand)
	if len(gws) != 1 {
		t.Fatalf("a running gateway that has spawned nothing is still a fact: %+v", gws)
	}
	if gws[0].Upstreams == nil || len(gws[0].Upstreams) != 0 {
		t.Errorf("upstreams = %+v, want an empty list", gws[0].Upstreams)
	}
}

func TestFindGatewaysCountsButDoesNotListDescendants(t *testing.T) {
	const out = `  PID  PPID JID USER     ELAPSED COMMAND
  100     1   5 mcpgw   01:00:00 /usr/local/bin/mcp-gateway serve
  101   100   5 mcpgw   01:00:00 /usr/local/libexec/mcp-gateway/lab-casemgmt
  102   101   5 mcpgw   01:00:00 /usr/local/bin/helper
  103   102   5 mcpgw   01:00:00 /usr/local/bin/helper-helper
`
	gws := findGateways(mustRows(t, out), DefaultGatewayCommand)
	if len(gws[0].Upstreams) != 1 {
		t.Fatalf("only direct children are upstreams: %+v", gws[0].Upstreams)
	}
	if gws[0].Upstreams[0].Descendants != 2 {
		t.Errorf("descendants = %d, want 2", gws[0].Upstreams[0].Descendants)
	}
}

func TestFindGatewaysSurvivesACycleInTheProcessTable(t *testing.T) {
	// Should not happen; must not hang if it does.
	const out = `  PID  PPID JID USER     ELAPSED COMMAND
  100     1   5 mcpgw   01:00:00 /usr/local/bin/mcp-gateway serve
  101   102   5 mcpgw   01:00:00 /usr/local/libexec/a
  102   101   5 mcpgw   01:00:00 /usr/local/libexec/b
`
	if gws := findGateways(mustRows(t, out), DefaultGatewayCommand); len(gws) != 1 {
		t.Errorf("gateways = %+v", gws)
	}
}

func TestFindGatewaysHonoursADifferentExecutableName(t *testing.T) {
	const out = `  PID  PPID JID USER     ELAPSED COMMAND
  100     1   5 mcpgw   01:00:00 /opt/bin/gw serve
  101   100   5 mcpgw   01:00:00 /opt/libexec/lab-casemgmt
`
	if gws := findGateways(mustRows(t, out), "gw"); len(gws) != 1 || len(gws[0].Upstreams) != 1 {
		t.Errorf("gateways = %+v", gws)
	}
	if gws := findGateways(mustRows(t, out), DefaultGatewayCommand); len(gws) != 0 {
		t.Errorf("a binary by another name must not be guessed at: %+v", gws)
	}
}

// ---------------------------------------------------------------------------
// pf-qualified exposure.
// ---------------------------------------------------------------------------

func TestClassifyReachability(t *testing.T) {
	denyAll := Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true, Rules: 7,
		DefaultDenyIn: true, DenyRule: "block drop in all"}
	openPF := Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true, Rules: 0}
	offPF := Firewall{Engine: "pf", Known: true}
	unreadable := Firewall{Engine: "pf"}
	opaque := Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true, Rules: 12}

	cases := []struct {
		name string
		e    Exposure
		k    Kind
		fw   Firewall
		want Reachability
	}{
		// The bug this fixes: syslogd on *:514 on the bun host, where pf
		// drops all inbound. A true statement about the bind, a false alarm
		// about the exposure.
		{"host plaintext behind default-deny", ExposurePlaintext, KindHost, denyAll, ReachFiltered},
		// pf enabled with an empty ruleset filters nothing. "pf is on" is
		// not the same fact as "pf is protecting this port".
		{"host plaintext, pf enabled but empty", ExposurePlaintext, KindHost, openPF, ReachUnfiltered},
		{"host plaintext, pf off", ExposurePlaintext, KindHost, offPF, ReachUnfiltered},
		{"host plaintext, pf unreadable", ExposurePlaintext, KindHost, unreadable, ReachUnknown},
		// A ruleset jailmap declines to evaluate is "unknown", not "fine".
		{"host plaintext, opaque ruleset", ExposurePlaintext, KindHost, opaque, ReachUnknown},
		// A classic jail's addresses are aliases on host interfaces, so the
		// host ruleset is the one that governs them.
		{"classic jail behind default-deny", ExposurePlaintext, KindClassic, denyAll, ReachFiltered},
		// A VNET jail has its own pf instance. Applying the host's verdict
		// there would be the overclaim in the other direction.
		{"vnet jail behind host default-deny", ExposurePlaintext, KindVNET, denyAll, ReachUnknown},
		// Loopback of a private stack: the question does not arise.
		{"local", ExposureLocal, KindVNET, denyAll, ReachNA},
		{"encrypted still gets qualified", ExposureEncrypted, KindHost, denyAll, ReachFiltered},
	}
	for _, c := range cases {
		got, note := classifyReachability(c.e, c.k, c.fw)
		if got != c.want {
			t.Errorf("%s: reachability = %q, want %q", c.name, got, c.want)
		}
		if c.want != ReachNA && note == "" {
			t.Errorf("%s: a verdict with no reason given is not much of a verdict", c.name)
		}
	}
}

func TestSummarizeFirewallNeverGuesses(t *testing.T) {
	cases := []struct {
		fw   Firewall
		want string
	}{
		{Firewall{Engine: "pf"}, "could not be read"},
		{Firewall{Engine: "pf", Known: true}, "disabled"},
		{Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true}, "empty"},
		{Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true, Rules: 7,
			DefaultDenyIn: true, DenyRule: "block drop in all"}, "default-deny"},
		{Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true, Rules: 7}, "unknown"},
	}
	for _, c := range cases {
		if got := summarizeFirewall(c.fw); !strings.Contains(got, c.want) {
			t.Errorf("summarizeFirewall(%+v) = %q, want it to mention %q", c.fw, got, c.want)
		}
	}
}
