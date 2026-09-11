package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every fixture in this file is real output copied from the jailmachine VM
// on 09 Sep 2026, not invented. Parsers are where the bugs are, and a
// parser tested against imagined text tests the imagination.

const jlsFixture = `jid name path host.hostname ip4.addr vnet
1 authelia /usr/local/bastille/jails/authelia/root authelia 10.17.89.20 inherit
5 mcp-gateway-test /usr/local/bastille/jails/mcp-gateway-test/root mcp-gateway-test - new
`

func TestParseJLS(t *testing.T) {
	recs, warns := parseJLS(jlsFixture)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}

	a := recs[0]
	if a.JID != 1 || a.Name != "authelia" || a.Hostname != "authelia" {
		t.Errorf("authelia row wrong: %+v", a)
	}
	if !reflect.DeepEqual(a.IP4, []string{"10.17.89.20"}) {
		t.Errorf("authelia ip4 = %v, want [10.17.89.20]", a.IP4)
	}
	if a.VNET {
		t.Error("authelia has vnet=inherit and must not be reported as VNET")
	}
	if !a.VNETKnown {
		t.Error("vnet was asked for and answered; VNETKnown must be true")
	}

	g := recs[1]
	if g.JID != 5 || g.Name != "mcp-gateway-test" {
		t.Errorf("gateway row wrong: %+v", g)
	}
	if !g.VNET {
		t.Error("mcp-gateway-test has vnet=new and must be reported as VNET")
	}
	// A VNET jail reports "-" for ip4.addr: its addresses are in its own
	// stack. Reading that as an address named "-" would poison the map.
	if len(g.IP4) != 0 {
		t.Errorf("vnet jail ip4 = %v, want none", g.IP4)
	}
}

func TestParseJLSWithoutVNETColumn(t *testing.T) {
	// The fallback query on a kernel with no VIMAGE.
	const out = `jid name path host.hostname ip4.addr
1 authelia /usr/local/bastille/jails/authelia/root authelia 10.17.89.20
`
	recs, warns := parseJLS(out)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].VNET {
		t.Error("no vnet column means we do not know; it must not be reported as VNET")
	}
	if recs[0].VNETKnown {
		t.Error("VNETKnown must be false so the caller can say so out loud")
	}
}

func TestParseJLSDegradesOnBadRows(t *testing.T) {
	const out = `jid name path host.hostname ip4.addr vnet
1 authelia /usr/local/bastille/jails/authelia/root authelia 10.17.89.20 inherit
this row is broken
x nope /p h - new
`
	recs, warns := parseJLS(out)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want only the good one", len(recs))
	}
	if len(warns) != 2 {
		t.Fatalf("got %d warnings, want 2 (short row, non-numeric jid): %v", len(warns), warns)
	}
	for _, w := range warns {
		if strings.Contains(w, "panic") {
			t.Errorf("warning should be a sentence, not a trace: %q", w)
		}
	}
}

func TestSplitAddrList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"-", nil},
		{"", nil},
		{"10.17.89.20", []string{"10.17.89.20"}},
		{"10.17.89.20,10.17.89.21", []string{"10.17.89.20", "10.17.89.21"}},
		{"lo0|127.0.1.10", []string{"127.0.1.10"}},
		{"bastille0|10.17.89.20/32", []string{"10.17.89.20"}},
	}
	for _, c := range cases {
		got := splitAddrList(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitAddrList(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Real `sockstat -4l -j 1` from the authelia jail: the plaintext listeners
// this tool has to make obvious.
const listenersAuthelia = `USER COMMAND     PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
www  nginx      3743  7 tcp4  10.17.89.20:80        *:*
www  nginx      3743  8 tcp4  10.17.89.20:443       *:*
root nginx      3742  7 tcp4  10.17.89.20:80        *:*
root nginx      3742  8 tcp4  10.17.89.20:443       *:*
root authelia   3687  8 tcp4  10.17.89.20:9091      *:*
`

// Real `sockstat -4l -j 0` from the host.
const listenersHost = `USER    COMMAND     PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
openvpn openvpn    9786  6 udp4  *:1194                *:*
root    sshd       2991  7 tcp4  *:22                  *:*
root    syslogd    2722  7 udp4  *:514                 *:*
`

// Real `sockstat -4l -j 5` from the VNET jail, taken from the HOST. The
// gateway's 127.0.0.1:8080 is genuinely private here, which is the whole
// point of ADR-0011's VNET resolution.
//
// Captured in the same instant as psFixture below, so pid 63090 is the same
// process in both -- which is what lets the process view cross-check its
// name-based inference against the socket table.
const listenersGateway = `USER  COMMAND      PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
mcpgw mcp-gatewa 63090 14 tcp4  127.0.0.1:8080        *:*
www   nginx      62489  7 tcp4  10.17.90.10:443       *:*
root  nginx      15272  7 tcp4  10.17.90.10:443       *:*
`

// Real `sockstat -4c -j 5` captured during live traffic through the
// gateway. The last three rows are the in-jail hop, and the "??" rows are
// exactly how sockstat reports a socket it cannot attribute.
const connsGateway = `USER COMMAND      PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
www  nginx      24319  3 tcp4  10.17.90.10:443       10.17.90.1:51217
www  nginx      24319  4 tcp4  10.17.90.10:443       10.17.90.1:52662
??   ??            ?? ?? tcp4  10.17.90.10:443       10.17.90.1:28855
??   ??            ?? ?? tcp4  127.0.0.1:26702       127.0.0.1:8080
??   ??            ?? ?? tcp4  127.0.0.1:27476       127.0.0.1:8080
??   ??            ?? ?? tcp4  127.0.0.1:50910       127.0.0.1:8080
`

func TestParseSockstatListeners(t *testing.T) {
	socks, warns := parseSockstat(listenersAuthelia)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(socks) != 5 {
		t.Fatalf("got %d sockets, want 5", len(socks))
	}
	first := socks[0]
	want := Socket{
		User: "www", Command: "nginx", PID: "3743", FD: "7", Proto: "tcp4",
		Local:   Endpoint{Addr: "10.17.89.20", Port: "80"},
		Foreign: Endpoint{Addr: "*", Port: "*"},
	}
	if first != want {
		t.Errorf("first listener = %+v, want %+v", first, want)
	}
	if !first.Attributed() {
		t.Error("a row with a real pid must be reported as attributed")
	}
}

func TestParseSockstatWildcardAndUDP(t *testing.T) {
	socks, _ := parseSockstat(listenersHost)
	if len(socks) != 3 {
		t.Fatalf("got %d sockets, want 3", len(socks))
	}
	if socks[0].Proto != "udp4" || socks[0].Local.Addr != "*" || socks[0].Local.Port != "1194" {
		t.Errorf("openvpn row = %+v", socks[0])
	}
}

func TestParseSockstatUnattributedRows(t *testing.T) {
	socks, warns := parseSockstat(connsGateway)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(socks) != 6 {
		t.Fatalf("got %d sockets, want 6", len(socks))
	}
	hop := socks[3]
	if hop.Local != (Endpoint{Addr: "127.0.0.1", Port: "26702"}) {
		t.Errorf("hop local = %+v", hop.Local)
	}
	if hop.Foreign != (Endpoint{Addr: "127.0.0.1", Port: "8080"}) {
		t.Errorf("hop foreign = %+v", hop.Foreign)
	}
	if hop.Attributed() {
		t.Error("a ?? row must not be reported as attributed")
	}
	if hop.Proto != "tcp4" {
		t.Errorf("hop proto = %q", hop.Proto)
	}
}

func TestParseSockstatCommandWithSpaces(t *testing.T) {
	// Fields are read from the right precisely so this cannot shift PROTO.
	const out = `USER COMMAND     PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
root some cmd    123  7 tcp4  127.0.0.1:8080        *:*
`
	socks, _ := parseSockstat(out)
	if len(socks) != 1 {
		t.Fatalf("got %d sockets, want 1", len(socks))
	}
	if socks[0].Command != "some cmd" || socks[0].PID != "123" || socks[0].Proto != "tcp4" {
		t.Errorf("row = %+v", socks[0])
	}
}

func TestParseSockstatEmptyIsNotAnError(t *testing.T) {
	// A jail with no connections prints only the header. That is a normal
	// answer, not a degradation.
	socks, warns := parseSockstat("USER COMMAND    PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS      \n")
	if len(socks) != 0 || len(warns) != 0 {
		t.Errorf("header-only output gave socks=%v warns=%v", socks, warns)
	}
}

func TestSplitEndpoint(t *testing.T) {
	cases := []struct{ in, addr, port string }{
		{"10.17.90.10:443", "10.17.90.10", "443"},
		{"127.0.0.1:8080", "127.0.0.1", "8080"},
		{"*:*", "*", "*"},
		{"*:1194", "*", "1194"},
		{"[::1]:8080", "::1", "8080"},
	}
	for _, c := range cases {
		got := splitEndpoint(c.in)
		if got.Addr != c.addr || got.Port != c.port {
			t.Errorf("splitEndpoint(%q) = %+v, want %s/%s", c.in, got, c.addr, c.port)
		}
	}
}

// Real host ifconfig. bastille0 is a LOOPBACK clone carrying the classic
// jail's address as a /32 alias -- the trap this whole tool is about.
const ifconfigHost = `vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	options=880028<VLAN_MTU,JUMBO_MTU,LINKSTATE,HWSTATS>
	ether 5a:94:ef:e4:0c:ee
	inet 192.168.127.2 netmask 0xffffff00 broadcast 192.168.127.255
	inet6 fe80::5894:efff:fee4:cee%vtnet0 prefixlen 64 scopeid 0x1
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
bastille0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
	inet 10.17.89.20 netmask 0xffffffff
tun0: flags=1008043<UP,BROADCAST,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 1500
	inet 10.8.0.1 netmask 0xffffff00 broadcast 10.8.0.255
socbr0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	inet 10.17.90.1 netmask 0xffffff00 broadcast 10.17.90.255
	member: e0a_mcpgw flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
e0a_mcpgw: flags=1008943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	ether 58:9c:fc:10:8b:84
`

// Real `jexec mcp-gateway-test ifconfig`: a genuinely private 127.0.0.1.
const ifconfigVNETJail = `lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
	inet 127.0.0.1 netmask 0xff000000
	inet6 ::1 prefixlen 128
vnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
	description: jail interface for socbr0
	ether 58:9c:fc:10:35:3a
	inet 10.17.90.10 netmask 0xffffff00 broadcast 10.17.90.255
`

func TestParseIfconfigHost(t *testing.T) {
	got := parseIfconfig(ifconfigHost)
	want := []IfAddr{
		{Iface: "vtnet0", Addr: "192.168.127.2"},
		{Iface: "lo0", Addr: "127.0.0.1", Loopback: true},
		{Iface: "bastille0", Addr: "10.17.89.20", Loopback: true},
		{Iface: "tun0", Addr: "10.8.0.1"},
		{Iface: "socbr0", Addr: "10.17.90.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIfconfig(host) =\n %+v\nwant\n %+v", got, want)
	}
}

func TestParseIfconfigJail(t *testing.T) {
	got := parseIfconfig(ifconfigVNETJail)
	want := []IfAddr{
		{Iface: "lo0", Addr: "127.0.0.1", Loopback: true},
		{Iface: "vnet0", Addr: "10.17.90.10"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIfconfig(vnet jail) = %+v, want %+v", got, want)
	}
}

// Real `ps -axo pid,ppid,jid,user,etime,command` from the jailmachine VM
// while a gateway with four spawned upstreams was serving. Kernel threads
// and the ssh session's own processes are elided; everything else is
// verbatim, including the daemon(8) supervisor line, which is the decoy the
// gateway-detection rule has to get right.
const psFixture = `  PID  PPID JID USER     ELAPSED COMMAND
    1     0   0 root    08:15:31 /sbin/init
  480     1   0 root    08:15:19 dhclient: system.syslog (dhclient)
 2722     1   0 root    08:14:57 /usr/sbin/syslogd -s
 3687  3686   1 root    08:14:55 /usr/local/bin/authelia --config /usr/local/etc/authelia.yml --config.experimental.filters template
 3742     1   1 root    08:14:55 nginx: master process /usr/local/sbin/nginx
 3743  3742   1 www     08:14:55 nginx: worker process (nginx)
 9786     1   0 openvpn 08:13:52 /usr/local/sbin/openvpn --cd /usr/local/etc/openvpn --daemon openvpn --config /usr/local/etc/openvpn/openvpn.conf
15272     1   5 root    08:04:40 nginx: master process /usr/local/sbin/nginx
62489 15272   5 www     04:40:10 nginx: worker process (nginx)
63089     1   5 1001    04:37:39 daemon: /usr/local/bin/mcp-gateway[63090] (daemon)
63090 63089   5 1001    04:37:39 /usr/local/bin/mcp-gateway serve -config /usr/local/etc/mcp-gateway/config.toml
63094 63090   5 1001    04:37:39 /usr/local/libexec/mcp-gateway/lab-logsearch
63095 63090   5 1001    04:37:39 /usr/local/libexec/mcp-gateway/lab-casemgmt
63096 63090   5 1001    04:37:39 /usr/local/libexec/mcp-gateway/lab-docsearch
63097 63090   5 1001    04:37:39 /usr/local/libexec/mcp-gateway/lab-threatintel
`

func TestParsePS(t *testing.T) {
	rows, warns := parsePS(psFixture)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(rows) != 15 {
		t.Fatalf("got %d rows, want 15", len(rows))
	}
	var gw ProcRow
	for _, r := range rows {
		if r.PID == 63090 {
			gw = r
		}
	}
	if gw.PPID != 63089 || gw.JID != 5 || gw.User != "1001" {
		t.Errorf("gateway row = %+v", gw)
	}
	// The command column contains spaces, which is exactly why it must be
	// taken as the remainder of the line rather than as one field.
	if gw.Command != "/usr/local/bin/mcp-gateway serve -config /usr/local/etc/mcp-gateway/config.toml" {
		t.Errorf("gateway command = %q", gw.Command)
	}
	if !gw.ElapsedKnown || gw.Elapsed != 4*time.Hour+37*time.Minute+39*time.Second {
		t.Errorf("gateway elapsed = %v (known=%v)", gw.Elapsed, gw.ElapsedKnown)
	}
}

func TestParsePSRefusesAHeaderItCannotTrust(t *testing.T) {
	// COMMAND not last: the position where the command starts is then
	// unknowable, and half-parsing a process list is worse than saying so.
	const out = `  PID COMMAND     JID
    1 /sbin/init    0
`
	rows, warns := parsePS(out)
	if len(rows) != 0 || len(warns) != 1 {
		t.Fatalf("rows=%v warns=%v", rows, warns)
	}
	if !strings.Contains(warns[0], "COMMAND") {
		t.Errorf("warning should name the problem: %q", warns[0])
	}
}

func TestParsePSSkipsBadRowsAndKeepsTheRest(t *testing.T) {
	const out = `  PID  PPID JID USER     ELAPSED COMMAND
    1     0   0 root    08:15:31 /sbin/init
short
    x     0   0 root    08:15:31 /sbin/nope
`
	rows, warns := parsePS(out)
	if len(rows) != 1 || rows[0].PID != 1 {
		t.Fatalf("rows = %+v, want only the good one", rows)
	}
	if len(warns) != 2 {
		t.Errorf("got %d warnings, want 2: %v", len(warns), warns)
	}
}

func TestParseEtime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"00:00", 0, true},
		{"00:02", 2 * time.Second, true},
		{"04:37:39", 4*time.Hour + 37*time.Minute + 39*time.Second, true},
		{"08:15:31", 8*time.Hour + 15*time.Minute + 31*time.Second, true},
		{"2-08:07:24", 2*24*time.Hour + 8*time.Hour + 7*time.Minute + 24*time.Second, true},
		{"", 0, false},
		{"nope", 0, false},
		{"1:2:3:4", 0, false},
	}
	for _, c := range cases {
		got, ok := parseEtime(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseEtime(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestProcName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/local/bin/mcp-gateway serve -config /x.toml", "mcp-gateway"},
		{"/usr/local/libexec/mcp-gateway/lab-logsearch", "lab-logsearch"},
		// The decoy: daemon(8) rewrites argv to a label that contains the
		// supervised binary's whole path. Matching a substring would call
		// this the gateway and hang the four real upstreams off the wrong
		// pid -- or off nothing, since they are not its children.
		{"daemon: /usr/local/bin/mcp-gateway[63090] (daemon)", "daemon:"},
		{"nginx: master process /usr/local/sbin/nginx", "nginx:"},
		{"[kernel]", "[kernel]"},
		{"", ""},
	}
	for _, c := range cases {
		if got := procName(c.in); got != c.want {
			t.Errorf("procName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Real `pfctl -s info` from the bun host (pf up) -- only the head, which is
// all that is read.
const pfInfoEnabled = `Status: Enabled for 0 days 00:12:18           Debug: Urgent

State Table                          Total             Rate
  current entries                       10
  searches                           14127           19.1/s
`

const pfInfoDisabled = `Status: Disabled                              Debug: Urgent

State Table                          Total             Rate
  current entries                        0
`

// Real `pfctl -s rules` from the bun host: a default-deny inbound policy
// with a handful of passes after it.
const pfRulesBun = `block drop in all
pass in on re0 inet proto udp from any port = bootps to any port = bootpc keep state
pass in on re0 inet proto tcp from 192.168.1.0/24 to (re0) port = ssh flags S/SA keep state
pass in inet proto icmp all keep state
pass in inet6 proto ipv6-icmp all keep state
pass out all flags S/SA keep state
pass on bridge0 all flags S/SA keep state
`

func TestParsePFInfo(t *testing.T) {
	if on, ok := parsePFInfo(pfInfoEnabled); !on || !ok {
		t.Errorf("enabled = %v,%v", on, ok)
	}
	if on, ok := parsePFInfo(pfInfoDisabled); on || !ok {
		t.Errorf("disabled = %v,%v", on, ok)
	}
	// "Cannot tell" must stay "cannot tell" and never collapse into either
	// answer -- that is the whole point of the second return value.
	if _, ok := parsePFInfo("pfctl: /dev/pf: No such file or directory\n"); ok {
		t.Error("unreadable pf must not be reported as a known state")
	}
	if _, ok := parsePFInfo(""); ok {
		t.Error("empty output must not be reported as a known state")
	}
}

func TestParsePFRulesFindsTheDefaultDeny(t *testing.T) {
	n, deny, rule := parsePFRules(pfRulesBun)
	if n != 7 {
		t.Errorf("rules = %d, want 7", n)
	}
	if !deny {
		t.Fatal("`block drop in all` is a default-deny inbound policy and must be recognised")
	}
	if rule != "block drop in all" {
		t.Errorf("deny rule = %q", rule)
	}
}

func TestParsePFRulesDoesNotInventADefaultDeny(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		// An empty ruleset with pf enabled filters nothing. Reading "pf is
		// on" as "pf is protecting you" is the error this guards.
		{"empty", ""},
		{"outbound only", "block drop out all\n"},
		// Conditional on an interface: a policy for one interface is not a
		// default policy, and jailmap does not evaluate which.
		{"interface qualified", "block drop in on re0 all\n"},
		{"protocol qualified", "block drop in proto tcp all\n"},
		{"address qualified", "block drop in from 10.0.0.0/8 to any\n"},
		{"pass only", "pass in all\npass out all\n"},
	}
	for _, c := range cases {
		if _, deny, _ := parsePFRules(c.in); deny {
			t.Errorf("%s: reported a default-deny it should not have (%q)", c.name, c.in)
		}
	}
}

func TestParsePFRulesAcceptsTheDecoratedForms(t *testing.T) {
	for _, in := range []string{
		"block in all\n",
		"block return in all\n",
		"block drop in log all\n",
		"block drop in quick all\n",
	} {
		if _, deny, _ := parsePFRules(in); !deny {
			t.Errorf("%q is a default-deny inbound policy", in)
		}
	}
}

func TestParseIfconfigIgnoresMemberLines(t *testing.T) {
	// "member: e0a_mcpgw flags=..." is indented and must not be mistaken
	// for the start of an interface block.
	for _, a := range parseIfconfig(ifconfigHost) {
		if a.Iface == "member" {
			t.Fatal("a bridge member line was parsed as an interface")
		}
	}
}
