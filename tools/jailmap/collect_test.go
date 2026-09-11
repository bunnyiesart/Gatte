package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner replays the real command output captured from the VM, so the
// collector can be driven end to end without a FreeBSD host.
type fakeRunner struct {
	out  map[string]string
	fail map[string]error

	mu   sync.Mutex // the collector samples jails concurrently
	seen []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	f.seen = append(f.seen, key)
	f.mu.Unlock()
	if err, ok := f.fail[key]; ok {
		return "", err
	}
	if out, ok := f.out[key]; ok {
		return out, nil
	}
	return "", errors.New(name + ": no such thing here")
}

func (f *fakeRunner) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

const (
	jlsCmd    = "jls -h jid name path host.hostname ip4.addr vnet"
	jlsNoVNET = "jls -h jid name path host.hostname ip4.addr"
	psCmd     = "ps -axo pid,ppid,jid,user,etime,command"
	pfInfoCmd = "pfctl -s info"
	pfRuleCmd = "pfctl -s rules"
)

func labRunner() *fakeRunner {
	return &fakeRunner{
		out: map[string]string{
			jlsCmd:                            jlsFixture,
			"ifconfig":                        ifconfigHost,
			"jexec mcp-gateway-test ifconfig": ifconfigVNETJail,
			"sockstat -4l -j 0":               listenersHost,
			"sockstat -4l -j 1":               listenersAuthelia,
			"sockstat -4l -j 5":               listenersGateway,
			"sockstat -4c -j 0":               "USER COMMAND    PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS\n",
			"sockstat -4c -j 1":               "USER COMMAND    PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS\n",
			"sockstat -4c -j 5":               connsGateway,
			psCmd:                             psFixture,
			pfInfoCmd:                         pfInfoEnabled,
			pfRuleCmd:                         pfRulesBun,
		},
		fail: map[string]error{},
	}
}

func TestCollectOnceBuildsTheWholeMap(t *testing.T) {
	run := labRunner()
	win := NewWindow(time.Minute)
	NewCollector(run, win, 100*time.Millisecond).CollectOnce(context.Background())

	snap := win.Snapshot(time.Now(), 100*time.Millisecond)
	if len(snap.Warnings) != 0 {
		t.Errorf("clean collection produced warnings: %v", snap.Warnings)
	}
	if len(snap.Participants) != 3 {
		t.Fatalf("got %d participants, want 3", len(snap.Participants))
	}
	if snap.Participants[0].Name != "host" || snap.Participants[0].Kind != KindHost {
		t.Errorf("participant 0 = %+v, want the host first", snap.Participants[0])
	}
	if snap.Participants[1].Kind != KindClassic {
		t.Errorf("authelia kind = %q, want classic", snap.Participants[1].Kind)
	}
	if snap.Participants[2].Kind != KindVNET {
		t.Errorf("mcp-gateway-test kind = %q, want vnet", snap.Participants[2].Kind)
	}

	// The VNET jail's addresses can only come from jexec ifconfig; a
	// collector that skipped that call would show it with no addresses.
	var haveJailAddr, haveJailLoopback bool
	for _, a := range snap.Participants[2].Addrs {
		if a.Addr == "10.17.90.10" {
			haveJailAddr = true
		}
		if a.Addr == "127.0.0.1" && a.Loopback {
			haveJailLoopback = true
		}
	}
	if !haveJailAddr || !haveJailLoopback {
		t.Errorf("VNET jail addresses = %+v; want 10.17.90.10 and its own 127.0.0.1", snap.Participants[2].Addrs)
	}

	// And the payoff: the in-jail hop, both ends named, from raw command
	// output through parsing, resolution and the window.
	f := findFlow(snap, "26702", "8080")
	if f == nil {
		t.Fatal("the in-jail nginx -> 127.0.0.1:8080 hop did not survive a full collection")
	}
	if f.Scope != ScopeInJail || f.Server.Name != "mcp-gateway-test" {
		t.Errorf("hop = %+v", f)
	}
}

// The collector must read sockets for every jail from the host: sockstat -j
// works for a VNET jail too, and jexec is only needed for its addresses.
func TestCollectorUsesJexecOnlyForVNETAddresses(t *testing.T) {
	run := labRunner()
	NewCollector(run, NewWindow(time.Minute), time.Second).CollectOnce(context.Background())

	jexecCalls := 0
	for _, c := range run.calls() {
		if strings.HasPrefix(c, "jexec ") {
			jexecCalls++
			if !strings.HasSuffix(c, " ifconfig") {
				t.Errorf("jexec was used for something other than ifconfig: %q", c)
			}
		}
	}
	if jexecCalls != 1 {
		t.Errorf("got %d jexec calls, want exactly one (the VNET jail's addresses)", jexecCalls)
	}
	for _, want := range []string{"sockstat -4c -j 0", "sockstat -4c -j 1", "sockstat -4c -j 5"} {
		found := false
		for _, c := range run.calls() {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q was never run; sockets must be sampled from the host for every jid", want)
		}
	}
}

func TestStoppedJailDegradesToAWarning(t *testing.T) {
	run := labRunner()
	run.fail["sockstat -4c -j 5"] = errors.New("sockstat: jail 5: No such file or directory")
	run.fail["jexec mcp-gateway-test ifconfig"] = errors.New("jexec: jail not found")

	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	// The other jails still answer, and the jail that did not is named.
	if len(snap.Participants) != 3 {
		t.Fatalf("got %d participants; one failing jail must not remove the rest", len(snap.Participants))
	}
	if len(snap.Listeners) == 0 {
		t.Error("listeners for the healthy jails disappeared because one jail failed")
	}
	joined := strings.Join(snap.Warnings, "\n")
	if !strings.Contains(joined, "jid 5") || !strings.Contains(joined, "jail not found") {
		t.Errorf("warnings do not name the failure clearly:\n%s", joined)
	}
	var note string
	for _, p := range snap.Participants {
		if p.Name == "mcp-gateway-test" {
			note = strings.Join(p.Notes, " ")
		}
	}
	if !strings.Contains(note, "addresses unavailable") {
		t.Errorf("the jail whose addresses could not be read says %q", note)
	}
}

func TestMissingJlsIsAMessageNotACrash(t *testing.T) {
	run := &fakeRunner{out: map[string]string{"ifconfig": ifconfigHost}, fail: map[string]error{}}
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())

	snap := win.Snapshot(time.Now(), time.Second)
	if len(snap.Participants) != 1 || snap.Participants[0].Name != "host" {
		t.Fatalf("participants = %+v, want the host alone", snap.Participants)
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "cannot list jails") {
		t.Errorf("warnings = %v, want a plain sentence about jls", snap.Warnings)
	}
}

func TestJlsWithoutVNETParameterFallsBack(t *testing.T) {
	run := labRunner()
	run.fail[jlsCmd] = errors.New("jls: unknown parameter: vnet")
	run.out[jlsNoVNET] = `jid name path host.hostname ip4.addr
1 authelia /usr/local/bastille/jails/authelia/root authelia 10.17.89.20
`
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	if len(snap.Participants) != 2 {
		t.Fatalf("got %d participants, want host + authelia", len(snap.Participants))
	}
	if snap.Participants[1].Kind != KindClassic {
		t.Errorf("kind = %q; with no vnet parameter every jail is classic", snap.Participants[1].Kind)
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "no vnet parameter") {
		t.Errorf("the fallback must say so: %v", snap.Warnings)
	}
}

// Regression: a `snapshot -for 6s` run used to end by printing three
// "sockstat: timed out after 3s" warnings, which described nothing except
// jailmap killing its own last commands on the way out. A degradation
// report that cries wolf on every clean exit is worse than none.
func TestShutdownIsNotReportedAsADegradation(t *testing.T) {
	run := labRunner()
	for _, k := range []string{"sockstat -4c -j 0", "sockstat -4c -j 1", "sockstat -4c -j 5", "jexec mcp-gateway-test ifconfig"} {
		run.fail[k] = errAborted
	}
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())

	if warns := win.Snapshot(time.Now(), time.Second).Warnings; len(warns) != 0 {
		t.Errorf("an aborted collection reported %v", warns)
	}
}

// The other half: a real failure must still be reported.
func TestRealFailureIsStillReported(t *testing.T) {
	run := labRunner()
	run.fail["sockstat -4c -j 5"] = errors.New("sockstat: timed out after 3s")
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())

	warns := win.Snapshot(time.Now(), time.Second).Warnings
	if len(warns) != 1 || !strings.Contains(warns[0], "timed out") {
		t.Errorf("warnings = %v, want the real timeout", warns)
	}
}

// The point of the whole process view: four MCP upstreams that own no
// socket at all, found end to end from raw ps output.
func TestCollectOnceFindsTheSpawnedMCPUpstreams(t *testing.T) {
	run := labRunner()
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	if len(snap.Gateways) != 1 {
		t.Fatalf("got %d gateways, want 1: %+v", len(snap.Gateways), snap.Gateways)
	}
	g := snap.Gateways[0]
	if g.PID != 63090 {
		t.Errorf("gateway pid = %d, want 63090 (not 63089, the daemon(8) supervisor)", g.PID)
	}
	if g.Owner != "mcp-gateway-test" || g.Kind != KindVNET {
		t.Errorf("gateway owner = %q/%q, want the VNET jail it runs in", g.Owner, g.Kind)
	}
	// The independent check: sockstat attributes 127.0.0.1:8080 to the same
	// pid the name match picked.
	if len(g.ListensOn) != 1 || !strings.Contains(g.ListensOn[0], "127.0.0.1:8080") {
		t.Errorf("gateway listens_on = %v, want the observed 8080 listener", g.ListensOn)
	}

	var names []string
	for _, u := range g.Upstreams {
		names = append(names, u.Name)
	}
	want := []string{"lab-logsearch", "lab-casemgmt", "lab-docsearch", "lab-threatintel"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("upstreams = %v, want %v", names, want)
	}
	if g.Upstreams[0].PID != 63094 || g.Upstreams[0].UptimeSeconds == 0 {
		t.Errorf("first upstream = %+v", g.Upstreams[0])
	}

	// And the constraint that keeps the display honest: none of this may
	// leak into the connection graph. A pipe is not a TCP edge.
	for _, e := range snap.Edges {
		for _, n := range want {
			if strings.Contains(e.Client, n) || strings.Contains(e.Server, n) || strings.Contains(e.Process, n) {
				t.Errorf("an MCP upstream appeared as a network edge: %+v", e)
			}
		}
	}
}

// A host with no gateway is a normal answer, not a failure.
func TestNoGatewayRunningIsAnEmptySectionNotAnError(t *testing.T) {
	run := labRunner()
	run.out[psCmd] = `  PID  PPID JID USER     ELAPSED COMMAND
    1     0   0 root    08:15:31 /sbin/init
 3742     1   1 root    08:14:55 nginx: master process /usr/local/sbin/nginx
`
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	if len(snap.Gateways) != 0 {
		t.Errorf("gateways = %+v, want none", snap.Gateways)
	}
	if snap.GatewaysSeen.IsZero() {
		t.Error("the process table was read; the snapshot must say when, so an empty section reads as 'none' and not as 'not looked'")
	}
	if len(snap.Warnings) != 0 {
		t.Errorf("no gateway is not a degradation: %v", snap.Warnings)
	}
}

func TestUnreadableProcessTableDegradesToAWarning(t *testing.T) {
	run := labRunner()
	run.fail[psCmd] = errors.New("ps: Operation not permitted")

	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	if len(snap.Listeners) == 0 || len(snap.Participants) != 3 {
		t.Error("a failing ps must not take the rest of the map with it")
	}
	if !strings.Contains(strings.Join(snap.Warnings, "\n"), "process tree unavailable") {
		t.Errorf("warnings = %v", snap.Warnings)
	}
	if !snap.GatewaysSeen.IsZero() {
		t.Error("a failed read must not be recorded as a successful one")
	}
}

func TestFirewallIsReadAndSummarised(t *testing.T) {
	run := labRunner()
	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	fw := snap.Firewall
	if !fw.Known || !fw.Enabled || !fw.RulesKnown || !fw.DefaultDenyIn || fw.Rules != 7 {
		t.Fatalf("firewall = %+v", fw)
	}
	if !strings.Contains(fw.Summary, "default-deny") {
		t.Errorf("summary = %q", fw.Summary)
	}
}

// pf is read with `pfctl -s`, which needs no write access, and jailmap must
// never reach for any other pfctl mode.
func TestFirewallIsOnlyEverReadWithDashS(t *testing.T) {
	run := labRunner()
	NewCollector(run, NewWindow(time.Minute), time.Second).CollectOnce(context.Background())
	for _, c := range run.calls() {
		if strings.HasPrefix(c, "pfctl") && !strings.HasPrefix(c, "pfctl -s ") {
			t.Errorf("jailmap ran %q", c)
		}
	}
}

func TestUnreadablePFIsSaidOutLoudRatherThanAssumed(t *testing.T) {
	run := labRunner()
	run.fail[pfInfoCmd] = errors.New("pfctl: /dev/pf: No such file or directory")

	win := NewWindow(time.Minute)
	NewCollector(run, win, time.Second).CollectOnce(context.Background())
	snap := win.Snapshot(time.Now(), time.Second)

	if snap.Firewall.Known {
		t.Fatal("pf that could not be read must not be reported as a known state")
	}
	if !strings.Contains(snap.Firewall.Summary, "could not be read") {
		t.Errorf("summary = %q", snap.Firewall.Summary)
	}
	// A host that simply has no pf must not carry a permanent DEGRADED line.
	if len(snap.Warnings) != 0 {
		t.Errorf("absent pf is not a degradation: %v", snap.Warnings)
	}
	// And every routable listener must say "unknown", not "fine".
	for _, l := range snap.Listeners {
		if l.Exposure != ExposureLocal && l.Reachability != ReachUnknown {
			t.Errorf("listener %s:%s reachability = %q, want unknown", l.Addr, l.Port, l.Reachability)
		}
	}
}

// The read-only contract, enforced rather than documented.
func TestRunnerRefusesAnythingThatCouldChangeSomething(t *testing.T) {
	r := execRunner{timeout: time.Second}
	for _, c := range [][]string{
		{"service", "nginx", "restart"},
		{"bastille", "stop", "authelia"},
		{"pfctl", "-d"},
		{"sh", "-c", "true"},
		{"jail", "-r", "5"},
	} {
		if _, err := r.Run(context.Background(), c[0], c[1:]...); err == nil {
			t.Errorf("execRunner ran %v", c)
		} else if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("refusal for %v should say why: %v", c, err)
		}
	}

	// jexec, pfctl and ps take arguments that decide what they do, so each
	// is pinned to the exact call jailmap needs. These are the ways the
	// read-only property could leak through a whitelisted program name.
	for _, c := range [][]string{
		{"jexec", "authelia", "service", "nginx", "restart"},
		{"jexec", "authelia", "sh"},
		{"jexec", "authelia"},
		// pfctl is on the list because `pfctl -s` reports; every other mode
		// of the same binary writes.
		{"pfctl", "-e"},
		{"pfctl", "-F", "rules"},
		{"pfctl", "-f", "/etc/pf.conf"},
		{"pfctl", "-s", "info", "-f", "/etc/pf.conf"},
		{"pfctl", "-sinfo"},
		{"pfctl"},
		{"ps", "-axo", "command", "-U", "root"},
		{"ps", "-axo", "pid,command"}, // any other format is still refused
		{"ps"},
	} {
		if _, err := r.Run(context.Background(), c[0], c[1:]...); err == nil {
			t.Errorf("execRunner ran %v", c)
		} else if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("refusal for %v should say why: %v", c, err)
		}
	}

	// The other half: the calls jailmap does make must not be refused. They
	// may well fail on the machine running the test -- there is no pf on a
	// Mac and no jails -- but they must fail as commands, not as policy.
	for _, c := range [][]string{
		{"pfctl", "-s", "info"},
		{"pfctl", "-s", "rules"},
		{"ps", "-axo", psFormat},
	} {
		if _, err := r.Run(context.Background(), c[0], c[1:]...); err != nil && strings.Contains(err.Error(), "refuses") {
			t.Errorf("execRunner refused its own call %v: %v", c, err)
		}
	}
}
