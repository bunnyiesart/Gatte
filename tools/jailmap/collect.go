// Package main -- jailmap collector.
//
// STRICTLY READ-ONLY. The complete list of commands this file will ever
// run is in readOnlyCommands below, and every one of them is an
// enumeration: jls, sockstat, ifconfig, ps, `pfctl -s`, and ifconfig inside
// a jail via jexec. There is no code path here that starts, stops,
// restarts, reconfigures or writes to anything.
package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// readOnlyCommands is the whole of jailmap's interaction with the system.
// It is written down so that "read-only" is checkable rather than claimed:
// runner.Run refuses anything not on this list.
var readOnlyCommands = map[string]bool{
	"jls":      true,
	"sockstat": true,
	"ifconfig": true,
	"ps":       true, // only ever `ps -axo <fixed format>`, enforced below
	"pfctl":    true, // only ever `pfctl -s info|rules`, enforced below
	"jexec":    true, // only ever with `ifconfig` as the command, enforced below
}

// pfctlReports are the only `pfctl -s` reports jailmap will ask for. pfctl
// is the one command on the list whose name is also the name of the tool
// that turns the firewall off, so it is pinned twice: to -s, which is
// pfctl's read-only mode, and to these two reports.
var pfctlReports = map[string]bool{
	"info":  true,
	"rules": true,
}

// Runner runs one enumeration command and returns its stdout.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execRunner struct {
	timeout time.Duration
}

// errAborted is returned when the collection context ended while a command
// was in flight -- jailmap shutting down, or a timed `snapshot -for` run
// reaching its deadline. It is not a fault of the host and must not be
// reported as one: before this was separated out, the last tick of every
// `snapshot -for` run printed three "sockstat: timed out" warnings that
// described nothing but jailmap's own exit.
var errAborted = errors.New("collection aborted")

func (r execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if !readOnlyCommands[name] {
		return "", fmt.Errorf("jailmap refuses to run %q: not one of its read-only enumeration commands", name)
	}
	// Three of the six take arguments that could change what they do, so
	// each is pinned to the exact invocation jailmap needs. The list above
	// says which programs; these say which calls.
	switch name {
	case "jexec":
		// jexec is the one command that takes another command as an
		// argument, so it is the one place the property could be lost.
		if len(args) < 2 || args[len(args)-1] != "ifconfig" {
			return "", fmt.Errorf("jailmap refuses this jexec: it is read-only and only ever runs `jexec <jail> ifconfig`")
		}
	case "pfctl":
		// `pfctl -s <report>` needs no write access to the firewall.
		// `pfctl -d`, `-e`, `-f` and `-F` do, and are refused here rather
		// than merely not being called anywhere.
		if len(args) != 2 || args[0] != "-s" || !pfctlReports[args[1]] {
			return "", fmt.Errorf("jailmap refuses this pfctl: it is read-only and only ever runs `pfctl -s info` or `pfctl -s rules`")
		}
	case "ps":
		// Pinned to the one format string, so the claim in this message and
		// in the README stays literally true rather than approximately.
		if len(args) != 2 || args[0] != "-axo" || args[1] != psFormat {
			return "", fmt.Errorf("jailmap refuses this ps: it is read-only and only ever runs `ps -axo %s`", psFormat)
		}
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		// The parent going away is checked FIRST, because a parent deadline
		// earlier than ours propagates into cmdCtx and would otherwise be
		// misreported as this command being slow.
		if ctx.Err() != nil {
			return string(out), errAborted
		}
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		if cmdCtx.Err() == context.DeadlineExceeded {
			return string(out), fmt.Errorf("%s: timed out after %s", name, timeout)
		}
		if stderr != "" {
			return string(out), fmt.Errorf("%s: %s", name, firstLine(stderr))
		}
		return string(out), fmt.Errorf("%s: %v", name, err)
	}
	return string(out), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Collector samples the system into a Window.
type Collector struct {
	run Runner
	win *Window

	// Interval between socket samples. The in-jail hop this tool exists to
	// show lives for milliseconds, so this is small on purpose.
	Interval time.Duration
	// TopologyEvery is how many socket samples pass between full jail
	// re-enumerations. Jails appear and disappear on a human timescale;
	// sockets do not.
	TopologyEvery int
	// ListenersEvery is how many socket samples pass between listener
	// polls. Listeners are near-static; connections are the volatile part.
	ListenersEvery int
	// ProcessesEvery is how many socket samples pass between process-tree
	// polls. A spawned MCP upstream lives as long as the gateway does, so
	// this is slow: the whole point of the fast path is short-lived sockets,
	// and processes are not that.
	ProcessesEvery int
	// GatewayCommand is the executable name treated as an MCP gateway when
	// looking for spawned upstreams.
	GatewayCommand string

	jids []int
}

// NewCollector returns a collector writing into win.
func NewCollector(run Runner, win *Window, interval time.Duration) *Collector {
	return &Collector{
		run:            run,
		win:            win,
		Interval:       interval,
		TopologyEvery:  40,
		ListenersEvery: 8,
		ProcessesEvery: 8,
		GatewayCommand: DefaultGatewayCommand,
	}
}

// Run samples until ctx is done. It never returns an error for a transient
// collection failure: a jail that stopped mid-loop, a binary that is not
// there, a jail that refuses inspection all become warnings on the
// snapshot. The loop keeps going, because the other jails are still
// answering and a dashboard that dies because one jail did is not useful.
func (c *Collector) Run(ctx context.Context) {
	tick := time.NewTicker(c.Interval)
	defer tick.Stop()

	n := 0
	for {
		if ctx.Err() != nil {
			return
		}
		if n%c.TopologyEvery == 0 {
			c.collectTopology(ctx)
		}
		if c.ProcessesEvery > 0 && n%c.ProcessesEvery == 0 {
			c.collectProcesses(ctx)
		}
		c.collectSockets(ctx, n%c.ListenersEvery == 0)
		c.win.MarkSample(time.Now())
		n++

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// CollectOnce does one full pass, topology included. Used by snapshot mode
// for its first sample and by the tests.
func (c *Collector) CollectOnce(ctx context.Context) {
	c.collectTopology(ctx)
	c.collectProcesses(ctx)
	c.collectSockets(ctx, true)
	c.win.MarkSample(time.Now())
}

func (c *Collector) collectTopology(ctx context.Context) {
	topo, jids, warns := buildTopology(ctx, c.run)
	c.jids = jids
	c.win.SetTopology(topo, warns)

	fw, fwWarns := readFirewall(ctx, c.run)
	c.win.SetFirewall(fw)
	for _, w := range fwWarns {
		c.win.AddWarning(w)
	}
}

// collectProcesses reads the process table and keeps the gateway subtrees.
//
// One `ps` for the whole box rather than one per jail, and not only because
// it is cheaper: a parent and its children have to come from the same
// instant for the tree between them to mean anything, and N separate ps runs
// do not.
//
// The result REPLACES the previous one instead of joining the rolling
// window. The window is right for sockets, which come and go faster than
// they can be sampled; it would be wrong here, where an upstream that died
// two minutes ago must stop being listed as running, not fade out over five
// minutes. A failed read leaves the last good tree in place and lets the
// "as of" age in the output say how stale it is.
func (c *Collector) collectProcesses(ctx context.Context) {
	out, err := c.run.Run(ctx, "ps", "-axo", psFormat)
	if err != nil {
		c.warnUnlessAborted("process tree unavailable", err)
		return
	}
	rows, warns := parsePS(out)
	for _, w := range warns {
		c.win.AddWarning(w)
	}
	c.win.SetGateways(findGateways(rows, c.GatewayCommand), time.Now())
}

// readFirewall reads pf, so that "bound to a routable address" can be told
// apart from "bound to a routable address and reachable".
//
// Both calls are `pfctl -s`, which reports and changes nothing. A host with
// no pf at all is a normal answer here, not a degradation: it is reported as
// "pf state could not be read" on the snapshot and, deliberately, not as a
// warning, because a jail host that does not run pf would otherwise carry a
// permanent DEGRADED line saying so.
func readFirewall(ctx context.Context, run Runner) (Firewall, []string) {
	fw := Firewall{Engine: "pf"}
	var warns []string

	info, err := run.Run(ctx, "pfctl", "-s", "info")
	if err != nil {
		if errors.Is(err, errAborted) {
			return fw, nil
		}
		fw.Error = firstLine(err.Error())
		fw.Summary = summarizeFirewall(fw)
		return fw, nil
	}
	enabled, ok := parsePFInfo(info)
	if !ok {
		fw.Error = "pfctl -s info printed no Status line"
		fw.Summary = summarizeFirewall(fw)
		return fw, warns
	}
	fw.Known, fw.Enabled = true, enabled
	if !enabled {
		fw.Summary = summarizeFirewall(fw)
		return fw, warns
	}

	rules, err := run.Run(ctx, "pfctl", "-s", "rules")
	if err != nil {
		if errors.Is(err, errAborted) {
			return fw, nil
		}
		fw.Error = firstLine(err.Error())
		fw.Summary = summarizeFirewall(fw)
		return fw, warns
	}
	fw.RulesKnown = true
	fw.Rules, fw.DefaultDenyIn, fw.DenyRule = parsePFRules(rules)
	fw.Summary = summarizeFirewall(fw)
	return fw, warns
}

// buildTopology enumerates the host and the jails and assembles the address
// book. Separated out so the test can drive it with a scripted Runner.
func buildTopology(ctx context.Context, run Runner) (*Topology, []int, []string) {
	var warns []string

	// note records a degradation unless it was jailmap's own shutdown.
	note := func(dst *[]string, prefix string, err error) bool {
		if errors.Is(err, errAborted) {
			return false
		}
		*dst = append(*dst, prefix+err.Error())
		return true
	}

	host := Participant{JID: HostJID, Name: HostName, Kind: KindHost}
	if out, err := run.Run(ctx, "ifconfig"); err != nil {
		if note(&warns, "host: ", err) {
			host.Notes = append(host.Notes, "addresses unavailable: "+err.Error())
		}
	} else {
		for _, a := range parseIfconfig(out) {
			host.Addrs = append(host.Addrs, Address{Addr: a.Addr, Iface: a.Iface, Loopback: a.Loopback})
		}
	}

	recs, jlsWarns, err := listJails(ctx, run)
	warns = append(warns, jlsWarns...)
	if err != nil {
		warns = append(warns, err.Error()+" -- showing the host only")
		return NewTopology(host, nil), []int{HostJID}, warns
	}

	jails := make([]Participant, 0, len(recs))
	jids := []int{HostJID}
	for _, r := range recs {
		p := Participant{
			JID:      r.JID,
			Name:     r.Name,
			Hostname: r.Hostname,
			Path:     r.Path,
			Kind:     KindClassic,
		}
		if r.VNET {
			p.Kind = KindVNET
		}
		if !r.VNETKnown {
			p.Notes = append(p.Notes, "kernel has no vnet jail parameter; treated as classic")
		}

		switch p.Kind {
		case KindVNET:
			// A VNET jail's addresses live in its own network stack, so the
			// host's ifconfig cannot see them and jls has none to report.
			// This is the one place jexec is required.
			out, err := run.Run(ctx, "jexec", r.Name, "ifconfig")
			if err != nil {
				if note(&warns, "jail "+r.Name+": ", err) {
					p.Notes = append(p.Notes, "addresses unavailable: "+err.Error())
				}
			} else {
				for _, a := range parseIfconfig(out) {
					p.Addrs = append(p.Addrs, Address{Addr: a.Addr, Iface: a.Iface, Loopback: a.Loopback})
				}
			}
		default:
			// A classic jail has no stack of its own: its addresses are
			// aliases on host interfaces, and jls already listed them.
			for _, a := range r.IP4 {
				p.Addrs = append(p.Addrs, Address{Addr: a, Iface: ifaceFor(host.Addrs, a)})
			}
			if len(p.Addrs) == 0 {
				p.Notes = append(p.Notes, "no ip4.addr reported by jls")
			}
			p.Notes = append(p.Notes,
				"classic jail: shares the host network stack, so a bind to 127.0.0.1 inside it is rewritten to a routable address")
		}
		jails = append(jails, p)
		jids = append(jids, r.JID)
	}
	sort.Ints(jids)
	return NewTopology(host, jails), jids, warns
}

// listJails asks jls for the jail list, and falls back to a query without
// the vnet parameter on a kernel that has none rather than reporting
// nothing at all.
func listJails(ctx context.Context, run Runner) ([]JailRecord, []string, error) {
	const withVNET = "jid name path host.hostname ip4.addr vnet"
	out, err := run.Run(ctx, "jls", append([]string{"-h"}, strings.Fields(withVNET)...)...)
	if err == nil {
		recs, warns := parseJLS(out)
		return recs, warns, nil
	}
	firstErr := err

	out, err = run.Run(ctx, "jls", "-h", "jid", "name", "path", "host.hostname", "ip4.addr")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot list jails (%v)", firstErr)
	}
	recs, warns := parseJLS(out)
	warns = append(warns, "jls has no vnet parameter here; every jail is reported as classic")
	return recs, warns, nil
}

func ifaceFor(addrs []Address, addr string) string {
	for _, a := range addrs {
		if a.Addr == addr {
			return a.Iface
		}
	}
	return ""
}

func (c *Collector) collectSockets(ctx context.Context, withListeners bool) {
	topo := c.win.Topology()
	if topo == nil {
		return
	}
	jids := c.jids
	if len(jids) == 0 {
		for _, p := range topo.Participants {
			jids = append(jids, p.JID)
		}
	}
	now := time.Now()

	if withListeners {
		// `sockstat -j <jid>` run from the host works for BOTH jail kinds,
		// VNET included. That is the finding this collector is built on: no
		// jexec per jail is needed for sockets, only for a VNET jail's
		// addresses.
		for jid, res := range c.sampleAll(ctx, jids, "-4l") {
			if res.err != nil {
				c.warnUnlessAborted(fmt.Sprintf("jid %d: listeners unavailable", jid), res.err)
				continue
			}
			for _, s := range res.socks {
				c.win.ObserveListener(now, jid, s)
			}
		}
	}

	isListening := c.win.ListenerPredicate()
	for jid, res := range c.sampleAll(ctx, jids, "-4c") {
		if res.err != nil {
			c.warnUnlessAborted(fmt.Sprintf("jid %d: connections unavailable", jid), res.err)
			continue
		}
		for _, s := range res.socks {
			c.win.ObserveConnection(now, jid, s, isListening)
		}
	}
}

type sampleResult struct {
	socks []Socket
	err   error
}

// sampleAll runs one sockstat per jid concurrently.
//
// Concurrent because the jails are sampled as one instant: running them in
// series stretches a "sample" across as many command startups as there are
// jails, which is exactly the interval during which the short-lived hop
// this tool is looking for opens and closes. It also keeps a busy host from
// pushing the whole pass past the per-command timeout.
func (c *Collector) sampleAll(ctx context.Context, jids []int, mode string) map[int]sampleResult {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = make(map[int]sampleResult, len(jids))
	)
	for _, jid := range jids {
		wg.Add(1)
		go func(jid int) {
			defer wg.Done()
			text, err := c.run.Run(ctx, "sockstat", mode, "-j", itoa(jid))
			var res sampleResult
			if err != nil {
				res.err = err
			} else {
				var warns []string
				res.socks, warns = parseSockstat(text)
				for _, w := range warns {
					c.addWarning(fmt.Sprintf("jid %d: %s", jid, w))
				}
			}
			mu.Lock()
			out[jid] = res
			mu.Unlock()
		}(jid)
	}
	wg.Wait()
	return out
}

func (c *Collector) addWarning(msg string) { c.win.AddWarning(msg) }

// warnUnlessAborted records a degradation, except when the "failure" was
// jailmap itself shutting down mid-command.
func (c *Collector) warnUnlessAborted(what string, err error) {
	if errors.Is(err, errAborted) {
		return
	}
	c.win.AddWarning(what + ": " + err.Error())
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
