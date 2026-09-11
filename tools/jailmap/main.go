// Command jailmap maps what is running on a FreeBSD jail host and who is
// connected to whom, and serves it as a live dashboard.
//
// # STRICTLY READ-ONLY
//
// jailmap observes. It does not act. The complete set of commands it will
// ever execute is `jls`, `sockstat`, `ifconfig`, `ps -axo <fixed format>`,
// `pfctl -s info`, `pfctl -s rules` and `jexec <jail> ifconfig` -- all
// enumeration, all non-mutating -- and runner.Run in collect.go refuses to
// execute anything else: jexec with any other inner command, pfctl in any
// mode but -s, ps with any other option. There is no code path in this
// program that starts, stops, restarts or reconfigures a jail, a service,
// an interface or a firewall, and no file it opens for writing. If you are
// auditing this: the whole list is readOnlyCommands in collect.go, and it
// is enforced, not documented.
//
// It binds loopback only, and refuses to do otherwise -- see
// requireLoopbackBind in serve.go, and
// design/adr/0011-network-exposure-and-tls-termination.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

const usage = `jailmap -- read-only live map of jails, listeners and connections

usage:
  jailmap serve    [-listen 127.0.0.1:8088] [-window 5m] [-interval 250ms]
  jailmap snapshot [-window 5m] [-interval 250ms] [-for 3s] [-max 25] [-json]

serve      samples continuously in the background and serves a dashboard
           plus GET /api/snapshot. Loopback bind only, by refusal.
snapshot   samples for -for, then prints the same data to stdout.

Why it samples rather than polls once: the interesting edges are short.
An nginx -> 127.0.0.1:8080 hop inside a VNET jail is open for a few
milliseconds; a single sockstat run during live traffic routinely shows
nothing. jailmap keeps a rolling window of what it saw, with first- and
last-seen times, so a working system never renders as an empty graph.

It also shows the MCP upstreams, which have no sockets at all: the gateway
spawns them as stdio subprocesses and talks over pipes, so they are visible
in the process tree and nowhere in sockstat. They are reported as a process
tree, separately from the connection graph, because a pipe is not an edge.

jailmap changes nothing. It runs jls, sockstat, ifconfig, ps -axo,
pfctl -s info, pfctl -s rules and jexec <jail> ifconfig, and refuses to
run anything else.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "snapshot":
		err = cmdSnapshot(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "jailmap: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "jailmap: "+err.Error())
		os.Exit(1)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8088", "loopback address to serve the dashboard on; a non-loopback bind is refused")
	window := fs.Duration("window", 5*time.Minute, "how long a connection stays on the map after it was last seen")
	interval := fs.Duration("interval", 250*time.Millisecond, "socket sampling interval; short, because the interesting hops are short")
	timeout := fs.Duration("cmd-timeout", 3*time.Second, "per-command timeout for jls/sockstat/ifconfig/ps/pfctl")
	gwCmd := fs.String("gateway-command", DefaultGatewayCommand, "executable name whose child processes are reported as MCP upstreams")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *interval < 10*time.Millisecond {
		return fmt.Errorf("-interval %s is below the 10ms floor", *interval)
	}
	if *window < *interval {
		return fmt.Errorf("-window %s is shorter than -interval %s", *window, *interval)
	}
	// Checked before anything else starts, so a refused bind costs nothing
	// and says so immediately.
	if err := requireLoopbackBind(*listen); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	win := NewWindow(*window)
	col := NewCollector(execRunner{timeout: *timeout}, win, *interval)
	col.GatewayCommand = *gwCmd
	go col.Run(ctx)

	fmt.Fprintf(os.Stderr, "jailmap: read-only. sampling every %s, %s window.\n", *interval, *window)
	fmt.Fprintf(os.Stderr, "jailmap: http://%s/  (loopback only -- tunnel with: ssh -L %s:127.0.0.1:%s <host>)\n",
		*listen, portOf(*listen), portOf(*listen))
	return ListenAndServe(ctx, *listen, NewServer(win, *interval))
}

func cmdSnapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	window := fs.Duration("window", 5*time.Minute, "how long a connection stays on the map after it was last seen")
	interval := fs.Duration("interval", 250*time.Millisecond, "socket sampling interval")
	dur := fs.Duration("for", 3*time.Second, "how long to sample before printing; 0 means a single pass")
	asJSON := fs.Bool("json", false, "print the snapshot as JSON")
	max := fs.Int("max", 25, "cap on the per-connection detail list; 0 for no cap")
	timeout := fs.Duration("cmd-timeout", 3*time.Second, "per-command timeout for jls/sockstat/ifconfig/ps/pfctl")
	gwCmd := fs.String("gateway-command", DefaultGatewayCommand, "executable name whose child processes are reported as MCP upstreams")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	win := NewWindow(*window)
	col := NewCollector(execRunner{timeout: *timeout}, win, *interval)
	col.GatewayCommand = *gwCmd

	if *dur <= 0 {
		col.CollectOnce(ctx)
	} else {
		// Sampling for a few seconds rather than once is the honest default
		// for the same reason serve exists: one pass will miss the in-jail
		// hop even while it is happening.
		sctx, cancel := context.WithTimeout(ctx, *dur)
		col.Run(sctx)
		cancel()
	}

	snap := win.Snapshot(time.Now(), *interval)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	printSnapshot(os.Stdout, snap, *max)
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "??"
	}
	return s
}

// printSnapshot renders the human-readable form. max caps the per-connection
// detail list; 0 means no cap.
func printSnapshot(w *os.File, s Snapshot, max int) {
	now := s.Generated
	fmt.Fprintf(w, "jailmap  %s  read-only  window=%s  samples=%d\n\n",
		now.Format(time.RFC3339), fmtDur(time.Duration(s.WindowSeconds*float64(time.Second))), s.Samples)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "WHAT IS RUNNING")
	fmt.Fprintln(tw, "  JID\tNAME\tKIND\tADDRESSES")
	for _, p := range s.Participants {
		var addrs []string
		for _, a := range p.Addrs {
			label := a.Addr
			if a.Loopback {
				label += " (lo)"
			}
			addrs = append(addrs, label)
		}
		if len(addrs) == 0 {
			addrs = []string{"-"}
		}
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", p.JID, p.Name, p.Kind, strings.Join(addrs, " "))
		for _, n := range p.Notes {
			fmt.Fprintf(tw, "  \t\t\t- %s\n", n)
		}
	}
	fmt.Fprintln(tw)

	printGateways(tw, s)

	fmt.Fprintln(tw, "WHAT IS LISTENING")
	fmt.Fprintf(tw, "  firewall: %s\n", s.Firewall.Summary)
	fmt.Fprintln(tw, "  OWNER\tPROTO\tADDRESS\tPROCESS\tUSER\tEXPOSURE")
	for _, l := range s.Listeners {
		addr := l.Addr + ":" + l.Port
		if l.Service != "" {
			addr += " (" + l.Service + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", l.Owner, l.Proto, addr, l.Command, l.User, exposureLabel(l))
	}
	fmt.Fprintln(tw)

	fmt.Fprintln(tw, "WHO IS TALKING TO WHOM")
	if len(s.Edges) == 0 {
		fmt.Fprintln(tw, "  (nothing seen in the window)")
	} else {
		fmt.Fprintln(tw, "  SCOPE\tCLIENT\tSERVER\tPROTO\tPROC\tCONNS\tAGE")
	}
	for _, e := range s.Edges {
		server := e.Server
		if e.Server != e.ServerAddr {
			server += " " + e.ServerAddr
		}
		server += ":" + e.ServerPort
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			e.Scope, e.Client, server, e.Proto, orUnknown(e.Process), e.Connections, fmtAge(e.AgeSeconds(now)))
	}

	// The per-connection detail is kept but capped: it is a log, and the
	// aggregate above is the answer to the question. -max 0 prints all of
	// it for when the individual source port is the point.
	if len(s.Flows) > 0 {
		shown := s.Flows
		if max > 0 && len(shown) > max {
			shown = shown[:max]
		}
		fmt.Fprintln(tw)
		fmt.Fprintf(tw, "CONNECTIONS (%d in the window, newest first)\n", len(s.Flows))
		fmt.Fprintln(tw, "  SCOPE\tCLIENT\tSERVER\tPROTO\tPROC\tAGE\tSEEN")
		for _, f := range shown {
			proc := f.ServerProc
			if proc == "" {
				proc = f.ClientProc
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%dx\n",
				f.Scope, endpointLabel(f.Client), endpointLabel(f.Server),
				f.Proto, orUnknown(proc), fmtAge(f.AgeSeconds(now)), f.Samples)
		}
		if len(s.Flows) > len(shown) {
			fmt.Fprintf(tw, "  ... %d more (pass -max 0 for all)\n", len(s.Flows)-len(shown))
		}
	}
	_ = tw.Flush()

	if len(s.Warnings) > 0 {
		fmt.Fprintln(w, "\nDEGRADED")
		sorted := append([]string(nil), s.Warnings...)
		sort.Strings(sorted)
		for _, msg := range sorted {
			fmt.Fprintf(w, "  - %s\n", msg)
		}
	}
}

// printGateways renders the MCP process tree.
//
// It is its own section, above the socket views and drawn as a tree rather
// than as rows of client -> server, because these are pipes. The gateway
// and its upstreams share no socket, so there is no address and no port to
// print for the relationship between them, and giving them one would be
// making it up. The one thing that IS a socket -- the gateway's own
// listener -- is shown against the gateway line, where it belongs.
func printGateways(tw *tabwriter.Writer, s Snapshot) {
	fmt.Fprintln(tw, "MCP UPSTREAMS  (stdio subprocesses: pipes, not sockets -- inferred from the process tree)")
	if s.GatewaysSeen.IsZero() {
		fmt.Fprintln(tw, "  (the process table has not been read yet)")
		fmt.Fprintln(tw)
		return
	}
	if len(s.Gateways) == 0 {
		fmt.Fprintln(tw, "  (no gateway process is running; nothing spawns MCP upstreams here)")
		fmt.Fprintln(tw)
		return
	}
	fmt.Fprintf(tw, "  process table read %s\n", fmtSince(s.GatewaysAgeSeconds))
	fmt.Fprintln(tw, "  OWNER\tPID\tUSER\tUPTIME\tPROCESS")
	for _, g := range s.Gateways {
		note := "gateway"
		if len(g.ListensOn) > 0 {
			note = "gateway, listening on " + strings.Join(g.ListensOn, ", ")
		} else {
			note = "gateway, no listening socket attributed to this pid"
		}
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s  [%s]\n",
			g.Owner, g.PID, g.User, fmtUptime(g.UptimeSeconds), g.Command, note)
		if len(g.Upstreams) == 0 {
			fmt.Fprintf(tw, "  \t\t\t\t  (no child processes: this gateway has spawned no stdio upstreams)\n")
			continue
		}
		for i, u := range g.Upstreams {
			branch := "|-"
			if i == len(g.Upstreams)-1 {
				branch = "`-"
			}
			extra := ""
			if u.Descendants > 0 {
				extra = fmt.Sprintf("  (+%d descendants)", u.Descendants)
			}
			fmt.Fprintf(tw, "  \t%d\t%s\t%s\t  %s %s%s\n",
				u.PID, u.User, fmtUptime(u.UptimeSeconds), branch, u.Command, extra)
		}
	}
	fmt.Fprintln(tw)
}

func endpointLabel(r Resolved) string {
	name := displayName(r)
	if r.Unknown {
		return fmt.Sprintf("%s:%s [unknown]", r.Addr, r.Port)
	}
	return fmt.Sprintf("%s %s:%s", name, r.Addr, r.Port)
}

// exposureLabel prints the exposure verdict qualified by the firewall.
//
// The unqualified form used to be printed for every routable bind, which
// made jailmap say PLAINTEXT ON ROUTABLE ADDRESS about ntpd on *:123 and
// syslogd on *:514 on a host whose pf drops all inbound traffic. Both
// statements were true about the bind and misleading about the exposure,
// and a tool that cries wolf is a tool that gets skimmed. The shout is now
// reserved for a bind nothing is known to stand in front of.
func exposureLabel(l Listener) string {
	base := string(l.Exposure)
	switch l.Exposure {
	case ExposureLocal:
		return "local"
	case ExposureEncrypted:
		base = "encrypted"
	case ExposurePlaintext:
		base = "PLAINTEXT ON ROUTABLE ADDRESS"
	case ExposureRewritten:
		base = "REWRITTEN (classic jail: not actually loopback)"
	}
	switch l.Reachability {
	case ReachFiltered:
		if l.Exposure == ExposurePlaintext {
			base = "plaintext bind"
		}
		return base + " [pf default-denies inbound]"
	case ReachUnknown:
		return base + " [reachability unknown]"
	}
	return base
}

// fmtUptime prints how long a process has been running. Distinct from
// fmtAge, which is about how long ago something was last seen: "4.5h" is
// the wrong shape for an uptime a person wants to compare against another.
func fmtUptime(sec float64) string {
	if sec <= 0 {
		return "?"
	}
	s := int64(sec)
	d := s / 86400
	s %= 86400
	h := s / 3600
	s %= 3600
	m := s / 60
	s %= 60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd%02dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func fmtAge(sec float64) string {
	switch {
	case sec < 1:
		return "now"
	case sec < 60:
		return fmt.Sprintf("%.0fs", sec)
	case sec < 3600:
		return fmt.Sprintf("%.0fm", sec/60)
	}
	return fmt.Sprintf("%.1fh", sec/3600)
}

func fmtDur(d time.Duration) string { return d.String() }

// fmtSince phrases an age as a moment rather than a duration. The process
// tree is a single reading, not a window, so how old it is is the only
// thing that says how far to trust it -- and "now ago" is not a phrase.
func fmtSince(sec float64) string {
	if sec < 1 {
		return "just now"
	}
	return fmtAge(sec) + " ago"
}
