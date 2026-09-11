// Package main -- jailmap address resolution.
//
// STRICTLY READ-ONLY. Pure functions over already-collected data.
package main

import (
	"fmt"
	"net"
	"sort"
)

// Kind is what sort of network stack a participant has. The distinction is
// the whole point of this tool: it changes what an address means.
type Kind string

const (
	KindHost    Kind = "host"    // jid 0
	KindClassic Kind = "classic" // non-VNET jail: shares the host network stack
	KindVNET    Kind = "vnet"    // VNET jail: its own stack, its own 127.0.0.1
)

// HostJID is the jail id of the host itself.
const HostJID = 0

// HostName is the participant name used for jid 0.
const HostName = "host"

// Address is one address owned by a participant.
type Address struct {
	Addr     string `json:"addr"`
	Iface    string `json:"iface,omitempty"`
	Loopback bool   `json:"loopback"`
}

// Participant is the host or one jail: a thing that can be an end of a
// connection.
type Participant struct {
	JID      int       `json:"jid"`
	Name     string    `json:"name"`
	Kind     Kind      `json:"kind"`
	Hostname string    `json:"hostname,omitempty"`
	Path     string    `json:"path,omitempty"`
	Addrs    []Address `json:"addrs"`
	// Notes carries per-participant degradation: an address list that could
	// not be read, a jail that could not be inspected. Never a stack trace.
	Notes []string `json:"notes,omitempty"`
}

// Topology is the address book: which participant owns which address.
type Topology struct {
	Participants []Participant `json:"participants"`

	byJID  map[int]*Participant
	byAddr map[string]string // routable address -> participant name
}

// NewTopology builds the address book. Order matters and is deliberate:
// host interface addresses go in first, then jail addresses overwrite them.
//
// That overwrite is not a tie-break, it is the correct answer. A classic
// jail's address lives on the host's bastille0 as a /32 alias, so it is
// visible in the host's own ifconfig; the jail still owns it. Getting this
// backwards would label every packet to the Authelia jail as host traffic.
func NewTopology(host Participant, jails []Participant) *Topology {
	t := &Topology{
		byJID:  map[int]*Participant{},
		byAddr: map[string]string{},
	}
	t.Participants = append(t.Participants, host)
	sort.Slice(jails, func(i, j int) bool { return jails[i].JID < jails[j].JID })
	t.Participants = append(t.Participants, jails...)

	for i := range t.Participants {
		p := &t.Participants[i]
		t.byJID[p.JID] = p
	}
	// Host first, jails after, so jails win.
	for _, a := range host.Addrs {
		if isLoopbackIP(a.Addr) {
			continue
		}
		t.byAddr[a.Addr] = host.Name
	}
	for _, p := range jails {
		for _, a := range p.Addrs {
			if isLoopbackIP(a.Addr) {
				continue
			}
			t.byAddr[a.Addr] = p.Name
		}
	}
	return t
}

// Resolved is one end of a socket, named.
type Resolved struct {
	Addr string `json:"addr"`
	Port string `json:"port"`
	// Name is the participant this end belongs to, or "" when nothing in
	// the address book claims the address.
	Name string `json:"name"`
	// Unknown means exactly that: the address is shown as sockstat printed
	// it and is not attributed to anybody. VPN clients on 10.8.0.x and the
	// workstation behind the VM's NAT land here, on purpose -- a plausible
	// label would be a guess, and a guess in a map of who-talks-to-whom is
	// worse than a blank.
	Unknown bool `json:"unknown"`
	// Loopback means the address is in 127/8 or ::1 and was therefore
	// resolved to the observing participant rather than to the address book.
	Loopback bool `json:"loopback"`
	// Wildcard means sockstat printed "*": a bind to every address of the
	// observing participant's stack.
	Wildcard bool `json:"wildcard"`
}

// Resolve names one end of a socket that was observed under observerJID.
//
// The observer is load-bearing. A loopback address has no global meaning:
// 127.0.0.1 seen under jid 5 is the VNET jail's own private loopback, and
// 127.0.0.1 seen under jid 0 is the host's. Resolving it against a global
// table would file the mcp-gateway-test jail's internal nginx -> gateway
// hop -- the single hop ADR-0011 exists to force -- as host traffic, which
// is precisely the observation this tool is built to make.
func (t *Topology) Resolve(e Endpoint, observerJID int) Resolved {
	r := Resolved{Addr: e.Addr, Port: e.Port}
	obs := t.byJID[observerJID]

	switch {
	case e.Addr == "*":
		r.Wildcard = true
		if obs != nil {
			r.Name = obs.Name
		} else {
			r.Unknown = true
		}
		return r

	case isLoopbackIP(e.Addr):
		r.Loopback = true
		if obs != nil {
			r.Name = obs.Name
		} else {
			r.Unknown = true
		}
		return r
	}

	// The observer's own addresses take precedence over the shared book, so
	// a host socket bound to an address the host also lends to a jail is
	// still reported as the host's.
	if obs != nil {
		for _, a := range obs.Addrs {
			if a.Addr == e.Addr {
				r.Name = obs.Name
				return r
			}
		}
	}
	if name, ok := t.byAddr[e.Addr]; ok {
		r.Name = name
		return r
	}
	r.Unknown = true
	return r
}

// Participant returns the participant with this jid, or nil.
func (t *Topology) Participant(jid int) *Participant {
	return t.byJID[jid]
}

// Kind returns the kind of the participant with this jid, or "" if unknown.
func (t *Topology) Kind(jid int) Kind {
	if p := t.byJID[jid]; p != nil {
		return p.Kind
	}
	return ""
}

func isLoopbackIP(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// encryptedPorts are the ports on which cleartext is not the expectation.
// This is a deliberately short, conservative list: anything not on it that
// is bound to a routable address gets flagged, because a false "exposed"
// costs one look and a false "fine" costs what ADR-0011 was written about.
var encryptedPorts = map[string]string{
	"22":   "ssh",
	"443":  "https",
	"465":  "smtps",
	"636":  "ldaps",
	"853":  "dot",
	"993":  "imaps",
	"995":  "pop3s",
	"1194": "openvpn",
	"8443": "https-alt",
}

// Exposure is the verdict on a listener.
type Exposure string

const (
	// ExposureLocal: bound to loopback of a stack nothing else shares.
	ExposureLocal Exposure = "local"
	// ExposureEncrypted: reachable off-box, but on a port where transport
	// encryption is the norm.
	ExposureEncrypted Exposure = "encrypted"
	// ExposurePlaintext: reachable off-box in the clear.
	ExposurePlaintext Exposure = "plaintext"
	// ExposureRewritten: bound to "loopback" inside a CLASSIC jail, where
	// the kernel rewrites the bind to the jail's routable address. The
	// process believes it is private and is not.
	ExposureRewritten Exposure = "rewritten"
)

// classifyExposure decides how reachable a listener is.
//
// The classic-jail case is the one worth spelling out. In a non-VNET jail
// there is no private loopback: a bind to 127.0.0.1 is silently rewritten
// to the jail's routable address, so the address sockstat prints is already
// the routable one. Anything a classic jail listens on is reachable by
// whoever can route to that jail, whatever the config file says.
func classifyExposure(r Resolved, port string, kind Kind) Exposure {
	if r.Wildcard {
		if _, ok := encryptedPorts[port]; ok {
			return ExposureEncrypted
		}
		return ExposurePlaintext
	}
	if r.Loopback {
		if kind == KindClassic {
			// Should not normally be observable -- the kernel rewrites it --
			// but if it is, it is not private.
			return ExposureRewritten
		}
		return ExposureLocal
	}
	if _, ok := encryptedPorts[port]; ok {
		return ExposureEncrypted
	}
	return ExposurePlaintext
}

// serviceName is the label for a well-known port, or "" when there is none.
func serviceName(port string) string {
	if s, ok := encryptedPorts[port]; ok {
		return s
	}
	switch port {
	case "80":
		return "http"
	case "514":
		return "syslog"
	case "8080":
		return "http-alt"
	case "9091":
		return "http"
	}
	return ""
}

// FlowScope says what kind of edge this is.
type FlowScope string

const (
	// ScopeInJail: both ends are the same participant over its own
	// loopback. For a VNET jail this is the ADR-0011 hop.
	ScopeInJail FlowScope = "in-jail"
	// ScopeInternal: two known participants on this box talking to each
	// other over routable addresses.
	ScopeInternal FlowScope = "internal"
	// ScopeExternal: one end is not in the address book.
	ScopeExternal FlowScope = "external"
)

func classifyScope(client, server Resolved) FlowScope {
	if client.Unknown || server.Unknown {
		return ScopeExternal
	}
	if client.Name == server.Name && client.Loopback && server.Loopback {
		return ScopeInJail
	}
	return ScopeInternal
}

// displayName is what to print for one end of an edge.
func displayName(r Resolved) string {
	if r.Unknown || r.Name == "" {
		return r.Addr
	}
	return r.Name
}

// ---------------------------------------------------------------------------
// Process tree: the MCP upstreams, which have no sockets at all.
// ---------------------------------------------------------------------------

// DefaultGatewayCommand is the executable name jailmap treats as an MCP
// gateway when looking for spawned upstreams.
const DefaultGatewayCommand = "mcp-gateway"

// SpawnedProc is one direct child of a gateway process: an MCP upstream,
// inferred.
//
// "Inferred" is not a hedge, it is the method. jailmap deliberately does not
// read the gateway's registry or its database to find out which upstreams
// are configured -- an observability tool that depends on the health of the
// thing it observes is useless in the situation you most want it. What it
// has instead is the kernel's process table, which is true whatever state
// the gateway's own state is in.
type SpawnedProc struct {
	PID  int    `json:"pid"`
	Name string `json:"name"` // executable basename, not a registry name
	// Command is argv as ps printed it.
	Command       string  `json:"command"`
	User          string  `json:"user"`
	Uptime        string  `json:"uptime"` // exactly as ps printed it
	UptimeSeconds float64 `json:"uptime_seconds,omitempty"`
	// Descendants is how many further processes hang off this one. An MCP
	// upstream that is itself a supervisor is a different animal from one
	// that is a single binary, and the count says which without listing a
	// whole subtree that is none of this tool's business.
	Descendants int `json:"descendants,omitempty"`
}

// GatewayProc is one gateway process and the upstreams it has spawned.
//
// This is NOT a set of network edges and is kept apart from them everywhere
// it is rendered. A parent and the child it talks to over a pipe share no
// socket, no address and no port; drawing that as an edge in a connection
// graph would be inventing a connection the kernel does not have.
type GatewayProc struct {
	JID           int     `json:"jid"`
	Owner         string  `json:"owner"`
	Kind          Kind    `json:"kind"`
	PID           int     `json:"pid"`
	PPID          int     `json:"ppid"`
	User          string  `json:"user"`
	Command       string  `json:"command"`
	Uptime        string  `json:"uptime"`
	UptimeSeconds float64 `json:"uptime_seconds,omitempty"`
	// ListensOn are the listening sockets sockstat attributes to this same
	// pid. It is the one independent check on the inference: a process that
	// is named like the gateway AND owns the gateway's listener is the
	// gateway. Empty is not a contradiction -- a gateway can be up before it
	// binds, and the listener poll is slower than the process poll.
	ListensOn []string `json:"listens_on,omitempty"`
	// Upstreams are its direct children, sorted by pid.
	Upstreams []SpawnedProc `json:"upstreams"`
}

// findGateways picks the gateway processes out of a full process list and
// attaches their direct children.
//
// The only string this matches is the gateway's own executable name, which
// is the name of the binary jailmap ships beside -- not anything read out of
// the gateway's configuration or state. Everything after that is structure:
// a child is a child because the kernel says its ppid is the gateway's pid.
//
// The jid check on children is not paranoia. A process can be started in one
// jail by a parent in another; a child in a different jail is not a stdio
// upstream of this gateway and is left out rather than mislabelled.
func findGateways(rows []ProcRow, gatewayName string) []GatewayProc {
	if gatewayName == "" {
		gatewayName = DefaultGatewayCommand
	}
	children := map[int][]ProcRow{}
	for _, r := range rows {
		children[r.PPID] = append(children[r.PPID], r)
	}
	var out []GatewayProc
	for _, r := range rows {
		if procName(r.Command) != gatewayName {
			continue
		}
		g := GatewayProc{
			JID: r.JID, PID: r.PID, PPID: r.PPID,
			User: r.User, Command: r.Command, Uptime: r.Etime,
			Upstreams: []SpawnedProc{},
		}
		if r.ElapsedKnown {
			g.UptimeSeconds = r.Elapsed.Seconds()
		}
		for _, c := range children[r.PID] {
			if c.JID != r.JID || c.PID == r.PID {
				continue
			}
			s := SpawnedProc{
				PID: c.PID, Name: procName(c.Command), Command: c.Command,
				User: c.User, Uptime: c.Etime,
				Descendants: countDescendants(children, c.PID, map[int]bool{}),
			}
			if c.ElapsedKnown {
				s.UptimeSeconds = c.Elapsed.Seconds()
			}
			g.Upstreams = append(g.Upstreams, s)
		}
		sort.Slice(g.Upstreams, func(i, j int) bool { return g.Upstreams[i].PID < g.Upstreams[j].PID })
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].JID != out[j].JID {
			return out[i].JID < out[j].JID
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// countDescendants counts everything below pid. seen guards against a
// process table that reports a cycle rather than recursing forever on it.
func countDescendants(children map[int][]ProcRow, pid int, seen map[int]bool) int {
	if seen[pid] {
		return 0
	}
	seen[pid] = true
	n := 0
	for _, c := range children[pid] {
		n += 1 + countDescendants(children, c.PID, seen)
	}
	return n
}

// ---------------------------------------------------------------------------
// Firewall: what a routable bind actually means on this host.
// ---------------------------------------------------------------------------

// Firewall is the host packet filter as jailmap read it.
type Firewall struct {
	Engine string `json:"engine"` // always "pf" here
	// Known is false when pfctl could not be read. "Cannot tell" is reported
	// as itself and never collapses into either answer.
	Known         bool   `json:"known"`
	Enabled       bool   `json:"enabled"`
	RulesKnown    bool   `json:"rules_known"`
	Rules         int    `json:"rules"`
	DefaultDenyIn bool   `json:"default_deny_in"`
	DenyRule      string `json:"deny_rule,omitempty"`
	Summary       string `json:"summary"`
	Error         string `json:"error,omitempty"`
}

// Reachability qualifies an exposure verdict with what the firewall does.
//
// It exists because "bound to a routable address" and "reachable from off
// this box" are different facts, and jailmap used to print the first while
// sounding like the second. On a host running pf with a default-deny inbound
// policy, `syslogd` on `*:514` is a true bind and a false alarm -- and a tool
// that cries wolf is a tool people stop reading.
type Reachability string

const (
	// ReachNA: the question does not arise -- loopback of a private stack.
	ReachNA Reachability = ""
	// ReachUnfiltered: nothing stands between the bind and the network.
	ReachUnfiltered Reachability = "unfiltered"
	// ReachFiltered: pf is up and default-denies inbound, so the bind alone
	// does not make the port reachable.
	ReachFiltered Reachability = "filtered"
	// ReachUnknown: pf could not be read, or its ruleset is one jailmap
	// declines to interpret, or the listener is in a VNET jail whose own pf
	// instance the host ruleset says nothing about.
	ReachUnknown Reachability = "unknown"
)

// classifyReachability qualifies a listener's exposure with the firewall.
//
// The VNET case is the one worth spelling out. A VNET jail has its own pf
// instance, which the host's `pfctl` does not report on; the host ruleset
// therefore does not govern what reaches a socket inside it. Applying the
// host's verdict there would be exactly the overclaim in the other
// direction, so it is reported as unknown and told why.
func classifyReachability(e Exposure, kind Kind, fw Firewall) (Reachability, string) {
	if e == ExposureLocal {
		return ReachNA, ""
	}
	if kind == KindVNET {
		return ReachUnknown, "VNET jail: it has its own pf instance, which the host's pfctl does not report on"
	}
	switch {
	case !fw.Known:
		return ReachUnknown, "pf state could not be read"
	case !fw.Enabled:
		return ReachUnfiltered, "pf is disabled on the host"
	case !fw.RulesKnown:
		return ReachUnknown, "pf is enabled but its ruleset could not be read"
	case fw.Rules == 0:
		return ReachUnfiltered, "pf is enabled but its ruleset is empty"
	case fw.DefaultDenyIn:
		return ReachFiltered, "pf default-denies inbound (" + fw.DenyRule + ")"
	}
	return ReachUnknown, "pf is enabled with rules jailmap does not evaluate"
}

// summarizeFirewall turns the pf reading into the one sentence printed above
// the listener table.
func summarizeFirewall(fw Firewall) string {
	switch {
	case !fw.Known:
		s := "pf state could not be read"
		if fw.Error != "" {
			s += " (" + fw.Error + ")"
		}
		return s + "; the exposure column below is about the bind only"
	case !fw.Enabled:
		return "pf is disabled on the host; a routable bind is reachable from wherever the address is routed"
	case !fw.RulesKnown:
		s := "pf is enabled but its ruleset could not be read"
		if fw.Error != "" {
			s += " (" + fw.Error + ")"
		}
		return s + "; reachability unknown"
	case fw.Rules == 0:
		return "pf is enabled but its ruleset is empty, so nothing is filtered"
	case fw.DefaultDenyIn:
		return fmt.Sprintf("pf is active with a default-deny inbound policy (%s) across %d rules; a routable bind is not by itself reachable", fw.DenyRule, fw.Rules)
	}
	return fmt.Sprintf("pf is active with %d rules and no unqualified default-deny; jailmap does not evaluate them, so reachability is unknown", fw.Rules)
}
