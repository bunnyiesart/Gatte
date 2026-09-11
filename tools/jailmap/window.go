// Package main -- jailmap rolling window.
//
// STRICTLY READ-ONLY. This file only remembers what the collector saw.
package main

import (
	"sort"
	"sync"
	"time"
)

// Listener is one observed listening socket, with the times it was seen.
type Listener struct {
	JID       int       `json:"jid"`
	Owner     string    `json:"owner"`
	Kind      Kind      `json:"kind"`
	Proto     string    `json:"proto"`
	Addr      string    `json:"addr"`
	Port      string    `json:"port"`
	Service   string    `json:"service,omitempty"`
	Command   string    `json:"command"`
	PID       string    `json:"pid,omitempty"`
	User      string    `json:"user"`
	Exposure  Exposure  `json:"exposure"`
	Wildcard  bool      `json:"wildcard"`
	Loopback  bool      `json:"loopback"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Samples   int       `json:"samples"`

	// Reachability and ReachabilityNote qualify Exposure with what the
	// firewall does. Exposure is a fact about the bind and is computed when
	// the socket is seen; reachability depends on a pf ruleset that can
	// change under it, so it is filled in at snapshot time from the latest
	// reading rather than frozen into the record.
	Reachability     Reachability `json:"reachability,omitempty"`
	ReachabilityNote string       `json:"reachability_note,omitempty"`
}

// Flow is one connection (or one identical 4-tuple re-observed) inside the
// rolling window.
//
// The window is the reason this program exists rather than a shell alias.
// The nginx -> 127.0.0.1:8080 hop inside the VNET jail lives for a few
// milliseconds; a one-shot `sockstat` during real traffic routinely shows
// nothing at all. A dashboard that renders an empty graph on a working
// system is worse than no dashboard, so what is displayed is "seen in the
// last N", with first/last-seen so a stale edge is never mistaken for a
// live one.
type Flow struct {
	Proto  string   `json:"proto"`
	Client Resolved `json:"client"`
	Server Resolved `json:"server"`
	// ClientProc / ServerProc are best-effort. sockstat reports "??" for
	// sockets it cannot attribute to a process (TIME_WAIT, and anything
	// owned by a jail it will not walk), and those stay blank rather than
	// being filled in from a neighbouring row.
	ClientProc string    `json:"client_proc,omitempty"`
	ServerProc string    `json:"server_proc,omitempty"`
	Scope      FlowScope `json:"scope"`
	// DirectionInferred is set when neither end matched a known listener and
	// the server side was picked by the lower-port heuristic.
	DirectionInferred bool      `json:"direction_inferred"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	Samples           int       `json:"samples"`
}

// AgeSeconds is how long ago this flow was last observed.
func (f Flow) AgeSeconds(now time.Time) float64 { return now.Sub(f.LastSeen).Seconds() }

type flowKey struct {
	proto  string
	client string // "<owner>|<addr>:<port>"
	server string
}

type listenerKey struct {
	jid   int
	proto string
	addr  string
	port  string
	pid   string
}

// Window keeps everything seen in the last d.
type Window struct {
	mu sync.Mutex
	d  time.Duration

	topo      *Topology
	flows     map[flowKey]*Flow
	listeners map[listenerKey]*Listener

	// gateways and fw are point-in-time readings, not window contents: the
	// last answer replaces the previous one. A dead upstream must vanish
	// from "what is running" at the next poll, and a pf ruleset that was
	// reloaded is simply a different ruleset, not an older sighting of the
	// same one.
	gateways   []GatewayProc
	gatewaysAt time.Time
	fw         Firewall

	samples     int64
	lastCollect time.Time
	startedAt   time.Time

	// warnings are deduplicated and time-stamped so a transient failure --
	// a jail that was mid-restart during one sample -- fades out of the
	// dashboard on the same schedule as a stale flow, instead of accreting
	// forever or being erased the instant it stops recurring.
	warnings map[string]time.Time
}

// NewWindow returns an empty rolling window of duration d.
func NewWindow(d time.Duration) *Window {
	return &Window{
		d:         d,
		flows:     map[flowKey]*Flow{},
		listeners: map[listenerKey]*Listener{},
		warnings:  map[string]time.Time{},
		startedAt: time.Now(),
	}
}

// SetTopology replaces the address book. Called on the slower jail-refresh
// tick, not on every socket sample.
func (w *Window) SetTopology(t *Topology, warnings []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.topo = t
	now := time.Now()
	for _, msg := range warnings {
		w.warnings[msg] = now
	}
}

// SetGateways replaces the process-tree reading.
func (w *Window) SetGateways(gs []GatewayProc, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gateways = gs
	w.gatewaysAt = at
}

// SetFirewall replaces the pf reading.
func (w *Window) SetFirewall(fw Firewall) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fw = fw
}

// AddWarning records a degradation message. Same text twice is one entry.
func (w *Window) AddWarning(msg string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.warnings[msg] = time.Now()
}

// ListenerPredicate returns a snapshot test for "is this a listening port
// of this participant", used to decide which end of a connection is the
// server. It copies under the lock and answers without one, so the caller
// can use it while observing.
func (w *Window) ListenerPredicate() func(owner, proto, port string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	set := make(map[string]bool, len(w.listeners))
	for _, l := range w.listeners {
		set[l.Owner+"|"+l.Proto+"|"+l.Port] = true
	}
	return func(owner, proto, port string) bool {
		return set[owner+"|"+proto+"|"+port]
	}
}

// Topology returns the current address book, or nil before the first
// collection.
func (w *Window) Topology() *Topology {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.topo
}

// ObserveListener records a listening socket seen under observerJID.
func (w *Window) ObserveListener(now time.Time, observerJID int, s Socket) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.topo == nil {
		return
	}
	r := w.topo.Resolve(s.Local, observerJID)
	kind := w.topo.Kind(observerJID)
	key := listenerKey{jid: observerJID, proto: s.Proto, addr: s.Local.Addr, port: s.Local.Port, pid: s.PID}
	l, ok := w.listeners[key]
	if !ok {
		l = &Listener{
			JID:       observerJID,
			Owner:     displayName(r),
			Kind:      kind,
			Proto:     s.Proto,
			Addr:      s.Local.Addr,
			Port:      s.Local.Port,
			Service:   serviceName(s.Local.Port),
			Command:   s.Command,
			PID:       s.PID,
			User:      s.User,
			Exposure:  classifyExposure(r, s.Local.Port, kind),
			Wildcard:  r.Wildcard,
			Loopback:  r.Loopback,
			FirstSeen: now,
		}
		w.listeners[key] = l
	}
	l.LastSeen = now
	l.Samples++
}

// ObserveConnection records a connected socket seen under observerJID.
//
// isListening decides which end is the server. It is consulted rather than
// assumed because both ends of an in-jail hop are loopback and both are
// plausible clients on sight alone.
func (w *Window) ObserveConnection(now time.Time, observerJID int, s Socket, isListening func(owner, proto, port string) bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.topo == nil {
		return
	}
	if s.Foreign.Addr == "" || s.Foreign.Addr == "*" || s.Foreign.Port == "*" {
		return // not a connection
	}
	local := w.topo.Resolve(s.Local, observerJID)
	foreign := w.topo.Resolve(s.Foreign, observerJID)

	client, server := local, foreign
	clientProc, serverProc := s.Command, ""
	inferred := false

	localIsServer := isListening(displayName(local), s.Proto, s.Local.Port)
	foreignIsServer := isListening(displayName(foreign), s.Proto, s.Foreign.Port)

	switch {
	case localIsServer && !foreignIsServer:
		client, server = foreign, local
		clientProc, serverProc = "", s.Command
	case foreignIsServer && !localIsServer:
		// already right
	default:
		// Nothing matched a listener, or both did. Lower port is the
		// conventional server side; the flow is marked so the dashboard can
		// say the direction was inferred rather than observed.
		inferred = true
		if portLess(s.Local.Port, s.Foreign.Port) {
			client, server = foreign, local
			clientProc, serverProc = "", s.Command
		}
	}
	if !s.Attributed() {
		clientProc, serverProc = "", ""
	}

	key := flowKey{
		proto:  s.Proto,
		client: displayName(client) + "|" + client.Addr + ":" + client.Port,
		server: displayName(server) + "|" + server.Addr + ":" + server.Port,
	}
	f, ok := w.flows[key]
	if !ok {
		f = &Flow{
			Proto:             s.Proto,
			Client:            client,
			Server:            server,
			Scope:             classifyScope(client, server),
			DirectionInferred: inferred,
			FirstSeen:         now,
		}
		w.flows[key] = f
	}
	// A later sample that can name the process fills in what an earlier
	// "??" sample could not; it never overwrites a name with a blank.
	if clientProc != "" {
		f.ClientProc = clientProc
	}
	if serverProc != "" {
		f.ServerProc = serverProc
	}
	if !inferred {
		f.DirectionInferred = false
	}
	f.LastSeen = now
	f.Samples++
}

// MarkSample records that one full collection pass completed.
func (w *Window) MarkSample(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.samples++
	w.lastCollect = now
}

func (w *Window) prune(now time.Time) {
	cut := now.Add(-w.d)
	for k, f := range w.flows {
		if f.LastSeen.Before(cut) {
			delete(w.flows, k)
		}
	}
	for k, l := range w.listeners {
		if l.LastSeen.Before(cut) {
			delete(w.listeners, k)
		}
	}
	for k, at := range w.warnings {
		if at.Before(cut) {
			delete(w.warnings, k)
		}
	}
}

// Edge is many connections collapsed to one line: who talks to which
// service on whom.
//
// It exists because the raw flow list is a per-connection log, and a
// hundred ephemeral source ports against one nginx is one fact, not a
// hundred. The detailed flows are still there underneath; this is the
// version a person reads first.
type Edge struct {
	Scope       FlowScope `json:"scope"`
	Proto       string    `json:"proto"`
	Client      string    `json:"client"`
	Server      string    `json:"server"`
	ServerAddr  string    `json:"server_addr"`
	ServerPort  string    `json:"server_port"`
	Process     string    `json:"process,omitempty"`
	Connections int       `json:"connections"`
	Samples     int       `json:"samples"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// AgeSeconds is how long ago any connection on this edge was last seen.
func (e Edge) AgeSeconds(now time.Time) float64 { return now.Sub(e.LastSeen).Seconds() }

type edgeKey struct {
	scope      FlowScope
	proto      string
	client     string
	server     string
	serverAddr string
	serverPort string
}

func edgesOf(flows []Flow) []Edge {
	byKey := map[edgeKey]*Edge{}
	var order []edgeKey
	for _, f := range flows {
		k := edgeKey{
			scope:      f.Scope,
			proto:      f.Proto,
			client:     displayName(f.Client),
			server:     displayName(f.Server),
			serverAddr: f.Server.Addr,
			serverPort: f.Server.Port,
		}
		e, ok := byKey[k]
		if !ok {
			e = &Edge{
				Scope: f.Scope, Proto: f.Proto,
				Client: k.client, Server: k.server,
				ServerAddr: f.Server.Addr, ServerPort: f.Server.Port,
				FirstSeen: f.FirstSeen,
			}
			byKey[k] = e
			order = append(order, k)
		}
		e.Connections++
		e.Samples += f.Samples
		if f.FirstSeen.Before(e.FirstSeen) {
			e.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(e.LastSeen) {
			e.LastSeen = f.LastSeen
		}
		if e.Process == "" {
			if f.ServerProc != "" {
				e.Process = f.ServerProc
			} else {
				e.Process = f.ClientProc
			}
		}
	}
	out := make([]Edge, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return scopeRank(out[i].Scope) < scopeRank(out[j].Scope)
		}
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		return out[i].Server+out[i].ServerPort < out[j].Server+out[j].ServerPort
	})
	return out
}

// scopeRank puts the in-jail hop first. It is the edge that is hardest to
// observe and the one a reader is most likely to be looking for.
func scopeRank(s FlowScope) int {
	switch s {
	case ScopeInJail:
		return 0
	case ScopeInternal:
		return 1
	}
	return 2
}

// Snapshot is the whole observable state, as served and as printed.
type Snapshot struct {
	Generated     time.Time     `json:"generated"`
	WindowSeconds float64       `json:"window_seconds"`
	IntervalMS    int64         `json:"interval_ms"`
	Samples       int64         `json:"samples"`
	UptimeSeconds float64       `json:"uptime_seconds"`
	LastCollect   time.Time     `json:"last_collect"`
	Participants  []Participant `json:"participants"`
	Listeners     []Listener    `json:"listeners"`
	Edges         []Edge        `json:"edges"`
	Flows         []Flow        `json:"flows"`

	// Firewall is what pf says, and the reason the exposure verdicts above
	// carry a Reachability as well.
	Firewall Firewall `json:"firewall"`

	// Gateways are the MCP gateway processes and the upstreams they have
	// spawned. These are PIPES, not sockets, and are kept out of Edges and
	// Flows on purpose: a parent-child pipe is a different relationship from
	// a TCP connection, and filing one as the other would make the
	// connection graph say something untrue.
	Gateways []GatewayProc `json:"gateways"`
	// GatewaysSeen is when the process table was last read, and
	// GatewaysAgeSeconds how long ago that was. Unlike the socket window
	// this is a single point-in-time reading, so its age is the only thing
	// that says how much to trust it.
	GatewaysSeen       time.Time `json:"gateways_seen"`
	GatewaysAgeSeconds float64   `json:"gateways_age_seconds"`

	Warnings []string `json:"warnings,omitempty"`
	ReadOnly bool     `json:"read_only"`
}

// Snapshot prunes anything older than the window and returns a copy.
func (w *Window) Snapshot(now time.Time, interval time.Duration) Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.prune(now)

	snap := Snapshot{
		Generated:     now,
		WindowSeconds: w.d.Seconds(),
		IntervalMS:    interval.Milliseconds(),
		Samples:       w.samples,
		UptimeSeconds: now.Sub(w.startedAt).Seconds(),
		LastCollect:   w.lastCollect,
		Firewall:      w.fw,
		GatewaysSeen:  w.gatewaysAt,
		ReadOnly:      true,
	}
	if !w.gatewaysAt.IsZero() {
		snap.GatewaysAgeSeconds = now.Sub(w.gatewaysAt).Seconds()
	}
	for msg := range w.warnings {
		snap.Warnings = append(snap.Warnings, msg)
	}
	sort.Strings(snap.Warnings)
	if w.topo != nil {
		snap.Participants = append(snap.Participants, w.topo.Participants...)
	}
	for _, l := range w.listeners {
		c := *l
		c.Reachability, c.ReachabilityNote = classifyReachability(c.Exposure, c.Kind, w.fw)
		snap.Listeners = append(snap.Listeners, c)
	}
	snap.Gateways = w.annotateGateways(now)
	for _, f := range w.flows {
		snap.Flows = append(snap.Flows, *f)
	}
	sort.Slice(snap.Listeners, func(i, j int) bool {
		a, b := snap.Listeners[i], snap.Listeners[j]
		if a.JID != b.JID {
			return a.JID < b.JID
		}
		if a.Port != b.Port {
			return portLess(a.Port, b.Port)
		}
		return a.Addr < b.Addr
	})
	sort.Slice(snap.Flows, func(i, j int) bool {
		a, b := snap.Flows[i], snap.Flows[j]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.Client.Addr+a.Client.Port < b.Client.Addr+b.Client.Port
	})
	if snap.Listeners == nil {
		snap.Listeners = []Listener{}
	}
	if snap.Flows == nil {
		snap.Flows = []Flow{}
	}
	snap.Edges = edgesOf(snap.Flows)
	if snap.Edges == nil {
		snap.Edges = []Edge{}
	}
	if snap.Participants == nil {
		snap.Participants = []Participant{}
	}
	return snap
}

// annotateGateways names each gateway's jail and cross-checks the inference
// against the socket table. Called with the lock held.
//
// The cross-check is the honest part. Matching a process by its executable
// name is a guess, however good; a listening socket the kernel attributes to
// that same pid is independent evidence, from a different command, that this
// process is the gateway rather than something that happens to share its
// name. When it is absent the tree is still shown -- a gateway that has not
// bound yet is a real state -- and the display says which it is.
func (w *Window) annotateGateways(now time.Time) []GatewayProc {
	out := make([]GatewayProc, len(w.gateways))
	copy(out, w.gateways)
	for i := range out {
		g := &out[i]
		g.Owner = "jid " + itoa(g.JID)
		if w.topo != nil {
			if p := w.topo.Participant(g.JID); p != nil {
				g.Owner, g.Kind = p.Name, p.Kind
			}
		}
		g.ListensOn = nil
		for _, l := range w.listeners {
			if l.JID == g.JID && l.PID == itoa(g.PID) {
				g.ListensOn = append(g.ListensOn, l.Proto+" "+l.Addr+":"+l.Port)
			}
		}
		sort.Strings(g.ListensOn)
		if g.Upstreams == nil {
			g.Upstreams = []SpawnedProc{}
		}
	}
	return out
}

func portLess(a, b string) bool {
	ai, aok := atoiSafe(a)
	bi, bok := atoiSafe(b)
	if aok && bok {
		return ai < bi
	}
	return a < b
}

func atoiSafe(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
