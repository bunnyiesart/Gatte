package main

import (
	"testing"
	"time"
)

func seedWindow(t *testing.T) (*Window, time.Time) {
	t.Helper()
	w := NewWindow(5 * time.Minute)
	w.SetTopology(labTopology(), nil)
	// Relative to the wall clock, because the server prunes against
	// time.Now() and a fixed date would be pruned as ancient.
	now := time.Now()

	for _, s := range mustParse(t, listenersGateway) {
		w.ObserveListener(now, 5, s)
	}
	for _, s := range mustParse(t, listenersAuthelia) {
		w.ObserveListener(now, 1, s)
	}
	for _, s := range mustParse(t, listenersHost) {
		w.ObserveListener(now, 0, s)
	}

	rows, warns := parsePS(psFixture)
	if len(warns) != 0 {
		t.Fatalf("ps fixture did not parse cleanly: %v", warns)
	}
	w.SetGateways(findGateways(rows, DefaultGatewayCommand), now)

	fw := Firewall{Engine: "pf", Known: true, Enabled: true, RulesKnown: true}
	fw.Rules, fw.DefaultDenyIn, fw.DenyRule = parsePFRules(pfRulesBun)
	fw.Summary = summarizeFirewall(fw)
	w.SetFirewall(fw)
	return w, now
}

func mustParse(t *testing.T, out string) []Socket {
	t.Helper()
	socks, warns := parseSockstat(out)
	if len(warns) != 0 {
		t.Fatalf("fixture did not parse cleanly: %v", warns)
	}
	return socks
}

func findFlow(s Snapshot, clientPort, serverPort string) *Flow {
	for i := range s.Flows {
		if s.Flows[i].Client.Port == clientPort && s.Flows[i].Server.Port == serverPort {
			return &s.Flows[i]
		}
	}
	return nil
}

// The in-jail hop, end to end through the window: both ends are loopback so
// neither is obviously the client, and the direction has to come from the
// observed listener set rather than from a guess.
func TestInJailHopIsRecordedWithBothEndsNamed(t *testing.T) {
	w, now := seedWindow(t)
	pred := w.ListenerPredicate()
	for _, s := range mustParse(t, connsGateway) {
		w.ObserveConnection(now, 5, s, pred)
	}
	snap := w.Snapshot(now, 250*time.Millisecond)

	f := findFlow(snap, "26702", "8080")
	if f == nil {
		t.Fatal("the nginx -> 127.0.0.1:8080 hop is missing from the window")
	}
	if f.Client.Name != "mcp-gateway-test" || f.Server.Name != "mcp-gateway-test" {
		t.Errorf("hop ends named %q -> %q, want both mcp-gateway-test", f.Client.Name, f.Server.Name)
	}
	if f.Scope != ScopeInJail {
		t.Errorf("hop scope = %q, want %q", f.Scope, ScopeInJail)
	}
	if f.DirectionInferred {
		t.Error("8080 is a known listener of this jail, so the direction was observed, not inferred")
	}
	if f.Server.Port != "8080" {
		t.Errorf("server side is %s, want 8080", f.Server.Port)
	}
}

func TestExternalTrafficKeepsUnknownEndsUnnamed(t *testing.T) {
	w, now := seedWindow(t)
	pred := w.ListenerPredicate()
	for _, s := range mustParse(t, connsGateway) {
		w.ObserveConnection(now, 5, s, pred)
	}
	snap := w.Snapshot(now, time.Second)

	f := findFlow(snap, "51217", "443")
	if f == nil {
		t.Fatal("the 10.17.90.1 -> nginx:443 flow is missing")
	}
	// 10.17.90.1 is the host's socbr0 address, so this one IS known.
	if f.Client.Name != "host" {
		t.Errorf("client named %q, want host", f.Client.Name)
	}
	if f.Server.Name != "mcp-gateway-test" {
		t.Errorf("server named %q, want mcp-gateway-test", f.Server.Name)
	}
	if f.Scope != ScopeInternal {
		t.Errorf("scope = %q, want %q", f.Scope, ScopeInternal)
	}
}

func TestUnattributedSocketDoesNotBorrowAProcessName(t *testing.T) {
	w, now := seedWindow(t)
	pred := w.ListenerPredicate()
	for _, s := range mustParse(t, connsGateway) {
		w.ObserveConnection(now, 5, s, pred)
	}
	snap := w.Snapshot(now, time.Second)
	f := findFlow(snap, "26702", "8080")
	if f == nil {
		t.Fatal("hop missing")
	}
	// Every row of that hop was "??" in the fixture. Filling it in from the
	// nginx rows above it would be a fabrication.
	if f.ClientProc != "" || f.ServerProc != "" {
		t.Errorf("a ?? socket was given process names %q/%q", f.ClientProc, f.ServerProc)
	}
}

func TestRepeatedObservationsAggregate(t *testing.T) {
	w, now := seedWindow(t)
	socks := mustParse(t, connsGateway)
	for i := 0; i < 4; i++ {
		pred := w.ListenerPredicate()
		for _, s := range socks {
			w.ObserveConnection(now.Add(time.Duration(i)*250*time.Millisecond), 5, s, pred)
		}
	}
	later := now.Add(time.Second)
	snap := w.Snapshot(later, 250*time.Millisecond)

	f := findFlow(snap, "26702", "8080")
	if f == nil {
		t.Fatal("hop missing")
	}
	if f.Samples != 4 {
		t.Errorf("samples = %d, want 4", f.Samples)
	}
	if !f.FirstSeen.Equal(now) {
		t.Errorf("first seen = %s, want %s", f.FirstSeen, now)
	}
	if f.AgeSeconds(later) < 0.24 {
		t.Errorf("age = %.3fs; the flow was last seen 250ms before the snapshot", f.AgeSeconds(later))
	}
	// One connection, four observations -- not four connections.
	hops := 0
	for _, g := range snap.Flows {
		if g.Scope == ScopeInJail {
			hops++
		}
	}
	if hops != 3 {
		t.Errorf("got %d in-jail flows, want the 3 distinct source ports in the fixture", hops)
	}
}

// The window is the point of the tool, so the thing that empties it needs a
// test: a flow that stops being seen must fall out at the boundary, not
// linger forever and not vanish the moment it stops.
func TestWindowPrunesOnlyPastTheBoundary(t *testing.T) {
	w := NewWindow(2 * time.Second)
	w.SetTopology(labTopology(), nil)
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	pred := w.ListenerPredicate()
	for _, s := range mustParse(t, connsGateway) {
		w.ObserveConnection(now, 5, s, pred)
	}

	if got := len(w.Snapshot(now.Add(1900*time.Millisecond), time.Second).Flows); got == 0 {
		t.Error("flows disappeared before the window elapsed")
	}
	if got := len(w.Snapshot(now.Add(3*time.Second), time.Second).Flows); got != 0 {
		t.Errorf("%d flows survived past the window", got)
	}
}

func TestListenerExposureReachesTheSnapshot(t *testing.T) {
	w, now := seedWindow(t)
	snap := w.Snapshot(now, time.Second)

	want := map[string]Exposure{
		"10.17.89.20:80":   ExposurePlaintext,
		"10.17.89.20:9091": ExposurePlaintext,
		"10.17.89.20:443":  ExposureEncrypted,
		"10.17.90.10:443":  ExposureEncrypted,
		"127.0.0.1:8080":   ExposureLocal,
		"*:514":            ExposurePlaintext,
		"*:22":             ExposureEncrypted,
	}
	got := map[string]Exposure{}
	owners := map[string]string{}
	for _, l := range snap.Listeners {
		got[l.Addr+":"+l.Port] = l.Exposure
		owners[l.Addr+":"+l.Port] = l.Owner
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("listener %s exposure = %q, want %q", k, got[k], v)
		}
	}
	if owners["127.0.0.1:8080"] != "mcp-gateway-test" {
		t.Errorf("the gateway listener is owned by %q, want mcp-gateway-test", owners["127.0.0.1:8080"])
	}
	if owners["10.17.89.20:9091"] != "authelia" {
		t.Errorf("authelia's listener is owned by %q, want authelia", owners["10.17.89.20:9091"])
	}
}

func TestWarningsAreDeduplicatedAndAged(t *testing.T) {
	w := NewWindow(50 * time.Millisecond)
	w.SetTopology(labTopology(), nil)
	w.AddWarning("jid 5: connections unavailable: sockstat: jail not found")
	w.AddWarning("jid 5: connections unavailable: sockstat: jail not found")

	if got := len(w.Snapshot(time.Now(), time.Second).Warnings); got != 1 {
		t.Errorf("got %d warnings, want 1 after deduplication", got)
	}
	time.Sleep(80 * time.Millisecond)
	if got := len(w.Snapshot(time.Now(), time.Second).Warnings); got != 0 {
		t.Errorf("got %d warnings, want them aged out of the window", got)
	}
}

func TestDirectionIsInferredWhenNoListenerMatches(t *testing.T) {
	w := NewWindow(time.Minute)
	w.SetTopology(labTopology(), nil)
	now := time.Now()
	// No listeners observed at all: the predicate can say nothing.
	s := Socket{User: "root", Command: "curl", PID: "1", FD: "3", Proto: "tcp4",
		Local:   Endpoint{Addr: "10.17.90.10", Port: "40000"},
		Foreign: Endpoint{Addr: "10.17.89.20", Port: "443"}}
	w.ObserveConnection(now, 5, s, w.ListenerPredicate())

	snap := w.Snapshot(now, time.Second)
	if len(snap.Flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(snap.Flows))
	}
	f := snap.Flows[0]
	if !f.DirectionInferred {
		t.Error("direction must be marked inferred when nothing matched a listener")
	}
	if f.Server.Port != "443" {
		t.Errorf("inferred server port = %s, want the lower port 443", f.Server.Port)
	}
}

func TestEdgesCollapseSourcePortsAndPutTheInJailHopFirst(t *testing.T) {
	w, now := seedWindow(t)
	pred := w.ListenerPredicate()
	for _, s := range mustParse(t, connsGateway) {
		w.ObserveConnection(now, 5, s, pred)
	}
	snap := w.Snapshot(now, time.Second)

	if len(snap.Edges) != 2 {
		t.Fatalf("got %d edges, want 2 (the in-jail hop and host -> nginx): %+v", len(snap.Edges), snap.Edges)
	}
	// The hardest edge to observe is the one a reader is looking for, so it
	// leads.
	hop := snap.Edges[0]
	if hop.Scope != ScopeInJail {
		t.Fatalf("first edge is %q, want the in-jail hop", hop.Scope)
	}
	if hop.Client != "mcp-gateway-test" || hop.Server != "mcp-gateway-test" || hop.ServerPort != "8080" {
		t.Errorf("hop edge = %+v", hop)
	}
	// Three source ports in the fixture, one edge.
	if hop.Connections != 3 {
		t.Errorf("hop edge collapsed %d connections, want 3", hop.Connections)
	}

	web := snap.Edges[1]
	if web.Scope != ScopeInternal || web.Client != "host" || web.ServerPort != "443" {
		t.Errorf("second edge = %+v", web)
	}
	if web.Connections != 3 {
		t.Errorf("nginx edge collapsed %d connections, want 3", web.Connections)
	}
}

func TestListenerOnlySocketsAreNotFlows(t *testing.T) {
	w, now := seedWindow(t)
	pred := w.ListenerPredicate()
	// Feeding the listener rows through the connection path must produce
	// nothing: "*:*" is the absence of a peer, not a peer.
	for _, s := range mustParse(t, listenersHost) {
		w.ObserveConnection(now, 0, s, pred)
	}
	if got := len(w.Snapshot(now, time.Second).Flows); got != 0 {
		t.Errorf("got %d flows from listener rows, want 0", got)
	}
}
