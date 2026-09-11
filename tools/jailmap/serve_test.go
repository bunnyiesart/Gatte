package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The refusal is the control, so it is the test.
// design/adr/0011-network-exposure-and-tls-termination.md item 1, and the
// same shape as cmd/mcp-gateway/serve_test.go's version.
func TestRequireLoopbackBind(t *testing.T) {
	accepted := []string{
		"127.0.0.1:8088",
		"127.0.1.10:8088",
		"[::1]:8088",
		"localhost:8088",
	}
	for _, addr := range accepted {
		if err := requireLoopbackBind(addr); err != nil {
			t.Errorf("requireLoopbackBind(%q) refused a loopback bind: %v", addr, err)
		}
	}

	refused := []string{
		"0.0.0.0:8088",       // the wildcard, the usual way this goes wrong
		"[::]:8088",          // and its v6 spelling
		"10.17.90.10:8088",   // a concrete jail address
		"192.168.127.2:8088", // a concrete host address
		":8088",              // empty host is the wildcard
		"8088",               // unparseable: "cannot tell" is not "safe"
		"",
	}
	for _, addr := range refused {
		err := requireLoopbackBind(addr)
		if err == nil {
			t.Errorf("requireLoopbackBind(%q) allowed a network-reachable bind", addr)
			continue
		}
		// The message has to name the fix, not just the problem.
		if !strings.Contains(err.Error(), "ssh -L") {
			t.Errorf("refusal for %q does not tell the operator how to reach it: %q", addr, err)
		}
	}
}

// There is deliberately no override, and this is what keeps it that way:
// nothing in the flag set may be able to switch the check off.
func TestNoOverrideFlagExists(t *testing.T) {
	for _, args := range [][]string{
		{"-listen", "0.0.0.0:8088"},
		{"-listen", "10.17.90.10:8088"},
	} {
		if err := cmdServe(args); err == nil {
			t.Errorf("cmdServe(%v) started on a non-loopback address", args)
		}
	}
}

func testSnapshotServer(t *testing.T) *Server {
	t.Helper()
	w, now := seedWindow(t)
	pred := w.ListenerPredicate()
	for _, s := range mustParse(t, connsGateway) {
		w.ObserveConnection(now, 5, s, pred)
	}
	return NewServer(w, 250*time.Millisecond)
}

func TestSnapshotAPI(t *testing.T) {
	srv := testSnapshotServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/snapshot", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var snap Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if !snap.ReadOnly {
		t.Error("the snapshot must state that jailmap is read-only")
	}
	if len(snap.Participants) != 3 {
		t.Errorf("got %d participants, want host + 2 jails", len(snap.Participants))
	}
	if findFlow(snap, "26702", "8080") == nil {
		t.Error("the in-jail hop did not survive the trip through JSON")
	}
}

// The MCP upstreams have to be in the API, not only in the terminal
// output: the dashboard reads this and nothing else.
func TestSnapshotAPICarriesTheMCPProcessTree(t *testing.T) {
	srv := testSnapshotServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/snapshot", nil))

	var snap Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if len(snap.Gateways) != 1 || len(snap.Gateways[0].Upstreams) != 4 {
		t.Fatalf("gateways = %+v, want one gateway with four upstreams", snap.Gateways)
	}
	if snap.Gateways[0].Owner != "mcp-gateway-test" {
		t.Errorf("gateway owner = %q", snap.Gateways[0].Owner)
	}
	if snap.GatewaysSeen.IsZero() {
		t.Error("a point-in-time reading without its timestamp cannot be judged stale")
	}
	// It must be its own thing in the payload, never folded into the
	// connection graph.
	for _, e := range snap.Edges {
		if e.ServerPort == "" && e.Server == "" {
			t.Errorf("a pipe leaked into the edge list: %+v", e)
		}
	}

	if !snap.Firewall.DefaultDenyIn || snap.Firewall.Summary == "" {
		t.Errorf("firewall = %+v", snap.Firewall)
	}
	// The whole point of the qualifier: a host listener bound in the clear
	// on a wildcard, behind a default-deny pf, must not read the same as
	// one with nothing in front of it.
	var syslog *Listener
	for i, l := range snap.Listeners {
		if l.Port == "514" && l.JID == 0 {
			syslog = &snap.Listeners[i]
		}
	}
	if syslog == nil {
		t.Fatal("the host syslogd listener is missing from the snapshot")
	}
	if syslog.Exposure != ExposurePlaintext {
		t.Errorf("syslogd exposure = %q; the bind is still plaintext and must still say so", syslog.Exposure)
	}
	if syslog.Reachability != ReachFiltered || syslog.ReachabilityNote == "" {
		t.Errorf("syslogd reachability = %q/%q, want filtered with a reason", syslog.Reachability, syslog.ReachabilityNote)
	}
}

// jailmap has no verb that changes anything, and the server should not
// accept one either.
func TestWriteMethodsAreRefused(t *testing.T) {
	srv := testSnapshotServer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, path := range []string{"/", "/api/snapshot"} {
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s returned %d, want 405", method, path, rec.Code)
			}
		}
	}
}

func TestDashboardIsEmbedded(t *testing.T) {
	srv := testSnapshotServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d serving the dashboard", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<title>jailmap</title>") {
		t.Error("the embedded dashboard is not what was served")
	}
	// The page loads nothing from anywhere else; if that ever changes, the
	// CSP will break it loudly rather than quietly phoning out from a host
	// that is meant to be reachable only over a VPN.
	//
	// "<script src=" used to be on this list, and that was wrong -- it
	// conflated "external" with "not inline". The script MUST be a separate
	// same-origin file: serve.go grants 'unsafe-inline' to styles only, so
	// an inline <script> falls through to default-src 'self' and is refused
	// by the browser. The page then renders, the CSS applies, and not one
	// line of JavaScript runs. That happened, and it cost an afternoon to
	// find because curl does not enforce CSP.
	//
	// So what is forbidden is a reference that leaves this origin, not a
	// reference as such.
	for _, forbidden := range []string{"https://", "http://", "src=\"//", "src='//"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the dashboard references something external (%q)", forbidden)
		}
	}

	// And the converse, which is the property that actually broke: the
	// script has to be loaded from a file, because inline is unusable under
	// this CSP. Without this check, someone "tidying up" by inlining it
	// again would reintroduce a silently blank dashboard.
	if !strings.Contains(body, `<script src="/app.js"`) {
		t.Error("the dashboard must load its script from /app.js -- an inline <script> is refused by the CSP in serve.go")
	}
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	if rec2.Code != http.StatusOK {
		t.Errorf("/app.js status %d -- the dashboard references a script that is not served", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "/api/snapshot") {
		t.Error("/app.js does not look like the dashboard script")
	}
}
