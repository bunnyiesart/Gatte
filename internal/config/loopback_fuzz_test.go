package config

import (
	"net"
	"strings"
	"testing"
)

// FuzzRequireLoopbackBind checks the ADR-0011 control from the outside: any
// listen address RequireLoopbackBind accepts must name a loopback host and a
// port that resolves to a TCP port number. Port 0 (ephemeral) is accepted
// by the current code and serve_test.go relies on it, so it is tolerated
// here; the security property checked is the loopback host. It never resolves a hostname
// (the only name accepted is the literal "localhost"), so it does no DNS.
func FuzzRequireLoopbackBind(f *testing.F) {
	for _, s := range []string{
		"127.0.0.1:8080", "[::1]:8080", "localhost:8080", "LOCALHOST:http",
		"0.0.0.0:8080", ":8080", "127.0.0.1:", "127.0.0.1:https!",
		"[::ffff:127.0.0.1]:80", "127.1.2.3:443", "[::1%lo0]:80", "10.0.0.1:80",
		"127.0.0.1:0", "localhost.:80",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, listen string) {
		if RequireLoopbackBind(listen) != nil {
			return
		}
		host, port, err := net.SplitHostPort(listen)
		if err != nil {
			t.Fatalf("accepted %q, which does not split: %v", listen, err)
		}
		if !strings.EqualFold(host, "localhost") {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				t.Fatalf("accepted %q whose host %q is not a loopback IP", listen, host)
			}
		}
		p, err := net.LookupPort("tcp", port)
		if err != nil {
			t.Fatalf("accepted %q whose port %q does not resolve: %v", listen, port, err)
		}
		if p < 0 || p > 65535 {
			t.Fatalf("accepted %q whose port resolves to out-of-range %d", listen, p)
		}
	})
}
