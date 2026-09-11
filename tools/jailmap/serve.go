// Package main -- jailmap HTTP server.
//
// STRICTLY READ-ONLY. Every handler here answers GET and nothing else.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

// requireLoopbackBind refuses to start on anything but loopback.
//
// This is the same rule, and the same reasoning, as
// cmd/mcp-gateway/serve.go's requireLoopbackBind
// (design/adr/0011-network-exposure-and-tls-termination.md item 1), and it
// applies here at least as strongly. This dashboard is a complete map of
// the internal layout of every jail on the box: every listener, every
// address, every port, which of them are in cleartext, and who is currently
// connected to whom. It is a reconnaissance report that refreshes itself.
// It terminates no TLS and authenticates nobody, so a non-loopback bind
// publishes all of that to whoever can route to the address.
//
// There is deliberately no override flag, for the reason ADR-0011 gives:
// an `allow_insecure_bind` gets switched on once "so a colleague can look"
// and never switched off. Reach it from a workstation with
// `ssh -L 8088:127.0.0.1:8088`; the README has the line.
func requireLoopbackBind(listen string) error {
	if isLoopbackAddr(listen) {
		return nil
	}
	return fmt.Errorf(
		"listen: %q is not a loopback address, and jailmap refuses to be network-reachable (design/adr/0011)\n"+
			"This dashboard is a live map of every jail's listeners, addresses and connections, with no auth and no TLS.\n"+
			"Set -listen to 127.0.0.1:%s and reach it over an SSH tunnel: ssh -L %s:127.0.0.1:%s <host>",
		listen, portOf(listen), portOf(listen), portOf(listen))
}

// isLoopbackAddr reports whether a host:port address is reachable only from
// this machine. An address it cannot parse, and the wildcard bind, are
// reported as not loopback: "cannot tell" must not read as "safe".
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return "PORT"
}

// Server serves the dashboard and the snapshot API.
type Server struct {
	win      *Window
	interval time.Duration
	mux      *http.ServeMux
}

// NewServer wires the routes.
func NewServer(win *Window, interval time.Duration) *Server {
	s := &Server{win: win, interval: interval, mux: http.NewServeMux()}

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("jailmap: embedded web assets missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	s.mux.HandleFunc("/api/snapshot", s.handleSnapshot)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !allowGET(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("jailmap: embedded dashboard missing: " + err.Error())
	}

	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowGET(w, r) {
			return
		}
		// The dashboard is same-origin only and loads nothing external, so
		// a strict policy costs nothing and forecloses the class of bug
		// where a process name lands in the DOM as markup.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			// Served directly rather than through the file server, which
			// would answer "/" with a redirect and "/index.html" with
			// another one back.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(index)
			return
		}
		files.ServeHTTP(w, r)
	})
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func allowGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	// jailmap has no verb that changes anything, so anything but a read is
	// a mistake and is answered as one.
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "jailmap is read-only", http.StatusMethodNotAllowed)
	return false
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !allowGET(w, r) {
		return
	}
	snap := s.win.Snapshot(time.Now(), s.interval)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

// ListenAndServe starts the dashboard, refusing any non-loopback bind.
func ListenAndServe(ctx context.Context, listen string, h http.Handler) error {
	if err := requireLoopbackBind(listen); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
