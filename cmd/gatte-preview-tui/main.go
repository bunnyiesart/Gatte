//go:build preview

// Command gatte-preview-tui runs the Gatte terminal front
// (internal/front/gattetui) against the in-memory fake management API
// (internal/adminapitest), for local UI work.
//
// It is MOCK-ONLY and exists behind the `preview` build tag, so it is never in
// the default build or the shipped binary. Like cmd/gatte-preview it runs NO
// real backend: the fake is started in-process on a throwaway UNIX socket in a
// temp dir, and there is no flag to point it anywhere else.
//
// With -gallery it prints every screen and state once, as text, and exits.
// Run it through `make preview-tui` (or `make preview-tui ARGS=-gallery`).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/internal/front/gattetui"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func main() {
	gallery := flag.Bool("gallery", false, "print every screen and state as text, then exit")
	readOnly := flag.Bool("read-only", false, "run without the accounts socket, as mcp-gateway tui without -manage-users")
	flag.Parse()
	if err := run(*gallery, *readOnly); err != nil {
		fmt.Fprintf(os.Stderr, "gatte-preview-tui: %v\n", err)
		os.Exit(1)
	}
}

func run(gallery, readOnly bool) error {
	dir, err := os.MkdirTemp("", "gatte-tui")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "fake.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("fake socket: %w", err)
	}
	fake := &http.Server{Handler: adminapitest.New().Handler()}
	go func() { _ = fake.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = fake.Shutdown(ctx)
	}()

	// adminapi.New for the accounts client too: it skips the "server must be
	// root" check, which guards a real privilege boundary the fake is not.
	o := gattetui.Options{Operator: adminapi.New(sock, adminapi.WithFront(gattetui.FrontName))}
	if !readOnly {
		o.Accounts = adminapi.New(sock, adminapi.WithFront(gattetui.FrontName))
	}
	if gallery {
		return gattetui.Gallery(os.Stdout, o)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return gattetui.Run(ctx, o, os.Stdin, os.Stdout)
}
