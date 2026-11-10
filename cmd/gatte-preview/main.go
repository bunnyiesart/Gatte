//go:build preview

// Command gatte-preview serves the Gatte web console (internal/front/gatteweb)
// against the in-memory fake management API (internal/adminapitest), on
// loopback, for local UI development.
//
// It is MOCK-ONLY and exists behind the `preview` build tag, so it is never in
// the default build or the shipped binary. It is the one approved exception to
// "never build or run Gatte on the Mac": it runs NO real backend. It cannot be
// pointed at a real socket, backend, secret or network -- the fake is started
// in-process on a throwaway UNIX socket in a temp dir, and there is no flag to
// change that. The only knob is the loopback address to listen on.
//
// Run it through `make preview-console`, which watches the source and relaunches
// this on every change, so console CRUD updates as the code is edited.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/internal/front/gatteweb"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

const defaultListen = "127.0.0.1:8099"

func main() {
	listen := defaultListen
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}
	if err := run(listen); err != nil {
		fmt.Fprintf(os.Stderr, "gatte-preview: %v\n", err)
		os.Exit(1)
	}
}

func run(listen string) error {
	// The fake, on a throwaway UNIX socket. Nothing here can reach a real
	// backend: the socket path is one we just made in a temp dir.
	dir, err := os.MkdirTemp("", "gatte-preview")
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

	// Both console clients talk to the fake. adminapi.New (not NewAccounts)
	// so the accounts client skips the "server must be root" check: this is
	// mock data, not a privilege boundary.
	op := adminapi.New(sock, adminapi.WithFront(gatteweb.FrontName))
	acc := adminapi.New(sock, adminapi.WithFront(gatteweb.FrontName))

	kit, err := frontkit.New(frontkit.Config{Listen: listen, MaxBody: 6 << 20})
	if err != nil {
		return err
	}
	defer func() { _ = kit.Close() }()

	front, err := gatteweb.New(gatteweb.Options{Operator: op, Accounts: acc, Kit: kit})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = kit.Shutdown(shut)
	}()

	fmt.Printf("Gatte console PREVIEW (mock data only) on %s.\n\nOpen this link (it logs this browser in):\n\n    %s\n\nCtrl-C stops it. No real backend is running; every row is from the in-memory fake.\n",
		kit.Addr(), kit.LoginURL())
	if err := front.Serve(); err != nil {
		return err
	}
	return nil
}
