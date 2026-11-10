package adminapitest

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Clients are pkg/adminapi clients wired to a running fake. Operator and
// Accounts talk to the same fake over one socket: the fake does not enforce
// the socket split, which is a privilege boundary of the real backend, not
// something a frontend's rendering depends on.
type Clients struct {
	Server   *Server
	Socket   string
	Operator *adminapi.Client
	Accounts *adminapi.Client
}

// Start runs the fake on a temporary UNIX socket for the duration of the test
// and returns clients wired to it. The socket is removed on cleanup.
//
// The accounts client is built with adminapi.New, not NewAccounts, so it skips
// the "server must be root" check: the fake runs as the test user, and the
// check guards a real privilege boundary the fake has no business asserting.
func Start(t testing.TB) *Clients {
	t.Helper()
	srv := New()
	sock := filepath.Join(shortTempDir(t), "fake.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("adminapitest: listen: %v", err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})
	return &Clients{
		Server:   srv,
		Socket:   sock,
		Operator: adminapi.New(sock, adminapi.WithFront("ui")),
		Accounts: adminapi.New(sock, adminapi.WithFront("ui")),
	}
}

// shortTempDir returns a temp dir short enough for a UNIX socket path (the sun_path
// limit is ~104 bytes on some systems, which t.TempDir can exceed).
func shortTempDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "gat")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if r, err := filepath.EvalSymlinks(d); err == nil {
		d = r
	}
	return d
}
