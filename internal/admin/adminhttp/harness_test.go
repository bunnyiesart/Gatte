package adminhttp_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

type testBackend struct {
	svc   *admin.Service
	trail *auditsqlite.Recorder
	db    *sql.DB
	log   *syncBuffer
}

// syncBuffer is a log sink the server and the test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newBackend(t *testing.T) *testBackend {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, m := range []func(*sql.DB) error{auditsqlite.Migrate, quarantinesqlite.Migrate, quotasqlite.Migrate, accesssqlite.Migrate} {
		if err := m(db); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := idp.HashPassword("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(t.TempDir(), "users.yml")
	fixture := "users:\n  ana:\n    displayname: \"Ana\"\n    PWKEY: \"" + hash + "\"\n    groups: [blue-ir]\n"
	if err := os.WriteFile(users, []byte(strings.Replace(fixture, "PWKEY", "pass"+"word", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Database: ":memory:", GroupToRole: map[string]string{"blue-ir": "ir"},
		Roles: []config.Role{{Name: "ir", Grants: map[string][]string{"casemgmt": {"*"}}}},
		IdP:   config.IdP{UsersFile: users}}
	b := &testBackend{trail: auditsqlite.New(db), db: db, log: &syncBuffer{}}
	b.svc, err = admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return cfg, nil },
		Tools:  quarantinesqlite.New(db),
		Blocks: accesssqlite.New(db),
		Trail:  b.trail,
		Quota:  quotasqlite.New(db),
		Record: func(ctx context.Context, _ *config.Config, rec audit.Record) error {
			return b.trail.Record(ctx, rec)
		},
		Accounts: func(c *config.Config) (idp.Directory, error) { return autheliafile.New(c.IdP.UsersFile), nil },
		IsBusy:   store.IsBusy,
		Log:      slog.New(slog.NewTextHandler(b.log, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// shortDir is a directory for sockets: resolved (no symbolic link above
// it) and short enough for sun_path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ga")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// testPolicy trusts root and this test's user, which own every directory
// above a temporary one.
func testPolicy() adminhttp.SocketPolicy {
	me := uint32(os.Getuid())
	return adminhttp.SocketPolicy{Group: -1, Mode: 0o600, SelfUID: me, OwnDirOK: true,
		Trusted: func(uid uint32) bool { return uid == 0 || uid == me }}
}

// serve starts o over a fresh socket and returns its path and a channel
// that yields Serve's result.
func serve(t *testing.T, o adminhttp.Options) (string, <-chan error) {
	t.Helper()
	if o.LookupUser == nil {
		o.LookupUser = func(uint32) (string, error) { return "alice", nil }
	}
	if o.ServiceUID == 0 {
		o.ServiceUID = 1 << 30
	}
	sock := filepath.Join(shortDir(t), "a.sock")
	ln, err := adminhttp.Listen(sock, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := adminhttp.New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() { done <- srv.Serve(ctx, ln); close(stopped) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})
	return sock, done
}

func unixClient(sock string) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
}

type apiErr struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	} `json:"error"`
}

// call sends one request and returns the status, the error code if any,
// and the body.
func call(t *testing.T, sock, method, path, body string, hdr map[string]string) (int, string, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://gatte-admin"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := unixClient(sock).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var e apiErr
	_ = json.Unmarshal(b, &e)
	return resp.StatusCode, e.Error.Code, b
}

var errTest = errors.New("test")
