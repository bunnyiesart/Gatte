package adminhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// TestIdentity_ComesFromThePeerAndNotFromTheRequest is design/adr/0040 §2:
// nothing a client sends names the operator.
func TestIdentity_ComesFromThePeerAndNotFromTheRequest(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})

	// A body that tries to name the operator is refused outright.
	status, code, _ := call(t, sock, "POST", "/v1/access/block", `{"subject":"sub-1","operator":"mallory"}`, nil)
	if status != 400 || code != adminapi.CodeBadRequest {
		t.Fatalf("a body with an operator field: %d %s, want 400 bad_request", status, code)
	}
	// Headers that try are ignored; the front label is display only.
	status, _, body := call(t, sock, "POST", "/v1/access/block", `{"subject":"sub-1","reason":"stolen laptop"}`, map[string]string{
		"X-Operator": "mallory", "Gatte-Operator": "mallory", "X-Forwarded-User": "mallory", adminapi.FrontHeader: "myfront",
	})
	if status != 200 {
		t.Fatalf("block: %d %s", status, body)
	}
	rows, err := b.trail.List(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	if rows[0].AnalystIdentity != "(operator:alice)" || strings.Contains(rows[0].Reason, "mallory") || !strings.Contains(rows[0].Reason, "[myfront] stolen laptop") {
		t.Fatalf("row %+v, want (operator:alice) with the [myfront] tag and no client-chosen name", rows[0])
	}

	_, _, body = call(t, sock, "GET", "/v1/whoami", "", map[string]string{adminapi.FrontHeader: "myfront"})
	var me adminapi.WhoAmI
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	if me.Operator.Name != "alice" || me.Operator.UID != uint32(os.Geteuid()) || me.Socket != adminapi.SocketOperator ||
		me.ContractVersion != adminapi.ContractVersion || me.Front != "myfront" {
		t.Fatalf("whoami %+v", me)
	}
}

// TestFrontLabel_OutsideItsCharsetIsRefused: the label lands in the trail.
func TestFrontLabel_OutsideItsCharsetIsRefused(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	for _, bad := range []string{"UI", "a b", "x\u202e", strings.Repeat("a", 33)} {
		if status, code, _ := call(t, sock, "GET", "/v1/whoami", "", map[string]string{adminapi.FrontHeader: bad}); status != 400 || code != adminapi.CodeBadRequest {
			t.Errorf("Gatte-Front %q: %d %s, want 400 bad_request", bad, status, code)
		}
	}
}

// TestPeer_WithNoAccountNameIsRefused: an action without an author is not
// a record.
func TestPeer_WithNoAccountNameIsRefused(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc,
		LookupUser: func(uint32) (string, error) { return "", errTest }})
	if status, code, _ := call(t, sock, "GET", "/v1/whoami", "", nil); status != 403 || code != adminapi.CodePeerUnattributable {
		t.Fatalf("a peer with no name: %d %s, want 403 peer_unattributable", status, code)
	}
}

// TestBrowserRequests_AreRefused: a browser's request must never reach
// the socket as it is.
func TestBrowserRequests_AreRefused(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	for _, h := range []map[string]string{{"Origin": "http://127.0.0.1:8090"}, {"Cookie": "gatte_ui=abc"}} {
		if status, code, _ := call(t, sock, "POST", "/v1/access/block", `{"subject":"sub-1"}`, h); status != 403 || code != adminapi.CodeBrowserRequestRefused {
			t.Errorf("request with %v: %d %s, want 403 browser_request_refused", h, status, code)
		}
	}
	if rows, _ := b.trail.List(context.Background()); len(rows) != 0 {
		t.Fatalf("a refused browser request changed state: %+v", rows)
	}
}

// TestRoutes_AccountRoutesAreAbsentOnTheOperatorSocket.
func TestRoutes_AccountRoutesAreAbsentOnTheOperatorSocket(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	for _, r := range []struct{ method, path, body string }{
		{"GET", "/v1/accounts", ""},
		{"POST", "/v1/accounts", `{"username":"bruno","display_name":"Bruno","groups":["blue-ir"]}`},
		{"GET", "/v1/accounts/ana", ""},
		{"POST", "/v1/accounts/ana/reset-password", ""},
		{"GET", "/v1/groups", ""},
		{"POST", "/v1/account-check", `{}`},
	} {
		status, code, body := call(t, sock, r.method, r.path, r.body, nil)
		if status != 404 || code != adminapi.CodeWrongSocket || !strings.Contains(string(body), `"socket":"accounts"`) {
			t.Errorf("%s %s on the operator socket: %d %s", r.method, r.path, status, body)
		}
	}
	if status, code, _ := call(t, sock, "GET", "/v1/nothing-here", "", nil); status != 404 || code != adminapi.CodeUnknownRoute {
		t.Errorf("unknown route: %d %s, want 404 unknown_route", status, code)
	}
	if status, code, _ := call(t, sock, "GET", "/v1/access/block", "", nil); status != 405 || code != adminapi.CodeMethodNotAllowed {
		t.Errorf("GET on a POST route: %d %s, want 405 method_not_allowed", status, code)
	}
}

// TestRoutes_OperatorRoutesAreAbsentOnTheAccountsSocket.
func TestRoutes_OperatorRoutesAreAbsentOnTheAccountsSocket(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: b.svc})
	status, code, body := call(t, sock, "POST", "/v1/access/block", `{"subject":"x"}`, nil)
	if status != 404 || code != adminapi.CodeWrongSocket || !strings.Contains(string(body), `"socket":"operator"`) {
		t.Fatalf("block on the accounts socket: %d %s", status, body)
	}
}

// TestAccountsSocket_RefusesTheServiceAccount even if the file mode was
// widened by mistake (design/adr/0040 §1).
func TestAccountsSocket_RefusesTheServiceAccount(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: b.svc, ServiceUID: uint32(os.Geteuid())})
	if status, code, _ := call(t, sock, "POST", "/v1/accounts/ana/reset-password", "", nil); status != 403 || code != adminapi.CodeForbiddenPeer {
		t.Fatalf("the service account on the accounts socket: %d %s, want 403 forbidden_peer", status, code)
	}
}

// TestOperatorSocket_WithAnOperatorGroupRefusesAPeerOutsideIt.
func TestOperatorSocket_WithAnOperatorGroupRefusesAPeerOutsideIt(t *testing.T) {
	b := newBackend(t)
	other := uint32(1<<31 - 7)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc, OperatorGID: &other})
	if os.Geteuid() != 0 {
		if status, code, _ := call(t, sock, "GET", "/v1/whoami", "", nil); status != 403 || code != adminapi.CodeForbiddenPeer {
			t.Fatalf("a peer outside the operator group: %d %s, want 403 forbidden_peer", status, code)
		}
	}
	mine := uint32(os.Getegid())
	sock, _ = serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc, OperatorGID: &mine})
	if status, _, body := call(t, sock, "GET", "/v1/whoami", "", nil); status != 200 {
		t.Fatalf("a peer in the operator group: %d %s", status, body)
	}
}

// TestBody_LimitAndUnknownFields.
func TestBody_LimitAndUnknownFields(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	big := `{"subject":"sub-1","reason":"` + strings.Repeat("a", 70<<10) + `"}`
	if status, code, _ := call(t, sock, "POST", "/v1/access/block", big, nil); status != 413 || code != adminapi.CodePayloadTooLarge {
		t.Errorf("a 70 KiB body: %d %s, want 413 payload_too_large", status, code)
	}
	if status, code, _ := call(t, sock, "POST", "/v1/tools/approve", `{"server":"a","tool":"b","fingerprnt":"x"}`, nil); status != 400 || code != adminapi.CodeBadRequest {
		t.Errorf("a misspelt field: %d %s, want 400 bad_request", status, code)
	}
}

// TestActivation_RefusesAFileThatIsNotAUnixStreamSocket.
func TestActivation_RefusesAFileThatIsNotAUnixStreamSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := adminhttp.ListenersFromFiles([]*os.File{f}); err == nil {
		t.Fatal("a TCP socket handed over by the service manager was accepted")
	}

	sock := filepath.Join(shortDir(t), "u.sock")
	uln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer uln.Close()
	uf, err := uln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer uf.Close()
	got, err := adminhttp.ListenersFromFiles([]*os.File{uf})
	if err != nil || len(got) != 1 {
		t.Fatalf("a UNIX stream socket: %v, %v", got, err)
	}
	got[0].Close()
}

// TestIdle_TheProcessExitsWithAnOpenIdleConnection: an idle connection does
// not keep the backend up (design/adr/0040 §4).
func TestIdle_TheProcessExitsWithAnOpenIdleConnection(t *testing.T) {
	b := newBackend(t)
	sock, done := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc, Idle: 300 * time.Millisecond})
	if status, _, _ := call(t, sock, "GET", "/v1/whoami", "", nil); status != 200 {
		t.Fatal("whoami")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after idle: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the backend did not exit after its idle time with a connection open")
	}
}

// TestSlowBody_DoesNotHoldTheMutexOfAnotherOperator: the body is read and
// validated before the lock that serialises changes.
func TestSlowBody_DoesNotHoldTheMutexOfAnotherOperator(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	slow, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	fmt.Fprint(slow, "POST /v1/access/block HTTP/1.1\r\nHost: gatte-admin\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"subject\":")
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	status, _, body := call(t, sock, "POST", "/v1/access/block", `{"subject":"sub-2"}`, nil)
	if status != 200 {
		t.Fatalf("second operator: %d %s", status, body)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the second operator waited %v behind a slow body", d)
	}
}

// TestConnections_TheSeventeenthIsClosed.
func TestConnections_TheSeventeenthIsClosed(t *testing.T) {
	b := newBackend(t)
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: b.svc})
	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for i := 0; i < 16; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	time.Sleep(200 * time.Millisecond)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "GET /v1/whoami HTTP/1.1\r\nHost: gatte-admin\r\n\r\n")
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	// Closed is EOF on macOS and, on Linux, ECONNRESET: the server closes
	// without reading the request this test wrote, and a close with unread
	// data in the receive buffer resets the connection. Either way nothing
	// was served, which is the property.
	if n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatalf("the 17th connection read (%d, %v), want it closed", n, err)
	}
	// Closing one frees a slot.
	open[0].Close()
	open = open[1:]
	time.Sleep(200 * time.Millisecond)
	if status, _, _ := call(t, sock, "GET", "/v1/whoami", "", nil); status != 200 {
		t.Fatal("a freed slot was not reused")
	}
}

// TestListen_RefusesASocketDirectoryAnotherAccountCouldReplace.
func TestListen_RefusesASocketDirectoryAnotherAccountCouldReplace(t *testing.T) {
	base := shortDir(t)
	me := uint32(os.Getuid())
	rootOnly := func(uid uint32) bool { return uid == 0 }

	// The directory above the socket's belongs to the service account
	// (this test's user): refused, even though the socket's own directory
	// may be the process's.
	opdir := filepath.Join(base, "operator")
	if err := os.Mkdir(opdir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := adminhttp.SocketPolicy{Group: -1, Mode: 0o600, SelfUID: me, OwnDirOK: true, Trusted: rootOnly}
	if me != 0 {
		if _, err := adminhttp.Listen(filepath.Join(opdir, "operator.sock"), p); err == nil {
			t.Fatal("a socket directory under one the service account owns was accepted")
		}
	}

	trusting := testPolicy()
	// Group-writable socket directory.
	gw := filepath.Join(base, "gw")
	if err := os.Mkdir(gw, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gw, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := adminhttp.Listen(filepath.Join(gw, "a.sock"), trusting); err == nil {
		t.Error("a group-writable socket directory was accepted")
	}
	// A symbolic link on the way.
	link := filepath.Join(base, "link")
	if err := os.Symlink(opdir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := adminhttp.Listen(filepath.Join(link, "a.sock"), trusting); err == nil {
		t.Error("a socket path through a symbolic link was accepted")
	}
	// A path that exists and is not a socket.
	plain := filepath.Join(opdir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminhttp.Listen(plain, trusting); err == nil {
		t.Error("an existing regular file was replaced by a socket")
	}
	// A mode that lets others in.
	wide := trusting
	wide.Mode = 0o666
	if _, err := adminhttp.Listen(filepath.Join(opdir, "wide.sock"), wide); err == nil {
		t.Error("a socket mode open to others was accepted")
	}
	grp := trusting
	grp.Mode = 0o660
	if _, err := adminhttp.Listen(filepath.Join(opdir, "grp.sock"), grp); err == nil {
		t.Error("a group mode with no group named was accepted")
	}
}

// TestListen_AppliesGroupAndModeBeforeTheFirstConnection.
func TestListen_AppliesGroupAndModeBeforeTheFirstConnection(t *testing.T) {
	p := testPolicy()
	p.Group = os.Getegid()
	p.Mode = 0o660
	sock := filepath.Join(shortDir(t), "a.sock")
	ln, err := adminhttp.Listen(sock, p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v, want a socket with 0660", fi.Mode())
	}
}

// TestSocketGroup_MustMatchTheConfiguredAccountGroup is design/adr/0040 §1:
// delegating accounts needs both settings, and a mismatch refuses to start.
func TestSocketGroup_MustMatchTheConfiguredAccountGroup(t *testing.T) {
	gid := uint32(os.Getegid())
	cases := []struct {
		name     string
		cfgGID   *uint32
		fileGID  uint32
		fileMode os.FileMode
		ok       bool
	}{
		{"no delegation, root-only file", nil, 0, 0o600, true},
		{"delegated group, 0660 file of that group", &gid, gid, 0o660, true},
		{"delegated group, 0600 file", &gid, gid, 0o600, false},
		{"file of a group the configuration does not name", nil, gid, 0o660, false},
		{"delegated group, file of another group", &gid, gid + 1, 0o660, false},
	}
	for _, c := range cases {
		err := adminhttp.CheckAccountsFile(c.fileGID, c.fileMode, c.cfgGID)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// TestLoginUID_NamesOnlyARootPeer is design/adr/0040 §2: a process whose
// loginuid is unset may write it without privilege, and every process
// systemd starts as the service account has it unset. A service-account
// peer is therefore never renamed by its loginuid (it could claim any
// operator); only a root peer, which could write the trail anyway, is.
func TestLoginUID_NamesOnlyARootPeer(t *testing.T) {
	const svc = 990
	if !adminhttp.TrustsLoginUID(0, svc) {
		t.Error("a root peer (sudo) is not named by its loginuid")
	}
	if adminhttp.TrustsLoginUID(svc, svc) {
		t.Error("a service-account peer is named by a loginuid it could have written itself")
	}
	if adminhttp.TrustsLoginUID(1001, svc) {
		t.Error("an operator connecting as themselves is renamed by a loginuid")
	}
}

// TestOperatorSocket_AFileOpenToOthersRefusesToStart is design/adr/0040
// §1: the barrier is the operator socket's mode, so a socket-activated
// file that admits every local user, or one of a group other than
// [admin] operator_group, refuses to start.
func TestOperatorSocket_AFileOpenToOthersRefusesToStart(t *testing.T) {
	gid := uint32(os.Getegid())
	cases := []struct {
		name     string
		cfgGID   *uint32
		fileGID  uint32
		fileMode os.FileMode
		ok       bool
	}{
		{"service-only file", nil, 0, 0o600, true},
		{"operators group file, no operator_group", nil, gid, 0o660, true},
		{"operators group file matching operator_group", &gid, gid, 0o660, true},
		{"file open to others", nil, gid, 0o666, false},
		{"file open to others with operator_group", &gid, gid, 0o666, false},
		{"group file of another group than operator_group", &gid, gid + 1, 0o660, false},
	}
	for _, c := range cases {
		err := adminhttp.CheckOperatorFile(c.fileGID, c.fileMode, c.cfgGID)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
