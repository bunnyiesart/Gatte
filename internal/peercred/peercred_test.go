package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// shortTempDir is a directory whose socket paths fit sun_path (104 bytes
// on macOS); t.TempDir() can be longer than that.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// TestOf_TheKernelNamesThisProcessOnBothEndsOfARealSocket is design/adr/0040
// §2 and §4: the backend reads the connecting process from the kernel, and
// the client reads the serving one the same way.
func TestOf_TheKernelNamesThisProcessOnBothEndsOfARealSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()

	for side, conn := range map[string]net.Conn{"server side (the peer is the client)": server, "client side (the peer is the server)": client} {
		c, err := Of(conn)
		if err != nil {
			t.Fatalf("%s: %v", side, err)
		}
		defer c.Release()
		if c.UID != uint32(os.Geteuid()) {
			t.Errorf("%s: uid %d, want %d", side, c.UID, os.Geteuid())
		}
		if !c.HasGroup(uint32(os.Getegid())) {
			t.Errorf("%s: groups %v (gid %d) do not include this process's gid %d", side, c.Groups, c.GID, os.Getegid())
		}
		if c.PID != 0 && c.PID != int32(os.Getpid()) {
			t.Errorf("%s: pid %d, want %d or 0", side, c.PID, os.Getpid())
		}
	}
}

// TestOf_RefusesAConnectionThatIsNotAUnixSocket: a TCP peer has no kernel
// credentials, and must not be given any.
func TestOf_RefusesAConnectionThatIsNotAUnixSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := Of(c); err == nil {
		t.Fatal("Of accepted a TCP connection")
	}
}

func writeProc(t *testing.T, root, pid, loginuid, status string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if loginuid != "" {
		if err := os.WriteFile(filepath.Join(dir, "loginuid"), []byte(loginuid), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoginUID_IsReadCheckedAgainstThePeerAndDiscardedWhenItCannotBeTrusted
// is design/adr/0040 §2: the loginuid names the human behind root or the
// service account, but only when it is set and the pid still belongs to
// the peer that connected.
func TestLoginUID_IsReadCheckedAgainstThePeerAndDiscardedWhenItCannotBeTrusted(t *testing.T) {
	root := t.TempDir()
	statusRoot := "Name:\tsudo\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
	writeProc(t, root, "42", "1000\n", statusRoot)
	writeProc(t, root, "43", "4294967295\n", statusRoot)
	writeProc(t, root, "44", "1000\n", "Name:\tother\nUid:\t1001\t1001\t1001\t1001\n")
	writeProc(t, root, "45", "", statusRoot)

	if v, ok := LoginUID(root, 42, 0, nil); !ok || v != 1000 {
		t.Errorf("a set loginuid of the peer's own process: (%d, %v), want (1000, true)", v, ok)
	}
	if _, ok := LoginUID(root, 43, 0, nil); ok {
		t.Error("the unset value 4294967295 was used")
	}
	if _, ok := LoginUID(root, 44, 0, nil); ok {
		t.Error("a loginuid was used although /proc/PID/status names another uid (the pid was reused)")
	}
	if _, ok := LoginUID(root, 45, 0, nil); ok {
		t.Error("a missing loginuid was used")
	}
	if _, ok := LoginUID(root, 42, 0, func() bool { return false }); ok {
		t.Error("a loginuid was used although the pinned process is gone")
	}
	if _, ok := LoginUID(root, 0, 0, nil); ok {
		t.Error("pid 0 was read")
	}
}
