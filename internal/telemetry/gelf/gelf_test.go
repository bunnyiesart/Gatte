package gelf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// ---------------------------------------------------------------------
// Harness: in-process fake listeners.
//
// Nothing in this file touches an external network. Both listeners bind
// 127.0.0.1:0 and hand their address back, which is also how the "the
// destination is down" cases are built: bind a port, close it, keep the
// address.
// ---------------------------------------------------------------------

// fastTiming compresses the intervals so a test can observe a backoff, a
// reconnection and a degraded summary inside a few hundred milliseconds
// instead of a minute. It is the only reason Config.timing exists.
func fastTiming() *timings {
	return &timings{
		reportEvery: 40 * time.Millisecond,
		backoffMin:  10 * time.Millisecond,
		backoffMax:  40 * time.Millisecond,
		closeBudget: 200 * time.Millisecond,
	}
}

// baseConfig is a well-formed configuration pointed at addr. Every test
// starts from it and breaks exactly one thing, so a failure names the
// thing that was broken.
func baseConfig(addr string, transport Transport) Config {
	return Config{
		Address:    addr,
		Transport:  transport,
		Host:       "mcp-gateway-01",
		ClienteSOC: "example-client",
		Buffer:     4096,
		Logger:     slog.New(slog.NewTextHandler(newSyncBuffer(), nil)),
		timing:     fastTiming(),
	}
}

// newSink builds a Sink and guarantees it is closed when the test ends,
// so a leaked goroutine cannot make a later test flake.
func newSink(t *testing.T, cfg Config) *Sink {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// syncBuffer is a bytes.Buffer safe for the writer goroutine and the test
// goroutine at once. slog handlers are not synchronized for the writer
// they wrap, and the race detector is right to complain.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newSyncBuffer() *syncBuffer { return &syncBuffer{} }

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeUDP is a UDP socket that hands every datagram it receives to a
// channel. One datagram is one GELF message: the transport has no framing
// to undo.
func fakeUDP(t *testing.T) (addr string, msgs chan []byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	msgs = make(chan []byte, 8192)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			select {
			case msgs <- b:
			default: // a test that stopped reading must not block the socket
			}
		}
	}()
	return pc.LocalAddr().String(), msgs
}

// fakeTCP is a TCP listener that reads NUL-delimited GELF frames. It can
// be stopped and restarted on the SAME address, which is how the
// reconnection tests are built without killing a live connection and
// hoping the timing works out.
type fakeTCP struct {
	t    *testing.T
	addr string
	msgs chan []byte
	tls  *tls.Config

	// accepted counts connections. It is the only way a test can tell
	// "the sink kept writing on the same connection" from "the sink tore
	// the connection down and dialled a new one", which look identical
	// from the message channel once the backoff is short.
	accepted atomic.Int64

	mu      sync.Mutex
	ln      net.Listener
	stalled bool // accept connections and never read them
}

// conns is how many connections this destination has accepted so far.
func (f *fakeTCP) conns() int64 { return f.accepted.Load() }

func newFakeTCP(t *testing.T) *fakeTCP {
	t.Helper()
	f := &fakeTCP{t: t, msgs: make(chan []byte, 8192)}
	f.listen()
	t.Cleanup(f.stop)
	return f
}

// reservedAddr binds a port and immediately releases it, producing an
// address where nothing is listening. Dialling it fails at once with
// connection refused, which is what makes the "destination down" tests
// deterministic instead of timing-dependent.
func reservedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func (f *fakeTCP) listen() {
	f.t.Helper()
	var (
		ln  net.Listener
		err error
	)
	if f.addr == "" {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		// The same address as before: this is how a destination is
		// brought back up after an outage, without racing a live
		// connection.
		ln, err = net.Listen("tcp", f.addr)
	}
	if err != nil {
		f.t.Fatalf("listen tcp: %v", err)
	}
	if f.tls != nil {
		ln = tls.NewListener(ln, f.tls)
	}
	f.mu.Lock()
	f.ln = ln
	f.addr = ln.Addr().String()
	stalled := f.stalled
	f.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			if stalled {
				// Accept and never read: the case a synchronous write
				// with a deadline would still pay for.
				continue
			}
			go f.read(c)
		}
	}()
}

func (f *fakeTCP) read(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		// GELF TCP framing: JSON terminated by a NUL byte. Reading up to
		// the NUL is also the frame assertion -- a value that smuggled a
		// raw NUL through would split here and the JSON would not parse.
		frame, err := r.ReadBytes(0)
		if err != nil {
			return
		}
		b := make([]byte, len(frame)-1)
		copy(b, frame[:len(frame)-1])
		select {
		case f.msgs <- b:
		default:
		}
	}
}

// stop closes the listener and keeps the address, so start() can bring
// the same destination back up.
func (f *fakeTCP) stop() {
	f.mu.Lock()
	ln := f.ln
	f.ln = nil
	f.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// waitMsg reads one message or fails the test.
func waitMsg(t *testing.T, msgs chan []byte, within time.Duration) []byte {
	t.Helper()
	select {
	case b := <-msgs:
		return b
	case <-time.After(within):
		t.Fatalf("no message arrived within %s", within)
		return nil
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", within, what)
}

// ---------------------------------------------------------------------
// Delivery, which is the positive control for the whole component.
// ---------------------------------------------------------------------

// TestDeliversToAFakeUDPListener is the end-to-end positive control: an
// event goes in one end and comes out of a real socket at the other,
// field for field. Every "it does not block" and "it drops safely" test
// in this file is worthless without it -- a sink that does nothing at all
// would pass all of them.
func TestDeliversToAFakeUDPListener(t *testing.T) {
	addr, msgs := fakeUDP(t)
	s := newSink(t, baseConfig(addr, TransportUDP))

	r := sampleRecord()
	r.Reason = ""
	s.Emit(r)

	m := decode(t, waitMsg(t, msgs, 3*time.Second))

	if got, want := m["_analyst_identity"], r.AnalystIdentity; got != want {
		t.Errorf("_analyst_identity = %v, want %q", got, want)
	}
	if got, want := m["_tool"], r.Tool; got != want {
		t.Errorf("_tool = %v, want %q", got, want)
	}
	if got, want := m["_target_upstream"], r.TargetUpstream; got != want {
		t.Errorf("_target_upstream = %v, want %q", got, want)
	}
	if got, want := m["_outcome"], string(r.Outcome); got != want {
		t.Errorf("_outcome = %v, want %q", got, want)
	}
	if got, want := m["host"], "mcp-gateway-01"; got != want {
		t.Errorf("host = %v, want %q", got, want)
	}

	waitFor(t, time.Second, "the write counter", func() bool { return s.Stats().Written == 1 })

	st := s.Stats()
	if !st.Configured {
		t.Error("Stats().Configured is false on a sink with a destination")
	}
	if st.Destination != "udp "+addr {
		t.Errorf("Destination = %q, want %q", st.Destination, "udp "+addr)
	}
	if !st.Healthy {
		t.Error("Healthy is false after a successful write")
	}
}

// TestDeliversToAFakeTCPListener is the same control over TCP, and the
// frame reader proves the NUL framing at the same time: without the
// terminator the listener would never complete a read.
func TestDeliversToAFakeTCPListener(t *testing.T) {
	f := newFakeTCP(t)
	s := newSink(t, baseConfig(f.addr, TransportTCP))

	r := sampleRecord()
	r.Outcome = audit.OutcomeFailed
	r.Reason = "upstream failed"
	s.Emit(r)

	m := decode(t, waitMsg(t, f.msgs, 3*time.Second))

	if got, want := m["_outcome"], "failed"; got != want {
		t.Errorf("_outcome = %v, want %q", got, want)
	}
	if got, want := m["_reason"], "upstream failed"; got != want {
		t.Errorf("_reason = %v, want %q", got, want)
	}
	if got, want := m["level"], float64(4); got != want {
		t.Errorf("level = %v, want %v", got, want)
	}
}

// TestFieldValuesCannotBreakTheFrame turns an assumption into a test: a
// field value holding NUL, a newline and a quote still produces ONE TCP
// frame with the value intact, because encoding/json escapes every
// control character.
//
// Left as a comment, that assumption survives an encoder swap. As a test,
// it does not.
func TestFieldValuesCannotBreakTheFrame(t *testing.T) {
	f := newFakeTCP(t)
	s := newSink(t, baseConfig(f.addr, TransportTCP))

	hostile := "evil\x00tool\n\"quoted\""
	r := sampleRecord()
	r.Tool = hostile
	s.Emit(r)

	m := decode(t, waitMsg(t, f.msgs, 3*time.Second))
	if got := m["_tool"]; got != hostile {
		t.Errorf("_tool = %q, want %q -- the value did not survive the frame intact", got, hostile)
	}

	// And there is no second frame: a raw NUL on the wire would have
	// split this message in two, and the tail would arrive here.
	select {
	case extra := <-f.msgs:
		t.Errorf("a second frame arrived (%q) -- the field value broke the framing", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------
// TLS, with the counter-proof that makes it more than decoration.
// ---------------------------------------------------------------------

// tlsFixture generates a CA and a leaf certificate for 127.0.0.1, writes
// the CA in PEM to a temp file, and returns the path plus the server's
// TLS configuration. ed25519 because it generates in microseconds; this
// is a test, not a key ceremony.
func tlsFixture(t *testing.T) (caFile string, serverTLS *tls.Config) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gelf-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafPub, caPriv)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	caFile = filepath.Join(t.TempDir(), "graylog-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write CA pem: %v", err)
	}

	serverTLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafPriv,
		}},
	}
	return caFile, serverTLS
}

// TestTLSDeliversOverTCP proves the TLS path delivers, and the
// counter-proof below it proves the TLS is real: a trust anchor that did
// not sign that certificate must deliver NOTHING and count the failure.
// Without the second half, a sink that quietly skipped verification would
// pass the first.
func TestTLSDeliversOverTCP(t *testing.T) {
	caFile, serverTLS := tlsFixture(t)

	f := &fakeTCP{t: t, msgs: make(chan []byte, 64), tls: serverTLS}
	f.listen()
	t.Cleanup(f.stop)

	cfg := baseConfig(f.addr, TransportTCP)
	cfg.TLS = true
	cfg.TLSCAFile = caFile
	s := newSink(t, cfg)

	s.Emit(sampleRecord())

	m := decode(t, waitMsg(t, f.msgs, 5*time.Second))
	if got, want := m["_tool"], "threatintel.virustotal"; got != want {
		t.Errorf("_tool = %v, want %q", got, want)
	}
}

func TestTLSRefusesAnUnrelatedTrustAnchor(t *testing.T) {
	_, serverTLS := tlsFixture(t)
	// A second, unrelated CA: well-formed PEM, correct file, and it did
	// not sign the certificate the listener presents.
	otherCA, _ := tlsFixture(t)

	f := &fakeTCP{t: t, msgs: make(chan []byte, 64), tls: serverTLS}
	f.listen()
	t.Cleanup(f.stop)

	cfg := baseConfig(f.addr, TransportTCP)
	cfg.TLS = true
	cfg.TLSCAFile = otherCA
	s := newSink(t, cfg)

	s.Emit(sampleRecord())

	waitFor(t, 5*time.Second, "the handshake failure to be counted", func() bool {
		return s.Stats().ConsecutiveFailures > 0
	})

	select {
	case b := <-f.msgs:
		t.Fatalf("a message got through against an unrelated trust anchor: %s", b)
	case <-time.After(300 * time.Millisecond):
	}

	if st := s.Stats(); st.Written != 0 {
		t.Errorf("Written = %d, want 0 -- nothing may cross an unverified connection", st.Written)
	}
	if st := s.Stats(); st.Healthy {
		t.Error("Healthy is true while every handshake is failing")
	}
}

// ---------------------------------------------------------------------
// Non-blocking, which is the invariant the request path depends on.
// ---------------------------------------------------------------------

// TestEmitNeverBlocksWhenTheDestinationIsUnreachable measures wall time
// per Emit against a destination that refuses connections, and then --
// the half that makes it mean something -- runs the same loop against a
// live listener and requires delivery. Without the second half, "it does
// not block" would pass for a sink that does nothing whatsoever.
func TestEmitNeverBlocksWhenTheDestinationIsUnreachable(t *testing.T) {
	const emits = 1000

	s := newSink(t, baseConfig(reservedAddr(t), TransportTCP))

	var worst time.Duration
	start := time.Now()
	for i := range emits {
		r := sampleRecord()
		r.Tool = fmt.Sprintf("threatintel.tool%d", i)
		callStart := time.Now()
		s.Emit(r)
		if d := time.Since(callStart); d > worst {
			worst = d
		}
	}
	total := time.Since(start)

	if worst > 50*time.Millisecond {
		t.Errorf("slowest Emit took %s -- the request path waited on telemetry", worst)
	}
	if total > time.Second {
		t.Errorf("%d Emits took %s against a dead destination", emits, total)
	}

	// Positive control, same shape, live listener.
	addr, msgs := fakeUDP(t)
	live := newSink(t, baseConfig(addr, TransportUDP))
	for i := range emits {
		r := sampleRecord()
		r.Tool = fmt.Sprintf("threatintel.tool%d", i)
		live.Emit(r)
	}
	waitMsg(t, msgs, 3*time.Second)
	waitFor(t, 3*time.Second, "deliveries on the live listener", func() bool {
		return live.Stats().Written > 0
	})
}

// TestEmitDoesNotBlockWhenTheReaderStalls is the case a synchronous write
// with a deadline would still pay for: a peer that accepts the connection
// and never reads, filling the window until the writer parks. It is the
// argument for the buffer, turned into a test.
func TestEmitDoesNotBlockWhenTheReaderStalls(t *testing.T) {
	f := &fakeTCP{t: t, msgs: make(chan []byte, 8), stalled: true}
	f.listen()
	t.Cleanup(f.stop)

	cfg := baseConfig(f.addr, TransportTCP)
	cfg.Buffer = 64
	s := newSink(t, cfg)

	start := time.Now()
	for i := range 5000 {
		r := sampleRecord()
		r.Tool = fmt.Sprintf("threatintel.tool%d", i)
		s.Emit(r)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("5000 Emits took %s against a stalled reader -- Emit is waiting on the socket", d)
	}
	if st := s.Stats(); st.Emitted != 5000 {
		t.Errorf("Emitted = %d, want 5000", st.Emitted)
	}
}

// TestQueueFullDropsTheNewestAndCountsIt pins the property a
// well-meaning refactor destroys: when the queue is full the ARRIVING
// event is dropped, so what remains is the oldest contiguous prefix.
//
// The exact count matters, and so does which events survived: dropping
// the oldest instead would leave a gap with holes in it, and no
// `mcp-gateway audit --since` query reconstructs that.
func TestQueueFullDropsTheNewestAndCountsIt(t *testing.T) {
	const (
		buffer = 4
		emits  = 100
	)

	cfg := baseConfig(reservedAddr(t), TransportTCP)
	cfg.Buffer = buffer
	s := newSink(t, cfg)

	for i := range emits {
		r := sampleRecord()
		r.Tool = fmt.Sprintf("threatintel.tool%d", i)
		s.Emit(r)
	}

	st := s.Stats()
	if want := uint64(emits - buffer); st.DroppedFull != want {
		t.Errorf("DroppedFull = %d, want %d", st.DroppedFull, want)
	}
	if st.Queued != buffer {
		t.Errorf("Queued = %d, want %d", st.Queued, buffer)
	}

	// The destination never accepted a connection, so the writer
	// goroutine never dequeued anything: what is in the channel is
	// exactly what the queue retained.
	for i := range buffer {
		select {
		case r := <-s.ch:
			if want := fmt.Sprintf("threatintel.tool%d", i); r.Tool != want {
				t.Fatalf("queue position %d holds %q, want %q -- the queue is not retaining the "+
					"OLDEST contiguous prefix, which breaks recovery by --since", i, r.Tool, want)
			}
		default:
			t.Fatalf("queue holds fewer than %d events", buffer)
		}
	}
}

// ---------------------------------------------------------------------
// Accounting.
// ---------------------------------------------------------------------

// checkAccounting is the invariant, executable:
//
//	Emitted == Written + DroppedFull + DroppedWrite + DroppedOversize + DroppedClosing + Queued
//
// It is the answer to "how many events did we lose", and it is checked
// after Close, when nothing is moving.
func checkAccounting(t *testing.T, s *Sink) {
	t.Helper()
	st := s.Stats()
	sum := st.Written + st.DroppedFull + st.DroppedWrite + st.DroppedOversize + st.DroppedClosing + uint64(st.Queued)
	if sum != st.Emitted {
		t.Errorf("accounting does not close: emitted=%d written=%d full=%d write=%d oversize=%d "+
			"closing=%d queued=%d (sum %d)",
			st.Emitted, st.Written, st.DroppedFull, st.DroppedWrite, st.DroppedOversize,
			st.DroppedClosing, st.Queued, sum)
	}
	if st.Queued != 0 {
		t.Errorf("Queued = %d after Close, want 0 -- an event left in the queue is an event nobody "+
			"will ever account for", st.Queued)
	}
}

func TestCountersAccountForEveryEmit(t *testing.T) {
	t.Run("everything delivered", func(t *testing.T) {
		addr, _ := fakeUDP(t)
		s := newSink(t, baseConfig(addr, TransportUDP))
		for range 50 {
			s.Emit(sampleRecord())
		}
		waitFor(t, 3*time.Second, "all 50 writes", func() bool { return s.Stats().Written == 50 })
		if err := s.Close(); err != nil {
			t.Errorf("Close reported loss on a healthy sink: %v", err)
		}
		checkAccounting(t, s)
		if st := s.Stats(); st.Written != 50 {
			t.Errorf("Written = %d, want 50", st.Written)
		}
	})

	t.Run("everything dropped", func(t *testing.T) {
		cfg := baseConfig(reservedAddr(t), TransportTCP)
		cfg.Buffer = 4
		s := newSink(t, cfg)
		for range 100 {
			s.Emit(sampleRecord())
		}
		if err := s.Close(); err == nil {
			t.Error("Close returned nil after discarding queued events -- it has to say what it lost")
		}
		checkAccounting(t, s)
		if st := s.Stats(); st.Written != 0 {
			t.Errorf("Written = %d, want 0 against a destination that never accepted", st.Written)
		}
	})

	t.Run("mixed, with the listener dying in the middle", func(t *testing.T) {
		f := newFakeTCP(t)
		cfg := baseConfig(f.addr, TransportTCP)
		cfg.Buffer = 32
		s := newSink(t, cfg)

		for range 20 {
			s.Emit(sampleRecord())
		}
		waitFor(t, 3*time.Second, "the first deliveries", func() bool { return s.Stats().Written > 0 })

		f.stop()
		for range 200 {
			s.Emit(sampleRecord())
		}
		time.Sleep(100 * time.Millisecond)

		_ = s.Close()
		checkAccounting(t, s)
		if st := s.Stats(); st.Emitted != 220 {
			t.Errorf("Emitted = %d, want 220", st.Emitted)
		}
	})
}

// ---------------------------------------------------------------------
// What the operator sees.
// ---------------------------------------------------------------------

// TestDegradedTransitionIsLoggedOnceAndThenSummarised: one line on the
// transition, not one per dropped event, and a periodic summary carrying
// CUMULATIVE totals plus the recovery command already assembled.
//
// One line per drop would turn a Graylog outage into a disk outage, and
// nobody reads 800 identical lines at 03:00.
func TestDegradedTransitionIsLoggedOnceAndThenSummarised(t *testing.T) {
	logs := newSyncBuffer()
	cfg := baseConfig(reservedAddr(t), TransportTCP)
	cfg.Buffer = 8
	cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
	s := newSink(t, cfg)

	for range 500 {
		s.Emit(sampleRecord())
	}

	waitFor(t, 3*time.Second, "the degraded summary", func() bool {
		return strings.Contains(logs.String(), "telemetry still failing")
	})

	out := logs.String()
	if n := strings.Count(out, "telemetry delivery failing"); n != 1 {
		t.Errorf("the healthy->degraded transition was logged %d times, want exactly 1\n%s", n, out)
	}
	if !strings.Contains(out, `recover_with="mcp-gateway audit --since `) {
		t.Errorf("no summary line carries the assembled recovery command\n%s", out)
	}
	if !strings.Contains(out, "dropped_full=") || !strings.Contains(out, "emitted=") {
		t.Errorf("the summary line does not carry cumulative totals\n%s", out)
	}

	// Positive control: with a live listener, none of those lines exist.
	healthyLogs := newSyncBuffer()
	addr, _ := fakeUDP(t)
	healthyCfg := baseConfig(addr, TransportUDP)
	healthyCfg.Logger = slog.New(slog.NewTextHandler(healthyLogs, nil))
	healthy := newSink(t, healthyCfg)
	for range 50 {
		healthy.Emit(sampleRecord())
	}
	waitFor(t, 3*time.Second, "delivery on the healthy sink", func() bool {
		return healthy.Stats().Written == 50
	})
	time.Sleep(120 * time.Millisecond) // past two report ticks
	if got := healthyLogs.String(); strings.Contains(got, "failing") {
		t.Errorf("a healthy sink logged a failure line:\n%s", got)
	}
}

// TestRecoveryEmitsAGapMessage: the first message on a recovered
// connection is the synthetic gap, carrying what was lost and how to get
// it back. Without it a hole in the stream is indistinguishable from a
// quiet period, and whoever looks afterwards concludes everything was
// fine.
func TestRecoveryEmitsAGapMessage(t *testing.T) {
	// A clock that advances one second per reading: the gap window is
	// then deterministic in shape (start before end, both derived from
	// the record clock) without depending on how fast the machine is.
	base := time.Date(2026, 9, 14, 3, 11, 0, 0, time.UTC)
	var ticks int64
	var clockMu sync.Mutex
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		ticks++
		return base.Add(time.Duration(ticks) * time.Second)
	}

	addr := reservedAddr(t)
	cfg := baseConfig(addr, TransportTCP)
	cfg.Buffer = 4
	cfg.Now = clock
	s := newSink(t, cfg)

	const emits = 100
	for range emits {
		s.Emit(sampleRecord())
	}
	waitFor(t, 3*time.Second, "the outage to be noticed", func() bool {
		return !s.Stats().Healthy
	})
	dropped := s.Stats().DroppedFull
	if dropped == 0 {
		t.Fatal("nothing was dropped, so there is no gap to announce -- the scenario is wrong")
	}

	// Bring the destination up on the same address.
	f := &fakeTCP{t: t, addr: addr, msgs: make(chan []byte, 64)}
	f.listen()
	t.Cleanup(f.stop)

	m := decode(t, waitMsg(t, f.msgs, 5*time.Second))

	if got, want := m["_event_kind"], "telemetry_gap"; got != want {
		t.Fatalf("the first message on the recovered connection is %v, want %q", got, want)
	}
	if got, want := m["_dropped"], float64(dropped); got != want {
		t.Errorf("_dropped = %v, want %v", got, want)
	}
	gapStart, ok := m["_gap_start"].(string)
	if !ok {
		t.Fatalf("_gap_start is %T, want a string", m["_gap_start"])
	}
	gapEnd, _ := m["_gap_end"].(string)
	start, err := time.Parse(time.RFC3339, gapStart)
	if err != nil {
		t.Fatalf("_gap_start %q does not parse: %v", gapStart, err)
	}
	end, err := time.Parse(time.RFC3339, gapEnd)
	if err != nil {
		t.Fatalf("_gap_end %q does not parse: %v", gapEnd, err)
	}
	if !start.After(base) || !end.After(start) {
		t.Errorf("gap window [%s, %s] does not cover the outage (clock base %s)", gapStart, gapEnd, base)
	}
	if got, want := m["_recover_with"], "mcp-gateway audit --since "+gapStart; got != want {
		t.Errorf("_recover_with = %v, want %q", got, want)
	}

	// And the next message is an ordinary audit event: the gap is
	// announced once, not prepended to everything.
	next := decode(t, waitMsg(t, f.msgs, 3*time.Second))
	if got, want := next["_event_kind"], "audit"; got != want {
		t.Errorf("the second message is %v, want %q", got, want)
	}
}

// TestRecoveryWithoutLossEmitsNoGapMessage is the paired negative
// control: a reconnection that lost nothing announces nothing, or every
// recovery becomes gap spam claiming zero.
func TestRecoveryWithoutLossEmitsNoGapMessage(t *testing.T) {
	addr := reservedAddr(t)
	cfg := baseConfig(addr, TransportTCP)
	cfg.Buffer = 4096 // large enough that the outage costs nothing
	s := newSink(t, cfg)

	waitFor(t, 3*time.Second, "the first dial to fail", func() bool {
		return !s.Stats().Healthy
	})

	s.Emit(sampleRecord())

	f := &fakeTCP{t: t, addr: addr, msgs: make(chan []byte, 64)}
	f.listen()
	t.Cleanup(f.stop)

	m := decode(t, waitMsg(t, f.msgs, 5*time.Second))
	if got := m["_event_kind"]; got != "audit" {
		t.Errorf("the first message after a lossless reconnection is %v, want an ordinary audit "+
			"event -- a gap message announcing zero is noise", got)
	}
	if st := s.Stats(); st.DroppedFull != 0 {
		t.Errorf("DroppedFull = %d, want 0 -- the scenario was supposed to be lossless", st.DroppedFull)
	}
}

// ---------------------------------------------------------------------
// Shutdown.
// ---------------------------------------------------------------------

// TestCloseDrainsWithinItsBudgetAndReportsWhatItDiscarded: telemetry
// cannot hold the shutdown. The 15s of shutdownTimeout are already
// committed to the HTTP drain and to reaping the containers that hold
// credentials.
func TestCloseDrainsWithinItsBudgetAndReportsWhatItDiscarded(t *testing.T) {
	t.Run("nothing to write to", func(t *testing.T) {
		cfg := baseConfig(reservedAddr(t), TransportTCP)
		cfg.Buffer = 8
		s := newSink(t, cfg)

		const emits = 8
		for range emits {
			s.Emit(sampleRecord())
		}
		queued := s.Stats().Queued

		start := time.Now()
		err := s.Close()
		elapsed := time.Since(start)

		if elapsed > 2*time.Second {
			t.Errorf("Close took %s -- shutdown does not wait on telemetry", elapsed)
		}
		if err == nil {
			t.Fatal("Close returned nil after discarding queued events")
		}
		if !strings.Contains(err.Error(), "mcp-gateway audit --since") {
			t.Errorf("Close error does not name the recovery command: %v", err)
		}
		if got, want := s.Stats().DroppedClosing, uint64(queued); got != want {
			t.Errorf("DroppedClosing = %d, want %d", got, want)
		}

		// Idempotent, and the same answer twice.
		second := s.Close()
		if second == nil || second.Error() != err.Error() {
			t.Errorf("second Close returned %v, want the same report as the first (%v)", second, err)
		}
		checkAccounting(t, s)
	})

	t.Run("a peer that stopped reading", func(t *testing.T) {
		f := &fakeTCP{t: t, msgs: make(chan []byte, 8), stalled: true}
		f.listen()
		t.Cleanup(f.stop)

		cfg := baseConfig(f.addr, TransportTCP)
		cfg.Buffer = 8192
		s := newSink(t, cfg)

		for range 6000 {
			s.Emit(sampleRecord())
		}
		time.Sleep(200 * time.Millisecond) // let the writer park inside a write

		start := time.Now()
		_ = s.Close()
		// Measured against the BUDGET, not against some round number
		// larger than the failure: at 5s this assertion passed at two and
		// a half times the budget, which is the overrun it was supposed
		// to catch.
		budget := cfg.timing.closeBudget + closeGrace + 750*time.Millisecond
		if elapsed := time.Since(start); elapsed > budget {
			t.Errorf("Close took %s against a budget of %s with a stalled peer -- the in-flight "+
				"write was never unblocked, and shutdown is now telemetry's hostage", elapsed, budget)
		}
		checkAccounting(t, s)
	})
}

// ---------------------------------------------------------------------
// Local errors fail the boot; remote conditions never do.
// ---------------------------------------------------------------------

// TestNewDoesNotTouchTheNetwork: a destination whose host does not
// resolve still produces a working Sink, quickly. A gateway that refuses
// to start because the SIEM's DNS is down would be telemetry taking down
// the request path at the worst possible moment.
func TestNewDoesNotTouchTheNetwork(t *testing.T) {
	cfg := baseConfig("graylog.invalid:12201", TransportUDP)

	start := time.Now()
	s, err := New(cfg)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("New failed on an unresolvable destination: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if elapsed > 250*time.Millisecond {
		t.Errorf("New took %s -- it is resolving or dialling, and boot now depends on the SIEM", elapsed)
	}

	s.Emit(sampleRecord())
	if st := s.Stats(); st.Emitted != 1 {
		t.Errorf("Emitted = %d, want 1", st.Emitted)
	}
	if st := s.Stats(); st.Written != 0 {
		t.Errorf("Written = %d, want 0 -- nothing can have been written to a name that does not resolve", st.Written)
	}
}

// TestNewRefusesALocalMistake is the paired half: the local errors are
// the ONLY errors New has, and each one fails the boot rather than
// waiting to fail quietly at 03:00.
func TestNewRefusesALocalMistake(t *testing.T) {
	unreadable := filepath.Join(t.TempDir(), "not-there.pem")
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cases := []struct {
		name    string
		breakIt func(c *Config)
		want    string
	}{
		{"invalid transport", func(c *Config) { c.Transport = "amqp" }, "transport"},
		{"no transport", func(c *Config) { c.Transport = "" }, "transport"},
		{"address without a port", func(c *Config) { c.Address = "192.0.2.11" }, "host:port"},
		{"address without a host", func(c *Config) { c.Address = ":12201" }, "host:port"},
		{"tls over udp", func(c *Config) { c.Transport = TransportUDP; c.TLS = true }, "GELF UDP over TLS"},
		{"empty host", func(c *Config) { c.Host = "" }, "host is required"},
		{"empty cliente_soc", func(c *Config) { c.ClienteSOC = "" }, "cliente_soc is required"},
		{"zero buffer", func(c *Config) { c.Buffer = 0 }, "not positive"},
		{"negative buffer", func(c *Config) { c.Buffer = -1 }, "not positive"},
		{"unreadable ca file", func(c *Config) { c.TLS = true; c.TLSCAFile = unreadable }, "tls_ca_file"},
		{"ca file with no certificate", func(c *Config) { c.TLS = true; c.TLSCAFile = empty }, "no PEM certificate"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig("192.0.2.11:12201", TransportTCP)
			tc.breakIt(&cfg)

			s, err := New(cfg)
			if err == nil {
				_ = s.Close()
				t.Fatalf("New accepted %s", tc.name)
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error does not wrap ErrInvalidConfig: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if s != nil {
				t.Error("New returned a Sink alongside an error -- there is a goroutine nobody will close")
			}
		})
	}
}

// TestSinkIsSafeForConcurrentEmit: Emit is called from every request
// goroutine there is. Meaningful under -race.
func TestSinkIsSafeForConcurrentEmit(t *testing.T) {
	addr, _ := fakeUDP(t)
	s := newSink(t, baseConfig(addr, TransportUDP))

	const (
		goroutines = 50
		each       = 100
	)
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				r := sampleRecord()
				r.Tool = fmt.Sprintf("threatintel.g%d.t%d", g, i)
				s.Emit(r)
				// Stats is read concurrently too: the operator console
				// and the report ticker do exactly this.
				_ = s.Stats()
			}
		}()
	}
	wg.Wait()

	if st := s.Stats(); st.Emitted != goroutines*each {
		t.Errorf("Emitted = %d, want %d", st.Emitted, goroutines*each)
	}
	_ = s.Close()
	checkAccounting(t, s)
}

// ---------------------------------------------------------------------
// Shutdown, continued: a dial in flight must not become the ceiling.
//
// The subtests below exist because the first version of this component
// had a Close bounded by dialTimeout (5s) rather than by closeBudget
// (2s): the loop calls s.dial outside the select, so while a dial is in
// flight nothing observes quit, and unblockWrite -- Close's other way
// out -- is a no-op because s.active is only published after the dial
// returns. Both were measured, not reasoned about: 4.9s against a 450ms
// budget.
// ---------------------------------------------------------------------

// blackHoleTLS accepts TCP connections and then says nothing at all, so a
// client's TLS handshake hangs until it is cancelled or times out. It is
// the in-process stand-in for the shape that matters in a filtered SOC
// network: a destination that swallows the connection instead of refusing
// it.
func blackHoleTLS(t *testing.T) (addr string, accepted <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case got <- struct{}{}:
			default:
			}
			// Held open and never spoken to. Closing it here would give
			// the client an error, which is the case that already works.
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().String(), got
}

// slowTLS completes the handshake only after delay, and then never reads.
// It is the second shape: a dial that succeeds AFTER Close has already
// spent its budget waiting for it.
func slowTLS(t *testing.T, delay time.Duration) (addr, caFile string, accepted <-chan struct{}) {
	t.Helper()
	caFile, serverTLS := tlsFixture(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan struct{}, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case got <- struct{}{}:
			default:
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				time.Sleep(delay)
				tc := tls.Server(c, serverTLS)
				if err := tc.Handshake(); err != nil {
					return
				}
				// Handshake done, and now nothing is ever read: the
				// writer will park inside a write, which is how the old
				// drain got to open a second budget of its own.
				select {}
			}(c)
		}
	}()
	return ln.Addr().String(), caFile, got
}

// waitSignal blocks for one value on ch or fails the test.
func waitSignal(t *testing.T, ch <-chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("timed out after %s waiting for %s", within, what)
	}
}

func TestCloseIsNotHostageToADialInFlight(t *testing.T) {
	// Both subtests keep dialTimeout at its production value on purpose:
	// the whole point is that Close must not inherit it. Shrinking it
	// here would remove the failure this test exists to catch.
	budget := func(cfg Config) time.Duration {
		return cfg.timing.closeBudget + closeGrace + 750*time.Millisecond
	}

	t.Run("a handshake that never completes", func(t *testing.T) {
		addr, accepted := blackHoleTLS(t)

		cfg := baseConfig(addr, TransportTCP)
		// The system pool: the handshake never gets far enough for a
		// trust anchor to matter, which is the point.
		cfg.TLS = true
		s := newSink(t, cfg)

		s.Emit(sampleRecord())
		waitSignal(t, accepted, 3*time.Second, "the sink to connect")
		// Let the loop settle inside the handshake rather than racing it.
		time.Sleep(100 * time.Millisecond)

		start := time.Now()
		_ = s.Close()
		elapsed := time.Since(start)

		if elapsed > budget(cfg) {
			t.Errorf("Close took %s against a budget of %s -- shutdown is waiting out the dial, "+
				"and those seconds come out of the 15s already committed to the HTTP drain and to "+
				"reaping the containers that hold credentials", elapsed, budget(cfg))
		}
		// The other half: returning on time by ABANDONING the goroutine
		// would satisfy the clock and leave the dial running. The dial
		// has to have been cancelled.
		select {
		case <-s.done:
		default:
			t.Error("Close returned on time but the writer goroutine is still running -- the dial " +
				"was abandoned rather than cancelled")
		}
	})

	t.Run("a handshake that lands after the budget", func(t *testing.T) {
		addr, caFile, accepted := slowTLS(t, time.Second)

		cfg := baseConfig(addr, TransportTCP)
		cfg.TLS = true
		cfg.TLSCAFile = caFile
		s := newSink(t, cfg)

		s.Emit(sampleRecord())
		waitSignal(t, accepted, 3*time.Second, "the sink to connect")
		time.Sleep(100 * time.Millisecond)

		start := time.Now()
		_ = s.Close()
		elapsed := time.Since(start)

		if elapsed > budget(cfg) {
			t.Errorf("Close took %s against a budget of %s -- a dial that succeeds late lets the "+
				"drain start a SECOND budget on top of what Close already spent", elapsed, budget(cfg))
		}
		checkAccounting(t, s)
	})
}

// ---------------------------------------------------------------------
// A record that never becomes bytes.
// ---------------------------------------------------------------------

// collectWriter is a writer that keeps what it was handed. It exists for
// the paths the loop reaches only under conditions a test cannot schedule
// -- the close drain, and a second gap on a second outage -- where
// driving a real socket would trade determinism for nothing.
type collectWriter struct {
	// delay makes one write cost something, which is what a budget has to
	// be measured against.
	delay time.Duration

	mu   sync.Mutex
	msgs [][]byte
	err  error
}

func (w *collectWriter) write(msg []byte, _ time.Time) error {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	b := make([]byte, len(msg))
	copy(b, msg)
	w.msgs = append(w.msgs, b)
	return nil
}

func (w *collectWriter) conn() net.Conn { return nil }

func (w *collectWriter) Close() error { return nil }

func (w *collectWriter) messages() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.msgs))
	copy(out, w.msgs)
	return out
}

// newUnstartedSink builds a Sink with no goroutine behind it, so a test
// can drive one step of the loop's bookkeeping at a time.
//
// It hand-builds the struct, which is a real cost: a field added in New
// and not here is a field these tests do not exercise. It is paid because
// the alternative -- a live goroutine dialling in the background -- puts
// a second author on the same counters, and the properties below are
// about exact numbers.
func newUnstartedSink(t *testing.T, buffer int, now func() time.Time) *Sink {
	t.Helper()
	s := &Sink{
		enc:         encoder{host: "mcp-gateway-01", clienteSOC: "example-client"},
		log:         slog.New(slog.NewTextHandler(newSyncBuffer(), nil)),
		now:         now,
		timing:      Config{timing: fastTiming()}.resolveTiming(),
		destination: "tcp 192.0.2.11:12201",
		ch:          make(chan audit.Record, buffer),
		quit:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	s.dialCtx, s.cancelDial = context.WithCancel(context.Background())
	t.Cleanup(s.cancelDial)
	s.startedAt = now()
	return s
}

// TestUnencodableRecordIsDroppedWithoutBreakingTheConnection pins the
// rule written in send's own comment: a record that cannot become bytes
// is dropped and counted, and the CONNECTION is still fine.
//
// Without this, two mutations survive the whole suite (both verified):
// send returning false on an encode failure, which tears the connection
// down and redials once per such record; and countEncodeFailure charging
// oversize to DroppedWrite, which sends the operator to investigate the
// network for a defect that is in the record.
func TestUnencodableRecordIsDroppedWithoutBreakingTheConnection(t *testing.T) {
	f := newFakeTCP(t)
	s := newSink(t, baseConfig(f.addr, TransportTCP))

	// Positive control first: the connection exists and has been counted,
	// so "one connection" below means something.
	s.Emit(sampleRecord())
	waitMsg(t, f.msgs, 3*time.Second)
	waitFor(t, 3*time.Second, "the first write", func() bool { return s.Stats().Written == 1 })
	if got := f.conns(); got != 1 {
		t.Fatalf("the destination accepted %d connections before the oversize record, want 1", got)
	}

	// A tool name of this size is reachable from OUTSIDE: an unknown tool
	// is audited under the name the CLIENT sent, and nothing between the
	// trail and this encoder measures it.
	huge := sampleRecord()
	huge.Tool = strings.Repeat("t", MaxMessageBytes)
	s.Emit(huge)
	waitFor(t, 3*time.Second, "the oversize record to be counted", func() bool {
		return s.Stats().DroppedOversize == 1
	})

	// And the next ordinary record still goes out, on the same connection.
	s.Emit(sampleRecord())
	waitFor(t, 3*time.Second, "the write after the oversize record", func() bool {
		return s.Stats().Written == 2
	})
	waitMsg(t, f.msgs, 3*time.Second)

	st := s.Stats()
	if st.DroppedWrite != 0 {
		t.Errorf("DroppedWrite = %d, want 0 -- a record that never reached the socket is not a "+
			"socket failure, and charging it here makes the destination look unstable", st.DroppedWrite)
	}
	if !st.Healthy {
		t.Error("Healthy is false after an oversize record -- an unencodable record opened a gap " +
			"that the network had nothing to do with")
	}
	if got := f.conns(); got != 1 {
		t.Errorf("the destination accepted %d connections, want 1 -- the oversize record tore the "+
			"connection down, which is one teardown and redial per such record", got)
	}

	_ = s.Close()
	checkAccounting(t, s)
}

// TestCloseDrainCountsAnUnencodableRecordAndKeepsGoing is the same rule on
// the shutdown path, which has its own copy of the accounting.
func TestCloseDrainCountsAnUnencodableRecordAndKeepsGoing(t *testing.T) {
	s := newUnstartedSink(t, 8, time.Now)
	w := &collectWriter{}

	huge := sampleRecord()
	huge.Tool = strings.Repeat("t", MaxMessageBytes)
	s.ch <- huge
	s.ch <- sampleRecord()

	s.drainWriting(w, time.Now().Add(2*time.Second))

	if got := s.Stats().DroppedOversize; got != 1 {
		t.Errorf("DroppedOversize = %d, want 1", got)
	}
	if got := s.Stats().DroppedWrite; got != 0 {
		t.Errorf("DroppedWrite = %d, want 0 during a drain that never failed a write", got)
	}
	if got := len(w.messages()); got != 1 {
		t.Errorf("the drain wrote %d messages, want 1 -- it stopped at the record it could not "+
			"encode instead of carrying on with the ones behind it", got)
	}
}

// ---------------------------------------------------------------------
// Two outages in one night.
// ---------------------------------------------------------------------

// TestSecondGapAnnouncesOnlyTheNewLoss pins the INCREMENTAL half of the
// gap accounting, which one outage per test cannot reach.
//
// Graylog goes down at 03:11 and 800 events are lost; it comes back, and
// goes down again at 04:40 costing 16 more. If the announced total stops
// advancing, the second synthetic message says 816 -- the first outage's
// loss re-announced -- and the analyst who only ever looks at the SIEM
// sizes the 04:40 window at fifty times what it was. The cumulative
// counters still reconcile, so the accounting invariant does not catch it.
func TestSecondGapAnnouncesOnlyTheNewLoss(t *testing.T) {
	clock := time.Date(2026, 9, 14, 3, 11, 0, 0, time.UTC)
	var clockMu sync.Mutex
	now := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(time.Second)
		return clock
	}

	s := newUnstartedSink(t, 4, now)
	w := &collectWriter{}

	// First outage: 800 lost.
	s.noteFailure(errors.New("dial tcp: connection refused"))
	s.droppedFull.Add(800)
	if err := s.sendGap(w); err != nil {
		t.Fatalf("sendGap on the first recovery: %v", err)
	}
	msgs := w.messages()
	if len(msgs) != 1 {
		t.Fatalf("the first recovery wrote %d messages, want 1", len(msgs))
	}
	if got := decode(t, msgs[0])["_dropped"]; got != float64(800) {
		t.Fatalf("_dropped = %v on the first gap, want 800 -- the scenario is wrong before it starts", got)
	}

	// Second outage: 16 lost, spread over all three buckets, because
	// sendGap subtracts each one separately.
	s.noteFailure(errors.New("write tcp: broken pipe"))
	s.droppedFull.Add(3)
	s.droppedWrite.Add(12)
	s.droppedOversize.Add(1)
	if err := s.sendGap(w); err != nil {
		t.Fatalf("sendGap on the second recovery: %v", err)
	}
	msgs = w.messages()
	if len(msgs) != 2 {
		t.Fatalf("the second recovery wrote %d messages in total, want 2", len(msgs))
	}
	second := decode(t, msgs[1])
	for _, tc := range []struct {
		key  string
		want float64
	}{
		{"_dropped", 16},
		{"_dropped_full", 3},
		{"_dropped_write", 12},
		{"_dropped_oversize", 1},
	} {
		if got := second[tc.key]; got != tc.want {
			t.Errorf("%s = %v on the second gap, want %v -- a larger number means the count is "+
				"cumulative, and whoever reads it at 04:40 sizes the wrong window", tc.key, got, tc.want)
		}
	}

	// Third recovery, nothing new lost: silence. This is the control --
	// if the announced total never advanced, everything lost so far would
	// be announced here for a third time.
	s.noteFailure(errors.New("dial tcp: connection refused"))
	if err := s.sendGap(w); err != nil {
		t.Fatalf("sendGap on the third recovery: %v", err)
	}
	if got := len(w.messages()); got != 2 {
		t.Errorf("a recovery that lost nothing brought the total to %d messages, want 2 -- every "+
			"reconnection is now gap spam", got)
	}
}

// ---------------------------------------------------------------------
// Loss while the destination is up.
// ---------------------------------------------------------------------

// TestGapCoversDropsFromWhileTheDestinationWasHealthy: the recovery
// window has to contain every event the message admits losing.
//
// A drop needs no outage. The queue fills whenever the consumer is slower
// than the producer -- a live but slow input, a burst, the moment right
// after a recovery while the queue is still full -- and those events are
// counted into the NEXT gap. If the window still began at the last
// successful write, the message would say "812 lost" and hand over a
// command that recovers 12 of them, with nothing saying the other 800 are
// outside it. That is worse than not admitting the loss: the operator
// runs the command and believes they are whole.
func TestGapCoversDropsFromWhileTheDestinationWasHealthy(t *testing.T) {
	var (
		clockMu sync.Mutex
		clock   = time.Date(2026, 9, 14, 3, 0, 0, 0, time.UTC)
	)
	at := func(h, m int) {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = time.Date(2026, 9, 14, h, m, 0, 0, time.UTC)
	}
	now := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}

	s := newUnstartedSink(t, 1, now)
	w := &collectWriter{}

	// 03:00, destination healthy: the queue is full and an event is lost.
	kept := sampleRecord()
	kept.Timestamp = time.Date(2026, 9, 14, 3, 0, 0, 0, time.UTC)
	s.Emit(kept)
	lost := sampleRecord()
	lost.Timestamp = time.Date(2026, 9, 14, 3, 0, 30, 0, time.UTC)
	s.Emit(lost)
	if got := s.Stats().DroppedFull; got != 1 {
		t.Fatalf("DroppedFull = %d, want 1 -- the scenario needs a drop with the destination up", got)
	}

	// 03:20 a write still succeeds, so the last-known-good instant moves
	// PAST the event that was already lost.
	at(3, 20)
	s.noteWritten()

	// 03:21 the destination goes down for real, and 03:29 it comes back.
	at(3, 21)
	s.noteFailure(errors.New("dial tcp: connection refused"))
	s.droppedFull.Add(12)
	at(3, 29)
	if err := s.sendGap(w); err != nil {
		t.Fatalf("sendGap: %v", err)
	}

	msgs := w.messages()
	if len(msgs) != 1 {
		t.Fatalf("the recovery wrote %d messages, want 1", len(msgs))
	}
	m := decode(t, msgs[0])
	if got, want := m["_dropped"], float64(13); got != want {
		t.Fatalf("_dropped = %v, want %v", got, want)
	}
	gapStart, _ := m["_gap_start"].(string)
	start, err := time.Parse(time.RFC3339, gapStart)
	if err != nil {
		t.Fatalf("_gap_start %q does not parse: %v", gapStart, err)
	}
	if start.After(lost.Timestamp) {
		t.Errorf("_gap_start = %s but the earliest lost event is %s -- the message admits 13 lost "+
			"events and the command it carries recovers 12 of them",
			gapStart, lost.Timestamp.Format(time.RFC3339))
	}
	if got, want := m["_recover_with"], "mcp-gateway audit --since "+gapStart; got != want {
		t.Errorf("_recover_with = %v, want %q", got, want)
	}

	// Paired control: with nothing lost while healthy, the window is NOT
	// widened -- otherwise "cover the drops" would quietly become "always
	// replay from the beginning", and every recovery would re-ingest the
	// whole trail.
	s2 := newUnstartedSink(t, 4, now)
	w2 := &collectWriter{}
	at(4, 0)
	s2.noteWritten()
	at(4, 10)
	s2.noteFailure(errors.New("dial tcp: connection refused"))
	s2.droppedFull.Add(5)
	at(4, 20)
	if err := s2.sendGap(w2); err != nil {
		t.Fatalf("sendGap on the control: %v", err)
	}
	m2 := decode(t, w2.messages()[0])
	if got, want := m2["_gap_start"], "2026-09-14T04:00:00Z"; got != want {
		t.Errorf("_gap_start = %v, want %q -- with no loss before the outage the window still "+
			"begins at the last successful write", got, want)
	}
}

// TestDroppingWhileHealthyIsSaidOutLoud: the queue overrunning with the
// destination UP is the one loss no other channel reports. The gap
// message needs a reconnection, and a queue that cannot keep up never
// disconnects -- so without this line the events lost in a 03:00 burst
// are invisible until the next outage, and invisible forever if there
// never is one.
func TestDroppingWhileHealthyIsSaidOutLoud(t *testing.T) {
	logs := newSyncBuffer()
	addr, _ := fakeUDP(t)
	cfg := baseConfig(addr, TransportUDP)
	cfg.Buffer = 1 // the smallest queue there is: a burst cannot fit
	cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
	s := newSink(t, cfg)

	for range 2000 {
		s.Emit(sampleRecord())
	}
	if st := s.Stats(); st.DroppedFull == 0 {
		t.Fatalf("nothing was dropped against a queue of 1 -- the scenario is wrong")
	}

	waitFor(t, 3*time.Second, "the line about a queue that is not keeping up", func() bool {
		return strings.Contains(logs.String(), "not keeping up")
	})
	if st := s.Stats(); !st.Healthy {
		t.Errorf("Healthy is false -- the scenario was supposed to be loss with the destination UP")
	}
	if !strings.Contains(logs.String(), `recover_with="mcp-gateway audit --since `) {
		t.Errorf("the line does not carry the recovery command:\n%s", logs.String())
	}

	// And it stops once the loss stops: the rule is "still dropping", not
	// "dropped once", or a single burst at 03:00 writes one line a minute
	// until the process restarts.
	time.Sleep(150 * time.Millisecond)
	settled := strings.Count(logs.String(), "not keeping up")
	time.Sleep(150 * time.Millisecond)
	if got := strings.Count(logs.String(), "not keeping up"); got != settled {
		t.Errorf("the line repeated (%d -> %d) with no new loss", settled, got)
	}

	// Positive control: a sink whose queue is big enough says none of it.
	quietLogs := newSyncBuffer()
	quietCfg := baseConfig(addr, TransportUDP)
	quietCfg.Logger = slog.New(slog.NewTextHandler(quietLogs, nil))
	quiet := newSink(t, quietCfg)
	for range 50 {
		quiet.Emit(sampleRecord())
	}
	waitFor(t, 3*time.Second, "delivery on the quiet sink", func() bool {
		return quiet.Stats().Written == 50
	})
	time.Sleep(120 * time.Millisecond) // past two report ticks
	if strings.Contains(quietLogs.String(), "not keeping up") {
		t.Errorf("a sink that dropped nothing reported a queue problem:\n%s", quietLogs.String())
	}
}

// TestDrainInheritsWhatIsLeftOfTheCloseBudget: the drain may not start a
// budget of its own.
//
// The loop can reach the drain long after Close signalled -- it was
// inside a dial, or inside a write -- and a budget counted from THAT
// moment is a second budget stacked on the first. Two 2s budgets in
// sequence is a 4s Close, out of the 15s already committed to the HTTP
// drain and to reaping the containers that hold credentials.
func TestDrainInheritsWhatIsLeftOfTheCloseBudget(t *testing.T) {
	s := newUnstartedSink(t, 64, time.Now)
	w := &collectWriter{delay: 10 * time.Millisecond}

	for range 64 {
		s.ch <- sampleRecord()
	}

	// Close signalled with its budget almost spent: 20ms left of the
	// 200ms the test timing allows.
	remaining := 20 * time.Millisecond
	s.closeDeadline.Store(time.Now().Add(remaining).UnixNano())

	start := time.Now()
	s.drain(w)
	elapsed := time.Since(start)

	if ceiling := remaining + 120*time.Millisecond; elapsed > ceiling {
		t.Errorf("the drain ran for %s with %s left of the close budget (ceiling %s) -- it counted "+
			"a fresh budget from the moment it started, on top of what Close already spent",
			elapsed, remaining, ceiling)
	}
	if st := s.Stats(); st.DroppedClosing == 0 {
		t.Errorf("DroppedClosing = 0 -- the scenario needs the drain to run out of budget with " +
			"events still queued")
	}
	if st := s.Stats(); st.Queued != 0 {
		t.Errorf("Queued = %d after the drain, want 0", st.Queued)
	}
}
