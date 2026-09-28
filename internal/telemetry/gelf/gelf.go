// Package gelf is the adapter that ships audit records to a Graylog GELF
// input over UDP or TCP (design/adr/0029-telemetria-gelf.md). It is one
// concrete way of satisfying telemetry.Sink, and the composition root is
// the only package allowed to name it.
//
// # What this component cannot do, said before anyone assumes otherwise
//
// It does not speak to the SIEM this SOC runs today. Checked on 14 Sep
// 2026 rather than assumed: of the 18 configured inputs, 16 are
// GELFAMQPInput (one per client), one is a SyslogUDPInput on 5514 and one
// is a NetFlowUdpInput on 2055. There is no GELF UDP, TCP or HTTP input
// at all, so on the day this compiles there is nowhere correct to point
// it, and config.example.toml ships with the address commented out. AMQP
// is out of scope by decision, and this is the price of that decision.
//
// There is no disk spool, no backfill, no retry of a dropped event, no
// /metrics endpoint and no `telemetry status` subcommand. The trail in
// SQLite is already the durable spool; recovery is manual and is spelled
// out in the log line that admits the loss.
//
// # The one rule everything else follows from
//
// Telemetry going down must never become the gateway going down. This
// process holds every backend credential in the fleet and is the only
// path calls take. So: Emit never blocks, New never touches the network,
// a local mistake fails the boot and a remote outage fails nothing.
package gelf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/telemetry"
)

// ErrInvalidConfig is returned by New when the operator wrote something
// that will not get better on its own. It is deliberately the only class
// of failure New has: a destination that is merely unreachable is not one
// of these.
var ErrInvalidConfig = errors.New("gelf: invalid configuration")

const (
	// dialTimeout bounds one connection attempt. Five seconds is long
	// enough for a TLS handshake across a slow link and short enough that
	// the backoff, not the dial, decides how often the goroutine retries.
	dialTimeout = 5 * time.Second

	// writeTimeout bounds one message write. It exists for the case that
	// costs the most: a peer that accepts the connection and then stops
	// reading, which without a deadline parks the writer goroutine
	// forever and turns the queue into a drop machine with no explanation
	// in the log.
	writeTimeout = 5 * time.Second

	// backoffMin and backoffMax bound the redial interval, with jitter.
	// One second is short enough that a Graylog restart costs nothing
	// visible; thirty is long enough that an outage lasting hours does
	// not become a connection storm against a SIEM that is trying to come
	// back up.
	backoffMin = 1 * time.Second
	backoffMax = 30 * time.Second

	// reportEvery is how often the degraded state is restated in the log.
	// One line per dropped event would turn a Graylog outage into a disk
	// outage, and nobody reads 800 identical lines at 03:00. A minute is
	// often enough to see progress in a live incident and rare enough to
	// leave a readable trace in journalctl afterwards.
	reportEvery = 60 * time.Second

	// closeTimeout is the whole budget Close gets to drain the queue.
	//
	// Two seconds is not negotiable upwards: the 15s of shutdownTimeout
	// (cmd/mcp-gateway/serve.go) are already committed to the HTTP drain
	// and to gateway.Close, which reaps the containers holding
	// credentials before the service manager sends SIGKILL. Telemetry
	// does not compete for that budget.
	closeTimeout = 2 * time.Second

	// closeGrace is the slack Close allows past the drain budget before
	// it forcibly unblocks a stuck write. Without it the normal path --
	// where the loop finishes right at the budget -- would take the
	// forced route every single time.
	closeGrace = 250 * time.Millisecond
)

// Transport is which socket the messages leave by.
//
// There is no default anywhere in this component or in the file, because
// the choice changes what the gateway can TELL you: under UDP a
// successful write means the datagram left the socket and nothing more,
// so loss in transit is invisible to the counter. An operator has to
// write that argument down by choosing.
type Transport string

const (
	TransportUDP Transport = "udp"
	TransportTCP Transport = "tcp"
)

// Config is everything this adapter needs. Every field is a value the
// operator wrote or a seam the composition root injects; none of them is
// a credential, and there is no field that could become one.
type Config struct {
	// Address is host:port. It is NOT resolved by New.
	Address string
	// Transport is "udp" or "tcp". Required.
	Transport Transport
	// TLS wraps the TCP connection. Only valid with TransportTCP.
	//
	// There is no InsecureSkipVerify here and no file key that reaches
	// one. A verification switch is a switch somebody flips at 03:00 to
	// make an error go away, and it never gets flipped back.
	TLS bool
	// TLSCAFile is the PATH to a PEM trust anchor, never the value
	// (design/adr/0009 §3). Empty means the system pool.
	TLSCAFile string
	// Host is the GELF `host` field. Required, and deliberately not
	// defaulted to os.Hostname(): in a containerized process that returns
	// an id that changes on every restart, which shatters the grouping of
	// every Graylog dashboard without telling anyone. One line in the
	// file removes the failure mode.
	Host string
	// ClienteSOC is the GELF `_cliente_soc` field. Required: it is how
	// the SOC's Graylog routes a message to the client's stream, and
	// without it messages enter the system and land in no stream at all,
	// which is worse than not sending -- it looks like it worked.
	ClienteSOC string
	// Buffer is the queue capacity, in events.
	Buffer int
	// Logger is optional; nil means slog.Default(), the repo convention.
	Logger *slog.Logger
	// Now is optional; nil means time.Now. Injected so the gap window is
	// deterministic under test, the same way the gateway injects its own
	// clock into audit.Record.Timestamp.
	Now func() time.Time

	// timing compresses the intervals above. Unexported on purpose: it
	// is a seam for this package's own tests, which cannot wait a minute
	// to observe the degraded summary, and there is no file key and no
	// caller outside this package that can reach it.
	timing *timings
}

// timings groups the intervals a test needs to shrink.
//
// dialTimeout and writeTimeout are in here and not only as package
// constants because the window they open is the one shutdown pays for: a
// test that cannot compress them cannot exercise a dial that hangs, which
// is precisely where Close used to lose its budget.
type timings struct {
	reportEvery  time.Duration
	backoffMin   time.Duration
	backoffMax   time.Duration
	closeBudget  time.Duration
	dialTimeout  time.Duration
	writeTimeout time.Duration
}

// resolveTiming fills in the package constants for anything the caller
// left alone.
func (c Config) resolveTiming() timings {
	t := timings{
		reportEvery:  reportEvery,
		backoffMin:   backoffMin,
		backoffMax:   backoffMax,
		closeBudget:  closeTimeout,
		dialTimeout:  dialTimeout,
		writeTimeout: writeTimeout,
	}
	if c.timing == nil {
		return t
	}
	if c.timing.reportEvery > 0 {
		t.reportEvery = c.timing.reportEvery
	}
	if c.timing.backoffMin > 0 {
		t.backoffMin = c.timing.backoffMin
	}
	if c.timing.backoffMax > 0 {
		t.backoffMax = c.timing.backoffMax
	}
	if c.timing.closeBudget > 0 {
		t.closeBudget = c.timing.closeBudget
	}
	if c.timing.dialTimeout > 0 {
		t.dialTimeout = c.timing.dialTimeout
	}
	if c.timing.writeTimeout > 0 {
		t.writeTimeout = c.timing.writeTimeout
	}
	return t
}

// Sink is the running adapter: one bounded queue, one goroutine, one
// connection at a time. It satisfies telemetry.Sink.
type Sink struct {
	cfg         Config
	enc         encoder
	tlsConfig   *tls.Config
	log         *slog.Logger
	now         func() time.Time
	timing      timings
	destination string
	startedAt   time.Time

	// ch is the queue, and it is bounded on purpose.
	//
	// When it is full, Emit drops the event that is ARRIVING -- the
	// NEWEST -- and never the oldest already queued. The reason is not
	// "do not reorder evidence". It is that the gap has to be CONTIGUOUS
	// and have a nameable beginning: dropping the newest leaves a
	// contiguous prefix in the queue and puts everything missing in the
	// tail, which is exactly the interval
	// `mcp-gateway audit --since <gap_start>` recovers. Dropping the
	// oldest would produce a gap with holes in it -- some events of the
	// period present, others not -- and no --since query reconstructs
	// that without manual deduplication.
	//
	// It is never closed: Emit may run concurrently with Close, and a
	// send on a closed channel panics. Shutdown is signalled by quit.
	ch   chan audit.Record
	quit chan struct{}
	done chan struct{}

	// dialCtx is cancelled by Close, and it is the only way an in-flight
	// dial can be made to return. quit alone cannot do it: the loop is
	// inside s.dial when it matters, and a channel nobody is selecting on
	// is a channel nobody reads.
	dialCtx    context.Context
	cancelDial context.CancelFunc

	// closeDeadline is the instant the drain budget expires, in Unix
	// nanoseconds, written by Close BEFORE it signals quit. The drain
	// reads it instead of starting a budget of its own from whenever the
	// loop happened to notice: a relative budget taken at that moment
	// stacks on top of whatever Close has already spent waiting, and two
	// budgets in sequence is exactly the overrun this field removes.
	closeDeadline atomic.Int64

	closeOnce sync.Once
	closeErr  error

	// Counters are atomic because Emit touches two of them and Emit is
	// on the request path: it must not wait behind the writer goroutine
	// for a mutex, however briefly.
	emitted         atomic.Uint64
	written         atomic.Uint64
	droppedFull     atomic.Uint64
	droppedWrite    atomic.Uint64
	droppedOversize atomic.Uint64
	droppedClosing  atomic.Uint64

	// firstDropAt is the Timestamp of the EARLIEST event dropped since the
	// last gap message, in Unix nanoseconds; zero means nothing is
	// pending. It exists because a drop does not need the destination to
	// be down: the queue fills whenever the consumer is slower than the
	// producer, and those events would otherwise be announced in the next
	// gap while falling OUTSIDE the window `--since gap_start` recovers,
	// which is the one recovery plan this design has.
	//
	// It holds the record's own timestamp rather than a reading of the
	// clock: that is the instant the SQLite row carries, so it is the
	// instant `mcp-gateway audit --since` understands, and taking it
	// costs Emit no syscall.
	firstDropAt atomic.Int64

	// mu guards the state that has to change together: a failure sets
	// four fields and decides whether a transition happened, and a
	// reader must never see half of that.
	mu                  sync.Mutex
	degraded            bool
	consecutiveFailures uint64
	lastError           string
	lastErrorAt         time.Time
	lastWriteAt         time.Time
	gapStart            time.Time
	// dropsAnnounced is the drop total as of the last gap message. What
	// a gap message reports is the difference against it, so every lost
	// event is admitted exactly once even when the loss started before
	// the goroutine noticed the destination was down -- which is the
	// normal case, because the queue fills and starts dropping while the
	// first dial is still in flight.
	dropsAnnounced dropCounts
	// lastHealthyDropReport is the drop total as of the last
	// "not keeping up" line, so that line repeats only while the loss is
	// still growing.
	lastHealthyDropReport dropCounts
	// active is the connection the loop is currently writing to, exposed
	// only so Close can put a deadline in the past on it and unblock a
	// write that is already stuck. Nothing else outside the loop may use
	// it.
	active net.Conn
}

// Compile-time proof that the adapter satisfies the port. Cheap, and it
// fails at build time rather than at wiring time.
var _ telemetry.Sink = (*Sink)(nil)

// New validates the LOCAL configuration and starts the goroutine. It
// does not touch the network: no DNS resolution, no dial, no write.
//
// It fails only on something the operator wrote that will not fix
// itself -- an invalid transport, an address that does not parse, an
// empty Host or ClienteSOC, a non-positive Buffer, a TLSCAFile that
// cannot be read or holds no certificate. Every one of those is a boot
// failure on purpose, and every remote condition is not: a gateway that
// refuses to start because the SIEM's DNS is down is telemetry taking
// down the request path.
//
// Like config.Validate, it reports every problem at once rather than the
// first one, so an operator fixing the file gets one round trip.
func New(cfg Config) (*Sink, error) {
	var errs []error

	switch cfg.Transport {
	case TransportUDP, TransportTCP:
	default:
		errs = append(errs, fmt.Errorf("transport %q is neither %q nor %q, and there is no default",
			cfg.Transport, TransportUDP, TransportTCP))
	}

	if host, port, err := net.SplitHostPort(cfg.Address); err != nil || host == "" || port == "" {
		errs = append(errs, fmt.Errorf("address %q is not host:port -- a GELF input is a port, "+
			"not a name, and there is no default port to guess", cfg.Address))
	}

	if cfg.TLS && cfg.Transport != TransportTCP {
		errs = append(errs, fmt.Errorf("tls is set with transport %q -- there is no GELF UDP over TLS",
			cfg.Transport))
	}

	if cfg.Host == "" {
		errs = append(errs, errors.New("host is required -- it is the field every Graylog dashboard "+
			"groups by, and this component will not invent one"))
	}
	if cfg.ClienteSOC == "" {
		errs = append(errs, errors.New("cliente_soc is required -- it is how the SOC's Graylog routes "+
			"a message to the client's stream"))
	}
	if cfg.Buffer <= 0 {
		errs = append(errs, fmt.Errorf("buffer %d is not positive -- a zero-length queue would make "+
			"Emit synchronous, and the request path never waits on telemetry", cfg.Buffer))
	}

	// The CA file is read HERE and not in internal/config: the file
	// validates form and contradiction, the adapter validates that a
	// local file exists and has a certificate in it. Both are boot
	// failures; neither resolves DNS.
	var tlsConfig *tls.Config
	if cfg.TLS {
		conf, err := loadTLSConfig(cfg.TLSCAFile)
		if err != nil {
			errs = append(errs, err)
		}
		tlsConfig = conf
	}

	if len(errs) > 0 {
		return nil, errors.Join(append([]error{ErrInvalidConfig}, errs...)...)
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	s := &Sink{
		cfg:         cfg,
		enc:         encoder{host: cfg.Host, clienteSOC: cfg.ClienteSOC},
		tlsConfig:   tlsConfig,
		log:         log,
		now:         now,
		timing:      cfg.resolveTiming(),
		destination: string(cfg.Transport) + " " + cfg.Address,
		ch:          make(chan audit.Record, cfg.Buffer),
		quit:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	// Background and not a caller's context, deliberately: see the
	// comment on the goroutine below. Close is what cancels this, and the
	// loop cancels it on the way out so a Sink that is never closed does
	// not leak the context along with its goroutine.
	s.dialCtx, s.cancelDial = context.WithCancel(context.Background())
	s.startedAt = now()

	// The goroutine's life runs from New to Close, and NEVER from the
	// process context. That context is cancelled the instant the signal
	// arrives, BEFORE server.Shutdown drains the in-flight requests, so
	// tying the sink to it would stop recording exactly during the drain
	// -- one of the more interesting windows there is.
	go s.loop()

	return s, nil
}

// loadTLSConfig builds the client TLS configuration from a PEM path.
// Empty path means the system pool, which is the right default for a
// destination with a publicly-issued certificate and the wrong one for an
// internal CA -- hence the file key.
func loadTLSConfig(caFile string) (*tls.Config, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return conf, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls_ca_file %q holds no PEM certificate -- a trust anchor that "+
			"parses to nothing would make every connection fail with a confusing error at 03:00",
			caFile)
	}
	conf.RootCAs = pool
	return conf, nil
}

// Emit hands r to the queue and returns. It is the whole request-path
// cost of this component: one channel send that cannot block, and one
// counter.
//
// No lock over I/O, no syscall, no timeout, no serialization. The JSON is
// built in the writer goroutine so that even an encoding failure is
// counted far away from the client.
func (s *Sink) Emit(r audit.Record) {
	// Counted before the send, so a concurrent Stats can never show more
	// written than emitted. The accounting invariant is asserted after
	// Close, when neither side is moving.
	s.emitted.Add(1)
	select {
	case s.ch <- r:
	default:
		s.droppedFull.Add(1)
		s.noteDrop(r)
	}
}

// noteDrop remembers the earliest record lost since the last gap message,
// so the gap can start where the loss started rather than where the
// destination was noticed to be down.
//
// On the request path (from Emit) in the drop branch only: one atomic
// load in the common case, no clock reading, no allocation and no lock.
// Keeping the EARLIEST rather than the first one seen matters because
// records reach Emit from every request goroutine there is, and the first
// one to lose the race is not necessarily the oldest.
func (s *Sink) noteDrop(r audit.Record) {
	if r.Timestamp.IsZero() {
		// A record with no timestamp would store a value from 1754 and
		// turn the recovery command into nonsense. The trail refuses such
		// a record, so this is a guard and not a case.
		return
	}
	ts := r.Timestamp.UnixNano()
	for {
		cur := s.firstDropAt.Load()
		if cur != 0 && cur <= ts {
			return
		}
		if s.firstDropAt.CompareAndSwap(cur, ts) {
			return
		}
	}
}

// Stats is a coherent snapshot. It never blocks on the network and never
// waits for the writer goroutine.
func (s *Sink) Stats() telemetry.Stats {
	s.mu.Lock()
	degraded := s.degraded
	st := telemetry.Stats{
		ConsecutiveFailures: s.consecutiveFailures,
		LastError:           s.lastError,
		LastErrorAt:         s.lastErrorAt,
		LastWriteAt:         s.lastWriteAt,
		GapStart:            s.gapStart,
	}
	s.mu.Unlock()

	st.Configured = true
	st.Destination = s.destination
	st.Healthy = !degraded
	st.Queued = len(s.ch)
	st.Capacity = cap(s.ch)
	st.Emitted = s.emitted.Load()
	st.Written = s.written.Load()
	st.DroppedFull = s.droppedFull.Load()
	st.DroppedWrite = s.droppedWrite.Load()
	st.DroppedOversize = s.droppedOversize.Load()
	st.DroppedClosing = s.droppedClosing.Load()
	return st
}

// Close stops the goroutine, drains what fits in its own budget, and
// reports what it discarded. Idempotent: the second call returns the same
// answer as the first without touching anything.
//
// Emitting after Close is a wiring mistake rather than a supported call.
// It does not panic -- the queue is never closed, precisely because Emit
// may be running concurrently -- but the event lands in a queue nobody is
// draining and shows up in Stats as Queued, which is the honest report of
// what happened to it.
func (s *Sink) Close() error {
	s.closeOnce.Do(func() {
		// Written BEFORE the signal, so the drain inherits what is left
		// of one budget instead of opening a second one.
		s.closeDeadline.Store(time.Now().Add(s.timing.closeBudget).UnixNano())
		close(s.quit)
		// Ends an in-flight dial. Without this the loop cannot observe
		// quit until the dial returns on its own -- up to dialTimeout,
		// two and a half times the whole budget -- and a destination that
		// swallows the SYN is where the loop spends most of its life.
		// Harmless to an already-established connection.
		s.cancelDial()

		select {
		case <-s.done:
		case <-time.After(s.timing.closeBudget + closeGrace):
			// The loop is parked inside a write against a peer that
			// stopped reading. A deadline in the past makes that Write
			// return immediately, and net.Conn deadlines are safe to set
			// from another goroutine -- this is the only thing outside
			// the loop that touches the connection.
			s.unblockWrite()
			select {
			case <-s.done:
			case <-time.After(closeGrace):
				// Giving up on the goroutine rather than on the
				// shutdown. An abandoned goroutine in a process that is
				// exiting costs nothing; a Close with no ceiling holds
				// the whole shutdown hostage, and the 15s of
				// shutdownTimeout are already committed elsewhere. Said
				// out loud because the counts below may now be short by
				// whatever that goroutine was still doing.
				s.log.Warn("mcp-gateway: telemetry writer did not stop within the close budget; "+
					"abandoning it to the exiting process, and the discard count below may be incomplete",
					slog.String("destination", s.destination),
					slog.Duration("budget", s.timing.closeBudget),
				)
			}
		}

		if n := s.droppedClosing.Load(); n > 0 {
			s.closeErr = fmt.Errorf("gelf: shutdown discarded %d queued audit events -- they are "+
				"still in the SQLite trail; recover with %q", n,
				"mcp-gateway audit --since "+s.recoverFrom().UTC().Format(time.RFC3339))
		}
	})
	return s.closeErr
}

// recoverFrom is the earliest instant the operator has to replay from to
// cover what this process failed to ship: the current gap if there is
// one, otherwise the last successful write, otherwise the moment the sink
// started.
func (s *Sink) recoverFrom() time.Time {
	s.mu.Lock()
	var from time.Time
	switch {
	case !s.gapStart.IsZero():
		from = s.gapStart
	case !s.lastWriteAt.IsZero():
		from = s.lastWriteAt
	default:
		from = s.startedAt
	}
	s.mu.Unlock()
	return s.widenToFirstDrop(from)
}

// widenToFirstDrop moves an instant back to the earliest unannounced
// drop, when there is one earlier.
//
// Recovery has to over-cover. A drop while the destination was healthy --
// the queue not keeping up, which needs no outage at all -- happens
// BEFORE the last successful write, so a window that begins at the last
// write silently excludes exactly the events it is admitting were lost.
// Re-fetching an event that did arrive costs nothing; missing one does.
func (s *Sink) widenToFirstDrop(from time.Time) time.Time {
	fd := s.firstDropAt.Load()
	if fd == 0 {
		return from
	}
	if t := time.Unix(0, fd).UTC(); from.IsZero() || t.Before(from) {
		return t
	}
	return from
}

// unblockWrite forces an in-flight write to return. See Close.
func (s *Sink) unblockWrite() {
	s.mu.Lock()
	c := s.active
	s.mu.Unlock()
	if c != nil {
		_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	}
}

// loop is the one goroutine. The report ticker lives in the SAME select
// as the writer, so there is no second timer to forget to stop and the
// report cannot be starved independently of delivery.
func (s *Sink) loop() {
	defer close(s.done)
	// Releases the dial context even when Close is never called, which is
	// a wiring mistake but not a reason to leak.
	defer s.cancelDial()

	ticker := time.NewTicker(s.timing.reportEvery)
	defer ticker.Stop()

	var w writer
	defer func() {
		if w != nil {
			_ = w.Close()
		}
	}()

	// retry is non-nil only while waiting out a backoff. While it is
	// pending the loop does not dequeue anything, which is the point: the
	// queue is what absorbs the outage, and an event pulled out of it
	// during a failure would be an event lost early for nothing.
	var retry <-chan time.Time
	backoff := s.timing.backoffMin

	for {
		// Never start a dial with shutdown already signalled. The select
		// below can pick <-retry over <-s.quit when both are ready --
		// select chooses at random -- and one more dial after Close has
		// begun is one more window where nothing observes quit.
		select {
		case <-s.quit:
			s.drain(w)
			return
		default:
		}

		if w == nil && retry == nil {
			nw, err := s.dial(s.dialCtx)
			if err != nil {
				select {
				case <-s.quit:
					// The dial was cancelled by Close, not refused by
					// the destination. Charging our own shutdown as a
					// delivery failure would put a WARN and an open gap
					// into every clean stop that happened to land inside
					// a dial.
					s.drain(nil)
					return
				default:
				}
				s.noteFailure(err)
				retry = time.After(backoff)
				backoff = nextBackoff(backoff, s.timing.backoffMax)
				continue
			}
			s.setActive(nw.conn())
			// The gap message is the FIRST thing on a new connection, or
			// it is not sent at all: a gap announced after the events
			// that followed it reads as a new outage.
			if err := s.sendGap(nw); err != nil {
				s.noteFailure(err)
				s.setActive(nil)
				_ = nw.Close()
				retry = time.After(backoff)
				backoff = nextBackoff(backoff, s.timing.backoffMax)
				continue
			}
			w = nw
		}

		// A nil channel blocks forever in a select, which is how the loop
		// stops dequeuing while there is nowhere to write.
		var in <-chan audit.Record
		if w != nil {
			in = s.ch
		}

		select {
		case r := <-in:
			if s.send(w, r) {
				backoff = s.timing.backoffMin
				continue
			}
			s.setActive(nil)
			_ = w.Close()
			w = nil
			retry = time.After(backoff)
			backoff = nextBackoff(backoff, s.timing.backoffMax)

		case <-retry:
			retry = nil

		case <-ticker.C:
			s.report()

		case <-s.quit:
			s.drain(w)
			return
		}
	}
}

// nextBackoff doubles d up to max, with jitter. The jitter matters
// because a fleet of gateways restarted together would otherwise redial
// in lockstep and hit a recovering Graylog as one burst.
func nextBackoff(d, max time.Duration) time.Duration {
	next := d * 2
	if next > max {
		next = max
	}
	// Up to 20% of the interval, subtracted rather than added, so the
	// ceiling stays a ceiling.
	span := int64(next) / 5
	if span <= 0 {
		return next
	}
	return next - time.Duration(rand.Int64N(span))
}

// send encodes and writes one record. It reports whether the CONNECTION
// is still usable -- which is not the same as whether the record was
// sent: an oversize or unencodable record is dropped and counted, and the
// connection is fine.
func (s *Sink) send(w writer, r audit.Record) bool {
	msg, err := s.enc.encode(r)
	if err != nil {
		s.countEncodeFailure(r, err)
		return true
	}
	if err := w.write(msg, time.Now().Add(s.timing.writeTimeout)); err != nil {
		// noteFailure first: it snapshots the drop counters to open the
		// gap, and this record's own drop belongs inside the gap it just
		// started.
		s.noteFailure(err)
		s.droppedWrite.Add(1)
		s.noteDrop(r)
		return false
	}
	s.written.Add(1)
	s.noteWritten()
	return true
}

// countEncodeFailure attributes a record that never became bytes.
//
// Oversize gets its own counter because it has its own fix (something in
// the trail is far bigger than a tool name should be). Anything else --
// in practice only an outcome the closed level map does not know -- lands
// in DroppedWrite, which is the "did not reach the socket" bucket; it
// does not deserve a seventh counter for a case audit.Record.Validate
// already makes unreachable.
func (s *Sink) countEncodeFailure(r audit.Record, err error) {
	s.noteDrop(r)
	if errors.Is(err, errOversize) {
		s.droppedOversize.Add(1)
		// Named fields, so the operator can find the row in the trail
		// that this message would have been about.
		s.log.Warn("mcp-gateway: telemetry message dropped, over the size ceiling",
			slog.String("destination", s.destination),
			slog.String("tool", r.Tool),
			slog.String("outcome", string(r.Outcome)),
			slog.Int("ceiling_bytes", MaxMessageBytes),
			slog.String("detail", truncate(err.Error(), maxErrorBytes)),
		)
		return
	}
	s.droppedWrite.Add(1)
	s.log.Warn("mcp-gateway: telemetry message could not be encoded",
		slog.String("destination", s.destination),
		slog.String("tool", r.Tool),
		slog.String("outcome", string(r.Outcome)),
		slog.String("detail", truncate(err.Error(), maxErrorBytes)),
	)
}

// dropCounts is the three drop buckets read together, so a gap can be
// expressed as the difference between two snapshots instead of as a
// running total that something else has to keep in step.
type dropCounts struct {
	full     uint64
	write    uint64
	oversize uint64
}

// drops reads the three buckets. Not atomic as a group, and it does not
// need to be: it is only ever read by the writer goroutine, and the worst
// a skew could do is move one event between two gap messages.
func (s *Sink) drops() dropCounts {
	return dropCounts{
		full:     s.droppedFull.Load(),
		write:    s.droppedWrite.Load(),
		oversize: s.droppedOversize.Load(),
	}
}

// sendGap writes the synthetic gap message on a freshly dialled
// connection, and only when something was actually dropped. A recovery
// with nothing lost sends nothing: otherwise every reconnection would
// become gap spam announcing zero.
func (s *Sink) sendGap(w writer) error {
	s.mu.Lock()
	degraded := s.degraded
	announced := s.dropsAnnounced
	g := gap{start: s.gapStart, end: s.now()}
	s.mu.Unlock()

	if !degraded {
		return nil
	}

	now := s.drops()
	g.droppedFull = now.full - announced.full
	g.droppedWrite = now.write - announced.write
	g.droppedOversize = now.oversize - announced.oversize
	// The window has to contain every event this message is admitting to,
	// including the ones lost while the destination still looked fine.
	g.start = s.widenToFirstDrop(g.start)

	if g.total() == 0 {
		// The connection came back and nothing was lost. Still a
		// recovery, still one INFO line, but nothing for the SIEM to be
		// told about: there is no hole in the stream to explain.
		s.firstDropAt.Store(0)
		s.markRecovered(g)
		return nil
	}

	msg, err := s.enc.gapMessage(g)
	if err != nil {
		// A gap message that will not encode is not worth failing a
		// recovered connection over; the recovery log line carries the
		// same numbers.
		s.log.Warn("mcp-gateway: telemetry gap message could not be encoded",
			slog.String("detail", truncate(err.Error(), maxErrorBytes)))
		s.announced(now)
		s.markRecovered(g)
		return nil
	}
	if err := w.write(msg, time.Now().Add(s.timing.writeTimeout)); err != nil {
		return err
	}
	// Deliberately NOT counted in Written. Written is the delivered half
	// of the accounting invariant over what Emit was given, and this
	// message came from nowhere but here -- counting it would make the
	// invariant fail by exactly the number of outages.
	s.announced(now)

	s.markRecovered(g)
	return nil
}

// announced records that everything lost up to n has now been admitted in
// a gap message: the next gap reports the difference against it, and the
// window of the next gap no longer has to reach back past it.
func (s *Sink) announced(n dropCounts) {
	s.mu.Lock()
	s.dropsAnnounced = n
	s.mu.Unlock()
	s.firstDropAt.Store(0)
}

// noteFailure records one delivery failure and, if this is the
// healthy->degraded transition, says so exactly once.
func (s *Sink) noteFailure(err error) {
	s.mu.Lock()
	s.consecutiveFailures++
	s.lastError = truncate(err.Error(), maxErrorBytes)
	s.lastErrorAt = s.now()

	transition := !s.degraded
	if transition {
		s.degraded = true
		// The gap starts at the last instant we know reached the SIEM,
		// NOT at the instant the problem was noticed. Recovery has to
		// over-cover rather than under-cover: the events between the
		// last successful write and the first failed attempt are
		// precisely the ones nobody would think to look for, and
		// `audit --since` re-fetching one event that did arrive costs
		// nothing.
		switch {
		case !s.lastWriteAt.IsZero():
			s.gapStart = s.lastWriteAt
		default:
			s.gapStart = s.startedAt
		}
	}
	detail := s.lastError
	gapStart := s.gapStart
	s.mu.Unlock()

	if !transition {
		return
	}
	s.log.Warn("mcp-gateway: telemetry delivery failing",
		slog.String("destination", s.destination),
		slog.String("detail", detail),
		slog.String("recover_with", recoverCommand(s.widenToFirstDrop(gapStart))),
	)
}

// noteWritten records one successful write, and clears the degraded state
// if a gap was open with nothing lost (the lossy case already recovered
// when its gap message went out).
func (s *Sink) noteWritten() {
	s.mu.Lock()
	s.lastWriteAt = s.now()
	s.consecutiveFailures = 0
	degraded := s.degraded
	g := gap{start: s.gapStart, end: s.lastWriteAt}
	s.mu.Unlock()

	if degraded {
		s.markRecovered(g)
	}
}

// markRecovered closes the current gap and says so once, with cumulative
// totals and the recovery command already assembled.
func (s *Sink) markRecovered(g gap) {
	s.mu.Lock()
	if !s.degraded {
		s.mu.Unlock()
		return
	}
	s.degraded = false
	s.consecutiveFailures = 0
	s.gapStart = time.Time{}
	s.mu.Unlock()

	st := s.Stats()
	s.log.Info("mcp-gateway: telemetry recovered",
		slog.String("destination", s.destination),
		slog.Duration("for", g.end.Sub(g.start)),
		slog.Uint64("emitted", st.Emitted),
		slog.Uint64("written", st.Written),
		slog.Uint64("dropped_full", st.DroppedFull),
		slog.Uint64("dropped_write", st.DroppedWrite),
		slog.Uint64("dropped_oversize", st.DroppedOversize),
		slog.String("recover_with", g.recoverWith()),
	)
}

// report restates the degraded state on the ticker, with CUMULATIVE
// totals and never deltas: one line has to answer "how many", without
// arithmetic between lines.
func (s *Sink) report() {
	s.mu.Lock()
	degraded := s.degraded
	gapStart := s.gapStart
	detail := s.lastError
	s.mu.Unlock()

	if !degraded {
		s.reportHealthyDrops()
		return
	}
	st := s.Stats()
	s.log.Warn("mcp-gateway: telemetry still failing",
		slog.String("destination", s.destination),
		slog.Duration("for", s.now().Sub(gapStart)),
		slog.String("detail", detail),
		slog.Uint64("emitted", st.Emitted),
		slog.Uint64("written", st.Written),
		slog.Uint64("dropped_full", st.DroppedFull),
		slog.Uint64("dropped_write", st.DroppedWrite),
		slog.Uint64("dropped_oversize", st.DroppedOversize),
		slog.Int("queued", st.Queued),
		slog.String("recover_with", recoverCommand(s.widenToFirstDrop(gapStart))),
	)
}

// reportHealthyDrops is the channel that would otherwise not exist: loss
// while the destination is UP.
//
// Nothing else says it. The gap message needs a reconnection, and a queue
// that simply cannot keep up never disconnects -- so without this line a
// burst that overran the buffer at 03:00 is invisible until the next
// outage, and invisible forever if there is never one. It repeats only
// while the total is still MOVING: "it dropped something once" restated
// every minute is noise, "it is still dropping" is an incident.
func (s *Sink) reportHealthyDrops() {
	now := s.drops()

	s.mu.Lock()
	announced := s.dropsAnnounced
	last := s.lastHealthyDropReport
	s.lastHealthyDropReport = now
	s.mu.Unlock()

	if now == announced || now == last {
		return
	}

	st := s.Stats()
	s.log.Warn("mcp-gateway: telemetry queue is not keeping up; events are being dropped with the "+
		"destination up",
		slog.String("destination", s.destination),
		slog.Uint64("emitted", st.Emitted),
		slog.Uint64("written", st.Written),
		slog.Uint64("dropped_full", st.DroppedFull),
		slog.Uint64("dropped_write", st.DroppedWrite),
		slog.Uint64("dropped_oversize", st.DroppedOversize),
		slog.Int("queued", st.Queued),
		slog.Int("capacity", st.Capacity),
		slog.String("recover_with", recoverCommand(s.recoverFrom())),
	)
}

// recoverCommand is the single spelling of the recovery instruction, so
// the log lines and the synthetic gap message cannot drift apart.
func recoverCommand(from time.Time) string {
	return "mcp-gateway audit --since " + from.UTC().Format(time.RFC3339)
}

// drain is Close's half of the bargain: write what fits in the budget,
// then account for everything left instead of leaving it in a queue
// nobody will ever read.
//
// If there is no connection it does not dial one. A dial during shutdown
// spends the whole budget on the least likely thing to succeed, and the
// events are in the trail either way.
func (s *Sink) drain(w writer) {
	if w != nil {
		s.drainWriting(w, s.drainDeadline())
	}
	for {
		select {
		case <-s.ch:
			s.droppedClosing.Add(1)
		default:
			return
		}
	}
}

// drainDeadline is what is LEFT of Close's budget, never a fresh one.
//
// The loop can reach the drain long after Close signalled -- it may have
// been inside a dial, or inside a write -- and a budget counted from that
// moment is a second budget stacked on the first. Close set the absolute
// instant before it signalled; this honours it.
func (s *Sink) drainDeadline() time.Time {
	dl := time.Now().Add(s.timing.closeBudget)
	if cd := s.closeDeadline.Load(); cd > 0 {
		if t := time.Unix(0, cd); t.Before(dl) {
			return t
		}
	}
	return dl
}

// drainWriting sends queued events until the queue is empty, the budget
// runs out, or the connection breaks.
func (s *Sink) drainWriting(w writer, deadline time.Time) {
	for time.Now().Before(deadline) {
		select {
		case r := <-s.ch:
			msg, err := s.enc.encode(r)
			if err != nil {
				s.countEncodeFailure(r, err)
				continue
			}
			// The per-write deadline is clamped by the close budget:
			// writeTimeout alone is longer than the whole budget, and
			// shutdown may not overrun on telemetry's account.
			wd := time.Now().Add(s.timing.writeTimeout)
			if deadline.Before(wd) {
				wd = deadline
			}
			if err := w.write(msg, wd); err != nil {
				s.noteFailure(err)
				s.droppedWrite.Add(1)
				s.noteDrop(r)
				return
			}
			s.written.Add(1)
			s.noteWritten()
		default:
			return
		}
	}
}

// setActive publishes (or clears) the connection Close is allowed to poke.
func (s *Sink) setActive(c net.Conn) {
	s.mu.Lock()
	s.active = c
	s.mu.Unlock()
}
