package gelf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// writer is one open connection to the destination. It exists so the
// writer loop holds a single notion of "can I send a message right now",
// with the framing difference between the two transports settled here
// rather than in the loop.
//
// There is no Reconnect: a failed write closes the writer and the loop
// dials a new one after backoff. A connection that repairs itself in
// place hides the state transition the operator needs to see.
type writer interface {
	// write sends one already-encoded message, adding whatever framing
	// the transport needs. deadline bounds the whole attempt.
	write(msg []byte, deadline time.Time) error
	// conn exposes the underlying connection so Close can set a deadline
	// in the past on it from another goroutine and unblock a write that
	// is already stuck. net.Conn deadlines are safe for concurrent use;
	// this is the only thing anyone outside the loop may touch.
	conn() net.Conn
	// Close releases the connection.
	Close() error
}

// udpWriter sends one datagram per message: no framing, no compression,
// no chunking. A datagram is a message boundary already, which is why
// nothing has to be appended.
type udpWriter struct {
	c net.Conn
}

func (w *udpWriter) write(msg []byte, deadline time.Time) error {
	if err := w.c.SetWriteDeadline(deadline); err != nil {
		return err
	}
	_, err := w.c.Write(msg)
	return err
}

func (w *udpWriter) conn() net.Conn { return w.c }

func (w *udpWriter) Close() error { return w.c.Close() }

// tcpWriter sends JSON terminated by a NUL byte, which is the framing the
// Graylog GELF TCP input requires -- and the same input that does not
// accept compression, which is one of the reasons nothing here compresses.
//
// A field value cannot break this frame: encoding/json escapes every
// control character, NUL included, as a six-character \u escape, so the
// only NUL in the buffer is the one appended here. That is asserted by a
// test rather than left as a comment, because it is the assumption an
// encoder swap would silently invalidate.
type tcpWriter struct {
	c net.Conn
	// framed is reused across writes so the hot path does not allocate a
	// second buffer per message.
	framed []byte
}

func (w *tcpWriter) write(msg []byte, deadline time.Time) error {
	if err := w.c.SetWriteDeadline(deadline); err != nil {
		return err
	}
	w.framed = append(append(w.framed[:0], msg...), 0)
	_, err := w.c.Write(w.framed)
	return err
}

func (w *tcpWriter) conn() net.Conn { return w.c }

func (w *tcpWriter) Close() error { return w.c.Close() }

// dial opens a new connection to the destination. It is called only from
// the writer goroutine, and never from New: a gateway that refuses to
// start because the SIEM's DNS is down would be telemetry taking down the
// request path at the worst possible moment.
//
// ctx is the shutdown seam, and it is the reason this takes a context
// while nothing else in the package does. dialTimeout alone bounds how
// long ONE attempt runs, not how long Close has to wait for it: a
// destination whose SYN is dropped by a firewall -- the ordinary shape of
// a wrong SIEM address on a filtered network -- parks this function for
// the whole timeout, and while it is parked the loop cannot observe quit
// and Close's own budget means nothing. Cancelling ctx ends the attempt
// in microseconds. Cancelling it AFTER a connection is established does
// nothing to that connection (net's DialContext contract), so the drain
// that follows still has a usable socket.
//
// tls.Dialer rather than tls.DialWithDialer for the same reason:
// DialWithDialer does not cancel the handshake, which is the half of a
// TLS dial that actually hangs.
func (s *Sink) dial(ctx context.Context) (writer, error) {
	d := net.Dialer{Timeout: s.timing.dialTimeout}

	switch s.cfg.Transport {
	case TransportUDP:
		// "Connecting" a UDP socket resolves the address and fixes the
		// peer; it sends nothing. What it buys is that the kernel can
		// report ICMP port-unreachable back as a write error, which is
		// the only way this transport ever learns that nobody is home.
		c, err := d.DialContext(ctx, "udp", s.cfg.Address)
		if err != nil {
			return nil, err
		}
		return &udpWriter{c: c}, nil

	case TransportTCP:
		if s.tlsConfig != nil {
			td := &tls.Dialer{NetDialer: &d, Config: s.tlsConfig}
			c, err := td.DialContext(ctx, "tcp", s.cfg.Address)
			if err != nil {
				return nil, err
			}
			return &tcpWriter{c: c}, nil
		}
		c, err := d.DialContext(ctx, "tcp", s.cfg.Address)
		if err != nil {
			return nil, err
		}
		return &tcpWriter{c: c}, nil
	}

	// Unreachable: New refuses any other transport before the goroutine
	// exists.
	return nil, fmt.Errorf("gelf: unsupported transport %q", s.cfg.Transport)
}
