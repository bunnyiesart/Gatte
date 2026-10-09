// Package adminhttp serves the management service as the versioned JSON
// API of api/admin.openapi.yaml, over UNIX sockets only
// (design/adr/0040 §1, §4).
//
// Who the operator is comes from the kernel at accept time
// (internal/peercred), never from the request. Everything else a request
// carries is data to validate: a body with an unknown field is refused, a
// request that looks like a browser's is refused, and the front label is
// display only.
package adminhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/peercred"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Limits (design/adr/0040 §4).
const (
	MaxBody           = 64 << 10
	MaxHeaderBytes    = 16 << 10
	MaxConns          = 16
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 30 * time.Second
	DefaultIdle       = 5 * time.Minute
	// RequestDeadline bounds one request's work, retries included.
	RequestDeadline = 25 * time.Second
)

// Options configures a Server.
type Options struct {
	// Socket is adminapi.SocketOperator or adminapi.SocketAccounts: which
	// route set this server answers.
	Socket  string
	Service *admin.Service
	// ServiceUID is the gateway's service account. The accounts socket
	// refuses it; the operator socket lets it in past OperatorGID.
	ServiceUID uint32
	// OperatorGID, when set ([admin] operator_group), is the group a peer
	// of the operator socket must have unless it is root or ServiceUID. On
	// the accounts socket it decides nothing about who connects: it says
	// whether the peer is also an operator, which an offboard that blocks
	// needs (design/adr/0046).
	OperatorGID *uint32
	// LookupUser maps a uid to its account name (default: os/user).
	LookupUser func(uid uint32) (string, error)
	// ProcRoot is where /proc is (default "/proc"), for the loginuid.
	ProcRoot string
	// Idle is how long the server stays up with no request in flight and
	// none completed; zero never exits.
	Idle time.Duration
	// MaxConns bounds simultaneous connections (default 16).
	MaxConns       int
	Log            *slog.Logger
	ConfigPath     string
	GatewayVersion string
}

// Server is one management socket's HTTP server.
type Server struct {
	o      Options
	mux    *http.ServeMux
	active atomic.Int64
	mu     sync.Mutex
	last   time.Time
}

// New builds a server.
func New(o Options) (*Server, error) {
	if o.Socket != adminapi.SocketOperator && o.Socket != adminapi.SocketAccounts {
		return nil, fmt.Errorf("adminhttp: unknown socket %q", o.Socket)
	}
	if o.Service == nil {
		return nil, errors.New("adminhttp: a service is required")
	}
	if o.LookupUser == nil {
		o.LookupUser = lookupUser
	}
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.MaxConns <= 0 {
		o.MaxConns = MaxConns
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{o: o, last: time.Now()}
	s.mux = s.routes()
	return s, nil
}

func lookupUser(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// Serve answers on ln until ctx ends or, with Idle set, until the server
// has been idle that long. Open connections are closed on the way out.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	lim := &limitListener{Listener: ln, sem: make(chan struct{}, s.o.MaxConns)}
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ConnContext:       s.connContext,
		ErrorLog:          nil,
	}
	stop := make(chan struct{})
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			close(stop)
			sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
			_ = srv.Close()
		})
	}
	go func() {
		var tick <-chan time.Time
		if s.o.Idle > 0 {
			t := time.NewTicker(max(s.o.Idle/4, 20*time.Millisecond))
			defer t.Stop()
			tick = t.C
		}
		for {
			select {
			case <-ctx.Done():
				shutdown()
				return
			case <-stop:
				return
			case <-tick:
				if s.idleFor() >= s.o.Idle {
					s.o.Log.Info("admin: idle, exiting", "socket", s.o.Socket, "idle", s.o.Idle.String())
					shutdown()
					return
				}
			}
		}
	}()
	err := srv.Serve(lim)
	shutdown()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// idleFor is how long no request has been in flight or completed.
func (s *Server) idleFor() time.Duration {
	if s.active.Load() > 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.last)
}

func (s *Server) begin() { s.active.Add(1) }

func (s *Server) end() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
	s.active.Add(-1)
}

// peer is what the kernel said about one connection, decided once.
type peer struct {
	uid  uint32
	name string
	via  string
	// operator: the peer is root or in OperatorGID, read from the kernel's
	// groups at accept.
	operator bool
	err      *adminapi.Error
}

type peerKey struct{}

// connContext reads the peer's credentials once per connection, at accept.
func (s *Server) connContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, peerKey{}, s.identify(c))
}

func (s *Server) identify(c net.Conn) *peer {
	cred, err := peercred.Of(c)
	if err != nil {
		return &peer{err: adminapi.NewError(adminapi.CodePeerUnattributable, "the kernel did not say who connected: %v", err)}
	}
	defer cred.Release()
	p := &peer{uid: cred.UID}
	name, err := s.o.LookupUser(cred.UID)
	if err != nil || name == "" {
		p.err = adminapi.NewError(adminapi.CodePeerUnattributable, "uid %d has no account name on this system; an action without an author is not a record", cred.UID)
		return p
	}
	p.name = name
	p.operator = cred.UID == 0 || s.o.OperatorGID != nil && cred.HasGroup(*s.o.OperatorGID)
	switch s.o.Socket {
	case adminapi.SocketAccounts:
		if cred.UID == s.o.ServiceUID {
			p.err = adminapi.NewError(adminapi.CodeForbiddenPeer, "the gateway's service account may not edit accounts (design/adr/0038)")
			return p
		}
	case adminapi.SocketOperator:
		if g := s.o.OperatorGID; g != nil && cred.UID != 0 && cred.UID != s.o.ServiceUID && !cred.HasGroup(*g) {
			p.err = adminapi.NewError(adminapi.CodeForbiddenPeer, "%s is not in the operator group", name)
			return p
		}
	}
	// Root behind sudo: the loginuid, read now, names the human.
	if peercred.HasLoginUID && trustsLoginUID(cred.UID, s.o.ServiceUID) {
		if lu, ok := peercred.LoginUID(s.o.ProcRoot, cred.PID, cred.UID, cred.Alive); ok && lu != cred.UID {
			if human, err := s.o.LookupUser(lu); err == nil && human != "" {
				p.via, p.name = name, human
			}
		}
	}
	return p
}

// trustsLoginUID says whether a peer of this uid is named by its loginuid
// (design/adr/0040 §2). Only root: a process whose loginuid is unset may
// set it without privilege (audit_set_loginuid_perm), and every process
// systemd starts as the service account has it unset, so a service-account
// peer could name any operator. It keeps its own name; an operator
// connects as themselves, as a member of the operator group. Root could
// write the trail directly anyway.
func trustsLoginUID(uid, _ uint32) bool { return uid == 0 }

var frontRe = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// request is one call as a handler sees it.
type request struct {
	*http.Request
	w     http.ResponseWriter
	actor admin.Actor
	peer  *peer
	front string
	// maxBody is the route's body limit; zero is MaxBody.
	maxBody int64
}

// decode reads the JSON body into v, refusing unknown fields, a body over
// MaxBody and a body that is not JSON. An absent body leaves v as it is.
// It runs before the service takes its lock.
func (r *request) decode(v any) error {
	limit := r.maxBody
	if limit <= 0 {
		limit = MaxBody
	}
	body := http.MaxBytesReader(r.w, r.Body, limit)
	data, err := io.ReadAll(body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return adminapi.NewError(adminapi.CodePayloadTooLarge, "the body is over %d bytes", limit)
		}
		return adminapi.NewError(adminapi.CodeBadRequest, "reading the body: %v", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return adminapi.NewError(adminapi.CodeBadRequest, "the body must be application/json")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return adminapi.NewError(adminapi.CodeBadRequest, "the body: %v", err)
	}
	if dec.More() {
		return adminapi.NewError(adminapi.CodeBadRequest, "the body carries more than one JSON value")
	}
	return nil
}

// handler wraps every route with the checks every request passes.
func (s *Server) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.begin()
		defer s.end()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		rw := &statusWriter{ResponseWriter: w}
		p, _ := r.Context().Value(peerKey{}).(*peer)
		defer func() {
			op := ""
			if p != nil {
				op = p.name
			}
			// Method, path and status only: never a body, never a query
			// that could carry something a person typed.
			s.o.Log.Info("admin: request", "socket", s.o.Socket, "method", r.Method, "path", r.URL.Path, "status", rw.status, "operator", op)
		}()
		if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" {
			writeErr(rw, adminapi.NewError(adminapi.CodeBrowserRequestRefused,
				"a request carrying Origin or Cookie is a browser's, and a browser never reaches this socket as it is; a web front terminates it with pkg/frontkit"))
			return
		}
		if p == nil {
			writeErr(rw, adminapi.NewError(adminapi.CodePeerUnattributable, "no peer credentials for this connection"))
			return
		}
		if p.err != nil {
			writeErr(rw, p.err)
			return
		}
		front := r.Header.Get(adminapi.FrontHeader)
		if front != "" && !frontRe.MatchString(front) {
			writeErr(rw, adminapi.NewError(adminapi.CodeBadRequest, "%s must be 1-32 of a-z 0-9 . _ -", adminapi.FrontHeader))
			return
		}
		// The service's busy retries stop at this deadline, inside the
		// write timeout, so an answer is always sent.
		ctx, cancel := context.WithTimeout(r.Context(), RequestDeadline)
		defer cancel()
		s.mux.ServeHTTP(rw, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeErr(w, adminapi.NewError(adminapi.CodeInternal, "encoding the answer: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *adminapi.Error
	if !errors.As(err, &ae) {
		ae = adminapi.NewError(adminapi.CodeInternal, "%v", err)
	}
	status := ae.Status
	if status == 0 {
		status = adminapi.StatusOf(ae.Code)
	}
	b, _ := json.Marshal(adminapi.ErrorResponse{Error: ae})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

// limitListener closes a connection beyond the limit at accept.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
		default:
			_ = c.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// UnixConn exposes the socket for peercred.Of.
func (c *limitedConn) UnixConn() *net.UnixConn {
	uc, _ := c.Conn.(*net.UnixConn)
	return uc
}
