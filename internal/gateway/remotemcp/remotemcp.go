// Package remotemcp is the remote adapter for [gateway.Dialer] (ADR-0058):
// a native MCP server reached by URL, held as a live connection over the
// official Go SDK's [mcp.StreamableClientTransport]. It has the shape of the
// stdio adapter -- one session per dial, ListTools and CallTool delegated to
// it, [gateway.ErrUpstreamGone] when the far end loses the session -- and
// not the stateless shape of the REST adapter.
//
// Three rules govern it.
//
//  1. Every request leaves through the shared egress guard
//     (internal/egress): no proxy, every resolved address judged (loopback,
//     private, link-local and the metadata range refused) at dial and at the
//     socket, redirects pinned to the signed origin.
//
//  2. The credential is the gateway's own, resolved from the vault once per
//     connection and sent on every request of that connection, as a bearer
//     token or in the header the signed descriptor names. The analyst's
//     token never reaches it: access.Identity has no token field, so there
//     is nothing to forward. The value is never logged and never quoted in
//     an error -- errors this package returns are masked with it.
//
//  3. Close ends the session.
//
// # What this adapter does not isolate, and does not claim to
//
// A remote backend runs on somebody else's host. There is no uid, jail or
// container under this gateway's control -- it does not even start the
// process -- so the barrier is the operator's trust in the endpoint,
// attested by signing the entry and approving each tool. What the backend
// itself connects to after it receives a call is outside this gateway's
// view and outside ADR-0033's egress declaration, which governs only the
// backends the gateway starts. Only the gateway-to-remote hop is guarded
// (ADR-0058 §9).
//
// Unlike the stdio adapter, this one must hold the credential for the life
// of the connection: there is no child process to hand it to. It sits in
// the request-signing RoundTripper and nowhere else.
package remotemcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bunnyiesart/Gatte/internal/egress"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TransportRemote is the only value of [gateway.UpstreamSpec.Transport] this
// dialer serves.
const TransportRemote = "remote"

// KindStreamable is the only remote kind this build dials: MCP Streamable
// HTTP. KindSSE (legacy HTTP+SSE) is reserved and refused (ADR-0058 §3).
const (
	KindStreamable = "streamable"
	KindSSE        = "sse"
)

// Auth kinds this adapter sends a credential as.
const (
	AuthNone   = ""
	AuthBearer = "bearer"
	AuthHeader = "header"
)

// maxRedirects bounds a same-origin redirect chain by the number of
// requests one exchange may send, as in the REST adapter.
const maxRedirects = 3

// Sentinel errors.
var (
	// ErrUnsupportedTransport means the spec asked for a transport, or a
	// remote kind, this dialer does not implement.
	ErrUnsupportedTransport = errors.New("remotemcp: unsupported transport")
	// ErrInvalidURL means the endpoint is not one this adapter will dial.
	ErrInvalidURL = errors.New("remotemcp: invalid endpoint url")
	// ErrAuthMismatch means the auth descriptor and the resolved secrets
	// disagree: a keyless entry with a secret, a keyed one without exactly
	// one, or an auth kind this adapter does not send.
	ErrAuthMismatch = errors.New("remotemcp: auth descriptor does not match the resolved credential")
	// ErrNoCredential means the vault resolved the entry's secret to the
	// empty string; an empty bearer is an anonymous request, not a keyed one.
	ErrNoCredential = errors.New("remotemcp: credential resolved to an empty value")
	// ErrClosed means a method was called on an upstream already closed.
	ErrClosed = errors.New("remotemcp: upstream connection is closed")
)

// Dialer opens remote MCP sessions. It implements [gateway.Dialer]. It
// holds policy only -- how the gateway names itself to backends, and the
// egress guard -- and no credential. It is safe for concurrent use.
type Dialer struct {
	clientName    string
	clientVersion string
	// guard is the zero egress.Guard (system resolver, egress.RefuseAddr)
	// outside _test.go, which is the only place that replaces it.
	guard egress.Guard
}

var _ gateway.Dialer = (*Dialer)(nil)

// Option configures a [Dialer].
type Option func(*Dialer)

// WithClientInfo sets the name and version reported in the MCP initialize
// handshake.
func WithClientInfo(name, version string) Option {
	return func(d *Dialer) {
		if name != "" {
			d.clientName = name
		}
		d.clientVersion = version
	}
}

// New returns a Dialer adjusted by opts.
func New(opts ...Option) *Dialer {
	d := &Dialer{clientName: "mcp-gateway"}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// ValidateURL reports the error Dial would return for raw as an endpoint,
// or nil, with no I/O: http or https, a host, no userinfo, query or
// fragment, and a literal-address host the egress policy accepts. A host
// name is not resolved here; it is judged at every dial. It is the console
// seam that refuses at register an entry the gateway would refuse forever.
func ValidateURL(raw string) error {
	_, err := parseEndpoint(raw, egress.Guard{})
	return err
}

// parseEndpoint checks raw and returns the origin the client is pinned to.
func parseEndpoint(raw string, guard egress.Guard) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", fmt.Errorf("%w: scheme %q is not http or https", ErrInvalidURL, u.Scheme)
	case u.Opaque != "" || u.Hostname() == "":
		return "", fmt.Errorf("%w: url has no host", ErrInvalidURL)
	case u.User != nil:
		return "", fmt.Errorf("%w: url carries userinfo", ErrInvalidURL)
	case u.RawQuery != "" || u.ForceQuery:
		return "", fmt.Errorf("%w: url carries a query", ErrInvalidURL)
	case u.Fragment != "" || u.RawFragment != "":
		return "", fmt.Errorf("%w: url carries a fragment", ErrInvalidURL)
	case strings.Contains(u.Hostname(), "%"):
		return "", fmt.Errorf("%w: host %q has a zone or escape", ErrInvalidURL, u.Hostname())
	}
	if err := guard.LiteralHostRefusal(u.Hostname()); err != nil {
		return "", fmt.Errorf("%w: host %q: %w", ErrInvalidURL, u.Hostname(), err)
	}
	return egress.Origin(u), nil
}

// credential picks the one secret value a keyed entry sends, or "" for a
// keyless one.
func credential(spec gateway.UpstreamSpec, env map[string]string) (string, error) {
	switch spec.AuthKind {
	case AuthNone:
		if len(env) != 0 {
			return "", fmt.Errorf("%w: a keyless entry was given %d credential(s)", ErrAuthMismatch, len(env))
		}
		return "", nil
	case AuthBearer, AuthHeader:
		if spec.AuthKind == AuthHeader && spec.AuthName == "" {
			return "", fmt.Errorf("%w: auth kind %q names no header", ErrAuthMismatch, spec.AuthKind)
		}
		if len(env) != 1 {
			return "", fmt.Errorf("%w: auth kind %q sends one secret but %d were resolved", ErrAuthMismatch, spec.AuthKind, len(env))
		}
		for _, value := range env {
			if value == "" {
				return "", ErrNoCredential
			}
			if strings.ContainsAny(value, "\r\n\x00") {
				// Never quoted: the value is the credential.
				return "", fmt.Errorf("%w: the credential contains a line break or NUL and cannot be sent as a header", ErrAuthMismatch)
			}
			return value, nil
		}
	}
	return "", fmt.Errorf("%w: auth kind %q is not %q, %q or keyless", ErrAuthMismatch, spec.AuthKind, AuthBearer, AuthHeader)
}

// Dial implements [gateway.Dialer]: it opens an MCP session to spec.URL
// over Streamable HTTP and completes the initialize handshake. ctx bounds
// the handshake only; the session lives until Close.
//
// env holds the one resolved secret of a keyed entry, or nothing. Its value
// is kept by the returned upstream's request signer and nowhere else; no
// error this function returns quotes it.
func (d *Dialer) Dial(ctx context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	if spec.Transport != TransportRemote {
		return nil, fmt.Errorf("%w: upstream %q declares transport %q, this dialer serves %q only",
			ErrUnsupportedTransport, spec.Name, spec.Transport, TransportRemote)
	}
	switch spec.RemoteKind {
	case KindStreamable:
	case KindSSE:
		return nil, fmt.Errorf("%w: upstream %q: remote kind %q is reserved and deferred (design/adr/0058 §3)",
			ErrUnsupportedTransport, spec.Name, KindSSE)
	default:
		return nil, fmt.Errorf("%w: upstream %q: remote kind %q", ErrUnsupportedTransport, spec.Name, spec.RemoteKind)
	}
	origin, err := parseEndpoint(spec.URL, d.guard)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}
	secret, err := credential(spec, env)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}

	signer := &signedTransport{base: d.guard.Transport()}
	switch spec.AuthKind {
	case AuthBearer:
		signer.header, signer.value = "Authorization", "Bearer "+secret
	case AuthHeader:
		signer.header, signer.value = http.CanonicalHeaderKey(spec.AuthName), secret
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint: spec.URL,
		HTTPClient: &http.Client{
			Transport:     signer,
			CheckRedirect: egress.PinRedirects(origin, maxRedirects),
		},
		// No standalone GET stream: this gateway handles no server-initiated
		// message (tools/list_changed included -- the refresh ticker is what
		// re-observes tools, ADR-0058 §8), so the stream would be a
		// long-lived connection with nothing to carry.
		DisableStandaloneSSE: true,
	}
	client := mcp.NewClient(&mcp.Implementation{Name: d.clientName, Version: d.clientVersion}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("remotemcp: upstream %q: connect: %w", spec.Name, scrub(err, env))
	}
	return &upstream{name: spec.Name, session: session, env: env}, nil
}

// signedTransport adds the gateway's own credential to every request of
// one connection. It is the one place the value lives after Dial.
type signedTransport struct {
	base          http.RoundTripper
	header, value string
}

// RoundTrip implements [http.RoundTripper]. The request is cloned, as the
// RoundTripper contract requires, before the header is set.
func (t *signedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.header == "" {
		return t.base.RoundTrip(req)
	}
	out := req.Clone(req.Context())
	out.Header.Set(t.header, t.value)
	return t.base.RoundTrip(out)
}

// scrub returns err with every value of env masked, keeping only errors.Is
// of the original -- the stdio adapter's discipline. A JSON-RPC error the
// server wrote is server-authored text and may echo the token it was sent.
func scrub(err error, env map[string]string) error {
	msg, masked := gateway.MaskCredentials(err.Error(), env)
	if !masked {
		return err
	}
	return scrubbedError{msg: msg, is: err}
}

type scrubbedError struct {
	msg string
	is  error
}

func (e scrubbedError) Error() string        { return e.msg }
func (e scrubbedError) Is(target error) bool { return errors.Is(e.is, target) }

// upstream is one live remote session, implementing [gateway.Upstream].
// env is kept only to mask errors; the value that is sent lives in the
// session's signedTransport.
type upstream struct {
	name    string
	session *mcp.ClientSession
	env     map[string]string

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

var _ gateway.Upstream = (*upstream)(nil)

// ListTools implements [gateway.Upstream], following every page: a tool
// the gateway failed to list but would dispatch is the "callable yet
// invisible" state ADR-0007 rules out.
func (u *upstream) ListTools(ctx context.Context) ([]gateway.ToolDef, error) {
	if u.closed.Load() {
		return nil, fmt.Errorf("%w: upstream %q", ErrClosed, u.name)
	}
	var defs []gateway.ToolDef
	for tool, err := range u.session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("remotemcp: upstream %q: list tools: %w", u.name, u.classify(err))
		}
		schema, err := rawJSON(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("remotemcp: upstream %q: tool %q: input schema is not representable as JSON: %w", u.name, tool.Name, err)
		}
		output, err := rawJSON(tool.OutputSchema)
		if err != nil {
			return nil, fmt.Errorf("remotemcp: upstream %q: tool %q: output schema is not representable as JSON: %w", u.name, tool.Name, err)
		}
		defs = append(defs, gateway.ToolDef{
			Name:         tool.Name,
			Description:  tool.Description,
			InputSchema:  schema,
			OutputSchema: output,
		})
	}
	return defs, nil
}

// CallTool implements [gateway.Upstream]. Content is always a JSON array;
// structured content stays absent (nil) when the server sent none, as the
// stdio adapter reports it (ADR-0014).
func (u *upstream) CallTool(ctx context.Context, tool string, args json.RawMessage) (gateway.Result, error) {
	if u.closed.Load() {
		return gateway.Result{}, fmt.Errorf("%w: upstream %q", ErrClosed, u.name)
	}
	params := &mcp.CallToolParams{Name: tool}
	if len(args) > 0 {
		params.Arguments = args
	}
	res, err := u.session.CallTool(ctx, params)
	if err != nil {
		return gateway.Result{}, fmt.Errorf("remotemcp: upstream %q: call tool %q: %w", u.name, tool, u.classify(err))
	}
	content := json.RawMessage("[]")
	if len(res.Content) > 0 {
		encoded, err := json.Marshal(res.Content)
		if err != nil {
			return gateway.Result{}, fmt.Errorf("remotemcp: upstream %q: call tool %q: result content is not representable as JSON: %w", u.name, tool, err)
		}
		content = encoded
	}
	var structured json.RawMessage
	if res.StructuredContent != nil {
		encoded, err := rawJSON(res.StructuredContent)
		if err != nil {
			return gateway.Result{}, fmt.Errorf("remotemcp: upstream %q: call tool %q: structured content is not representable as JSON: %w", u.name, tool, err)
		}
		structured = encoded
	}
	return gateway.Result{Content: content, StructuredContent: structured, IsError: res.IsError}, nil
}

// isGone reports the errors that mean the server no longer holds this
// session: a 404 on the session (the server restarted or ended it,
// mcp.ErrSessionMissing) and the session closed under us afterwards
// (mcp.ErrConnectionClosed). A refused connection, a timeout or a 5xx is a
// server failing to answer, not a lost session, and is left as it is:
// treating it as death would make the health check a redial loop
// (ADR-0024). When such a server comes back it no longer knows the session,
// answers 404, and that is when the gateway redials.
func isGone(err error) bool {
	return errors.Is(err, mcp.ErrSessionMissing) || errors.Is(err, mcp.ErrConnectionClosed)
}

// classify maps a lost session to gateway.ErrUpstreamGone -- unless this
// side closed it, which is ErrClosed (ADR-0024 item 2, as in stdio) -- and
// masks the credential in whatever it returns.
func (u *upstream) classify(err error) error {
	if isGone(err) {
		if u.closed.Load() {
			err = fmt.Errorf("%w: %w", ErrClosed, err)
		} else {
			err = fmt.Errorf("%w: %w", gateway.ErrUpstreamGone, err)
		}
	}
	return scrub(err, u.env)
}

// Close implements [gateway.Upstream]. Safe to call more than once; the
// closed flag is set before the session is torn down so a concurrent call
// fails fast and is never reported as the server gone.
func (u *upstream) Close() error {
	u.closeOnce.Do(func() {
		u.closed.Store(true)
		if err := u.session.Close(); err != nil {
			u.closeErr = fmt.Errorf("remotemcp: upstream %q: close: %w", u.name, scrub(err, u.env))
		}
	})
	return u.closeErr
}

// rawJSON returns an SDK-decoded value as raw JSON bytes with no
// normalization of ours (ADR-0007), as the stdio adapter does.
func rawJSON(value any) (json.RawMessage, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		return bytes.Clone(typed), nil
	case []byte:
		return bytes.Clone(typed), nil
	}
	return json.Marshal(value)
}
