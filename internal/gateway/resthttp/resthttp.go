package resthttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// TransportHTTP is the only value of [gateway.UpstreamSpec.Transport] this
// dialer serves.
const TransportHTTP = "http"

// Sentinel errors.
var (
	// ErrUnsupportedTransport means the spec asked for a transport this
	// dialer does not implement. Every dialer in this tree refuses the
	// transports it does not serve rather than guessing, so that a
	// misrouted entry fails loudly at dial time instead of being run by
	// whichever adapter happened to be wired.
	ErrUnsupportedTransport = errors.New("resthttp: unsupported transport")
	// ErrInvalidURL means the signed base URL is not one this adapter will
	// pin a client to -- see parseBase for the rules.
	ErrInvalidURL = errors.New("resthttp: invalid base url")
	// ErrAuthMismatch means the auth descriptor and the resolved
	// environment disagree: a keyless entry arrived with a secret, or a
	// keyed one arrived with none or with several. The registry refuses
	// both at register time (registry.validateHTTP); this is the same rule
	// at the point the secret would be used.
	ErrAuthMismatch = errors.New("resthttp: auth descriptor and credential disagree")
	// ErrNoVault means a keyed entry was dialled through a Dialer built
	// without a vault.Provider, so no call could ever resolve its secret.
	ErrNoVault = errors.New("resthttp: no credential vault to resolve the secret with")
	// ErrUnknownTool means CallTool named a tool the operation set does
	// not contain.
	ErrUnknownTool = errors.New("resthttp: unknown tool")
	// errInvalidArguments means the call's arguments could not be placed on
	// a request: not an object, a key outside the declared properties, a
	// value the location cannot carry, or an attempt at the credential's
	// slot. Refused before any request is built -- and never returned by
	// CallTool as an error: the caller, not the backend, got it wrong, so
	// CallTool answers with a Result{IsError: true} that says why
	// (ADR-0041 item 2; ADR-0048 Decisão 9, dated note). An error here
	// would reach the analyst as BackendFailedError, pointing the operator
	// at a backend that was never called.
	errInvalidArguments = errors.New("invalid arguments")
	// ErrBodyTooLarge means the response body exceeded WithMaxBodyBytes.
	// The body is refused whole, never truncated: a truncated JSON document
	// handed to a model as if complete is worse than no document.
	ErrBodyTooLarge = errors.New("resthttp: response body too large")
	// ErrNoCredential means the vault resolved the entry's secret to the
	// empty string. A keyed API called with an empty key would answer 401
	// at best; at worst the server treats "no key" as "anonymous tier" and
	// the operator never learns the secret is gone.
	ErrNoCredential = errors.New("resthttp: credential resolved to an empty value")
)

// Defaults for the two options.
const (
	// defaultClientTimeout bounds one whole exchange (connect, send,
	// headers, body) when the caller's ctx carries no deadline. The gateway
	// always does (Gateway.CallTimeout, default config.DefaultCallTimeout =
	// 2 min), so this is the backstop for a caller that is not the gateway.
	defaultClientTimeout = 2 * time.Minute
	// defaultMaxBodyBytes is the gateway's own result ceiling: a body the
	// gateway would refuse as a Result is not worth holding in memory first.
	defaultMaxBodyBytes = gateway.DefaultMaxResultBytes
	// maxRedirects bounds a same-origin redirect chain by the number of
	// requests one call may send: checkRedirect sees `via`, the requests
	// already sent, and refuses the hop that would be request number
	// maxRedirects+1 -- so maxRedirects-1 redirects are followed and the
	// next 3xx is handed back as the response. Three requests cover "add a
	// trailing slash" then "moved to v2"; a longer chain is the API's
	// problem to report, not ours to chase.
	// TestCallTool_SameOriginRedirectsAreFollowedUpToALimit pins the count.
	maxRedirects = 3
)

// Dialer builds stateless REST upstreams. It implements [gateway.Dialer].
//
// A Dialer holds policy -- the vault to resolve credentials through, the
// client timeout, the body ceiling, the egress policy -- and nothing
// per-entry. It holds no credential material and has no field that could.
//
// A Dialer is safe for concurrent use.
type Dialer struct {
	provider vault.Provider
	timeout  time.Duration
	maxBody  int64

	// lookup and egress are the resolver and the IP policy of egress.go.
	// They are fields so that _test.go can point a name at a forbidden
	// address, or let httptest's loopback through, without a network;
	// nothing outside the tests assigns them (export_test.go).
	lookup lookupFunc
	egress func(addr netip.Addr) error
}

var _ gateway.Dialer = (*Dialer)(nil)

// Option configures a [Dialer].
type Option func(*Dialer)

// WithHTTPClientTimeout sets the ceiling on one whole HTTP exchange, as
// http.Client.Timeout applies it. Values <= 0 select the default. The
// gateway's per-call ctx deadline is the ceiling that normally fires; this
// one exists so that a caller without a deadline cannot hang a goroutine
// on a server that never answers.
func WithHTTPClientTimeout(d time.Duration) Option {
	return func(dl *Dialer) {
		if d > 0 {
			dl.timeout = d
		}
	}
}

// WithMaxBodyBytes sets how many bytes of a response body one call will
// read before refusing the response as ErrBodyTooLarge. Values <= 0 select
// the default (gateway.DefaultMaxResultBytes). This is the adapter's own
// ceiling, applied while reading, so a hostile or merely verbose API cannot
// make the gateway buffer an unbounded body before the gateway's own result
// ceiling (which judges the finished Result) gets to see it.
func WithMaxBodyBytes(n int64) Option {
	return func(dl *Dialer) {
		if n > 0 {
			dl.maxBody = n
		}
	}
}

// New returns a Dialer that resolves credentials through provider,
// adjusted by opts. provider may be nil for a deployment with only keyless
// REST entries; a keyed entry then fails at Dial with ErrNoVault rather
// than at its first call.
func New(provider vault.Provider, opts ...Option) *Dialer {
	d := &Dialer{
		provider: provider,
		timeout:  defaultClientTimeout,
		maxBody:  defaultMaxBodyBytes,
		lookup:   defaultLookup,
		egress:   refuseAddr,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Dial implements [gateway.Dialer]. It performs no I/O: a REST API has no
// connection to open and no handshake to complete (ADR-0047 §2), so Dial
// validates the entry and builds the host-pinned client every call will
// use. Health is therefore a fixed "up" (ADR-0048 Decisão 9); a server that
// is down is discovered by the first call, not by the dial.
//
// What is refused: a Transport other than "http"; a URL parseBase refuses,
// or whose host is a literal address the egress policy refuses (the dial
// would fail on every call, so it fails here, as ValidateBaseURL makes it
// fail at register); an auth kind that disagrees with env (keyless with a
// secret, keyed without exactly one); a keyed entry when New was given no
// vault; an operation set Decode refuses. The last error is masked with env
// before it is returned -- an operation set is operator-authored text and
// should not hold a secret, but "should not" is not the standard here.
//
// env is read for exactly one thing: the NAME of its single entry, which
// is the secret-ref the upstream re-resolves on every call (ADR-0047 §5).
// No value from env reaches the returned Upstream, a log line, or an error.
func (d *Dialer) Dial(ctx context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	if spec.Transport != TransportHTTP {
		return nil, fmt.Errorf("%w: upstream %q declares transport %q, this dialer serves %q only",
			ErrUnsupportedTransport, spec.Name, spec.Transport, TransportHTTP)
	}
	b, err := parseBase(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}
	// d.egress, not refuseAddr: the test-only loopback allowance must let
	// an httptest base through here exactly as it does at the socket.
	if err := b.literalHostRefusal(d.egress); err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}
	secretName, err := secretRef(spec.AuthKind, env)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, err)
	}
	if secretName != "" && d.provider == nil {
		return nil, fmt.Errorf("%w: upstream %q", ErrNoVault, spec.Name)
	}
	ops, err := Decode(spec.Operations, spec.AuthKind, spec.AuthName)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, scrubDialError(err, env))
	}
	routes, err := routesOf(ops)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec.Name, scrubDialError(err, env))
	}

	return &upstream{
		name:       spec.Name,
		base:       b,
		authKind:   spec.AuthKind,
		authName:   spec.AuthName,
		secretName: secretName,
		provider:   d.provider,
		ops:        ops,
		routes:     routes,
		maxBody:    d.maxBody,
		client: &http.Client{
			Transport:     d.newTransport(),
			Timeout:       d.timeout,
			CheckRedirect: b.checkRedirect,
		},
	}, nil
}

// secretRef returns the name of the one secret a keyed entry injects, or
// "" for a keyless one, and refuses any other combination of descriptor
// and resolved environment.
func secretRef(authKind string, env map[string]string) (string, error) {
	if authKind == AuthNone {
		if len(env) != 0 {
			return "", fmt.Errorf("%w: auth kind is empty (keyless) but %d credential(s) were resolved; a keyless entry injects nothing", ErrAuthMismatch, len(env))
		}
		return "", nil
	}
	if len(env) != 1 {
		return "", fmt.Errorf("%w: auth kind %q injects one secret but %d were resolved", ErrAuthMismatch, authKind, len(env))
	}
	for name := range env {
		if name == "" {
			return "", fmt.Errorf("%w: the secret reference has an empty name", ErrAuthMismatch)
		}
		return name, nil
	}
	return "", fmt.Errorf("%w: no secret reference", ErrAuthMismatch) // unreachable: len(env) == 1
}

// scrubDialError returns err with every value of env masked, keeping only
// errors.Is of the original -- the same discipline as the stdio adapter's
// function of the same name (internal/gateway/stdio/stdio.go:306). When
// nothing matches, err is returned untouched and its chain stays whole, so
// the console can still errors.Is(err, ErrInvalidOperations).
func scrubDialError(err error, env map[string]string) error {
	msg, masked := gateway.MaskCredentials(err.Error(), env)
	if !masked {
		return err
	}
	return scrubbedError{msg: msg, is: err}
}

// ValidateBaseURL reports the error Dial would return for raw as the signed
// base URL, or nil, without building a client and with no I/O. It is the
// operator console's seam (cmd/mcp-gateway dialTimeRefusal): a URL this
// adapter would refuse at every start is refused at register/sign instead
// (ADR-0047 §2, "validação de pré-registro do transporte http"). The rules
// are parseBase's plus the egress policy applied to a host that is already
// a literal address (http://169.254.169.254/, http://127.0.0.1/, ...):
// that needs no resolver, so it belongs at the prompt rather than in the
// trail of the first failed call. A host NAME is not resolved here --
// register must not do DNS -- and is judged per call by dialPinned.
//
// Pre-condition: none. Post-condition: nil if and only if Dial would accept
// raw as its URL; a non-nil error wraps ErrInvalidURL, and additionally
// ErrEgressRefused when it is the literal host that was refused.
func ValidateBaseURL(raw string) error {
	b, err := parseBase(raw)
	if err != nil {
		return err
	}
	return b.literalHostRefusal(refuseAddr)
}

// base is the signed URL decomposed into what the client is pinned to.
type base struct {
	scheme string
	// host is the authority as the URL spelled it (lower-cased), used to
	// build request URLs; origin is scheme://host with the default port
	// made explicit, used to compare a redirect target against.
	host   string
	origin string
	// path is the base path with no trailing slash ("" or "/api/v2"); an
	// operation's template is appended to it (ADR-0047 §6, "dobrar o base
	// path").
	path string
	// hostname is host without the port or brackets, for the literal-address
	// check (literalHostRefusal).
	hostname string
}

// literalHostRefusal applies egress to the base's host when it is already an
// IP literal, and returns nil for a host name (judged at dial, when it has
// addresses). A refusal wraps ErrInvalidURL and the egress error, so the
// console reports an invalid entry and the caller can still tell why.
func (b base) literalHostRefusal(egress func(netip.Addr) error) error {
	a, err := netip.ParseAddr(b.hostname)
	if err != nil {
		return nil
	}
	if err := egress(a); err != nil {
		return fmt.Errorf("%w: host %q: %w", ErrInvalidURL, b.hostname, err)
	}
	return nil
}

// parseBase checks the signed URL and splits it into the parts the client
// is pinned to. Refused: a scheme other than http or https; an opaque URL;
// a missing host; userinfo (a credential in the URL is a credential in
// every error that prints the URL); a query or a fragment (the query is
// built by the adapter from arguments and the auth descriptor, so a
// pre-loaded one would be an unsigned second channel into it); and a base
// path that ParsePath refuses or that carries a template. ParsePath runs on
// the path AS SPELLED, before its one trailing "/" is dropped: trimming
// first turned "https://h//" into the accepted "/" and "https://h/api//"
// into "/api/", and every request then began "//check" or "/api//check" --
// the "//" ParsePath exists to refuse, smuggled in by the base.
//
// Pre-condition: none. Post-condition: on nil error every request URL this
// upstream builds starts with b.scheme://b.host + b.path, where b.path is
// "" or begins with "/", has no "//" and does not end in "/".
func parseBase(raw string) (base, error) {
	if strings.TrimSpace(raw) == "" {
		return base{}, fmt.Errorf("%w: url is empty", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return base{}, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return base{}, fmt.Errorf("%w: scheme %q is not http or https", ErrInvalidURL, u.Scheme)
	}
	if u.Opaque != "" {
		return base{}, fmt.Errorf("%w: url is opaque", ErrInvalidURL)
	}
	if u.User != nil {
		return base{}, fmt.Errorf("%w: url carries userinfo; a credential is injected from the vault, never written into the url", ErrInvalidURL)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return base{}, fmt.Errorf("%w: url carries a query; the query is built per call from arguments and the auth descriptor", ErrInvalidURL)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return base{}, fmt.Errorf("%w: url carries a fragment", ErrInvalidURL)
	}
	hostname := u.Hostname()
	if hostname == "" {
		return base{}, fmt.Errorf("%w: url has no host", ErrInvalidURL)
	}
	if strings.ContainsAny(hostname, "%") {
		return base{}, fmt.Errorf("%w: host %q has a zone or escape", ErrInvalidURL, hostname)
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	path := u.EscapedPath()
	if path != "" && path != "/" {
		templates, err := ParsePath(path)
		if err != nil {
			return base{}, fmt.Errorf("%w: base path: %v", ErrInvalidURL, err)
		}
		if len(templates) != 0 {
			return base{}, fmt.Errorf("%w: base path %q carries a template; only an operation path may", ErrInvalidURL, path)
		}
	}
	path = strings.TrimSuffix(path, "/")
	host := strings.ToLower(u.Host)
	return base{
		scheme:   u.Scheme,
		host:     host,
		origin:   u.Scheme + "://" + joinHostPort(strings.ToLower(hostname), port),
		path:     path,
		hostname: strings.ToLower(hostname),
	}, nil
}

// joinHostPort brackets an IPv6 literal, as net.JoinHostPort does.
func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// originOf renders u's origin the way parseBase did for the base, with
// the default port explicit, so "https://h" and "https://h:443" compare
// equal and "https://h" and "http://h:443" do not.
func originOf(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + joinHostPort(strings.ToLower(u.Hostname()), port)
}

// checkRedirect is the http.Client.CheckRedirect of every upstream's
// client: the structural host-pin of ADR-0048 Decisão 6. A redirect whose
// scheme, host or port differs from the signed origin is refused with
// ErrEgressRefused -- not followed, and not reported with its full URL,
// since a Location an API controls can carry anything. A same-origin
// redirect is followed up to maxRedirects; past that the last 3xx is
// returned as the response (http.ErrUseLastResponse) and reaches the caller
// as an IsError result with its Location header, which the gateway's
// scrubResult masks like any header.
func (b base) checkRedirect(req *http.Request, via []*http.Request) error {
	if got := originOf(req.URL); got != b.origin {
		return fmt.Errorf("%w: redirect to %s refused; this upstream is pinned to %s", ErrEgressRefused, got, b.origin)
	}
	if len(via) >= maxRedirects {
		return http.ErrUseLastResponse
	}
	return nil
}

// route is one operation with what CallTool needs pre-computed from its
// schema: the set of declared property names, so an argument the operator
// never approved is refused by lookup rather than by guesswork.
type route struct {
	op    Operation
	props map[string]bool
}

// routesOf indexes a decoded operation set by tool name.
func routesOf(ops []Operation) (map[string]route, error) {
	routes := make(map[string]route, len(ops))
	for _, op := range ops {
		schema, err := decodeObject(op.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("%w: operation %q: input schema %v", ErrInvalidOperations, op.Name, err)
		}
		props := map[string]bool{}
		if raw, ok := schema["properties"].(map[string]any); ok {
			for name := range raw {
				props[name] = true
			}
		}
		routes[op.Name] = route{op: op, props: props}
	}
	return routes, nil
}

// upstream is one registered REST API, implementing [gateway.Upstream].
//
// It is stateless: no connection, no session, nothing that can die. What it
// holds is the pinned base, the auth descriptor, the operation set, the
// vault and the NAME of the secret. There is deliberately no field for the
// secret's value, and TestSecUpstreamRetainsNoCredential walks every field
// by reflection to keep it that way.
type upstream struct {
	name       string
	base       base
	authKind   string
	authName   string
	secretName string
	provider   vault.Provider
	ops        []Operation
	routes     map[string]route
	maxBody    int64
	client     *http.Client

	closeOnce sync.Once
}

var _ gateway.Upstream = (*upstream)(nil)

// ListTools implements [gateway.Upstream]: one ToolDef per operation, in
// the set's (name) order, each with SecurityClass from ClassOf(method)
// (ADR-0048 Decisão 5). Nothing is fetched; the set is the signed one.
func (u *upstream) ListTools(context.Context) ([]gateway.ToolDef, error) {
	defs := make([]gateway.ToolDef, 0, len(u.ops))
	for _, op := range u.ops {
		defs = append(defs, op.ToolDef())
	}
	return defs, nil
}

// CallTool implements [gateway.Upstream]: it turns one call into one HTTP
// request on the pinned base and the response into one Result.
//
// Order, and why: the arguments are placed first (buildRequest), so a
// refused argument costs no vault round-trip and no network -- and is
// answered as a Result{IsError: true} naming the fault, not as an error,
// because the gateway reports every CallTool error as the backend's
// failure (endpoint.go Dispatch, ADR-0041 items 2-3) and the backend was
// never called; the secret is resolved next, through the vault, for this
// call only (ADR-0047 §5, the third place that touches plaintext), and
// injected where the signed descriptor says; the exchange runs on the
// caller's ctx; the body is read up to maxBody and refused past it; and the
// response is serialised by serialize, with the injected value masked out
// of it. Every error from the client or the body read passes through
// scrubCallError before it is returned (ADR-0048 Decisão 7).
//
// Pre-condition: tool is the operation's own name; an unknown one is an
// error (ErrUnknownTool), since the gateway dispatches only tools the set
// advertised and a miss is a gateway/adapter disagreement, not a caller
// mistake. Post-condition: the returned error holds neither the URL that
// was requested nor the credential's value in any rendering, and errors.Is
// still answers for context.Canceled, context.DeadlineExceeded and
// ErrEgressRefused; a returned Result holds no rendering of the value the
// call injected; gateway.ErrUpstreamGone is never returned (ADR-0048
// Decisão 9).
func (u *upstream) CallTool(ctx context.Context, tool string, args json.RawMessage) (gateway.Result, error) {
	rt, ok := u.routes[tool]
	if !ok {
		return gateway.Result{}, fmt.Errorf("%w: upstream %q has no tool %q", ErrUnknownTool, u.name, tool)
	}
	req, query, err := u.buildRequest(ctx, rt, args)
	if err != nil {
		if errors.Is(err, errInvalidArguments) {
			return argumentRefusal(tool, err)
		}
		return gateway.Result{}, fmt.Errorf("resthttp: upstream %q: call tool %q: %w", u.name, tool, err)
	}

	// env is the one-entry map the masking functions take; it exists for
	// the duration of this call and is cleared on every exit.
	var env map[string]string
	defer func() { clear(env) }()
	if u.secretName != "" {
		secret, err := u.provider.Resolve(ctx, u.secretName)
		if err != nil {
			return gateway.Result{}, fmt.Errorf("resthttp: upstream %q: call tool %q: resolve credential %q: %w", u.name, tool, u.secretName, err)
		}
		value := secret.Value()
		if value == "" {
			return gateway.Result{}, fmt.Errorf("%w: upstream %q, secret %q", ErrNoCredential, u.name, u.secretName)
		}
		env = map[string]string{u.secretName: value}
		u.inject(req, query, value)
	}
	req.URL.RawQuery = query.Encode()

	resp, err := u.client.Do(req)
	if err != nil {
		return gateway.Result{}, fmt.Errorf("resthttp: upstream %q: call tool %q: %w", u.name, tool, scrubCallError(err, rt.op, env))
	}
	defer resp.Body.Close()

	body, err := readBody(resp.Body, u.maxBody)
	if err != nil {
		if errors.Is(err, ErrBodyTooLarge) {
			return gateway.Result{}, fmt.Errorf("resthttp: upstream %q: call tool %q: %w", u.name, tool, err)
		}
		return gateway.Result{}, fmt.Errorf("resthttp: upstream %q: call tool %q: read body: %w", u.name, tool, scrubCallError(err, rt.op, env))
	}
	return serialize(resp, body, env)
}

// argumentRefusal is the Result a call with arguments the operation cannot
// carry gets: one text block with the reason, IsError set, nothing else.
// The reason names keys and the rule they broke, never a value -- the
// buildRequest errors are written that way -- and it is the caller's own
// input, so there is nothing to mask.
func argumentRefusal(tool string, err error) (gateway.Result, error) {
	text := fmt.Sprintf("tool %q: %s", tool, strings.TrimPrefix(err.Error(), errInvalidArguments.Error()+": "))
	content, merr := marshalCanonical([]textBlock{{Type: "text", Text: text}})
	if merr != nil {
		return gateway.Result{}, fmt.Errorf("resthttp: argument refusal is not representable as JSON: %v", merr)
	}
	return gateway.Result{Content: content, IsError: true}, nil
}

// inject places the credential where the auth descriptor says and nowhere
// else: bearer -> Authorization: Bearer <v>; header -> <AuthName>: <v>;
// query -> ?<AuthName>=<v>. Set, not Add: the server-side value wins, and
// Validate already refused any declared parameter on the same slot.
func (u *upstream) inject(req *http.Request, query url.Values, value string) {
	switch u.authKind {
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+value)
	case AuthHeader:
		req.Header.Set(u.authName, value)
	case AuthQuery:
		query.Set(u.authName, value)
	}
}

// buildRequest places args on a request for rt: path_* into the template,
// query_* into the returned url.Values (the caller encodes them after the
// credential is added), header_* into headers, cookie_* into one Cookie
// header, body as the JSON body with Content-Type application/json.
//
// Refused with errInvalidArguments, before any of that: args that are not
// a JSON object; a key the operation's schema does not declare (the
// operator approved that schema, so an undeclared query_debug is a request
// the operator never saw -- fail closed, whatever additionalProperties
// says); a required template with no value; a path value that is empty,
// holds "/" or a control byte, or is "." or ".." (url.PathEscape leaves
// those able to change which resource is named); a header value with a
// control byte; a cookie value outside RFC 6265's cookie-octet (Go's
// AddCookie would silently drop the bad bytes); and a non-scalar where a
// scalar is needed. The credential's own slot cannot be reached here at
// all, since Validate refused any property that named it.
func (u *upstream) buildRequest(ctx context.Context, rt route, args json.RawMessage) (*http.Request, url.Values, error) {
	fields := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(args)) != 0 {
		dec := json.NewDecoder(bytes.NewReader(args))
		if err := dec.Decode(&fields); err != nil {
			return nil, nil, fmt.Errorf("%w: arguments must be a JSON object: %v", errInvalidArguments, err)
		}
		if dec.More() {
			return nil, nil, fmt.Errorf("%w: arguments have trailing data after the object", errInvalidArguments)
		}
	}

	pathValues := map[string]string{}
	query := url.Values{}
	headers := http.Header{}
	var cookies []string
	var body json.RawMessage

	// Deterministic order so that which of two faults is reported does not
	// depend on map iteration.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !rt.props[key] {
			return nil, nil, fmt.Errorf("%w: %q is not a declared property of tool %q", errInvalidArguments, key, rt.op.Name)
		}
		raw := fields[key]
		switch {
		case key == BodyProperty:
			body = raw
		case strings.HasPrefix(key, PrefixPath):
			v, err := scalarText(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", errInvalidArguments, key, err)
			}
			if err := validPathValue(v); err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", errInvalidArguments, key, err)
			}
			pathValues[key[len(PrefixPath):]] = v
		case strings.HasPrefix(key, PrefixQuery):
			values, err := scalarTexts(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", errInvalidArguments, key, err)
			}
			query[key[len(PrefixQuery):]] = values
		case strings.HasPrefix(key, PrefixHeader):
			v, err := scalarText(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", errInvalidArguments, key, err)
			}
			if !validHeaderValue(v) {
				return nil, nil, fmt.Errorf("%w: %q: header value holds a control byte", errInvalidArguments, key)
			}
			headers.Set(key[len(PrefixHeader):], v)
		case strings.HasPrefix(key, PrefixCookie):
			v, err := scalarText(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %q: %v", errInvalidArguments, key, err)
			}
			if !validCookieValue(v) {
				return nil, nil, fmt.Errorf("%w: %q: cookie value holds a byte outside RFC 6265 cookie-octet", errInvalidArguments, key)
			}
			cookies = append(cookies, key[len(PrefixCookie):]+"="+v)
		default:
			// Validate admits no other shape into props; a route built from
			// a validated set cannot reach here.
			return nil, nil, fmt.Errorf("%w: %q is outside the location vocabulary", errInvalidArguments, key)
		}
	}

	escapedPath, err := fillPath(rt.op.Path, pathValues)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidArguments, err)
	}
	escapedPath = u.base.path + escapedPath
	unescaped, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: path: %v", errInvalidArguments, err)
	}
	target := &url.URL{Scheme: u.base.scheme, Host: u.base.host, Path: unescaped, RawPath: escapedPath}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, rt.op.Method, target.String(), reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", errInvalidArguments, err)
	}
	for name, values := range headers {
		req.Header[name] = values
	}
	if len(cookies) != 0 {
		req.Header.Set("Cookie", strings.Join(cookies, "; "))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, query, nil
}

// fillPath substitutes every {x} of template with the escaped value of
// pathValues[x]. ParsePath already guaranteed the literal parts are raw
// pchars, so the result is a fully escaped path.
func fillPath(template string, pathValues map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(template); {
		if template[i] != '{' {
			b.WriteByte(template[i])
			i++
			continue
		}
		end := strings.IndexByte(template[i:], '}')
		name := template[i+1 : i+end]
		v, ok := pathValues[name]
		if !ok {
			return "", fmt.Errorf("path template {%s} has no %s%s argument", name, PrefixPath, name)
		}
		b.WriteString(url.PathEscape(v))
		i += end + 1
	}
	return b.String(), nil
}

// scalarText renders one JSON scalar as the text a URL or header carries:
// a string as itself, a number or boolean as its literal. null, objects
// and arrays are refused: none has one obvious wire form.
func scalarText(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", errors.New("value is empty")
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("value is not a JSON string: %v", err)
		}
		return s, nil
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return "", fmt.Errorf("value is not a JSON boolean: %v", err)
		}
		return string(raw), nil
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return "", fmt.Errorf("value is not a JSON number: %v", err)
		}
		return n.String(), nil
	default:
		return "", errors.New("value must be a string, number or boolean")
	}
}

// scalarTexts is scalarText for a query parameter, which may also be an
// array of scalars (sent as a repeated parameter).
func scalarTexts(raw json.RawMessage) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) != 0 && trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("value is not a JSON array: %v", err)
		}
		out := make([]string, 0, len(items))
		for i, item := range items {
			v, err := scalarText(item)
			if err != nil {
				return nil, fmt.Errorf("item %d: %v", i, err)
			}
			out = append(out, v)
		}
		return out, nil
	}
	v, err := scalarText(raw)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

func validPathValue(v string) error {
	switch {
	case v == "":
		return errors.New("path value must not be empty")
	case v == "." || v == "..":
		return errors.New("path value must not be a dot segment")
	case strings.ContainsRune(v, '/'):
		return errors.New("path value must not contain \"/\"")
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return errors.New("path value holds a control byte")
		}
	}
	return nil
}

// validHeaderValue is RFC 9110 §5.5 field-value: VCHAR, SP, HTAB and
// obs-text, no other control byte.
func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// validCookieValue is RFC 6265 §4.1.1 cookie-octet: %x21 / %x23-2B /
// %x2D-3A / %x3C-5B / %x5D-7E -- no control, space, DQUOTE, comma,
// semicolon or backslash.
func validCookieValue(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == 0x21, c >= 0x23 && c <= 0x2b, c >= 0x2d && c <= 0x3a, c >= 0x3c && c <= 0x5b, c >= 0x5d && c <= 0x7e:
		default:
			return false
		}
	}
	return true
}

// readBody reads at most limit bytes of the body and refuses a body that
// has more. One byte past the limit is read on purpose: it is the only
// way to tell "exactly limit bytes" from "more than limit" without
// trusting Content-Length, which a server need not send and need not
// honour.
func readBody(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, limit)
	}
	return data, nil
}

// envelope is the one canonical shape a REST response takes inside an MCP
// result (ADR-0047 §2, "forma canônica definida na Fase A"):
//
//	{"status":200,"headers":{"Content-Type":["application/json"]},"body":...}
//
// headers holds every response header, canonical name -> values, keys
// sorted; nothing is filtered here -- a reflected credential in a Location
// or Set-Cookie is masked (serialize, then the gateway's scrubResult), and
// an adapter that dropped headers would also drop that evidence. body is the
// decoded JSON document when the response declares a JSON media type and
// the bytes parse; otherwise the body as a string, and when the bytes are
// not UTF-8, base64 with "encoding":"base64" beside it. A HEAD or empty
// response has "body":"".
type envelope struct {
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	Body     any                 `json:"body"`
	Encoding string              `json:"encoding,omitempty"`
}

// textBlock is the MCP content block the envelope travels in.
type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// serialize renders resp and its (already read) body as a Result: Content
// is a single text block holding the canonical envelope; IsError is any
// status outside 2xx; StructuredContent is the JSON body itself for a 2xx
// JSON response and nil otherwise, so an OutputSchema the ingestion derives
// from the API's response schema validates against the API's document, not
// against the envelope.
//
// secrets is the one-entry map of the value THIS call injected (empty for a
// keyless entry), and every rendering of it is masked out of the envelope
// and the structured body before they are returned (gateway.ScrubJSON). The
// gateway's scrubResult masks again, with the value it re-resolves from the
// vault; the difference is the window between the two resolves. A rotation
// in that window has the server echoing the OLD value -- in a 401 body, a
// Location, a Set-Cookie -- which only this function still knows. Masking
// here with the injected value closes it without holding the value past
// the call (ADR-0047 §5, dated note; ADR-0048 Decisão 7). A match that
// would leave the text invalid JSON is refused whole with
// gateway.ErrResultUnscrubbable, as scrubResult refuses it.
func serialize(resp *http.Response, body []byte, secrets map[string]string) (gateway.Result, error) {
	env := envelope{Status: resp.StatusCode, Headers: map[string][]string{}, Body: ""}
	for name, values := range resp.Header {
		env.Headers[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
	var structured json.RawMessage
	switch {
	case len(body) == 0:
	case isJSONMediaType(resp.Header.Get("Content-Type")) && json.Valid(body):
		compact, err := canonicalize(body)
		if err != nil {
			return gateway.Result{}, fmt.Errorf("resthttp: response body: %v", err)
		}
		env.Body = compact
		structured = compact
	case utf8.Valid(body):
		env.Body = string(body)
	default:
		env.Body = base64.StdEncoding.EncodeToString(body)
		env.Encoding = "base64"
	}

	isError := resp.StatusCode < 200 || resp.StatusCode > 299
	if isError {
		structured = nil
	}
	text, err := marshalCanonical(env)
	if err != nil {
		return gateway.Result{}, fmt.Errorf("resthttp: response is not representable as JSON: %v", err)
	}
	// Masked as JSON text, before the envelope is wrapped in its block: the
	// block's encoder would escape a rendering a second time, and the forms
	// ScrubJSON matches are those of a value inside one JSON string.
	if text, _, err = gateway.ScrubJSON(text, secrets); err != nil {
		return gateway.Result{}, fmt.Errorf("resthttp: response echoed the injected credential and could not be redacted: %w", err)
	}
	if structured, _, err = gateway.ScrubJSON(structured, secrets); err != nil {
		return gateway.Result{}, fmt.Errorf("resthttp: response echoed the injected credential and could not be redacted: %w", err)
	}
	content, err := marshalCanonical([]textBlock{{Type: "text", Text: string(text)}})
	if err != nil {
		return gateway.Result{}, fmt.Errorf("resthttp: response is not representable as JSON: %v", err)
	}
	return gateway.Result{Content: content, StructuredContent: structured, IsError: isError}, nil
}

// isJSONMediaType reports whether a Content-Type names JSON: application/
// json or any +json structured syntax suffix (RFC 6839).
func isJSONMediaType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	mt = strings.ToLower(mt)
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// Close implements [gateway.Upstream]. There is no connection to close
// and no process to reap: the transport keeps no idle connection
// (newTransport, DisableKeepAlives), so CloseIdleConnections is a
// formality kept for the day that changes. Idempotent and safe from
// several goroutines; it never fails.
func (u *upstream) Close() error {
	u.closeOnce.Do(func() {
		u.client.CloseIdleConnections()
	})
	return nil
}

// scrubCallError is ADR-0048 Decisão 7 in one place: every error out of
// http.Client.Do or the body read passes through it before it is returned.
//
//   - A *url.Error prints the FULL request URL, which with AuthKind=query
//     holds the live credential after "?name=". Its URL is replaced by the
//     operation's method and path TEMPLATE (never the filled path, which
//     holds caller arguments) and only the inner error's text is kept.
//   - gateway.MaskCredentials then masks every rendering of the live
//     value -- raw, %q, JSON and URL-encoded (redact.go renderingsOf) --
//     anywhere in what is left, in case the inner error echoed it.
//   - The result has no Unwrap, so errors.As cannot reach the *url.Error
//     and its URL, but it still answers errors.Is for the original chain:
//     context.Canceled, context.DeadlineExceeded and ErrEgressRefused keep
//     working for the gateway's dispatch.
//
// gateway.ErrUpstreamGone is never produced: a REST upstream has no stream
// that can end (ADR-0048 Decisão 9), so there is no classify step here,
// only this redaction.
func scrubCallError(err error, op Operation, env map[string]string) error {
	msg := err.Error()
	var uerr *url.Error
	if errors.As(err, &uerr) {
		msg = fmt.Sprintf("%s %s: %v", op.Method, op.Path, uerr.Err)
	}
	msg, _ = gateway.MaskCredentials(msg, env)
	return scrubbedError{msg: msg, is: err}
}

// scrubbedError is a scrubbed message that still answers errors.Is for its
// original cause, and deliberately has no Unwrap. GoString covers %#v, the
// one fmt verb that prints a struct's fields instead of calling Error().
type scrubbedError struct {
	msg string
	is  error
}

func (e scrubbedError) Error() string        { return e.msg }
func (e scrubbedError) GoString() string     { return "resthttp.scrubbedError{" + e.msg + "}" }
func (e scrubbedError) Is(target error) bool { return errors.Is(e.is, target) }
