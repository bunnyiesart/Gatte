// Package httpapi is the client-facing HTTP adapter for the Gateway
// Endpoint: it serves MCP over streamable HTTP and is the only surface an
// analyst's MCP client ever touches.
//
// It is therefore the boundary where an attacker meets this system, and
// everything below is written from that assumption. Three properties carry
// the weight:
//
//  1. **Every request is authenticated on its own.** The SDK handler runs in
//     Stateless mode, which neither reads nor sets Mcp-Session-Id, so there
//     is no session that could be mistaken for authentication. This is
//     required by design/adr/0008 ("ID de sessao nunca vale como
//     autenticacao"), not a preference; see [Config].
//
//  2. **The credential is read from `Authorization: Bearer` and nowhere
//     else.** Not a query parameter, not a custom header, not a cookie. A
//     credential in a URL lands in access logs, proxy logs and browser
//     history, and cannot be recalled from any of them. See [bearerToken].
//
//  3. **Internal errors do not cross the wire.** The errors this gateway
//     raises internally are deliberately informative -- access.Policy's
//     forbidden error names the caller's `sub` claim, the quarantine's
//     names the route -- because the audit trail and the operator's log
//     need that. A caller gets a fixed, constant string per failure class
//     and nothing else. See errors.go.
//
// Per the ports & adapters split this project follows, the domain packages
// (internal/gateway, internal/access) contain no reference to HTTP; this
// package is where HTTP lives and it is deliberately thin -- it
// authenticates, it maps errors, and it delegates every decision that
// matters to the Gateway it was given.
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// MetadataPath is the well-known path of the OAuth 2.0 Protected Resource
// Metadata document (RFC 9728 section 3).
//
// When Config.Resource carries a path -- "https://gw.soc.internal/mcp" --
// RFC 9728 section 3.1 says the metadata lives at that path *appended* to
// the well-known prefix ("/.well-known/oauth-protected-resource/mcp"). This
// handler serves both that computed location and the bare prefix, because
// clients in the wild reach for either and the document is public discovery
// metadata: serving it twice costs nothing and reveals nothing.
const MetadataPath = "/.well-known/oauth-protected-resource"

// defaultServerName and defaultServerVersion identify this gateway to MCP
// clients in the initialize handshake when Config does not.
const (
	defaultServerName    = "mcp-gateway"
	defaultServerVersion = "0.0.0"
)

// Config carries everything the Handler needs. Gateway, Verifier, Policy,
// Resource and AuthorizationServers are required: like gateway.Config, this
// type holds no infrastructure of its own and cannot invent a safe default
// for a missing one. A missing port is a wiring bug at startup, and the
// alternative is discovering it during an incident.
type Config struct {
	// Gateway is the Gateway Endpoint whose tools are served. Its
	// ListTools/Dispatch pair is the only way this package reaches an
	// upstream, and it re-authorizes every dispatch independently of the
	// per-identity filtering done here (see [Handler.getServer]).
	Gateway *gateway.Gateway

	// Verifier turns a bearer token into an access.Identity. It is the only
	// thing that can authenticate a request. Required.
	Verifier access.TokenVerifier

	// Policy is the same access.Policy the Gateway holds.
	//
	// It is used here for one thing only: naming the caller's roles in the
	// operational log, so an operator reading "this analyst saw 4 tools" can
	// see which role produced that. It is NEVER the authorization decision
	// on this path -- that stays inside the Gateway, where ListTools and
	// Dispatch consult it in the same order. Duplicating the decision here
	// would be a second implementation of it, free to drift.
	Policy *access.Policy

	// Resource is this gateway's resource identifier: the absolute URI that
	// RFC 8707 resource indicators name and that RFC 9728 metadata
	// advertises, e.g. "https://gw.soc.internal/mcp".
	//
	// It should be the same value configured as the OIDC verifier's expected
	// audience. This package cannot check that -- Verifier is an opaque
	// interface by design -- so it is stated here as an operator's
	// obligation.
	Resource string

	// AuthorizationServers are the issuer identifiers of the IdP(s) that may
	// mint tokens for this resource, advertised in the metadata document so
	// a compliant client can discover where to get a token. At least one is
	// required: a 401 pointing at a metadata document that names no
	// authorization server sends the client nowhere.
	AuthorizationServers []string

	// ScopesSupported is optional and advertised as-is when non-empty.
	ScopesSupported []string

	// ServerName and ServerVersion identify this gateway to MCP clients in
	// the initialize handshake. Optional.
	ServerName    string
	ServerVersion string

	// Logger receives the operational detail the client is deliberately not
	// told: which token failed and why, which identity was refused which
	// tool, the Go error behind a 500. Optional; defaults to slog.Default().
	//
	// Nothing written here ever contains a bearer token.
	Logger *slog.Logger

	// AllowInsecureResourceURLs permits http:// (non-loopback) values in
	// Resource and AuthorizationServers.
	//
	// It exists for a deployment that terminates TLS somewhere this process
	// cannot see and still, wrongly, wants to advertise an http:// identity.
	// It is off by default because advertising an http:// resource
	// identifier is an instruction to clients to send bearer tokens in
	// cleartext. Loopback addresses are exempt without this flag, for local
	// development.
	AllowInsecureResourceURLs bool
}

// Handler serves MCP over streamable HTTP for authenticated callers, plus
// the unauthenticated RFC 9728 metadata document.
//
// It is safe for concurrent use and is meant to be long-lived: one per
// process, wrapped in whatever TLS-terminating server the deployment runs.
//
// # Routing
//
// Two GET/HEAD paths (see [MetadataPath]) serve the metadata document
// without authentication. Every other request -- any method, any path --
// goes through authentication and then to the MCP handler. That "everything
// else" default is deliberate: a path this handler does not recognise must
// not become an unauthenticated hole, so the safe answer to an unknown path
// is the authenticated one.
type Handler struct {
	gateway  *gateway.Gateway
	verifier access.TokenVerifier
	policy   *access.Policy
	log      *slog.Logger

	// metadata is the pre-rendered RFC 9728 document. Rendered once at
	// construction: it never varies by caller, and a document built per
	// request is a document that can be made to vary by caller.
	metadata []byte
	// metadataPaths are the paths metadata is served from, computed per RFC
	// 9728 section 3.1.
	metadataPaths []string
	// challenge is the single WWW-Authenticate value every 401 carries. See
	// [Handler.rejectUnauthenticated].
	challenge string

	// impl identifies this gateway in the MCP initialize handshake.
	impl *mcp.Implementation
	// mcpHandler is the SDK's streamable HTTP handler, in Stateless mode.
	mcpHandler http.Handler
}

var _ http.Handler = (*Handler)(nil)

// New validates cfg and returns a Handler ready to serve.
func New(cfg Config) (*Handler, error) {
	var missing []string
	if cfg.Gateway == nil {
		missing = append(missing, "Gateway")
	}
	if cfg.Verifier == nil {
		missing = append(missing, "Verifier")
	}
	if cfg.Policy == nil {
		missing = append(missing, "Policy")
	}
	if strings.TrimSpace(cfg.Resource) == "" {
		missing = append(missing, "Resource")
	}
	if len(cfg.AuthorizationServers) == 0 {
		missing = append(missing, "AuthorizationServers")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("httpapi: missing required config: %s", strings.Join(missing, ", "))
	}

	resource, err := resourceIdentifier(strings.TrimSpace(cfg.Resource), cfg.AllowInsecureResourceURLs)
	if err != nil {
		return nil, fmt.Errorf("httpapi: Resource: %w", err)
	}
	servers := make([]string, 0, len(cfg.AuthorizationServers))
	for _, raw := range cfg.AuthorizationServers {
		issuer, err := resourceIdentifier(strings.TrimSpace(raw), cfg.AllowInsecureResourceURLs)
		if err != nil {
			return nil, fmt.Errorf("httpapi: AuthorizationServers: %w", err)
		}
		servers = append(servers, issuer.String())
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	name := cfg.ServerName
	if strings.TrimSpace(name) == "" {
		name = defaultServerName
	}
	version := cfg.ServerVersion
	if strings.TrimSpace(version) == "" {
		version = defaultServerVersion
	}

	doc := protectedResourceMetadata{
		Resource:             resource.String(),
		AuthorizationServers: servers,
		ScopesSupported:      slices.Clone(cfg.ScopesSupported),
		// Declared explicitly, and it is not decoration: it tells a client,
		// in the discovery document itself, that this resource server reads
		// the credential from the header and will not look at a query
		// parameter or a form body (RFC 6750 sections 2.2 and 2.3).
		BearerMethodsSupported: []string{"header"},
	}
	rendered, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("httpapi: rendering protected resource metadata: %w", err)
	}

	h := &Handler{
		gateway:       cfg.Gateway,
		verifier:      cfg.Verifier,
		policy:        cfg.Policy,
		log:           logger,
		metadata:      rendered,
		metadataPaths: metadataPathsFor(resource),
		challenge:     challengeFor(resource),
		impl:          &mcp.Implementation{Name: name, Version: version},
	}

	// Stateless is required, not a preference.
	//
	// A stateless streamable handler neither reads nor sets Mcp-Session-Id
	// and builds a throwaway session per request. That removes the thing
	// design/adr/0008 forbids outright: a session identifier that, once
	// issued, would let a later request in without a token. Here there is no
	// such identifier -- getServer runs on every POST, off an Identity that
	// this handler verified for that POST, so a caller whose token expires
	// or whose role is revoked is refused by their next request rather than
	// by the end of a session that nobody bounded.
	//
	// The cost is real and accepted: no server->client requests, and GET and
	// DELETE return 405. Neither is needed to serve tools, and neither is
	// worth a credential-free code path.
	h.mcpHandler = mcp.NewStreamableHTTPHandler(h.getServer, &mcp.StreamableHTTPOptions{
		Stateless: true,
		Logger:    logger,
	})

	return h, nil
}

// ServeHTTP implements http.Handler.
//
// The order is the security property: metadata (public) is answered before
// anything else, then the request is authenticated, and only then is
// anything delegated to the MCP handler. Nothing below the authentication
// step runs for a caller this handler could not identify.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if slices.Contains(h.metadataPaths, r.URL.Path) {
		h.serveMetadata(w, r)
		return
	}

	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	// The caller's tool list is resolved here, before delegating, for two
	// reasons. It makes getServer total -- it cannot fail, so it never has
	// to decide what a failure should be served as. And it gives a broken
	// Tool Quarantine an honest HTTP status: gateway.ListTools fails the
	// whole call rather than returning a short list precisely so that "no
	// tools" and "the approval store is down" do not look the same to an
	// operator, and answering 200 with an empty list here would throw that
	// distinction away at the last hop.
	tools, err := h.gateway.ListTools(r.Context(), id)
	if err != nil {
		h.fail(w, r, id, "listing tools for caller", err)
		return
	}

	h.log.DebugContext(r.Context(), "httpapi: authenticated request",
		slog.String("subject", id.Subject),
		slog.Any("roles", roleNames(h.policy, id)),
		slog.Int("tools", len(tools)),
	)

	ctx := context.WithValue(r.Context(), callerContextKey{}, &caller{identity: id, tools: tools})
	h.mcpHandler.ServeHTTP(w, r.WithContext(ctx))
}

// ---------------------------------------------------------- authentication

// authenticate reads and verifies the request's bearer credential. On
// failure it has already written the 401 response and reports false.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (access.Identity, bool) {
	// Warn -- loudly, and without ever touching the value -- when a client
	// puts a credential in the URL. It is ignored either way (nothing below
	// reads the query string), but a SOC wants to know that a token has
	// probably just been written to every access log between here and the
	// analyst's browser, so it can be revoked.
	if credentialInQuery(r.URL) {
		h.log.WarnContext(r.Context(), "httpapi: credential offered in query string; ignored, and it should be treated as compromised",
			slog.String("path", r.URL.Path),
		)
	}

	token, ok := bearerToken(r.Header)
	if !ok {
		h.rejectUnauthenticated(w, r, "no usable Authorization: Bearer credential", nil)
		return access.Identity{}, false
	}

	id, err := h.verifier.Verify(r.Context(), token)
	if err != nil {
		h.rejectUnauthenticated(w, r, "token verification failed", err)
		return access.Identity{}, false
	}
	if strings.TrimSpace(id.Subject) == "" {
		// access.TokenVerifier's contract already requires a subject, and
		// the oidc adapter enforces it. This is the belt to those braces: an
		// Identity with no Subject would produce audit records attributed to
		// nobody, which is the one thing this gateway exists to prevent.
		h.rejectUnauthenticated(w, r, "verifier returned an identity with no subject", nil)
		return access.Identity{}, false
	}

	return id, true
}

// bearerToken extracts the credential from `Authorization: Bearer <token>`.
//
// # What is accepted
//
// Exactly one Authorization header, whose scheme is "Bearer" compared
// case-insensitively (RFC 7235 section 2.1 makes the auth-scheme
// case-insensitive, and this project follows the RFC: rejecting `bearer`
// buys no security, since the token still has to verify, and costs
// interoperability with clients that lowercase it). Between the scheme and
// the token, one or more spaces or tabs, per RFC 7235's BWS. The token
// itself is an RFC 6750 b64token and so contains no whitespace.
//
// # What is not
//
//   - More than one Authorization header. Two credentials in one request is
//     ambiguous, and "pick one" is how a request smuggled past a proxy that
//     inspected the *other* one gets authenticated.
//   - Any other scheme -- Basic, Negotiate, a bare token with no scheme.
//   - A token containing whitespace, which is not a b64token and would mean
//     this function had to guess where the credential ended.
//   - A query parameter, a cookie, a custom header, or a request body. This
//     function is given only the header set and reads only that one field;
//     there is no fallback here because a fallback is precisely how a
//     credential ends up in a URL.
func bearerToken(header http.Header) (string, bool) {
	values := header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	scheme, rest, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token := strings.TrimLeft(rest, " \t")
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}

// credentialInQuery reports whether the URL carries something that looks
// like a credential, so it can be logged as an incident. The names are the
// ones OAuth 2.0 deployments have historically (and wrongly) used.
//
// The *value* is never read, never logged and never used.
func credentialInQuery(u *url.URL) bool {
	q := u.Query()
	for _, name := range []string{"access_token", "token", "bearer_token", "api_key", "apikey"} {
		if q.Has(name) {
			return true
		}
	}
	return false
}

// rejectUnauthenticated writes the one 401 this handler ever writes.
//
// Body and headers are byte-identical for every cause -- no header at all,
// the wrong scheme, a garbage token, an expired token, an unreachable IdP.
// That is the same discipline internal/access/oidc applies to its own error
// text, and for the same reason: a caller who can tell "no credential" from
// "expired" from "wrong audience" has an oracle, and the answer it gives is
// worth more to an attacker than to any legitimate client.
//
// In particular the WWW-Authenticate value carries no `error` parameter.
// RFC 6750 section 3.1 makes it optional and says it SHOULD be omitted when
// the request carried no credential; omitting it always is the only choice
// under which the challenge cannot be used to classify the failure. What it
// does carry is `resource_metadata` (RFC 9728 section 5.1), which is what a
// compliant client actually needs: where to go to get a token.
func (h *Handler) rejectUnauthenticated(w http.ResponseWriter, r *http.Request, reason string, cause error) {
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("path", r.URL.Path),
	}
	if cause != nil {
		// The verifier's own error is already uniform and token-free (see
		// oidc.Verifier); logging it adds the operator-facing detail without
		// putting a credential anywhere.
		attrs = append(attrs, slog.String("detail", cause.Error()))
	}
	h.log.LogAttrs(r.Context(), slog.LevelWarn, "httpapi: rejected request", attrs...)

	w.Header().Set("WWW-Authenticate", h.challenge)
	writeGeneric(w, classUnauthenticated)
}

// fail writes the generic response for an internal failure and logs the
// real one.
//
// The split is the whole point: the caller gets a fixed string chosen only
// by the failure's class, and the operator gets the error text, the
// identity and what was being attempted.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, id access.Identity, doing string, err error) {
	class := classify(err)
	h.log.LogAttrs(r.Context(), slog.LevelError, "httpapi: request failed",
		slog.String("subject", id.Subject),
		slog.String("doing", doing),
		slog.String("class", class.String()),
		slog.String("detail", err.Error()),
	)
	writeGeneric(w, class)
}

// ------------------------------------------------------------- MCP surface

// callerContextKey is the (unexported, and therefore unforgeable from
// outside this package) key under which ServeHTTP stashes what it resolved
// about the request.
type callerContextKey struct{}

// caller is everything ServeHTTP established about one authenticated
// request: who is asking, and exactly which tools they may see.
type caller struct {
	identity access.Identity
	tools    []gateway.ToolDef
}

// getServer builds the *mcp.Server for one already-authenticated request.
//
// # Per-identity exposure
//
// Only the tools gateway.ListTools returned for this identity are
// registered. A tool the caller may not use is not on their server at all,
// so it can be neither listed nor called: the filtering is a property of
// the object they are talking to, not a check somebody has to remember to
// write. Each registered handler still calls gateway.Dispatch, which
// re-authorizes and re-checks Tool Quarantine. That redundancy is deliberate
// defence in depth and must not be optimized away -- the list was true when
// it was built, and a call arrives later.
//
// # The unreachable path
//
// ServeHTTP installs the caller in the context before it delegates, and it
// is the only thing that calls this. If the value is somehow absent -- a
// future refactor that delegates from somewhere else, an SDK change -- the
// answer is an empty server, never a permissive one. A caller we cannot
// identify gets a working MCP session with nothing in it.
func (h *Handler) getServer(r *http.Request) *mcp.Server {
	srv := mcp.NewServer(h.impl, &mcp.ServerOptions{Logger: h.log})

	c, ok := r.Context().Value(callerContextKey{}).(*caller)
	if !ok || c == nil {
		h.log.ErrorContext(r.Context(), "httpapi: no verified identity on an authenticated path; serving an empty server",
			slog.String("path", r.URL.Path),
		)
		return srv
	}

	for _, def := range c.tools {
		schema, ok := objectSchema(def.InputSchema)
		if !ok {
			// mcp.Server.AddTool panics on a nil or non-object input schema,
			// and the schema is upstream-controlled data that reached us
			// through gateway.ToolDef. Skipping the tool -- rather than
			// substituting a permissive schema, which would advertise
			// something other than what Tool Quarantine approved -- is the
			// fail-closed reading, and it keeps a malformed backend from
			// taking the process down.
			h.log.ErrorContext(r.Context(), "httpapi: tool not served: input schema is not a JSON object",
				slog.String("tool", def.Name),
			)
			continue
		}
		srv.AddTool(&mcp.Tool{
			Name: def.Name,
			// Description and schema are re-advertised exactly as the
			// upstream wrote them and Tool Quarantine fingerprinted them
			// (design/adr/0007): no rewriting, no sanitizing. A description
			// this gateway silently edited would be a description no human
			// reviewing the quarantine ever saw.
			Description: def.Description,
			InputSchema: schema,
		}, h.dispatchTool(c.identity, def.Name))
	}
	return srv
}

// dispatchTool returns the handler registered for one namespaced tool: it
// forwards to gateway.Dispatch and translates the outcome.
//
// The identity is captured from the request that built this server, not
// read from anywhere at call time, so a handler cannot be induced to
// dispatch as somebody else.
func (h *Handler) dispatchTool(id access.Identity, namespaced string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args json.RawMessage
		if req != nil && req.Params != nil {
			// Forwarded as raw JSON, unexamined: json.RawMessage marshals to
			// itself, so the bytes the client sent are the bytes the upstream
			// sees. Validating them here would mean a second, divergent
			// opinion about the schema the upstream already publishes.
			args = req.Params.Arguments
		}

		res, err := h.gateway.Dispatch(ctx, id, namespaced, args)
		if err != nil {
			return nil, h.rejectCall(ctx, id, namespaced, err)
		}

		out, err := toCallToolResult(res)
		if err != nil {
			return nil, h.rejectCall(ctx, id, namespaced,
				fmt.Errorf("upstream result is not representable: %w", err))
		}
		return out, nil
	}
}

// rejectCall logs the real reason a dispatch failed and returns the
// sanitized JSON-RPC error the client receives.
func (h *Handler) rejectCall(ctx context.Context, id access.Identity, tool string, err error) error {
	class := classify(err)
	h.log.LogAttrs(ctx, slog.LevelWarn, "httpapi: tool call refused",
		slog.String("subject", id.Subject),
		slog.String("tool", tool),
		slog.String("class", class.String()),
		slog.String("detail", err.Error()),
	)
	return jsonRPCError(class, tool)
}

// toCallToolResult converts an upstream result into the SDK's shape.
//
// It goes through the SDK's own CallToolResult.UnmarshalJSON rather than
// reconstructing content blocks by hand: gateway.Result.Content is the raw
// content array the upstream produced, and re-deriving typed blocks here
// would be a second, divergent decoder for attacker-adjacent data.
//
// Known and accepted limitation: a content block of a type this SDK does
// not know fails to decode, and the call is refused with the generic
// internal error rather than forwarded. That is fail-closed and visible in
// the log; forwarding an opaque blob would mean this gateway passing
// through content it could not name.
func toCallToolResult(res gateway.Result) (*mcp.CallToolResult, error) {
	content := res.Content
	if len(content) == 0 {
		// Never a literal null: clients treat content as an array.
		content = json.RawMessage("[]")
	}

	// Marshal first so invalid JSON from an upstream is caught here, with
	// the error naming nothing but "not representable".
	payload, err := json.Marshal(struct {
		Content json.RawMessage `json:"content"`
		IsError bool            `json:"isError"`
	}{Content: content, IsError: res.IsError})
	if err != nil {
		return nil, err
	}

	var out mcp.CallToolResult
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// objectSchema returns raw as an input schema the SDK will accept, and
// reports whether it is one.
//
// The check mirrors mcp.Server.AddTool's own precondition (a JSON object
// whose "type" is "object"), performed here so a violation is a skipped
// tool and a log line rather than a panic in the request path. The bytes
// returned are the caller's own, unaltered -- json.RawMessage marshals to
// itself, so what the client is shown is what the quarantine hashed.
func objectSchema(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, false
	}
	if typ, _ := probe["type"].(string); typ != "object" {
		return nil, false
	}
	return raw, true
}

// roleNames resolves the caller's role names for the log line. It is
// diagnostic only; see Config.Policy.
func roleNames(p *access.Policy, id access.Identity) []string {
	roles := p.RolesFor(id)
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	return names
}

// ------------------------------------------------------------- RFC 9728

// protectedResourceMetadata is the OAuth 2.0 Protected Resource Metadata
// document of RFC 9728 section 2, limited to the fields this gateway can
// state truthfully.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// serveMetadata answers the RFC 9728 discovery document.
//
// It is unauthenticated by design, and that is not an omission: the whole
// point of the document is to tell a client that has *no* token where to
// get one, so requiring a token to read it would be circular. It contains
// no secret -- an issuer URL and this gateway's own identifier, both of
// which any client that can reach this port already knows or is about to be
// told by the 401 it would otherwise get.
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// RFC 9110 section 15.5.6: a 405 MUST carry Allow.
		w.Header().Set("Allow", "GET, HEAD")
		writeGeneric(w, classMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The document is static for the life of the process; letting clients
	// cache it keeps discovery from becoming per-request traffic.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	// net/http discards the body for HEAD, so this one path serves both.
	_, _ = w.Write(h.metadata)
}

// resourceIdentifier parses and validates a resource or issuer identifier.
//
// RFC 9728 section 2 and RFC 8707 section 2 both require an absolute URI
// with no fragment. This adds one rule of its own: the scheme must be https
// unless the host is a loopback address (or the operator has explicitly
// opted out). A resource identifier advertised over http:// is an
// instruction to every client that reads it to put a bearer token on the
// wire in cleartext.
func resourceIdentifier(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid URI", raw)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("%q must be an absolute URI with a host", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%q must not carry a fragment (RFC 9728 section 2)", raw)
	}
	if u.RawQuery != "" {
		return nil, fmt.Errorf("%q must not carry a query string", raw)
	}
	if u.Scheme != "https" && !allowInsecure && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("%q must use https: an http resource identifier tells clients to send bearer tokens in cleartext (set AllowInsecureResourceURLs to override)", raw)
	}
	return u, nil
}

// isLoopbackHost reports whether host names the local machine, the one case
// where http:// is not a credential-on-the-wire problem.
func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

// metadataPathsFor returns the paths the metadata document is served from:
// the RFC 9728 section 3.1 location for a resource with a path, and the
// bare well-known path.
func metadataPathsFor(resource *url.URL) []string {
	paths := []string{MetadataPath}
	if p := strings.TrimSuffix(resource.Path, "/"); p != "" && p != "/" {
		paths = append(paths, MetadataPath+p)
	}
	return paths
}

// challengeFor builds the constant WWW-Authenticate value, whose
// resource_metadata parameter points a compliant client at the document
// above (RFC 9728 section 5.1).
func challengeFor(resource *url.URL) string {
	metadataURL := *resource
	metadataURL.Path = MetadataPath + strings.TrimSuffix(resource.Path, "/")
	metadataURL.RawQuery = ""
	metadataURL.Fragment = ""
	return fmt.Sprintf("Bearer resource_metadata=%q", metadataURL.String())
}
