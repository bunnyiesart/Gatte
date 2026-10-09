package resthttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// ErrInvalidOperations is returned, wrapped with a description of which
// rule failed, by every function here that refuses an operation set. One
// sentinel for the whole family, like registry.ErrInvalid: the console asks
// "is this entry servable?" and does not need to tell a bad path from a bad
// header name to answer it; the wrapped text tells the operator which.
var ErrInvalidOperations = errors.New("resthttp: invalid operation set")

// The property-name prefixes that carry a parameter's LOCATION
// (ADR-0047 §3, "namespacing"). OpenAPI identifies a parameter by the pair
// (name, in); a flat object would collide `id` in the path with `id` in the
// query, so the location is part of the property name and CallTool reads
// it back from the prefix. BodyProperty is the one non-prefixed name: the
// request body is a single dedicated property (ADR-0048 Decisão 4 -- not a
// `body_*` family, because oneOf/anyOf bodies must keep their alternation
// under one property rather than be spread as top-level siblings).
//
// Any property name outside this vocabulary is refused by Validate, so the
// adapter never has to guess where an argument goes.
const (
	PrefixPath   = "path_"
	PrefixQuery  = "query_"
	PrefixHeader = "header_"
	PrefixCookie = "cookie_"
	BodyProperty = "body"
)

// The credential-injection kinds, as registry.AuthKind spells them
// (internal/registry/registry.go:76-90). Copied rather than imported: this
// adapter depends on gateway.* and vault.Provider only, and gateway.
// UpstreamSpec carries the kind as a plain string. TestAuthKindsMatchTheRegistry
// pins the spelling to the registry's, so the copy cannot drift silently.
const (
	AuthNone   = ""
	AuthBearer = "bearer"
	AuthHeader = "header"
	AuthQuery  = "query"
)

// authorizationHeader is the fixed header AuthBearer injects into, and the
// header a bearer entry therefore reserves (ADR-0047 §3, "servidor-vence").
const authorizationHeader = "authorization"

// maxPathLen bounds a path template. 2048 is past any real API path and
// keeps a hostile spec from storing megabytes of template per operation.
const maxPathLen = 2048

// Operation is one REST operation of a registered http upstream: the
// method and path template the adapter calls, and the tool the gateway
// advertises for it. It is the unit the frozen set is made of
// (registry.UpstreamServer.Operations), one per generated tool.
//
// There is deliberately no Class field. The security class is ClassOf
// (Method): the method is inside the signed bytes, so the class is covered
// by the ADR-0048 Decisão 2 digest without a second, writable field that
// could say "safe" over a POST.
type Operation struct {
	// Name is the tool name, as gateway.ValidToolName accepts it, unique
	// within the set. Not namespaced: the gateway prefixes the upstream.
	Name string `json:"name"`
	// Description is what the tool is said to do; it reaches the model as
	// operational context and is in the quarantine fingerprint.
	Description string `json:"description,omitempty"`
	// Method is the HTTP method, upper-case, one of ValidMethod's set.
	Method string `json:"method"`
	// Path is the path template, relative to the signed base URL: a single
	// leading "/", literal segments and {name} templates, nothing else --
	// see ParsePath for what is refused and why.
	Path string `json:"path"`
	// InputSchema is a JSON Schema object with type "object" whose
	// properties are all named by location (PrefixPath, PrefixQuery,
	// PrefixHeader, PrefixCookie or BodyProperty). Decode and Encode hand it
	// back in canonical bytes: keys sorted, no insignificant whitespace, no
	// HTML escaping -- so the quarantine fingerprint over it does not depend
	// on how the stored blob was formatted.
	InputSchema json.RawMessage `json:"inputSchema"`
	// OutputSchema is the optional schema for the result's structuredContent
	// (gateway.ToolDef.OutputSchema); nil when none. Canonical like
	// InputSchema when present.
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
}

// ToolDef is the gateway's view of this operation: the single producer of
// a REST tool definition, so ListTools and the OpenAPI ingestion advertise
// exactly the same name, description, schemas and class.
//
// Post-condition: SecurityClass is ClassOf(op.Method); the schemas are the
// operation's bytes, shared not copied (the gateway treats them as
// read-only, as it does the stdio adapter's).
func (op Operation) ToolDef() gateway.ToolDef {
	return gateway.ToolDef{
		Name:          op.Name,
		Description:   op.Description,
		InputSchema:   op.InputSchema,
		OutputSchema:  op.OutputSchema,
		SecurityClass: ClassOf(op.Method),
	}
}

// ClassOf is the one rule that turns an HTTP method into a security class
// (ADR-0048 Decisão 5): GET, HEAD and OPTIONS -- the methods RFC 9110 §9.2.1
// defines as safe -- are quarantine.ClassSafe; everything else, including a
// method this package does not serve, is quarantine.ClassSensitive. Fail
// closed on the unknown: a class is a permission, and an unrecognised
// method is not evidence that it only reads.
//
// Pre-condition: none; method is compared as given (case-sensitive, because
// Validate already requires upper case and a lower-case "get" in a signed
// set is a set this package refuses, not one it should quietly accept).
func ClassOf(method string) quarantine.Class {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return quarantine.ClassSafe
	default:
		return quarantine.ClassSensitive
	}
}

// ValidMethod reports whether method is one this adapter sends: the seven
// of RFC 9110 §9.3 that a REST API exposes, upper-case. CONNECT and TRACE
// are out on purpose -- the first opens a tunnel, the second echoes the
// request (headers included, so the injected credential) -- and so is
// anything an OpenAPI document could spell that the adapter does not know
// how to classify.
func ValidMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// tokenChars is the grammar of an HTTP token (RFC 9110 §5.6.2): the only
// shape a header or cookie name the adapter will SEND may have. It is a
// copy of registry.authNameChars (internal/registry/registry.go:444), which
// is unexported and which this adapter must not import the package of; the
// two guard the same thing from the two ends -- the registry the name the
// credential goes into, this file every other name the spec declares --
// and the regexp is small enough that a copy is clearer than a new export.
var tokenChars = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)

// ValidToken reports whether name is a well-formed HTTP token: non-empty,
// no whitespace, control bytes or delimiters. A name that fails this could
// carry a second header or a request-splitting sequence into the wire.
func ValidToken(name string) bool {
	return tokenChars.MatchString(name)
}

// controlHeaders is the denylist of ADR-0048 Decisão 6: headers a
// parameter may never set, compared case-insensitively, because the
// transport or the proxy in front of the API owns them. Setting Host or
// Content-Length from a tool argument is request smuggling; Connection,
// Upgrade, TE, Trailer, Transfer-Encoding and Keep-Alive are hop-by-hop
// (RFC 9110 §7.6.1) and rewrite how the connection itself behaves;
// Authorization and Cookie are the credential's own channels, reserved
// whatever the auth kind (a keyless entry must not be turned into a keyed
// one by a caller supplying header_authorization). Proxy-* is a prefix,
// covering Proxy-Authorization, Proxy-Connection and whatever else a
// proxy honours.
var controlHeaders = map[string]bool{
	"host":              true,
	"content-length":    true,
	"transfer-encoding": true,
	"connection":        true,
	"upgrade":           true,
	"te":                true,
	"trailer":           true,
	"keep-alive":        true,
	"authorization":     true,
	"cookie":            true,
}

// IsControlHeader reports whether name (any case, "_" read as "-") is one
// a parameter may not set -- see controlHeaders and foldHeader.
func IsControlHeader(name string) bool {
	folded := foldHeader(name)
	return controlHeaders[folded] || strings.HasPrefix(folded, "proxy-")
}

// foldHeader is the one equivalence under which two header names are "the
// same" for the denylist, the reserved auth slot and the duplicate check:
// lower-cased, with "_" read as "-". Case because RFC 9110 §5.1 says so;
// the underscore because of where the names end up. On the wire X_API_Key
// and X-API-Key are distinct fields, but a CGI, WSGI, Rack or PHP backend
// receives both as HTTP_X_API_KEY and then concatenates or overwrites one
// with the other -- so a declared header_x_api_key beside an injected
// X-API-Key would let the caller reach the credential's slot on exactly the
// servers where "server-wins" (ADR-0047 §3) is supposed to hold. The token
// grammar admits "_", so the fold is applied at every comparison instead of
// refusing the character (nginx drops underscored headers by default, which
// is the server's choice, not a reason to reject a spec here).
func foldHeader(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// templateNameChars is the grammar of the x in a {x} path template, which
// is also the suffix of the path_x property that fills it.
var templateNameChars = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ParsePath checks a path template and returns the names of its {x}
// templates in order of appearance.
//
// What it refuses, and why (ADR-0048 Decisão 6, "Operation.Path é derivado
// da URL assinada"): the template is later joined onto the signed base URL,
// so anything that could make the joined URL reach somewhere else is an
// SSRF hidden inside signed bytes.
//
//   - Not exactly one leading "/": a scheme ("https://evil.tld/x") or an
//     authority ("//evil.tld/x") would replace the base, and a relative
//     path has no fixed meaning.
//   - "//" anywhere, and the segments "." and "..": path normalisation on
//     the far side could climb above the base path the entry signed. A
//     segment that is "." or ".." BEFORE its first ";" is refused for the
//     same reason: servlet containers (Tomcat, Jetty) strip path parameters
//     ("..;x") before they normalise, so "/api/..;/admin" reaches "/admin".
//   - "?" and "#": the query and fragment are built by the adapter from
//     query_* arguments and the auth descriptor; a template must not
//     pre-load them.
//   - "%": a percent-escape in a template ("%2F", "%2e%2e") is a second
//     spelling of the characters above, which the checks here could not
//     see through.
//   - Space, control bytes (CR/LF included), non-ASCII and the RFC 3986
//     characters outside pchar: nothing a request line may carry raw.
//   - A "{" without its "}", a nested or empty template, a template name
//     outside [A-Za-z0-9_.-], or the same name twice.
//
// Pre-condition: none. Post-condition: on nil error the returned names are
// unique and every byte of path is either "/" or a pchar, so url.URL can
// carry it as Path without re-encoding surprises.
func ParsePath(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path must not be empty", ErrInvalidOperations)
	}
	if len(path) > maxPathLen {
		return nil, fmt.Errorf("%w: path is %d bytes, over the %d-byte limit", ErrInvalidOperations, len(path), maxPathLen)
	}
	if path[0] != '/' {
		return nil, fmt.Errorf("%w: path %q must begin with exactly one \"/\" (no scheme, no authority, not relative): it is joined onto the signed base URL", ErrInvalidOperations, path)
	}
	if strings.Contains(path, "//") {
		return nil, fmt.Errorf("%w: path %q contains \"//\": an empty segment is an authority at the start and a normalisation hazard anywhere else", ErrInvalidOperations, path)
	}

	var names []string
	seen := map[string]bool{}
	for i := 0; i < len(path); {
		c := path[i]
		switch {
		case c == '{':
			end := strings.IndexByte(path[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("%w: path %q has an unterminated template at offset %d", ErrInvalidOperations, path, i)
			}
			name := path[i+1 : i+end]
			if strings.ContainsAny(name, "{/") {
				return nil, fmt.Errorf("%w: path %q has a nested or slash-containing template at offset %d", ErrInvalidOperations, path, i)
			}
			if !templateNameChars.MatchString(name) {
				return nil, fmt.Errorf("%w: path %q template name %q must be non-empty and use only [A-Za-z0-9_.-]", ErrInvalidOperations, path, name)
			}
			if seen[name] {
				return nil, fmt.Errorf("%w: path %q uses template {%s} twice", ErrInvalidOperations, path, name)
			}
			seen[name] = true
			names = append(names, name)
			i += end + 1
		case c == '}':
			return nil, fmt.Errorf("%w: path %q has a \"}\" without a template at offset %d", ErrInvalidOperations, path, i)
		case c == '?' || c == '#':
			return nil, fmt.Errorf("%w: path %q contains %q at offset %d: the query and fragment are built by the adapter, never carried by a template", ErrInvalidOperations, path, string(c), i)
		case c == '%':
			return nil, fmt.Errorf("%w: path %q contains a percent-escape at offset %d; a template is spelled literally so that what is checked is what is sent", ErrInvalidOperations, path, i)
		case !isPathChar(c):
			return nil, fmt.Errorf("%w: path %q contains byte %q at offset %d, outside the characters a path may carry raw (no spaces, control bytes or non-ASCII)", ErrInvalidOperations, path, string(c), i)
		default:
			i++
		}
	}

	for _, seg := range strings.Split(path[1:], "/") {
		// The part before ";" is what a container that strips path
		// parameters normalises; judging the whole segment would let "..;"
		// through as "not ..".
		head, _, _ := strings.Cut(seg, ";")
		if head == "." || head == ".." {
			return nil, fmt.Errorf("%w: path %q has a %q segment: dot segments can climb above the signed base path", ErrInvalidOperations, path, seg)
		}
	}
	return names, nil
}

// isPathChar is RFC 3986 pchar minus pct-encoded, plus "/": unreserved,
// sub-delims, ":" and "@".
func isPathChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/':
		return true
	}
	return false
}

// Decode parses the frozen operation set of an http entry
// (registry.UpstreamServer.Operations, gateway.UpstreamSpec.Operations) and
// validates it against the entry's credential-injection descriptor. It is
// what the adapter runs at dial time and what the operator console runs at
// register/sign time, so an entry the gateway would refuse to serve is
// refused where it is written.
//
// The bytes are expected in the form Encode produces -- a JSON array ordered
// by Name -- but any JSON formatting of that form is accepted; the schemas
// come back canonical regardless. What is NOT accepted, besides every rule
// of Validate:
//
//   - a key this version does not know on an operation: an unknown key
//     would be dropped on re-encode, and the set served would then differ
//     from the set signed;
//   - names out of ascending order: ADR-0048 Decisão 4 fixes the order so
//     one set has one digest.
//
// Pre-condition: authKind and authName are the entry's descriptor as the
// registry validated it. Post-condition: on nil error the slice is
// non-empty, sorted by Name, and Validate(ops, authKind, authName) is nil.
func Decode(operations []byte, authKind, authName string) ([]Operation, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(operations, &raws); err != nil {
		return nil, fmt.Errorf("%w: operations is not a JSON array: %v", ErrInvalidOperations, err)
	}
	ops := make([]Operation, 0, len(raws))
	for i, raw := range raws {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var op Operation
		if err := dec.Decode(&op); err != nil {
			return nil, fmt.Errorf("%w: operation %d: %v", ErrInvalidOperations, i, err)
		}
		if i > 0 && op.Name <= ops[i-1].Name {
			if op.Name == ops[i-1].Name {
				return nil, fmt.Errorf("%w: operation name %q appears twice", ErrInvalidOperations, op.Name)
			}
			return nil, fmt.Errorf("%w: operations are not ordered by name (%q after %q); the frozen set is sorted so one set has one digest", ErrInvalidOperations, op.Name, ops[i-1].Name)
		}
		ops = append(ops, op)
	}
	if err := Validate(ops, authKind, authName); err != nil {
		return nil, err
	}
	for i := range ops {
		// Validate already parsed both schemas, so canonicalize cannot fail
		// here; the error path is kept rather than ignored on principle.
		var err error
		if ops[i].InputSchema, err = canonicalize(ops[i].InputSchema); err != nil {
			return nil, fmt.Errorf("%w: operation %q: input schema: %v", ErrInvalidOperations, ops[i].Name, err)
		}
		if len(ops[i].OutputSchema) != 0 {
			if ops[i].OutputSchema, err = canonicalize(ops[i].OutputSchema); err != nil {
				return nil, fmt.Errorf("%w: operation %q: output schema: %v", ErrInvalidOperations, ops[i].Name, err)
			}
		} else {
			ops[i].OutputSchema = nil
		}
	}
	return ops, nil
}

// Encode produces the canonical bytes of an operation set: a JSON array
// ordered by Name, each operation an object with keys in lexicographic
// order, each schema canonical (keys sorted, compact, numbers as written,
// no HTML escaping), no insignificant whitespace. These are the bytes the
// registry stores and the signer digests (ADR-0048 Decisão 2, 4), so the
// form is fixed here and nowhere else; Encode(Decode(Encode(x))) is
// Encode(x) byte for byte (TestRoundTrip_EncodeDecodeEncodeIsStable).
//
// Encode does NOT run Validate -- it has no auth descriptor to validate
// against -- and the OpenAPI ingestion calls Validate before it. Bytes that
// skipped it are not served: Decode runs Validate at dial time.
//
// Pre-condition: names are unique (duplicates are refused, because a sort
// with duplicates has no single canonical order) and every schema is valid
// JSON. ops is not modified; a sorted copy is encoded.
func Encode(ops []Operation) ([]byte, error) {
	sorted := make([]Operation, len(ops))
	copy(sorted, ops)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	items := make([]map[string]any, 0, len(sorted))
	for i, op := range sorted {
		if i > 0 && op.Name == sorted[i-1].Name {
			return nil, fmt.Errorf("%w: operation name %q appears twice", ErrInvalidOperations, op.Name)
		}
		in, err := canonicalize(op.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("%w: operation %q: input schema: %v", ErrInvalidOperations, op.Name, err)
		}
		item := map[string]any{
			"name":        op.Name,
			"method":      op.Method,
			"path":        op.Path,
			"inputSchema": in,
		}
		if op.Description != "" {
			item["description"] = op.Description
		}
		if len(op.OutputSchema) != 0 {
			out, err := canonicalize(op.OutputSchema)
			if err != nil {
				return nil, fmt.Errorf("%w: operation %q: output schema: %v", ErrInvalidOperations, op.Name, err)
			}
			item["outputSchema"] = out
		}
		items = append(items, item)
	}
	return marshalCanonical(items)
}

// Validate applies every fail-closed rule of ADR-0047 §3 and ADR-0048
// Decisão 6 to an operation set against the entry's auth descriptor. It
// is the full check -- the console can call it without dialing -- and it
// refuses, in this order per operation:
//
//   - a Name that fails gateway.ValidToolName, or that another operation
//     already uses;
//   - a Method outside ValidMethod (upper-case GET/HEAD/OPTIONS/POST/PUT/
//     PATCH/DELETE);
//   - a Path that ParsePath refuses;
//   - an InputSchema that is not a JSON object with "type":"object", or
//     whose "properties" is not an object of object-valued schemas, or
//     whose "required" names a property that is not declared;
//   - a property outside the location vocabulary (PrefixPath, PrefixQuery,
//     PrefixHeader, PrefixCookie, BodyProperty), or with an empty suffix;
//   - a path_x with no {x} in the template, or a {x} with no path_x;
//   - a header_* or cookie_* suffix that is not an HTTP token, or that
//     repeats another one case-insensitively (for headers, with "_" and "-"
//     read as the same character -- foldHeader says why);
//   - a header_* that IsControlHeader, or that names the injection slot
//     (Authorization for bearer, authName for header) in any case or with
//     "_" for "-";
//   - a query_* with a non-printable or non-ASCII byte, or that names the
//     injection slot for a query credential (compared case-insensitively
//     too: some servers fold query names, and the credential must win
//     whatever the server does);
//   - a body on GET, HEAD or OPTIONS, whose semantics RFC 9110 §9.3.1
//     leaves undefined and which the adapter would otherwise send.
//
// The auth descriptor itself is checked first (kind known; bearer with no
// name; header/query with a token name), because every slot rule below
// reads it.
//
// Pre-condition: none. Post-condition: nil means Decode would serve this
// set and CallTool can place every declared argument without guessing.
func Validate(ops []Operation, authKind, authName string) error {
	reservedHeader, reservedQuery, err := reservedSlots(authKind, authName)
	if err != nil {
		return err
	}
	if len(ops) == 0 {
		return fmt.Errorf("%w: an http entry must serve at least one operation", ErrInvalidOperations)
	}

	names := map[string]bool{}
	for _, op := range ops {
		if !gateway.ValidToolName(op.Name) {
			return fmt.Errorf("%w: operation name %q is not a legal tool name (1-%d bytes of [A-Za-z0-9_-])", ErrInvalidOperations, op.Name, gateway.MaxToolNameLen)
		}
		if names[op.Name] {
			return fmt.Errorf("%w: operation name %q appears twice", ErrInvalidOperations, op.Name)
		}
		names[op.Name] = true

		if !ValidMethod(op.Method) {
			return fmt.Errorf("%w: operation %q: method %q is not one of GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE (upper-case)", ErrInvalidOperations, op.Name, op.Method)
		}
		templates, err := ParsePath(op.Path)
		if err != nil {
			return fmt.Errorf("%w: operation %q: %s", ErrInvalidOperations, op.Name, detail(err))
		}
		if err := validateInputSchema(op, templates, reservedHeader, reservedQuery); err != nil {
			return fmt.Errorf("%w: operation %q: %v", ErrInvalidOperations, op.Name, err)
		}
		if len(op.OutputSchema) != 0 {
			if _, err := decodeObject(op.OutputSchema); err != nil {
				return fmt.Errorf("%w: operation %q: output schema %v", ErrInvalidOperations, op.Name, err)
			}
		}
	}
	return nil
}

// reservedSlots translates the auth descriptor into the names a parameter
// may not use: the folded header (foldHeader) for bearer/header, the
// lower-cased query parameter for query. Empty when nothing is reserved.
func reservedSlots(authKind, authName string) (header, query string, err error) {
	switch authKind {
	case AuthNone:
		if authName != "" {
			return "", "", fmt.Errorf("%w: auth kind is empty (keyless) but auth name %q is set", ErrInvalidOperations, authName)
		}
		return "", "", nil
	case AuthBearer:
		if authName != "" {
			return "", "", fmt.Errorf("%w: auth kind %q injects a fixed Authorization header, so auth name must be empty", ErrInvalidOperations, authKind)
		}
		return authorizationHeader, "", nil
	case AuthHeader, AuthQuery:
		if !ValidToken(authName) {
			return "", "", fmt.Errorf("%w: auth kind %q needs an HTTP-token auth name; got %q", ErrInvalidOperations, authKind, authName)
		}
		if authKind == AuthHeader {
			// The denylist a parameter is held to holds for the injection
			// slot too: a Host, Content-Length or Transfer-Encoding is
			// dropped by net/http when the request is written (the secret
			// never leaves, and the 401 has no explanation), and Connection,
			// Upgrade, TE, Trailer or Proxy-* is hop-by-hop, which a proxy in
			// front of the API strips. A derived descriptor (securitySchemes)
			// could otherwise choose one the same spec could not name as a
			// parameter. Authorization is the exception: "Authorization:
			// <token>" without the Bearer prefix is what -auth-kind header
			// exists for on more than one real API.
			if IsControlHeader(authName) && foldHeader(authName) != authorizationHeader {
				return "", "", fmt.Errorf("%w: auth name %q is a control header; the credential cannot be injected there", ErrInvalidOperations, authName)
			}
			return foldHeader(authName), "", nil
		}
		return "", strings.ToLower(authName), nil
	default:
		return "", "", fmt.Errorf("%w: auth kind %q is not one of %q, %q, %q (or empty for a keyless API)", ErrInvalidOperations, authKind, AuthBearer, AuthHeader, AuthQuery)
	}
}

// validateInputSchema is the schema half of Validate for one operation.
// Errors are returned without the sentinel; Validate wraps them.
func validateInputSchema(op Operation, templates []string, reservedHeader, reservedQuery string) error {
	schema, err := decodeObject(op.InputSchema)
	if err != nil {
		return fmt.Errorf("input schema %v", err)
	}
	if typ, _ := schema["type"].(string); typ != "object" {
		return fmt.Errorf("input schema must declare \"type\":\"object\" (got %v)", schema["type"])
	}

	props := map[string]any{}
	if raw, ok := schema["properties"]; ok {
		props, ok = raw.(map[string]any)
		if !ok {
			return errors.New("input schema \"properties\" must be an object")
		}
	}
	if raw, ok := schema["required"]; ok {
		list, ok := raw.([]any)
		if !ok {
			return errors.New("input schema \"required\" must be an array")
		}
		for _, item := range list {
			name, ok := item.(string)
			if !ok {
				return errors.New("input schema \"required\" must hold property names")
			}
			if _, declared := props[name]; !declared {
				return fmt.Errorf("input schema requires %q, which is not a declared property", name)
			}
		}
	}

	// Sorted so that which of several faults is reported is deterministic.
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pathParams := map[string]bool{}
	headers := map[string]string{} // folded name (foldHeader) -> property
	cookies := map[string]string{}
	for _, key := range keys {
		if _, ok := props[key].(map[string]any); !ok {
			return fmt.Errorf("property %q must be a schema object", key)
		}
		switch {
		case key == BodyProperty:
			if ClassOf(op.Method) == quarantine.ClassSafe {
				return fmt.Errorf("property %q is not allowed on %s: a body on a safe method has no defined meaning (RFC 9110 §9.3.1)", key, op.Method)
			}
		case strings.HasPrefix(key, PrefixPath):
			name := key[len(PrefixPath):]
			if name == "" {
				return fmt.Errorf("property %q has an empty parameter name", key)
			}
			pathParams[name] = true
		case strings.HasPrefix(key, PrefixQuery):
			name := key[len(PrefixQuery):]
			if name == "" {
				return fmt.Errorf("property %q has an empty parameter name", key)
			}
			if !isPrintableASCII(name) {
				return fmt.Errorf("property %q: query parameter name must be printable ASCII without spaces", key)
			}
			if reservedQuery != "" && strings.ToLower(name) == reservedQuery {
				return fmt.Errorf("property %q names the query parameter the credential is injected into; the server-side value wins, so the parameter is refused", key)
			}
		case strings.HasPrefix(key, PrefixHeader):
			name := key[len(PrefixHeader):]
			if !ValidToken(name) {
				return fmt.Errorf("property %q: header name must be a non-empty HTTP token", key)
			}
			folded := foldHeader(name)
			if IsControlHeader(name) {
				return fmt.Errorf("property %q: %s is a control header a parameter may not set", key, name)
			}
			if reservedHeader != "" && folded == reservedHeader {
				return fmt.Errorf("property %q names the header the credential is injected into; the server-side value wins, so the parameter is refused", key)
			}
			if prev, dup := headers[folded]; dup {
				return fmt.Errorf("property %q repeats the header of %q (header names are case-insensitive, and \"_\" reads as \"-\")", key, prev)
			}
			headers[folded] = key
		case strings.HasPrefix(key, PrefixCookie):
			name := key[len(PrefixCookie):]
			if !ValidToken(name) {
				return fmt.Errorf("property %q: cookie name must be a non-empty HTTP token", key)
			}
			lower := strings.ToLower(name)
			if prev, dup := cookies[lower]; dup {
				return fmt.Errorf("property %q repeats the cookie of %q", key, prev)
			}
			cookies[lower] = key
		default:
			return fmt.Errorf("property %q is outside the location vocabulary: a parameter is named %s*, %s*, %s*, %s* or %s (ADR-0047 §3)", key, PrefixPath, PrefixQuery, PrefixHeader, PrefixCookie, BodyProperty)
		}
	}

	for _, name := range templates {
		if !pathParams[name] {
			return fmt.Errorf("path template {%s} has no %s%s property to fill it", name, PrefixPath, name)
		}
	}
	for name := range pathParams {
		found := false
		for _, t := range templates {
			if t == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("property %s%s has no {%s} template in path %q", PrefixPath, name, name, op.Path)
		}
	}
	return nil
}

// detail strips the sentinel prefix from an error this package produced,
// so that re-wrapping it under the operation's name does not repeat
// "resthttp: invalid operation set" twice in one line.
func detail(err error) string {
	return strings.TrimPrefix(err.Error(), ErrInvalidOperations.Error()+": ")
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// decodeObject parses raw as a JSON object, numbers kept as json.Number so
// that a re-encode reproduces them as written. The error names the shape
// without the sentinel; callers add context.
func decodeObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, errors.New("is missing")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("is not valid JSON: %v", err)
	}
	if dec.More() {
		return nil, errors.New("has trailing data after the JSON value")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	return obj, nil
}

// canonicalize re-encodes a JSON document into its canonical bytes: keys
// sorted lexicographically (encoding/json sorts map keys), no insignificant
// whitespace, numbers as written (json.Number), and no HTML escaping -- a
// description with "<" is encoded as "<" and not "<", so the bytes the
// signer digests are the bytes a reader sees.
func canonicalize(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, errors.New("is missing")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("is not valid JSON: %v", err)
	}
	if dec.More() {
		return nil, errors.New("has trailing data after the JSON value")
	}
	return marshalCanonical(v)
}

// marshalCanonical is the one encoder every canonical byte string here
// comes from: compact, map keys sorted, HTML escaping off.
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
