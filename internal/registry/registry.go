// Package registry is the domain package for the Upstream Registry
// component (design/02-components.md): the configuration of backend MCP
// servers the gateway fans out to (today: casemgmt, logsearch, docsearch,
// threatintel). It defines the UpstreamServer entity, its validation rules, and
// the Repository port that any storage adapter must implement.
//
// Per the ports & adapters split this project follows
// (context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Sentinel errors returned by Repository implementations. Callers should
// check these with errors.Is, since adapters wrap them with additional
// context.
var (
	// ErrNotFound is returned when no UpstreamServer is registered under
	// the requested name.
	ErrNotFound = errors.New("registry: upstream server not found")
	// ErrAlreadyExists is returned by Register when the given name is
	// already registered.
	ErrAlreadyExists = errors.New("registry: upstream server already exists")
	// ErrInvalid is returned when an UpstreamServer fails Validate.
	ErrInvalid = errors.New("registry: invalid upstream server")
	// ErrTransportUnsupported means the entry names a transport this build
	// has no dialer for. Deliberately NOT ErrInvalid: the entry is not
	// malformed and the operator did not mistype anything -- the transport is
	// a real one this project intends to serve. It is refused because
	// accepting it would store configuration that cannot be honoured, and the
	// honest moment to say so is now rather than at dial time. A caller can
	// tell the two apart and say something different about each.
	//
	// As of ADR-0047 every recognised transport (stdio, oci, http) has a
	// dialer, so Validate does not currently return this; it is kept for the
	// next recognised-but-undialable transport, which is how http stood
	// between GAB-19 and ADR-0047.
	ErrTransportUnsupported = errors.New("registry: transport has no dialer in this build")
)

// nameSeparator is the character the gateway joins an upstream's name to a
// tool's own name with, to build the namespaced names clients see.
//
// It is a third declaration of gateway.NameSeparator (internal/access holds
// the second), and it is a debt paid knowingly for the same reason that one
// is: internal/gateway imports this package, so this package cannot import
// it back. This package genuinely needs the value, because the one rule
// below that is a security control rather than hygiene is stated in terms of
// it. The two are pinned equal by TestRegistryNameSeparatorMatchesGateway in
// name_external_test.go, which sits in package registry_test precisely so it
// may import both and fail the build the day they diverge.
const nameSeparator = "."

// Transport identifies how the gateway reaches an upstream MCP server.
type Transport string

// AuthKind names where the gateway injects the upstream credential on an
// outbound REST request (ADR-0047 §5, ADR-0048). It is a signed field of an
// http entry -- it decides WHERE the live secret is placed, so an attacker
// who could flip it by a direct database write would redirect the secret
// (e.g. move it from an Authorization header into a query parameter that the
// response echoes). Covering it in the signature (signer canonical/v3-http)
// is what closes that. The AuthKind names the location only; the secret
// *value* comes from the Credential Vault at call time and is never stored
// or signed, exactly as EnvVarNames are names only.
type AuthKind string

const (
	// AuthNone is the zero value: no credential injection. It is the only
	// valid AuthKind for a non-http entry, and is refused for http.
	AuthNone AuthKind = ""
	// AuthBearer injects the secret as "Authorization: Bearer <value>". The
	// header name is fixed, so AuthName is unused (and must be empty).
	AuthBearer AuthKind = "bearer"
	// AuthHeader injects the secret as the value of the request header named
	// by AuthName (e.g. "X-API-Key").
	AuthHeader AuthKind = "header"
	// AuthQuery injects the secret as the value of the URL query parameter
	// named by AuthName.
	AuthQuery AuthKind = "query"
)

// Valid reports whether k is a recognised injection location.
func (k AuthKind) Valid() bool {
	switch k {
	case AuthNone, AuthBearer, AuthHeader, AuthQuery:
		return true
	default:
		return false
	}
}

// NamesLocation reports whether this kind needs an AuthName (a header or
// query parameter name). AuthBearer and AuthNone do not.
func (k AuthKind) NamesLocation() bool {
	return k == AuthHeader || k == AuthQuery
}

const (
	// TransportStdio is a locally spawned process communicating over
	// stdin/stdout.
	TransportStdio Transport = "stdio"
	// TransportHTTP is a remote server reached over HTTP.
	TransportHTTP Transport = "http"
	// TransportOCI runs the upstream as an ephemeral, digest-pinned
	// container: a stdio child that is `podman run --rm -i`, built by
	// internal/gateway/oci. Ported from the internal line on 28 Sep 2026.
	TransportOCI Transport = "oci"
)

// UpstreamServer is a registered backend MCP server the gateway can
// dispatch calls to.
//
// EnvVarNames holds only the *names* of environment variables the
// upstream process needs at spawn time -- never secret values. Resolving
// a name to its actual value is the Credential Vault's job
// (design/adr/0003-security-controls.md), not the registry's; this type
// deliberately has no field capable of holding a secret value.
type UpstreamServer struct {
	Name      string
	Transport Transport
	Command   string // binary/command to spawn, for TransportStdio
	Args      []string
	Image     string // digest-pinned image reference, for TransportOCI; never a value
	// URL is the endpoint an http entry is reached at (scheme, host, port and
	// base path). Reachable through Register since ADR-0047 closed GAB-19 and
	// the resthttp dialer landed; empty for stdio and oci entries. It is a
	// signed field (the full string, under signer canonical/v3-http).
	URL         string   // endpoint to call, for TransportHTTP
	EnvVarNames []string // names only, never values
	// AuthKind and AuthName describe where the credential is injected on an
	// outbound REST request, for TransportHTTP (ADR-0047 §5). Both are empty
	// for stdio and oci entries. They are signed fields (signer
	// canonical/v3-http): the injection location is part of what a signature
	// attests to, so it cannot be redirected by a direct database write that
	// still verifies.
	AuthKind AuthKind
	AuthName string
	// Operations is the frozen set of REST operations an http entry serves,
	// one per generated tool, as canonical JSON (ADR-0047 §3, ADR-0048). It
	// is produced by ingesting the OpenAPI spec at registration and is empty
	// for stdio and oci entries. Its *digest* is a signed field: the method
	// and path a tool maps to live here, not in the tool's quarantine hash
	// (which covers only name+description+schema), so without signing the set
	// a database write could repoint an approved tool at a different path and
	// nothing would notice.
	Operations []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// safeUpstreamName is the grammar of an upstream name.
//
// The name is the namespace prefix of every tool it serves ("NAME.tool"),
// a signed field, a column in `upstream list` and an argument operators
// paste into `sign NAME` and `deregister NAME`. Only non-blank and free of
// the separator used to be checked, so a name could carry a newline or tab,
// which printed a forged row -- "signed: valid" included -- in `upstream
// list`; whitespace, control characters, terminal escapes, shell
// metacharacters, '/', NUL, or a leading '-' that reads as a flag.
// Ported from the internal tree (2026-09-24). The separator keeps its own
// check and message below, which says why that character in particular is
// a security control.
var safeUpstreamName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// ValidName reports whether name is one a registry entry may take: the
// grammar of safeUpstreamName and not the reserved gatte. For callers that
// name backends without an entry in hand, such as the operator's backend
// notes in the configuration file (design/adr/0042 item 3).
func ValidName(name string) bool {
	return safeUpstreamName.MatchString(name) && !strings.EqualFold(name, ReservedName)
}

// ReservedName is the upstream name no registry entry may take, in any
// case: it is the namespace of the tools the gateway serves itself
// (design/adr/0041 item 5).
const ReservedName = "gatte"

// Validate checks that s satisfies the registry's entry contract:
//
//   - Name must be non-empty, must not contain the namespace separator,
//     and must match safeUpstreamName.
//   - Transport must be TransportStdio, TransportOCI or TransportHTTP.
//   - If Transport is TransportStdio, Command must be non-empty and Image
//     empty; if TransportOCI, Image must be digest-pinned and Command and
//     URL empty; if TransportHTTP, URL must be a well-formed http(s) URL,
//     Command and Image empty, the AuthKind/AuthName descriptor consistent
//     with the single secret it names, and Operations a non-empty JSON array
//     (ADR-0047). The AuthKind/AuthName/Operations fields are refused on any
//     non-http entry.
//   - Every entry in EnvVarNames must look like an environment variable
//     name: non-empty and free of whitespace.
//
// Validate returns ErrInvalid, wrapped with a description of which rule
// failed, on any violation; it returns nil when s is well-formed. Every
// recognised transport (stdio, oci, http) now has a dialer, so Validate no
// longer returns ErrTransportUnsupported; that sentinel is kept for the next
// recognised-but-undialable transport, should one be declared before its
// dialer lands, exactly as http was between GAB-19 and ADR-0047.
func (s UpstreamServer) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalid)
	}
	// A security control, not naming hygiene. Every client-facing tool name
	// is this name joined to a tool's own name by nameSeparator, and every
	// consumer of such a name recovers the upstream half by cutting at the
	// *first* separator: gateway.SplitNamespaced, access.Role.Allows
	// resolving a per-backend grant, `tool approve` reporting which roles an
	// approval serves. A name that already contains the separator makes that
	// cut land inside it, so the upstream those callers name is not the
	// upstream that serves the call -- a grant naming "threatintel" reaches
	// every approved tool of a separately registered "threatintel.staging",
	// which is authorization deciding about one backend while routing
	// dispatches to another. Refusing the character here is what makes the
	// two readings coincide, and it is the closure ADR-0016 leaves to this
	// package.
	//
	// Only the separator is refused, not every prefix relationship:
	// "threatintel" is a prefix of "threatintelx" and no name built for
	// "threatintelx" can ever begin with "threatintel" plus the separator,
	// so that pair is unambiguous and legal.
	if strings.Contains(s.Name, nameSeparator) {
		return fmt.Errorf("%w: name %q must not contain %q -- it is the separator between an upstream's name and a tool's, so a name containing it would make this upstream's tools indistinguishable from another upstream's",
			ErrInvalid, s.Name, nameSeparator)
	}
	if !safeUpstreamName.MatchString(s.Name) {
		return fmt.Errorf("%w: name %q must be letters, digits, '_' and '-', starting with a letter or digit", ErrInvalid, s.Name)
	}
	// The gateway's own namespace (design/adr/0041 item 5): gatte.status is
	// a tool the gateway serves itself, so no backend may register under
	// the name its tools would share. Compared without case, because a
	// "Gatte.status" beside "gatte.status" is the confusion the reservation
	// exists to prevent. Connect and Reconcile re-apply Validate to every
	// entry read back, so a row written into the database by hand is
	// refused too.
	if strings.EqualFold(s.Name, ReservedName) {
		return fmt.Errorf("%w: name %q is reserved for the gateway's own tools (gatte.status)", ErrInvalid, s.Name)
	}

	switch s.Transport {
	case TransportStdio:
		if strings.TrimSpace(s.Command) == "" {
			return fmt.Errorf("%w: command must not be empty for stdio transport", ErrInvalid)
		}
		if err := rejectImage(TransportStdio, s.Image); err != nil {
			return err
		}
	case TransportOCI:
		if err := validateImage(s.Image); err != nil {
			return err
		}
		if err := rejectUnusedByOCI("command", s.Command); err != nil {
			return err
		}
		if err := rejectUnusedByOCI("url", s.URL); err != nil {
			return err
		}
	case TransportHTTP:
		// GAB-19 closes here: the http dialer exists (internal/gateway/
		// resthttp), so an http entry is validated rather than refused. It
		// reaches a remote API by URL, carries no Command or Image, injects
		// a credential at the location AuthKind/AuthName name, and serves the
		// frozen operation set in Operations (ADR-0047).
		if err := validateHTTP(s); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: transport must be %q, %q or %q", ErrInvalid, TransportStdio, TransportOCI, TransportHTTP)
	}

	// The injection descriptor and the operation set belong to http entries
	// only. Rejecting them on a stdio or oci entry is the same discipline as
	// rejectUnusedByOCI: a field with no effect on what runs must not sit in
	// the signature, where it would be attested without meaning anything.
	if s.Transport != TransportHTTP {
		if s.AuthKind != AuthNone {
			return fmt.Errorf("%w: auth kind must be empty for %s transport; only http entries inject a credential on an outbound request", ErrInvalid, s.Transport)
		}
		if strings.TrimSpace(s.AuthName) != "" {
			return fmt.Errorf("%w: auth name must be empty for %s transport", ErrInvalid, s.Transport)
		}
		if len(s.Operations) != 0 {
			return fmt.Errorf("%w: operations must be empty for %s transport; only http entries carry a frozen operation set", ErrInvalid, s.Transport)
		}
	}

	for _, name := range s.EnvVarNames {
		// EnvVarNames must hold only variable *names*, never values. A
		// name containing "=" or whitespace strongly suggests a KEY=value
		// pair was passed by mistake, which would mean a secret value is
		// about to be stored in the registry's plaintext config rather
		// than resolved through the Credential Vault at spawn time
		// (design/adr/0003-security-controls.md). Rejecting that shape
		// here is a security control, not just input hygiene.
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: env var name must not be empty", ErrInvalid)
		}
		if strings.ContainsAny(name, "= \t\n\r") {
			return fmt.Errorf("%w: env var name must not contain \"=\" or whitespace", ErrInvalid)
		}
	}

	return nil
}

// Repository is the port through which the domain persists and retrieves
// UpstreamServer entries. Implementations are adapters (e.g. the sqlite
// subpackage) and must honor the contracts documented on each method.
type Repository interface {
	// Register adds s to the registry. It returns ErrInvalid if
	// s.Validate() fails, and ErrAlreadyExists if s.Name is already
	// registered.
	Register(ctx context.Context, s UpstreamServer) error

	// Get returns the UpstreamServer registered under name. It returns
	// ErrNotFound if no entry has that name.
	Get(ctx context.Context, name string) (UpstreamServer, error)

	// List returns every registered UpstreamServer. When the registry is
	// empty, List returns an empty, non-nil slice and a nil error -- an
	// empty registry is not an error condition.
	List(ctx context.Context) ([]UpstreamServer, error)

	// Deregister removes the UpstreamServer registered under name. It
	// returns ErrNotFound if no entry has that name.
	Deregister(ctx context.Context, name string) error
}

// ImageUpdater replaces the image of an oci entry in place: the one
// change to an entry that keeps its name, and therefore its quarantine
// state, on purpose (design/adr/0043). It is a port of its own, not a
// method of Repository, because only `upstream update` may reach it.
type ImageUpdater interface {
	// UpdateImage sets the image of the oci entry registered under name
	// and returns the entry as stored. It returns ErrNotFound if no entry
	// has that name, and ErrInvalid if the entry is not oci or the image
	// fails Validate (it must be pinned by digest). Nothing else of the
	// entry changes, CreatedAt included.
	UpdateImage(ctx context.Context, name, image string) (UpstreamServer, error)
}

// digestPinned is NAME@sha256:<64 lowercase hex>. A tag can be repointed at
// other bytes without changing the entry, so a signature over a tag would
// attest a name instead of the code that runs.
var digestPinned = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

func validateImage(image string) error {
	if strings.TrimSpace(image) == "" {
		return fmt.Errorf("%w: image must not be empty for oci transport; pin it by digest, as in \"mcp-casemgmt@sha256:<64 hex chars>\"", ErrInvalid)
	}
	if !digestPinned.MatchString(image) {
		return fmt.Errorf("%w: image %q is not pinned by digest; a tag can be repointed at other bytes without changing this entry, so the signature would attest a name instead of the code that runs. Use \"NAME@sha256:<64 hex chars>\" -- podman inspect --format '{{index .RepoDigests 0}}' NAME:TAG prints the digest", ErrInvalid, image)
	}
	return nil
}

// validateHTTP checks the rules specific to an http entry (ADR-0047 §1): a
// well-formed URL, no Command or Image, a credential-injection descriptor
// consistent with the secret it names, and a non-empty frozen operation set.
//
// It intentionally does not re-validate the inner shape of each operation
// (that is the OpenAPI ingestion's job at registration, ADR-0048); it checks
// only that Operations is well-formed JSON holding at least one operation, so
// that an entry read back from the database with a corrupted blob is refused
// here rather than failing deep in the dialer.
func validateHTTP(s UpstreamServer) error {
	if err := rejectImage(TransportHTTP, s.Image); err != nil {
		return err
	}
	if strings.TrimSpace(s.Command) != "" {
		return fmt.Errorf("%w: command must be empty for http transport; an http entry is reached by url, not by spawning a process", ErrInvalid)
	}

	if strings.TrimSpace(s.URL) == "" {
		return fmt.Errorf("%w: url must not be empty for http transport", ErrInvalid)
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return fmt.Errorf("%w: url %q is not a valid URL: %v", ErrInvalid, s.URL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: url %q must use scheme http or https, not %q", ErrInvalid, s.URL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: url %q has no host", ErrInvalid, s.URL)
	}

	if !s.AuthKind.Valid() {
		return fmt.Errorf("%w: auth kind %q is not one of %q, %q, %q (or empty for a keyless API)", ErrInvalid, s.AuthKind, AuthBearer, AuthHeader, AuthQuery)
	}
	switch s.AuthKind {
	case AuthNone:
		// A keyless public API: no credential is injected, so no secret-ref
		// and no injection name may be configured.
		if len(s.EnvVarNames) != 0 {
			return fmt.Errorf("%w: auth kind is empty (keyless) but env var names are set; a keyless http entry resolves no secret", ErrInvalid)
		}
		if strings.TrimSpace(s.AuthName) != "" {
			return fmt.Errorf("%w: auth kind is empty (keyless) but auth name is set", ErrInvalid)
		}
	default:
		// A keyed API: exactly one secret-ref names the value the descriptor
		// injects, so there is no ambiguity about which secret is the key.
		if len(s.EnvVarNames) != 1 {
			return fmt.Errorf("%w: http transport with auth kind %q needs exactly one env var name (the secret to inject); got %d", ErrInvalid, s.AuthKind, len(s.EnvVarNames))
		}
		if s.AuthKind.NamesLocation() {
			if err := validateAuthName(s.AuthName); err != nil {
				return err
			}
			if s.AuthKind == AuthHeader && isControlHeaderSlot(s.AuthName) {
				return fmt.Errorf("%w: auth name %q is a control header; the credential cannot be injected there", ErrInvalid, s.AuthName)
			}
		} else if strings.TrimSpace(s.AuthName) != "" {
			return fmt.Errorf("%w: auth kind %q injects a fixed Authorization header, so auth name must be empty", ErrInvalid, s.AuthKind)
		}
	}

	if len(s.Operations) == 0 {
		return fmt.Errorf("%w: http transport requires a non-empty operation set (generated from the OpenAPI spec at registration)", ErrInvalid)
	}
	var ops []json.RawMessage
	if err := json.Unmarshal(s.Operations, &ops); err != nil {
		return fmt.Errorf("%w: operations is not a well-formed JSON array: %v", ErrInvalid, err)
	}
	if len(ops) == 0 {
		return fmt.Errorf("%w: operations is an empty array; an http entry must serve at least one operation", ErrInvalid)
	}

	return nil
}

// authNameChars is the grammar of a header or query-parameter name the
// gateway will inject a credential into: a conservative subset with no
// whitespace, control characters or delimiters, so a signed name can never
// carry a smuggled second header or a request-splitting sequence.
var authNameChars = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)

// controlHeaderSlots mirrors the denylist of internal/gateway/resthttp
// (operation.go, controlHeaders and IsControlHeader), minus Authorization:
// the headers a credential may not be injected into, because net/http drops
// them when it writes the request (Host, Content-Length,
// Transfer-Encoding) or they are hop-by-hop and a proxy strips them
// (Connection, Upgrade, TE, Trailer, Keep-Alive, Proxy-*), or they are the
// other credential channel (Cookie). A mirror, not an import: resthttp
// imports this package, so the import would be a cycle.
// resthttp's TestReservedSlots_RegistryMirrorsTheDenylist fails if the two
// drift.
var controlHeaderSlots = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true,
	"connection": true, "upgrade": true, "te": true, "trailer": true,
	"keep-alive": true, "cookie": true,
}

// isControlHeaderSlot folds name the way resthttp does (case-insensitive,
// "_" read as "-") and reports whether it is in controlHeaderSlots or a
// Proxy-* header.
func isControlHeaderSlot(name string) bool {
	folded := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	return controlHeaderSlots[folded] || strings.HasPrefix(folded, "proxy-")
}

func validateAuthName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: auth name must not be empty for a header or query credential", ErrInvalid)
	}
	if !authNameChars.MatchString(name) {
		return fmt.Errorf("%w: auth name %q must be an HTTP token (letters, digits and !#$%%&'*+-.^_`|~)", ErrInvalid, name)
	}
	return nil
}

func rejectImage(t Transport, image string) error {
	if strings.TrimSpace(image) == "" {
		return nil
	}
	return fmt.Errorf("%w: image must be empty for %s transport; only oci entries run an image", ErrInvalid, t)
}

func rejectUnusedByOCI(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return fmt.Errorf("%w: %s must be empty for oci transport; an oci entry runs the image named in image, "+
		"and nothing reads %s -- leaving it set would put a field in the signature that has no effect on what runs",
		ErrInvalid, field, field)
}
