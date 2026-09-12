// Package registry is the domain package for the Upstream Registry
// component (design/02-components.md): the configuration of backend MCP
// servers the gateway fans out to (today: casemgmt, logsearch, docsearch,
// threatintel). It defines the UpstreamServer entity, its validation rules, and
// the Repository port that any storage adapter must implement.
//
// Per the ports & adapters split this project follows
// (docs/context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter.
package registry

import (
	"context"
	"errors"
	"fmt"
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
	// malformed and the operator did not mistype anything -- "http" is a
	// real transport this project intends to serve. It is refused because
	// accepting it would store configuration that cannot be honoured, and
	// the honest moment to say so is now rather than at dial time. A caller
	// can tell the two apart and say something different about each.
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

const (
	// TransportStdio is a locally spawned process communicating over
	// stdin/stdout.
	TransportStdio Transport = "stdio"
	// TransportHTTP is a remote server reached over HTTP.
	TransportHTTP Transport = "http"
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
	// URL is unreachable through Register in this build and that is not a
	// bug: TransportHTTP is refused at Validate (GAB-19), so the only
	// transport that reads this field never gets stored. The field, its
	// column and its round-trip are kept and still correct, because the
	// day an http dialer lands they are what makes that a dialer landing
	// rather than a migration. Deliberately not deleted -- undoing that
	// cleanup would cost more than carrying it.
	URL         string   // endpoint to call, for TransportHTTP
	EnvVarNames []string // names only, never values
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Validate checks that s satisfies the registry's entry contract:
//
//   - Name must be non-empty and must not contain the namespace separator.
//   - Transport must be exactly TransportStdio. TransportHTTP is a
//     recognised value with no dialer behind it, so it is refused here
//     rather than accepted and failed at dial time -- see
//     ErrTransportUnsupported.
//   - If Transport is TransportStdio, Command must be non-empty.
//   - Every entry in EnvVarNames must look like an environment variable
//     name: non-empty and free of whitespace.
//
// Validate returns ErrInvalid, wrapped with a description of which rule
// failed, on any violation; it returns nil when s is well-formed. The one
// exception is a recognised-but-undialable transport, which returns
// ErrTransportUnsupported.
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

	switch s.Transport {
	case TransportStdio:
		if strings.TrimSpace(s.Command) == "" {
			return fmt.Errorf("%w: command must not be empty for stdio transport", ErrInvalid)
		}
	case TransportHTTP:
		// Refused at the point of acceptance, not at dial time. Nothing in
		// this build dials http: internal/gateway/stdio serves "stdio" only
		// and returns ErrUnsupportedTransport for anything else. Storing an
		// entry the system cannot honour buys nothing and costs the
		// operator a runtime fault, at connect, for a mistake that was
		// fully knowable at registration -- the same fail-early reasoning
		// access.NewPolicy uses when it refuses an undefined role mapping
		// at construction instead of at request time.
		//
		// TransportHTTP stays a declared constant on purpose. The type is
		// not the error; the absence of a dialer is. When one exists, this
		// case becomes the URL check it used to be and nothing else here
		// has to move.
		return fmt.Errorf("%w: upstream %q declares transport %q; this build dials %q only. The constant is reserved for when an http dialer exists -- until then, register this upstream as stdio or leave it out",
			ErrTransportUnsupported, s.Name, TransportHTTP, TransportStdio)
	default:
		return fmt.Errorf("%w: transport must be %q (%q is recognised but has no dialer in this build)", ErrInvalid, TransportStdio, TransportHTTP)
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
