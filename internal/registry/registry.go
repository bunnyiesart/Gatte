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
)

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
	Name        string
	Transport   Transport
	Command     string // binary/command to spawn, for TransportStdio
	Args        []string
	URL         string   // endpoint to call, for TransportHTTP
	EnvVarNames []string // names only, never values
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Validate checks that s satisfies the registry's entry contract:
//
//   - Name must be non-empty.
//   - Transport must be exactly TransportStdio or TransportHTTP.
//   - If Transport is TransportStdio, Command must be non-empty.
//   - If Transport is TransportHTTP, URL must be non-empty.
//   - Every entry in EnvVarNames must look like an environment variable
//     name: non-empty and free of whitespace.
//
// Validate returns ErrInvalid, wrapped with a description of which rule
// failed, on any violation; it returns nil when s is well-formed.
func (s UpstreamServer) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalid)
	}

	switch s.Transport {
	case TransportStdio:
		if strings.TrimSpace(s.Command) == "" {
			return fmt.Errorf("%w: command must not be empty for stdio transport", ErrInvalid)
		}
	case TransportHTTP:
		if strings.TrimSpace(s.URL) == "" {
			return fmt.Errorf("%w: url must not be empty for http transport", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: transport must be \"stdio\" or \"http\"", ErrInvalid)
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
