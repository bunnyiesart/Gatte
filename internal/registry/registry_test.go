package registry

import (
	"errors"
	"strings"
	"testing"
)

func TestUpstreamServer_Validate(t *testing.T) {
	tests := []struct {
		name    string
		server  UpstreamServer
		wantErr bool
		// wantIs is the sentinel the error must wrap. Empty means
		// ErrInvalid, which is the answer for every malformed entry. A
		// recognised transport with no dialer is NOT malformed and says so
		// with its own sentinel, so the distinction is pinned here rather
		// than left to whichever sentinel happened to be returned.
		wantIs error
	}{
		{
			name: "valid stdio entry",
			server: UpstreamServer{
				Name:        "casemgmt",
				Transport:   TransportStdio,
				Command:     "/usr/local/bin/casemgmt-mcp",
				Args:        []string{"--config", "/etc/casemgmt/config.yaml"},
				EnvVarNames: []string{"CASEMGMT_API_KEY"},
			},
			wantErr: false,
		},
		{
			// Accepted again since ADR-0047 closed GAB-19: the resthttp
			// dialer exists, so a well-formed http entry is valid. This case
			// has swung from accepted (pre-GAB-19) to refused (GAB-19) to
			// accepted (ADR-0047), and the comment history on each swing is
			// why the contract never changed silently.
			name:    "valid http entry",
			server:  validHTTP(),
			wantErr: false,
		},
		{
			name: "http without url is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.URL = ""
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http with a command is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.Command = "/usr/local/bin/something"
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http with a non-http scheme is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.URL = "ftp://api.example.com/v2"
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http header auth without a name is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.AuthName = ""
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http header auth with a non-token name is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.AuthName = "X API Key"
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http bearer auth with a name is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.AuthKind = AuthBearer
				s.AuthName = "X-API-Key"
				return s
			}(),
			wantErr: true,
		},
		{
			name: "keyed http with no secret-ref is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.EnvVarNames = nil
				return s
			}(),
			wantErr: true,
		},
		{
			name: "keyless http with a secret-ref is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.AuthKind = AuthNone
				s.AuthName = ""
				// keep EnvVarNames set: a keyless entry must resolve nothing
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http with an empty operation set is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.Operations = []byte(`[]`)
				return s
			}(),
			wantErr: true,
		},
		{
			name: "http with malformed operations is refused",
			server: func() UpstreamServer {
				s := validHTTP()
				s.Operations = []byte(`{not json`)
				return s
			}(),
			wantErr: true,
		},
		{
			name: "auth kind on a stdio entry is refused",
			server: UpstreamServer{
				Name:      "casemgmt",
				Transport: TransportStdio,
				Command:   "/usr/local/bin/casemgmt-mcp",
				AuthKind:  AuthBearer,
			},
			wantErr: true,
		},
		{
			name: "operations on a stdio entry is refused",
			server: UpstreamServer{
				Name:       "casemgmt",
				Transport:  TransportStdio,
				Command:    "/usr/local/bin/casemgmt-mcp",
				Operations: []byte(`[{"name":"x"}]`),
			},
			wantErr: true,
		},
		{
			name: "empty name",
			server: UpstreamServer{
				Name:      "",
				Transport: TransportStdio,
				Command:   "/usr/local/bin/foo",
			},
			wantErr: true,
		},
		{
			name: "whitespace-only name",
			server: UpstreamServer{
				Name:      "   ",
				Transport: TransportStdio,
				Command:   "/usr/local/bin/foo",
			},
			wantErr: true,
		},
		{
			name: "invalid transport",
			server: UpstreamServer{
				Name:      "docsearch",
				Transport: Transport("websocket"),
				Command:   "/usr/local/bin/docsearch-mcp",
			},
			wantErr: true,
		},
		{
			name: "stdio without command",
			server: UpstreamServer{
				Name:      "threatintel",
				Transport: TransportStdio,
				Command:   "",
			},
			wantErr: true,
		},
		{
			name: "env var name containing = is rejected",
			server: UpstreamServer{
				Name:        "threatintel",
				Transport:   TransportStdio,
				Command:     "/usr/local/bin/threatintel-mcp",
				EnvVarNames: []string{"THREATINTEL_API_KEY=supersecretvalue"},
			},
			wantErr: true,
		},
		{
			name: "env var name containing whitespace is rejected",
			server: UpstreamServer{
				Name:        "threatintel",
				Transport:   TransportStdio,
				Command:     "/usr/local/bin/threatintel-mcp",
				EnvVarNames: []string{"THREATINTEL API KEY"},
			},
			wantErr: true,
		},
		{
			name: "empty env var name is rejected",
			server: UpstreamServer{
				Name:        "threatintel",
				Transport:   TransportStdio,
				Command:     "/usr/local/bin/threatintel-mcp",
				EnvVarNames: []string{""},
			},
			wantErr: true,
		},
		{
			name: "totally empty EnvVarNames is valid",
			server: UpstreamServer{
				Name:        "no-secrets-needed",
				Transport:   TransportStdio,
				Command:     "/usr/local/bin/no-secrets-needed",
				EnvVarNames: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.server.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want an error")
				}
				want := tt.wantIs
				if want == nil {
					want = ErrInvalid
				}
				if !errors.Is(err, want) {
					t.Errorf("Validate() error = %v, want it to wrap %v", err, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

// validHTTP returns a well-formed keyed http entry: an API reached by URL,
// injecting one secret as an X-API-Key header, serving one frozen operation.
// Tests mutate one field at a time off this base so each case says exactly
// what makes it invalid.
func validHTTP() UpstreamServer {
	return UpstreamServer{
		Name:        "abuseipdb",
		Transport:   TransportHTTP,
		URL:         "https://api.abuseipdb.com/api/v2",
		AuthKind:    AuthHeader,
		AuthName:    "X-API-Key",
		EnvVarNames: []string{"ABUSEIPDB_KEY"},
		Operations:  []byte(`[{"name":"check","method":"GET","path":"/check"}]`),
	}
}

// TestUnrecognisedTransportIsMalformed pins the remaining half of the two
// sentinels' distinction. Since ADR-0047 every recognised transport has a
// dialer, so http is valid (asserted in the table). A transport this project
// does not recognise at all is the operator's mistake and keeps wrapping
// ErrInvalid, never ErrTransportUnsupported, which is reserved for a
// recognised-but-undialable transport.
func TestUnrecognisedTransportIsMalformed(t *testing.T) {
	err := UpstreamServer{
		Name:      "docsearch",
		Transport: Transport("websocket"),
		Command:   "/usr/local/bin/docsearch-mcp",
	}.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("unrecognised transport error = %v, want ErrInvalid", err)
	}
	if errors.Is(err, ErrTransportUnsupported) {
		t.Errorf("unrecognised transport error = %v, must NOT wrap ErrTransportUnsupported: "+
			"\"websocket\" is not a transport this project recognises at all", err)
	}
	// The message lists the three transports, and does not say http lacks
	// a dialer: since ADR-0047 step 4 it registers end to end.
	if msg := err.Error(); !strings.Contains(msg, `"stdio", "oci" or "http"`) || strings.Contains(msg, "no dialer") {
		t.Errorf("unrecognised transport message = %q, want the three transports and no \"no dialer\" claim", msg)
	}
}

// TestHTTPAuthNameIsNotAControlHeader: a header credential cannot be
// injected into a header net/http drops (Host, Content-Length,
// Transfer-Encoding) or a proxy strips (hop-by-hop, Proxy-*), nor into
// Cookie; raw Authorization is legal. Mirrors resthttp's reservedSlots,
// which TestReservedSlots_RegistryMirrorsTheDenylist pins against this.
func TestHTTPAuthNameIsNotAControlHeader(t *testing.T) {
	for _, name := range []string{"Connection", "Proxy-Authorization", "host", "Transfer_Encoding", "Cookie", "TE"} {
		e := validHTTP()
		e.AuthName = name
		if err := e.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "control header") {
			t.Errorf("auth name %q: %v, want a control-header refusal", name, err)
		}
		// As a query parameter the same name is just a name.
		e.AuthKind = AuthQuery
		if err := e.Validate(); err != nil {
			t.Errorf("query auth name %q: %v", name, err)
		}
	}
	e := validHTTP()
	e.AuthName = "Authorization"
	if err := e.Validate(); err != nil {
		t.Errorf("raw Authorization header: %v", err)
	}
}
