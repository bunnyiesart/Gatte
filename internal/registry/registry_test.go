package registry

import (
	"errors"
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
			// This case asserted `wantErr: false` until GAB-19: a
			// well-formed http entry WAS accepted, and then failed at dial
			// time because no dialer serves http. It is kept and inverted
			// rather than deleted, because deleting it would leave nothing
			// pinning the new contract -- a test that never existed and a
			// test that was removed look identical in a year, and the old
			// behaviour would come back silently.
			name: "well-formed http entry is refused: nothing dials http",
			server: UpstreamServer{
				Name:      "logsearch",
				Transport: TransportHTTP,
				URL:       "https://logsearch.internal:9000",
			},
			wantErr: true,
			wantIs:  ErrTransportUnsupported,
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
			// Still refused, but for a different reason than it used to be:
			// the transport is rejected before the URL is looked at, so this
			// now wraps ErrTransportUnsupported and not ErrInvalid. Stating
			// the sentinel is the point -- if a future http dialer lands and
			// this case starts failing on the empty URL again, that is the
			// correct new answer and the test will say so plainly.
			name: "http without url is refused on the transport, not the url",
			server: UpstreamServer{
				Name:      "threatintel",
				Transport: TransportHTTP,
				URL:       "",
			},
			wantErr: true,
			wantIs:  ErrTransportUnsupported,
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

// TestHTTPRefusalIsNotConflatedWithMalformed pins the distinction the two
// sentinels exist to draw. A malformed entry is the operator's mistake; an
// http entry is correct configuration this build cannot honour yet. Code
// that reports them identically would tell an operator to fix a typo that
// is not there.
//
// This is the half of the old contract that the table test cannot express:
// the table asserts which sentinel IS wrapped, and this asserts which one
// is NOT.
func TestHTTPRefusalIsNotConflatedWithMalformed(t *testing.T) {
	err := UpstreamServer{
		Name:      "logsearch",
		Transport: TransportHTTP,
		URL:       "https://logsearch.internal:9000",
	}.Validate()
	if err == nil {
		t.Fatal("a http entry must be refused while no dialer serves it")
	}
	if !errors.Is(err, ErrTransportUnsupported) {
		t.Errorf("error = %v, want ErrTransportUnsupported", err)
	}
	if errors.Is(err, ErrInvalid) {
		t.Errorf("error = %v, must NOT also wrap ErrInvalid: the entry is well-formed, "+
			"it is the missing dialer that refuses it", err)
	}

	// An unrecognised transport is the other side: that one IS malformed,
	// and must keep saying so.
	err = UpstreamServer{
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
}
