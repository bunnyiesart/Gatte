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
			name: "valid http entry",
			server: UpstreamServer{
				Name:      "logsearch",
				Transport: TransportHTTP,
				URL:       "https://logsearch.internal:9000",
			},
			wantErr: false,
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
			name: "http without url",
			server: UpstreamServer{
				Name:      "threatintel",
				Transport: TransportHTTP,
				URL:       "",
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
				if !errors.Is(err, ErrInvalid) {
					t.Errorf("Validate() error = %v, want it to wrap ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
