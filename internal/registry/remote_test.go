package registry

import (
	"errors"
	"strings"
	"testing"
)

func remoteEntry() UpstreamServer {
	return UpstreamServer{
		Name:        "vendor",
		Transport:   TransportRemote,
		URL:         "https://mcp.vendor.example/mcp",
		AuthKind:    AuthBearer,
		EnvVarNames: []string{"VENDOR_TOKEN"},
		RemoteKind:  RemoteStreamable,
	}
}

// TestValidateRemote pins ADR-0058 §4: what a remote entry must carry and
// what it may not.
func TestValidateRemote(t *testing.T) {
	keyless := remoteEntry()
	keyless.AuthKind, keyless.EnvVarNames = AuthNone, nil
	header := remoteEntry()
	header.AuthKind, header.AuthName = AuthHeader, "X-Api-Key"
	for name, ok := range map[string]UpstreamServer{"bearer": remoteEntry(), "keyless": keyless, "header": header} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%s: want valid, got %v", name, err)
		}
	}

	bad := map[string]func(*UpstreamServer){
		"no url":            func(s *UpstreamServer) { s.URL = "" },
		"ftp url":           func(s *UpstreamServer) { s.URL = "ftp://mcp.vendor.example/" },
		"userinfo":          func(s *UpstreamServer) { s.URL = "https://u:p@mcp.vendor.example/" },
		"query":             func(s *UpstreamServer) { s.URL = "https://mcp.vendor.example/mcp?key=x" },
		"fragment":          func(s *UpstreamServer) { s.URL = "https://mcp.vendor.example/mcp#x" },
		"command":           func(s *UpstreamServer) { s.Command = "/bin/sh" },
		"image":             func(s *UpstreamServer) { s.Image = "x@sha256:" + strings.Repeat("a", 64) },
		"args":              func(s *UpstreamServer) { s.Args = []string{"--x"} },
		"operations":        func(s *UpstreamServer) { s.Operations = []byte(`[{}]`) },
		"query auth":        func(s *UpstreamServer) { s.AuthKind, s.AuthName = AuthQuery, "key" },
		"bearer with name":  func(s *UpstreamServer) { s.AuthName = "X" },
		"bearer no secret":  func(s *UpstreamServer) { s.EnvVarNames = nil },
		"two secrets":       func(s *UpstreamServer) { s.EnvVarNames = []string{"A", "B"} },
		"keyless w/ secret": func(s *UpstreamServer) { s.AuthKind = AuthNone },
		"mcp header":        func(s *UpstreamServer) { s.AuthKind, s.AuthName = AuthHeader, "Mcp-Session-Id" },
		"control header":    func(s *UpstreamServer) { s.AuthKind, s.AuthName = AuthHeader, "Host" },
		"no remote kind":    func(s *UpstreamServer) { s.RemoteKind = "" },
		"unknown kind":      func(s *UpstreamServer) { s.RemoteKind = "websocket" },
	}
	for name, mutate := range bad {
		s := remoteEntry()
		mutate(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

// TestValidateRemote_SSEIsDeferredNotInvalid: "sse" is a recognised value
// this build does not dial yet, so it is ErrTransportUnsupported with a
// message that says so, not a typo.
func TestValidateRemote_SSEIsDeferredNotInvalid(t *testing.T) {
	s := remoteEntry()
	s.RemoteKind = RemoteSSE
	err := s.Validate()
	if !errors.Is(err, ErrTransportUnsupported) || errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrTransportUnsupported only, got %v", err)
	}
	if !strings.Contains(err.Error(), "deferred, not a typo") {
		t.Errorf("message should say the path is deferred: %v", err)
	}
}

// TestRemoteKindOnlyOnRemote: a field with no effect on other transports is
// refused there, so it is never signed without meaning anything.
func TestRemoteKindOnlyOnRemote(t *testing.T) {
	s := UpstreamServer{Name: "x", Transport: TransportStdio, Command: "/bin/x", RemoteKind: RemoteStreamable}
	if err := s.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("stdio with remote kind: want ErrInvalid, got %v", err)
	}
}
