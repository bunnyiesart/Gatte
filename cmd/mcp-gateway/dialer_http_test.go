package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	gwrest "github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// design/adr/0047 §2 and design/adr/0048 at the composition root: the http
// transport reaches the resthttp adapter, and what the adapter would refuse
// at every start is refused at the prompt by the adapter's own functions.

// httpOperations is one valid operation set, as the OpenAPI ingestion will
// produce it, so the tests below have something the adapter accepts.
func httpOperations(t *testing.T) []byte {
	t.Helper()
	b, err := gwrest.Encode([]gwrest.Operation{{
		Name:        "check",
		Description: "Look an IP up",
		Method:      "GET",
		Path:        "/check/{ip}",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path_ip":{"type":"string"}},"required":["path_ip"]}`),
	}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

// httpEntry is a keyless http entry the registry and the adapter both
// accept, for tests that change one thing about it.
func httpEntry(t *testing.T) registry.UpstreamServer {
	t.Helper()
	return registry.UpstreamServer{
		Name:       "ioc",
		Transport:  registry.TransportHTTP,
		URL:        "https://api.example.com/v2",
		Operations: httpOperations(t),
	}
}

// TestDialTimeRefusalAppliesTheHTTPRules: an operation set or a URL the
// adapter would refuse is refused at register/sign with the adapter's own
// error -- not a paraphrase of its rules that could drift from them.
func TestDialTimeRefusalAppliesTheHTTPRules(t *testing.T) {
	good := httpEntry(t)
	if err := dialTimeRefusal(good); err != nil {
		t.Fatalf("dialTimeRefusal refused a valid keyless http entry: %v", err)
	}

	// A spec-authored SSRF inside the signed set (ADR-0048 Decisão 6): the
	// path carries an authority. Hand-written JSON, because Encode does not
	// validate and this is exactly the kind of bytes that must not be signed.
	bad := good
	bad.Operations = []byte(`[{"name":"check","method":"GET","path":"//169.254.169.254/latest","inputSchema":{"type":"object"}}]`)
	err := dialTimeRefusal(bad)
	if !errors.Is(err, gwrest.ErrInvalidOperations) {
		t.Fatalf("dialTimeRefusal(http, path with an authority) = %v, want ErrInvalidOperations", err)
	}
	// The console's message IS the adapter's: the same Decode, so the same
	// text, and the dial error of the real adapter carries it verbatim.
	if _, direct := gwrest.Decode(bad.Operations, string(bad.AuthKind), bad.AuthName); direct == nil || direct.Error() != err.Error() {
		t.Errorf("console refusal %q differs from the adapter's Decode %v", err, direct)
	}
	_, dialErr := gwrest.New(nil).Dial(context.Background(), specOf(bad), nil)
	if dialErr == nil || !strings.Contains(dialErr.Error(), err.Error()) {
		t.Errorf("the adapter's dial error %v does not carry the console's refusal %q", dialErr, err)
	}

	// A URL the adapter would not pin a client to (userinfo: a credential in
	// the URL is a credential in every error that prints it).
	badURL := good
	badURL.URL = "https://user:hunter2@api.example.com/v2"
	if err := dialTimeRefusal(badURL); !errors.Is(err, gwrest.ErrInvalidURL) {
		t.Errorf("dialTimeRefusal(http, url with userinfo) = %v, want ErrInvalidURL", err)
	}

	// A host that is already an address the egress guard refuses on every
	// call (the metadata endpoint, loopback, private space): refused at the
	// prompt by the adapter's own policy, with no DNS -- an entry that can
	// never serve must not be signed. A host NAME is not resolved here.
	for _, host := range []string{"http://169.254.169.254/latest", "http://127.0.0.1:8080/", "https://10.0.0.1/v2", "http://[::1]/"} {
		literal := good
		literal.URL = host
		err := dialTimeRefusal(literal)
		if !errors.Is(err, gwrest.ErrInvalidURL) || !errors.Is(err, gwrest.ErrEgressRefused) {
			t.Errorf("dialTimeRefusal(http, %s) = %v, want ErrInvalidURL wrapping ErrEgressRefused", host, err)
		}
	}

	// A parameter name that shadows the credential's slot, which the
	// adapter reserves server-wins (Decisão 6): refused before signing.
	shadow := good
	shadow.AuthKind, shadow.AuthName, shadow.EnvVarNames = registry.AuthHeader, "X-API-Key", []string{"IOC_API_KEY"}
	shadow.Operations = []byte(`[{"name":"check","method":"GET","path":"/check","inputSchema":{"type":"object","properties":{"header_x-api-key":{"type":"string"}}}}]`)
	if err := dialTimeRefusal(shadow); !errors.Is(err, gwrest.ErrInvalidOperations) {
		t.Errorf("dialTimeRefusal(http, header_* on the auth slot) = %v, want ErrInvalidOperations", err)
	}
}

// specOf is the composition root's view of an entry as the gateway hands it
// to a Dialer (gateway.specFor), for the one field set that matters here.
func specOf(entry registry.UpstreamServer) gateway.UpstreamSpec {
	return gateway.UpstreamSpec{
		Name:       entry.Name,
		Transport:  string(entry.Transport),
		URL:        entry.URL,
		AuthKind:   string(entry.AuthKind),
		AuthName:   entry.AuthName,
		Operations: entry.Operations,
	}
}

// TestTransportDialerRoutesHTTPToTheAdapter: before this wiring an http
// entry fell into the default branch ("does not serve"); now it reaches
// the adapter, and only the adapter.
func TestTransportDialerRoutesHTTPToTheAdapter(t *testing.T) {
	stdio, oci, rest := &recordingDialer{}, &recordingDialer{}, &recordingDialer{}
	d := transportDialer{stdio: stdio, oci: oci, resthttp: rest}

	_, err := d.Dial(context.Background(), gateway.UpstreamSpec{Name: "ioc", Transport: "http"}, nil)
	if !rest.called {
		t.Fatal("an http entry did not reach the resthttp adapter")
	}
	if stdio.called || oci.called {
		t.Error("an http entry reached a process adapter")
	}
	if err != nil && strings.Contains(err.Error(), "does not serve") {
		t.Errorf("an http entry was still refused as unserved: %v", err)
	}

	// The real wiring: the adapter built by newTransportDialer accepts a
	// valid keyless entry with no I/O (Dial opens nothing, ADR-0047 §2), so
	// this proves the route end to end without a network.
	real := newTransportDialer(&config.Config{}, nil)
	up, err := real.Dial(context.Background(), specOf(httpEntry(t)), nil)
	if err != nil {
		t.Fatalf("newTransportDialer(...).Dial(http) = %v, want an upstream", err)
	}
	defer up.Close()
	defs, err := up.ListTools(context.Background())
	if err != nil || len(defs) != 1 || defs[0].Name != "check" {
		t.Errorf("ListTools = %+v, %v; want the one signed operation", defs, err)
	}

	// An unknown transport is still refused, and the refusal now names all
	// three the gateway serves.
	_, err = d.Dial(context.Background(), gateway.UpstreamSpec{Name: "ioc", Transport: "grpc"}, nil)
	if err == nil || !strings.Contains(err.Error(), "does not serve") {
		t.Fatalf("Dial(grpc) = %v, want the unserved refusal", err)
	}
	for _, want := range []string{`"stdio"`, `"oci"`, `"http"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the unserved refusal does not list %s: %v", want, err)
		}
	}
}

// TestEntryNetworkHTTPIsHost pins the Phase D placeholder (ADR-0047 §6):
// for http the gateway is the client, in its own namespace, and
// `upstream list -json` says so with the same word as stdio until a
// vocabulary for "this host, to that host:port" exists.
func TestEntryNetworkHTTPIsHost(t *testing.T) {
	network, err := entryNetwork(httpEntry(t))
	if err != nil {
		t.Fatalf("entryNetwork(http) error = %v", err)
	}
	if network != stdioNetwork {
		t.Errorf("entryNetwork(http) = %q, want %q", network, stdioNetwork)
	}
}
