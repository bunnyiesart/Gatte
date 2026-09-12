package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newRNG() *rand.Rand { return rand.New(rand.NewSource(1)) }

func schemaFromJSON(t *testing.T, s string) *jsonschema.Schema {
	t.Helper()
	var out jsonschema.Schema
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	return &out
}

func TestSynthArgsAlwaysFillsRequired(t *testing.T) {
	s := schemaFromJSON(t, `{
		"type":"object",
		"properties":{"case_id":{"type":"string"},"note":{"type":"string"}},
		"required":["case_id"]
	}`)
	// Optional properties are included by coin flip, so one pass proves
	// nothing about the required one. Many passes do.
	for i := 0; i < 50; i++ {
		got := synthArgs(s, rand.New(rand.NewSource(int64(i))))
		if _, ok := got["case_id"]; !ok {
			t.Fatalf("seed %d: required property case_id missing from %v", i, got)
		}
	}
}

func TestSynthArgsIsDeterministicForASeed(t *testing.T) {
	s := schemaFromJSON(t, `{
		"type":"object",
		"properties":{"a":{"type":"string"},"b":{"type":"integer"},"c":{"type":"boolean"}}
	}`)
	first := synthArgs(s, rand.New(rand.NewSource(7)))
	second := synthArgs(s, rand.New(rand.NewSource(7)))

	fj, _ := json.Marshal(first)
	sj, _ := json.Marshal(second)
	if string(fj) != string(sj) {
		t.Fatalf("same seed produced different arguments:\n %s\n %s", fj, sj)
	}
}

func TestSynthValueHonoursEnumAndConst(t *testing.T) {
	enum := schemaFromJSON(t, `{"type":"string","enum":["critical","high","medium"]}`)
	for i := 0; i < 20; i++ {
		v, ok := synthValue(enum, "severity", rand.New(rand.NewSource(int64(i))), 0)
		if !ok {
			t.Fatal("enum produced no value")
		}
		switch v {
		case "critical", "high", "medium":
		default:
			t.Fatalf("value %v is not in the enum", v)
		}
	}

	cst := schemaFromJSON(t, `{"const":"only-this"}`)
	v, ok := synthValue(cst, "x", newRNG(), 0)
	if !ok || v != "only-this" {
		t.Fatalf("const = %v (ok=%v), want only-this", v, ok)
	}
}

func TestSynthValueRespectsNumericBounds(t *testing.T) {
	s := schemaFromJSON(t, `{"type":"integer","minimum":10,"maximum":20}`)
	for i := 0; i < 100; i++ {
		v, _ := synthValue(s, "limit", rand.New(rand.NewSource(int64(i))), 0)
		n, ok := v.(int64)
		if !ok {
			t.Fatalf("integer schema produced %T", v)
		}
		if n < 10 || n > 20 {
			t.Fatalf("value %d outside [10,20]", n)
		}
	}
}

// The generated values must stay inside ranges reserved for documentation.
// A load generator that emits real addresses becomes a scanner.
func TestSynthStringUsesReservedRangesOnly(t *testing.T) {
	for i := 0; i < 200; i++ {
		rng := rand.New(rand.NewSource(int64(i)))

		ip := synthString(nil, "ip", rng)
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("ip %q does not parse", ip)
		}
		if !strings.HasPrefix(ip, "192.0.2.") {
			t.Fatalf("ip %q is outside the RFC 5737 documentation range", ip)
		}

		if d := synthString(nil, "domain", rng); !strings.HasSuffix(d, ".example.com") {
			t.Fatalf("domain %q is not under example.com", d)
		}
		if v6 := synthString(nil, "ipv6", rng); !strings.HasPrefix(v6, "2001:db8:") {
			t.Fatalf("ipv6 %q is outside the RFC 3849 range", v6)
		}
	}
}

func TestSynthStringRespectsMinLength(t *testing.T) {
	min := 40
	s := &jsonschema.Schema{Type: "string", MinLength: &min}
	got := synthString(s, "freeform", newRNG())
	if len(got) < min {
		t.Fatalf("value %q is %d chars, want at least %d", got, len(got), min)
	}
}

func TestSynthValueTerminatesOnRecursiveSchema(t *testing.T) {
	// A self-referential object must not recurse forever. The timeout is the
	// assertion: without the depth cap this test hangs instead of failing,
	// which is the one outcome a test must never have.
	s := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{}}
	s.Properties["self"] = s

	done := make(chan struct{})
	go func() {
		defer close(done)
		synthValue(s, "root", newRNG(), 0)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("synthValue did not terminate on a self-referential schema")
	}
}

func TestGuardEndpointBlocksRemoteWithoutConfirm(t *testing.T) {
	cases := []struct {
		endpoint string
		confirm  bool
		wantErr  bool
	}{
		{"http://127.0.0.1:8080/", false, false},
		{"http://localhost:8080/", false, false},
		{"http://[::1]:8080/", false, false},
		{"https://mcp.soc.internal/", false, true},
		{"https://mcp.soc.internal/", true, false},
		{"https://10.17.90.10/", false, true},
	}
	for _, c := range cases {
		err := guardEndpoint(c.endpoint, c.confirm)
		if (err != nil) != c.wantErr {
			t.Errorf("guardEndpoint(%q, confirm=%v) error = %v, wantErr %v",
				c.endpoint, c.confirm, err, c.wantErr)
		}
	}
}

func TestLoadTokenPrefersFileAndRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("  tok-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GATTE_TOKEN", "tok-from-env")

	got, err := loadToken(path)
	if err != nil || got != "tok-from-file" {
		t.Fatalf("loadToken(file) = %q, %v; want tok-from-file", got, err)
	}
	if got, err = loadToken(""); err != nil || got != "tok-from-env" {
		t.Fatalf("loadToken(env) = %q, %v; want tok-from-env", got, err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken(empty); err == nil {
		t.Fatal("an empty token file must be an error, not an anonymous request")
	}

	t.Setenv("GATTE_TOKEN", "")
	if _, err := loadToken(""); err == nil {
		t.Fatal("no token anywhere must be an error")
	}
}

func TestSelectToolsFiltersAndSorts(t *testing.T) {
	tools := []*mcp.Tool{
		{Name: "logsearch.search_keyword"},
		{Name: "casemgmt.list_cases"},
		{Name: "casemgmt.get_case"},
		{Name: "threatintel.lookup_ip"},
	}
	got, err := selectTools(tools, "^casemgmt\\.", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "casemgmt.get_case" || got[1].Name != "casemgmt.list_cases" {
		t.Fatalf("-only gave %v", names(got))
	}

	if got, err = selectTools(tools, "", "lookup"); err != nil {
		t.Fatal(err)
	} else if len(got) != 3 {
		t.Fatalf("-skip gave %v", names(got))
	}

	if _, err := selectTools(tools, "([", ""); err == nil {
		t.Fatal("a malformed -only regexp must be a usage error")
	}
}

func names(ts []*mcp.Tool) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	return out
}

func TestNextCallProducesUnknownToolsAtTheRequestedRate(t *testing.T) {
	tools := []*mcp.Tool{{Name: "casemgmt.list_cases"}}

	none := 0
	for i := 0; i < 200; i++ {
		if name, _ := nextCall(tools, 0, rand.New(rand.NewSource(int64(i)))); name != "casemgmt.list_cases" {
			none++
		}
	}
	if none != 0 {
		t.Fatalf("-unknown-pct 0 still invented %d tool names", none)
	}

	all := 0
	for i := 0; i < 200; i++ {
		name, _ := nextCall(tools, 100, rand.New(rand.NewSource(int64(i))))
		if strings.Contains(name, "tool_that_does_not_exist") {
			all++
			if !strings.HasPrefix(name, "casemgmt.") {
				t.Fatalf("invented name %q lost the backend namespace", name)
			}
		}
	}
	if all != 200 {
		t.Fatalf("-unknown-pct 100 invented %d/200", all)
	}
}

func TestIsTransportFailureSeparatesRefusalFromUnreachable(t *testing.T) {
	if isTransportFailure(errNotGranted{}) {
		t.Error("a JSON-RPC refusal is the gateway deciding, not a transport failure")
	}
	for _, msg := range []string{"dial tcp: connection refused", "x509: certificate signed by unknown authority", "unexpected EOF"} {
		if !isTransportFailure(errString(msg)) {
			t.Errorf("%q should count as a transport failure", msg)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

type errNotGranted struct{}

func (errNotGranted) Error() string { return "tool not granted to role" }
func (errNotGranted) Code() int64   { return -32000 }

func TestParseFlagsRejectsBadInput(t *testing.T) {
	var stderr bytes.Buffer
	for _, args := range [][]string{
		{},
		{"-endpoint", "http://x/", "-rate", "0"},
		{"-endpoint", "http://x/", "-duration", "0"},
		{"-endpoint", "http://x/", "-unknown-pct", "101"},
	} {
		if _, _, err := parseFlags(args, &stderr); err == nil {
			t.Errorf("parseFlags(%v) accepted invalid input", args)
		}
	}
	cfg, _, err := parseFlags([]string{"-endpoint", "http://127.0.0.1:8080/"}, &stderr)
	if err != nil || cfg == nil {
		t.Fatalf("valid flags rejected: %v", err)
	}
}

// The end-to-end proof: a real MCP server over streamable HTTP, reached
// through the same code path the gateway will be. Without this the tool is
// only proven to compile.
func TestRunAgainstLiveServer(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-gateway", Version: "v0"}, nil)

	type caseArgs struct {
		CaseID string `json:"case_id" jsonschema:"the case to fetch"`
	}
	var seenAuth string
	var calls int
	mcp.AddTool(server, &mcp.Tool{Name: "casemgmt.get_case", Description: "fetch a case"},
		func(ctx context.Context, req *mcp.CallToolRequest, args caseArgs) (*mcp.CallToolResult, any, error) {
			calls++
			if args.CaseID == "" {
				return nil, nil, errString("required argument case_id was empty")
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: `{"case_id":"` + args.CaseID + `"}`}},
			}, nil, nil
		})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		handler.ServeHTTP(w, r)
	}))
	defer ts.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-token-value"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-endpoint", ts.URL,
		"-token-file", tokenPath,
		"-duration", "300ms",
		"-rate", "20",
		"-seed", "42",
		"-unknown-pct", "0",
	}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("run exited %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if calls == 0 {
		t.Fatal("no tool was actually called")
	}
	if seenAuth != "Bearer test-token-value" {
		t.Fatalf("Authorization header = %q, want the bearer token", seenAuth)
	}
	out := stdout.String()
	if !strings.Contains(out, "casemgmt.get_case") {
		t.Errorf("plan did not name the served tool:\n%s", out)
	}
	if !strings.Contains(out, "seed 42") {
		t.Errorf("run did not report its seed:\n%s", out)
	}
	// The token must never appear in output a transcript could capture.
	if strings.Contains(out, "test-token-value") || strings.Contains(stderr.String(), "test-token-value") {
		t.Fatal("the bearer token leaked into the tool's own output")
	}
}

func TestRunPlanMakesNoCalls(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-gateway", Version: "v0"}, nil)
	var calls int
	mcp.AddTool(server, &mcp.Tool{Name: "casemgmt.list_cases", Description: "list"},
		func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
			calls++
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "{}"}}}, nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Setenv("GATTE_TOKEN", "tok")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-endpoint", ts.URL, "-plan"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("-plan exited %d: %s", code, stderr.String())
	}
	if calls != 0 {
		t.Fatalf("-plan made %d call(s); it must make none", calls)
	}
}

// A remote endpoint without -confirm must stop before any call is dispatched.
func TestRunRefusesRemoteEndpointWithoutConfirm(t *testing.T) {
	t.Setenv("GATTE_TOKEN", "tok")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-endpoint", "https://mcp.soc.internal/", "-duration", "10ms"}, &stdout, &stderr)
	if code != exitUsageErr {
		t.Fatalf("exit = %d, want %d", code, exitUsageErr)
	}
}
