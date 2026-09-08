package sopsage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
	"github.com/bunnyiesart/Gatte/lab/mockutil"
)

// helperProcessEnv, when set to "1" in this test binary's own
// environment, makes it behave as a mock MCP stdio upstream instead of
// running go test -- the standard Go idiom for an os/exec-based test that
// needs a real child process without shipping a second compiled binary
// (the same trick os/exec's and net/http's own test suites use).
const helperProcessEnv = "MCP_GATEWAY_VAULT_LEAKTEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperProcessEnv) == "1" {
		runHelperMockServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runHelperMockServer serves lab/mockutil's <name>_credcheck tool over
// stdio -- the same helper the lab used to evaluate all five external
// gateway candidates (lab/README.md), reused here rather than reinvented
// (WORKFLOW.md Phase 2).
func runHelperMockServer() {
	server := gomcp.NewServer(&gomcp.Implementation{Name: "leaktest-mock", Version: "v0.0.0"}, nil)
	mockutil.AddCredCheck(server, "threatintel_credcheck")
	_ = server.Run(context.Background(), &gomcp.StdioTransport{})
}

// TestResolveThenSpawnDoesNotLeak is the test WORKFLOW.md Phase 2 names
// as "the single most important test in the whole project, given every
// rejected candidate failed some version of it": resolve a real secret
// through the sopsage Provider, inject it into a spawned upstream
// process's environment exactly the way the future Gateway Endpoint
// (Phase 5) will, and prove the raw secret appears nowhere the client
// side of that exchange could observe it -- not in the tool result, not
// in the full JSON-RPC wire transcript, not in the subprocess's stderr.
func TestResolveThenSpawnDoesNotLeak(t *testing.T) {
	const secretValue = "vt-l3ak-check-9f8e7d6c5b4a"

	secretsFile, ageKeyFile := newFixture(t, map[string]string{
		"THREATINTEL_VT_KEY": secretValue,
	})

	p, err := sopsage.New(context.Background(), secretsFile, ageKeyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	secret, err := p.Resolve(context.Background(), "THREATINTEL_VT_KEY")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(),
		helperProcessEnv+"=1",
		// This is the one and only place secret.Value() is called in
		// this test -- exactly what a real Gateway Endpoint spawn does:
		// take Resolve's return value and set it as the upstream
		// process's environment.
		"MOCK_SECRET="+secret.Value(),
		"MOCK_EXPECT="+secretValue,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	var transcript bytes.Buffer
	transport := &gomcp.LoggingTransport{
		Transport: &gomcp.CommandTransport{Command: cmd},
		Writer:    &transcript,
	}

	client := gomcp.NewClient(&gomcp.Implementation{Name: "leaktest-client", Version: "v0.0.0"}, nil)
	sess, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect to mock upstream: %v (stderr: %s)", err, stderr.String())
	}
	defer sess.Close()

	res, err := sess.CallTool(context.Background(), &gomcp.CallToolParams{Name: "threatintel_credcheck"})
	if err != nil {
		t.Fatalf("call threatintel_credcheck: %v", err)
	}

	tc, ok := res.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var got mockutil.CredCheckResult
	if err := json.Unmarshal([]byte(tc.Text), &got); err != nil {
		t.Fatalf("unmarshal credcheck result: %v", err)
	}
	if !got.ReceivedExpectedSecret {
		t.Fatal("mock upstream did not receive the injected secret -- Resolve/spawn wiring is broken, not just leaking")
	}

	// The decisive assertions: the raw secret must appear nowhere the
	// client side of this exchange could have seen it.
	if strings.Contains(tc.Text, secretValue) {
		t.Fatalf("LEAK: tool result contains the raw secret: %s", tc.Text)
	}
	if strings.Contains(transcript.String(), secretValue) {
		t.Fatal("LEAK: full JSON-RPC transcript contains the raw secret")
	}
	if strings.Contains(stderr.String(), secretValue) {
		t.Fatal("LEAK: mock upstream's stderr contains the raw secret")
	}
}
