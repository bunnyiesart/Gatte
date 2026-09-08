package mockutil

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCredCheckSmoke(t *testing.T) {
	t.Setenv("MOCK_SECRET", "sw1ss-abc123")
	t.Setenv("MOCK_EXPECT", "sw1ss-abc123")

	server := mcp.NewServer(&mcp.Implementation{Name: "smoke"}, nil)
	AddCredCheck(server, "threatintel_credcheck")

	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()

	serverDone := make(chan error, 1)
	go func() { _, err := server.Connect(ctx, st, nil); serverDone <- err }()

	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "threatintel_credcheck"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}

	if strings.Contains(tc.Text, "sw1ss-abc123") {
		t.Fatalf("LEAK: credcheck result contains the raw secret: %s", tc.Text)
	}

	var got CredCheckResult
	if err := json.Unmarshal([]byte(tc.Text), &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !got.ReceivedExpectedSecret {
		t.Errorf("ReceivedExpectedSecret = false, want true")
	}
	if got.Fingerprint == "" {
		t.Errorf("Fingerprint is empty")
	}
	t.Logf("result: %+v (raw: %s)", got, tc.Text)
}

func TestCredCheckMismatch(t *testing.T) {
	os.Setenv("MOCK_SECRET", "actual-value")
	os.Setenv("MOCK_EXPECT", "different-value")
	defer os.Unsetenv("MOCK_SECRET")
	defer os.Unsetenv("MOCK_EXPECT")

	server := mcp.NewServer(&mcp.Implementation{Name: "smoke2"}, nil)
	AddCredCheck(server, "x_credcheck")
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go server.Connect(ctx, st, nil)
	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "x_credcheck"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	tc := res.Content[0].(*mcp.TextContent)
	var got CredCheckResult
	json.Unmarshal([]byte(tc.Text), &got)
	if got.ReceivedExpectedSecret {
		t.Errorf("ReceivedExpectedSecret = true for mismatched secrets, want false")
	}
	if strings.Contains(tc.Text, "actual-value") || strings.Contains(tc.Text, "different-value") {
		t.Fatalf("LEAK: result contains a raw secret value: %s", tc.Text)
	}
}
