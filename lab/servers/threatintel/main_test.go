package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect spins up an in-memory threatintel server and connects a client to it,
// returning the client session. The caller must close the returned
// session.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := newServer()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()

	go func() {
		if _, err := server.Connect(ctx, st, nil); err != nil {
			t.Logf("server.Connect: %v", err)
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	return sess
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

func TestLookupIPKnownAddress(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "lookup_ip",
		Arguments: map[string]any{"ip": "203.0.113.42"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got lookupIPResult
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.IP != "203.0.113.42" {
		t.Errorf("IP = %q, want %q", got.IP, "203.0.113.42")
	}
	if got.Country == "" {
		t.Errorf("Country is empty, want a value")
	}
}

func TestLookupIPEmptyAddress(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "lookup_ip",
		Arguments: map[string]any{"ip": ""},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError = true for empty ip, got false: %s", textOf(t, res))
	}
}

func TestEnrichKnownAddress(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "enrich",
		Arguments: map[string]any{"ip": "203.0.113.42"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got enrichResult
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.IP != "203.0.113.42" {
		t.Errorf("IP = %q, want %q", got.IP, "203.0.113.42")
	}
	if got.VirusTotal.TotalEngines == 0 {
		t.Errorf("VirusTotal.TotalEngines is zero, want populated")
	}
	if len(got.Shodan.OpenPorts) == 0 {
		t.Errorf("Shodan.OpenPorts is empty, want populated")
	}
	if got.AbuseIPDB.AbuseConfidenceScore == 0 {
		t.Errorf("AbuseIPDB.AbuseConfidenceScore is zero, want populated")
	}
}

func TestEnrichEmptyAddress(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "enrich",
		Arguments: map[string]any{"ip": ""},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError = true for empty ip, got false: %s", textOf(t, res))
	}
}

func TestCredCheck(t *testing.T) {
	t.Setenv("MOCK_SECRET", "vt-KEY-abc123")
	t.Setenv("MOCK_EXPECT", "vt-KEY-abc123")

	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "threatintel_credcheck"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got struct {
		ReceivedExpectedSecret bool   `json:"received_expected_secret"`
		Fingerprint            string `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.ReceivedExpectedSecret {
		t.Errorf("ReceivedExpectedSecret = false, want true")
	}
	if got.Fingerprint == "" {
		t.Errorf("Fingerprint is empty")
	}
}
