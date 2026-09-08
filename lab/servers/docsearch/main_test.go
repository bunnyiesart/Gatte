package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect spins up an in-memory docsearch server and connects a client
// to it, returning the client session. The caller must close the
// returned session.
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

func TestListIndices(t *testing.T) {
	sess := connect(t)
	defer sess.Close()

	ctx := context.Background()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "docsearch_list_indices"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got listIndicesResult
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Indices) != 3 {
		t.Fatalf("expected 3 indices, got %d: %+v", len(got.Indices), got.Indices)
	}
}

func TestSearchKnownIndex(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	index := fakeIndices[0].Index
	query := "failed login attempt"
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "docsearch_search",
		Arguments: map[string]any{"index": index, "query": query},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got []searchHit
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 hits, got %d: %+v", len(got), got)
	}
	for _, hit := range got {
		if hit.Index != index {
			t.Errorf("hit _index = %q, want %q", hit.Index, index)
		}
		if !strings.Contains(hit.Source.Message, query) {
			t.Errorf("hit _source.message = %q, want it to contain %q", hit.Source.Message, query)
		}
		if hit.Source.Timestamp == "" {
			t.Errorf("hit _source.timestamp is empty")
		}
	}
}

func TestSearchUnknownIndex(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "docsearch_search",
		Arguments: map[string]any{"index": "does-not-exist", "query": "anything"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError = true for unknown index, got false: %s", textOf(t, res))
	}
}

func TestCredCheck(t *testing.T) {
	t.Setenv("MOCK_SECRET", "os-PWD-zzz222")
	t.Setenv("MOCK_EXPECT", "os-PWD-zzz222")

	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "docsearch_credcheck"})
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
