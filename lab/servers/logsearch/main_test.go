package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T) (*mcp.ClientSession, func()) {
	t.Helper()
	server := newServer()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()

	go server.Connect(ctx, st, nil)

	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return sess, func() { sess.Close() }
}

func callTool(t *testing.T, sess *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("call tool %s: %v", name, err)
	}
	return res
}

// textOf returns the text of the sole content item. Exactly 1 is
// asserted: the go-sdk's AddTool appends a duplicate TextContent
// fallback when a handler's structured return value isn't
// object-shaped, which is exactly why the search handlers wrap their
// []LogEntry results in searchResult before returning them (see
// textResult) -- this assertion is what actually proves that wrapping
// works, not just documentation of a quirk to work around elsewhere.
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("expected exactly 1 content item, got %d: %#v", len(res.Content), res.Content)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

func TestSearchRelative(t *testing.T) {
	sess, closeFn := connect(t)
	defer closeFn()

	res := callTool(t, sess, "logsearch_search_relative", map[string]any{
		"query":         "failed login",
		"range_minutes": 30,
	})
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textOf(t, res))
	}

	var entries []LogEntry
	if err := json.Unmarshal([]byte(textOf(t, res)), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if !strings.Contains(e.Message, "failed login") {
			t.Errorf("entry %d message %q does not contain query text", i, e.Message)
		}
	}
}

func TestSearchKeyword(t *testing.T) {
	sess, closeFn := connect(t)
	defer closeFn()

	res := callTool(t, sess, "logsearch_search_keyword", map[string]any{
		"keyword": "ransomware",
	})
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textOf(t, res))
	}

	var entries []LogEntry
	if err := json.Unmarshal([]byte(textOf(t, res)), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if !strings.Contains(e.Message, "ransomware") {
			t.Errorf("entry %d message %q does not contain keyword", i, e.Message)
		}
	}
}

func TestSearchKeywordEmpty(t *testing.T) {
	sess, closeFn := connect(t)
	defer closeFn()

	res := callTool(t, sess, "logsearch_search_keyword", map[string]any{
		"keyword": "",
	})
	if !res.IsError {
		t.Fatalf("expected IsError=true for empty keyword, got false")
	}
	if textOf(t, res) == "" {
		t.Fatalf("expected an explanatory error message")
	}
}

func TestCredCheck(t *testing.T) {
	t.Setenv("MOCK_SECRET", "gl-TOK-qqq111")
	t.Setenv("MOCK_EXPECT", "gl-TOK-qqq111")

	sess, closeFn := connect(t)
	defer closeFn()

	res := callTool(t, sess, "logsearch_credcheck", nil)
	if res.IsError {
		t.Fatalf("unexpected error result: %s", textOf(t, res))
	}

	text := textOf(t, res)
	if strings.Contains(text, "gl-TOK-qqq111") {
		t.Fatalf("LEAK: credcheck result contains the raw secret: %s", text)
	}

	var got struct {
		ReceivedExpectedSecret bool   `json:"received_expected_secret"`
		Fingerprint            string `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.ReceivedExpectedSecret {
		t.Errorf("received_expected_secret = false, want true")
	}
	if got.Fingerprint == "" {
		t.Errorf("fingerprint is empty")
	}
}
