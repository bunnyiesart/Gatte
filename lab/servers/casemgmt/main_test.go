package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect spins up an in-memory casemgmt server and connects a client to it,
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

func TestListCases(t *testing.T) {
	sess := connect(t)
	defer sess.Close()

	ctx := context.Background()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "list_cases"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got listCasesResult
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Cases) != 2 {
		t.Fatalf("expected 2 cases, got %d: %+v", len(got.Cases), got.Cases)
	}
}

func TestGetCaseKnownID(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	want := fakeCases[0]
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_case",
		Arguments: map[string]any{"case_id": want.CaseID},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textOf(t, res))
	}

	var got caseDetail
	if err := json.Unmarshal([]byte(textOf(t, res)), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.CaseID != want.CaseID {
		t.Errorf("CaseID = %q, want %q", got.CaseID, want.CaseID)
	}
	if got.Title != want.Title {
		t.Errorf("Title = %q, want %q", got.Title, want.Title)
	}
	if got.Description == "" {
		t.Errorf("Description is empty, want detail")
	}
	if got.Assignee == "" {
		t.Errorf("Assignee is empty, want detail")
	}
}

func TestGetCaseUnknownID(t *testing.T) {
	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_case",
		Arguments: map[string]any{"case_id": "does-not-exist"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError = true for unknown case ID, got false: %s", textOf(t, res))
	}
}

func TestCredCheck(t *testing.T) {
	t.Setenv("MOCK_SECRET", "casemgmt-TOK-xyz789")
	t.Setenv("MOCK_EXPECT", "casemgmt-TOK-xyz789")

	sess := connect(t)
	defer sess.Close()
	ctx := context.Background()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "casemgmt_credcheck"})
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
