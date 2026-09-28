package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestAddTool_TurnsASDKPanicIntoAnError pins the second guard in
// getServer: a definition the SDK refuses by panicking costs that one tool,
// not the request. The schema used breaks an x-mcp-header rule that
// gateway.validateSchema also refuses at discovery; here it is handed to
// addTool directly, as a rule discovery does not know about yet would be.
func TestAddTool_TurnsASDKPanicIntoAnError(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	noop := func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	}

	bad := json.RawMessage(`{"type":"object","properties":{"q":{"type":"array","x-mcp-header":"X-Q"}}}`)
	if err := addTool(srv, &mcp.Tool{Name: "bad", InputSchema: bad}, noop); err == nil {
		t.Fatal("addTool accepted a definition AddTool panics on")
	}
	good := json.RawMessage(`{"type":"object"}`)
	if err := addTool(srv, &mcp.Tool{Name: "good", InputSchema: good}, noop); err != nil {
		t.Fatalf("addTool refused a valid definition: %v", err)
	}
}
