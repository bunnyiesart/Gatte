// Command outputfixture is a mock MCP server used only by the stdio
// dialer's own tests (internal/gateway/stdio). It exists because none of
// the four lab backends declares an output schema
// (design/adr/0014-response-validation-scope.md checked this rather than
// assuming it), so without a fixture there is no traffic on the path that
// carries one, and the plumbing could be missing without a single test
// noticing.
//
// It declares an output schema on both of its tools and then answers,
// deliberately, one way that satisfies it and one way that does not. The
// second is the whole point: the dialer must carry an upstream's answer
// through unaltered, including a wrong one, so that the *gateway* is the
// thing that judges it. An adapter that quietly fixed up or dropped a
// non-conforming result would disarm the check one layer above it and
// leave the tests up there passing against data no backend ever sends.
//
// It uses the low-level [mcp.Server.AddTool] rather than the generic
// top-level [mcp.AddTool] for the same reason: the generic one validates
// its own output against the schema it inferred, which makes a
// deliberately non-conforming answer impossible to send.
package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// caseSchema is the output contract both tools below publish: an object
// with a required string case_id.
var caseSchema = json.RawMessage(`{"type":"object","properties":{"case_id":{"type":"string"}},"required":["case_id"]}`)

// emptyInput is the "any input is valid" input schema the SDK requires
// every tool to carry.
var emptyInput = json.RawMessage(`{"type":"object"}`)

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "outputfixture", Version: "test-fixture"}, nil)

	server.AddTool(&mcp.Tool{
		Name:         "structured_ok",
		Description:  "Answers with structured content that satisfies its declared output schema.",
		InputSchema:  emptyInput,
		OutputSchema: caseSchema,
	}, respondWith(`{"case_id":"7"}`))

	server.AddTool(&mcp.Tool{
		Name:         "structured_bad",
		Description:  "Answers with structured content that violates its declared output schema.",
		InputSchema:  emptyInput,
		OutputSchema: caseSchema,
		// case_id is a number here, and the schema says string. This is
		// what a backend swapped for a different implementation looks like
		// from the outside -- the half of a rug pull Tool Quarantine cannot
		// see, since the quarantine reads the tool's definition and never
		// what it returns.
	}, respondWith(`{"case_id":7}`))

	// No output schema and no structured content: the shape a backend that
	// predates SEP-2106 produces. It is here because it is surprisingly
	// hard to obtain otherwise -- the SDK's generic AddTool fills
	// structuredContent in from the handler's return value, so every lab
	// backend sends some -- and "the upstream sent none" has to be
	// representable end to end, as nothing rather than as a JSON null.
	server.AddTool(&mcp.Tool{
		Name:        "no_structure",
		Description: "Answers with content blocks only: no output schema, no structured content.",
		InputSchema: emptyInput,
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "plain text answer"}},
		}, nil
	})

	return server
}

// respondWith returns a handler that answers with structured content
// exactly as given, plus the text block a pre-SEP-2106 client would read.
func respondWith(structured string) mcp.ToolHandler {
	return func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content:           []mcp.Content{&mcp.TextContent{Text: structured}},
			StructuredContent: json.RawMessage(structured),
		}, nil
	}
}

func main() {
	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("outputfixture exited with error: %v", err)
	}
}
