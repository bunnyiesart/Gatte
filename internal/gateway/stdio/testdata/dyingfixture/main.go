// Command dyingfixture is a mock MCP server used only by the stdio
// dialer's own tests (internal/gateway/stdio). It exists so that a backend
// PROCESS DYING is a thing the test suite can produce on demand.
//
// Every other fixture here fails in ways that keep the connection alive: a
// tool that errors, a result that violates its schema, a schema that will
// not marshal. None of those is death, and the distinction is the whole of
// design/adr/0024 -- the gateway closes and re-dials an upstream it can
// recognise as gone, and must not do that to one that merely answered
// badly or answered late. Without a fixture that really exits, the only
// evidence for "gone" would be a hand-written error value, which proves
// that errors.Is works and nothing about what the SDK actually returns
// when a child's stdout reaches EOF.
//
// It serves one tool. Calling it terminates this process immediately,
// which is what a backend crashing looks like from the gateway's side:
// no protocol-level goodbye, just a stream that ends.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// emptyInput is the "any input is valid" input schema the SDK requires
// every tool to carry.
var emptyInput = json.RawMessage(`{"type":"object"}`)

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "dyingfixture", Version: "test-fixture"}, nil)

	server.AddTool(&mcp.Tool{
		Name:        "die",
		Description: "Exits this process without answering. Simulates a backend crash.",
		InputSchema: emptyInput,
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// os.Exit, not a panic and not a returned error: a panic would
		// still unwind through the SDK and might close the transport
		// politely, and an error is an answer. This is the process being
		// gone mid-sentence.
		os.Exit(7)
		return nil, nil
	})

	server.AddTool(&mcp.Tool{
		Name:        "alive",
		Description: "Answers normally, so a test can prove the connection worked before it stopped working.",
		InputSchema: emptyInput,
	}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "alive"}},
		}, nil
	})

	return server
}

func main() {
	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("dyingfixture exited with error: %v", err)
	}
}
