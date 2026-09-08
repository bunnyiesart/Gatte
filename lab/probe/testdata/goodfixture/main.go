// Command goodfixture is a minimal, correct mock MCP server used only by
// lab/probe's own tests. It registers a single credcheck tool via
// mockutil.AddCredCheck and nothing else -- it will never leak the
// secret it receives, and exists to prove the probe reports PASS/CLEAN
// against a server that behaves correctly.
package main

import (
	"context"
	"log"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "goodfixture", Version: "test-fixture"}, nil)
	mockutil.AddCredCheck(server, "test_credcheck")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("goodfixture exited with error: %v", err)
	}
}
