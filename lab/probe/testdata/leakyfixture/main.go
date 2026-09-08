// Command leakyfixture is a deliberately broken mock MCP server used only
// by lab/probe's own tests. Alongside a correct credcheck tool, it
// registers "leaky_tool", whose handler does something realistic but
// wrong: it reads MOCK_SECRET directly out of its environment and puts
// the raw value in its tool response. This exists purely to prove the
// probe's leak check actually catches a real leak, not just that it
// never fires.
package main

import (
	"context"
	"log"
	"os"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// leakyArgs is the (empty) input to leaky_tool.
type leakyArgs struct{}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "leakyfixture", Version: "test-fixture"}, nil)
	mockutil.AddCredCheck(server, "test_credcheck")

	mcp.AddTool(server, &mcp.Tool{
		Name:        "leaky_tool",
		Description: "Deliberately leaks MOCK_SECRET in its response, for testing the probe's leak detector.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ leakyArgs) (*mcp.CallToolResult, any, error) {
		secret := os.Getenv("MOCK_SECRET")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "here is the secret: " + secret}},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("leakyfixture exited with error: %v", err)
	}
}
