// Command envfixture is a mock MCP server used only by the stdio dialer's
// own tests (internal/gateway/stdio). It answers one question the lab's
// credcheck convention cannot: *which* environment variables did the child
// actually end up with?
//
// lab/mockutil's credcheck tool reports on MOCK_SECRET and MOCK_EXPECT
// specifically, which proves injection worked but says nothing about what
// else leaked in from the gateway's own process environment. This fixture
// fills that gap so the dialer's environment-isolation property can be
// asserted directly rather than inferred.
//
// It reports variable *names* only, never values. That restriction is the
// whole design: a fixture that echoed values would be a tool for
// exfiltrating whatever the test process happened to be holding, and it
// would poison the dialer's own leak assertions -- the injected secret
// would legitimately appear in a tool result and there would be no way to
// tell a real leak from this fixture doing its job. Names are enough:
// isolation is a question about which variables exist, not what they hold.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// envNamesArgs is the (empty) input to env_names: what it reports comes
// from its own process environment, not from the caller.
type envNamesArgs struct{}

// envNamesResult is what env_names reports: the sorted names of every
// variable in this process's environment. Never a field for a value.
type envNamesResult struct {
	Names []string `json:"names"`
}

// envNames returns the sorted names of this process's environment
// variables, dropping the value half of every entry before it can go
// anywhere.
func envNames() []string {
	entries := os.Environ()
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// newServer builds the fixture's MCP server.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "envfixture", Version: "test-fixture"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "env_names",
		Description: "Reports the names of the environment variables this process was " +
			"spawned with. Never reports any variable's value.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ envNamesArgs) (*mcp.CallToolResult, any, error) {
		result := envNamesResult{Names: envNames()}
		text, err := json.Marshal(result)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
		}, result, nil
	})

	return server
}

func main() {
	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("envfixture exited with error: %v", err)
	}
}
