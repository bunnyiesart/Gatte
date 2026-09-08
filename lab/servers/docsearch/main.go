// Command docsearch is a fake/mock stand-in for the real Docsearch MCP
// server (lab/README.md). It serves canned, synthetic index and search
// data over stdio so a gateway can be exercised end-to-end without
// touching a real Docsearch backend or its credentials.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// indexInfo is the shape of one entry returned by docsearch_list_indices:
// a fake Docsearch index and its made-up metadata.
type indexInfo struct {
	Index     string `json:"index"`
	DocsCount int    `json:"docs_count"`
	SizeMB    int    `json:"size_mb"`
}

// listIndicesArgs is the (empty) input to docsearch_list_indices.
type listIndicesArgs struct{}

// listIndicesResult is the output of docsearch_list_indices.
type listIndicesResult struct {
	Indices []indexInfo `json:"indices"`
}

// searchArgs is the input to docsearch_search.
type searchArgs struct {
	// Index is the name of the index to search, e.g. "logs-2026.09.01".
	Index string `json:"index" jsonschema:"the index name to search"`
	// Query is the free-text query to run against the index.
	Query string `json:"query" jsonschema:"the search query text"`
}

// searchHitSource is the nested _source object of one fake search hit.
type searchHitSource struct {
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// searchHit is the shape of one entry returned by docsearch_search.
type searchHit struct {
	Index  string          `json:"_index"`
	ID     string          `json:"_id"`
	Source searchHitSource `json:"_source"`
}

// searchResult wraps the hits from docsearch_search for structured
// output. The tool's unstructured Content is the bare JSON array of
// hits; this object wrapper is used only as the handler's structured
// (second) return value, since the SDK adds a redundant TextContent
// duplicate when a manually-set Content is non-object-shaped JSON.
type searchResult struct {
	Hits []searchHit `json:"hits"`
}

// fakeIndices are the three canned, clearly-synthetic indices this mock
// knows about. docsearch_list_indices serves this table directly, and
// docsearch_search validates its Index argument against it.
var fakeIndices = []indexInfo{
	{Index: "logs-2026.09.01", DocsCount: 148213, SizeMB: 512},
	{Index: "logs-2026.09.02", DocsCount: 152904, SizeMB: 531},
	{Index: "alerts-2026.09", DocsCount: 342, SizeMB: 4},
}

// knownIndex reports whether name matches one of fakeIndices.
func knownIndex(name string) bool {
	for _, idx := range fakeIndices {
		if idx.Index == name {
			return true
		}
	}
	return false
}

// newServer builds the docsearch mock's MCP server: registers the
// credential check tool plus the two fake domain tools,
// docsearch_list_indices and docsearch_search.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "docsearch", Version: "lab-mock"}, nil)

	mockutil.AddCredCheck(server, "docsearch_credcheck")

	mcp.AddTool(server, &mcp.Tool{
		Name:        "docsearch_list_indices",
		Description: "Lists fake Docsearch indices with metadata (synthetic test data, not a real backend).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ listIndicesArgs) (*mcp.CallToolResult, any, error) {
		result := listIndicesResult{Indices: fakeIndices}

		text, err := json.Marshal(result)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
		}, result, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "docsearch_search",
		Description: "Searches a fake Docsearch index and returns canned hits (synthetic test data, not a real backend).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
		if !knownIndex(args.Index) {
			msg := fmt.Sprintf("index not found: %q", args.Index)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				IsError: true,
			}, nil, nil
		}

		hits := []searchHit{
			{
				Index: args.Index,
				ID:    "fake-doc-1",
				Source: searchHitSource{
					Message:   fmt.Sprintf("synthetic log line matching query %q", args.Query),
					Timestamp: "2026-09-01T12:00:00Z",
				},
			},
			{
				Index: args.Index,
				ID:    "fake-doc-2",
				Source: searchHitSource{
					Message:   fmt.Sprintf("another synthetic log line for query %q", args.Query),
					Timestamp: "2026-09-01T12:05:00Z",
				},
			},
		}

		text, err := json.Marshal(hits)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
		}, searchResult{Hits: hits}, nil
	})

	return server
}

func main() {
	server := newServer()
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("docsearch mock server exited with error: %v", err)
	}
}
