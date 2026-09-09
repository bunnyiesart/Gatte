// Command logsearch is a fake/mock Logsearch MCP server used by the lab to
// test the gateway without touching a real Logsearch backend (lab/README.md).
// It returns canned, deterministic responses -- no network calls, no real
// log data -- and exposes logsearch_credcheck to prove credential injection
// works without ever leaking the injected secret.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// LogEntry is a single fake Logsearch log entry returned by the mock search
// tools.
type LogEntry struct {
	// Timestamp is an RFC3339 timestamp for the fake entry.
	Timestamp string `json:"timestamp"`
	// Source is the fake host or device that produced the entry.
	Source string `json:"source"`
	// Message is a short, made-up log line.
	Message string `json:"message"`
	// Level is the fake log severity, e.g. "info", "warning", or "error".
	Level string `json:"level"`
}

// SearchRelativeArgs is the input to logsearch_search_relative.
type SearchRelativeArgs struct {
	// Query is the Logsearch search query string.
	Query string `json:"query" jsonschema:"the Logsearch search query string"`
	// RangeMinutes is how many minutes back from now to search.
	RangeMinutes int `json:"range_minutes" jsonschema:"how many minutes back from now to search"`
}

// SearchKeywordArgs is the input to logsearch_search_keyword.
type SearchKeywordArgs struct {
	// Keyword is the keyword to search log messages for.
	Keyword string `json:"keyword" jsonschema:"the keyword to search log messages for"`
}

// searchResult wraps a []LogEntry as a JSON object rather than a bare
// array. It exists only for the *structured* half of a tool result
// (AddTool's second return value): the go-sdk (v1.7.0) auto-appends a
// duplicate TextContent block whenever a handler both sets Content
// manually and returns a non-object-shaped (array) structured value --
// it only skips that fallback when the structured output marshals to a
// JSON object. Content.Text itself stays the plain array; only the
// structured return value needs the wrapper.
type searchResult struct {
	Entries []LogEntry `json:"entries"`
}

// textResult builds a CallToolResult whose Content.Text is the JSON
// marshaling of content, with structured as the separate structured
// return value (see searchResult for why these are sometimes different
// shapes).
func textResult(content, structured any) (*mcp.CallToolResult, any, error) {
	text, err := json.Marshal(content)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
	}, structured, nil
}

func handleSearchRelative(_ context.Context, _ *mcp.CallToolRequest, args SearchRelativeArgs) (*mcp.CallToolResult, any, error) {
	entries := []LogEntry{
		{
			Timestamp: "2026-09-08T09:12:03Z",
			Source:    "fw-edge-01",
			Message:   fmt.Sprintf("connection accepted matching query %q", args.Query),
			Level:     "info",
		},
		{
			Timestamp: "2026-09-08T09:14:47Z",
			Source:    "vpn-gw-02",
			Message:   fmt.Sprintf("repeated auth retries observed for query %q", args.Query),
			Level:     "warning",
		},
		{
			Timestamp: "2026-09-08T09:15:31Z",
			Source:    "ids-sensor-03",
			Message:   fmt.Sprintf("signature match while evaluating query %q", args.Query),
			Level:     "error",
		},
	}
	return textResult(entries, searchResult{Entries: entries})
}

func handleSearchKeyword(_ context.Context, _ *mcp.CallToolRequest, args SearchKeywordArgs) (*mcp.CallToolResult, any, error) {
	if args.Keyword == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: "a keyword is required",
			}},
			IsError: true,
		}, nil, nil
	}

	entries := []LogEntry{
		{
			Timestamp: "2026-09-08T08:02:11Z",
			Source:    "proxy-01",
			Message:   fmt.Sprintf("blocked request containing keyword %q", args.Keyword),
			Level:     "warning",
		},
		{
			Timestamp: "2026-09-08T08:05:56Z",
			Source:    "mail-relay-02",
			Message:   fmt.Sprintf("message flagged for keyword %q", args.Keyword),
			Level:     "info",
		},
	}
	return textResult(entries, searchResult{Entries: entries})
}

// newServer builds the logsearch mock MCP server and registers all of its
// tools.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "logsearch", Version: "lab-mock"}, nil)

	mockutil.AddCredCheck(server, "logsearch_credcheck")

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_relative",
		Description: "Search fake Logsearch logs over a relative time range. Returns canned, deterministic results.",
	}, handleSearchRelative)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_keyword",
		Description: "Search fake Logsearch logs for a keyword. Returns canned, deterministic results.",
	}, handleSearchKeyword)

	return server
}

func main() {
	server := newServer()
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("logsearch mock server exited with error: %v", err)
	}
}
