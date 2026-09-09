// Command casemgmt is a fake/mock stand-in for the real CASEMGMT MCP server
// (lab/README.md). It serves canned, synthetic case data over stdio so a
// gateway can be exercised end-to-end without touching a real CASEMGMT
// backend or its credentials.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// caseSummary is the shape returned by casemgmt_list_cases: a short summary of
// one fake CASEMGMT case.
type caseSummary struct {
	CaseID   string `json:"case_id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
}

// caseDetail is the shape returned by casemgmt_get_case: a caseSummary plus
// the extra fields a single-case lookup would include.
type caseDetail struct {
	caseSummary
	Description string `json:"description"`
	Assignee    string `json:"assignee"`
}

// listCasesArgs is the (empty) input to casemgmt_list_cases.
type listCasesArgs struct{}

// listCasesResult is the output of casemgmt_list_cases.
type listCasesResult struct {
	Cases []caseSummary `json:"cases"`
}

// getCaseArgs is the input to casemgmt_get_case.
type getCaseArgs struct {
	// CaseID is the case identifier to look up, e.g. "57769".
	CaseID string `json:"case_id" jsonschema:"the case ID to fetch details for"`
}

// fakeCases are the two canned, clearly-synthetic cases this mock knows
// about. Both casemgmt_list_cases and casemgmt_get_case are served from this
// table.
var fakeCases = []caseDetail{
	{
		caseSummary: caseSummary{
			CaseID:   "57769",
			Title:    "IDS Enumeration Attack",
			Status:   "open",
			Severity: "high",
		},
		Description: "Synthetic test case: repeated port-scan and enumeration " +
			"attempts detected against a fake DMZ host in the lab environment.",
		Assignee: "analyst.fake@lab.example",
	},
	{
		caseSummary: caseSummary{
			CaseID:   "59456",
			Title:    "Suspicious Login From New Device",
			Status:   "closed",
			Severity: "low",
		},
		Description: "Synthetic test case: a lab user's fake account logged in " +
			"from an unrecognized device; confirmed benign after review.",
		Assignee: "analyst.fake@lab.example",
	},
}

// newServer builds the casemgmt mock's MCP server: registers the credential
// check tool plus the two fake domain tools, casemgmt_list_cases and
// casemgmt_get_case.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "casemgmt", Version: "lab-mock"}, nil)

	mockutil.AddCredCheck(server, "casemgmt_credcheck")

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_cases",
		Description: "Lists fake CASEMGMT case summaries (synthetic test data, not a real backend).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ listCasesArgs) (*mcp.CallToolResult, any, error) {
		result := listCasesResult{Cases: make([]caseSummary, len(fakeCases))}
		for i, c := range fakeCases {
			result.Cases[i] = c.caseSummary
		}

		text, err := json.Marshal(result)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
		}, result, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_case",
		Description: "Fetches full detail for one fake CASEMGMT case by ID (synthetic test data, not a real backend).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args getCaseArgs) (*mcp.CallToolResult, any, error) {
		for _, c := range fakeCases {
			if c.CaseID == args.CaseID {
				text, err := json.Marshal(c)
				if err != nil {
					return nil, nil, err
				}
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
				}, c, nil
			}
		}

		msg := fmt.Sprintf("case not found: %q", args.CaseID)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
			IsError: true,
		}, nil, nil
	})

	return server
}

func main() {
	server := newServer()
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("casemgmt mock server exited with error: %v", err)
	}
}
