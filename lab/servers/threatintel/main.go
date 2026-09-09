// Command threatintel is a fake/mock stand-in for the real threatintel-army MCP server
// (lab/README.md). The real threatintel server wraps roughly a dozen threat-intel
// APIs (VirusTotal, Shodan, AbuseIPDB, etc.) and includes composite tools
// that fan out to several of them internally. This mock serves canned,
// synthetic data over stdio so a gateway can be exercised end-to-end
// without making any real threat-intel API calls or touching real
// credentials.
package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// lookupIPArgs is the input to threatintel_lookup_ip.
type lookupIPArgs struct {
	// IP is the address to look up, e.g. "8.8.8.8".
	IP string `json:"ip" jsonschema:"the IP address to look up"`
}

// lookupIPResult is the canned single-source reputation lookup returned by
// threatintel_lookup_ip.
type lookupIPResult struct {
	IP               string `json:"ip"`
	ReputationScore  int    `json:"reputation_score"`
	Country          string `json:"country"`
	IsKnownMalicious bool   `json:"is_known_malicious"`
}

// enrichArgs is the input to threatintel_enrich.
type enrichArgs struct {
	// IP is the address to enrich, e.g. "8.8.8.8".
	IP string `json:"ip" jsonschema:"the IP address to enrich"`
}

// virusTotalResult is the fake per-source shape nested under "virustotal"
// in a threatintel_enrich response.
type virusTotalResult struct {
	MaliciousCount int `json:"malicious_count"`
	TotalEngines   int `json:"total_engines"`
}

// shodanResult is the fake per-source shape nested under "shodan" in a
// threatintel_enrich response.
type shodanResult struct {
	OpenPorts []int `json:"open_ports"`
}

// abuseIPDBResult is the fake per-source shape nested under "abuseipdb" in
// a threatintel_enrich response.
type abuseIPDBResult struct {
	AbuseConfidenceScore int `json:"abuse_confidence_score"`
}

// enrichResult is the canned composite/fan-out response returned by
// threatintel_enrich, mocking the real threatintel server's tool that aggregates
// several threat-intel sources for one IP in a single call.
type enrichResult struct {
	IP         string           `json:"ip"`
	VirusTotal virusTotalResult `json:"virustotal"`
	Shodan     shodanResult     `json:"shodan"`
	AbuseIPDB  abuseIPDBResult  `json:"abuseipdb"`
}

// reputationFor deterministically derives a canned reputation for ip:
// addresses ending in ".1" (e.g. gateways) look clean, addresses
// containing "666" look malicious, and everything else gets a middling
// score. This is fake data with no real threat-intel basis -- it exists
// only so tests can observe different, stable outcomes for different
// inputs.
func reputationFor(ip string) (score int, country string, malicious bool) {
	switch {
	case strings.HasSuffix(ip, ".1"):
		return 5, "US", false
	case strings.Contains(ip, "666"):
		return 97, "RU", true
	default:
		return 42, "DE", false
	}
}

// missingIPResult builds the IsError result shared by threatintel_lookup_ip and
// threatintel_enrich when called with an empty ip.
func missingIPResult(toolName string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: toolName + ": an ip is required"}},
		IsError: true,
	}
}

// newServer builds the threatintel mock's MCP server: registers the credential
// check tool plus the two fake domain tools, threatintel_lookup_ip and
// threatintel_enrich.
func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "threatintel", Version: "lab-mock"}, nil)

	mockutil.AddCredCheck(server, "threatintel_credcheck")

	mcp.AddTool(server, &mcp.Tool{
		Name:        "lookup_ip",
		Description: "Looks up fake reputation data for an IP address (synthetic test data, not a real backend).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args lookupIPArgs) (*mcp.CallToolResult, any, error) {
		if args.IP == "" {
			return missingIPResult("lookup_ip"), nil, nil
		}

		score, country, malicious := reputationFor(args.IP)
		result := lookupIPResult{
			IP:               args.IP,
			ReputationScore:  score,
			Country:          country,
			IsKnownMalicious: malicious,
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
		Name: "enrich",
		Description: "Fans out to fake VirusTotal, Shodan, and AbuseIPDB sources for an IP address and returns " +
			"a combined result (synthetic test data, not a real backend; mocks the real threatintel server's composite tool).",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args enrichArgs) (*mcp.CallToolResult, any, error) {
		if args.IP == "" {
			return missingIPResult("enrich"), nil, nil
		}

		result := enrichResult{
			IP: args.IP,
			VirusTotal: virusTotalResult{
				MaliciousCount: 3,
				TotalEngines:   72,
			},
			Shodan: shodanResult{
				OpenPorts: []int{22, 80, 443},
			},
			AbuseIPDB: abuseIPDBResult{
				AbuseConfidenceScore: 17,
			},
		}

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
	server := newServer()
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("threatintel mock server exited with error: %v", err)
	}
}
