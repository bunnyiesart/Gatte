// Package mockutil is shared infrastructure for the lab's mock MCP
// servers (lab/README.md). It exists so every mock implements the
// <name>_credcheck pattern identically -- this is a security-sensitive
// piece of test code (it exists specifically to prove a secret did or
// did not leak) and should have exactly one implementation, not four
// independently-written ones.
package mockutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CredCheckArgs is the (empty) input to a credcheck tool -- it takes no
// arguments, since what it reports comes from its own process
// environment, not from the caller.
type CredCheckArgs struct{}

// CredCheckResult is what a credcheck tool reports: whether the value in
// the MOCK_SECRET environment variable matched MOCK_EXPECT, plus a short
// fingerprint of what MOCK_SECRET actually held.
//
// Never a field for the secret value itself -- that is the entire point
// of this type existing.
type CredCheckResult struct {
	// ReceivedExpectedSecret is true if MOCK_SECRET's value, at the
	// moment this tool ran, equaled MOCK_EXPECT's value, and neither was
	// empty.
	ReceivedExpectedSecret bool `json:"received_expected_secret"`
	// Fingerprint is the first 8 hex characters of SHA-256(MOCK_SECRET).
	// It lets a test confirm *which* value arrived without the value
	// itself ever appearing in a tool result, a log line, or an MCP
	// message on the wire.
	Fingerprint string `json:"fingerprint"`
}

// AddCredCheck registers a tool named toolName on server implementing
// the <name>_credcheck pattern (lab/README.md): it reads MOCK_SECRET and
// MOCK_EXPECT from its own process environment (set by whatever spawned
// this mock -- in production this would be the gateway's Credential
// Vault; in a probe-driven test it is the probe itself) and reports
// whether they matched, plus a fingerprint of MOCK_SECRET -- never
// MOCK_SECRET's actual value.
//
// toolName should follow the "<upstream-name>_credcheck" convention,
// e.g. "casemgmt_credcheck", so a client aggregating multiple mocks can
// still tell which upstream answered.
func AddCredCheck(server *mcp.Server, toolName string) {
	mcp.AddTool(server, &mcp.Tool{
		Name: toolName,
		Description: "Reports whether this process received the expected secret " +
			"via the MOCK_SECRET environment variable, and a fingerprint of what " +
			"it actually received. Never returns the secret value itself.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ CredCheckArgs) (*mcp.CallToolResult, any, error) {
		secret := os.Getenv("MOCK_SECRET")
		expect := os.Getenv("MOCK_EXPECT")

		sum := sha256.Sum256([]byte(secret))
		result := CredCheckResult{
			ReceivedExpectedSecret: secret != "" && secret == expect,
			Fingerprint:            hex.EncodeToString(sum[:])[:8],
		}

		text, err := json.Marshal(result)
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(text)}},
		}, result, nil
	})
}
