package httpapi

// Behavioural tests of design/adr/0041 at the MCP boundary, written first
// against the wire alone and seen failing on the code before it.

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// killCasemgmt makes every call to casemgmt fail the way a dead stdio
// child does.
func (h *harness) killCasemgmt() {
	h.t.Helper()
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.callErr = fmt.Errorf("stdio: upstream %q: call tool: %w", "casemgmt", gateway.ErrUpstreamGone)
	up.mu.Unlock()
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// TestDownBackendCallIsAnIsErrorResultWithTheFixedText: the model reads a
// JSON-RPC error as its message and nothing else, and "internal error" said
// nothing about a backend being down (ADR-0041, Contexto 1-2).
func TestDownBackendCallIsAnIsErrorResultWithTheFixedText(t *testing.T) {
	h := newHarness(t)
	h.killCasemgmt()
	cs := h.session(tokenAnalyst)

	for i := 0; i < 2; i++ { // the in-flight death, then the known-dead backend
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: toolListCases, Arguments: map[string]any{}})
		if err != nil {
			t.Fatalf("call %d: CallTool error = %v, want an isError result", i, err)
		}
		text := resultText(res)
		if !res.IsError || !strings.Contains(text, `the backend "casemgmt" is unavailable since`) ||
			!strings.Contains(text, "This is not a problem with your request") || !strings.Contains(text, "gatte.status") {
			t.Errorf("call %d: result = isError %v %q, want the fixed unavailable text", i, res.IsError, text)
		}
		assertNoLeak(t, text)
	}
}

// TestInitializeCarriesTheInstructions: the instructions are the one text of
// the server the model always sees (ADR-0041, Contexto 4).
func TestInitializeCarriesTheInstructions(t *testing.T) {
	h := newHarness(t)
	cs := h.session(tokenAnalyst)
	got := cs.InitializeResult().Instructions
	if !strings.HasPrefix(got, "If a Gatte tool call fails saying its backend is unavailable") {
		t.Errorf("instructions = %q, want the directive first", got)
	}
	if got != serverInstructions {
		t.Errorf("with no contact and no backend notes configured the instructions are %q, want the constant", got)
	}
}

// TestGatteStatusIsAlwaysServed: even a caller with no tools has gatte.status.
func TestGatteStatusIsAlwaysServed(t *testing.T) {
	h := newHarness(t)
	for _, token := range []string{tokenAnalyst, tokenStranger} {
		cs := h.session(token)
		res, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		var names []string
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		if !slices.Contains(names, "gatte.status") {
			t.Errorf("%s: tools/list = %v, want gatte.status", token, names)
		}
	}
}

// TestSuspendedFleetAnswers503WithTheConstantText: every ListTools failure
// after admission is one 503 whose first sentence says it is temporary.
func TestSuspendedFleetAnswers503WithTheConstantText(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{blocklist: noBlocks{}})
	if err := h.db.Close(); err != nil {
		t.Fatal(err)
	}
	res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody)
	const want = "Gatte is temporarily unable to serve tools. This is not a problem with your request; retry in a few minutes or tell the user.\n"
	if got := body(t, res); res.StatusCode != http.StatusServiceUnavailable || got != want {
		t.Errorf("unreadable quarantine: %d %q, want 503 %q", res.StatusCode, got, want)
	}
}
