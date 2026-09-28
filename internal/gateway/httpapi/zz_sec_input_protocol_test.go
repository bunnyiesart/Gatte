package httpapi

// Input-protocol lens, ported from the internal tree's security pass of
// 24 Sep 2026: an upstream-controlled tool definition that
// mcp.Server.AddTool panics on must not take a caller's listing down.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
)

// secDo posts body with the given Authorization value and reports a
// transport-level failure instead of aborting the test, so a test can tell
// "the server answered with an error" from "the server dropped the
// connection" (which is what a panic in a handler looks like on the wire).
func secDo(h *harness, auth, body string) (int, string, error) {
	req, err := http.NewRequest(http.MethodPost, h.endpoint(), strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, string(b), err
}

// secToolNamesFromBody extracts the sorted tool names from a tools/list
// answer, JSON or a single SSE event.
func secToolNamesFromBody(body string) []string {
	payload := body
	if i := strings.Index(body, "data: "); i >= 0 {
		payload = body[i+len("data: "):]
		if j := strings.Index(payload, "\n"); j >= 0 {
			payload = payload[:j]
		}
	}
	var msg struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return []string{"<unparseable: " + err.Error() + ">"}
	}
	var names []string
	for _, tl := range msg.Result.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

// TestSecUpstreamSchemaWithInvalidHeaderAnnotationDoesNotTakeDownListing:
// InputSchema is upstream-controlled. gateway.validateSchema refuses the
// schemas that make mcp.Server.AddTool panic because of shape (absent,
// null, non-object type), but AddTool ALSO panics on an x-mcp-header
// annotation that is not on a primitive-typed property
// (validateParamHeaderAnnotations, go-sdk v1.7.0). Such a schema passed
// discovery; once the tool was approved, every request by every caller
// whose role included it panicked inside getServer and the connection was
// dropped -- tools/list and every other tool included.
func TestSecUpstreamSchemaWithInvalidHeaderAnnotationDoesNotTakeDownListing(t *testing.T) {
	h := newHarness(t)

	bomb := `{"type":"object","properties":{"q":{"type":"array","x-mcp-header":"X-Q"}}}`
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	for i := range up.defs {
		if up.defs[i].Name == "pending_tool" {
			up.defs[i].InputSchema = json.RawMessage(bomb)
		}
	}
	up.mu.Unlock()
	if err := h.gw.Refresh(context.Background()); err != nil {
		t.Logf("Refresh: %v", err)
	}
	if _, err := quarantinesql.New(h.db).Approve(context.Background(), "casemgmt", "pending_tool"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	status, out, err := secDo(h, "Bearer "+tokenAnalyst, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if err != nil {
		t.Fatalf("tools/list as analyst: connection dropped (handler panicked): %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("tools/list status %d body %.200q", status, out)
	}
	names := secToolNamesFromBody(out)
	if !slices.Contains(names, toolListCases) {
		t.Fatalf("one malformed approved tool hid the caller's other tools: %v", names)
	}
}
