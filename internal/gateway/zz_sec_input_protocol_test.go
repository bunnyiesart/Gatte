package gateway

// Input-protocol lens, ported from the internal tree's security pass of
// 24 Sep 2026: upstreams that advertise hostile tool definitions.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestSecSchemaAcceptedAtDiscoveryDoesNotPanicAddTool pins the invariant
// validateSchema documents: anything it accepts must be something
// mcp.Server.AddTool accepts without panicking. The x-mcp-header cases
// broke it (see the httpapi test for the end-to-end effect).
func TestSecSchemaAcceptedAtDiscoveryDoesNotPanicAddTool(t *testing.T) {
	schemas := []string{
		`{"type":"object"}`,
		`{"type":"object","properties":{"q":{"type":"string","x-mcp-header":"X-Q"}}}`,
		`{"type":"object","properties":{"q":{"type":"array","x-mcp-header":"X-Q"}}}`,
		`{"type":"object","properties":{"q":{"type":"string","x-mcp-header":"bad header"}}}`,
		`{"type":"object","properties":{"q":{"type":"string","x-mcp-header":""}}}`,
		`{"type":"object","properties":{"q":{"type":"string","x-mcp-header":7}}}`,
		`{"type":"object","properties":{"a":{"type":"string","x-mcp-header":"X"},"b":{"type":"string","x-mcp-header":"x"}}}`,
		`{"type":"object","properties":{"o":{"type":"object","properties":{"q":{"type":"array","x-mcp-header":"X-Q"}}}}}`,
	}
	var panicked []string
	for _, s := range schemas {
		if validateSchema(json.RawMessage(s)) != nil {
			continue
		}
		if p := secIPAddToolPanics(s); p != "" {
			panicked = append(panicked, fmt.Sprintf("%s => %s", s, p))
		}
	}
	if len(panicked) > 0 {
		t.Fatalf("validateSchema accepted schemas that make AddTool panic:\n  %s", strings.Join(panicked, "\n  "))
	}
	// And it must not refuse what the SDK serves: a valid annotation.
	if err := validateSchema(json.RawMessage(schemas[1])); err != nil {
		t.Errorf("validateSchema refused a valid x-mcp-header annotation: %v", err)
	}
}

func secIPAddToolPanics(schema string) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	srv.AddTool(&mcp.Tool{Name: "t", InputSchema: json.RawMessage(schema)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil })
	return ""
}

// FuzzSecValidateSchema: whatever validateSchema accepts must be a JSON
// object with "type":"object", and must not panic mcp.Server.AddTool.
// Seeds are benign; run with -fuzz to search.
func FuzzSecValidateSchema(f *testing.F) {
	for _, s := range []string{
		`{"type":"object"}`, `null`, `{}`, `{"type":"string"}`,
		`{"type":"object","properties":{"q":{"type":"string"}}}`,
		`{"type":"object","properties":{"q":{"type":"array","x-mcp-header":"X-Q"}}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if validateSchema(raw) != nil {
			return
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil || m["type"] != "object" {
			t.Fatalf("accepted %q", raw)
		}
		if !utf8.Valid(raw) {
			return // the SDK remarshal path is not what this target is about
		}
		if p := secIPAddToolPanics(string(raw)); p != "" {
			t.Fatalf("accepted schema %q panics AddTool: %s", raw, p)
		}
	})
}
