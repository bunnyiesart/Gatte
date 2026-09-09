package mockutil

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCredCheckSmoke(t *testing.T) {
	t.Setenv("MOCK_SECRET", "sw1ss-abc123")
	t.Setenv("MOCK_EXPECT", "sw1ss-abc123")

	server := mcp.NewServer(&mcp.Implementation{Name: "smoke"}, nil)
	AddCredCheck(server, "threatintel_credcheck")

	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()

	serverDone := make(chan error, 1)
	go func() { _, err := server.Connect(ctx, st, nil); serverDone <- err }()

	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "threatintel_credcheck"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}

	if strings.Contains(tc.Text, "sw1ss-abc123") {
		t.Fatalf("LEAK: credcheck result contains the raw secret: %s", tc.Text)
	}

	var got CredCheckResult
	if err := json.Unmarshal([]byte(tc.Text), &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if !got.ReceivedExpectedSecret {
		t.Errorf("ReceivedExpectedSecret = false, want true")
	}
	if got.Fingerprint == "" {
		t.Errorf("Fingerprint is empty")
	}
	t.Logf("result: %+v (raw: %s)", got, tc.Text)
}

func TestCredCheckMismatch(t *testing.T) {
	os.Setenv("MOCK_SECRET", "actual-value")
	os.Setenv("MOCK_EXPECT", "different-value")
	defer os.Unsetenv("MOCK_SECRET")
	defer os.Unsetenv("MOCK_EXPECT")

	server := mcp.NewServer(&mcp.Implementation{Name: "smoke2"}, nil)
	AddCredCheck(server, "x_credcheck")
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go server.Connect(ctx, st, nil)
	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "x_credcheck"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}

	// received_expected_secret == false is the negative half of the
	// positive control every leak test in this repo keys off (see
	// internal/vault/sopsage/leak_test.go, internal/gateway/stdio,
	// internal/e2e, lab/servers/*): they all trust a *true* here to mean
	// "the secret really did arrive", and this is the only place the
	// false direction is pinned at all. So it has to be a claim that can
	// actually fail.
	//
	// It could not, before: the unmarshal error was discarded, and got is
	// the zero value on any error -- so "ReceivedExpectedSecret is false"
	// passed just as happily on a malformed body, an empty body, or a
	// tool that had stopped emitting the field at all. A control that
	// cannot fail is not a control.
	//
	// Three assertions make it falsifiable, in order: the payload parsed;
	// every key in it is one CredCheckResult declares
	// (DisallowUnknownFields, so a producer that drifts to a different
	// wire shape fails loudly here instead of decoding as a silent
	// false); and the fingerprint is present, proving we decoded a real
	// credcheck result and not an empty object that satisfies the first
	// two vacuously.
	//
	// Honest limit: because this test decodes with the very struct
	// AddCredCheck encodes with, a rename of the `json:"..."` tag itself
	// moves both sides at once and stays invisible here. What pins the
	// wire name is the four mock servers' own tests
	// (lab/servers/*/main_test.go), which declare
	// `json:"received_expected_secret"` in a separate, independently
	// written struct. This test's job is the narrower one: that a false
	// read here is a false the tool actually reported.
	dec := json.NewDecoder(strings.NewReader(tc.Text))
	dec.DisallowUnknownFields()
	var got CredCheckResult
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("unmarshal result %q: %v", tc.Text, err)
	}
	if got.Fingerprint == "" {
		t.Fatalf("Fingerprint is empty -- decoded %q as %+v, which is not a real credcheck result", tc.Text, got)
	}
	if got.ReceivedExpectedSecret {
		t.Errorf("ReceivedExpectedSecret = true for mismatched secrets, want false")
	}
	if strings.Contains(tc.Text, "actual-value") || strings.Contains(tc.Text, "different-value") {
		t.Fatalf("LEAK: result contains a raw secret value: %s", tc.Text)
	}
}
