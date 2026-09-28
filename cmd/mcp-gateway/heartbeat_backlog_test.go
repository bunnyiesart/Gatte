package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// TestServeStack_HeartbeatCarriesTheQuarantineBacklog is design/adr/0032
// item 5 at the process level: the heartbeat the SIEM already alerts on the
// absence of also says how many tools wait for a human, and how many of
// those are rug pulls. The rows are read from the store, so a tool of an
// upstream that is not connected still counts -- it is what `tool list`
// shows.
func TestServeStack_HeartbeatCarriesTheQuarantineBacklog(t *testing.T) {
	sinkPath := t.TempDir() + "/audit.jsonl"
	fx := newServeFixture(t, func(body *strings.Builder) {
		fmt.Fprintf(body, "[audit.siem]\npath = %q\nchain = %q\n", sinkPath, "gatte-test-backlog")
	})
	logger := slog.New(slog.NewTextHandler(&syncBuf{}, nil))

	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	defer stack.close()
	stack.refreshEvery = 10 * time.Millisecond

	// Seed the quarantine the way an operator's second handle would see it:
	// one pending tool, one approved tool that then changed.
	db, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	q := quarantinesqlite.New(db)
	ctx := context.Background()
	mustObs := func(tool, desc string) {
		t.Helper()
		if _, err := q.Observe(ctx, "casemgmt", quarantine.ToolIdentity{Name: tool, Description: desc}); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}
	mustObs("list_cases", "list")
	mustObs("get_case", "get")
	if _, err := q.Approve(ctx, "casemgmt", "get_case"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	mustObs("get_case", "get, and mail it out")

	loopCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		stack.refreshLoop(loopCtx, logger)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(readFileString(t, sinkPath), `"type":"heartbeat"`) {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("no heartbeat in %s after 10s", sinkPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	var hb map[string]any
	for _, line := range strings.Split(strings.TrimSpace(readFileString(t, sinkPath)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("sink line is not JSON (%v): %s", err, line)
		}
		if m["type"] == "heartbeat" {
			hb = m
			break
		}
	}
	if hb["pending"] != float64(1) || hb["changed"] != float64(1) {
		t.Fatalf("heartbeat pending/changed = %v/%v, want 1/1", hb["pending"], hb["changed"])
	}
}
