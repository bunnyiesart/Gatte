package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// hangingUpstream never answers tools/list until the caller's ctx dies --
// the "accepted the spawn, never replied" backend.
type hangingUpstream struct{}

func (hangingUpstream) ListTools(ctx context.Context) ([]ToolDef, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (hangingUpstream) CallTool(context.Context, string, json.RawMessage) (Result, error) {
	return Result{}, errors.New("no")
}
func (hangingUpstream) Close() error { return nil }

type mixedDialer struct{ hang string }

func (d mixedDialer) Dial(ctx context.Context, spec UpstreamSpec, _ map[string]string) (Upstream, error) {
	if spec.Name == d.hang {
		return hangingUpstream{}, nil
	}
	// A well-behaved dialer respects the ctx it was handed.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &fakeUpstream{}, nil
}

// Does ONE stalled upstream burn the whole connect budget, so the ctx that
// buildServer then hands to newStartupSummary is already expired?
func TestRefute3_ConnectBurnsWholeBudget(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quarantinesql.Migrate(db); err != nil {
		t.Fatalf("quarantine migrate: %v", err)
	}
	if err := auditsql.Migrate(db); err != nil {
		t.Fatalf("audit migrate: %v", err)
	}
	policy, err := access.NewPolicy([]access.Role{{Name: "r"}}, map[string]string{"s": "r"})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	var connLogs bytes.Buffer
	reg := &fakeRegistry{}
	for _, n := range []string{"casemgmt", "logsearch", "docsearch", "threatintel"} {
		reg.entries = append(reg.entries, registry.UpstreamServer{
			Name: n, Transport: registry.TransportStdio, Command: "/usr/bin/" + n,
		})
	}

	gw, err := New(Config{
		Registry:   reg,
		Vault:      newFakeVault(),
		Quarantine: quarantinesql.New(db),
		Audit:      auditsql.New(db),
		Policy:     policy,
		Dialer:     mixedDialer{hang: "logsearch"},
		Logger:     slog.New(slog.NewTextHandler(&connLogs, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	// Stand-in for config.DefaultConnectTimeout (30s), same shape.
	budget := 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	connErr := gw.Connect(ctx)
	elapsed := time.Since(start)

	t.Logf("Connect took %v of a %v budget; ctx.Err()=%v", elapsed, budget, ctx.Err())
	t.Logf("connErr = %v", connErr)
	t.Log("gateway log during Connect:\n" + connLogs.String())

	if ctx.Err() == nil {
		t.Errorf("the connect ctx SURVIVED a stalled upstream -- the finding's premise fails")
	}
	if elapsed < budget {
		t.Errorf("Connect returned before the budget was spent (%v < %v)", elapsed, budget)
	}
}
