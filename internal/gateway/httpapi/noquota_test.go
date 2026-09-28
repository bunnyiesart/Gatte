package httpapi

import (
	"testing"

	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// noQuota is the per-analyst quota of an installation with no [quota]
// section: a Gate over an empty plan, which admits every call without
// touching its store (design/adr/0030-quota-por-analista.md). The Gateway
// requires one; this is how "nothing is counted" is wired out loud.
func noQuota(t *testing.T) *quota.Gate {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quotasqlite.Migrate(db); err != nil {
		t.Fatalf("quota migrate: %v", err)
	}
	plan, err := quota.NewPlan(nil, nil)
	if err != nil {
		t.Fatalf("quota.NewPlan: %v", err)
	}
	gate, err := quota.NewGate(plan, quotasqlite.New(db))
	if err != nil {
		t.Fatalf("quota.NewGate: %v", err)
	}
	return gate
}
