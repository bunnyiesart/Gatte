package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate is not idempotent: %v", err)
	}
	return db
}

var t0 = time.Date(2026, 9, 29, 13, 0, 0, 0, time.UTC)

func TestMaintenance_StartEndRoundTrip(t *testing.T) {
	s := New(newDB(t))
	ctx := context.Background()

	got, err := s.Maintenance(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("Maintenance on an empty table = %v, %v", got, err)
	}

	until := t0.Add(2 * time.Hour)
	res, err := s.Start(ctx, health.Maintenance{Target: "casemgmt", Message: `Troca de versão do "casemgmt" \ v2`, Until: until, SetBy: "(operator:alice)", SetAt: t0})
	if err != nil || !res.Changed || res.Previous != nil {
		t.Fatalf("first Start = %+v, %v", res, err)
	}
	if !res.Stored.StartedAt.Equal(t0) {
		t.Errorf("StartedAt = %v, want the first start's instant %v", res.Stored.StartedAt, t0)
	}

	// The same message and until again: nothing changes.
	res, err = s.Start(ctx, health.Maintenance{Target: "casemgmt", Message: `Troca de versão do "casemgmt" \ v2`, Until: until, SetBy: "(operator:bob)", SetAt: t0.Add(time.Minute)})
	if err != nil || res.Changed {
		t.Fatalf("repeated Start = %+v, %v; want changed false", res, err)
	}

	// Another message: updated, started_at kept, set_at and set_by moved.
	later := t0.Add(30 * time.Minute)
	res, err = s.Start(ctx, health.Maintenance{Target: "casemgmt", Message: "Atrasou", SetBy: "(operator:bob)", SetAt: later})
	if err != nil || !res.Changed || res.Previous == nil || res.Previous.Message == "Atrasou" {
		t.Fatalf("updating Start = %+v, %v", res, err)
	}
	if !res.Stored.StartedAt.Equal(t0) || !res.Stored.SetAt.Equal(later) || res.Stored.SetBy != "(operator:bob)" || !res.Stored.Until.IsZero() {
		t.Errorf("updated row = %+v, want started_at kept, set_* moved and until cleared", res.Stored)
	}

	if _, err := s.Start(ctx, health.Maintenance{Target: health.GatewayTarget, Message: "Atualização do binário", SetBy: "(operator:alice)", SetAt: t0}); err != nil {
		t.Fatal(err)
	}
	all, err := s.Maintenance(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("Maintenance = %v, %v; want two rows", all, err)
	}

	prev, err := s.End(ctx, "casemgmt")
	if err != nil || prev == nil || prev.Message != "Atrasou" {
		t.Fatalf("End = %+v, %v", prev, err)
	}
	prev, err = s.End(ctx, "casemgmt")
	if err != nil || prev != nil {
		t.Fatalf("second End = %+v, %v; want nothing ended", prev, err)
	}
}

// TestMaintenance_SurvivesARestart: the row is in the file, not in a
// process, so a second handle on the same database reads it.
func TestMaintenance_SurvivesARestart(t *testing.T) {
	path := t.TempDir() + "/gatte.db"
	open := func() *sql.DB {
		db, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := Migrate(db); err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := open()
	if _, err := New(db).Start(context.Background(), health.Maintenance{Target: "casemgmt", Message: "Reindexação", SetBy: "(operator:alice)", SetAt: t0}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db = open()
	defer db.Close()
	got, err := New(db).Maintenance(context.Background())
	if err != nil || len(got) != 1 || got[0].Message != "Reindexação" || !got[0].StartedAt.Equal(t0) {
		t.Fatalf("after reopening: %+v, %v", got, err)
	}
}

func TestValidateMessage(t *testing.T) {
	for label, msg := range map[string]string{
		"empty":           "   ",
		"newline":         "linha um\nlinha dois",
		"carriage return": "a\rb",
		"tab":             "a\tb",
		"C1 control":      "a\u0085b",
		"bidi override":   "a\u202eb",
		"zero width":      "a\u200bb",
		"line separator":  "a\u2028b",
		"201 runes":       strings.Repeat("é", 201),
	} {
		if _, err := health.ValidateMessage(msg); !errors.Is(err, health.ErrInvalid) {
			t.Errorf("%s: ValidateMessage = %v, want ErrInvalid", label, err)
		}
	}
	for label, msg := range map[string]string{
		"200 accented runes": strings.Repeat("é", 200),
		"quote and slash":    `Troca do "casemgmt" \ v2`,
	} {
		if _, err := health.ValidateMessage(msg); err != nil {
			t.Errorf("%s: ValidateMessage = %v, want nil", label, err)
		}
	}
	if got, _ := health.ValidateMessage("  aparado  "); got != "aparado" {
		t.Errorf("ValidateMessage did not trim: %q", got)
	}
}

func TestValidateUntil(t *testing.T) {
	if err := health.ValidateUntil(time.Time{}, t0); err != nil {
		t.Errorf("no until: %v", err)
	}
	for label, until := range map[string]time.Time{
		"past":          t0.Add(-time.Minute),
		"now":           t0,
		"over 90 days":  t0.Add(health.MaxUntilAhead + time.Minute),
		"mistyped year": t0.AddDate(10, 0, 0),
	} {
		if err := health.ValidateUntil(until, t0); !errors.Is(err, health.ErrInvalid) {
			t.Errorf("%s: ValidateUntil = %v, want ErrInvalid", label, err)
		}
	}
	if err := health.ValidateUntil(t0.Add(health.MaxUntilAhead), t0); err != nil {
		t.Errorf("exactly 90 days: %v", err)
	}
}

// TestWriteState_HealthAndListingInOneTransaction: the listing a backend
// is booted from must be the one written beside its health row, never one
// written without it.
func TestWriteState_HealthAndListingInOneTransaction(t *testing.T) {
	db := newDB(t)
	s := New(db)
	ctx := context.Background()

	snap := health.Snapshot{
		Backends: []health.BackendRecord{
			{Backend: "casemgmt", Live: true, Since: t0, UpdatedAt: t0},
			{Backend: "logsearch", Live: false, Since: t0, LastAttempt: t0, Cause: health.CauseNotBroughtUp, UpdatedAt: t0},
		},
		Listings: map[string][]health.ListedTool{"casemgmt": {{Tool: "list_cases", Hash: "aa"}, {Tool: "get_case", Hash: "bb"}}},
		ListedAt: t0,
		Serve:    &health.ServeStatus{Boot: t0, LastRoundAt: t0, RoundInterval: 5 * time.Minute},
	}
	if err := s.WriteState(ctx, snap); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	backends, err := s.Backends(ctx)
	if err != nil || len(backends) != 2 || backends[1].Cause != health.CauseNotBroughtUp {
		t.Fatalf("Backends = %+v, %v", backends, err)
	}
	listings, err := s.Listings(ctx)
	if err != nil || len(listings["casemgmt"]) != 2 {
		t.Fatalf("Listings = %+v, %v", listings, err)
	}
	st, ok, err := s.Serve(ctx)
	if err != nil || !ok || st.RoundInterval != 5*time.Minute || !st.Boot.Equal(t0) {
		t.Fatalf("Serve = %+v, %v, %v", st, ok, err)
	}

	// A write that fails part-way leaves the previous state whole: the
	// listing is rewritten only with its health row.
	if _, err := db.Exec(`CREATE TRIGGER refuse_health BEFORE INSERT ON backend_health BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	snap.Listings = map[string][]health.ListedTool{"casemgmt": {{Tool: "list_cases", Hash: "cc"}}}
	if err := s.WriteState(ctx, snap); err == nil {
		t.Fatal("WriteState succeeded through a refusing trigger")
	}
	listings, _ = s.Listings(ctx)
	if len(listings["casemgmt"]) != 2 {
		t.Errorf("the listing was rewritten although its health row was not: %+v", listings)
	}

	// A backend absent from the next snapshot loses its health row.
	if _, err := db.Exec(`DROP TRIGGER refuse_health`); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState(ctx, health.Snapshot{Backends: snap.Backends[:1]}); err != nil {
		t.Fatal(err)
	}
	if backends, _ := s.Backends(ctx); len(backends) != 1 {
		t.Errorf("Backends = %+v, want only casemgmt", backends)
	}
}

func TestForget_RemovesEveryTraceOfAName(t *testing.T) {
	s := New(newDB(t))
	ctx := context.Background()
	_, _ = s.Start(ctx, health.Maintenance{Target: "casemgmt", Message: "x", SetBy: "(operator:a)", SetAt: t0})
	_ = s.WriteState(ctx, health.Snapshot{
		Backends: []health.BackendRecord{{Backend: "casemgmt", Live: true, Since: t0, UpdatedAt: t0}},
		Listings: map[string][]health.ListedTool{"casemgmt": {{Tool: "list_cases", Hash: "aa"}}}, ListedAt: t0,
	})
	if err := s.Forget(ctx, "casemgmt"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.Maintenance(ctx)
	b, _ := s.Backends(ctx)
	l, _ := s.Listings(ctx)
	if len(m)+len(b)+len(l) != 0 {
		t.Errorf("after Forget: maintenance %v, health %v, listing %v", m, b, l)
	}
}
