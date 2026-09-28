package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// Windows are constants. Nothing in this package reads the clock -- the
// window start arrives inside a Charge, the way audit.Record receives its
// Timestamp -- so a rollover is exercised by passing a different constant
// rather than by waiting for midnight.
var (
	dayStart     = time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	nextDayStart = time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
)

func charge(provider string, limit int, windowStart time.Time) quota.Charge {
	return quota.Charge{
		Provider:    provider,
		Limit:       limit,
		WindowStart: windowStart,
		WindowEnd:   windowStart.Add(24 * time.Hour),
	}
}

func reservation(analyst string, charges ...quota.Charge) quota.Reservation {
	return quota.Reservation{Analyst: analyst, Charges: charges}
}

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return New(db), db
}

// newConcurrentStore returns a store backed by a real file rather than
// ":memory:", because the concurrency tests would otherwise prove nothing:
// internal/store pins the pool to a single connection for ":memory:" (a
// correctness requirement of that mode), and a single connection serialises
// transactions by itself. A file-backed pool opens as many connections as
// there are callers, which is the shape the production host runs.
//
// With busyTimeout it goes through store.Open, which is how production
// opens the file: store.Open puts busy_timeout and _txlock=immediate in the
// DSN of every connection. Without it the file is opened with the driver's
// defaults, whose busy handler gives up immediately: a second writer
// arriving during the first one's transaction is refused rather than
// queued. That refusal is fail-closed and is asserted on its own below, in
// TestReserve_ContentionIsRefusedAndNeverOverGranted -- it is what any
// handle opened without store.Open would produce.
func newConcurrentStore(t *testing.T, busyTimeout bool) (*Store, *sql.DB) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "quota.db")
	var (
		db  *sql.DB
		err error
	)
	if busyTimeout {
		db, err = store.Open(path)
	} else {
		// The same driver store.Open registers, with none of its pragmas.
		db, err = sql.Open("sqlite", "file:"+path)
	}
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { db.Close() })

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return New(db), db
}

// used reads a counter straight out of the table. Tests read the database
// directly rather than through an accessor on purpose: quota.Store has one
// method and no way to read a counter, because a counter is a record of
// what an analyst has been investigating and nothing in the gateway should
// be able to enumerate that. A read helper on the adapter would be the
// first step back towards one.
func used(t *testing.T, db *sql.DB, analyst, provider string, windowStart time.Time) int {
	t.Helper()

	var n int
	err := db.QueryRow(
		`SELECT used FROM quota_counters WHERE analyst = ? AND provider = ? AND window_start = ?`,
		analyst, provider, windowStart.Format(timeLayout),
	).Scan(&n)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0
	case err != nil:
		t.Fatalf("reading counter for %q/%q: %v", analyst, provider, err)
	}
	return n
}

func rowCount(t *testing.T, db *sql.DB) int {
	t.Helper()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM quota_counters`).Scan(&n); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	return n
}

// -----------------------------------------------------------------------
// Fail closed. First test in the file, as in the domain package.
// -----------------------------------------------------------------------

// TestReserve_FailsClosedWhateverBreaksTheCounter is the ADR-0004 class
// test against the real storage: a counter that cannot be read, a counter
// that cannot be written, a handle that is gone and a context that is
// already over all refuse the call. None of them is allowed to look like a
// grant, and none of them is allowed to look like exhaustion either --
// the gateway records those two as different reasons.
//
// The write case is the one the ADR insists on and it is here on purpose.
// The tempting distinction is "could not read is serious, could not write
// is infrastructure noise"; whoever wants free quota has no such
// preference, and if a failed write could pass, the attack is to make the
// write fail.
//
// The positive control at the end is what makes the rest mean anything: a
// store that refused everything would satisfy every case above.
func TestReserve_FailsClosedWhateverBreaksTheCounter(t *testing.T) {
	r := reservation("analyst-a", charge("virustotal", 10, dayStart))

	cases := []struct {
		name   string
		break_ func(t *testing.T, db *sql.DB) context.Context
	}{
		{
			// An unmigrated database, or one whose table was removed: the
			// counter cannot be read at all.
			name: "the counter table does not exist",
			break_: func(t *testing.T, db *sql.DB) context.Context {
				if _, err := db.Exec(`DROP TABLE quota_counters`); err != nil {
					t.Fatalf("dropping the table: %v", err)
				}
				return context.Background()
			},
		},
		{
			// The table is perfectly readable; only writing fails. This is
			// the half that must not be treated as recoverable.
			name: "the counter can be read but not written",
			break_: func(t *testing.T, db *sql.DB) context.Context {
				const trigger = `
CREATE TRIGGER quota_counters_readonly BEFORE INSERT ON quota_counters
BEGIN
	SELECT RAISE(ABORT, 'simulated write failure');
END;`
				if _, err := db.Exec(trigger); err != nil {
					t.Fatalf("installing the write-failure trigger: %v", err)
				}
				// Prove the read path still works, so the refusal below is
				// really about the write. QueryRow, not Query: the pool for
				// ":memory:" holds a single connection, and a *sql.Rows left
				// open would keep it forever.
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM quota_counters`).Scan(&n); err != nil {
					t.Fatalf("the table should still be readable: %v", err)
				}
				return context.Background()
			},
		},
		{
			name: "the database handle is closed",
			break_: func(t *testing.T, db *sql.DB) context.Context {
				if err := db.Close(); err != nil {
					t.Fatalf("closing the database: %v", err)
				}
				return context.Background()
			},
		},
		{
			name: "the context is already over",
			break_: func(t *testing.T, db *sql.DB) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := newTestStore(t)
			ctx := tc.break_(t, db)

			err := s.Reserve(ctx, r)
			if err == nil {
				t.Fatal("Reserve returned nil: a call whose consumption could not be counted was granted")
			}
			if errors.Is(err, quota.ErrExhausted) {
				t.Errorf("Reserve error = %v, wrapped ErrExhausted: a broken counter is not a spent one", err)
			}

			// And the whole stack: the domain classifies every one of these
			// as ErrUnavailable, which is what the gateway records as
			// "quota unavailable" before refusing the call.
			plan, perr := quota.NewPlan([]quota.Provider{{
				Name: "virustotal", Upstream: "threatintel", Limit: 10,
				Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip"},
			}}, nil)
			if perr != nil {
				t.Fatalf("NewPlan: %v", perr)
			}
			gate, gerr := quota.NewGate(plan, s)
			if gerr != nil {
				t.Fatalf("NewGate: %v", gerr)
			}
			if err := gate.Admit(ctx, "analyst-a", "threatintel.lookup_ip", dayStart.Add(12*time.Hour)); !errors.Is(err, quota.ErrUnavailable) {
				t.Errorf("Admit over a broken counter = %v, want ErrUnavailable", err)
			}
		})
	}

	t.Run("positive control: an intact counter grants the same call", func(t *testing.T) {
		s, db := newTestStore(t)
		if err := s.Reserve(context.Background(), r); err != nil {
			t.Fatalf("Reserve on an intact store = %v, want nil; the cases above would prove nothing if every call were refused", err)
		}
		if got := used(t, db, "analyst-a", "virustotal", dayStart); got != 1 {
			t.Errorf("used = %d, want 1", got)
		}
	})
}

// -----------------------------------------------------------------------
// Counting
// -----------------------------------------------------------------------

func TestMigrate_IsIdempotent(t *testing.T) {
	_, db := newTestStore(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

// TestSchema_HasNowhereToPutALimit pins ADR-0009 §2's split as a property
// of the table rather than a convention. The limit is policy and lives in
// the reviewed TOML; the counter is operational state and lives here. A
// limit column would be policy that an UPDATE could widen, with no diff,
// no review, and no history beyond this file -- which is exactly the
// arrangement that ADR rejected for roles.
func TestSchema_HasNowhereToPutALimit(t *testing.T) {
	_, db := newTestStore(t)

	rows, err := db.Query(`SELECT name FROM pragma_table_info('quota_counters')`)
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scanning a column name: %v", err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("reading the schema: %v", err)
	}

	want := []string{"analyst", "provider", "window_start", "used"}
	if !slices.Equal(columns, want) {
		t.Errorf("quota_counters has columns %v, want exactly %v.\n"+
			"A column holding a limit, an allowance or an override would move policy into the database, "+
			"where widening it leaves no reviewable diff (ADR-0009 §2, ADR-0030 decision 4).", columns, want)
	}
}

func TestReserve_CountsUpAndRoundTrips(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	r := reservation("analyst-a", charge("virustotal", 5, dayStart))

	for want := 1; want <= 3; want++ {
		if err := s.Reserve(ctx, r); err != nil {
			t.Fatalf("Reserve %d: %v", want, err)
		}
		if got := used(t, db, "analyst-a", "virustotal", dayStart); got != want {
			t.Errorf("used = %d after %d reservations, want %d", got, want, want)
		}
	}
	if got := rowCount(t, db); got != 1 {
		t.Errorf("rows = %d, want 1: one analyst, one account and one window is one counter", got)
	}
}

// TestReserve_StoresTheWindowStartAsUTCText pins the spelling, not just
// the instant. The window start is part of the primary key and is stored
// as text, so the same instant written with an offset would key a second
// counter for a window that already has one, and the allowance would
// silently double.
func TestReserve_StoresTheWindowStartAsUTCText(t *testing.T) {
	s, db := newTestStore(t)

	if err := s.Reserve(context.Background(), reservation("analyst-a", charge("virustotal", 5, dayStart))); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	var stored string
	if err := db.QueryRow(`SELECT window_start FROM quota_counters`).Scan(&stored); err != nil {
		t.Fatalf("reading window_start: %v", err)
	}
	if stored != "2026-09-14T00:00:00Z" {
		t.Errorf("window_start = %q, want %q", stored, "2026-09-14T00:00:00Z")
	}
}

// TestReserve_RefusedByQuotaDebitsNothing is one half of ADR-0030
// decision 5. The other half -- a call that fails at the upstream debits
// anyway, because the fan-out may already have spent the budget -- is not
// visible from here: it is a property of where the gate sits in Dispatch,
// and belongs to the gateway's tests.
func TestReserve_RefusedByQuotaDebitsNothing(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	r := reservation("analyst-a", charge("virustotal", 2, dayStart))

	for i := 1; i <= 2; i++ {
		if err := s.Reserve(ctx, r); err != nil {
			t.Fatalf("Reserve %d: %v", i, err)
		}
	}

	err := s.Reserve(ctx, r)
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("third Reserve against a limit of 2 = %v, want ErrExhausted", err)
	}
	if got := used(t, db, "analyst-a", "virustotal", dayStart); got != 2 {
		t.Errorf("used = %d after a refusal, want 2: a refused call does not spend quota", got)
	}

	// And the refusal keeps saying no, rather than drifting upwards with
	// each attempt -- the analyst in a loop must not ratchet the counter.
	for i := 0; i < 3; i++ {
		if err := s.Reserve(ctx, r); !errors.Is(err, quota.ErrExhausted) {
			t.Fatalf("Reserve after exhaustion = %v, want ErrExhausted", err)
		}
	}
	if got := used(t, db, "analyst-a", "virustotal", dayStart); got != 2 {
		t.Errorf("used = %d after four refusals, want 2", got)
	}
}

// TestReserve_IsAllOrNothingAcrossAccounts is the `lookup_ip` case: one
// call spends six accounts, and the gateway cannot ask the upstream to
// perform five sixths of a fan-out it does not control. If the last
// account is spent, the call is refused whole and none of the others is
// debited.
func TestReserve_IsAllOrNothingAcrossAccounts(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	// shodan is spent by an earlier call; the other two are untouched.
	if err := s.Reserve(ctx, reservation("analyst-a", charge("shodan", 1, dayStart))); err != nil {
		t.Fatalf("priming shodan: %v", err)
	}

	fanOut := reservation("analyst-a",
		charge("abuseipdb", 100, dayStart),
		charge("ipinfo", 100, dayStart),
		charge("shodan", 1, dayStart),
		charge("virustotal", 100, dayStart),
	)
	err := s.Reserve(ctx, fanOut)
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("Reserve with one spent account = %v, want ErrExhausted", err)
	}
	if !strings.Contains(err.Error(), "shodan") {
		t.Errorf("refusal %q does not name the spent account", err.Error())
	}

	for _, provider := range []string{"abuseipdb", "ipinfo", "virustotal"} {
		if got := used(t, db, "analyst-a", provider, dayStart); got != 0 {
			t.Errorf("used(%s) = %d after an all-or-nothing refusal, want 0", provider, got)
		}
	}
	if got := used(t, db, "analyst-a", "shodan", dayStart); got != 1 {
		t.Errorf("used(shodan) = %d, want 1: the refused attempt must not have debited it either", got)
	}
}

// TestReserve_CountersAreIsolatedPerAnalyst is why the limit is per
// analyst and not a pool. A pooled ceiling would let the first analyst in
// a loop exhaust everybody -- the defect this component exists to remove
// -- and would let one analyst infer from a shrinking balance that
// somebody else had been busy.
func TestReserve_CountersAreIsolatedPerAnalyst(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	spend := func(analyst string) error {
		return s.Reserve(ctx, reservation(analyst, charge("virustotal", 2, dayStart)))
	}

	for i := 1; i <= 2; i++ {
		if err := spend("analyst-a"); err != nil {
			t.Fatalf("analyst-a call %d: %v", i, err)
		}
	}
	if err := spend("analyst-a"); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("analyst-a third call = %v, want ErrExhausted", err)
	}

	for i := 1; i <= 2; i++ {
		if err := spend("analyst-b"); err != nil {
			t.Fatalf("analyst-b call %d = %v, want nil: one analyst's spending must not move another's balance", i, err)
		}
	}
	if got := used(t, db, "analyst-a", "virustotal", dayStart); got != 2 {
		t.Errorf("analyst-a used = %d, want 2", got)
	}
	if got := used(t, db, "analyst-b", "virustotal", dayStart); got != 2 {
		t.Errorf("analyst-b used = %d, want 2", got)
	}
}

// TestReserve_RefusalNamesTheAccountAndTheResetButNoAnalyst pins what the
// analyst reads and what they do not. The account name is not a secret --
// it is in the tool names and in the threatintel README -- and ADR-0030 decision
// 7 makes this refusal explicit rather than opaque, on the same line
// ErrForbidden already draws. An analyst identity in the message would be
// a component whose output describes somebody's investigative activity.
func TestReserve_RefusalNamesTheAccountAndTheResetButNoAnalyst(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const analyst = "0f3c-analyst-a-subject"
	r := reservation(analyst, charge("virustotal", 1, dayStart))

	if err := s.Reserve(ctx, r); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	err := s.Reserve(ctx, r)
	if !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("second Reserve = %v, want ErrExhausted", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "virustotal") {
		t.Errorf("refusal %q does not name the spent account", msg)
	}
	if !strings.Contains(msg, nextDayStart.Format(time.RFC3339)) {
		t.Errorf("refusal %q does not say when the window resets", msg)
	}
	if strings.Contains(msg, analyst) {
		t.Errorf("refusal %q names the analyst", msg)
	}
}

// -----------------------------------------------------------------------
// The window
// -----------------------------------------------------------------------

// TestReserve_TheNextWindowIsANewCounter exercises the rollover with two
// constants and no clock: a spent window stays spent and is not rewritten,
// and the next window starts at zero.
func TestReserve_TheNextWindowIsANewCounter(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	today := reservation("analyst-a", charge("virustotal", 1, dayStart))
	tomorrow := reservation("analyst-a", charge("virustotal", 1, nextDayStart))

	if err := s.Reserve(ctx, today); err != nil {
		t.Fatalf("first call of the day: %v", err)
	}
	if err := s.Reserve(ctx, today); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("second call of the same day = %v, want ErrExhausted", err)
	}
	if err := s.Reserve(ctx, tomorrow); err != nil {
		t.Errorf("first call of the next window = %v, want nil: a fixed window resets at its boundary", err)
	}

	if got := used(t, db, "analyst-a", "virustotal", dayStart); got != 1 {
		t.Errorf("the spent window's counter = %d, want 1: a rolled-over window is left behind, not rewritten", got)
	}
	if got := used(t, db, "analyst-a", "virustotal", nextDayStart); got != 1 {
		t.Errorf("the new window's counter = %d, want 1", got)
	}
	if got := rowCount(t, db); got != 2 {
		t.Errorf("rows = %d, want 2: each window keeps its own counter", got)
	}
}

// -----------------------------------------------------------------------
// Concurrency: the reservation is one atomic operation, not read-then-write
// -----------------------------------------------------------------------

// TestReserve_ConcurrentCallersNeverOverGrant is the test ADR-0030
// compliance item 3 names: N callers racing for N-1 units get exactly N-1
// grants.
//
// It is the reason Reserve increments first and asks afterwards. Dispatch
// serialises nothing -- N goroutines call concurrently over one session,
// with no queue and no pool, several per analyst under ADR-0035's cap --
// so an implementation that read the counter, compared it and wrote it
// back would let every caller read limit-1 and every caller pass, on a
// control whose whole purpose is to stop one analyst in a loop.
//
// The assertion is deliberately exact on both sides: the number of grants
// AND the counter left in the table. Counting only the grants would miss
// an implementation that refused correctly but debited twice; counting
// only the row would miss one that granted twice and debited once.
func TestReserve_ConcurrentCallersNeverOverGrant(t *testing.T) {
	const (
		callers = 16
		limit   = callers - 1
	)

	s, db := newConcurrentStore(t, true)
	r := reservation("analyst-a", charge("virustotal", limit, dayStart))

	var (
		mu        sync.Mutex
		granted   int
		exhausted int
		other     []error
	)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			err := s.Reserve(context.Background(), r)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				granted++
			case errors.Is(err, quota.ErrExhausted):
				exhausted++
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()

	for _, err := range other {
		t.Errorf("unexpected error from a concurrent Reserve: %v", err)
	}
	if granted != limit {
		t.Errorf("granted = %d of %d concurrent callers, want exactly %d (the limit)", granted, callers, limit)
	}
	if exhausted != callers-limit {
		t.Errorf("refused as exhausted = %d, want %d", exhausted, callers-limit)
	}
	if got := used(t, db, "analyst-a", "virustotal", dayStart); got != limit {
		t.Errorf("counter = %d after %d concurrent callers, want %d: a debit landed without a grant, or the other way round", got, callers, limit)
	}
}

// TestReserve_ContentionIsRefusedAndNeverOverGranted is the same race
// without a busy_timeout, which is what a handle opened without store.Open
// gets. SQLite then refuses the second writer immediately instead of
// queueing it.
//
// That refusal is the correct direction -- it is a refusal, and Gate.Admit
// turns it into ErrUnavailable, so the call does not go out. What this
// test pins is that contention never grants more than it debits, whatever
// the driver does with the collision. The operational cost of the
// refusals is why store.Open sets a busy timeout for every adapter: the
// audit trail writes a row per call on the same file.
func TestReserve_ContentionIsRefusedAndNeverOverGranted(t *testing.T) {
	const callers = 16

	s, db := newConcurrentStore(t, false)
	// A limit high enough that exhaustion cannot be what refuses anybody:
	// whatever is refused here is refused by contention.
	r := reservation("analyst-a", charge("virustotal", callers, dayStart))

	var (
		mu      sync.Mutex
		granted int
		refused int
	)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			err := s.Reserve(context.Background(), r)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				granted++
				return
			}
			refused++
			if errors.Is(err, quota.ErrExhausted) {
				t.Errorf("a caller under the limit was refused as exhausted: %v", err)
			}
		}()
	}
	wg.Wait()

	if granted+refused != callers {
		t.Fatalf("accounted for %d outcomes, want %d", granted+refused, callers)
	}
	if got := used(t, db, "analyst-a", "virustotal", dayStart); got != granted {
		t.Errorf("counter = %d but %d callers were granted: under contention a grant must be exactly a debit", got, granted)
	}
}

// -----------------------------------------------------------------------
// Input contract
// -----------------------------------------------------------------------

// TestReserve_RefusesAMalformedReservationAndWritesNothing keeps the
// domain's validation on the storage side of the port too. A Store is
// reachable by anything the composition root hands it to, and a
// reservation that skipped validation here could write a counter keyed by
// an empty analyst or by a window start spelled in the wrong offset --
// which is a second allowance for a window that already has one.
func TestReserve_RefusesAMalformedReservationAndWritesNothing(t *testing.T) {
	saoPaulo := time.FixedZone("-03", -3*60*60)

	cases := []struct {
		name string
		r    quota.Reservation
	}{
		{"no analyst", reservation("", charge("virustotal", 5, dayStart))},
		{"no charges", reservation("analyst-a")},
		{"window start carrying an offset", reservation("analyst-a", charge("virustotal", 5, dayStart.In(saoPaulo)))},
		{"the same account twice", reservation("analyst-a", charge("virustotal", 5, dayStart), charge("virustotal", 5, dayStart))},
		{"no limit", reservation("analyst-a", charge("virustotal", 0, dayStart))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := newTestStore(t)

			err := s.Reserve(context.Background(), tc.r)
			if !errors.Is(err, quota.ErrInvalidReservation) {
				t.Fatalf("Reserve = %v, want ErrInvalidReservation", err)
			}
			if got := rowCount(t, db); got != 0 {
				t.Errorf("the table holds %d row(s) after a refused reservation, want 0", got)
			}
		})
	}
}

// --------------------------------------------------------- the read port
//
// quota.Reader is the Operator Console's half of this adapter. Everything
// above is the Gateway's half, which can debit and cannot read; these
// tests are the other side of that separation, and the separation itself
// is asserted in the domain package.

// TestUsage_ReadsBackEveryCounterInOrder is the round trip: what Reserve
// wrote is what the console prints, in the order the port promises.
//
// Ordering is asserted rather than assumed because it is the port's
// documented guarantee and the console relies on it -- a table an operator
// scans at 03:00 that reshuffles between runs is a table they cannot
// compare against the last one.
func TestUsage_ReadsBackEveryCounterInOrder(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Written deliberately out of order, so passing cannot be an accident
	// of insertion sequence.
	writes := []struct {
		analyst  string
		provider string
		window   time.Time
		times    int
	}{
		{"analyst-b", "shodan", dayStart, 1},
		{"analyst-a", "virustotal", nextDayStart, 3},
		{"analyst-a", "virustotal", dayStart, 2},
		{"analyst-a", "abusech", dayStart, 1},
	}
	for _, w := range writes {
		for range w.times {
			if err := s.Reserve(ctx, reservation(w.analyst, charge(w.provider, 10, w.window))); err != nil {
				t.Fatalf("Reserve(%s, %s): %v", w.analyst, w.provider, err)
			}
		}
	}

	got, err := s.Usage(ctx)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	want := []quota.Usage{
		{Analyst: "analyst-a", Provider: "abusech", WindowStart: dayStart, Used: 1},
		{Analyst: "analyst-a", Provider: "virustotal", WindowStart: dayStart, Used: 2},
		{Analyst: "analyst-a", Provider: "virustotal", WindowStart: nextDayStart, Used: 3},
		{Analyst: "analyst-b", Provider: "shodan", WindowStart: dayStart, Used: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("Usage returned %d counters, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Analyst != want[i].Analyst || got[i].Provider != want[i].Provider || got[i].Used != want[i].Used {
			t.Errorf("counter %d = %+v, want %+v", i, got[i], want[i])
		}
		if !got[i].WindowStart.Equal(want[i].WindowStart) {
			t.Errorf("counter %d window = %s, want %s", i, got[i].WindowStart, want[i].WindowStart)
		}
		// UTC on the way out, so that two rows of the same window can
		// never print as two different windows.
		if _, offset := got[i].WindowStart.Zone(); offset != 0 {
			t.Errorf("counter %d window start is not UTC: %s", i, got[i].WindowStart)
		}
	}
}

// TestUsage_IsEmptyBeforeAnythingIsSpent: nothing spent is an empty list
// and not an error. The console says "no quota has been spent" on the
// strength of this, and an error here would have it report a broken
// database on a fresh install.
func TestUsage_IsEmptyBeforeAnythingIsSpent(t *testing.T) {
	s, _ := newTestStore(t)

	got, err := s.Usage(context.Background())
	if err != nil {
		t.Fatalf("Usage on a fresh database = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("Usage returned %d counters on a fresh database", len(got))
	}
}

// TestUsage_RefusedCallsAreNotInTheCounters closes the loop between the
// two halves of the adapter: a call refused for quota debits nothing, so
// the operator's view must not show it either. Reading a phantom unit
// would have somebody raise a limit that was never reached.
func TestUsage_RefusedCallsAreNotInTheCounters(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.Reserve(ctx, reservation("analyst-a", charge("virustotal", 1, dayStart))); err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := s.Reserve(ctx, reservation("analyst-a", charge("virustotal", 1, dayStart))); !errors.Is(err, quota.ErrExhausted) {
		t.Fatalf("second Reserve = %v, want ErrExhausted", err)
	}

	got, err := s.Usage(ctx)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if len(got) != 1 || got[0].Used != 1 {
		t.Errorf("Usage = %+v, want exactly one counter at 1: the refused call must not appear", got)
	}
}

// TestUsage_FailsLoudlyOnARowItDidNotWrite: every row this adapter writes
// formats its window start with timeLayout, so a row that will not parse
// means something else has written to the table. The operator reading
// consumption is told, rather than handed a silently shortened list -- the
// same fail-closed instinct the rest of the component is built on, applied
// to a read.
func TestUsage_FailsLoudlyOnARowItDidNotWrite(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	if err := s.Reserve(ctx, reservation("analyst-a", charge("virustotal", 10, dayStart))); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO quota_counters (analyst, provider, window_start, used) VALUES (?, ?, ?, ?)`,
		"analyst-a", "shodan", "last tuesday", 4); err != nil {
		t.Fatalf("seeding a hand-written row: %v", err)
	}

	got, err := s.Usage(ctx)
	if err == nil {
		t.Fatalf("Usage = %+v, want an error naming the unreadable row", got)
	}
	for _, want := range []string{"shodan", "last tuesday"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q, so an operator cannot find the row: %v", want, err)
		}
	}
}
