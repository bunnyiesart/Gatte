package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// The quota console runs against the real adapter, like every other
// command here: the counters it prints are counters something actually
// reserved, so a rendering that drifts from what the component stores
// fails rather than agreeing with a fixture of itself.

// declareQuota puts one account in the environment's configuration, the
// way a [[quota.provider]] block would.
func declareQuota(e opTestEnv, providers ...config.QuotaProvider) {
	e.cfg.Quota.Providers = providers
}

func vtAccount() config.QuotaProvider {
	return config.QuotaProvider{
		Name:     "virustotal",
		Upstream: "threatintel",
		Limit:    500,
		Window:   24 * time.Hour,
		Tools:    []string{"threatintel.lookup_ip", "threatintel.virustotal"},
	}
}

// spend reserves n units for one analyst against one account, through the
// real store, so the counters the console reads were written by the same
// code the Gateway writes them with.
func spend(t *testing.T, e opTestEnv, analyst, account string, window time.Time, n int) {
	t.Helper()
	s := quotasqlite.New(e.db)
	for range n {
		err := s.Reserve(context.Background(), quota.Reservation{
			Analyst: analyst,
			Charges: []quota.Charge{{
				Provider:    account,
				Limit:       1000,
				WindowStart: window,
				WindowEnd:   window.Add(24 * time.Hour),
			}},
		})
		if err != nil {
			t.Fatalf("seeding %d unit(s) for %s/%s: %v", n, analyst, account, err)
		}
	}
}

var seedWindow = time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

func TestQuotaList_ShowsWhatTheFileDeclares(t *testing.T) {
	e := newOpTestEnv(t)
	declareQuota(e, vtAccount())
	mustRegister(t, e, stdioEntry("threatintel"))

	if code := runQuotaList(e.opEnv, false); code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, e.stderrText())
	}
	out := e.stdoutText()
	for _, want := range []string{"ACCOUNT", "virustotal", "threatintel", "500", "24h", "threatintel.lookup_ip"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
	// The arithmetic the operator has to do is stated where they will read
	// it, because a per-analyst limit multiplied by the team is the number
	// the provider actually sees.
	if !strings.Contains(out, "per analyst") {
		t.Errorf("the summary does not say the limit is per analyst:\n%s", out)
	}
}

func TestQuotaList_SaysSoWhenNothingIsDeclared(t *testing.T) {
	e := newOpTestEnv(t)

	if code := runQuotaList(e.opEnv, false); code != exitProblem {
		t.Fatalf("exit = %d, want %d for a file that budgets nothing", code, exitProblem)
	}
	out := e.stdoutText()
	if !strings.Contains(out, "quota.provider") {
		t.Errorf("the empty case does not say how to declare an account:\n%s", out)
	}
}

// TestQuotaList_ReportsARegistryThatDisagrees is the console half of
// gateway.CheckQuotaCoverage, and it matters that it is the same function:
// this disagreement is what will stop the gateway from serving on the next
// restart, and the operator should meet it while editing the file rather
// than after bouncing the process at 03:00.
func TestQuotaList_ReportsARegistryThatDisagrees(t *testing.T) {
	t.Run("upstream not registered", func(t *testing.T) {
		e := newOpTestEnv(t)
		declareQuota(e, vtAccount()) // threatintel is never registered

		if code := runQuotaList(e.opEnv, false); code != exitProblem {
			t.Fatalf("exit = %d, want %d", code, exitProblem)
		}
		out := e.stdoutText()
		for _, want := range []string{"refuses to", "not registered", "virustotal"} {
			if !strings.Contains(out, want) {
				t.Errorf("output does not mention %q:\n%s", want, out)
			}
		}
	})

	t.Run("an unbudgeted entry carries the budgeted credential", func(t *testing.T) {
		e := newOpTestEnv(t)
		declareQuota(e, vtAccount())
		budgeted := stdioEntry("threatintel")
		budgeted.EnvVarNames = []string{"THREATINTEL_VIRUSTOTAL_API_KEY"}
		canary := stdioEntry("threatintel-canary")
		canary.EnvVarNames = []string{"THREATINTEL_VIRUSTOTAL_API_KEY"}
		mustRegister(t, e, budgeted)
		mustRegister(t, e, canary)

		if code := runQuotaList(e.opEnv, false); code != exitProblem {
			t.Fatalf("exit = %d, want %d", code, exitProblem)
		}
		out := e.stdoutText()
		for _, want := range []string{"threatintel-canary", "THREATINTEL_VIRUSTOTAL_API_KEY", "without being counted"} {
			if !strings.Contains(out, want) {
				t.Errorf("output does not mention %q:\n%s", want, out)
			}
		}
	})
}

func TestQuotaList_JSONCarriesTheWholePolicy(t *testing.T) {
	e := newOpTestEnv(t)
	declareQuota(e, vtAccount())
	mustRegister(t, e, stdioEntry("threatintel"))

	if code := runQuotaList(e.opEnv, true); code != exitOK {
		t.Fatalf("exit = %d: %s", code, e.stderrText())
	}
	var got []struct {
		Name     string   `json:"name"`
		Upstream string   `json:"upstream"`
		Limit    int      `json:"limit"`
		Window   string   `json:"window"`
		Tools    []string `json:"tools"`
	}
	if err := json.Unmarshal([]byte(e.stdoutText()), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, e.stdoutText())
	}
	if len(got) != 1 || got[0].Name != "virustotal" || got[0].Limit != 500 || got[0].Window != "24h0m0s" {
		t.Fatalf("JSON = %+v", got)
	}
	if len(got[0].Tools) != 2 {
		t.Errorf("JSON carries %d tools, want 2", len(got[0].Tools))
	}
}

// TestQuotaUsage_ShowsConsumptionAgainstTheDeclaredLimit is the command
// the whole read port exists for: a limit nobody can observe consumption
// against is a number picked once and never checked, and its first signal
// is an analyst blocked mid-incident.
func TestQuotaUsage_ShowsConsumptionAgainstTheDeclaredLimit(t *testing.T) {
	e := newOpTestEnv(t)
	declareQuota(e, vtAccount())
	spend(t, e, "sub-analyst-1", "virustotal", seedWindow, 3)

	if code := runQuotaUsage(e.opEnv, quotaUsageFilter{}, false); code != exitOK {
		t.Fatalf("exit = %d: %s", code, e.stderrText())
	}
	out := e.stdoutText()
	for _, want := range []string{"ANALYST", "sub-analyst-1", "virustotal", "500"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
	// Used 3 of 500 leaves 497, and the remaining column is the reason an
	// operator opens this rather than doing the subtraction themselves.
	if !strings.Contains(out, "497") {
		t.Errorf("output does not show what is left:\n%s", out)
	}
}

func TestQuotaUsage_FiltersNarrowWhatIsShown(t *testing.T) {
	// Each subtest builds its own environment: the counters are the thing
	// under test, and a shared one would have each case asserting against
	// what its neighbours happened to spend.
	t.Run("by analyst", func(t *testing.T) {
		e := newOpTestEnv(t)
		declareQuota(e, vtAccount())
		spend(t, e, "sub-analyst-1", "virustotal", seedWindow, 1)
		spend(t, e, "sub-analyst-2", "virustotal", seedWindow, 1)

		if code := runQuotaUsage(e.opEnv, quotaUsageFilter{Analyst: "sub-analyst-2"}, false); code != exitOK {
			t.Fatalf("exit = %d: %s", code, e.stderrText())
		}
		out := e.stdoutText()
		if strings.Contains(out, "sub-analyst-1") {
			t.Errorf("the filter did not exclude the other analyst:\n%s", out)
		}
		if !strings.Contains(out, "sub-analyst-2") {
			t.Errorf("the filter excluded the analyst it was given:\n%s", out)
		}
	})

	t.Run("nothing matches", func(t *testing.T) {
		e := newOpTestEnv(t)
		declareQuota(e, vtAccount())
		spend(t, e, "sub-analyst-1", "virustotal", seedWindow, 1)

		code := runQuotaUsage(e.opEnv, quotaUsageFilter{Analyst: "sub-nobody"}, false)
		if code != exitProblem {
			t.Fatalf("exit = %d, want %d when nothing matches", code, exitProblem)
		}
		if !strings.Contains(e.stdoutText(), "sub-nobody") {
			t.Errorf("the empty answer does not repeat the filter, so the operator cannot see what they asked for:\n%s", e.stdoutText())
		}
	})

	t.Run("by window", func(t *testing.T) {
		e := newOpTestEnv(t)
		declareQuota(e, vtAccount())
		spend(t, e, "sub-analyst-1", "virustotal", seedWindow, 1)
		spend(t, e, "sub-analyst-1", "virustotal", seedWindow.Add(24*time.Hour), 2)

		if code := runQuotaUsage(e.opEnv, quotaUsageFilter{Since: seedWindow.Add(12 * time.Hour)}, false); code != exitOK {
			t.Fatalf("exit = %d: %s", code, e.stderrText())
		}
		out := e.stdoutText()
		if strings.Contains(out, "2026-09-14 00:00") {
			t.Errorf("-since did not exclude the earlier window:\n%s", out)
		}
		if !strings.Contains(out, "2026-09-15 00:00") {
			t.Errorf("-since excluded the window it should have kept:\n%s", out)
		}
	})
}

// TestQuotaUsage_KeepsCountersOfUndeclaredAccounts: a counter outlives the
// block that created it, and that history is exactly what somebody needs
// when reinstating or retuning an account they removed. Hiding the row
// would hide what the limit actually cost while it was in force.
func TestQuotaUsage_KeepsCountersOfUndeclaredAccounts(t *testing.T) {
	e := newOpTestEnv(t)
	declareQuota(e, vtAccount())
	spend(t, e, "sub-analyst-1", "shodan", seedWindow, 4) // no block declares shodan

	if code := runQuotaUsage(e.opEnv, quotaUsageFilter{}, false); code != exitOK {
		t.Fatalf("exit = %d: %s", code, e.stderrText())
	}
	out := e.stdoutText()
	if !strings.Contains(out, "shodan") {
		t.Errorf("the counter of an undeclared account was dropped:\n%s", out)
	}
	if !strings.Contains(out, "longer declares") {
		t.Errorf("the output does not explain why LIMIT is empty for it:\n%s", out)
	}
}

// TestQuotaUsage_JSONOmitsALimitItDoesNotHave pins the pointer fields: an
// undeclared account has no limit, and a zero would read as "no allowance
// left", which is a different and much more alarming claim.
func TestQuotaUsage_JSONOmitsALimitItDoesNotHave(t *testing.T) {
	e := newOpTestEnv(t)
	declareQuota(e, vtAccount())
	spend(t, e, "sub-analyst-1", "virustotal", seedWindow, 2)
	spend(t, e, "sub-analyst-1", "shodan", seedWindow, 1)

	if code := runQuotaUsage(e.opEnv, quotaUsageFilter{}, true); code != exitOK {
		t.Fatalf("exit = %d: %s", code, e.stderrText())
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(e.stdoutText()), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, e.stdoutText())
	}
	if len(got) != 2 {
		t.Fatalf("JSON holds %d counters, want 2", len(got))
	}
	for _, row := range got {
		switch row["account"] {
		case "virustotal":
			if row["limit"] != float64(500) || row["remaining"] != float64(498) {
				t.Errorf("declared account row = %+v, want limit 500 and remaining 498", row)
			}
			if row["window_end"] == nil {
				t.Errorf("declared account row has no window end: %+v", row)
			}
		case "shodan":
			if _, present := row["limit"]; present {
				t.Errorf("undeclared account row carries a limit: %+v", row)
			}
		default:
			t.Errorf("unexpected row: %+v", row)
		}
	}
}

// TestQuotaHasNoSubcommandThatLowersACounter pins ADR-0030 decision 8 at
// the surface an operator would actually reach for at 03:00.
//
// Returning 120 units to one analyst does not create 120 requests at
// VirusTotal; it takes them from the rest of the team, with no diff and no
// review. The escape valve is another analyst with budget making the call,
// and the fix for a limit that is wrong is an edit to the file.
func TestQuotaHasNoSubcommandThatLowersACounter(t *testing.T) {
	for _, sub := range []string{"reset", "clear", "grant", "refund", "set"} {
		out, errBuf := &strings.Builder{}, &strings.Builder{}
		if code := cmdQuota([]string{sub}, out, errBuf); code != exitCannotRun {
			t.Errorf("quota %s exited %d, want %d -- no command may hand an allowance back", sub, code, exitCannotRun)
		}
		if !strings.Contains(errBuf.String(), "unknown") {
			t.Errorf("quota %s was not reported as unknown: %s", sub, errBuf.String())
		}
	}
}

// TestOpenStoreMigratesTheQuotaTable is ADR-0030 Compliance item 9.
//
// The failure it exists to prevent is specific: a Migrate that is written,
// tested by its own package, and never added to the composition root's
// map. Every test that builds its own database would pass, and the first
// symptom would be "no such table: quota_counters" inside a request on the
// production host -- which is the exact failure that map exists to turn
// into a startup error.
func TestOpenStoreMigratesTheQuotaTable(t *testing.T) {
	cfg := &config.Config{Database: t.TempDir() + "/gateway.db"}

	db, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer db.Close()

	// Through the port, not through a raw query: what has to work is what
	// the console and the Gateway will do on the next boot.
	if _, err := quotasqlite.New(db).Usage(context.Background()); err != nil {
		t.Fatalf("reading counters from a freshly opened store: %v -- is quotasqlite.Migrate registered in openStore?", err)
	}
	if err := quotasqlite.New(db).Reserve(context.Background(), quota.Reservation{
		Analyst: "sub-analyst-1",
		Charges: []quota.Charge{{
			Provider:    "virustotal",
			Limit:       10,
			WindowStart: seedWindow,
			WindowEnd:   seedWindow.Add(24 * time.Hour),
		}},
	}); err != nil {
		t.Fatalf("reserving against a freshly opened store: %v", err)
	}

	// And the canary for this test: a database that was NOT opened through
	// openStore has no such table, so the assertions above are testing the
	// migration and not the adapter's tolerance.
	bare, err := store.Open(t.TempDir() + "/bare.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer bare.Close()
	if _, err := quotasqlite.New(bare).Usage(context.Background()); err == nil {
		t.Fatal("an unmigrated database answered a counter read, so this test would pass with no migration wired at all")
	}
}
