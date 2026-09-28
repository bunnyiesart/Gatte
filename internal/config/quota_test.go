package config

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// [[quota.provider]] and [quota] (design/adr/0030-quota-por-analista.md)
// -----------------------------------------------------------------------

// quotaBlock is a well-formed account, used as the positive control that
// every refusal below is measured against. Written as a function so each
// test can break exactly one field and leave the rest correct.
func quotaBlock(fields ...string) string {
	block := "\n[[quota.provider]]\n"
	for _, f := range fields {
		block += f + "\n"
	}
	return block
}

const (
	quotaName     = `name     = "virustotal"`
	quotaUpstream = `upstream = "threatintel"`
	quotaLimit    = `limit    = 500`
	quotaWindow   = `window   = "24h"`
	quotaTools    = `tools    = ["threatintel.lookup_ip", "threatintel.virustotal"]`
)

func wellFormedQuota() string {
	return quotaBlock(quotaName, quotaUpstream, quotaLimit, quotaWindow, quotaTools)
}

// TestQuotaProviderLoads is the positive control for everything below, and
// also pins that the file's fields land where the domain expects them.
func TestQuotaProviderLoads(t *testing.T) {
	c := mustLoad(t, minimalConfig+wellFormedQuota())

	if len(c.Quota.Providers) != 1 {
		t.Fatalf("parsed %d accounts, want 1", len(c.Quota.Providers))
	}
	got := c.Quota.Providers[0]
	if got.Name != "virustotal" || got.Upstream != "threatintel" || got.Limit != 500 {
		t.Errorf("parsed %+v, want name=virustotal upstream=threatintel limit=500", got)
	}
	if got.Window != 24*time.Hour {
		t.Errorf("window = %v, want 24h", got.Window)
	}
	if !slices.Equal(got.Tools, []string{"threatintel.lookup_ip", "threatintel.virustotal"}) {
		t.Errorf("tools = %v", got.Tools)
	}

	plan, err := c.ToQuotaPlan()
	if err != nil {
		t.Fatalf("ToQuotaPlan: %v", err)
	}
	if n := len(plan.Providers()); n != 1 {
		t.Fatalf("plan holds %d accounts, want 1", n)
	}
}

// TestQuotaLimitCannotDisableTheCounter is the direct analogue of
// TestRefreshIntervalCannotDisableReobservation, and exists for the same
// reason: a security control that can be switched off by a value nobody
// reads as "off" gets switched off during an incident and found still off
// a quarter later.
//
// Absent is refused too, and that is the case worth having a test for: a
// block with a name, an upstream, a window and tools but no limit reads
// like a complete declaration, and TOML would hand it a zero.
func TestQuotaLimitCannotDisableTheCounter(t *testing.T) {
	cases := map[string]string{
		"zero":     quotaBlock(quotaName, quotaUpstream, `limit    = 0`, quotaWindow, quotaTools),
		"negative": quotaBlock(quotaName, quotaUpstream, `limit    = -1`, quotaWindow, quotaTools),
		"absent":   quotaBlock(quotaName, quotaUpstream, quotaWindow, quotaTools),
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadErr(t, minimalConfig+block)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load = %v, want ErrInvalid", err)
			}
			for _, want := range []string{"limit", "greater than zero"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

func TestQuotaWindowMustBePositive(t *testing.T) {
	cases := map[string]string{
		"zero":     quotaBlock(quotaName, quotaUpstream, quotaLimit, `window   = "0s"`, quotaTools),
		"negative": quotaBlock(quotaName, quotaUpstream, quotaLimit, `window   = "-1h"`, quotaTools),
		"absent":   quotaBlock(quotaName, quotaUpstream, quotaLimit, quotaTools),
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			err := loadErr(t, minimalConfig+block)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), "window") {
				t.Errorf("error does not mention the window: %v", err)
			}
		})
	}
}

// TestQuotaAccountWithNoToolsIsRefused: an account no tool spends is a
// limit that can never apply, which is a control that is off while the
// file reads as though it were on. Unlike a role with no tools -- which is
// a real thing, an onboarding role that may authenticate and not act --
// there is no account worth declaring and never charging.
func TestQuotaAccountWithNoToolsIsRefused(t *testing.T) {
	err := loadErr(t, minimalConfig+quotaBlock(quotaName, quotaUpstream, quotaLimit, quotaWindow, `tools    = []`))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "lists no tools") {
		t.Errorf("error does not say the account charges nothing: %v", err)
	}
}

// TestQuotaToolsMustBeNamespaced is the same quiet failure
// TestRoleToolsMustBeNamespaced guards against, one component over: the
// charge table is matched against the namespaced names Dispatch routes on,
// exactly and with no wildcard, so a bare "lookup_ip" matches no call. The
// block would load, the limit would read as enforced, and the account
// would be spent with nothing ever debited.
func TestQuotaToolsMustBeNamespaced(t *testing.T) {
	err := loadErr(t, minimalConfig+quotaBlock(quotaName, quotaUpstream, quotaLimit, quotaWindow, `tools    = ["lookup_ip"]`))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	for _, want := range []string{"not namespaced", "threatintel.lookup_ip"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// TestQuotaToolMustBelongToTheAccountsUpstream catches the paste this
// file's shape invites: an account declared on one backend listing a tool
// served by another. The account's key is held by exactly one upstream --
// it reaches it as one of that entry's EnvVarNames -- so a tool of any
// other backend cannot spend it. Charging one would bill an analyst for a
// call that consumed nothing, and, worse, leave the calls that DO spend
// the account uncounted while the file reads as covering them.
func TestQuotaToolMustBelongToTheAccountsUpstream(t *testing.T) {
	err := loadErr(t, minimalConfig+quotaBlock(quotaName, quotaUpstream, quotaLimit, quotaWindow,
		`tools    = ["threatintel.lookup_ip", "casemgmt.list_cases"]`))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	for _, want := range []string{"casemgmt.list_cases", "upstream \"casemgmt\"", "upstream \"threatintel\""} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// TestDuplicateQuotaAccountRejected: two blocks with one name are two
// budgets against one account -- the abuse.ch counting mistake wearing a
// different hat -- and since the counter is keyed by name, which block's
// limit applied would be decided by map order.
func TestDuplicateQuotaAccountRejected(t *testing.T) {
	err := loadErr(t, minimalConfig+wellFormedQuota()+wellFormedQuota())
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "declared more than once") {
		t.Errorf("error does not name the duplicate: %v", err)
	}
}

// TestQuotaUnknownKeyIsRefused: the loader's rule applies inside this
// section too. `limitt = 500` would otherwise parse, leave Limit at zero,
// and be refused for a missing limit -- which sends the operator to look
// at the wrong line. More to the point, it is the same class as
// `require_signd`: a misspelled key that is silently dropped reads as
// though it were applied.
func TestQuotaUnknownKeyIsRefused(t *testing.T) {
	err := loadErr(t, minimalConfig+quotaBlock(quotaName, quotaUpstream, `limitt   = 500`, quotaWindow, quotaTools))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "limitt") {
		t.Errorf("error does not name the unknown key: %v", err)
	}
}

// TestQuotaReportsEveryProblemAtOnce: an operator fixing this file should
// see the whole list in one run, as the rest of Validate already gives
// them. Three distinct mistakes, one load.
func TestQuotaReportsEveryProblemAtOnce(t *testing.T) {
	err := loadErr(t, minimalConfig+quotaBlock(quotaName, quotaUpstream, `limit    = 0`, `window   = "0s"`, `tools    = ["lookup_ip"]`))
	for _, want := range []string{"limit", "window", "not namespaced"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q -- the problems are not being accumulated: %v", want, err)
		}
	}
}

// TestNoQuotaSectionIsAnEmptyPlanAndNotAMissingOne pins the distinction
// the whole wiring rests on: a file with no account yields a plan that
// charges nothing, which is a plan. A nil one would make quota.NewGate
// refuse, which is what stops "the quota is off" from being expressible by
// leaving something out.
func TestNoQuotaSectionIsAnEmptyPlanAndNotAMissingOne(t *testing.T) {
	c := mustLoad(t, minimalConfig)
	if len(c.Quota.Providers) != 0 {
		t.Fatalf("parsed %d accounts from a file with none", len(c.Quota.Providers))
	}

	plan, err := c.ToQuotaPlan()
	if err != nil {
		t.Fatalf("ToQuotaPlan on a file with no accounts = %v, want nil", err)
	}
	if plan == nil {
		t.Fatal("ToQuotaPlan returned a nil plan; an installation with no account must still get a plan that charges nothing")
	}
	if n := len(plan.Providers()); n != 0 {
		t.Errorf("the empty plan holds %d accounts", n)
	}
	if charges := plan.Charges("threatintel.lookup_ip", time.Now()); len(charges) != 0 {
		t.Errorf("the empty plan charges %d account(s) for a call", len(charges))
	}
}

// TestToQuotaPlanDoesNotShareSlices is TestToAccessPolicyDoesNotShareSlices
// for the other domain type, and exists because the aliasing bug it guards
// against has been found in this codebase before: a plan sharing a backing
// array with the parsed file is a plan a later edit of the file can
// silently rewrite.
func TestToQuotaPlanDoesNotShareSlices(t *testing.T) {
	c := mustLoad(t, minimalConfig+wellFormedQuota())
	plan, err := c.ToQuotaPlan()
	if err != nil {
		t.Fatalf("ToQuotaPlan: %v", err)
	}

	c.Quota.Providers[0].Tools[0] = "threatintel.mutated"
	if got := plan.Providers()[0].Tools[0]; got != "threatintel.lookup_ip" {
		t.Errorf("mutating the parsed config changed the plan: tool is now %q", got)
	}

	// And the other direction: what Providers hands out is a copy too.
	plan.Providers()[0].Tools[0] = "threatintel.mutated_again"
	if got := plan.Providers()[0].Tools[0]; got != "threatintel.lookup_ip" {
		t.Errorf("mutating what Providers returned changed the plan: tool is now %q", got)
	}
}

// TestExampleConfigDocumentsTheQuota is the argument
// TestExampleConfigLoads already makes for refresh_interval and
// max_bytes, applied here: the example is where an operator finds out a
// control exists at all.
//
// The assertion is that the example TEACHES the section, not that it
// enables it. The shipped blocks are commented out on purpose -- no limit
// in this project has been measured against a real provider budget, and a
// number invented for an example is a number somebody copies into
// production, where it looks like a control and is not.
func TestExampleConfigDocumentsTheQuota(t *testing.T) {
	raw, err := os.ReadFile(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	text := string(raw)

	for _, want := range []string{"[[quota.provider]]", "mcp-gateway quota usage", "abuse.ch"} {
		if !strings.Contains(text, want) {
			t.Errorf("config.example.toml never mentions %q -- an operator reading it would not learn that the per-analyst quota exists, what it counts, or how to read consumption", want)
		}
	}

	// And it must not ship an enabled account: every limit in it is a
	// placeholder, and a placeholder that loads is a placeholder that
	// reaches production.
	c, err := Load(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("the example no longer loads: %v", err)
	}
	if len(c.Quota.Providers) != 0 {
		t.Errorf("the example declares %d live quota account(s); the numbers in it are placeholders and must stay commented out until somebody measures a real budget", len(c.Quota.Providers))
	}
}

// TestQuotaFreeTools covers the list that says, out loud, that a tool spends
// nothing. It buys nothing on the request path and that is the point: before
// it existed, "this tool is free" and "nobody remembered this tool" were the
// same state in the file, and for a tool of a budgeted upstream only one of
// those is safe -- the provider bills the call either way.
func TestQuotaFreeTools(t *testing.T) {
	t.Run("a well-formed list loads and reaches the plan", func(t *testing.T) {
		c := mustLoad(t, minimalConfig+wellFormedQuota()+
			"\n[quota]\nfree_tools = [\"threatintel.decode\", \"threatintel.lookup_cve\"]\n")
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate = %v, want nil", err)
		}
		plan, err := c.ToQuotaPlan()
		if err != nil {
			t.Fatalf("ToQuotaPlan: %v", err)
		}
		if !plan.IsDeclared("threatintel.decode") {
			t.Error("a tool listed in free_tools did not reach the plan as declared")
		}
		if plan.IsDeclared("threatintel.enrich") {
			t.Error("a tool nobody listed came back declared")
		}
	})

	for _, tc := range []struct {
		name string
		list string
		want string
	}{
		{
			name: "not namespaced",
			list: `free_tools = ["decode"]`,
			// A bare name matches no dispatched call, so the tool it was
			// meant to excuse would still be withheld -- the file would
			// look fixed and the tool would stay gone.
			want: "not namespaced",
		},
		{
			name: "empty entry",
			list: `free_tools = [""]`,
			want: "empty tool name",
		},
		{
			name: "listed twice",
			list: `free_tools = ["threatintel.decode", "threatintel.decode"]`,
			want: "listed more than once",
		},
		{
			name: "also charged to an account",
			list: `free_tools = ["threatintel.lookup_ip"]`,
			want: "also charged to account",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadErr(t, minimalConfig+wellFormedQuota()+"\n[quota]\n"+tc.list+"\n")
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Load = %v, want one wrapping ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load error does not say %q: %v", tc.want, err)
			}
		})
	}
}

// TestQuotaWhitespacePaddedToolsAreRefused: a quota account's tool and a
// free tool are matched exactly against the names Dispatch routes, so a
// padded name is a distinct map key from its trimmed form -- the line looks
// right and matches nothing. For an account that is a limit that never
// applies; for a free tool it is an excuse that excuses nothing, and the
// tool it was meant for stays withheld.
func TestQuotaWhitespacePaddedToolsAreRefused(t *testing.T) {
	cases := map[string]string{
		"quota tool trailing space": minimalConfig + `
[[quota.provider]]
name     = "virustotal"
upstream = "threatintel"
limit    = 5
window   = "24h"
tools    = ["threatintel.virustotal "]
`,
		"free tool trailing space": minimalConfig + `
[quota]
free_tools = ["threatintel.lookup_ip "]
`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			if err := loadErr(t, contents); !errors.Is(err, ErrInvalid) {
				t.Errorf("Load = %v, want ErrInvalid", err)
			}
		})
	}
}
