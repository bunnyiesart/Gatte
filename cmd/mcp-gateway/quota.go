// Operator Console -- the "quota" subcommand: the per-analyst quota's
// operator surface (design/adr/0030-quota-por-analista.md).
//
// Two halves, because the component has two halves that live in different
// places on purpose: `quota list` prints the POLICY, read from the TOML
// file where a limit is a reviewed diff; `quota usage` prints the
// COUNTERS, read from the database where spending accumulates.
//
// # Why reading exists at all, and why writing does not
//
// A quota nobody can observe is a number picked once and never checked,
// and its first signal is an analyst blocked in the middle of an incident.
// Sizing a limit against a provider's real budget needs last month's
// consumption, not a guess -- so the operator reads.
//
// What the operator cannot do from here is lower a counter. There is no
// `quota reset`, deliberately (ADR-0030 decision 8): handing an analyst
// 120 units back does not create 120 lookups at VirusTotal, it takes them
// from the rest of the team, with no diff and no review. Raising a limit
// is a commit, a review and a restart, exactly as widening a role is.
//
// The read is a port of its own (quota.Reader) rather than a method on the
// one the Gateway holds, so that the request path cannot answer "what has
// this analyst been looking up" even by accident -- see the port
// declarations and the fitness function that keeps them apart.

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quota"
)

// cmdQuota implements "mcp-gateway quota": show the declared limits and
// what each analyst has spent.
func cmdQuota(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		quotaUsageText(stderr)
		return exitCannotRun
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return quotaList(rest, stdout, stderr)
	case "usage":
		return quotaUsage(rest, stdout, stderr)
	case "-h", "--help", "help":
		quotaUsageText(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown \"quota\" subcommand %q\n\n", sub)
		quotaUsageText(stderr)
		return exitCannotRun
	}
}

func quotaUsageText(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway quota list  [-config FILE] [-json]
  mcp-gateway quota usage [-config FILE] [-analyst SUBJECT] [-account NAME]
                          [-since RFC3339] [-json]

"list" shows the declared accounts: what the configuration file budgets,
and whether the registry agrees with it. "usage" shows the counters: what
each analyst has actually spent, per account, per window.

The counted unit is an ACCOUNT at a third party, not an upstream and not a
tool. One call to threatintel.lookup_ip can spend several accounts at once,
and one to threatintel.decode spends none. LIMIT is per analyst, and the window is FIXED
rather than sliding, so one analyst can spend LIMIT just before a boundary
and LIMIT again just after: the worst case against a provider is LIMIT
times TWICE the number of analysts.

There is deliberately no command that lowers a counter. Returning units to
one analyst does not create requests at the provider, it takes them from
everybody else. Raising a limit is an edit to the configuration file, a
review, and a restart.

Exit codes: 0 ok, 1 ran and found a problem (nothing to show, or the
registry and the file disagree), 2 could not run.
`)
}

// quotaProviderJSON is the -json shape of one declared account. It holds
// no counter: this half is the policy.
type quotaProviderJSON struct {
	Name     string   `json:"name"`
	Upstream string   `json:"upstream"`
	Limit    int      `json:"limit"`
	Window   string   `json:"window"`
	Tools    []string `json:"tools"`
}

func quotaList(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("quota list", stderr)
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	if code, ok := opParse(fs, args, stdout, stderr, quotaUsageText); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, quotaUsageText) {
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runQuotaList(e, *asJSON)
	})
}

func runQuotaList(e *opEnv, asJSON bool) int {
	plan, err := e.cfg.ToQuotaPlan()
	if err != nil {
		fmt.Fprintf(e.stderr, "quota: %v\n", err)
		return exitCannotRun
	}
	providers := plan.Providers()

	if asJSON {
		out := make([]quotaProviderJSON, 0, len(providers))
		for _, p := range providers {
			out = append(out, quotaProviderJSON{
				Name:     p.Name,
				Upstream: p.Upstream,
				Limit:    p.Limit,
				Window:   p.Window.String(),
				Tools:    p.Tools,
			})
		}
		if err := opJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "writing json: %v\n", err)
			return exitCannotRun
		}
		if len(providers) == 0 {
			return exitProblem
		}
		return exitOK
	}

	if len(providers) == 0 {
		fmt.Fprint(e.stdout, "No quota accounts are declared, so no call is charged.\n\n"+
			"That is the right state for a fleet whose backends all speak to internal\n"+
			"systems. It is the wrong one if any backend carries a third party's key:\n"+
			"declare the account with a [[quota.provider]] block naming the tools that\n"+
			"spend it. See config.example.toml.\n")
		return exitProblem
	}

	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "ACCOUNT\tUPSTREAM\tLIMIT\tWINDOW\tTOOLS")
	for _, p := range providers {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", p.Name, p.Upstream, p.Limit, p.Window, strings.Join(p.Tools, ", "))
	}
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}

	if free := plan.FreeTools(); len(free) > 0 {
		fmt.Fprintf(e.stdout, "\nDeclared to spend nothing (quota.free_tools): %s\n", strings.Join(free, ", "))
	}

	// The arithmetic, and it is written this way because the obvious version
	// of it is wrong by a factor of two. The window is fixed and truncated,
	// so two adjacent windows are two independent counters: an analyst who
	// spends the whole allowance just before the boundary and the whole
	// allowance just after has had 2 x LIMIT inside one window's length.
	// Measured: 200 calls in two seconds against a declared limit of 100 per
	// 24h. Printing "N x LIMIT" here would hand the operator a sizing rule
	// that under-provisions by half.
	fmt.Fprintf(e.stdout, "\n%d %s. LIMIT is per analyst per window, never a pool.\n"+
		"The window is FIXED, not sliding, so one analyst can spend LIMIT just before a\nboundary and LIMIT again just after: the worst case is 2 x LIMIT per analyst per\nwindow, and with N analysts 2 x N x LIMIT against the provider. Size LIMIT as\nbudget / (2 x analysts).\n",
		len(providers), opPlural(len(providers), "account", "accounts"))

	// The same function gateway.Connect applies at startup and
	// gateway.Reconcile applies every round, not a second opinion about it.
	// A disagreement here is what will stop the gateway from serving on the
	// next restart -- and, on a running one, from bringing any upstream up
	// -- and an operator should meet it while editing the file rather than
	// after bouncing the process.
	entries, err := e.upstreams().List(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}
	if err := gateway.CheckQuotaCoverage(plan, entries); err != nil {
		// errors.Join renders one problem per line, and every one of them
		// is a separate thing to fix -- indented so the block reads as the
		// detail of the sentence above it rather than as more prose.
		detail := "  " + strings.ReplaceAll(strings.TrimSpace(err.Error()), "\n", "\n  ")
		fmt.Fprintf(e.stdout, "\nThe registry does NOT match this file. Until it does, the gateway refuses to\nstart, and a running one brings no upstream up:\n\n%s\n", detail)
		return exitProblem
	}
	return exitOK
}

// quotaUsageJSON is the -json shape of one counter.
//
// Limit and Remaining are pointers because an account can be spent and
// then undeclared -- somebody removed the block, or renamed it -- and the
// counter outlives the policy. Zero would read as "no allowance left",
// which is a different and much more alarming thing than "no limit is
// declared for this any more".
type quotaUsageJSON struct {
	Analyst     string     `json:"analyst_identity"`
	Account     string     `json:"account"`
	WindowStart time.Time  `json:"window_start"`
	WindowEnd   *time.Time `json:"window_end,omitempty"`
	Used        int        `json:"used"`
	Limit       *int       `json:"limit,omitempty"`
	Remaining   *int       `json:"remaining,omitempty"`
}

// quotaUsageFilter narrows what "quota usage" shows. The zero value
// matches every counter.
type quotaUsageFilter struct {
	// Analyst restricts to one identity, matched exactly against the same
	// value the audit trail's ANALYST column carries.
	Analyst string
	// Account restricts to one provider account, matched exactly.
	Account string
	// Since excludes windows that started before this instant.
	Since time.Time
}

func (f quotaUsageFilter) matches(u quota.Usage) bool {
	if f.Analyst != "" && u.Analyst != f.Analyst {
		return false
	}
	if f.Account != "" && u.Provider != f.Account {
		return false
	}
	if !f.Since.IsZero() && u.WindowStart.Before(f.Since) {
		return false
	}
	return true
}

func (f quotaUsageFilter) describe() string {
	var parts []string
	if f.Analyst != "" {
		parts = append(parts, "analyst "+f.Analyst)
	}
	if f.Account != "" {
		parts = append(parts, "account "+f.Account)
	}
	if !f.Since.IsZero() {
		parts = append(parts, "since "+opTime(f.Since))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func quotaUsage(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("quota usage", stderr)
	analyst := fs.String("analyst", "", "only counters for this analyst identity (exact match, the audit trail's ANALYST value)")
	account := fs.String("account", "", "only counters for this provider account (exact match)")
	since := fs.String("since", "", "only windows starting at or after this RFC3339 timestamp, e.g. 2026-09-14T00:00:00Z")
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	if code, ok := opParse(fs, args, stdout, stderr, quotaUsageText); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, quotaUsageText) {
		return exitCannotRun
	}

	filter := quotaUsageFilter{Analyst: *analyst, Account: *account}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(stderr, "-since %q is not an RFC3339 timestamp, e.g. 2026-09-14T00:00:00Z\n", *since)
			return exitCannotRun
		}
		filter.Since = t
	}

	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runQuotaUsage(e, filter, *asJSON)
	})
}

func runQuotaUsage(e *opEnv, filter quotaUsageFilter, asJSON bool) int {
	// The declared plan, so each counter can be shown against the limit it
	// is being measured by. The limit is NOT stored beside the counter --
	// the schema has nowhere to put one, deliberately -- so this join is
	// the only place the two halves meet, and it happens in the console,
	// where an operator can see both sources named.
	plan, err := e.cfg.ToQuotaPlan()
	if err != nil {
		fmt.Fprintf(e.stderr, "quota: %v\n", err)
		return exitCannotRun
	}
	declared := map[string]quota.Provider{}
	for _, p := range plan.Providers() {
		declared[p.Name] = p
	}

	counters, err := e.quotaCounters().Usage(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "quota counters: %v\n", err)
		return exitCannotRun
	}

	matching := make([]quota.Usage, 0, len(counters))
	for _, u := range counters {
		if filter.matches(u) {
			matching = append(matching, u)
		}
	}
	// Newest window first, then analyst, then account: an operator reading
	// during an incident wants the window that is running now at the top,
	// which is the opposite of the port's storage order.
	sort.SliceStable(matching, func(i, j int) bool {
		a, b := matching[i], matching[j]
		if !a.WindowStart.Equal(b.WindowStart) {
			return a.WindowStart.After(b.WindowStart)
		}
		if a.Analyst != b.Analyst {
			return a.Analyst < b.Analyst
		}
		return a.Provider < b.Provider
	})

	if asJSON {
		out := make([]quotaUsageJSON, 0, len(matching))
		for _, u := range matching {
			row := quotaUsageJSON{
				Analyst:     u.Analyst,
				Account:     u.Provider,
				WindowStart: u.WindowStart,
				Used:        u.Used,
			}
			if p, ok := declared[u.Provider]; ok {
				limit := p.Limit
				remaining := max(p.Limit-u.Used, 0)
				end := u.WindowStart.Add(p.Window)
				row.Limit = &limit
				row.Remaining = &remaining
				row.WindowEnd = &end
			}
			out = append(out, row)
		}
		if err := opJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "writing json: %v\n", err)
			return exitCannotRun
		}
		if len(matching) == 0 {
			return exitProblem
		}
		return exitOK
	}

	if len(matching) == 0 {
		fmt.Fprintf(e.stdout, "No quota has been spent (filters: %s).\n", filter.describe())
		return exitProblem
	}

	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "WINDOW START\tANALYST\tACCOUNT\tUSED\tLIMIT\tREMAINING")
	undeclared := map[string]bool{}
	for _, u := range matching {
		limit, remaining := "-", "-"
		if p, ok := declared[u.Provider]; ok {
			limit = fmt.Sprintf("%d", p.Limit)
			remaining = fmt.Sprintf("%d", max(p.Limit-u.Used, 0))
		} else {
			undeclared[u.Provider] = true
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			opTime(u.WindowStart), u.Analyst, u.Provider, u.Used, limit, remaining)
	}
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}

	fmt.Fprintf(e.stdout, "\n%d %s (filters: %s). USED is per analyst per window and only ever\nrises; a window that has rolled over keeps its own row.\n",
		len(matching), opPlural(len(matching), "counter", "counters"), filter.describe())
	if len(undeclared) > 0 {
		names := make([]string, 0, len(undeclared))
		for name := range undeclared {
			names = append(names, name)
		}
		sort.Strings(names)
		// Shown rather than hidden: these rows are the only record of what
		// a limit cost while it was in force, and they are exactly what an
		// operator needs when reinstating or retuning an account somebody
		// removed.
		fmt.Fprintf(e.stdout, "\nLIMIT is \"-\" for %s: spent under a [[quota.provider]] block this file no\nlonger declares. The counters stand; nothing charges against them now.\n",
			strings.Join(names, ", "))
	}
	return exitOK
}
