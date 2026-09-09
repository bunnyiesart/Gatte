// Operator Console -- the "audit" subcommand: reading the Audit Trail.

package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// auditDefaultLimit is how many records "mcp-gateway audit" shows when
// -limit is not given. Big enough to cover the last few minutes of a busy
// shift, small enough to fit a scrollback without paging.
const auditDefaultLimit = 50

// auditFilter is the set of questions an operator can narrow the trail
// with. The zero value matches every record.
type auditFilter struct {
	// Limit caps how many of the *most recent* matching records are
	// shown. Zero means no cap.
	Limit int
	// Since excludes records older than this instant.
	Since time.Time
	// Subject restricts to one analyst identity, matched exactly.
	Subject string
	// Outcome restricts to one of allowed/denied/failed.
	Outcome audit.Outcome
}

// matches reports whether r passes every filter that is set.
func (f auditFilter) matches(r audit.Record) bool {
	if !f.Since.IsZero() && r.Timestamp.Before(f.Since) {
		return false
	}
	if f.Subject != "" && r.AnalystIdentity != f.Subject {
		return false
	}
	if f.Outcome != "" && r.Outcome != f.Outcome {
		return false
	}
	return true
}

// describe renders the active filters for the header line, so a reader can
// see at a glance what they are *not* being shown.
func (f auditFilter) describe() string {
	var parts []string
	if !f.Since.IsZero() {
		parts = append(parts, "since "+opTime(f.Since))
	}
	if f.Subject != "" {
		parts = append(parts, "subject "+f.Subject)
	}
	if f.Outcome != "" {
		parts = append(parts, "outcome "+string(f.Outcome))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// cmdAudit implements "mcp-gateway audit": read the audit trail.
func cmdAudit(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("audit", stderr)
	limit := fs.Int("limit", auditDefaultLimit, "show at most this many of the most recent matching records; 0 for all")
	since := fs.String("since", "", "only records at or after this RFC3339 timestamp, e.g. 2026-09-08T00:00:00Z")
	subject := fs.String("subject", "", "only records for this analyst identity (exact match)")
	outcome := fs.String("outcome", "", "only records with this outcome: allowed, denied or failed")
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	fs.Usage = func() { auditUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if !opNoArgs(fs, stderr) {
		return exitCannotRun
	}

	filter := auditFilter{Limit: *limit, Subject: *subject}
	if *limit < 0 {
		fmt.Fprintf(stderr, "-limit must not be negative (got %d); use 0 for no limit\n", *limit)
		return exitCannotRun
	}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(stderr, "-since %q is not an RFC3339 timestamp, e.g. 2026-09-08T00:00:00Z\n", *since)
			return exitCannotRun
		}
		filter.Since = t
	}
	if *outcome != "" {
		o := audit.Outcome(*outcome)
		if !o.Valid() {
			fmt.Fprintf(stderr, "-outcome %q is not one of %q, %q, %q\n", *outcome,
				audit.OutcomeAllowed, audit.OutcomeDenied, audit.OutcomeFailed)
			return exitCannotRun
		}
		filter.Outcome = o
	}

	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runAudit(e, filter, *asJSON)
	})
}

func auditUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway audit [-config FILE] [-limit N] [-since RFC3339]
                    [-subject IDENTITY] [-outcome allowed|denied|failed] [-json]

Prints the most recent matching records, NEWEST FIRST. OUTCOME and REASON
are the point of the trail: outcome says whether the gateway allowed,
denied or attempted-and-failed the call, and reason is the classification
the caller was deliberately not told.

Exit codes: 0 ok, 1 ran and found a problem (nothing matched), 2 could not run.
`)
}

// auditJSON is the -json shape of one audit record.
type auditJSON struct {
	Timestamp time.Time `json:"timestamp"`
	Analyst   string    `json:"analyst_identity"`
	Tool      string    `json:"tool"`
	Upstream  string    `json:"target_upstream"`
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason,omitempty"`
}

func runAudit(e *opEnv, filter auditFilter, asJSON bool) int {
	// audit.Recorder.List is the whole trail, oldest first, and there is
	// no filtered read on the port. Filtering here keeps the port small
	// and the ordering guarantee in one place; if this trail ever outgrows
	// memory, that is a change to the port, not to this command.
	all, err := e.auditTrail().List(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "audit trail: %v\n", err)
		return exitCannotRun
	}

	matching := make([]audit.Record, 0, len(all))
	for _, r := range all {
		if filter.matches(r) {
			matching = append(matching, r)
		}
	}

	// Oldest-first is the port's guarantee and the right one for an
	// append-only log. An operator reading during an incident wants the
	// other end of it, so take the newest Limit and reverse: "the last N
	// things that happened", most recent at the top.
	shown := matching
	if filter.Limit > 0 && len(shown) > filter.Limit {
		shown = shown[len(shown)-filter.Limit:]
	}
	newestFirst := make([]audit.Record, 0, len(shown))
	for i := len(shown) - 1; i >= 0; i-- {
		newestFirst = append(newestFirst, shown[i])
	}

	if asJSON {
		out := make([]auditJSON, 0, len(newestFirst))
		for _, r := range newestFirst {
			out = append(out, auditJSON{
				Timestamp: r.Timestamp,
				Analyst:   r.AnalystIdentity,
				Tool:      r.Tool,
				Upstream:  r.TargetUpstream,
				Outcome:   string(r.Outcome),
				Reason:    r.Reason,
			})
		}
		if err := opJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "writing json: %v\n", err)
			return exitCannotRun
		}
		if len(newestFirst) == 0 {
			return exitProblem
		}
		return exitOK
	}

	if len(newestFirst) == 0 {
		if len(all) == 0 {
			fmt.Fprint(e.stdout, "The audit trail is empty: no tool call has been recorded yet.\n")
		} else {
			fmt.Fprintf(e.stdout, "No audit records match those filters (%s). The trail holds %d %s\nin total.\n",
				filter.describe(), len(all), opPlural(len(all), "record", "records"))
		}
		return exitProblem
	}

	// Said before the table, not after it: which slice of the trail this
	// is, and in what order, is the first thing a reader needs and the
	// last thing they should have to infer from the rows.
	fmt.Fprintf(e.stdout, "Showing %d of %d matching %s, NEWEST FIRST.\nFilters: %s. The trail holds %d %s in total.\n\n",
		len(newestFirst), len(matching), opPlural(len(matching), "record", "records"),
		filter.describe(), len(all), opPlural(len(all), "record", "records"))

	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "TIME\tANALYST\tTOOL\tUPSTREAM\tOUTCOME\tREASON")
	for _, r := range newestFirst {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			opTime(r.Timestamp), r.AnalystIdentity, r.Tool, r.TargetUpstream, r.Outcome, opDash(r.Reason))
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "writing table: %v\n", err)
		return exitCannotRun
	}

	if filter.Limit > 0 && len(matching) > len(newestFirst) {
		fmt.Fprintf(e.stdout, "\n%d older matching %s not shown. Raise -limit, or narrow with -since.\n",
			len(matching)-len(newestFirst), opPlural(len(matching)-len(newestFirst), "record is", "records are"))
	}
	return exitOK
}
