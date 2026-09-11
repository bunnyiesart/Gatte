// Operator Console -- the "audit" subcommand: reading the Audit Trail.

package main

import (
	"flag"
	"fmt"
	"io"
	"sort"
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
	// Source restricts to one source address, matched exactly. Exact
	// rather than a prefix or CIDR: a subnet match is a question about
	// the network's shape, which this command has no model of, and an
	// operator who wants one has -json and their own tools.
	Source string
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
	if f.Source != "" && r.SourceAddress != f.Source {
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
	if f.Source != "" {
		parts = append(parts, "source "+f.Source)
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
	source := fs.String("source", "", "only records from this source address (exact match)")
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	verify := fs.Bool("verify", false, "check the trail's hash chain instead of printing records")
	expectHead := fs.String("expect-head", "", "with -verify, fail unless the chain head equals this hash")
	if code, ok := opParse(fs, args, stdout, stderr, auditUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, auditUsage) {
		return exitCannotRun
	}

	// -verify reads the chain, not the filtered view, so a filter passed
	// alongside it would be silently ignored -- and an operator who
	// believes they verified "only Ana's records" has been told something
	// false by omission, which is the failure mode this whole component
	// exists to avoid. Refuse instead.
	if ignored := auditFlagsIgnoredByVerify(fs, *verify); len(ignored) > 0 {
		fmt.Fprintf(stderr, "-verify checks the whole chain and cannot be filtered; remove %s\n",
			strings.Join(ignored, ", "))
		return exitCannotRun
	}
	if *expectHead != "" && !*verify {
		fmt.Fprint(stderr, "-expect-head only means something with -verify\n")
		return exitCannotRun
	}
	if *verify {
		return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
			return runAuditVerify(e, *expectHead)
		})
	}

	filter := auditFilter{Limit: *limit, Subject: *subject, Source: *source}
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
                    [-subject IDENTITY] [-outcome allowed|denied|failed]
                    [-source ADDRESS] [-json]
  mcp-gateway audit -verify [-config FILE] [-expect-head HASH]

-verify checks the trail's hash chain instead of printing records: every
record carries a hash over its own fields and its predecessor's, so a
record edited or deleted in the MIDDLE of the trail stops verifying. It
cannot be combined with the filters above, which is refused rather than
ignored.

What -verify does NOT detect is truncation of the END: removing the last
N records leaves a shorter chain that verifies perfectly. -verify prints
the chain head; record that value somewhere this gateway cannot write,
and pass it back later as -expect-head to catch that case too.

Prints the most recent matching records, NEWEST FIRST. OUTCOME and REASON
are the point of the trail: outcome says whether the gateway allowed,
denied or attempted-and-failed the call, and reason is the classification
the caller was deliberately not told.

SOURCE is where the call came from, as the gateway's reverse proxy saw
it. One analyst identity arriving from two addresses is what a stolen
token looks like.

COUNTING: a call that was dispatched and then failed leaves two rows --
an "allowed" one written before the call, and a "failed" one written
after. The trail is append-only, so the first is never rewritten. Count
"-outcome allowed" for attempts, and read a "failed" row as an annotation
on the allowed row above it. A "-" means the record predates the column.

Rows attributed to (unauthenticated) are requests refused at the door:
no credential, or one that did not verify. The gateway deliberately does
not distinguish those, so neither can the trail; what it has is that the
attempt happened, when, and from where.

Exit codes: 0 ok, 1 ran and found a problem (nothing matched), 2 could not run.
`)
}

// auditJSON is the -json shape of one audit record.
type auditJSON struct {
	Timestamp     time.Time `json:"timestamp"`
	Analyst       string    `json:"analyst_identity"`
	Tool          string    `json:"tool"`
	Upstream      string    `json:"target_upstream"`
	Outcome       string    `json:"outcome"`
	Reason        string    `json:"reason,omitempty"`
	SourceAddress string    `json:"source_address,omitempty"`
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
				Timestamp:     r.Timestamp,
				Analyst:       r.AnalystIdentity,
				Tool:          r.Tool,
				Upstream:      r.TargetUpstream,
				Outcome:       string(r.Outcome),
				Reason:        r.Reason,
				SourceAddress: r.SourceAddress,
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
	fmt.Fprintln(tw, "TIME\tANALYST\tSOURCE\tTOOL\tUPSTREAM\tOUTCOME\tREASON")
	for _, r := range newestFirst {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			opTime(r.Timestamp), r.AnalystIdentity, opDash(r.SourceAddress), r.Tool,
			r.TargetUpstream, r.Outcome, opDash(r.Reason))
	}
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}

	if filter.Limit > 0 && len(matching) > len(newestFirst) {
		fmt.Fprintf(e.stdout, "\n%d older matching %s not shown. Raise -limit, or narrow with -since.\n",
			len(matching)-len(newestFirst), opPlural(len(matching)-len(newestFirst), "record is", "records are"))
	}
	return exitOK
}

// auditFlagsIgnoredByVerify returns the names of the record-filtering
// flags the operator set that -verify would not honour. Empty when
// -verify was not requested, or when nothing conflicting was passed.
func auditFlagsIgnoredByVerify(fs *flag.FlagSet, verify bool) []string {
	if !verify {
		return nil
	}
	conflicts := map[string]bool{
		"limit": true, "since": true, "subject": true, "outcome": true,
		"source": true, "json": true,
	}
	var ignored []string
	fs.Visit(func(f *flag.Flag) {
		if conflicts[f.Name] {
			ignored = append(ignored, "-"+f.Name)
		}
	})
	sort.Strings(ignored)
	return ignored
}

// runAuditVerify walks the audit trail's hash chain and reports what it
// found (design/adr/0015-audit-tamper-evidence.md item 5).
//
// It is deliberate that this prints the head on success as well as on
// failure: the head is the value an operator records somewhere the gateway
// cannot reach, and it is the only thing that turns tail-truncation into
// something detectable at all.
func runAuditVerify(e *opEnv, expectHead string) int {
	check, err := e.auditChain().VerifyChain(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "audit trail: %v\n", err)
		return exitCannotRun
	}

	if check.FirstBreak != nil {
		b := check.FirstBreak
		fmt.Fprintf(e.stderr, "TAMPERED: the audit trail does not verify.\n\n")
		fmt.Fprintf(e.stderr, "  first break at record %d of %d\n", b.Position, check.Count)
		fmt.Fprintf(e.stderr, "  record now reads  %s  %s  %s -> %s  (%s)\n",
			b.Record.Timestamp.Format(time.RFC3339), b.Record.AnalystIdentity,
			b.Record.Tool, b.Record.TargetUpstream, b.Record.Outcome)
		fmt.Fprintf(e.stderr, "  hash expected     %s\n", b.Want)
		fmt.Fprintf(e.stderr, "  hash stored       %s\n\n", b.Got)
		fmt.Fprintf(e.stderr, "A record at or before this position was edited or removed. Records after\n")
		fmt.Fprintf(e.stderr, "it are not re-verified against it, so this is the earliest damage, not\n")
		fmt.Fprintf(e.stderr, "necessarily the only damage.\n")
		return exitProblem
	}

	fmt.Fprintf(e.stdout, "chain intact: %d record(s)\n", check.Count)
	fmt.Fprintf(e.stdout, "head: %s\n", headOrNone(check.Head))
	if check.RetroactivelyChained > 0 {
		fmt.Fprintf(e.stdout, "\nNote: the first %d record(s) were hashed when this database was\n",
			check.RetroactivelyChained)
		fmt.Fprintf(e.stdout, "migrated, not when they were written. They verify against each other,\n")
		fmt.Fprintf(e.stdout, "which says nothing about whether they were already altered before that.\n")
	}
	fmt.Fprintf(e.stdout, "\nThis detects edits and deletions in the MIDDLE of the trail. Removing\n")
	fmt.Fprintf(e.stdout, "records from the END leaves a shorter chain that still verifies. Record\n")
	fmt.Fprintf(e.stdout, "the head above somewhere this gateway cannot write, and pass it back as\n")
	fmt.Fprintf(e.stdout, "-expect-head to catch that too.\n")

	if expectHead != "" && !strings.EqualFold(expectHead, check.Head) {
		fmt.Fprintf(e.stderr, "\nTRUNCATED OR REWRITTEN: head does not match the expected value.\n")
		fmt.Fprintf(e.stderr, "  expected  %s\n", expectHead)
		fmt.Fprintf(e.stderr, "  found     %s\n", headOrNone(check.Head))
		return exitProblem
	}
	return exitOK
}

// headOrNone renders an empty head as something an operator will not
// mistake for a hash they failed to copy.
func headOrNone(head string) string {
	if head == audit.GenesisHash {
		return "(none -- the trail is empty)"
	}
	return head
}
