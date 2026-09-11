package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// The two addresses the seeded trail is written from. Distinct so a
// filter that ignores the field, or matches on the wrong one, shows up.
const (
	analystAddress  = "198.51.100.14"
	strangerAddress = "203.0.113.200"
)

// seedAuditTrail writes a small, deliberately mixed trail: two analysts,
// three outcomes, two source addresses, three timestamps an hour apart.
func seedAuditTrail(t *testing.T, e opTestEnv) []audit.Record {
	t.Helper()
	base := time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC)
	records := []audit.Record{
		{
			AnalystIdentity: "alice@soc.example",
			Tool:            "casemgmt.list_cases",
			TargetUpstream:  "casemgmt",
			Timestamp:       base,
			Outcome:         audit.OutcomeAllowed,
			SourceAddress:   analystAddress,
		},
		{
			AnalystIdentity: "bob@soc.example",
			Tool:            "threatintel.whois",
			TargetUpstream:  "threatintel",
			Timestamp:       base.Add(time.Hour),
			Outcome:         audit.OutcomeDenied,
			Reason:          "quarantined",
			SourceAddress:   analystAddress,
		},
		{
			// Alice again -- from somewhere Alice does not sit. One
			// identity, two addresses, which is the shape of a stolen
			// token and the reason the column exists.
			AnalystIdentity: "alice@soc.example",
			Tool:            "logsearch.search",
			TargetUpstream:  "logsearch",
			Timestamp:       base.Add(2 * time.Hour),
			Outcome:         audit.OutcomeFailed,
			Reason:          "upstream timeout",
			SourceAddress:   strangerAddress,
		},
	}
	for _, r := range records {
		mustRecord(t, e, r)
	}
	return records
}

// TestRunAudit_Filters is the trail's whole operator interface: narrow by
// who, by what happened, and by when.
func TestRunAudit_Filters(t *testing.T) {
	tests := []struct {
		name       string
		filter     auditFilter
		wantTools  []string
		wantAbsent []string
	}{
		{
			name:      "no filter shows everything",
			filter:    auditFilter{Limit: auditDefaultLimit},
			wantTools: []string{"casemgmt.list_cases", "threatintel.whois", "logsearch.search"},
		},
		{
			name:       "by outcome denied",
			filter:     auditFilter{Limit: auditDefaultLimit, Outcome: audit.OutcomeDenied},
			wantTools:  []string{"threatintel.whois"},
			wantAbsent: []string{"casemgmt.list_cases", "logsearch.search"},
		},
		{
			name:       "by outcome failed",
			filter:     auditFilter{Limit: auditDefaultLimit, Outcome: audit.OutcomeFailed},
			wantTools:  []string{"logsearch.search"},
			wantAbsent: []string{"threatintel.whois"},
		},
		{
			name:       "by subject",
			filter:     auditFilter{Limit: auditDefaultLimit, Subject: "alice@soc.example"},
			wantTools:  []string{"casemgmt.list_cases", "logsearch.search"},
			wantAbsent: []string{"threatintel.whois", "bob@soc.example"},
		},
		{
			name:       "by subject and outcome together",
			filter:     auditFilter{Limit: auditDefaultLimit, Subject: "alice@soc.example", Outcome: audit.OutcomeAllowed},
			wantTools:  []string{"casemgmt.list_cases"},
			wantAbsent: []string{"logsearch.search", "threatintel.whois"},
		},
		{
			name:       "since excludes anything older",
			filter:     auditFilter{Limit: auditDefaultLimit, Since: time.Date(2026, 9, 8, 10, 30, 0, 0, time.UTC)},
			wantTools:  []string{"logsearch.search"},
			wantAbsent: []string{"casemgmt.list_cases", "threatintel.whois"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)
			seedAuditTrail(t, e)

			requireExit(t, runAudit(e.opEnv, tc.filter, false), exitOK, tc.name)
			got := e.stdoutText()
			for _, want := range tc.wantTools {
				requireContains(t, got, want, tc.name)
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("%s: output should not contain %q\n--- output ---\n%s", tc.name, absent, got)
				}
			}
		})
	}
}

// TestRunAudit_ShowsOutcomeAndReason: those two columns are the point of
// the trail -- "was this blocked, and why" is the first question asked of
// it -- so their presence is pinned rather than left to the renderer.
func TestRunAudit_ShowsOutcomeAndReason(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{Limit: auditDefaultLimit}, false), exitOK, "audit")
	got := e.stdoutText()

	for _, want := range []string{
		"OUTCOME", "REASON",
		string(audit.OutcomeAllowed), string(audit.OutcomeDenied), string(audit.OutcomeFailed),
		"quarantined", "upstream timeout",
		"alice@soc.example", "bob@soc.example",
	} {
		requireContains(t, got, want, "audit")
	}
	// A record with no reason must not render as a blank column.
	requireContains(t, got, "allowed", "audit")
	if strings.Contains(got, "allowed  \n") {
		t.Errorf("an empty reason rendered as blank space rather than a dash\n%s", got)
	}
}

// TestRunAudit_NewestFirstAndLimited pins the ordering decision: the port
// guarantees oldest-first, an operator reading recent activity wants the
// other end, and the command says which order it printed.
func TestRunAudit_NewestFirstAndLimited(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{Limit: 2}, false), exitOK, "audit -limit 2")
	got := e.stdoutText()

	requireContains(t, got, "NEWEST FIRST", "audit -limit 2")
	requireContains(t, got, "Showing 2 of 3", "audit -limit 2")
	requireContains(t, got, "1 older matching record is not shown", "audit -limit 2")

	newest := strings.Index(got, "logsearch.search")
	middle := strings.Index(got, "threatintel.whois")
	if newest < 0 || middle < 0 {
		t.Fatalf("expected the two most recent records\n%s", got)
	}
	if newest > middle {
		t.Errorf("records are not newest-first\n%s", got)
	}
	if strings.Contains(got, "casemgmt.list_cases") {
		t.Errorf("-limit 2 showed the third-oldest record\n%s", got)
	}
}

func TestRunAudit_NothingToShowIsAProblem(t *testing.T) {
	tests := []struct {
		name   string
		seed   bool
		filter auditFilter
		want   string
	}{
		{
			name: "empty trail",
			seed: false,
			want: "The audit trail is empty",
		},
		{
			name:   "filters match nothing",
			seed:   true,
			filter: auditFilter{Limit: 10, Subject: "mallory@soc.example"},
			want:   "No audit records match",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)
			if tc.seed {
				seedAuditTrail(t, e)
			}
			requireExit(t, runAudit(e.opEnv, tc.filter, false), exitProblem, tc.name)
			requireContains(t, e.stdoutText(), tc.want, tc.name)
		})
	}
}

func TestRunAudit_JSON(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{Limit: 1, Outcome: audit.OutcomeDenied}, true), exitOK, "audit -json")

	var got []auditJSON
	if err := json.Unmarshal(e.out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, e.stdoutText())
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Outcome != string(audit.OutcomeDenied) || got[0].Reason != "quarantined" {
		t.Errorf("record = %+v, want the denied one with reason %q", got[0], "quarantined")
	}
}

// TestCmdAudit_BadFlags: a filter that cannot be parsed must stop the
// command, not silently widen it. An operator who mistypes -outcome
// "denyed" and gets the whole trail will read it as "nothing was denied".
func TestCmdAudit_BadFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown outcome", []string{"-outcome", "denyed"}, `-outcome "denyed" is not one of`},
		{"unparseable since", []string{"-since", "yesterday"}, "not an RFC3339 timestamp"},
		{"negative limit", []string{"-limit", "-3"}, "must not be negative"},
		{"stray argument", []string{"alice"}, `unexpected argument "alice"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			// No -config: a bad flag must be refused before any attempt to
			// open a database.
			requireExit(t, cmdAudit(tc.args, &out, &errBuf), exitCannotRun, tc.name)
			requireContains(t, errBuf.String(), tc.want, tc.name)
		})
	}
}

// TestRunAudit_ShowsAndFiltersOnSourceAddress: the column exists to
// answer "was that really Ana, or somebody with Ana's token?", and it
// only answers it if an operator can both see it and narrow to it.
// Rendering it without a filter would mean grepping; filtering without
// rendering would mean trusting the filter.
func TestRunAudit_ShowsAndFiltersOnSourceAddress(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{Limit: auditDefaultLimit}, false), exitOK, "audit")
	got := e.stdoutText()
	requireContains(t, got, "SOURCE", "audit")
	for _, want := range []string{analystAddress, strangerAddress} {
		requireContains(t, got, want, "audit")
	}

	// Same analyst identity, two addresses: the trail can separate them.
	e2 := newOpTestEnv(t)
	seedAuditTrail(t, e2)
	requireExit(t, runAudit(e2.opEnv, auditFilter{Limit: auditDefaultLimit, Source: strangerAddress}, false),
		exitOK, "audit -source")
	narrowed := e2.stdoutText()
	requireContains(t, narrowed, "logsearch.search", "audit -source")
	for _, absent := range []string{"casemgmt.list_cases", "threatintel.whois"} {
		if strings.Contains(narrowed, absent) {
			t.Errorf("-source %s showed %q, a record from a different address\n%s",
				strangerAddress, absent, narrowed)
		}
	}
	requireContains(t, narrowed, "source "+strangerAddress, "audit -source")
}

// TestRunAudit_JSONCarriesSourceAddress: -json is what a script reads,
// and a field missing there is a field that does not exist for anything
// automated.
func TestRunAudit_JSONCarriesSourceAddress(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{Limit: 1, Outcome: audit.OutcomeFailed}, true), exitOK, "audit -json")

	var got []auditJSON
	if err := json.Unmarshal(e.out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, e.stdoutText())
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].SourceAddress != strangerAddress {
		t.Errorf("source_address = %q, want %q", got[0].SourceAddress, strangerAddress)
	}
}

// TestAuditUsage_DoesNotPromiseWhatTheTrailCannotDeliver.
//
// The help text is part of the interface. Two things about it are
// load-bearing after design/adr/0012: `failed` is now a real outcome
// something writes (before GAB-24 it was advertised and unreachable, so
// -outcome failed could only ever come back empty), and a failed call
// costs two rows, which anyone counting rows has to be told before they
// count.
func TestAuditUsage_DoesNotPromiseWhatTheTrailCannotDeliver(t *testing.T) {
	var buf bytes.Buffer
	auditUsage(&buf)
	usage := buf.String()

	for _, want := range []string{"-source", "two", "failed"} {
		requireContains(t, usage, want, "audit usage")
	}
}

// TestRunAuditVerify_IntactTrailReportsTheHead covers the success path,
// and asserts the two things the output exists to carry: the head an
// operator anchors externally, and the plain statement that this does not
// cover truncation. An "all good" that omits the second is the kind of
// reassurance this project keeps finding and removing.
func TestRunAuditVerify_IntactTrailReportsTheHead(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	if code := runAuditVerify(e.opEnv, ""); code != exitOK {
		t.Fatalf("runAuditVerify = %d, want %d; stderr: %s", code, exitOK, e.stderrText())
	}
	out := e.stdoutText()
	if !strings.Contains(out, "chain intact: 3 record(s)") {
		t.Errorf("output does not report the count:\n%s", out)
	}
	if !strings.Contains(out, "head: ") {
		t.Errorf("output does not print the head, which is the only thing that makes "+
			"truncation detectable later:\n%s", out)
	}
	for _, want := range []string{"END", "shorter chain", "-expect-head"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q -- an operator could read this as "+
				"proof the trail is complete:\n%s", want, out)
		}
	}
}

// TestRunAuditVerify_EditedRecordIsReported is the point of the whole
// feature, exercised through the operator's actual entry point rather
// than the adapter.
func TestRunAuditVerify_EditedRecordIsReported(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	if _, err := e.db.Exec(`UPDATE audit_records SET outcome = 'allowed' WHERE id = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	if code := runAuditVerify(e.opEnv, ""); code != exitProblem {
		t.Fatalf("runAuditVerify = %d, want %d (ran and found a problem)", code, exitProblem)
	}
	errText := e.stderrText()
	if !strings.Contains(errText, "TAMPERED") {
		t.Errorf("stderr does not say the trail is tampered:\n%s", errText)
	}
	if !strings.Contains(errText, "record 2 of 3") {
		t.Errorf("stderr does not locate the break:\n%s", errText)
	}
	// The operator must not read "first break" as "only break".
	if !strings.Contains(errText, "not\nnecessarily the only damage") {
		t.Errorf("stderr does not warn that later damage is not re-checked:\n%s", errText)
	}
}

// TestRunAuditVerify_ExpectHead covers the anchor: the same intact chain
// passes or fails depending only on whether the head matches what the
// operator recorded earlier. This is what turns tail-truncation from
// invisible into caught.
func TestRunAuditVerify_ExpectHead(t *testing.T) {
	e := newOpTestEnv(t)
	seedAuditTrail(t, e)

	check, err := e.auditChain().VerifyChain(e.ctx())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	if code := runAuditVerify(e.opEnv, check.Head); code != exitOK {
		t.Errorf("matching head returned %d, want %d; stderr: %s", code, exitOK, e.stderrText())
	}

	e2 := newOpTestEnv(t)
	seedAuditTrail(t, e2)
	if code := runAuditVerify(e2.opEnv, "0000000000000000000000000000000000000000000000000000000000000000"); code != exitProblem {
		t.Errorf("mismatched head returned %d, want %d", code, exitProblem)
	}
	if !strings.Contains(e2.stderrText(), "TRUNCATED OR REWRITTEN") {
		t.Errorf("a head mismatch is not reported as such:\n%s", e2.stderrText())
	}
}

// TestCmdAudit_VerifyRefusesFiltersInsteadOfIgnoringThem: silently
// ignoring a filter would tell an operator they verified a subset when
// they verified everything -- or nothing of what they asked for.
func TestCmdAudit_VerifyRefusesFiltersInsteadOfIgnoringThem(t *testing.T) {
	for _, args := range [][]string{
		{"-verify", "-subject", "alice@soc.example"},
		{"-verify", "-outcome", "denied"},
		{"-verify", "-limit", "5"},
		{"-verify", "-json"},
	} {
		var out, errb bytes.Buffer
		if code := cmdAudit(args, &out, &errb); code != exitCannotRun {
			t.Errorf("cmdAudit(%v) = %d, want %d", args, code, exitCannotRun)
		}
		if !strings.Contains(errb.String(), "cannot be filtered") {
			t.Errorf("cmdAudit(%v) stderr does not explain the refusal: %s", args, errb.String())
		}
	}

	// And -expect-head without -verify is a no-op the operator would
	// never be told about.
	var out, errb bytes.Buffer
	if code := cmdAudit([]string{"-expect-head", "abc"}, &out, &errb); code != exitCannotRun {
		t.Errorf("bare -expect-head = %d, want %d", code, exitCannotRun)
	}
}

// TestAuditUsage_StatesWhatVerifyDoesNotCover holds the help text to the
// same standard as the ADR: the limit is named, not left for the operator
// to discover during an incident.
func TestAuditUsage_StatesWhatVerifyDoesNotCover(t *testing.T) {
	var b bytes.Buffer
	auditUsage(&b)
	text := b.String()

	for _, want := range []string{"-verify", "MIDDLE", "END", "-expect-head"} {
		if !strings.Contains(text, want) {
			t.Errorf("usage does not mention %q:\n%s", want, text)
		}
	}
}
