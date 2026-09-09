package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// seedAuditTrail writes a small, deliberately mixed trail: two analysts,
// three outcomes, three timestamps an hour apart.
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
		},
		{
			AnalystIdentity: "bob@soc.example",
			Tool:            "threatintel.whois",
			TargetUpstream:  "threatintel",
			Timestamp:       base.Add(time.Hour),
			Outcome:         audit.OutcomeDenied,
			Reason:          "quarantined",
		},
		{
			AnalystIdentity: "alice@soc.example",
			Tool:            "logsearch.search",
			TargetUpstream:  "logsearch",
			Timestamp:       base.Add(2 * time.Hour),
			Outcome:         audit.OutcomeFailed,
			Reason:          "upstream timeout",
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
