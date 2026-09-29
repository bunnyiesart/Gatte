package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// Analyst name on the trail (design/adr/0037-nome-do-analista-na-trilha.md).

const namedSubject = "95f757fe-0c7b-4272-9d5e-3f1a2b4c6d8e"

func seedNamedTrail(t *testing.T, e opTestEnv) {
	t.Helper()
	base := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	mustRecord(t, e, audit.Record{
		AnalystIdentity: namedSubject,
		AnalystName:     "Ana Lyst",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       base,
		Outcome:         audit.OutcomeAllowed,
	})
	mustRecord(t, e, audit.Record{
		AnalystIdentity: "(operator:root)",
		Tool:            "access.block",
		TargetUpstream:  "(operator)",
		Timestamp:       base.Add(time.Minute),
		Outcome:         audit.OutcomeAllowed,
	})
}

// TestRunAudit_TableShowsTheNameNextToTheSubject: the operator sees who
// the UUID is, and a row with no name says so with a dash.
func TestRunAudit_TableShowsTheNameNextToTheSubject(t *testing.T) {
	e := newOpTestEnv(t)
	seedNamedTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{}, false), exitOK, "audit")
	out := e.stdoutText()
	requireContains(t, out, "NAME", "audit header")
	var namedLine string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, namedSubject) {
			namedLine = l
		}
	}
	if !strings.Contains(namedLine, "Ana Lyst") {
		t.Errorf("the row for %s does not show the name:\n%s", namedSubject, out)
	}
}

// TestRunAudit_JSONCarriesTheAnalystName: analyst_name is present when the
// row has one and absent when it does not, like source_address.
func TestRunAudit_JSONCarriesTheAnalystName(t *testing.T) {
	e := newOpTestEnv(t)
	seedNamedTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{}, true), exitOK, "audit -json")
	var raw []map[string]any
	if err := json.Unmarshal(e.out.Bytes(), &raw); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, e.stdoutText())
	}
	if len(raw) != 2 {
		t.Fatalf("got %d records, want 2", len(raw))
	}
	// Newest first: the operator row, then the named one.
	if v, present := raw[0]["analyst_name"]; present {
		t.Errorf("an unnamed row carries analyst_name %#v", v)
	}
	if raw[1]["analyst_name"] != "Ana Lyst" || raw[1]["analyst_identity"] != namedSubject {
		t.Errorf("named row = %v, want analyst_name %q next to analyst_identity %q", raw[1], "Ana Lyst", namedSubject)
	}
}

// TestRunAudit_SubjectFilterDoesNotMatchTheName: -subject is attribution,
// and the name is display only.
func TestRunAudit_SubjectFilterDoesNotMatchTheName(t *testing.T) {
	e := newOpTestEnv(t)
	seedNamedTrail(t, e)

	requireExit(t, runAudit(e.opEnv, auditFilter{Subject: "Ana Lyst"}, false), exitProblem, "audit -subject <name>")

	e2 := newOpTestEnv(t)
	seedNamedTrail(t, e2)
	requireExit(t, runAudit(e2.opEnv, auditFilter{Subject: namedSubject}, false), exitOK, "audit -subject <sub>")
}
