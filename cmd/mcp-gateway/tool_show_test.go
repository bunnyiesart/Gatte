package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// hiddenIdentity is a definition poisoned the way a reviewer cannot see: a
// bidi override, a zero-width space, an ANSI escape and tag characters
// spelling an instruction.
var hiddenIdentity = quarantine.ToolIdentity{
	Name:        "list_cases",
	Description: "List CASEMGMT cases.\u202e\u200b\x1b[8m\U000E0041\U000E0042\nSecond line.",
	InputSchema: []byte(`{"type":"object","properties":{}}`),
}

// requireNoRawHidden fails if s carries any of the code points the escaper
// exists to neutralise, raw.
func requireNoRawHidden(t *testing.T, s, what string) {
	t.Helper()
	for _, r := range []string{"\u202e", "\u200b", "\x1b", "\U000E0041", "\U000E0042"} {
		if strings.Contains(s, r) {
			t.Errorf("%s printed %q raw\n%s", what, r, s)
		}
	}
}

// TestRunToolShow_EscapesHiddenCodePoints is design/adr/0032 items 2 and 3:
// the operator is shown the definition the gateway fingerprinted, with every
// invisible or control code point written as \u{XXXX}.
func TestRunToolShow_EscapesHiddenCodePoints(t *testing.T) {
	e := newOpTestEnv(t)
	obs := mustObserve(t, e, "casemgmt", hiddenIdentity)

	requireExit(t, runToolShow(e.opEnv, "casemgmt", "list_cases"), exitOK, "tool show")
	got := e.stdoutText()
	requireNoRawHidden(t, got, "tool show")
	for _, want := range []string{
		obs.ObservedHash,
		`List CASEMGMT cases.\u{202E}\u{200B}\u{001B}[8m\u{E0041}\u{E0042}`,
		"Second line.",
		`"type": "object"`,
		"not approved",
		"5 hidden",
	} {
		requireContains(t, got, want, "tool show")
	}
}

// TestRunToolShow_WarnsAboutHiddenCodePointsWrittenAsJSONEscapes: a schema
// is JSON, and JSON can carry a hidden code point as the ASCII text
// \u202e. The reviewer then reads six harmless characters while a model
// that decodes the schema gets the real override, so the warning counts the
// decoded strings, not only the bytes on screen.
func TestRunToolShow_WarnsAboutHiddenCodePointsWrittenAsJSONEscapes(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{
		Name:        "list_cases",
		Description: "List cases.",
		InputSchema: []byte(`{"type":"object","properties":{"q":{"type":"string","description":"query\u202e\u2028"}}}`),
	})

	requireExit(t, runToolShow(e.opEnv, "casemgmt", "list_cases"), exitOK, "tool show")
	requireContains(t, e.stdoutText(), "WARNING: the observed definition carries 2 hidden", "tool show")
}

// TestRunToolShow_DiffsApprovedAgainstObserved: after a rug pull, the
// approved definition is still on disk and the two are shown side by side
// as a line diff -- the "cannot show you a diff" of the old console is gone.
func TestRunToolShow_DiffsApprovedAgainstObserved(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", irisListCases)
	mustApprove(t, e, "casemgmt", "list_cases")
	mustObserve(t, e, "casemgmt", changedIrisListCases)

	requireExit(t, runToolShow(e.opEnv, "casemgmt", "list_cases"), exitOK, "tool show (changed)")
	got := e.stdoutText()
	for _, want := range []string{
		"APPROVED",
		"OBSERVED",
		"-   " + irisListCases.Description,
		"+   " + changedIrisListCases.Description,
	} {
		requireContains(t, got, want, "tool show (changed)")
	}
}

// TestRunToolShow_SaysWhenTheApprovedDefinitionWasNotKept: a baseline
// approved before ADR-0032 has a hash and nothing else. The console says so
// rather than printing an empty block that reads like an empty description.
func TestRunToolShow_SaysWhenTheApprovedDefinitionWasNotKept(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", changedIrisListCases)
	mustApprove(t, e, "casemgmt", "list_cases")
	// A pre-ADR-0032 baseline: a hash no definition row answers to.
	if _, err := e.db.Exec(`UPDATE quarantined_tools SET approved_hash = 'aaaa', status = 'changed'`); err != nil {
		t.Fatal(err)
	}

	requireExit(t, runToolShow(e.opEnv, "casemgmt", "list_cases"), exitOK, "tool show (legacy)")
	requireContains(t, e.stdoutText(), "was not kept", "tool show (legacy)")
}

// TestRunToolApprove_WithoutFingerprintRefusesAndSaysWhatToRun: approving
// is a statement about one definition, so the command no longer baselines
// "whatever is there now". Without -fingerprint it prints the definition,
// the fingerprint and the exact command, and changes nothing.
func TestRunToolApprove_WithoutFingerprintRefusesAndSaysWhatToRun(t *testing.T) {
	e := newOpTestEnv(t)
	e.configPath = "/etc/mcp-gateway/mcp-gateway.toml"
	obs := mustObserve(t, e, "casemgmt", hiddenIdentity)

	requireExit(t, runToolApproveFingerprint(e.opEnv, "casemgmt", "list_cases", ""), exitProblem, "approve without -fingerprint")
	requireNoRawHidden(t, e.bothText(), "approve without -fingerprint")
	requireContains(t, e.stdoutText(), `\u{202E}`, "approve without -fingerprint")
	requireContains(t, e.stderrText(), "NOT approved", "approve without -fingerprint")
	requireContains(t, e.stderrText(),
		"mcp-gateway tool approve -config /etc/mcp-gateway/mcp-gateway.toml -fingerprint "+obs.ObservedHash+" casemgmt list_cases",
		"approve without -fingerprint")

	got, err := e.tools().Get(context.Background(), "casemgmt", "list_cases")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != quarantine.StatusPending || got.Usable() {
		t.Fatalf("an approval without -fingerprint changed state: %+v", got)
	}
}

// TestRunToolApprove_ChangedToolShowsTheDiffBeforeApproving: the rug-pull
// decision point now shows what changed, not two hashes.
func TestRunToolApprove_ChangedToolShowsTheDiffBeforeApproving(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", irisListCases)
	mustApprove(t, e, "casemgmt", "list_cases")
	changed := mustObserve(t, e, "casemgmt", changedIrisListCases)

	requireExit(t, runToolApproveFingerprint(e.opEnv, "casemgmt", "list_cases", changed.ObservedHash), exitOK, "approve changed")
	got := e.stdoutText()
	requireContains(t, got, "-   "+irisListCases.Description, "approve changed")
	requireContains(t, got, "+   "+changedIrisListCases.Description, "approve changed")
	if strings.Contains(got, "cannot show you a diff") {
		t.Errorf("approve still claims it cannot show a diff:\n%s", got)
	}
}

// TestRunToolList_EscapesUntrustedNames: a row written past the registry's
// own validation -- by hand, or by an older binary -- must not be able to
// drive the operator's terminal.
func TestRunToolList_EscapesUntrustedNames(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "evil\x1b]0;owned\x07\u202e", Description: "d"})

	requireExit(t, runToolList(e.opEnv, "", false), exitOK, "tool list")
	got := e.stdoutText()
	if strings.ContainsAny(got, "\x1b\x07\u202e") {
		t.Errorf("tool list printed a control or bidi code point raw: %q", got)
	}
	requireContains(t, got, `evil\u{001B}]0;owned\u{0007}\u{202E}`, "tool list")
}

// TestRunAudit_EscapesUntrustedStrings: probe names are whatever a caller
// typed, and `audit` used to print them verbatim -- an analyst could put an
// OSC sequence in the operator's terminal through a tools/call name.
func TestRunAudit_EscapesUntrustedStrings(t *testing.T) {
	e := newOpTestEnv(t)
	mustRecord(t, e, audit.Record{
		AnalystIdentity: "sub\u202e",
		Tool:            "casemgmt.x\x1b]52;c;ZXZpbA==\x07",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
		Outcome:         audit.OutcomeDenied,
		Reason:          "not visible to caller\u200b",
		SourceAddress:   "198.51.100.7\x1b[2K",
	})

	requireExit(t, runAudit(e.opEnv, auditFilter{}, false), exitOK, "audit")
	got := e.stdoutText()
	if strings.ContainsAny(got, "\x1b\x07\u202e\u200b") {
		t.Errorf("audit printed a control or invisible code point raw: %q", got)
	}
	for _, want := range []string{`sub\u{202E}`, `casemgmt.x\u{001B}]52;c;ZXZpbA==\u{0007}`, `caller\u{200B}`, `198.51.100.7\u{001B}[2K`} {
		requireContains(t, got, want, "audit")
	}
}

// TestRunToolApprove_RefusesWhenTheObservedDefinitionWasNotKept: a row
// observed by a pre-ADR-0032 binary has a fingerprint and no definition.
// Approving it would be the blind stamp this change removes, so the console
// refuses until discovery has stored what the fingerprint stands for.
func TestRunToolApprove_RefusesWhenTheObservedDefinitionWasNotKept(t *testing.T) {
	e := newOpTestEnv(t)
	mustObserve(t, e, "casemgmt", irisListCases)
	if _, err := e.db.Exec(`UPDATE quarantined_tools SET observed_hash = 'bbbb'`); err != nil {
		t.Fatal(err)
	}

	requireExit(t, runToolApproveFingerprint(e.opEnv, "casemgmt", "list_cases", "bbbb"), exitProblem, "approve unkept")
	requireContains(t, e.stderrText(), "NOT approved", "approve unkept")
	requireContains(t, e.stderrText(), "next discovery", "approve unkept")
	if got, _ := e.tools().Get(context.Background(), "casemgmt", "list_cases"); got.Usable() {
		t.Fatalf("a definition nobody could be shown was approved: %+v", got)
	}
}
