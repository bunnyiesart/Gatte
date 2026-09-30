package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
)

// design/adr/0046 in the binary: the block writer of an offboard, the
// round's record of an expired block, and the CLI filters and -until.

func asUID1000(t *testing.T) {
	t.Helper()
	old := adminGeteuid
	adminGeteuid = func() int { return 1000 }
	t.Cleanup(func() { adminGeteuid = old })
}

// TestAdmin_TheBlockWriterPlacesOneOperatorBlock runs the child's body the
// way the accounts backend feeds it.
func TestAdmin_TheBlockWriterPlacesOneOperatorBlock(t *testing.T) {
	cfgPath := writeAdminTestConfig(t)
	asUID1000(t)
	in := blockWriterInput{Subject: "sub-ana", Reason: `[ui] offboard of account "ana"`, By: "alice", At: time.Now().UTC()}
	body, _ := json.Marshal(in)
	var out, errb bytes.Buffer
	if code := runWithStdin([]string{"admin", "-block-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code != exitOK {
		t.Fatalf("block writer: exit %d\n%s", code, errb.String())
	}
	var res blockWriterOutput
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || !res.Placed {
		t.Fatalf("answer %q, %v; want placed", out.String(), err)
	}
	out.Reset()
	if code := runWithStdin([]string{"admin", "-block-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code != exitOK {
		t.Fatalf("block writer, again: exit %d", code)
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Placed {
		t.Fatalf("second answer %q; want not placed", out.String())
	}
	// A block with no operator tag is not an operator action's.
	in.Subject, in.Reason = "sub-bruno", "no tag"
	body, _ = json.Marshal(in)
	if code := runWithStdin([]string{"admin", "-block-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code == exitOK {
		t.Fatal("the block writer placed a block without an operator's tag")
	}
	// Nor does it write the trail: the row is the audit writer's.
	if rows := readAdminTestTrail(t, cfgPath); len(rows) != 0 {
		t.Fatalf("the block writer wrote rows: %+v", rows)
	}
}

// TestAdmin_TheBlockWriterSaysWhichEndedBlockItReplaced: the accounts
// backend cannot read the blocklist, so the child answers with the ended
// block its placement replaced, for the offboard's row to name
// (design/adr/0046, correction of 30 Sep 2026).
func TestAdmin_TheBlockWriterSaysWhichEndedBlockItReplaced(t *testing.T) {
	cfgPath := writeAdminTestConfig(t)
	asUID1000(t)
	start := time.Now().UTC().Add(-2 * time.Hour)
	end := time.Now().UTC().Add(-time.Hour)
	first := blockWriterInput{Subject: "sub-ana", Reason: "[cli] short", By: "alice", At: start, Until: end}
	body, _ := json.Marshal(first)
	var out, errb bytes.Buffer
	if code := runWithStdin([]string{"admin", "-block-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code != exitOK {
		t.Fatalf("block writer: exit %d\n%s", code, errb.String())
	}
	second := blockWriterInput{Subject: "sub-ana", Reason: `[ui] offboard of account "ana"`, By: "bob", At: time.Now().UTC()}
	body, _ = json.Marshal(second)
	out.Reset()
	if code := runWithStdin([]string{"admin", "-block-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code != exitOK {
		t.Fatalf("block writer over the ended block: exit %d\n%s", code, errb.String())
	}
	var res blockWriterOutput
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || !res.Placed || res.Replaced == nil {
		t.Fatalf("answer %q, %v; want placed, with the replaced block", out.String(), err)
	}
	if r := res.Replaced; r.By != "alice" || !r.Until.Equal(end) || !r.At.Equal(start) {
		t.Fatalf("replaced %+v; want alice's block that ended at %v", r, end)
	}
}

// TestAdmin_TheBlockWriterRefusesToRunAsRoot, like the audit writer.
func TestAdmin_TheBlockWriterRefusesToRunAsRoot(t *testing.T) {
	old := adminGeteuid
	adminGeteuid = func() int { return 0 }
	t.Cleanup(func() { adminGeteuid = old })
	var out, errb bytes.Buffer
	code := runWithStdin([]string{"admin", "-block-writer", "-config", "none.toml"}, strings.NewReader("{}"), &out, &errb)
	if code != exitCannotRun || !strings.Contains(errb.String(), "root") {
		t.Fatalf("admin -block-writer as root: exit %d\n%s", code, errb.String())
	}
}

// TestAdmin_TheAuditWriterTakesTheOffboardRows: (access block), (account
// disable), (account offboard) and (account delete) come from the accounts
// socket now.
func TestAdmin_TheAuditWriterTakesTheOffboardRows(t *testing.T) {
	cfgPath := writeAdminTestConfig(t)
	asUID1000(t)
	for _, tool := range []string{admin.AccessBlock, admin.AccountOffboard, admin.AccountDelete} {
		rec := audit.Record{AnalystIdentity: "(operator:alice)", Tool: tool, TargetUpstream: "(gateway)", Outcome: audit.OutcomeAllowed, Reason: "x [ui]"}
		body, _ := json.Marshal(auditWriterRecord(rec))
		var out, errb bytes.Buffer
		if code := runWithStdin([]string{"admin", "-audit-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code != exitOK {
			t.Fatalf("audit writer, %s: exit %d\n%s", tool, code, errb.String())
		}
	}
	// The gateway's own expiry row is not an account action's.
	rec := audit.Record{AnalystIdentity: "(operator:alice)", Tool: admin.AccessBlockExpired, TargetUpstream: "(gateway)", Outcome: audit.OutcomeAllowed}
	body, _ := json.Marshal(auditWriterRecord(rec))
	var out, errb bytes.Buffer
	if code := runWithStdin([]string{"admin", "-audit-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code == exitOK {
		t.Fatal("the audit writer appended an (access block expired) row")
	}
}

// failingRecorder refuses every row.
type failingRecorder struct{ audit.Recorder }

func (failingRecorder) Record(context.Context, audit.Record) error { return errors.New("disk full") }

// TestServe_TheRoundRecordsAnExpiredBlockThenRemovesIt: the row first, and
// a row that cannot be written leaves the block listed.
func TestServe_TheRoundRecordsAnExpiredBlockThenRemovesIt(t *testing.T) {
	e := newOpTestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	blocks := accesssqlite.New(e.db).WithClock(clock)
	placed := now.Add(-2 * time.Hour)
	for _, b := range []access.Block{
		{Subject: "sub-ana", Reason: "[ui] on leave", By: "alice", At: placed, Until: now.Add(-time.Minute)},
		{Subject: "sub-bruno", Reason: "[cli] incident", By: "alice", At: placed, Until: now.Add(time.Hour)},
		{Subject: "sub-carla", Reason: "[cli] left", By: "alice", At: placed},
	} {
		if _, err := blocks.Block(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	s := &serveStack{blocks: blocks, audit: failingRecorder{e.auditTrail()}}
	if n := s.expireBlocks(ctx, logger); n != 0 {
		t.Fatalf("with no trail, %d blocks were removed", n)
	}
	if list, _ := blocks.Blocks(ctx); len(list) != 3 {
		t.Fatalf("an expiry the trail did not take removed its block: %+v", list)
	}

	s.audit = e.auditTrail()
	if n := s.expireBlocks(ctx, logger); n != 1 {
		t.Fatalf("removed %d, want 1\n%s", n, logs.String())
	}
	list, _ := blocks.Blocks(ctx)
	if len(list) != 2 || list[0].Subject == "sub-ana" || list[1].Subject == "sub-ana" {
		t.Fatalf("after the round: %+v", list)
	}
	rows, _ := e.auditTrail().List(ctx)
	if len(rows) != 1 || rows[0].Tool != admin.AccessBlockExpired || rows[0].AnalystIdentity != "(gateway)" ||
		!strings.Contains(rows[0].Reason, `subject "sub-ana" until `) || !strings.Contains(rows[0].Reason, "placed by alice") || !strings.Contains(rows[0].Reason, "on leave") {
		t.Fatalf("rows %+v", rows)
	}
	if n := s.expireBlocks(ctx, logger); n != 0 {
		t.Fatalf("a second round removed %d", n)
	}
}

// TestRunAudit_ToolServerAndUntil: the three CLI filters.
func TestRunAudit_ToolServerAndUntil(t *testing.T) {
	for name, tc := range map[string]struct {
		f       auditFilter
		want    []string
		without []string
	}{
		"tool":   {auditFilter{Tool: "threatintel.whois"}, []string{"threatintel.whois"}, []string{"casemgmt.list_cases", "logsearch.search"}},
		"server": {auditFilter{Server: "logsearch"}, []string{"logsearch.search"}, []string{"casemgmt.list_cases", "threatintel.whois"}},
		"until is exclusive": {auditFilter{Until: time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)},
			[]string{"casemgmt.list_cases"}, []string{"threatintel.whois", "logsearch.search"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newOpTestEnv(t)
			seedAuditTrail(t, e)
			requireExit(t, runAudit(e.opEnv, tc.f, false), exitOK, name)
			got := e.stdoutText()
			for _, w := range tc.want {
				requireContains(t, got, w, name)
			}
			for _, w := range tc.without {
				if strings.Contains(got, w) {
					t.Errorf("%s: %q shown\n%s", name, w, got)
				}
			}
		})
	}
	code, _, errText := runCLI("audit", "-since", "2026-09-08T10:00:00Z", "-until", "2026-09-08T10:00:00Z")
	if code != exitCannotRun || !strings.Contains(errText, "-until must be after -since") {
		t.Fatalf("an empty window: exit %d %s", code, errText)
	}
	code, _, errText = runCLI("audit", "-verify", "-tool", "x")
	if code != exitCannotRun || !strings.Contains(errText, "-tool") {
		t.Fatalf("-verify -tool: exit %d %s", code, errText)
	}
}

// TestAccessBlock_UntilThroughTheBinary: -until takes a duration, the row
// states the end, and the list shows it.
func TestAccessBlock_UntilThroughTheBinary(t *testing.T) {
	cfg := accessConfig(t, "")
	t.Setenv("SUDO_USER", "operator1")
	code, out, errText := runCLI("access", "block", "-config", cfg, "-until", "8h", "-reason", "on leave", "sub-analyst-1")
	requireExit(t, code, exitOK, "access block -until: "+out+errText)
	requireContains(t, out, "ends by itself", "access block -until")
	code, out, _ = runCLI("access", "list", "-config", cfg)
	requireExit(t, code, exitOK, "access list")
	if !strings.Contains(out, "UNTIL") || strings.Contains(out, "EXPIRED") {
		t.Fatalf("access list:\n%s", out)
	}
	code, out, _ = runCLI("access", "list", "-config", cfg, "-json")
	requireExit(t, code, exitOK, "access list -json")
	if !strings.Contains(out, `"until"`) {
		t.Fatalf("access list -json carries no until:\n%s", out)
	}
	rows, _ := trailOf(t, cfg)
	if len(rows) != 1 || !strings.Contains(rows[0].Reason, `"sub-analyst-1" until `) {
		t.Fatalf("rows %+v", rows)
	}
	for _, bad := range []string{"-1h", "2020-01-01T00:00:00Z", "tomorrow"} {
		code, _, errText := runCLI("access", "block", "-config", cfg, "-until", bad, "sub-analyst-2")
		if code != exitCannotRun {
			t.Errorf("-until %s: exit %d %s", bad, code, errText)
		}
	}
	if code, _, _ := runCLI("access", "unblock", "-config", cfg, "-until", "8h", "sub-analyst-1"); code != exitCannotRun {
		t.Error("unblock took -until")
	}
}
