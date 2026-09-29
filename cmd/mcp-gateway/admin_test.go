package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/audit"
)

// TestAdmin_TheAccountsBackendRefusesToRunOutsideRoot is design/adr/0040
// §1: the service account can never edit accounts.
func TestAdmin_TheAccountsBackendRefusesToRunOutsideRoot(t *testing.T) {
	old := adminGeteuid
	adminGeteuid = func() int { return 1000 }
	t.Cleanup(func() { adminGeteuid = old })
	var out, errb bytes.Buffer
	code := run([]string{"admin", "-accounts", "-config", filepath.Join(t.TempDir(), "none.toml"), "-socket", filepath.Join(t.TempDir(), "a.sock")}, &out, &errb)
	if code != exitCannotRun || !strings.Contains(errb.String(), "root") {
		t.Fatalf("admin -accounts as uid 1000: exit %d\n%s", code, errb.String())
	}
}

// TestAdmin_TheAuditWriterRefusesToRunAsRoot: the child exists so that the
// root process never opens a file of the service account.
func TestAdmin_TheAuditWriterRefusesToRunAsRoot(t *testing.T) {
	old := adminGeteuid
	adminGeteuid = func() int { return 0 }
	t.Cleanup(func() { adminGeteuid = old })
	var out, errb bytes.Buffer
	code := runWithStdin([]string{"admin", "-audit-writer", "-config", filepath.Join(t.TempDir(), "none.toml")}, strings.NewReader("{}"), &out, &errb)
	if code != exitCannotRun || !strings.Contains(errb.String(), "root") {
		t.Fatalf("admin -audit-writer as root: exit %d\n%s", code, errb.String())
	}
}

// TestAdmin_NoFlagOpensATCPListener: the management API is UNIX sockets
// only, with no override (design/adr/0040 §1).
func TestAdmin_NoFlagOpensATCPListener(t *testing.T) {
	for _, flag := range []string{"-listen", "-tcp", "-addr", "-port", "-http"} {
		var out, errb bytes.Buffer
		if code := run([]string{"admin", flag, "127.0.0.1:9000"}, &out, &errb); code != exitCannotRun {
			t.Errorf("admin %s: exit %d, want the flag refused", flag, code)
		}
	}
	var out, errb bytes.Buffer
	run([]string{"admin", "-h"}, &out, &errb)
	help := out.String()
	for _, word := range []string{"-listen", "tcp://", "127.0.0.1"} {
		if strings.Contains(help, word) {
			t.Errorf("admin -h mentions %q", word)
		}
	}
	if !strings.Contains(help, "-socket") {
		t.Errorf("admin -h does not document -socket:\n%s", help)
	}
}

// TestAdmin_TheAuditWriterAppendsOneOperatorRow runs the child's body the
// way the root process feeds it: one record on standard input.
func TestAdmin_TheAuditWriterAppendsOneOperatorRow(t *testing.T) {
	cfgPath := writeAdminTestConfig(t)
	old := adminGeteuid
	adminGeteuid = func() int { return 1000 }
	t.Cleanup(func() { adminGeteuid = old })
	rec := audit.Record{AnalystIdentity: "(operator:alice)", Tool: "(account add)", TargetUpstream: "(gateway)",
		Outcome: audit.OutcomeAllowed, Reason: `account "bruno": groups blue-ir [api]`}
	body, _ := json.Marshal(auditWriterRecord(rec))
	var out, errb bytes.Buffer
	if code := runWithStdin([]string{"admin", "-audit-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code != exitOK {
		t.Fatalf("audit writer: exit %d\n%s", code, errb.String())
	}
	rows := readAdminTestTrail(t, cfgPath)
	if len(rows) != 1 || rows[0].Tool != "(account add)" || rows[0].AnalystIdentity != "(operator:alice)" {
		t.Fatalf("rows %+v", rows)
	}
	// Only operator rows: the child is not a way to forge an analyst's.
	rec.AnalystIdentity = "sub-analyst-1"
	body, _ = json.Marshal(auditWriterRecord(rec))
	errb.Reset()
	if code := runWithStdin([]string{"admin", "-audit-writer", "-config", cfgPath}, bytes.NewReader(body), &out, &errb); code == exitOK {
		t.Fatal("the audit writer appended a row that is not an operator row")
	}
}

// TestCLI_RowsSayWhereTheOperatorNameCameFrom is design/adr/0040 §2: a name
// the environment gave is marked [cli env]; one the kernel gave, [cli].
func TestCLI_RowsSayWhereTheOperatorNameCameFrom(t *testing.T) {
	old := cliLoginUID
	t.Cleanup(func() { cliLoginUID = old })

	cliLoginUID = func() (uint32, bool) { return 0, false }
	t.Setenv("SUDO_USER", "ana.ops")
	a, err := cliActor()
	if err != nil || a.Name != "ana.ops" || a.Front != "cli env" {
		t.Fatalf("from SUDO_USER: %+v, %v; want ana.ops [cli env]", a, err)
	}

	e := newOpTestEnv(t)
	e.opEnv.actor = a
	requireExit(t, runAccessBlock(e.opEnv, a.Name, "sub-1", "stolen laptop"), exitOK, "access block")
	recs, err := e.auditTrail().List(context.Background())
	if err != nil || len(recs) != 1 || !strings.Contains(recs[0].Reason, "[cli env] stolen laptop") {
		t.Fatalf("rows %+v, %v; want the [cli env] tag", recs, err)
	}

	cliLoginUID = func() (uint32, bool) { return uint32(os.Getuid()), true }
	a, err = cliActor()
	if err != nil || a.Front != "cli" || a.Name == "" {
		t.Fatalf("from the loginuid: %+v, %v; want [cli]", a, err)
	}
}

// TestCLI_ApproveAndRevokeWriteOperatorRows: the CLI calls the same service
// as the API, so its approvals reach the trail too.
func TestCLI_ApproveAndRevokeWriteOperatorRows(t *testing.T) {
	e := newOpTestEnv(t)
	obs := mustObserve(t, e, "casemgmt", irisListCases)
	requireExit(t, runToolApproveFingerprint(e.opEnv, "casemgmt", "list_cases", obs.ObservedHash), exitOK, "tool approve")
	requireExit(t, runToolRevoke(e.opEnv, "casemgmt", "list_cases"), exitOK, "tool revoke")
	recs, err := e.auditTrail().List(context.Background())
	if err != nil || len(recs) != 2 || recs[0].Tool != "(tool approve)" || recs[1].Tool != "(tool revoke)" {
		t.Fatalf("rows %+v, %v; want (tool approve) then (tool revoke)", recs, err)
	}
	for _, r := range recs {
		if !strings.HasPrefix(r.AnalystIdentity, "(operator:") || !strings.Contains(r.Reason, obs.ObservedHash) || !strings.Contains(r.Reason, "[cli") {
			t.Errorf("row %+v", r)
		}
	}
}

// writeAdminTestConfig writes a configuration that loads, with its
// database in a directory of its own.
func writeAdminTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "db"), 0o700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("listen = \"127.0.0.1:0\"\n")
	b.WriteString("database = \"" + filepath.Join(dir, "db", "gateway.db") + "\"\n")
	b.WriteString("[oidc]\nissuer = \"https://idp.example.internal\"\naudience = \"https://gw.example.internal/mcp\"\n")
	b.WriteString("[vault]\nsecrets_file = \"" + filepath.Join(dir, "secrets.json") + "\"\nage_key_file = \"" + filepath.Join(dir, "age.key") + "\"\n")
	b.WriteString("[signer]\nrequire_signed = false\n")
	b.WriteString("[[role]]\nname = \"n1\"\ntools = [\"casemgmt.list_cases\"]\n")
	b.WriteString("[group_to_role]\n\"soc-n1\" = \"n1\"\n")
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readAdminTestTrail(t *testing.T, cfgPath string) []audit.Record {
	t.Helper()
	var recs []audit.Record
	code := opRun(cfgPath, &bytes.Buffer{}, &bytes.Buffer{}, func(e *opEnv) int {
		var err error
		recs, err = e.auditTrail().List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return exitOK
	})
	if code != exitOK {
		t.Fatalf("opening the trail: exit %d", code)
	}
	return recs
}

// TestAdmin_TheAuditWriterRunsAsTheOwnerOfARealDatabaseDirectory: the
// accounts backend takes the writer's uid from the database's directory,
// which must be a directory -- a symbolic link in its place is refused.
func TestAdmin_TheAuditWriterRunsAsTheOwnerOfARealDatabaseDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "db")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	uid, _, err := databaseOwner(filepath.Join(real, "gateway.db"))
	if os.Geteuid() != 0 && (err != nil || uid != uint32(os.Getuid())) {
		t.Fatalf("databaseOwner of this test's directory: %d, %v", uid, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := databaseOwner(filepath.Join(link, "gateway.db")); err == nil {
		t.Fatal("a database directory that is a symbolic link was accepted")
	}
}
