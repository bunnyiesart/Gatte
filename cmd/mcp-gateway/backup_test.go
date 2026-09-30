package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// fileEnv is an operator environment over a database FILE (backup and
// restore are about files; ":memory:" has none), with one signed entry and
// a few rows on the trail.
type fileEnv struct {
	opTestEnv
	dir string
}

func newFileEnv(t *testing.T) fileEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Listen:    "127.0.0.1:0",
		Database:  filepath.Join(dir, "gw.db"),
		Vault:     config.Vault{SecretsFile: filepath.Join(dir, "secrets.enc.json"), AgeKeyFile: filepath.Join(dir, "age.key")},
		Upstreams: config.Upstreams{AllowCredentialedStdio: true},
	}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	e := opTestEnv{opEnv: &opEnv{cfg: cfg, db: db, stdout: out, stderr: errBuf, configPath: filepath.Join(dir, "config.toml")}, out: out, err: errBuf}

	useSigningKey(t, e)
	mustRegister(t, e, stdioEntry("casemgmt"))
	if code := runSign(e.opEnv, "casemgmt"); code != exitOK {
		t.Fatalf("sign: %d\n%s", code, e.bothText())
	}
	for i := 0; i < 3; i++ {
		appendRow(t, e.opEnv, fmt.Sprintf("row %d", i))
	}
	e.out.Reset()
	e.err.Reset()
	return fileEnv{opTestEnv: e, dir: dir}
}

func appendRow(t *testing.T, e *opEnv, reason string) {
	t.Helper()
	rec := audit.Record{AnalystIdentity: "(operator:tester)", Tool: "(access block)", TargetUpstream: "(gateway)",
		Timestamp: time.Now(), Outcome: audit.OutcomeAllowed, Reason: reason}
	if err := e.recordOperatorAction(rec); err != nil {
		t.Fatal(err)
	}
}

func chainOf(t *testing.T, e *opEnv) audit.ChainCheck {
	t.Helper()
	c, err := e.auditChain().VerifyChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// backupInto runs backup into dir and returns the file it wrote.
func backupInto(t *testing.T, e fileEnv, dir string) (string, backupResult) {
	t.Helper()
	e.out.Reset()
	e.err.Reset()
	if code := runBackup(e.opEnv, dir, 0, true, time.Now()); code != exitOK {
		t.Fatalf("backup = %d\n%s", code, e.bothText())
	}
	var res backupResult
	if err := json.Unmarshal(e.out.Bytes(), &res); err != nil {
		t.Fatalf("backup -json: %v\n%s", err, e.stdoutText())
	}
	return res.File, res
}

func TestBackup_WritesAVerifiedPrivateCopy(t *testing.T) {
	e := newFileEnv(t)
	want := chainOf(t, e.opEnv)
	out := filepath.Join(t.TempDir(), "copy.db")
	if code := runBackup(e.opEnv, out, 0, false, time.Now()); code != exitOK {
		t.Fatalf("backup = %d\n%s", code, e.bothText())
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the copy is mode %04o, want 0600", fi.Mode().Perm())
	}
	sum, _, _ := fileSHA256(out)
	text := e.stdoutText()
	for _, s := range []string{
		"sha256: " + sum,
		fmt.Sprintf("%d record(s), chain intact, head %s", want.Count, want.Head),
		"1 entry: 1 signed by a trusted key",
		"NOT in this file",
		e.cfg.Vault.AgeKeyFile,
		e.cfg.Signer.KeyFile,
		e.configPath,
		"offline",
	} {
		if !strings.Contains(text, s) {
			t.Errorf("backup's report does not say %q:\n%s", s, text)
		}
	}
	// No temporary directory is left beside the copy.
	ents, _ := os.ReadDir(filepath.Dir(out))
	if len(ents) != 1 {
		t.Errorf("backup left %d entries beside the copy, want only the copy", len(ents))
	}
}

func TestBackup_NeverOverwrites(t *testing.T) {
	e := newFileEnv(t)
	out := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(out, []byte("earlier"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runBackup(e.opEnv, out, 0, false, time.Now()); code != exitCannotRun {
		t.Fatalf("backup over an existing file = %d, want %d", code, exitCannotRun)
	}
	if b, _ := os.ReadFile(out); string(b) != "earlier" {
		t.Error("backup changed a file that already existed")
	}
}

func TestBackup_KeepPrunesOnlyItsOwnNames(t *testing.T) {
	e := newFileEnv(t)
	dir := t.TempDir()
	old := []string{"mcp-gateway-20260101T000000Z.db", "mcp-gateway-20260102T000000Z.db", "mcp-gateway-20260103T000000Z.db"}
	for _, n := range append(old, "notes.txt", "mcp-gateway-latest.db") {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if code := runBackup(e.opEnv, dir, 2, false, now); code != exitOK {
		t.Fatalf("backup = %d\n%s", code, e.bothText())
	}
	var names []string
	ents, _ := os.ReadDir(dir)
	for _, ent := range ents {
		names = append(names, ent.Name())
	}
	want := []string{"mcp-gateway-20260103T000000Z.db", "mcp-gateway-20260930T120000Z.db", "mcp-gateway-latest.db", "notes.txt"}
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Errorf("after -keep 2 the directory holds %v, want %v", names, want)
	}

	// -keep with a file -out is bad usage.
	if code := runBackup(e.opEnv, filepath.Join(t.TempDir(), "x.db"), 2, false, now); code != exitCannotRun {
		t.Errorf("-keep with a file -out = %d, want %d", code, exitCannotRun)
	}
}

func TestBackup_UsageNeedsOut(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"backup"}, &out, &errBuf); code != exitCannotRun {
		t.Fatalf("backup without -out = %d, want %d", code, exitCannotRun)
	}
	if code := run([]string{"restore"}, &out, &errBuf); code != exitCannotRun {
		t.Fatalf("restore without -in = %d, want %d", code, exitCannotRun)
	}
	out.Reset()
	if code := run([]string{"backup", "-h"}, &out, &errBuf); code != exitOK || !strings.Contains(out.String(), "NOT in it") {
		t.Errorf("backup -h = %d:\n%s", code, out.String())
	}
}

// restoreEnv closes the live handle, the way restore runs: serve stopped
// and no command holding the file.
func restoreEnv(t *testing.T, e fileEnv) *opEnv {
	t.Helper()
	e.db.Close()
	e.out.Reset()
	e.err.Reset()
	return &opEnv{cfg: e.cfg, stdout: e.out, stderr: e.err, configPath: e.configPath}
}

func TestRestore_RoundTrip(t *testing.T) {
	e := newFileEnv(t)
	file, res := backupInto(t, e, t.TempDir())
	appendRow(t, e.opEnv, "after the backup")

	r := restoreEnv(t, e)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if code := runRestore(r, file, res.AuditHead, now); code != exitOK {
		t.Fatalf("restore = %d\n%s", code, e.bothText())
	}
	kept := e.cfg.Database + ".pre-restore-20260930T120000Z"
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("the replaced database was not kept at %s: %v", kept, err)
	}
	if !strings.Contains(e.stdoutText(), kept) || !strings.Contains(e.stdoutText(), "fork") {
		t.Errorf("restore's report does not name the kept file and the SIEM fork:\n%s", e.stdoutText())
	}

	db, err := openStore(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after := &opEnv{cfg: e.cfg, db: db}
	recs, err := after.auditTrail().(interface {
		ChainOrder(context.Context) ([]audit.Record, error)
	}).ChainOrder(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if rec.Reason == "after the backup" {
			t.Error("a row written after the backup survived the restore")
		}
	}
	last := recs[len(recs)-1]
	if last.Tool != restoreTool || !strings.Contains(last.Reason, res.SHA256) || !strings.Contains(last.Reason, kept) {
		t.Errorf("the last row is not the restore row naming the backup and the kept file: %+v", last)
	}
	c := chainOf(t, after)
	if !c.Intact() || c.Count != res.AuditRecords+1 {
		t.Errorf("restored chain: intact %v, %d records; want intact, %d", c.Intact(), c.Count, res.AuditRecords+1)
	}
	if v, _ := store.SchemaOf(context.Background(), db); v != store.SchemaVersion {
		t.Errorf("restored file reads schema %d", v)
	}
	// The operator's backup file itself is untouched.
	if sum, _, _ := fileSHA256(file); sum != res.SHA256 {
		t.Error("restore changed the backup file it read")
	}
}

// refuseRestore runs restore on a doctored copy and checks nothing changed.
func refuseRestore(t *testing.T, e fileEnv, file, expectHead, want string) {
	t.Helper()
	r := restoreEnv(t, e)
	before, _, _ := fileSHA256(e.cfg.Database)
	code := runRestore(r, file, expectHead, time.Now())
	if code == exitOK {
		t.Fatalf("restore accepted it:\n%s", e.bothText())
	}
	if !strings.Contains(e.stderrText(), want) || !strings.Contains(e.stderrText(), "was not changed") &&
		!strings.Contains(e.stderrText(), "Nothing was changed") {
		t.Errorf("the refusal does not say %q and that nothing changed:\n%s", want, e.stderrText())
	}
	if after, _, _ := fileSHA256(e.cfg.Database); after != before {
		t.Error("a refused restore changed the live database")
	}
	ents, _ := os.ReadDir(e.dir)
	for _, ent := range ents {
		if strings.HasPrefix(ent.Name(), ".mcp-gateway-restore-") || strings.Contains(ent.Name(), "pre-restore") {
			t.Errorf("a refused restore left %s behind", ent.Name())
		}
	}
}

// doctor copies the backup and changes the copy with sql.
func doctor(t *testing.T, file, stmt string) string {
	t.Helper()
	cp := filepath.Join(t.TempDir(), "doctored.db")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cp)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	return cp
}

func TestRestore_RefusesAnEditedTrail(t *testing.T) {
	e := newFileEnv(t)
	file, _ := backupInto(t, e, t.TempDir())
	cp := doctor(t, file, `UPDATE audit_records SET reason = 'nothing to see' WHERE id = 2`)
	refuseRestore(t, e, cp, "", "BROKEN at record 2")
}

func TestRestore_RefusesTheWrongHead(t *testing.T) {
	e := newFileEnv(t)
	file, _ := backupInto(t, e, t.TempDir())
	refuseRestore(t, e, file, strings.Repeat("0", 64), "not at -expect-head")
}

func TestRestore_RefusesAnEntryChangedAfterSigning(t *testing.T) {
	e := newFileEnv(t)
	file, _ := backupInto(t, e, t.TempDir())
	cp := doctor(t, file, `UPDATE upstream_servers SET command = '/bin/sh' WHERE name = 'casemgmt'`)
	refuseRestore(t, e, cp, "", "signature fails")
}

func TestRestore_RefusesACorruptFile(t *testing.T) {
	e := newFileEnv(t)
	file, _ := backupInto(t, e, t.TempDir())
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(b) / 2; i < len(b)/2+8192 && i < len(b); i++ {
		b[i] = 0x5A
	}
	cp := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(cp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	refuseRestore(t, e, cp, "", "integrity")
}

func TestRestore_RefusesANewerSchema(t *testing.T) {
	e := newFileEnv(t)
	file, _ := backupInto(t, e, t.TempDir())
	cp := doctor(t, file, fmt.Sprintf("PRAGMA user_version = %d", store.SchemaVersion+1))
	refuseRestore(t, e, cp, "", "newer mcp-gateway")
}

func TestRestore_RefusesWhileServeListens(t *testing.T) {
	e := newFileEnv(t)
	file, _ := backupInto(t, e, t.TempDir())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e.cfg.Listen = ln.Addr().String()
	refuseRestore(t, e, file, "", "Stop serve first")
}

func TestRestore_RefusesTheLiveFileItself(t *testing.T) {
	e := newFileEnv(t)
	r := restoreEnv(t, e)
	if code := runRestore(r, e.cfg.Database, "", time.Now()); code != exitCannotRun {
		t.Fatalf("restore of the live file onto itself = %d, want %d", code, exitCannotRun)
	}
}

// A disaster recovery: no database at all yet on this host.
func TestRestore_OntoAHostWithNoDatabase(t *testing.T) {
	e := newFileEnv(t)
	file, res := backupInto(t, e, t.TempDir())
	r := restoreEnv(t, e)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(e.cfg.Database + suffix)
	}
	if code := runRestore(r, file, res.AuditHead, time.Now()); code != exitOK {
		t.Fatalf("restore onto an empty host = %d\n%s", code, e.bothText())
	}
	if strings.Contains(e.stdoutText(), "kept as") {
		t.Errorf("restore claims to have kept a database that did not exist:\n%s", e.stdoutText())
	}
}
