package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/store"
)

// setUserVersion stamps a database file with v, as a binary from before
// the schema guard (0) or a newer one (SchemaVersion+1) would have left it.
func setUserVersion(t *testing.T, p string, v int) {
	t.Helper()
	raw, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("PRAGMA user_version = " + strconv.Itoa(v)); err != nil {
		t.Fatal(err)
	}
}

func userVersionOf(t *testing.T, p string) int {
	t.Helper()
	db, err := store.OpenReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v, err := store.SchemaOf(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// pretendRoot makes becomeDatabaseOwner believe it runs as root, and
// records the drop instead of making it; atDrop runs at the moment of the
// drop, to look at what already exists.
func pretendRoot(t *testing.T, atDrop func()) *[]int {
	t.Helper()
	var dropped []int
	signGeteuid = func() int { return 0 }
	signDropTo = func(uid, gid int) error {
		dropped = append(dropped, uid, gid)
		if atDrop != nil {
			atDrop()
		}
		return nil
	}
	t.Cleanup(func() { signGeteuid, signDropTo = os.Geteuid, dropPrivileges })
	return &dropped
}

// noSQLiteFilesYet fails when the database's -wal or -shm, or a restore
// staging file, already exists: something opened the database before the
// drop.
func noSQLiteFilesYet(t *testing.T, dbPath string) func() {
	return func() {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(dbPath + suffix); err == nil {
				t.Errorf("%s existed before the drop: the database was opened as root", filepath.Base(dbPath+suffix))
			}
		}
		ents, _ := os.ReadDir(filepath.Dir(dbPath))
		for _, ent := range ents {
			if strings.HasPrefix(ent.Name(), ".mcp-gateway-restore-") {
				t.Errorf("%s existed before the drop", ent.Name())
			}
		}
	}
}

func dirOwner(t *testing.T, p string) []int {
	t.Helper()
	fi, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	return fileOwner(t, fi)
}

// A file from a binary before the guard (user_version 0) is what every
// host has on its first upgrade to this one: check still reads its chain
// and signatures, through a migrated private copy, and leaves it alone.
func TestCheck_AnOlderSchemaIsReadWithoutWritingIt(t *testing.T) {
	fx := newCheckFixture(t, "")
	setUserVersion(t, fx.cfg.Database, 0)
	before, _, _ := fileSHA256(fx.cfg.Database)

	rep, _ := runFixture(t, fixtureChecker(t, fx))
	if r := resultOf(t, rep, "database schema"); r.Status != checkPass || !strings.Contains(r.Detail, "migrates it") {
		t.Errorf("database schema: %+v", r)
	}
	if r := resultOf(t, rep, "audit trail"); r.Status != checkPass || !strings.Contains(r.Detail, "chain intact") {
		t.Errorf("audit trail: %+v", r)
	}
	if r := resultOf(t, rep, "registry signatures"); r.Status != checkPass || !strings.Contains(r.Detail, "1 signed by a trusted key") {
		t.Errorf("registry signatures: %+v", r)
	}
	if r := resultOf(t, rep, "vault contents"); r.Status != checkPass {
		t.Errorf("vault contents: %+v", r)
	}
	if after, _, _ := fileSHA256(fx.cfg.Database); after != before {
		t.Error("check changed a database at an older schema")
	}
	if v := userVersionOf(t, fx.cfg.Database); v != 0 {
		t.Errorf("check stamped the file with schema %d", v)
	}
}

// Run as root, check stats as root and then becomes the database
// directory's owner before SQLite opens anything.
func TestCheck_AsRootDropsBeforeOpeningTheDatabase(t *testing.T) {
	fx := newCheckFixture(t, "")
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(fx.cfg.Database + suffix)
	}
	c := fixtureChecker(t, fx)
	var statsAfterDrop []string
	dropped := false
	owned := c.stat
	c.stat = func(p string) (fileFacts, error) {
		if dropped {
			statsAfterDrop = append(statsAfterDrop, p)
		}
		return owned(p)
	}
	check := noSQLiteFilesYet(t, fx.cfg.Database)
	got := pretendRoot(t, func() { check(); dropped = true })

	rep, _ := runFixture(t, c)
	if want := dirOwner(t, fx.cfg.Database); len(*got) != 2 || (*got)[0] != want[0] || (*got)[1] != want[1] {
		t.Fatalf("dropped to %v, want the database directory's owner %v", *got, want)
	}
	if r := resultOf(t, rep, "registry signatures"); r.Status != checkPass {
		t.Errorf("after the drop the database was not read: %+v", r)
	}
	for _, p := range statsAfterDrop {
		if p == fx.cfg.Signer.KeyFile || p == fx.cfg.Vault.AgeKeyFile || p == fx.configPath {
			t.Errorf("%s was examined after the drop, without root's view of it", p)
		}
	}
}

// backup is the first command of an upgrade, run with the NEW binary
// while the OLD serve still runs: it must not migrate or stamp the live
// file, which the old binary would then have to open.
func TestBackup_NeverMigratesTheLiveDatabase(t *testing.T) {
	e := newFileEnv(t)
	e.db.Close()
	setUserVersion(t, e.cfg.Database, 0)

	db, err := openLiveForBackup(e.cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e.db = db
	file, res := backupInto(t, e, t.TempDir())
	if v := userVersionOf(t, e.cfg.Database); v != 0 {
		t.Errorf("backup stamped the live file with schema %d", v)
	}
	if res.Schema != 0 || userVersionOf(t, file) != 0 {
		t.Errorf("the copy reports schema %d (file %d), want 0: it is the bytes as they were", res.Schema, userVersionOf(t, file))
	}
	if !res.ChainIntact || res.Upstreams != 1 || len(res.Invalid) != 0 {
		t.Errorf("an older file's copy was not examined: %+v", res)
	}
	if sum, _, _ := fileSHA256(file); sum != res.SHA256 {
		t.Error("the sha256 printed is not the copy's")
	}
}

func TestBackup_RefusesAMissingOrNewerDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gw.db")
	if _, err := openLiveForBackup(missing); err == nil {
		t.Error("backup opened a database that does not exist")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("backup created the database it was asked to copy")
	}

	e := newFileEnv(t)
	e.db.Close()
	setUserVersion(t, e.cfg.Database, store.SchemaVersion+1)
	if _, err := openLiveForBackup(e.cfg.Database); err == nil || !strings.Contains(err.Error(), "newer mcp-gateway") {
		t.Errorf("backup of a newer schema: %v", err)
	}
}

// Through the commands, as root would run them: backup and restore both
// become the database directory's owner before SQLite opens anything, and
// restore reads -in before the drop.
func TestCmdBackupAndRestore_AsRootDropBeforeOpening(t *testing.T) {
	fx := newCheckFixture(t, "")
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(fx.cfg.Database + suffix)
	}
	outDir := t.TempDir()
	got := pretendRoot(t, noSQLiteFilesYet(t, fx.cfg.Database))

	var out, errb bytes.Buffer
	requireExit(t, run([]string{"backup", "-config", fx.configPath, "-out", outDir, "-json"}, &out, &errb), exitOK, "backup as root\n"+errb.String())
	var res backupResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if want := dirOwner(t, fx.cfg.Database); len(*got) != 2 || (*got)[0] != want[0] {
		t.Fatalf("backup dropped to %v, want %v", *got, want)
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(fx.cfg.Database + suffix)
	}
	*got = nil
	out.Reset()
	errb.Reset()
	requireExit(t, run([]string{"restore", "-config", fx.configPath, "-in", res.File, "-expect-head", res.AuditHead}, &out, &errb), exitOK, "restore as root\n"+errb.String())
	if len(*got) != 2 {
		t.Fatalf("restore did not drop: %v", *got)
	}
	requireContains(t, out.String(), "Restored "+fx.cfg.Database, "restore report")
}
