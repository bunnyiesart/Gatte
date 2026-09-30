package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openFile(t *testing.T) (string, func() *sql.DB) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gw.db")
	return p, func() *sql.DB {
		db, err := Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}
}

func TestSchemaVersion_NewFileIsZeroAndRecordRaisesIt(t *testing.T) {
	ctx := context.Background()
	_, open := openFile(t)
	db := open()
	if v, err := CheckSchema(ctx, db); err != nil || v != 0 {
		t.Fatalf("CheckSchema on a new file = %d, %v; want 0, nil", v, err)
	}
	if err := RecordSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if v, _ := SchemaOf(ctx, db); v != SchemaVersion {
		t.Fatalf("after RecordSchema the file reads %d, want %d", v, SchemaVersion)
	}
}

func TestSchemaVersion_ANewerFileIsRefusedAndLeftAlone(t *testing.T) {
	ctx := context.Background()
	_, open := openFile(t)
	db := open()
	newer := SchemaVersion + 1
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", newer)); err != nil {
		t.Fatal(err)
	}
	v, err := CheckSchema(ctx, db)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("CheckSchema on schema %d = %v; want ErrSchemaTooNew", newer, err)
	}
	if v != newer {
		t.Errorf("CheckSchema reported %d, want the file's %d", v, newer)
	}
	for _, want := range []string{fmt.Sprint(newer), fmt.Sprint(SchemaVersion), "newer mcp-gateway", "docs/upgrade.md", "Nothing was changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
	// RecordSchema never lowers what a newer binary wrote.
	if err := RecordSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if got, _ := SchemaOf(ctx, db); got != newer {
		t.Errorf("RecordSchema lowered schema %d to %d", newer, got)
	}
}

func TestSnapshot_IsConsistentWhileAnotherHandleWrites(t *testing.T) {
	ctx := context.Background()
	p, open := openFile(t)
	db := open()
	if _, err := db.Exec(`CREATE TABLE t (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := db.Exec(`INSERT INTO t VALUES (?)`, i); err != nil {
			t.Fatal(err)
		}
	}

	// A second handle keeps writing, the way serve does while a timer runs
	// the backup from another process.
	writer, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1000; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = writer.Exec(`INSERT INTO t VALUES (?)`, i)
		}
	}()

	dst := filepath.Join(t.TempDir(), "snap.db")
	err = Snapshot(ctx, db, dst)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst + "-wal"); err == nil {
		t.Error("the snapshot has a -wal beside it; it must be one self-contained file")
	}

	snap, err := OpenReadOnly(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	problems, err := IntegrityCheck(ctx, snap)
	if err != nil || problems != nil {
		t.Fatalf("integrity of the snapshot: %v %v", problems, err)
	}
	var n int
	if err := snap.QueryRow(`SELECT COUNT(*) FROM t WHERE n < 50`).Scan(&n); err != nil || n != 50 {
		t.Fatalf("the snapshot holds %d of the 50 rows committed before it (%v)", n, err)
	}
	if _, err := snap.Exec(`INSERT INTO t VALUES (1)`); err == nil {
		t.Error("OpenReadOnly accepted a write")
	}

	// VACUUM INTO refuses to overwrite a file that exists.
	if err := Snapshot(ctx, db, dst); err == nil {
		t.Error("Snapshot overwrote an existing file")
	}
}

func TestIntegrityCheck_ReportsACorruptFile(t *testing.T) {
	ctx := context.Background()
	_, open := openFile(t)
	db := open()
	if _, err := db.Exec(`CREATE TABLE t (s TEXT); CREATE INDEX i ON t(s)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := db.Exec(`INSERT INTO t VALUES (?)`, strings.Repeat("x", i%50)+fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	dst := filepath.Join(t.TempDir(), "snap.db")
	if err := Snapshot(ctx, db, dst); err != nil {
		t.Fatal(err)
	}
	// Overwrite part of a page past the header: the file still opens and
	// the check must say it is damaged.
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(b) / 2; i < len(b)/2+4096 && i < len(b); i++ {
		b[i] = 0xA5
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := OpenReadOnly(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	problems, err := IntegrityCheck(ctx, snap)
	if err == nil && len(problems) == 0 {
		t.Fatal("IntegrityCheck said ok for a file with a page overwritten")
	}
}
