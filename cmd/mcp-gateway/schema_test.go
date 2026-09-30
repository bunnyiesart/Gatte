package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// schemaGolden is the schema openStore produced when SchemaVersion took
// its current value. Regenerate with GATTE_UPDATE_SCHEMA=1 only in the
// change that raises store.SchemaVersion.
func schemaGolden() string {
	return filepath.Join("testdata", fmt.Sprintf("schema-v%d.sql", store.SchemaVersion))
}

// TestSchemaFingerprintMatchesTheVersion is what keeps the schema guard
// honest (design/adr/0045 item 3): a change to any adapter's tables that
// does not raise store.SchemaVersion would let an older binary open a file
// it does not understand, and the guard would say nothing.
func TestSchemaFingerprintMatchesTheVersion(t *testing.T) {
	db, err := openStore(&config.Config{Database: filepath.Join(t.TempDir(), "gw.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := store.SchemaText(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GATTE_UPDATE_SCHEMA") == "1" {
		if err := os.WriteFile(schemaGolden(), []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", schemaGolden())
	}
	want, err := os.ReadFile(schemaGolden())
	if err != nil {
		t.Fatalf("no golden schema for store.SchemaVersion %d (%v). If you raised it, generate %s with GATTE_UPDATE_SCHEMA=1.",
			store.SchemaVersion, err, schemaGolden())
	}
	if got != string(want) {
		t.Fatalf("the database schema changed but store.SchemaVersion is still %d.\n"+
			"Raise it by one in internal/store/schema.go, say what changed in its comment, and generate\n"+
			"testdata/schema-v%d.sql with GATTE_UPDATE_SCHEMA=1 go test -run TestSchemaFingerprint ./cmd/mcp-gateway/\n\n"+
			"schema now:\n%s", store.SchemaVersion, store.SchemaVersion+1, got)
	}
}

func TestOpenStore_RecordsTheSchemaVersion(t *testing.T) {
	cfg := &config.Config{Database: filepath.Join(t.TempDir(), "gw.db")}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	v, err := store.SchemaOf(context.Background(), db)
	db.Close()
	if err != nil || v != store.SchemaVersion {
		t.Fatalf("a file openStore created reads schema %d (%v), want %d", v, err, store.SchemaVersion)
	}
}

// A file from a binary before the guard reads 0 and is migrated as always:
// that is the N-1 file opened by this binary.
func TestOpenStore_AFileFromBeforeTheGuardIsMigratedAndStamped(t *testing.T) {
	cfg := &config.Config{Database: filepath.Join(t.TempDir(), "gw.db")}
	db, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 0"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = openStore(cfg)
	if err != nil {
		t.Fatalf("a pre-guard file (user_version 0) was refused: %v", err)
	}
	defer db.Close()
	if v, _ := store.SchemaOf(context.Background(), db); v != store.SchemaVersion {
		t.Errorf("the pre-guard file now reads %d, want %d", v, store.SchemaVersion)
	}
}

// The N-1 binary on an N file: this binary plays N-1 against a file
// stamped one version ahead. It must refuse before any migration runs, so
// the file is exactly as the newer binary left it.
func TestOpenStore_RefusesANewerSchemaBeforeMigrating(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gw.db")
	raw, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", store.SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db, err := openStore(&config.Config{Database: p})
	if err == nil {
		db.Close()
		t.Fatal("openStore accepted a file one schema version ahead of this binary")
	}
	if !errors.Is(err, store.ErrSchemaTooNew) {
		t.Fatalf("openStore = %v, want ErrSchemaTooNew", err)
	}

	raw, err = store.OpenReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	schema, err := store.SchemaText(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if schema != "" {
		t.Errorf("a migration ran on the refused file:\n%s", schema)
	}
}

// Every operator command goes through openStore, so each refuses too, and
// says why in the terms of the fix.
func TestOperatorCommands_RefuseANewerSchema(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gw.db")
	raw, err := store.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", store.SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	cfgPath := writeMinimalConfig(t, dir, p)

	var out, errBuf bytes.Buffer
	code := run([]string{"upstream", "list", "-config", cfgPath}, &out, &errBuf)
	if code != exitCannotRun {
		t.Fatalf("upstream list on a newer schema = %d, want %d\n%s", code, exitCannotRun, errBuf.String())
	}
	for _, want := range []string{"newer", "docs/upgrade.md"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("the refusal does not say %q:\n%s", want, errBuf.String())
		}
	}
}

// TestCmdServe_RefusesANewerSchema is the item as ADR-0045 states it: serve
// does not start on a file a newer binary wrote.
func TestCmdServe_RefusesANewerSchema(t *testing.T) {
	fx := newServeFixture(t, nil)
	raw, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", store.SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	var out, errBuf bytes.Buffer
	if code := cmdServe([]string{"-config", fx.configPath}, &out, &errBuf); code != exitCannotRun {
		t.Fatalf("serve on a newer schema = %d, want %d\n%s", code, exitCannotRun, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "newer mcp-gateway") {
		t.Errorf("serve's refusal does not name the cause:\n%s", errBuf.String())
	}
}

// The boot row: first on a fresh trail, attributed to the gateway, with
// this binary's identity and schema.
func TestBuildServer_WritesTheBootRow(t *testing.T) {
	fx := newServeFixture(t, nil)
	logger, _ := serveTestLogger()
	stack, err := buildServer(context.Background(), fx.cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	stack.close()

	db, err := openStore(fx.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := &opEnv{cfg: fx.cfg, db: db}
	recs, err := e.auditTrail().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var boot []string
	for _, r := range recs {
		if r.Tool == bootTool {
			if r.AnalystIdentity != "(gateway)" || r.TargetUpstream != "(gateway)" {
				t.Errorf("boot row attributed to %q -> %q, want (gateway) -> (gateway)", r.AnalystIdentity, r.TargetUpstream)
			}
			boot = append(boot, r.Reason)
		}
	}
	if len(boot) != 1 {
		t.Fatalf("%d boot rows after one boot, want 1: %v", len(boot), boot)
	}
	want := fmt.Sprintf("boot: mcp-gateway %s, schema %d", buildIdentity(), store.SchemaVersion)
	if boot[0] != want {
		t.Errorf("boot row reason = %q, want %q", boot[0], want)
	}
}

// writeMinimalConfig writes a configuration that loads without a vault
// fixture: the operator commands never read the vault.
func writeMinimalConfig(t *testing.T, dir, dbPath string) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "listen = %q\ndatabase = %q\n", "127.0.0.1:0", dbPath)
	fmt.Fprintf(&b, "[oidc]\nissuer = %q\naudience = %q\n", "https://idp.example.org", "https://gatte.example.org/mcp")
	fmt.Fprintf(&b, "[vault]\nsecrets_file = %q\nage_key_file = %q\n", filepath.Join(dir, "secrets.enc.json"), filepath.Join(dir, "age.key"))
	fmt.Fprintf(&b, "[signer]\nrequire_signed = false\n")
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
