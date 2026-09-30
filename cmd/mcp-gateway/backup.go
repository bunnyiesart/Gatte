// Operator Console -- "backup" and "restore": a consistent copy of the
// database while serve runs, and the way back from one
// (design/adr/0045 item 2).
//
// These are host commands, not management-API actions, like register and
// sign: a backup writes a file on the host and a restore replaces the
// database under a stopped gateway, and neither is something a front on a
// socket should be able to ask for.

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// backupNameLayout names a backup written into a directory. UTC and
// fixed-width, so the names sort in time order and -keep can prune by name.
const backupNameLayout = "20060102T150405Z"

var backupNameRe = regexp.MustCompile(`^mcp-gateway-[0-9]{8}T[0-9]{6}Z\.db$`)

// Tool of the operator row a restore writes. A declared interface string.
const restoreTool = "(restore)"

func backupUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway backup  [-config FILE] -out FILE|DIR [-keep N] [-json]
  mcp-gateway restore [-config FILE] -in FILE [-expect-head HASH]

backup writes a consistent copy of the database (SQLite VACUUM INTO) while
serve runs, then checks the copy: SQLite integrity, the audit trail's hash
chain, and every registry entry's signature against this configuration's
trusted keys. -out names a new file, or an existing directory, where the
copy is named mcp-gateway-YYYYMMDDTHHMMSSZ.db; with a directory, -keep N
then removes all but the newest N copies of that name. The copy is 0600.
backup never migrates the live database, so the new binary can take the
copy before an upgrade while the old serve still runs. Run it as the
service account; run as root, it first becomes the owner of the database's
directory, as sign does.

The copy is the database and nothing else. NOT in it, to be backed up
separately (backup prints the paths this configuration names): the
configuration file, the encrypted vault, the age key, the signing key, the
identity provider's accounts, the SIEM copy of the trail, the proxy's TLS
material. The age key and the signing key are secrets: keep their copies
offline and apart from the database copies.

restore replaces the database with a backup, with serve stopped. It refuses
unless the file passes SQLite's integrity check, its schema is one this
binary knows, its audit chain verifies (and ends at -expect-head, when
given), and no registry entry in it carries a signature that fails against
this configuration's trusted keys. The database it replaces is kept beside
it as FILE.pre-restore-YYYYMMDDTHHMMSSZ, and the restore is recorded in the
restored trail as a (restore) operator row. Run as root, it opens -in as
root and then becomes the owner of the database's directory before writing
anything there. See docs/upgrade.md.

Exit codes: 0 ok; 1 ran and found a problem (a copy whose chain is broken
is still written, and says so; a refused restore changes nothing); 2 could
not run.
`)
}

// backupResult is what backup -json prints.
type backupResult struct {
	File         string   `json:"file"`
	Bytes        int64    `json:"bytes"`
	SHA256       string   `json:"sha256"`
	Schema       int      `json:"schema_version"`
	SchemaDrift  []string `json:"schema_drift"`
	AuditRecords int      `json:"audit_records"`
	AuditHead    string   `json:"audit_head"`
	ChainIntact  bool     `json:"chain_intact"`
	Upstreams    int      `json:"upstreams"`
	Invalid      []string `json:"invalid_signatures"`
	Pruned       []string `json:"pruned"`
	NotIncluded  []string `json:"not_included"`
}

func cmdBackup(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("backup", stderr)
	out := fs.String("out", "", "file to write, or an existing directory")
	keep := fs.Int("keep", 0, "with a directory -out: keep only the newest N backups there")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if code, ok := opParse(fs, args, stdout, stderr, backupUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, backupUsage) {
		return exitCannotRun
	}
	if *out == "" {
		fmt.Fprint(stderr, "backup: -out is required\n\n")
		backupUsage(stderr)
		return exitCannotRun
	}
	if *keep < 0 {
		fmt.Fprint(stderr, "backup: -keep must be 0 (keep all) or more\n")
		return exitCannotRun
	}
	cfg, ok := loadConfig(*configPath, stderr)
	if !ok {
		return exitCannotRun
	}
	if !becomeDatabaseOwner(cfg, stderr) {
		return exitCannotRun
	}
	db, err := openLiveForBackup(cfg.Database)
	if err != nil {
		fmt.Fprintf(stderr, "backup: %v\n", err)
		if errors.Is(err, store.ErrSchemaTooNew) {
			return exitProblem
		}
		return exitCannotRun
	}
	defer db.Close()
	abs, err := filepath.Abs(*configPath)
	if err != nil {
		abs = *configPath
	}
	return runBackup(&opEnv{cfg: cfg, db: db, stdout: stdout, stderr: stderr, configPath: abs}, *out, *keep, *asJSON, time.Now())
}

// openLiveForBackup opens the live database for reading a copy out of it,
// and nothing else: no migration and no schema stamp. Every other command
// goes through openStore, which migrates; backup must not, because it is
// the command an upgrade runs FIRST, with the new binary, while the old
// serve still runs on the file (docs/upgrade.md, step 2). The copy is
// examined after a migration of its own, on a scratch file.
//
// The schema guard still applies: a file a newer binary wrote is refused.
// A missing file is refused rather than created.
func openLiveForBackup(dbPath string) (*sql.DB, error) {
	if dbPath == ":memory:" {
		return nil, errors.New("database = \":memory:\" has no file to back up")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("the database %s cannot be read: %w", dbPath, err)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := store.CheckSchema(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func runBackup(e *opEnv, out string, keep int, asJSON bool, now time.Time) int {
	ctx := e.ctx()
	dest, intoDir, err := backupDestination(out, now)
	if err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}
	if keep > 0 && !intoDir {
		fmt.Fprint(e.stderr, "backup: -keep needs -out to be a directory\n")
		return exitCannotRun
	}

	// The snapshot is written into a private directory beside the
	// destination and renamed into place: the copy is never readable by
	// anyone else, even for the moment between VACUUM and chmod, and a
	// failed or interrupted run leaves no half-written file under the
	// destination's name.
	tmpDir, err := os.MkdirTemp(filepath.Dir(dest), ".mcp-gateway-backup-")
	if err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	snap := filepath.Join(tmpDir, "snapshot.db")
	if err := store.Snapshot(ctx, e.db, snap); err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}
	if err := os.Chmod(snap, 0o600); err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}

	rep, code := inspectFile(ctx, e.cfg, snap, e.stderr, false)
	if code != exitOK {
		fmt.Fprint(e.stderr, "backup: the copy failed its own check and was not kept.\n")
		return code
	}
	sum, size, err := fileSHA256(snap)
	if err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}
	if err := syncFile(snap); err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}
	if err := placeNoReplace(snap, dest); err != nil {
		fmt.Fprintf(e.stderr, "backup: %v\n", err)
		return exitCannotRun
	}
	_ = syncDir(filepath.Dir(dest))

	var pruned []string
	if keep > 0 {
		pruned, err = pruneBackups(filepath.Dir(dest), keep)
		if err != nil {
			fmt.Fprintf(e.stderr, "backup: written, but pruning old copies failed: %v\n", err)
		}
	}

	res := backupResult{
		File: dest, Bytes: size, SHA256: sum, Schema: rep.Schema,
		SchemaDrift: nonNil(rep.Drift), AuditRecords: rep.Chain.Count, AuditHead: rep.Chain.Head, ChainIntact: rep.Chain.Intact(),
		Upstreams: rep.Upstreams, Invalid: nonNil(rep.Invalid), Pruned: nonNil(pruned),
		NotIncluded: notInBackup(e),
	}
	if asJSON {
		if err := opJSON(e.stdout, res); err != nil {
			fmt.Fprintf(e.stderr, "backup: %v\n", err)
			return exitCannotRun
		}
	} else {
		fmt.Fprintf(e.stdout, "Wrote %s (%d bytes, 0600)\n", dest, size)
		fmt.Fprintf(e.stdout, "sha256: %s\n", sum)
		fmt.Fprintf(e.stdout, "schema: %d\n", rep.Schema)
		fmt.Fprintln(e.stdout, "audit trail: "+rep.chainLine())
		fmt.Fprintln(e.stdout, "registry: "+rep.signatureLine())
		for _, p := range pruned {
			fmt.Fprintf(e.stdout, "removed old backup %s\n", p)
		}
		fmt.Fprint(e.stdout, "\nNOT in this file; back these up separately:\n")
		for _, n := range res.NotIncluded {
			fmt.Fprintf(e.stdout, "  - %s\n", n)
		}
		fmt.Fprint(e.stdout, "\nKeep the sha256 and the audit head where this host cannot write: restore\n"+
			"-expect-head takes the head back, and together they say this copy is the one you took.\n")
	}

	if len(rep.Drift) > 0 {
		fmt.Fprintf(e.stderr, "\nWARNING: the database this copy was taken from: %s.\n"+
			"The copy is kept as evidence; restore will refuse it. Compare with a new database's\n"+
			"schema (sqlite3 FILE .schema) before trusting the live one.\n", rep.driftLine())
		return exitProblem
	}
	if !rep.Chain.Intact() || len(rep.Invalid) > 0 {
		// Kept: it is a faithful copy of what is there, and what is there is
		// evidence. But not a copy restore will accept, and the operator
		// learns that now rather than on the day they need it.
		fmt.Fprint(e.stderr, "\nWARNING: the database this copy was taken from has a broken audit chain or an\n"+
			"entry whose signature fails. The copy is kept as evidence; restore will refuse it.\n"+
			"Run mcp-gateway audit -verify and mcp-gateway upstream list on the live database.\n")
		return exitProblem
	}
	return exitOK
}

// backupDestination resolves -out: a directory gets a timestamped name,
// anything else must not exist yet.
func backupDestination(out string, now time.Time) (dest string, intoDir bool, err error) {
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		return filepath.Join(out, "mcp-gateway-"+now.UTC().Format(backupNameLayout)+".db"), true, nil
	}
	if _, err := os.Lstat(out); err == nil {
		return "", false, fmt.Errorf("%s exists; backup never overwrites a file", out)
	}
	if fi, err := os.Stat(filepath.Dir(out)); err != nil || !fi.IsDir() {
		return "", false, fmt.Errorf("the directory of %s does not exist", out)
	}
	return out, false, nil
}

// pruneBackups removes all but the newest keep files named like a backup
// in dir. Only that exact name: nothing else in the directory is touched.
func pruneBackups(dir string, keep int) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, ent := range ents {
		if ent.Type().IsRegular() && backupNameRe.MatchString(ent.Name()) {
			names = append(names, ent.Name())
		}
	}
	slices.Sort(names)
	var removed []string
	for len(names) > keep {
		p := filepath.Join(dir, names[0])
		if err := os.Remove(p); err != nil {
			return removed, err
		}
		removed = append(removed, p)
		names = names[1:]
	}
	return removed, nil
}

// notInBackup names what the database copy does not hold, with the paths
// this configuration gives them. Paths only: nothing is read.
func notInBackup(e *opEnv) []string {
	var out []string
	add := func(what, p string) {
		if p != "" {
			out = append(out, what+": "+p)
		}
	}
	add("the configuration file (roles, trusted keys)", e.configPath)
	if e.configPath == "" {
		out = append(out, "the configuration file (roles, trusted keys)")
	}
	add("the encrypted vault (sops)", e.cfg.Vault.SecretsFile)
	add("the age key that decrypts it (a secret: offline, apart from this copy)", e.cfg.Vault.AgeKeyFile)
	if e.cfg.Signer.KeyFile != "" {
		add("the signing key (a secret, root's: offline, apart from this copy)", e.cfg.Signer.KeyFile)
	} else {
		out = append(out, "the signing key (a secret, root's: offline, apart from this copy)")
	}
	if e.cfg.IdP.UsersFile != "" {
		add("the identity provider's accounts", e.cfg.IdP.UsersFile)
	} else {
		out = append(out, "the identity provider's accounts, keys and configuration (the IdP's own backup)")
	}
	if e.cfg.Audit.SIEM.Enabled() {
		add("the SIEM copy of the trail (the trail itself is in this copy)", e.cfg.Audit.SIEM.Path)
	}
	add("the CA the connect scripts hand out", e.cfg.Connect.CAFile)
	out = append(out, "the reverse proxy's TLS certificates and configuration",
		"container images of oci backends (the registry pins each by digest)")
	return out
}

func cmdRestore(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("restore", stderr)
	in := fs.String("in", "", "the backup file to restore")
	expectHead := fs.String("expect-head", "", "refuse unless the backup's audit chain ends at this hash")
	if code, ok := opParse(fs, args, stdout, stderr, backupUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, backupUsage) {
		return exitCannotRun
	}
	if *in == "" {
		fmt.Fprint(stderr, "restore: -in is required\n\n")
		backupUsage(stderr)
		return exitCannotRun
	}
	cfg, ok := loadConfig(*configPath, stderr)
	if !ok {
		return exitCannotRun
	}
	// The backup is opened before the drop below: an operator who copied
	// it back from elsewhere as root need not hand it to the service
	// account first. Everything after the drop runs as the database
	// directory's owner, so every file restore writes there is the
	// service's, the restored database included.
	src, err := os.Open(*in)
	if err != nil {
		fmt.Fprintf(stderr, "restore: %v\n", err)
		return exitCannotRun
	}
	defer src.Close()
	if !becomeDatabaseOwner(cfg, stderr) {
		return exitCannotRun
	}
	abs, err := filepath.Abs(*configPath)
	if err != nil {
		abs = *configPath
	}
	return runRestoreFrom(&opEnv{cfg: cfg, stdout: stdout, stderr: stderr, configPath: abs}, *in, src, *expectHead, time.Now())
}

// runRestore is restore of the file at in; see runRestoreFrom.
func runRestore(e *opEnv, in, expectHead string, now time.Time) int {
	src, err := os.Open(in)
	if err != nil {
		fmt.Fprintf(e.stderr, "restore: %v\n", err)
		return exitCannotRun
	}
	defer src.Close()
	return runRestoreFrom(e, in, src, expectHead, now)
}

// runRestoreFrom is restore with the configuration loaded, the backup open
// as src, and no database open: it opens the files it needs itself, in the
// order that keeps the live database untouched until every check has
// passed.
func runRestoreFrom(e *opEnv, in string, src *os.File, expectHead string, now time.Time) int {
	ctx := e.ctx()
	live := e.cfg.Database

	// serve holds the listen address while it runs. A restore under a
	// running serve would swap the file under its open handle: serve
	// would keep writing to the replaced file, and the restore would
	// silently not have happened.
	ln, err := net.Listen("tcp", e.cfg.Listen)
	if err != nil {
		fmt.Fprintf(e.stderr, "restore: something is listening on %s, the address serve uses (%v).\n"+
			"Stop serve first (maintenance on, then stop the service): see docs/upgrade.md. Nothing was changed.\n",
			e.cfg.Listen, err)
		return exitProblem
	}
	_ = ln.Close()

	inInfo, err := src.Stat()
	if err != nil || !inInfo.Mode().IsRegular() {
		fmt.Fprintf(e.stderr, "restore: %s is not a regular file\n", in)
		return exitCannotRun
	}
	if liveInfo, err := os.Stat(live); err == nil && os.SameFile(inInfo, liveInfo) {
		fmt.Fprint(e.stderr, "restore: -in is the live database itself\n")
		return exitCannotRun
	}

	// A staging copy beside the live file: the checks run on it (they
	// migrate it, which must never touch the operator's backup), and the
	// swap is then a rename within one directory. The sha256 is of the
	// bytes copied, the ones every check then reads.
	staging, sum, err := stageCopy(src, filepath.Dir(live))
	if err != nil {
		fmt.Fprintf(e.stderr, "restore: %v\n", err)
		return exitCannotRun
	}
	cleanup := func() { removeDBFiles(staging) }

	rep, code := inspectFile(ctx, e.cfg, staging, e.stderr, true)
	if code == exitOK {
		code = restoreVerdict(e, rep, expectHead)
	}
	if code != exitOK {
		cleanup()
		fmt.Fprintf(e.stderr, "restore: refused. %s was not changed.\n", live)
		return code
	}

	// Every check passed: move the live database aside, with its -wal and
	// -shm, which hold committed rows not yet in the main file, and put the
	// staging copy in its place.
	kept := ""
	if _, err := os.Lstat(live); err == nil {
		kept = live + ".pre-restore-" + now.UTC().Format(backupNameLayout)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := os.Rename(live+suffix, kept+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanup()
				fmt.Fprintf(e.stderr, "restore: could not move the live database aside: %v\n"+
					"Check %s and %s by hand before starting serve.\n", err, live, kept)
				return exitCannotRun
			}
		}
	}
	if err := os.Rename(staging, live); err != nil {
		fmt.Fprintf(e.stderr, "restore: could not put the backup in place: %v\n", err)
		if kept != "" {
			fmt.Fprintf(e.stderr, "The previous database is at %s; move it back to %s before starting serve.\n", kept, live)
		}
		return exitCannotRun
	}
	cleanup()
	_ = syncDir(filepath.Dir(live))

	db, err := openStore(e.cfg)
	if err != nil {
		fmt.Fprintf(e.stderr, "restore: the restored database does not open: %v\n", err)
		return exitCannotRun
	}
	defer db.Close()
	e.db = db

	reason := fmt.Sprintf("restored from a backup, sha256:%s, %d audit record(s), head %s",
		sum, rep.Chain.Count, headOrNone(rep.Chain.Head))
	if kept != "" {
		reason += "; the database it replaced is kept as " + strconv.Quote(kept)
	}
	recorded := true
	actor, err := e.operator()
	if err == nil {
		rec := audit.Record{
			AnalystIdentity: actor.Identity(), Tool: restoreTool, TargetUpstream: operatorTarget,
			Timestamp: time.Now(), Outcome: audit.OutcomeAllowed, Reason: actor.Tag() + " " + reason,
		}
		err = retryBusy(ctx, func() error { return e.recordOperatorAction(rec) })
	}
	if err != nil {
		recorded = false
		fmt.Fprintf(e.stderr, "restore: the database is restored, but the trail could not record it: %v\n"+
			"Record it by hand before starting serve.\n", err)
	}

	fmt.Fprintf(e.stdout, "Restored %s from %s (sha256 %s).\n", live, in, sum)
	fmt.Fprintln(e.stdout, "audit trail: "+rep.chainLine())
	fmt.Fprintln(e.stdout, "registry: "+rep.signatureLine())
	if kept != "" {
		fmt.Fprintf(e.stdout, "The database it replaced is kept as %s.\n", kept)
	}
	fmt.Fprint(e.stdout, "\nEverything written after this backup was taken is not in the restored trail.\n"+
		"The SIEM copy still holds it: the restore row links to the backup's head, so the\n"+
		"SIEM sees two lines after that head. That fork is this restore, not tampering.\n"+
		"Next: mcp-gateway check, then start serve, then maintenance off.\n")
	if !recorded {
		return exitProblem
	}
	return exitOK
}

// restoreVerdict applies restore's refusal rules to a file that passed
// the integrity check.
func restoreVerdict(e *opEnv, rep dbReport, expectHead string) int {
	ok := true
	if len(rep.Drift) > 0 {
		fmt.Fprintf(e.stderr, "restore: the backup's %s\n"+
			"A trigger, view or index this binary did not create is a rule the file brings with it (one that\n"+
			"approves a tool as it is observed, or removes a block as it is placed), and no other check sees it.\n",
			rep.driftLine())
		ok = false
	}
	if rep.Chain.FirstBreak != nil {
		fmt.Fprintf(e.stderr, "restore: the backup's audit trail is %s\n", rep.chainLine())
		ok = false
	}
	if expectHead != "" && !strings.EqualFold(expectHead, rep.Chain.Head) {
		fmt.Fprintf(e.stderr, "restore: the backup's audit chain ends at %s, not at -expect-head %s\n",
			headOrNone(rep.Chain.Head), expectHead)
		ok = false
	}
	if len(rep.Invalid) > 0 {
		fmt.Fprintf(e.stderr, "restore: registry entries whose signature fails against this configuration's trusted keys: %s\n"+
			"An entry changed after it was signed has no benign reading (design/adr/0006).\n",
			strings.Join(rep.Invalid, ", "))
		ok = false
	}
	if !ok {
		return exitProblem
	}
	if expectHead == "" {
		// The chain has no key: it proves the rows agree with each other,
		// not that they are the ones this host wrote. A trail rewritten
		// whole and chained again verifies; only a head kept elsewhere
		// tells them apart.
		fmt.Fprint(e.stderr, "note: no -expect-head, so the trail was checked for consistency only. A trail rewritten\n"+
			"whole and chained again passes that check; the head backup printed, kept off this host, does not.\n")
	}
	if len(rep.Unsigned) > 0 {
		fmt.Fprintf(e.stderr, "note: unsigned entries in the backup (%s); serve does not serve them while signer.require_signed is on.\n",
			strings.Join(rep.Unsigned, ", "))
	}
	return exitOK
}

// inspectFile runs the integrity check on path, then (only if it passed)
// the schema guard, and examines the rest.
//
// With migrate false the file is only read: that is backup's own copy,
// whose bytes are the ones the printed sha256 describes, or check's
// snapshot. A file at an older schema than this binary's may lack a column
// the adapters read, so it is examined through a scratch copy beside it,
// migrated the way the next serve will migrate it; the file itself is
// never written. With migrate true it is opened the way openStore opens a
// database, migrations included: that is restore's staging copy, which is
// about to become the live file.
//
// rep.Schema is always the version recorded in path, before any migration.
// Problems are printed to stderr; the code is exitOK, exitProblem (the
// file failed a check) or exitCannotRun.
func inspectFile(ctx context.Context, cfg *config.Config, path string, stderr io.Writer, migrate bool) (dbReport, int) {
	var rep dbReport
	raw, err := store.OpenReadOnly(path)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return rep, exitCannotRun
	}
	problems, err := inspectIntegrity(ctx, raw)
	if err != nil || len(problems) > 0 {
		raw.Close()
		if err != nil {
			problems = append(problems, err.Error())
		}
		fmt.Fprintf(stderr, "SQLite integrity check of %s failed:\n", path)
		for i, p := range problems {
			if i == 10 {
				fmt.Fprintf(stderr, "  ... and %d more\n", len(problems)-10)
				break
			}
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		return rep, exitProblem
	}
	recorded, err := store.CheckSchema(ctx, raw)
	if err != nil {
		raw.Close()
		fmt.Fprintf(stderr, "%v\n", err)
		if errors.Is(err, store.ErrSchemaTooNew) {
			return rep, exitProblem
		}
		return rep, exitCannotRun
	}

	db := raw
	switch {
	case migrate:
		raw.Close()
		if db, err = openStorePath(path); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return rep, exitCannotRun
		}
	case recorded < store.SchemaVersion:
		raw.Close()
		scratch, err := stageCopyFile(path, filepath.Dir(path))
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return rep, exitCannotRun
		}
		defer removeDBFiles(scratch)
		if db, err = openStorePath(scratch); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return rep, exitCannotRun
		}
	}
	defer db.Close()
	if err := inspectContent(ctx, cfg, db, &rep); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return rep, exitProblem
	}
	rep.Schema = recorded
	if migrate {
		// Fold the WAL back so the file is complete on its own when closed.
		_, _ = db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	return rep, exitOK
}

// removeDBFiles removes a database file and the files SQLite keeps beside it.
func removeDBFiles(p string) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(p + suffix)
	}
}

// stageCopy copies src to a new private file in dir, and returns its name
// and the hex SHA-256 of the bytes copied.
func stageCopy(src io.Reader, dir string) (string, string, error) {
	dst, err := os.CreateTemp(dir, ".mcp-gateway-restore-*.db")
	if err != nil {
		return "", "", err
	}
	fail := func(err error) (string, string, error) {
		dst.Close()
		_ = os.Remove(dst.Name())
		return "", "", err
	}
	if err := dst.Chmod(0o600); err != nil {
		return fail(err)
	}
	h := sha256.New()
	if _, err := io.Copy(dst, io.TeeReader(src, h)); err != nil {
		return fail(err)
	}
	if err := dst.Sync(); err != nil {
		return fail(err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(dst.Name())
		return "", "", err
	}
	return dst.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// stageCopyFile is stageCopy of the file at p.
func stageCopyFile(p, dir string) (string, error) {
	src, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer src.Close()
	name, _, err := stageCopy(src, dir)
	return name, err
}

// placeNoReplace moves src to dst, refusing to replace a file that
// appeared under dst's name since backupDestination looked. A hard link
// refuses atomically; where the file system has none, a rename after one
// more look.
func placeNoReplace(src, dst string) error {
	err := os.Link(src, dst)
	if err == nil || errors.Is(err, os.ErrExist) {
		return err
	}
	if _, lerr := os.Lstat(dst); lerr == nil {
		return fmt.Errorf("%s exists; backup never overwrites a file", dst)
	}
	return os.Rename(src, dst)
}

// fileSHA256 is the hex SHA-256 and size of a file.
func fileSHA256(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func syncFile(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(p string) error {
	d, err := os.Open(p)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
