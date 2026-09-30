// Operator Console -- "check": the configuration and this host's files,
// checked before serve is started, each problem with its fix
// (design/adr/0045 item 1).
//
// Offline by default: nothing leaves the host, nothing is written, and the
// database is opened read-only. -online adds the one check that needs the
// network, the identity provider's discovery document.

package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// checkStatus is one check's verdict. FAIL is what makes the exit code 1.
type checkStatus string

const (
	checkPass checkStatus = "PASS"
	checkWarn checkStatus = "WARN"
	checkFail checkStatus = "FAIL"
	checkSkip checkStatus = "SKIP"
)

// checkResult is one line of the report.
type checkResult struct {
	Name   string      `json:"name"`
	Status checkStatus `json:"status"`
	Detail string      `json:"detail"`
	Fix    string      `json:"fix,omitempty"`
}

// svcAccount is the account serve runs as, the one the ownership checks
// are about.
type svcAccount struct {
	Name   string          `json:"name"`
	UID    uint32          `json:"uid"`
	Group  string          `json:"group"`
	From   string          `json:"from"`
	groups map[uint32]bool // primary and supplementary gids
}

// fileFacts is what the ownership checks read from a file: its owner,
// group and permission bits. ACLs are not read, which the report says.
type fileFacts struct {
	uid, gid uint32
	mode     fs.FileMode
}

// canRead and canWrite apply the POSIX permission bits the way the kernel
// does for a process of this account: owner bits if it owns the file,
// else group bits if it is in the file's group, else the other bits.
func (a svcAccount) canRead(f fileFacts) bool  { return a.permits(f, 04) }
func (a svcAccount) canWrite(f fileFacts) bool { return a.permits(f, 02) }

func (a svcAccount) permits(f fileFacts, bit fs.FileMode) bool {
	if a.UID == 0 {
		return true
	}
	perm := f.mode.Perm()
	switch {
	case f.uid == a.UID:
		return perm&(bit<<6) != 0
	case a.groups[f.gid]:
		return perm&(bit<<3) != 0
	default:
		return perm&bit != 0
	}
}

// checker runs the checks. Its function fields are seams for tests.
type checker struct {
	cfg        *config.Config
	configPath string
	svc        *svcAccount
	online     bool
	results    []checkResult

	lookPath   func(string) (string, error)
	lookupUser func(string) (*user.User, error)
	stat       func(string) (fileFacts, error)
	subidFiles [2]string
	httpClient *http.Client
	goos       string
}

func (c *checker) add(name string, st checkStatus, detail, fix string) {
	c.results = append(c.results, checkResult{Name: name, Status: st, Detail: detail, Fix: fix})
}

func checkUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: mcp-gateway check [-config FILE] [-user NAME] [-online] [-json]

Checks, before serve is started and without changing anything:
  the configuration loads; the owner and mode of the configuration file, the
  signing key, the age key, the vault and the database; that the service
  account can append to the SIEM copy ([audit.siem] path); sops on PATH; the
  vault decrypts and holds every credential a registered backend names;
  podman and subordinate ids for oci backends; every registered entry is
  signed by a trusted key; the database's schema is one this binary knows;
  the audit trail's hash chain; with -online, the identity provider's
  discovery document.

Run it as root: only root can read the signing key's metadata and the age
key. -user names the account serve runs as; without it, check takes the
owner of the database's directory, or the user running check when that is
not root. Permission checks read owner, group and mode bits; ACLs and MAC
policies are not read. PATH is this shell's: the service manager gives serve
its own.

Each FAIL and WARN line says how to fix it. The database is opened
read-only; nothing is written and no backend is started.

Exit codes: 0 no check failed (warnings allowed); 1 at least one FAIL; 2
could not run (bad usage, an unknown -user).
`)
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("check", stderr)
	userName := fs.String("user", "", "the account serve runs as (default: the owner of the database's directory)")
	online := fs.Bool("online", false, "also fetch the identity provider's discovery document")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if code, ok := opParse(fs, args, stdout, stderr, checkUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, checkUsage) {
		return exitCannotRun
	}
	c := newChecker(*configPath, *online)
	if code := c.run(context.Background(), *userName, stderr); code != exitOK {
		return code
	}
	return c.report(stdout, stderr, *asJSON)
}

func newChecker(configPath string, online bool) *checker {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		abs = configPath
	}
	return &checker{
		configPath: abs,
		online:     online,
		lookPath:   exec.LookPath,
		lookupUser: user.Lookup,
		stat:       statFacts,
		subidFiles: [2]string{"/etc/subuid", "/etc/subgid"},
		httpClient: &http.Client{Timeout: 10 * time.Second},
		goos:       runtime.GOOS,
	}
}

// run performs every check. It returns exitCannotRun only for what stops
// check itself (an unknown -user); a problem found is a result.
func (c *checker) run(ctx context.Context, userName string, stderr io.Writer) int {
	cfg, err := config.Load(c.configPath)
	if err != nil {
		c.add("configuration", checkFail, err.Error(),
			"fix what the message names; config.example.toml documents every key")
		return exitOK
	}
	c.cfg = cfg
	c.add("configuration", checkPass, "loads and validates: "+c.configPath, "")

	svc, err := c.resolveAccount(userName)
	if err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return exitCannotRun
	}
	c.svc = svc
	if svc == nil {
		c.add("service account", checkSkip, "cannot tell which account serve runs as; the ownership checks are skipped",
			"pass -user NAME (the account the service manager runs serve as)")
	} else if svc.UID == 0 {
		c.add("service account", checkFail, "serve would run as root, which reads the signing key and every file below",
			"run serve as an unprivileged account (README, Quick start, step 0) and pass it as -user")
	} else {
		c.add("service account", checkPass, fmt.Sprintf("%s (uid %d), from %s", svc.Name, svc.UID, svc.From), "")
	}

	c.checkConfigFile()
	c.checkSigningKey()
	c.checkAgeKey()
	c.checkSecretsFile()
	sopsOK := c.checkSops()
	// Every check that stats a file as root comes before the database,
	// where check run as root drops to the database directory's owner.
	c.checkSIEMPath()
	entries, dbOK := c.checkDatabase(ctx)
	c.checkVault(ctx, sopsOK, entries, dbOK)
	c.checkOCI(entries)
	c.checkIdP(ctx)
	return exitOK
}

// resolveAccount decides whose permissions the checks are about.
func (c *checker) resolveAccount(name string) (*svcAccount, error) {
	var u *user.User
	var from string
	switch {
	case name != "":
		found, err := c.lookupUser(name)
		if err != nil {
			return nil, fmt.Errorf("-user %q: %v", name, err)
		}
		u, from = found, "-user"
	default:
		dir := filepath.Dir(c.cfg.Database)
		if f, err := c.stat(dir); err == nil && f.uid != 0 {
			if found, err := user.LookupId(strconv.FormatUint(uint64(f.uid), 10)); err == nil {
				u, from = found, "the owner of "+dir
			}
		}
		if u == nil && effectiveUID() > 0 {
			if found, err := user.Current(); err == nil {
				u, from = found, "the user running check"
			}
		}
	}
	if u == nil {
		return nil, nil
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("account %q has a non-numeric uid %q", u.Username, u.Uid)
	}
	a := &svcAccount{Name: u.Username, UID: uint32(uid), From: from, groups: map[uint32]bool{}}
	gids, _ := u.GroupIds()
	for _, g := range append([]string{u.Gid}, gids...) {
		if n, err := strconv.ParseUint(g, 10, 32); err == nil {
			a.groups[uint32(n)] = true
		}
	}
	a.Group = u.Gid
	if g, err := user.LookupGroupId(u.Gid); err == nil {
		a.Group = g.Name
	}
	return a, nil
}

// statFacts reads a file's owner, group and mode.
func statFacts(p string) (fileFacts, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return fileFacts{}, err
	}
	uid, gid, ok := fileOwnerIDs(fi)
	if !ok {
		return fileFacts{}, errors.New("this platform does not report file owners")
	}
	return fileFacts{uid: uid, gid: gid, mode: fi.Mode()}, nil
}

// statOrResult stats p, adding a result for a file that cannot be
// examined. ok reports whether the caller has facts to judge.
func (c *checker) statOrResult(name, p string, missing checkStatus, missingFix string) (fileFacts, bool) {
	f, err := c.stat(p)
	switch {
	case err == nil:
		return f, true
	case errors.Is(err, fs.ErrNotExist):
		c.add(name, missing, p+" does not exist", missingFix)
	case errors.Is(err, fs.ErrPermission):
		c.add(name, checkWarn, p+" cannot be examined as this user", "run mcp-gateway check as root")
	default:
		c.add(name, checkWarn, fmt.Sprintf("%s cannot be examined: %v", p, err), "")
	}
	return fileFacts{}, false
}

func (c *checker) checkConfigFile() {
	const name = "configuration file"
	if c.svc == nil {
		c.add(name, checkSkip, "no service account to check it against", "")
		return
	}
	f, ok := c.statOrResult(name, c.configPath, checkFail, "")
	if !ok {
		return
	}
	dir := filepath.Dir(c.configPath)
	d, dok := c.statOrResult(name, dir, checkFail, "")
	q := opShellQuote(c.configPath)
	switch {
	case !c.svc.canRead(f):
		c.add(name, checkFail, fmt.Sprintf("%s cannot read %s", c.svc.Name, c.configPath),
			fmt.Sprintf("sudo chown root:%s %s && sudo chmod 0640 %s", c.svc.Group, q, q))
	case c.svc.canWrite(f):
		c.add(name, checkFail, fmt.Sprintf("%s can write %s, which holds the trusted keys and the roles it is judged by", c.svc.Name, c.configPath),
			fmt.Sprintf("sudo chown root:%s %s && sudo chmod 0640 %s", c.svc.Group, q, q))
	case dok && c.svc.canWrite(d):
		c.add(name, checkFail, fmt.Sprintf("%s can write the directory %s, and so replace the file", c.svc.Name, dir),
			fmt.Sprintf("sudo chown root:%s %s && sudo chmod 0750 %s", c.svc.Group, opShellQuote(dir), opShellQuote(dir)))
	default:
		c.add(name, checkPass, fmt.Sprintf("%s reads it and can write neither it nor its directory", c.svc.Name), "")
	}
}

// judgeSigningKey is the signing key's rule (README, "Who owns what";
// design/adr/0006): root's, 0600, unreadable by the service account.
func judgeSigningKey(f fileFacts, svc *svcAccount, p string) (checkStatus, string, string) {
	q := opShellQuote(p)
	switch {
	case f.uid != 0:
		return checkFail, fmt.Sprintf("%s is owned by uid %d, not root: whoever owns it can sign a backend", p, f.uid),
			fmt.Sprintf("sudo chown root:root %s && sudo chmod 0600 %s", q, q)
	case f.mode.Perm()&0o077 != 0:
		return checkFail, fmt.Sprintf("%s is mode %04o: others than root can read it", p, f.mode.Perm()),
			fmt.Sprintf("sudo chmod 0600 %s", q)
	case svc != nil && svc.canRead(f):
		return checkFail, fmt.Sprintf("the service account %s can read %s: anyone who can write the database could sign their own backend", svc.Name, p),
			fmt.Sprintf("sudo chown root:root %s && sudo chmod 0600 %s", q, q)
	}
	return checkPass, fmt.Sprintf("%s is root's, 0600, and the service account cannot read it", p), ""
}

func (c *checker) checkSigningKey() {
	const name = "signing key"
	p := c.cfg.Signer.KeyFile
	if p == "" {
		c.add(name, checkSkip, "signer.key_file is not set: this host verifies signatures and cannot make them", "")
		return
	}
	f, ok := c.statOrResult(name, p, checkWarn, "fine if the key is kept on another host; mcp-gateway sign cannot run here")
	if !ok {
		return
	}
	st, detail, fix := judgeSigningKey(f, c.svc, p)
	if st == checkPass && c.svc != nil {
		// The file is root's and unreadable, but a directory the service
		// account can write lets it put another file under that name: the
		// next sign, run as root, then signs with a key the service account
		// chose, or with none at all.
		dir := filepath.Dir(p)
		if d, ok := c.statOrResult(name, dir, checkWarn, ""); !ok {
			return
		} else if c.svc.canWrite(d) {
			q := opShellQuote(dir)
			c.add(name, checkFail, fmt.Sprintf("the service account %s can write %s, and so replace or remove the key in it", c.svc.Name, dir),
				fmt.Sprintf("keep the key in a directory only root writes: sudo chown root:root %s && sudo chmod 0700 %s, or move it (signer.key_file)", q, q))
			return
		}
	}
	c.add(name, st, detail, fix)
}

// judgeAgeKey is the age key's rule: owner-only (sopsage refuses anything
// else) and readable by the service account, which decrypts with it.
func judgeAgeKey(f fileFacts, svc *svcAccount, p string) (checkStatus, string, string) {
	q := opShellQuote(p)
	switch {
	case f.mode.Perm()&0o077 != 0:
		return checkFail, fmt.Sprintf("%s is mode %04o; the vault refuses a key that is not owner-only", p, f.mode.Perm()),
			fmt.Sprintf("sudo chmod 0600 %s", q)
	case svc != nil && !svc.canRead(f):
		return checkFail, fmt.Sprintf("the service account %s cannot read %s, so serve cannot decrypt the vault", svc.Name, p),
			fmt.Sprintf("sudo chown %s:%s %s && sudo chmod 0600 %s", svc.Name, svc.Group, q, q)
	}
	return checkPass, fmt.Sprintf("%s is 0600 and the service account's", p), ""
}

func (c *checker) checkAgeKey() {
	const name = "age key"
	p := c.cfg.Vault.AgeKeyFile
	f, ok := c.statOrResult(name, p, checkFail, "age-keygen -o "+opShellQuote(p)+" (README, Quick start, step 3)")
	if !ok {
		return
	}
	st, detail, fix := judgeAgeKey(f, c.svc, p)
	c.add(name, st, detail, fix)
}

func (c *checker) checkSecretsFile() {
	const name = "vault file"
	p := c.cfg.Vault.SecretsFile
	f, ok := c.statOrResult(name, p, checkFail, "encrypt one with sops (README, Quick start, step 3)")
	if !ok {
		return
	}
	if c.svc == nil {
		c.add(name, checkPass, p+" exists", "")
		return
	}
	q := opShellQuote(p)
	switch {
	case !c.svc.canRead(f):
		c.add(name, checkFail, fmt.Sprintf("%s cannot read %s", c.svc.Name, p),
			fmt.Sprintf("sudo chgrp %s %s && sudo chmod 0640 %s", c.svc.Group, q, q))
	case c.svc.canWrite(f):
		c.add(name, checkWarn, fmt.Sprintf("%s can rewrite %s; Gatte never writes it", c.svc.Name, p),
			fmt.Sprintf("sudo chown root:%s %s && sudo chmod 0640 %s", c.svc.Group, q, q))
	default:
		c.add(name, checkPass, fmt.Sprintf("%s reads it and cannot write it", c.svc.Name), "")
	}
}

func (c *checker) checkSops() bool {
	p, err := c.lookPath("sops")
	if err != nil {
		c.add("sops", checkFail, "sops is not on PATH; serve decrypts the vault with it",
			"install sops 3.13.2 or later (README, What you need) where the service's PATH finds it")
		return false
	}
	c.add("sops", checkPass, p+" (this shell's PATH; check the service's too)", "")
	return true
}

// checkDatabase checks the database's directory and files, then reads the
// file (read-only) for its schema, audit chain and signatures. It returns
// the registry's entries for the checks that depend on them.
func (c *checker) checkDatabase(ctx context.Context) ([]registry.UpstreamServer, bool) {
	const name = "database"
	p := c.cfg.Database
	dir := filepath.Dir(p)
	d, ok := c.statOrResult(name, dir, checkFail,
		fmt.Sprintf("sudo install -d -m 0750 -o %s -g %s %s", c.svcName(), c.svcGroup(), opShellQuote(dir)))
	if !ok {
		return nil, false
	}
	if c.svc != nil && !c.svc.canWrite(d) {
		c.add(name, checkFail, fmt.Sprintf("%s cannot write %s, where SQLite keeps the database and its -wal and -shm", c.svc.Name, dir),
			fmt.Sprintf("sudo chown %s:%s %s", c.svc.Name, c.svc.Group, opShellQuote(dir)))
		return nil, false
	}
	if _, err := c.stat(p); errors.Is(err, fs.ErrNotExist) {
		c.add(name, checkPass, p+" does not exist yet; serve creates it", "")
		return nil, false
	}
	if c.svc != nil {
		var wrong []string
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if f, err := c.stat(p + suffix); err == nil && !c.svc.canWrite(f) {
				wrong = append(wrong, p+suffix)
			}
		}
		if len(wrong) > 0 {
			c.add(name, checkFail, fmt.Sprintf("%s cannot write %s (a command run as root leaves root-owned -wal and -shm behind)",
				c.svc.Name, strings.Join(wrong, ", ")),
				fmt.Sprintf("sudo chown %s:%s %s", c.svc.Name, c.svc.Group, opShellQuote(p)+"*"))
			return nil, false
		}
	}

	// Run as root, check becomes the directory's owner here, after every
	// ownership check above has been made as root and before SQLite opens
	// anything: a read-only open of a WAL database still creates its -wal
	// and -shm when they are missing, and root-owned ones would stop serve
	// (the very fault the loop above looks for). What follows, the vault
	// included, then runs with the service's own rights.
	var dropErr strings.Builder
	if !becomeDatabaseOwner(c.cfg, &dropErr) {
		c.add(name, checkFail, strings.TrimSpace(dropErr.String()), "")
		return nil, false
	}

	db, err := store.OpenReadOnly(p)
	if err != nil {
		c.add(name, checkWarn, fmt.Sprintf("%s cannot be opened: %v", p, err), "")
		return nil, false
	}
	defer db.Close()
	v, err := store.CheckSchema(ctx, db)
	switch {
	case errors.Is(err, store.ErrSchemaTooNew):
		c.add("database schema", checkFail, err.Error(), "run the binary that wrote it, or restore the backup taken before the upgrade (docs/upgrade.md)")
		return nil, false
	case err != nil:
		c.add(name, checkWarn, fmt.Sprintf("%s cannot be read: %v", p, err), "run mcp-gateway check as root or as the service account")
		return nil, false
	case v < store.SchemaVersion:
		c.add("database schema", checkPass, fmt.Sprintf("schema %d; this binary migrates it to %d at its next start", v, store.SchemaVersion), "")
	default:
		c.add("database schema", checkPass, fmt.Sprintf("schema %d, the one this binary writes", v), "")
	}
	if problems, err := store.IntegrityCheck(ctx, db); err != nil || len(problems) > 0 {
		if err != nil {
			problems = append(problems, err.Error())
		}
		c.add(name, checkFail, "SQLite integrity check failed: "+strings.Join(problems[:min(3, len(problems))], "; "),
			"stop serve and restore the newest backup that passes (docs/upgrade.md, Rollback)")
		return nil, false
	}

	rep, ok := c.inspectLive(ctx, db, v)
	if !ok {
		return nil, false
	}
	if len(rep.Drift) > 0 {
		c.add("database schema objects", checkFail, "the database: "+rep.driftLine(),
			"stop serve and restore the newest backup that restore accepts (docs/upgrade.md, Rollback); keep this file as evidence")
	} else {
		c.add("database schema objects", checkPass, "every table, index and trigger is what this binary's migrations create", "")
	}
	if rep.Chain.FirstBreak != nil {
		c.add("audit trail", checkFail, rep.chainLine(), "mcp-gateway audit -verify prints the record; see design/adr/0015")
	} else {
		c.add("audit trail", checkPass, rep.chainLine(), "")
	}
	c.judgeSignatures(rep)
	return rep.entries, true
}

// inspectLive reads the schema, chain and signatures of the live database.
// A file at this binary's schema is read in place, read-only. An older one
// may lack a column the adapters read, so a copy of it is taken into a
// private temporary directory (VACUUM INTO, as backup takes one), migrated
// there as the next serve will migrate the live file, read, and removed:
// the live file is never written.
func (c *checker) inspectLive(ctx context.Context, db *sql.DB, recorded int) (dbReport, bool) {
	const name = "database"
	var rep dbReport
	if recorded == store.SchemaVersion {
		if err := inspectContent(ctx, c.cfg, db, &rep); err != nil {
			c.add(name, checkWarn, err.Error(), "")
			return rep, false
		}
		rep.Schema = recorded
		return rep, true
	}
	tmp, err := os.MkdirTemp("", "mcp-gateway-check-")
	if err != nil {
		c.add(name, checkWarn, "the file is at an older schema and no private copy could be made to read it: "+err.Error(), "")
		return rep, false
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	snap := filepath.Join(tmp, "snapshot.db")
	if err := store.Snapshot(ctx, db, snap); err != nil {
		c.add(name, checkWarn, err.Error(), "")
		return rep, false
	}
	var errs strings.Builder
	rep, code := inspectFile(ctx, c.cfg, snap, &errs, false)
	if code != exitOK {
		c.add(name, checkWarn, "a copy migrated to schema "+strconv.Itoa(store.SchemaVersion)+" could not be read: "+
			strings.TrimSpace(errs.String()), "")
		return rep, false
	}
	return rep, true
}

func (c *checker) judgeSignatures(rep dbReport) {
	const name = "registry signatures"
	required := c.cfg.Signer.SignaturesRequired()
	switch {
	case len(rep.Invalid) > 0:
		c.add(name, checkFail, rep.signatureLine()+": an entry changed after it was signed has no benign reading",
			"compare with mcp-gateway upstream list; re-sign only an entry you have re-read (design/adr/0006)")
	case len(rep.Unsigned) > 0 && required:
		c.add(name, checkFail, rep.signatureLine()+": serve does not serve an unsigned entry while signer.require_signed is on",
			"sudo mcp-gateway sign -config "+opShellQuote(c.configPath)+" NAME, for each")
	case len(rep.Unsigned) > 0:
		c.add(name, checkWarn, rep.signatureLine()+": signer.require_signed is off, so serve dials them unsigned",
			"sign each, then set signer.require_signed = true")
	case rep.Upstreams == 0:
		c.add(name, checkWarn, "no backend is registered: serve starts and serves no tool", "mcp-gateway upstream register (README, Quick start, step 4)")
	default:
		c.add(name, checkPass, rep.signatureLine(), "")
	}
}

func (c *checker) checkSIEMPath() {
	const name = "SIEM copy"
	if !c.cfg.Audit.SIEM.Enabled() {
		c.add(name, checkSkip, "[audit.siem] is not configured", "")
		return
	}
	p := c.cfg.Audit.SIEM.Path
	dir := filepath.Dir(p)
	d, ok := c.statOrResult(name, dir, checkFail,
		fmt.Sprintf("sudo install -d -m 0750 -o %s -g %s %s", c.svcName(), c.svcGroup(), opShellQuote(dir)))
	if !ok || c.svc == nil {
		return
	}
	if f, err := c.stat(p); err == nil && !c.svc.canWrite(f) {
		c.add(name, checkFail, fmt.Sprintf("%s cannot append to %s", c.svc.Name, p),
			fmt.Sprintf("sudo chown %s:%s %s", c.svc.Name, c.svc.Group, opShellQuote(p)))
		return
	}
	if !c.svc.canWrite(d) {
		c.add(name, checkFail, fmt.Sprintf("%s cannot create files in %s", c.svc.Name, dir),
			fmt.Sprintf("sudo chown %s:%s %s", c.svc.Name, c.svc.Group, opShellQuote(dir)))
		return
	}
	c.add(name, checkPass, fmt.Sprintf("%s can append to %s", c.svc.Name, p), "")
}

// checkVault decrypts the vault in this process and looks up every name a
// registered entry declares. No value is printed, logged or kept.
func (c *checker) checkVault(ctx context.Context, sopsOK bool, entries []registry.UpstreamServer, haveEntries bool) {
	const name = "vault contents"
	if !sopsOK {
		c.add(name, checkSkip, "needs sops", "")
		return
	}
	f, err := os.Open(c.cfg.Vault.AgeKeyFile)
	if err != nil {
		c.add(name, checkSkip, "the age key cannot be read as this user", "run mcp-gateway check as root or as the service account")
		return
	}
	f.Close()
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	vault, err := sopsage.New(dctx, c.cfg.Vault.SecretsFile, c.cfg.Vault.AgeKeyFile)
	if err != nil {
		// sopsage's errors never carry decrypted material (its doc).
		c.add(name, checkFail, "the vault does not decrypt: "+err.Error(),
			"check that the file was encrypted to this age key's recipient (age-keygen -y "+opShellQuote(c.cfg.Vault.AgeKeyFile)+")")
		return
	}
	if !haveEntries {
		c.add(name, checkPass, "decrypts with the age key (no registry to compare against)", "")
		return
	}
	var missing []string
	names := 0
	for _, e := range entries {
		for _, n := range e.EnvVarNames {
			names++
			if _, err := vault.Resolve(ctx, n); err != nil {
				missing = append(missing, visible.Escape(e.Name)+": "+visible.Escape(n))
			}
		}
	}
	if len(missing) > 0 {
		c.add(name, checkFail, "registered backends name credentials the vault does not hold: "+strings.Join(missing, ", "),
			"sops "+opShellQuote(c.cfg.Vault.SecretsFile)+" and add each name")
		return
	}
	c.add(name, checkPass, fmt.Sprintf("decrypts, and holds all %d credential name(s) the registry declares", names), "")
}

func (c *checker) checkOCI(entries []registry.UpstreamServer) {
	const name = "oci backends"
	var oci []string
	for _, e := range entries {
		if e.Transport == registry.TransportOCI {
			oci = append(oci, visible.Escape(e.Name))
		}
	}
	if len(oci) == 0 {
		c.add(name, checkSkip, "no oci backend is registered", "")
		return
	}
	if _, err := c.lookPath("podman"); err != nil {
		c.add(name, checkFail, fmt.Sprintf("%s run as containers and podman is not on PATH", strings.Join(oci, ", ")),
			"install podman (rootless) for the service account (design/adr/0028)")
		return
	}
	if c.goos != "linux" {
		c.add(name, checkPass, "podman is on PATH; subordinate ids are a Linux setting and are not checked here", "")
		return
	}
	if c.svc == nil {
		c.add(name, checkWarn, "podman is on PATH; subordinate ids not checked without a service account", "pass -user NAME")
		return
	}
	var lacking []string
	for _, file := range c.subidFiles {
		if !hasSubordinateRange(file, c.svc.Name, c.svc.UID) {
			lacking = append(lacking, file)
		}
	}
	if len(lacking) > 0 {
		c.add(name, checkFail, fmt.Sprintf("%s has no subordinate id range of at least 65536 in %s; rootless podman cannot start the containers",
			c.svc.Name, strings.Join(lacking, " and ")),
			fmt.Sprintf("sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 %s", c.svc.Name))
		return
	}
	c.add(name, checkPass, "podman is on PATH and "+c.svc.Name+" has subordinate uid and gid ranges", "")
}

// hasSubordinateRange reports whether an /etc/subuid-style file gives the
// account (by name or uid) a range of at least 65536 ids.
func hasSubordinateRange(file, name string, uid uint32) bool {
	f, err := os.Open(file)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) != 3 || (parts[0] != name && parts[0] != strconv.FormatUint(uint64(uid), 10)) {
			continue
		}
		if n, err := strconv.ParseUint(parts[2], 10, 32); err == nil && n >= 65536 {
			return true
		}
	}
	return false
}

func (c *checker) checkIdP(ctx context.Context) {
	const name = "identity provider"
	issuer := c.cfg.OIDC.Issuer
	disc := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	if !c.online {
		c.add(name, checkSkip, "not checked offline; -online fetches "+disc, "")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc, nil)
	if err != nil {
		c.add(name, checkFail, err.Error(), "")
		return
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.add(name, checkFail, fmt.Sprintf("%s is not reachable: %v", disc, err),
			"serve cannot start without discovery: check DNS, the route and the IdP from this host")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		c.add(name, checkFail, fmt.Sprintf("%s answered %s", disc, resp.Status), "check oidc.issuer against the IdP's own issuer URL")
		return
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		c.add(name, checkFail, fmt.Sprintf("%s is not a discovery document: %v", disc, err), "")
		return
	}
	switch {
	case doc.Issuer != issuer:
		c.add(name, checkFail, fmt.Sprintf("the IdP says its issuer is %q, the configuration says %q; tokens would be refused",
			visible.Escape(doc.Issuer), issuer), "set oidc.issuer to exactly the IdP's issuer")
	case doc.JWKSURI == "":
		c.add(name, checkFail, "the discovery document names no jwks_uri", "")
	default:
		c.add(name, checkPass, disc+" answers, with this issuer and a jwks_uri", "")
	}
}

func (c *checker) svcName() string {
	if c.svc == nil {
		return "SERVICE-ACCOUNT"
	}
	return c.svc.Name
}

func (c *checker) svcGroup() string {
	if c.svc == nil {
		return "SERVICE-GROUP"
	}
	return c.svc.Group
}

// checkReport is what check -json prints.
type checkReport struct {
	Config         string        `json:"config"`
	ServiceAccount *svcAccount   `json:"service_account"`
	Checks         []checkResult `json:"checks"`
	Failed         int           `json:"failed"`
	Warnings       int           `json:"warnings"`
}

func (c *checker) report(stdout, stderr io.Writer, asJSON bool) int {
	counts := map[checkStatus]int{}
	for _, r := range c.results {
		counts[r.Status]++
	}
	if asJSON {
		if err := opJSON(stdout, checkReport{Config: c.configPath, ServiceAccount: c.svc, Checks: c.results,
			Failed: counts[checkFail], Warnings: counts[checkWarn]}); err != nil {
			fmt.Fprintf(stderr, "check: %v\n", err)
			return exitCannotRun
		}
	} else {
		width := 0
		for _, r := range c.results {
			width = max(width, len(r.Name))
		}
		fmt.Fprintf(stdout, "mcp-gateway check -config %s\n\n", opShellQuote(c.configPath))
		for _, r := range c.results {
			fmt.Fprintf(stdout, "  %-4s  %-*s  %s\n", r.Status, width, r.Name, r.Detail)
			if r.Fix != "" && (r.Status == checkFail || r.Status == checkWarn) {
				fmt.Fprintf(stdout, "        %-*s  fix: %s\n", width, "", r.Fix)
			}
		}
		fmt.Fprintf(stdout, "\n%d failed, %d %s, %d passed, %d skipped.\n",
			counts[checkFail], counts[checkWarn], opPlural(counts[checkWarn], "warning", "warnings"), counts[checkPass], counts[checkSkip])
		fmt.Fprint(stdout, "Not checked: ACLs and MAC policy, the service manager's PATH and limits, the proxy in front, "+
			"and whether each backend answers (serve's startup summary says that).\n")
	}
	if counts[checkFail] > 0 {
		return exitProblem
	}
	return exitOK
}
