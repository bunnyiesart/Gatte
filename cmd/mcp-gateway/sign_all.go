// Operator Console -- "sign -all", and how sign runs as root without
// leaving root-owned files in the service account's database directory
// (design/adr/0044 item 3).

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// signGeteuid and signDropTo are variables so the root path is testable
// without root: the test stands in for the kernel.
var (
	signGeteuid = os.Geteuid
	signDropTo  = dropPrivileges
)

// dropPrivileges makes this whole process uid:gid with no supplementary
// groups, for good: there is no way back to root afterwards. On Linux Go
// applies it to every thread; on the BSDs setuid is per process.
func dropPrivileges(uid, gid int) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	if os.Geteuid() != uid || os.Getegid() != gid {
		return fmt.Errorf("still running as %d:%d after dropping to %d:%d", os.Geteuid(), os.Getegid(), uid, gid)
	}
	return nil
}

// signRun is opRun for sign. Run as root, it reads the configuration and
// the signing key as root -- both are root's -- and then becomes the owner
// of the database directory BEFORE the database is opened, so the -wal and
// -shm files SQLite creates are the service account's, and root never
// opens a file in a directory the service account can write (the rule
// design/adr/0040 §1 set for the accounts backend). The README told
// operators to chown the directory after every sign until this existed.
//
// A database directory that is itself root's is left alone: there is no
// account to drop to and nothing a root-owned file there would break
// that the root-owned directory does not already.
func signRun(configPath string, stdout, stderr io.Writer, fn func(*opEnv) int) int {
	cfg, ok := loadConfig(configPath, stderr)
	if !ok {
		return exitCannotRun
	}
	var key []byte
	var keyFile string
	if signGeteuid() == 0 && cfg.Database != ":memory:" {
		k, f, ok := loadSigningKey(cfg, stderr)
		if !ok {
			return exitCannotRun
		}
		if !becomeDatabaseOwner(cfg, stderr) {
			return exitCannotRun
		}
		key, keyFile = k, f
	}
	db, err := openStore(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "database: %v\n", err)
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied") || strings.Contains(err.Error(), "readonly") {
			fmt.Fprintf(stderr, "\nIf an earlier sign run as root left files in %s owned by root, give them back once:\n    chown -R SERVICE_ACCOUNT: %s\n", filepath.Dir(cfg.Database), filepath.Dir(cfg.Database))
		}
		return exitCannotRun
	}
	defer db.Close()
	abs, err := filepath.Abs(configPath)
	if err != nil {
		abs = configPath
	}
	e := &opEnv{cfg: cfg, db: db, stdout: stdout, stderr: stderr, configPath: abs}
	if key != nil {
		e.signingKey, e.signingKeyFile = key, keyFile
	}
	return fn(e)
}

// becomeDatabaseOwner is the drop signRun makes, for every command that
// may run as root and then opens the database: sign, and backup, restore
// and check (design/adr/0045). Run as root, the process becomes the owner
// of the database directory, for good, before the database is opened, so
// the -wal and -shm SQLite creates are the service account's and root
// never opens a file in a directory the service account can write. Not
// root, or a root-owned directory, it does nothing. A directory reached
// through a symbolic link is refused. It reports whether the caller may
// go on; a refusal has been printed.
func becomeDatabaseOwner(cfg *config.Config, stderr io.Writer) bool {
	if signGeteuid() != 0 || cfg.Database == ":memory:" {
		return true
	}
	dir := filepath.Dir(cfg.Database)
	fi, err := os.Lstat(dir)
	if err != nil {
		fmt.Fprintf(stderr, "database directory: %v\n", err)
		return false
	}
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !isStat {
		fmt.Fprintf(stderr, "the database directory %s is not a directory (a symbolic link is refused)\n", dir)
		return false
	}
	if st.Uid != 0 {
		if err := signDropTo(int(st.Uid), int(st.Gid)); err != nil {
			fmt.Fprintf(stderr, "could not become the database directory's owner (uid %d) before opening the database: %v\n", st.Uid, err)
			return false
		}
	}
	return true
}

// signPlan is one entry sign -all looked at.
type signPlan struct {
	entry  registry.UpstreamServer
	state  string // what its signature is now
	refuse error  // why it cannot be signed, if it cannot
}

// signPlanDomainTag scopes a sign -all manifest, as the review-set
// manifest's tag scopes it: it can never be confused with another hash.
const signPlanDomainTag = "mcp-gateway/sign-all/plan/v1"

// signPlanManifest is the hex SHA-256 of what sign -all would sign: the
// signing key, and for each entry it would sign, in registry order, its
// name, what its signature is now, and the exact bytes its signature
// covers (signer.Canonical). It changes when anything the operator was
// shown changes: an entry joining or leaving the plan, any signed field,
// or the key. Every field is length-prefixed, so no two plans collide.
func signPlanManifest(pub []byte, plan []signPlan) string {
	h := sha256.New()
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	field([]byte(signPlanDomainTag))
	field(pub)
	var signable []signPlan
	for _, p := range plan {
		if p.refuse == nil {
			signable = append(signable, p)
		}
	}
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(signable)))
	field(n[:])
	for _, p := range signable {
		field([]byte(p.entry.Name))
		field([]byte(p.state))
		field(signer.Canonical(p.entry))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// runSignAll signs every registered entry that is not validly signed by
// the configured key -- unsigned, stale, or signed by another key -- and
// only as the plan named by reviewed (design/adr/0044 item 4, amended):
// the operator signs what -dry-run showed them, the way a review set is
// approved by its manifest (design/adr/0043). A stale entry is exactly
// what ADR-0010's attacker leaves behind, so signing it unseen would undo
// the signature's point. Without reviewed, or with dryRun, it prints the
// plan and its manifest and signs nothing.
func runSignAll(e *opEnv, dryRun bool, reviewed string) int {
	key, keyFile, ok := e.signingKeyOrLoad()
	if !ok {
		return exitCannotRun
	}
	s, err := signer.NewSigner(key)
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	verifier, err := opVerifier(e)
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	entries, err := e.upstreams().List(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}
	if len(entries) == 0 {
		fmt.Fprintf(e.stdout, "No upstream is registered, so there is nothing to sign.\n")
		return exitOK
	}

	sigs := e.signatures()
	pub := s.PublicKey()
	var plan []signPlan
	current := 0
	for _, entry := range entries {
		prev, err := sigs.Get(e.ctx(), entry.Name)
		var state string
		switch {
		case errors.Is(err, signer.ErrNotFound):
			state = "unsigned"
		case err != nil:
			fmt.Fprintf(e.stderr, "signatures: %v\n", err)
			return exitCannotRun
		case verifier.Verify(entry, prev) != nil:
			state = "INVALID (the entry changed after it was signed, or its key is not trusted)"
		case !bytes.Equal(prev.PublicKey, pub):
			state = "signed by another key (" + signer.KeyFingerprint(prev.PublicKey) + ")"
		default:
			current++
			continue
		}
		p := signPlan{entry: entry, state: state}
		if err := dialTimeRefusal(entry); err != nil {
			p.refuse = fmt.Errorf("the dialer for its transport would refuse it at every start: %w", err)
		} else if err := credentialedStdioRefusal(entry, e.cfg); err != nil {
			p.refuse = fmt.Errorf("the gateway would refuse it at every start: %w", err)
		}
		plan = append(plan, p)
	}

	if len(plan) == 0 {
		fmt.Fprintf(e.stdout, "All %d registered %s already validly signed by this key (%s); nothing to sign.\n",
			len(entries), opPlural(len(entries), "entry is", "entries are"), signer.KeyFingerprint(pub))
		return exitOK
	}

	manifest := signPlanManifest(pub, plan)
	reviewed = strings.TrimPrefix(strings.TrimSpace(reviewed), "sha256:")
	sign := !dryRun && reviewed == manifest
	verb := "Signing"
	if !sign {
		verb = "Would sign (nothing is written)"
	}
	fmt.Fprintf(e.stdout, "%s with %s (%s); %d already signed by it %s left alone.\n\n",
		verb, keyFile, signer.KeyFingerprint(pub), current, opPlural(current, "is", "are"))

	problem, signed, signable := false, 0, 0
	for _, p := range plan {
		fmt.Fprintf(e.stdout, "%s -- was %s\n", p.entry.Name, p.state)
		tw := opTable(e.stdout)
		fmt.Fprintf(tw, "  transport\t%s\n", p.entry.Transport)
		fmt.Fprintf(tw, "  command / url\t%s\n", opCommandLine(p.entry))
		if p.entry.Image != "" {
			fmt.Fprintf(tw, "  image\t%s\n", p.entry.Image)
		}
		fmt.Fprintf(tw, "  env var names\t%s\n", opDash(strings.Join(p.entry.EnvVarNames, ", ")))
		if !opFlushTable(tw, e.stderr) {
			return exitProblem
		}
		switch {
		case p.refuse != nil:
			fmt.Fprintf(e.stdout, "  NOT signed: %v\n\n", p.refuse)
			problem = true
			continue
		case !sign:
			signable++
			fmt.Fprint(e.stdout, "  would be signed\n\n")
			continue
		}
		if err := sigs.Put(e.ctx(), p.entry.Name, s.Sign(p.entry)); err != nil {
			fmt.Fprintf(e.stderr, "signatures: %v (entries listed above this one are signed; this one and the ones after it are not)\n", err)
			return exitCannotRun
		}
		signed++
		fmt.Fprint(e.stdout, "  signed\n\n")
	}

	switch {
	case sign:
		fmt.Fprintf(e.stdout, "Signed %d %s (plan sha256:%s). Each signature covers the fields shown and no secret value.\n",
			signed, opPlural(signed, "entry", "entries"), manifest)
		fmt.Fprint(e.stdout, "A running gateway picks them up within one quarantine.refresh_interval; no restart.\n")
	case signable == 0:
		fmt.Fprint(e.stdout, "Nothing above can be signed.\n")
	case dryRun || reviewed == "":
		fmt.Fprintf(e.stdout, "plan  sha256:%s\n\nRead every entry above -- an INVALID one was changed after it was signed. If\nall of them are sound, sign exactly this plan:\n\n    %s -all -manifest %s\n",
			manifest, e.cmd("sign"), manifest)
		if !dryRun {
			fmt.Fprint(e.stderr, "\nNOT signed: sign -all signs only the plan you reviewed; pass its -manifest.\n")
			problem = true
		}
	default:
		fmt.Fprintf(e.stderr, "\nNOT signed: the plan is now sha256:%s, not the sha256:%s you reviewed.\nSomething joined, left or changed since you looked. Review the plan above, then\nsign its manifest if it is sound.\n",
			manifest, visible.Escape(reviewed))
		problem = true
	}
	if !verifier.Trusts(pub) {
		fmt.Fprintf(e.stdout, "\nThe gateway will NOT serve these yet: the key that signed them is not in\nsigner.trusted_keys. Add it and restart the gateway (trusted_keys is not reloadable):\n\n    [signer]\n    trusted_keys = [\n      %q,  # %s\n    ]\n",
			trustedKeyLine(pub), signer.KeyFingerprint(pub))
	}
	if problem {
		return exitProblem
	}
	return exitOK
}
