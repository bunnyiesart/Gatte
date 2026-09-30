// Operator Console -- "sign -all", and how sign runs as root without
// leaving root-owned files in the service account's database directory
// (design/adr/0044 item 3).

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
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
		dir := filepath.Dir(cfg.Database)
		fi, err := os.Lstat(dir)
		if err != nil {
			fmt.Fprintf(stderr, "database directory: %v\n", err)
			return exitCannotRun
		}
		st, isStat := fi.Sys().(*syscall.Stat_t)
		if !fi.IsDir() || !isStat {
			fmt.Fprintf(stderr, "the database directory %s is not a directory (a symbolic link is refused)\n", dir)
			return exitCannotRun
		}
		if st.Uid != 0 {
			if err := signDropTo(int(st.Uid), int(st.Gid)); err != nil {
				fmt.Fprintf(stderr, "could not become the database directory's owner (uid %d) before opening the database: %v\n", st.Uid, err)
				return exitCannotRun
			}
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

// signPlan is one entry sign -all looked at.
type signPlan struct {
	entry  registry.UpstreamServer
	state  string // what its signature is now
	refuse error  // why it cannot be signed, if it cannot
}

// runSignAll signs every registered entry that is not validly signed by
// the configured key: unsigned, stale, or signed by another key.
func runSignAll(e *opEnv, dryRun bool) int {
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

	verb := "Signing"
	if dryRun {
		verb = "Would sign (-dry-run: nothing is written)"
	}
	fmt.Fprintf(e.stdout, "%s with %s (%s); %d already signed by it %s left alone.\n\n",
		verb, keyFile, signer.KeyFingerprint(pub), current, opPlural(current, "is", "are"))

	problem, signed := false, 0
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
		case dryRun:
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

	if !dryRun {
		fmt.Fprintf(e.stdout, "Signed %d %s. Each signature covers the fields shown and no secret value.\n",
			signed, opPlural(signed, "entry", "entries"))
		fmt.Fprint(e.stdout, "A running gateway picks them up within one quarantine.refresh_interval; no restart.\n")
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
