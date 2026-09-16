// Package sopsage is the sops+age-backed adapter for the Credential Vault
// domain (internal/vault), per design/adr/0003-security-controls.md.
//
// It shells out to the standalone `sops` binary rather than importing
// github.com/getsops/sops/v3 as a library -- see
// design/adr/0005-shell-out-to-sops-cli.md for why: that package pulls in
// AWS/GCP/Azure/Vault KMS client SDKs this project never uses, which
// would undo the "single small binary, no external KMS" reasoning that
// won sops+age the comparison against Vault OSS in the first place
// (DEVELOPMENT-LOG.md §9.3). `sops` and `age`/`age-keygen` must be on
// PATH on the gateway host; they are not Go dependencies of this module.
package sopsage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/vault"
)

// Provider is a vault.Provider that decrypts a sops-encrypted JSON
// document, once, at construction time, using an age identity, and
// answers Resolve calls from the resulting in-memory map.
//
// The encrypted secrets file is safe to store in Git -- that is the
// entire point of sops. The age identity file
// (design/adr/0003-security-controls.md) must be a root-only file on the
// gateway host; it is this design's one knowingly-accepted
// plaintext-on-disk exposure (see that ADR's "Consequências").
//
// Decrypting once at construction, rather than re-invoking sops on every
// Resolve call, is a deliberate adapter-level choice: ADR-0003's "no
// segredo em disco" and "nunca logado" guarantees hold either way, and a
// gateway typically constructs one Provider per boot (or per upstream
// registration), not per tool call -- re-shelling out to sops for every
// Resolve would be pure overhead with no additional safety.
//
// # It reloads when the file changes (ADR-0023)
//
// "Once" turned out to be too strong, and the cost of that was a control
// that could not fire. GAB-20's credential-drift detection compares what a
// connected upstream was handed against what the vault holds NOW -- and
// with a map frozen at construction, both sides came from the same frozen
// map, so the two were equal by construction and the warning was inert
// while three documents said it worked.
//
// So Resolve stats the encrypted file and re-decrypts when its modification
// time or size has moved. In the common tick nothing has, and the cost is
// one stat. What that buys, beyond the drift warning: a re-dial (which
// ADR-0020 does when a registry entry changes) now really does pick up a
// rotated value, which the deployment documentation claimed before it was
// true.
//
// What it deliberately does not buy: nothing reconnects a live upstream.
// That upstream keeps the value it was spawned with until a restart --
// GAB-20's other half, still not built, still for the reason written there.
// Option configures a Provider at construction. The pattern matches
// internal/gateway/stdio's, for the same reason: a constructor that grows
// positional parameters for every optional behaviour is a constructor
// nobody can read at the call site.
type Option func(*Provider)

// WithReloadErrorHandler gives the Provider a way to report that it could
// NOT re-read the encrypted file (ADR-0023 item 2).
//
// # Why a callback and not a logger
//
// This package holds no logger by design: nothing in it may write anything
// derived from a secret, and the simplest way to keep that true is to have
// no writer at all. A callback inverts it -- the composition root owns the
// logger and decides what is said -- while keeping this package's rule
// intact.
//
// What reaches the handler is safe to log, and that is a property of the
// two failures it reports rather than a promise: os.Stat's error carries a
// path, and decrypt() discards sops's stderr entirely (see its own comment
// on why) and returns only the exit status. Neither is derived from
// plaintext.
//
// Without it the failure is invisible, which is what shipped on 15 Sep
// 2026 while three comments claimed otherwise.
func WithReloadErrorHandler(fn func(error)) Option {
	return func(p *Provider) { p.onReloadError = fn }
}

type Provider struct {
	secretsFile string
	ageKeyFile  string

	// onReloadError, when set, is called when a reload attempt fails and
	// again when one succeeds after failing. See reloadIfChanged for why it
	// is edge-triggered.
	onReloadError func(error)

	// mu guards the two fields below, which Resolve may replace.
	mu sync.RWMutex
	// secrets is the decrypted document as of stamp.
	secrets map[string]string
	// failing reports whether the last reload attempt failed, so the
	// handler fires on the edge rather than on every Resolve.
	failing bool
	// stamp is what the encrypted file looked like when secrets was built.
	// Modification time and size, not a content hash: hashing would mean
	// reading the whole file on every Resolve, and it would buy nothing
	// against the only actor who could defeat mtime+size -- one who already
	// has write access to the vault file and the age identity beside it
	// (ADR-0023 item 3).
	stamp fileStamp
}

// fileStamp is the cheap identity of a file on disk.
type fileStamp struct {
	modTime time.Time
	size    int64
}

// stampOf reads the current stamp. A failure here is not a change: see
// Resolve.
func stampOf(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{modTime: info.ModTime(), size: info.Size()}, nil
}

// New decrypts secretsFile (a sops-encrypted JSON document, top level a
// flat object of string values) using the age identity in ageKeyFile, and
// returns a Provider ready to serve Resolve. ctx bounds the sops
// subprocess call.
//
// The decrypted plaintext is captured directly into an in-memory buffer
// (never a temp file) and is never included in any error this function
// returns -- sops's own stderr diagnostics can echo fragments of the file
// being decrypted on some failure paths, so they are deliberately
// discarded rather than surfaced.
func New(ctx context.Context, secretsFile, ageKeyFile string, opts ...Option) (*Provider, error) {
	if err := requireOwnerOnly(ageKeyFile); err != nil {
		return nil, err
	}

	plaintext, err := decrypt(ctx, secretsFile, ageKeyFile)
	if err != nil {
		return nil, err
	}
	defer zero(plaintext)

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		// Deliberately a fixed string, not %w-wrapping err: encoding/json
		// error messages can quote fragments of the input they failed to
		// parse, which here is decrypted secret material.
		return nil, fmt.Errorf("sopsage: decrypted content is not a flat JSON object of string values")
	}

	// A failure to stamp here is not fatal: the zero stamp simply never
	// matches, so the first Resolve re-decrypts. Refusing to construct
	// because of a stat would turn a readable file into an unbootable
	// gateway.
	stamp, _ := stampOf(secretsFile)

	p := &Provider{
		secretsFile: secretsFile,
		ageKeyFile:  ageKeyFile,
		secrets:     secrets,
		stamp:       stamp,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Resolve implements vault.Provider, re-reading the encrypted file first if
// it has changed since the last read (ADR-0023).
//
// # Failing to re-read is not a reason to fail
//
// If the stat or the decryption fails, Resolve answers from what it already
// has, with no error. The alternative -- refusing to resolve -- would turn
// a file that is briefly unreadable into a fleet that cannot dial, during
// exactly the disk incident that made it unreadable. It is the same rule
// ADR-0013 sets for the quarantine and ADR-0020 for the signature store:
// failing to measure is not evidence that something changed.
//
// Answering successfully is NOT the same as saying nothing: the failure
// goes to the handler passed to WithReloadErrorHandler, which the
// composition root wires to the log. Between 15 and 16 Sep 2026 there was
// no handler and this comment claimed there was a "returned reload error
// path", which there has never been -- a vault that had gone unreadable
// was invisible to every component.
func (p *Provider) Resolve(ctx context.Context, name string) (vault.Secret, error) {
	p.reloadIfChanged(ctx)

	p.mu.RLock()
	value, ok := p.secrets[name]
	p.mu.RUnlock()

	if !ok {
		return vault.Secret{}, fmt.Errorf("%w: %q", vault.ErrNotFound, name)
	}
	return vault.NewSecret(value), nil
}

// reloadIfChanged re-decrypts when the file's stamp has moved, and does
// nothing -- including nothing bad -- when it has not.
//
// It returns nothing on purpose: there is no failure here that a CALLER
// could act on differently from "use what we have", and a Resolve that
// returned a reload error would make every caller write the same branch.
// The operator is a different audience, and reaches the handler below.
//
// # The handler is edge-triggered
//
// Resolve runs several times per dial and once per credential per drift
// tick, so a handler called on every failed attempt would emit hundreds of
// identical lines during one disk incident -- the kind of volume that
// trains an operator to filter the message. It fires when the state
// changes: once when reloading starts failing, once when it works again.
func (p *Provider) reloadIfChanged(ctx context.Context) {
	stamp, err := stampOf(p.secretsFile)
	if err != nil {
		// Unreadable now; the previous contents stand, and the operator is
		// told once. Until 16 Sep 2026 this said the failure reached
		// gateway.CredentialDrift instead -- it cannot, because Resolve
		// answers successfully from the cached map, so nothing downstream
		// ever sees an error to report.
		p.reportReload(fmt.Errorf("sopsage: cannot stat the secrets file, serving the values from the last successful read: %w", err))
		return
	}

	p.mu.RLock()
	unchanged := stamp == p.stamp
	p.mu.RUnlock()
	if unchanged {
		// Readable and identical: whatever went wrong before is over, and
		// saying so here is what keeps the edge from latching. Reporting
		// recovery only after a successful RE-READ -- which is what this
		// did until 16 Sep 2026 -- means a file that goes away and comes
		// back unchanged (a rename out and in, a mount that flaps, a
		// permission fixed) leaves `failing` true forever: the recovery
		// line never comes, and the NEXT real outage is silent, because
		// reportReload only fires on a change of state.
		p.reportReload(nil)
		return
	}

	plaintext, err := decrypt(ctx, p.secretsFile, p.ageKeyFile)
	if err != nil {
		// Same rule as above, and one extra reason: a half-written file
		// mid-rotation decrypts to garbage, and serving the previous values
		// for another second is better than failing every dial in that
		// window. The stamp is NOT advanced, so the next Resolve tries
		// again -- which is why a transient corruption heals itself.
		//
		// err carries no plaintext: decrypt discards sops's stderr for
		// exactly that reason and returns the exit status alone.
		p.reportReload(fmt.Errorf("sopsage: the secrets file changed but could not be decrypted, serving the values from the last successful read: %w", err))
		return
	}
	defer zero(plaintext)

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		// The error itself is NOT passed on, for the reason New gives: json
		// errors quote the input they failed to parse, which here is
		// decrypted secret material. The operator learns that it happened
		// and where, and nothing about the content.
		p.reportReload(errors.New("sopsage: the secrets file changed but its decrypted content is not a flat JSON object of string values, serving the values from the last successful read"))
		return
	}

	p.mu.Lock()
	p.secrets, p.stamp = secrets, stamp
	p.mu.Unlock()
	p.reportReload(nil)
}

// reportReload tells the handler that reloading started failing, or that it
// works again. Repeated failures and repeated successes say nothing.
func (p *Provider) reportReload(err error) {
	p.mu.Lock()
	was := p.failing
	p.failing = err != nil
	changed := was != p.failing
	p.mu.Unlock()

	if !changed || p.onReloadError == nil {
		return
	}
	if err == nil {
		err = errors.New("sopsage: the secrets file can be read again; the values in use are current")
	}
	p.onReloadError(err)
}

// requireOwnerOnly refuses an age identity that any account other than its
// owner can read (GAB-26).
//
// config.Vault.AgeKeyFile has always *documented* this requirement --
// "must be owner-only on disk; this project's one knowingly-accepted
// plaintext-on-disk exposure" -- and until now nothing enforced it, while
// signer.LoadKey enforced exactly the same rule for the signing key. That
// asymmetry had it backwards: compromising the signing key lets an
// attacker vouch for registry entries, but compromising this one hands
// over *every backend credential the gateway holds*. It is the more
// dangerous of the two and it was the unchecked one.
//
// # Why this cannot be TOCTOU-free, unlike signer.LoadKey
//
// LoadKey stats the descriptor it then reads from, so nothing can swap the
// file between check and use. That is impossible here: this process never
// reads the age identity at all. It hands the *path* to sops(1) in
// SOPS_AGE_KEY_FILE, and sops opens it itself, so there is unavoidably a
// window between this check and that open.
//
// The check is still worth making. It catches the case that actually
// happens -- a key provisioned or copied with the wrong mode, sitting
// readable for weeks -- and it fails loudly at startup in front of the
// operator who just installed it. What it does not do is defend against an
// attacker who can already write to that directory at exactly the right
// moment, and pretending otherwise would be the kind of overclaim this
// project keeps finding in other people's software.
//
// Deliberately duplicated rather than shared with signer.LoadKey: the two
// have different lifetimes (that one holds the descriptor and reads it,
// this one only validates and closes), and internal/vault/sopsage importing
// internal/signer would be an adapter reaching into an unrelated domain --
// the exact dependency the fitness functions forbid. If a third call site
// ever appears, extract it then.
func requireOwnerOnly(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sopsage: cannot open the age identity %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("sopsage: cannot stat the age identity %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("sopsage: the age identity %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf(
			"sopsage: the age identity %s is group- or world-readable (mode %04o); "+
				"it decrypts every backend credential, so anyone who can read it holds them all -- chmod 600 %s",
			path, perm, path,
		)
	}
	return nil
}

// decrypt runs `sops --decrypt --input-type json --output-type json
// secretsFile` with SOPS_AGE_KEY_FILE pointed at ageKeyFile, in an
// explicit minimal environment (PATH plus SOPS_AGE_KEY_FILE only, not the
// caller's full os.Environ()), and returns the decrypted bytes.
func decrypt(ctx context.Context, secretsFile, ageKeyFile string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sops",
		"--decrypt",
		"--input-type", "json",
		"--output-type", "json",
		secretsFile,
	)
	cmd.Env = []string{"SOPS_AGE_KEY_FILE=" + ageKeyFile}
	if path, ok := os.LookupEnv("PATH"); ok {
		cmd.Env = append(cmd.Env, "PATH="+path)
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// cmd.Stderr is intentionally left nil (discarded), not wired to a
	// buffer included in the returned error -- see New's doc comment.
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sopsage: sops decrypt failed: %w", err)
	}
	return stdout.Bytes(), nil
}

// zero overwrites b in place. Best-effort defense in depth -- Go's
// garbage collector may already have copied bytes out of this backing
// array before zero runs -- kept anyway because it costs nothing and
// shrinks the window the plaintext sits in memory unnecessarily.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
