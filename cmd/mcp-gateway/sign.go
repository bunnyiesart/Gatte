// Operator Console -- the "sign" subcommand: the Definition Signer's
// operator surface.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// signatureState is the operator-facing answer to "will the gateway trust
// this entry". It is a rendering of three distinguishable situations that
// must never be collapsed into a boolean.
type signatureState string

const (
	// sigValid means a stored signature authenticates the entry as it
	// stands now.
	sigValid signatureState = "yes"
	// sigUnsigned means no signature is stored. Normal for a newly
	// registered entry; how the gateway reacts is configuration
	// (signer.require_signed), per ADR-0006 item 4.
	sigUnsigned signatureState = "no"
	// sigInvalid means a signature is stored and does not authenticate the
	// entry. ADR-0006 item 4 is explicit that this has no benign reading:
	// the entry changed after it was signed. Rendered in capitals because
	// it is the one value in the column that should stop a skim.
	sigInvalid signatureState = "INVALID"
)

// entrySignatureState reports whether the gateway would accept entry's
// signature. A missing signature is a state, not an error; only a failure
// to read the signature store is.
func entrySignatureState(ctx context.Context, sigs signer.Store, entry registry.UpstreamServer) (signatureState, error) {
	sig, err := sigs.Get(ctx, entry.Name)
	switch {
	case errors.Is(err, signer.ErrNotFound):
		return sigUnsigned, nil
	case err != nil:
		return "", err
	}
	if err := signer.Verify(entry, sig); err != nil {
		return sigInvalid, nil
	}
	return sigValid, nil
}

// keyFingerprint identifies a public key without printing the key itself:
// the hex SHA-256 of the public half, which is the usual way to name a key
// in an operator message. The private half never reaches this function --
// only the public key is passed in -- so no formatting mistake here can
// leak signing material.
func keyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// cmdSign implements "mcp-gateway sign NAME": sign a registry entry so the
// gateway will serve it.
func cmdSign(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("sign", stderr)
	fs.Usage = func() { signUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "sign takes exactly one argument: the name of the registry entry to sign\n\n")
		signUsage(stderr)
		return exitCannotRun
	}
	name := fs.Arg(0)

	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runSign(e, name)
	})
}

func signUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway sign [-config FILE] NAME

Signs the registry entry NAME with the Ed25519 key at signer.key_file, and
stores the signature so the gateway will serve the entry.

Re-signing an entry is normal: a signature covers what the entry runs
(command/url, args, env var NAMES), so any legitimate change to those
requires a new signature. It covers no secret value, which is why rotating
a credential never invalidates one.

The key file must be readable by its owner only (chmod 600).

Exit codes: 0 ok, 1 ran and found a problem, 2 could not run.
`)
}

func runSign(e *opEnv, name string) int {
	keyFile := strings.TrimSpace(e.cfg.Signer.KeyFile)
	if keyFile == "" {
		// Not a problem found by a command that ran -- the command cannot
		// run at all. Signing needs a key, and there is nothing sensible
		// to default to: generating one here would silently mint a new
		// trust anchor that nothing else in the deployment knows about.
		fmt.Fprint(e.stderr, `no signing key is configured: signer.key_file is empty.

Signing requires an Ed25519 private key, in its own owner-only file on this
host (design/adr/0006-signing-key-and-signature-storage.md item 1). Set it
in the configuration file:

    [signer]
    key_file = "/usr/local/etc/mcp-gateway/signing.key"

Create the key with, for example:

    openssl genpkey -algorithm ed25519 -out /usr/local/etc/mcp-gateway/signing.key
    chmod 600 /usr/local/etc/mcp-gateway/signing.key
`)
		return exitCannotRun
	}

	key, err := signer.LoadKey(keyFile)
	if err != nil {
		// LoadKey refuses a group- or world-readable key file, and its
		// message already says which mode it found and what to chmod. That
		// is a real misconfiguration on a shared host -- anyone with a
		// login could sign entries -- so it is surfaced verbatim rather
		// than summarised. No error from LoadKey contains key material.
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	s, err := signer.NewSigner(key)
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}

	entry, err := e.upstreams().Get(e.ctx(), name)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		fmt.Fprintf(e.stderr, "no upstream named %q is registered, so there is nothing to sign.\n\nList what is:\n\n    mcp-gateway upstream list\n", name)
		return exitProblem
	case err != nil:
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}

	sigs := e.signatures()
	prev, prevErr := sigs.Get(e.ctx(), name)
	hadPrev := prevErr == nil
	if prevErr != nil && !errors.Is(prevErr, signer.ErrNotFound) {
		fmt.Fprintf(e.stderr, "signatures: %v\n", prevErr)
		return exitCannotRun
	}
	// Whether the signature being replaced still matched the entry decides
	// what this operation means, and it can only be answered before the
	// replacement happens.
	prevValid := hadPrev && signer.Verify(entry, prev) == nil

	sig := s.Sign(entry)
	if err := sigs.Put(e.ctx(), name, sig); err != nil {
		fmt.Fprintf(e.stderr, "signatures: %v\n", err)
		return exitCannotRun
	}

	// Show what was signed. A signature is an assertion that these exact
	// fields are what the operator intends the gateway to run, so the
	// operator should see them at the moment of asserting it.
	fmt.Fprintf(e.stdout, "Signed %q.\n\n", name)
	tw := opTable(e.stdout)
	fmt.Fprintf(tw, "  transport\t%s\n", entry.Transport)
	fmt.Fprintf(tw, "  command / url\t%s\n", opCommandLine(entry))
	fmt.Fprintf(tw, "  env var names\t%s\n", opDash(strings.Join(entry.EnvVarNames, ", ")))
	fmt.Fprintf(tw, "  key file\t%s\n", keyFile)
	fmt.Fprintf(tw, "  public key\tsha256:%s\n", keyFingerprint(s.PublicKey()))
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "writing table: %v\n", err)
		return exitCannotRun
	}
	fmt.Fprint(e.stdout, "\nThe signature covers those fields and nothing else -- no secret value is\ncovered, which is why rotating a credential will not invalidate it.\n")

	switch {
	case !hadPrev:
		fmt.Fprintf(e.stdout, "\nThis is the first signature stored for %q. The gateway will now serve it.\n", name)
	case !bytes.Equal(prev.PublicKey, sig.PublicKey):
		// A different key having signed this entry before is either a
		// rotation the operator just performed or someone else's key in
		// the store. Both are worth a line; only the operator knows which.
		fmt.Fprintf(e.stdout, "\nReplaced an existing signature that was made with a DIFFERENT key\n(sha256:%s).\nIf you did not just rotate the signing key, find out whose key that was.\n",
			keyFingerprint(prev.PublicKey))
	case prevValid:
		fmt.Fprintf(e.stdout, "\nReplaced an existing, still-valid signature made with the same key. Nothing\nabout what the gateway will serve has changed.\n")
	default:
		// The replaced signature did not match the entry. That is the
		// normal outcome of legitimately editing an entry -- and it is
		// also exactly what tampering looks like. The command cannot tell
		// the two apart, so it says so instead of guessing.
		fmt.Fprintf(e.stdout, "\nNOTE: the signature previously stored for %q did NOT match the entry as it\nstands now, and has just been replaced. If you changed this entry yourself,\nthat is expected. If you did not, you have re-signed a definition somebody\nelse changed -- check the fields above against what you intended, and read\nthe audit trail:\n\n    mcp-gateway audit\n", name)
	}
	return exitOK
}
