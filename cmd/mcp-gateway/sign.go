// Operator Console -- the "sign" subcommand: the Definition Signer's
// operator surface.

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// opVerifier builds the trust anchor from the configuration: the keys in
// signer.trusted_keys and nothing else (ADR-0010).
//
// Every operator command that reports a signature state goes through this,
// so `upstream list` answers the same question the gateway will answer at
// boot. A console that verified differently from the serving process would
// be worse than no console: it would print SIGNED: yes for an entry the
// gateway is about to refuse, or the reverse.
func opVerifier(e *opEnv) (*signer.Verifier, error) {
	trusted, err := e.cfg.Signer.TrustedPublicKeys()
	if err != nil {
		return nil, err
	}
	return signer.NewVerifier(trusted)
}

// entrySignatureState reports whether the gateway would accept entry's
// signature. A missing signature is a state, not an error; only a failure
// to read the signature store, or to build the trust anchor, is.
//
// It takes the whole opEnv rather than just the store because the answer
// depends on the configuration as much as on the database -- which is the
// entire point of ADR-0010, and is worth being visible in the signature.
func entrySignatureState(e *opEnv, entry registry.UpstreamServer) (signatureState, error) {
	verifier, err := opVerifier(e)
	if err != nil {
		return "", err
	}
	sig, err := e.signatures().Get(e.ctx(), entry.Name)
	switch {
	case errors.Is(err, signer.ErrNotFound):
		return sigUnsigned, nil
	case err != nil:
		return "", err
	}
	if err := verifier.Verify(entry, sig); err != nil {
		return sigInvalid, nil
	}
	return sigValid, nil
}

// trustedKeyLine renders pub the way signer.trusted_keys wants it: base64
// of the raw 32 bytes, standard encoding. This is the operator-facing half
// of ADR-0010 item 4 -- a control that is annoying to switch on stays off,
// so the command that creates the need prints the exact text that satisfies
// it.
func trustedKeyLine(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// cmdSign implements "mcp-gateway sign NAME": sign a registry entry so the
// gateway will serve it.
func cmdSign(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("sign", stderr)
	genKey := fs.Bool("generate-key", false,
		"create a new Ed25519 signing key at signer.key_file and exit; refuses to overwrite an existing one")
	fs.Usage = func() { signUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if *genKey {
		if fs.NArg() != 0 {
			fmt.Fprintf(stderr, "sign -generate-key takes no arguments (it creates a key; it does not sign)\n\n")
			signUsage(stderr)
			return exitCannotRun
		}
		return opRun(*configPath, stdout, stderr, runGenerateKey)
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
  mcp-gateway sign [-config FILE] -generate-key

Signs the registry entry NAME with the Ed25519 key at signer.key_file, and
stores the signature so the gateway will serve the entry.

Re-signing an entry is normal: a signature covers what the entry runs
(command/url, args, env var NAMES), so any legitimate change to those
requires a new signature. It covers no secret value, which is why rotating
a credential never invalidates one.

The key file must be readable by its owner only (chmod 600).

-generate-key creates that key at signer.key_file and prints the
trusted_keys line to paste. It refuses to overwrite an existing key, since
that would invalidate every signature the old one made. It does not edit
the configuration file: this command must not be able to grant itself
trust (ADR-0010).

Signing is not enough on its own: the gateway accepts a signature only from
a key listed in signer.trusted_keys. If the key used here is not listed,
this command prints the line to paste into the configuration file.

Exit codes: 0 ok, 1 ran and found a problem, 2 could not run.
`)
}

// runGenerateKey creates the signing key an operator needs before they can
// sign anything at all.
//
// This exists because ADR-0010 made signer.trusted_keys required whenever
// require_signed is on -- which is the default -- so "create a key" became
// the literal first step of setting this gateway up. Until now
// signer.GenerateKey and signer.WriteKey were built, tested, and reachable
// from no command: an operator's only route was to know that the format is
// PKCS#8 PEM and reach for `openssl genpkey -algorithm ed25519`. Leaving a
// mandatory control's first step to folklore is how it ends up skipped.
//
// It deliberately does NOT add the new key to trusted_keys. Writing to the
// operator's configuration file from a command would mean this process
// grants its own trust, which is exactly the property ADR-0010 exists to
// prevent -- the anchor has to be placed by a person, in a reviewed diff.
// Printing the line to paste is the furthest this may go.
func runGenerateKey(e *opEnv) int {
	path := strings.TrimSpace(e.cfg.Signer.KeyFile)
	if path == "" {
		fmt.Fprintf(e.stderr, "signer.key_file is not set: nowhere to write the key.\nSet it in the configuration file first -- see config.example.toml.\n")
		return exitCannotRun
	}

	key, err := signer.GenerateKey()
	if err != nil {
		fmt.Fprintf(e.stderr, "generate key: %v\n", err)
		return exitCannotRun
	}

	// WriteKey opens with O_EXCL and mode 0600, so an existing key is never
	// clobbered and the new one is owner-only from the instant it exists --
	// there is no window where it sits readable and then gets chmodded.
	if err := signer.WriteKey(path, key); err != nil {
		fmt.Fprintf(e.stderr, "write key: %v\n", err)
		if errors.Is(err, fs.ErrExist) {
			fmt.Fprintf(e.stderr, "\nA key already exists there and was left untouched. Overwriting it would\ninvalidate every signature it made. To rotate deliberately: move the old\nkey aside, generate a new one, re-sign every entry (`mcp-gateway sign NAME`),\nand only then remove the old key from signer.trusted_keys.\n")
		}
		return exitCannotRun
	}

	pub := key.Public().(ed25519.PublicKey)
	fmt.Fprintf(e.stdout, "Wrote a new Ed25519 signing key to %s (owner-only).\n", path)
	fmt.Fprintf(e.stdout, "\nThe gateway will not accept its signatures until you trust it. Add this to\nthe configuration file:\n\n    [signer]\n    trusted_keys = [\n      %q,  # %s\n    ]\n",
		trustedKeyLine(pub), signer.KeyFingerprint(pub))
	fmt.Fprintf(e.stdout, "\nThen sign each registry entry:\n\n    mcp-gateway sign NAME\n")
	return exitOK
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

	verifier, err := opVerifier(e)
	if err != nil {
		// Only reachable if the config was not loaded through Load, which
		// already decodes trusted_keys and refuses a bad one. Reported
		// rather than ignored: guessing at a trust anchor is not a thing to
		// do quietly.
		fmt.Fprintf(e.stderr, "%v\n", err)
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
	prevValid := hadPrev && verifier.Verify(entry, prev) == nil

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
	fmt.Fprintf(tw, "  public key\t%s\n", signer.KeyFingerprint(s.PublicKey()))
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "writing table: %v\n", err)
		return exitCannotRun
	}
	fmt.Fprint(e.stdout, "\nThe signature covers those fields and nothing else -- no secret value is\ncovered, which is why rotating a credential will not invalidate it.\n")

	// What this operation replaced, if anything.
	trusted := verifier.Trusts(s.PublicKey())
	switch {
	case !hadPrev && trusted:
		fmt.Fprintf(e.stdout, "\nThis is the first signature stored for %q. The gateway will now serve it.\n", name)
	case !hadPrev:
		// Deliberately not "the gateway will now serve it": it will not,
		// and the block below says why. Claiming success here and
		// retracting it two paragraphs later is how an operator stops
		// reading the second paragraph.
		fmt.Fprintf(e.stdout, "\nThis is the first signature stored for %q.\n", name)
	case !bytes.Equal(prev.PublicKey, sig.PublicKey):
		// A different key having signed this entry before is either a
		// rotation the operator just performed or someone else's key in
		// the store. Both are worth a line; only the operator knows which.
		fmt.Fprintf(e.stdout, "\nReplaced an existing signature that was made with a DIFFERENT key\n(%s).\nIf you did not just rotate the signing key, find out whose key that was.\n",
			signer.KeyFingerprint(prev.PublicKey))
	case prevValid:
		fmt.Fprintf(e.stdout, "\nReplaced an existing, still-valid signature made with the same key. Nothing\nabout what the gateway will serve has changed.\n")
	default:
		// The replaced signature did not match the entry. That is the
		// normal outcome of legitimately editing an entry -- and it is
		// also exactly what tampering looks like. The command cannot tell
		// the two apart, so it says so instead of guessing.
		fmt.Fprintf(e.stdout, "\nNOTE: the signature previously stored for %q did NOT match the entry as it\nstands now, and has just been replaced. If you changed this entry yourself,\nthat is expected. If you did not, you have re-signed a definition somebody\nelse changed -- check the fields above against what you intended, and read\nthe audit trail:\n\n    mcp-gateway audit\n", name)
	}

	// ADR-0010 item 4, and it goes last on purpose: it is the only thing
	// left for the operator to do, so it should be the last thing on the
	// screen rather than something scrolled past on the way to a summary.
	//
	// The signature is stored, but the gateway will refuse the entry until
	// the key that made it is named in the configuration -- and an operator
	// who has to work out the encoding themselves is an operator who leaves
	// require_signed off. So the command that creates the obligation prints
	// the exact text that discharges it.
	if !trusted {
		fmt.Fprintf(e.stdout, `
The gateway will NOT serve %q yet: the key that signed it is not in
signer.trusted_keys, and a signature is only evidence relative to a key that
was trusted in advance (design/adr/0010-signature-trust-anchor.md). Until it
is listed, `+"`mcp-gateway upstream list`"+` reports this entry as INVALID.

Add this to the configuration file and restart the gateway:

    [signer]
    trusted_keys = [
      %q,  # %s
    ]

That value is the public half only -- it is not a secret, and putting it in
a versioned, reviewed file is the point: changing whom this gateway trusts
to define what it spawns should be a diff somebody read.
`, name, trustedKeyLine(s.PublicKey()), signer.KeyFingerprint(s.PublicKey()))
	}
	return exitOK
}
