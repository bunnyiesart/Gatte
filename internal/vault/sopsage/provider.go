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
	"fmt"
	"os"
	"os/exec"

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
type Provider struct {
	secrets map[string]string
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
func New(ctx context.Context, secretsFile, ageKeyFile string) (*Provider, error) {
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

	return &Provider{secrets: secrets}, nil
}

// Resolve implements vault.Provider.
func (p *Provider) Resolve(_ context.Context, name string) (vault.Secret, error) {
	value, ok := p.secrets[name]
	if !ok {
		return vault.Secret{}, fmt.Errorf("%w: %q", vault.ErrNotFound, name)
	}
	return vault.NewSecret(value), nil
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
