// Operator Console -- the adapters of design/adr/0050, "the console
// manages everything": the ports internal/admin's ManageDeps names, wired
// here, the composition root.
//
// On the operator socket (the service account, owner of the database):
// one entry in detail, registering an http backend through the same
// ingestion as `upstream register -transport http` (ingestHTTP,
// validateEntry), and deregistering through the same steps as `upstream
// deregister` (deregisterEntry).
//
// On the accounts socket (root, which never opens the service account's
// database, design/adr/0040 §1): signing, by a child `mcp-gateway sign`
// that reads the key as root and drops to the database's owner before it
// opens the database, as the CLI does; the vault, through sops on standard
// input and output (internal/vault/sopsage.Store); the roles file; and the
// registry's declared names, read by a child `admin -registry-reader`
// running as the database's owner.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/atomicfile"
	"github.com/bunnyiesart/Gatte/internal/config"
	gwrest "github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// operatorManageDeps are the operator socket's ports of design/adr/0050.
// envFor builds the CLI environment over the backend's database for one
// operation's configuration.
func operatorManageDeps(envFor func(*config.Config) *opEnv) admin.ManageDeps {
	return admin.ManageDeps{
		UpstreamDetail: func(_ context.Context, cfg *config.Config, name string) (adminapi.UpstreamDetail, error) {
			return upstreamDetail(envFor(cfg), name)
		},
		RegisterHTTP: func(ctx context.Context, cfg *config.Config, req adminapi.RegisterUpstreamRequest) (adminapi.RegisterUpstreamResult, error) {
			return registerHTTP(ctx, envFor(cfg), req)
		},
		Deregister: func(_ context.Context, cfg *config.Config, name string) (adminapi.DeregisterResult, error) {
			out := deregisterEntry(envFor(cfg), name)
			res := adminapi.DeregisterResult{Name: name, Registered: out.registered, SignatureRemoved: out.signatureRemoved, ToolsForgotten: out.forgotten}
			if out.failed != "" {
				// What was removed before the failure stays removed; the
				// message says which part is left, as the CLI's warning does.
				return res, adminapi.NewError(adminapi.CodeInternal, "deregistering %q: the %s step failed (%v); the steps before it took effect -- registry removed %t, signature removed %t, %d quarantine entries removed. Run it again: every step is safe to repeat",
					name, out.failed, out.err, out.registered, out.signatureRemoved, out.forgotten)
			}
			return res, nil
		},
	}
}

// apiUpstream is upstreamRow in the contract's shape.
func apiUpstream(r upstreamJSON) adminapi.Upstream {
	return adminapi.Upstream{Name: r.Name, Transport: r.Transport, Command: r.Command, Args: r.Args, URL: r.URL,
		Image: r.Image, Network: r.Network, NetworkError: r.NetworkError, EnvVarNames: r.EnvVarNames, Signature: r.Signature,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

// authOf is an http entry's descriptor in the contract's words: the
// location and the vault NAME, never a value (the registry has no field
// for one).
func authOf(s registry.UpstreamServer) adminapi.UpstreamAuth {
	a := adminapi.UpstreamAuth{Kind: string(s.AuthKind), Name: s.AuthName}
	if s.AuthKind == registry.AuthNone {
		a.Kind = authKindNone
	}
	if len(s.EnvVarNames) == 1 && s.AuthKind != registry.AuthNone {
		a.Secret = s.EnvVarNames[0]
	}
	return a
}

func apiOperations(ops []gwrest.Operation) []adminapi.UpstreamOperation {
	out := make([]adminapi.UpstreamOperation, 0, len(ops))
	for _, op := range ops {
		out = append(out, adminapi.UpstreamOperation{Name: op.Name, Method: op.Method, Path: op.Path, Class: string(gwrest.ClassOf(op.Method))})
	}
	return out
}

// upstreamDetail is GET /v1/upstreams/{name}.
func upstreamDetail(e *opEnv, name string) (adminapi.UpstreamDetail, error) {
	entry, err := e.upstreams().Get(e.ctx(), name)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return adminapi.UpstreamDetail{}, adminapi.NewError(adminapi.CodeNotFound, "no registered backend is named %q", name).With("upstream", name)
	case err != nil:
		return adminapi.UpstreamDetail{}, err
	}
	state, err := entrySignatureState(e, entry)
	if err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	d := adminapi.UpstreamDetail{Upstream: apiUpstream(upstreamRow(entry, state)), Tools: []adminapi.Tool{}}
	if entry.Transport == registry.TransportHTTP {
		a := authOf(entry)
		d.Auth = &a
		sum := sha256.Sum256(entry.Operations)
		d.OperationsSHA256 = hex.EncodeToString(sum[:])
		if ops, err := gwrest.Decode(entry.Operations, string(entry.AuthKind), entry.AuthName); err != nil {
			d.OperationsError = err.Error()
		} else {
			d.Operations = apiOperations(ops)
		}
	}
	tools, err := e.tools().List(e.ctx(), name)
	if err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	for _, t := range tools {
		d.Tools = append(d.Tools, admin.ToolOf(t))
	}
	return d, nil
}

// registerHTTP is POST /v1/upstreams: the console's register, step for
// step -- ingestHTTP, validateEntry, credentialedStdioRefusal, Register,
// then the signature state the gateway will see.
func registerHTTP(ctx context.Context, e *opEnv, req adminapi.RegisterUpstreamRequest) (adminapi.RegisterUpstreamResult, error) {
	entry := registry.UpstreamServer{Name: req.Name, Transport: registry.TransportHTTP, URL: req.URL}
	if req.KeyName != "" {
		entry.EnvVarNames = []string{req.KeyName}
	}
	in := httpRegistration{openapi: req.OpenAPIURL, authKind: req.AuthKind, authName: req.AuthName}
	if req.OpenAPIDocument != "" {
		in.document, in.source = []byte(req.OpenAPIDocument), "the document sent"
	}
	refused := func(err error) error {
		return adminapi.NewError(adminapi.CodeInvalidArgument, "%s", err.Error())
	}
	report, err := ingestHTTP(ctx, &entry, in)
	if err != nil {
		return adminapi.RegisterUpstreamResult{}, refused(err)
	}
	if err := validateEntry(entry, report); err != nil {
		return adminapi.RegisterUpstreamResult{}, refused(err)
	}
	if err := credentialedStdioRefusal(entry, e.cfg); err != nil {
		return adminapi.RegisterUpstreamResult{}, refused(err)
	}
	switch err := e.upstreams().Register(ctx, entry); {
	case errors.Is(err, registry.ErrAlreadyExists):
		return adminapi.RegisterUpstreamResult{}, adminapi.NewError(adminapi.CodeUpstreamExists, "a backend named %q is already registered: deregister it first, or choose another name", entry.Name).With("upstream", entry.Name)
	case errors.Is(err, registry.ErrInvalid):
		return adminapi.RegisterUpstreamResult{}, refused(err)
	case err != nil:
		return adminapi.RegisterUpstreamResult{}, err
	}
	res := adminapi.RegisterUpstreamResult{Name: entry.Name, URL: entry.URL, Source: report.source, BasePath: report.basePath,
		Auth: authOf(entry), AuthDerived: report.authDerived, Tools: apiOperations(report.ops), Skipped: report.skipped, IngestWarnings: report.warnings}
	if report.fetched {
		res.FetchedBytes = report.bytes
	}
	state, err := entrySignatureState(e, entry)
	if err != nil {
		// Registered; only the signature store's reading failed. Not a
		// guess either way, as the CLI says.
		res.Signature = "unknown"
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: "signature_unknown", Message: "Registered, but whether it is signed could not be determined: " + err.Error()})
		return res, nil
	}
	res.Signature = string(state)
	if state != sigUnsigned {
		// The GAB-25 case the CLI warns about loudly: a signature left
		// under the name by an earlier entry already matches (or fails)
		// this one.
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: "signature_left_under_name",
			Message: fmt.Sprintf("A signature stored under %q by an earlier entry of the name is already there (%s): nobody reviewed this entry. Sign it now, or deregister it.", entry.Name, state)})
	}
	return res, nil
}

// rolesFile is the RolesStore over the file cfg.RolesFile names.
type rolesFile struct{}

func (rolesFile) Read(cfg *config.Config) ([]byte, error) {
	f, err := os.Open(cfg.RolesFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, adminapi.MaxRolesTextBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > adminapi.MaxRolesTextBytes {
		return nil, fmt.Errorf("%s is over %d bytes", cfg.RolesFile, adminapi.MaxRolesTextBytes)
	}
	return b, nil
}

// Write replaces the roles file atomically, keeping its owner and mode:
// serve reads it as the service account on the next reload.
func (rolesFile) Write(cfg *config.Config, text []byte) error {
	return atomicfile.Replace(cfg.RolesFile, text, 0o644)
}

// sopsVault is the VaultStore over [vault] secrets_file and age_key_file.
type sopsVault struct{}

func (sopsVault) store(cfg *config.Config) *sopsage.Store {
	return sopsage.NewStore(cfg.Vault.SecretsFile, cfg.Vault.AgeKeyFile)
}

func (v sopsVault) Names(ctx context.Context, cfg *config.Config) ([]string, error) {
	return v.store(cfg).Names(ctx)
}

func (v sopsVault) Set(ctx context.Context, cfg *config.Config, name string, value []byte) (bool, error) {
	return v.store(cfg).Set(ctx, name, value)
}

func (v sopsVault) Delete(ctx context.Context, cfg *config.Config, name string) (bool, error) {
	return v.store(cfg).Delete(ctx, name)
}

// accountsManageDeps are the accounts socket's ports of design/adr/0050.
// serviceUID and serviceGID own the database the children open.
func accountsManageDeps(configPath string, serviceUID, serviceGID uint32) admin.ManageDeps {
	return admin.ManageDeps{
		Sign:  spawnSign(configPath),
		Vault: sopsVault{},
		DeclaredSecrets: func(ctx context.Context, _ *config.Config) (map[string][]string, error) {
			out, err := runAdminChild(ctx, configPath, "-registry-reader", serviceUID, serviceGID, nil)
			if err != nil {
				return nil, err
			}
			var declared map[string][]string
			if err := json.Unmarshal(out, &declared); err != nil {
				return nil, fmt.Errorf("registry reader: unreadable answer: %v", err)
			}
			return declared, nil
		},
		Roles:         rolesFile{},
		ValidateRoles: func(text []byte) error { return config.ValidateRolesText(configPath, text) },
		// The vault's two files are read and written by this root
		// process: held to the rule config.toml is (design/adr/0040 §1).
		CheckPaths: func(paths []string) error { return admin.CheckOwnedChain(paths, adminRootOnly) },
		// Except the age identity, which is the service account's by design
		// (README, "Who owns what"): its own rule, admin.CheckServiceKey.
		CheckAgeKey: func(path string) error { return admin.CheckServiceKey(path, adminRootOnly, serviceUID) },
	}
}

// adminRootOnly is adminhttp.RootOnly, a variable so a test can trust its
// own uid.
var adminRootOnly = func(uid uint32) bool { return uid == 0 }

// signChild runs `mcp-gateway sign -config configPath name` and returns
// its exit code, standard output and standard error. A variable so the
// mapping below is testable without root and without a built binary.
var signChild = func(ctx context.Context, configPath, name string) (int, []byte, []byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, nil, nil, err
	}
	// As root, unchanged: sign reads the key as root and drops to the
	// database's owner itself before opening the database (signRun). An
	// empty environment and / as its directory, like the other children.
	// "--" ends the flags: the name is never read as one, whatever the
	// service's name check let through.
	cmd := exec.CommandContext(ctx, exe, "sign", "-config", configPath, "--", name) // #nosec G204 -- this binary
	cmd.Env, cmd.Dir = []string{}, "/"
	var outb, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outb, &errb
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), outb.Bytes(), errb.Bytes(), nil
	}
	if err != nil {
		return 0, nil, nil, err
	}
	return exitOK, outb.Bytes(), errb.Bytes(), nil
}

// spawnSign is the accounts backend's Sign: the key's fingerprint is read
// here, as root, from signer.key_file (LoadKey refuses a key others can
// read, and none of its errors carries key material); the signature is
// made and stored by the child.
func spawnSign(configPath string) func(context.Context, *config.Config, string) (admin.SignOutcome, error) {
	return func(ctx context.Context, cfg *config.Config, name string) (admin.SignOutcome, error) {
		keyFile := strings.TrimSpace(cfg.Signer.KeyFile)
		if keyFile == "" {
			return admin.SignOutcome{}, adminapi.NewError(adminapi.CodeInvalidArgument, "no signing key is configured: signer.key_file is empty")
		}
		key, err := signer.LoadKey(keyFile)
		if err != nil {
			return admin.SignOutcome{}, adminapi.NewError(adminapi.CodeInternal, "%v", err)
		}
		s, err := signer.NewSigner(key)
		if err != nil {
			return admin.SignOutcome{}, err
		}
		pub := s.PublicKey()
		out := admin.SignOutcome{KeyFingerprint: signer.KeyFingerprint(pub)}
		if trusted, err := cfg.Signer.TrustedPublicKeys(); err == nil {
			if v, err := signer.NewVerifier(trusted); err == nil {
				out.Trusted = v.Trusts(pub)
			}
		}
		code, stdout, stderr, err := signChild(ctx, configPath, name)
		if err != nil {
			return admin.SignOutcome{}, fmt.Errorf("sign: %v", err)
		}
		msg := strings.TrimSpace(string(stderr))
		switch code {
		case exitOK:
		case exitProblem:
			if strings.Contains(msg, "is registered, so there is nothing to sign") {
				return admin.SignOutcome{}, adminapi.NewError(adminapi.CodeNotFound, "no registered backend is named %q", name).With("upstream", name)
			}
			return admin.SignOutcome{}, adminapi.NewError(adminapi.CodeInvalidArgument, "not signed: %s", msg)
		default:
			return admin.SignOutcome{}, adminapi.NewError(adminapi.CodeInternal, "sign could not run (exit %d): %s", code, msg)
		}
		sc := bufio.NewScanner(bytes.NewReader(stdout))
		for sc.Scan() {
			out.Output = append(out.Output, sc.Text())
		}
		return out, nil
	}
}

// runRegistryReader prints, as JSON, each vault name a registered entry
// declares and the entries declaring it: what GET /v1/secrets on the
// accounts socket needs of the registry, read as the database's owner so
// root never opens it (design/adr/0040 §1). Names only; the registry holds
// no value.
func runRegistryReader(configPath string, stdout, stderr io.Writer) int {
	if adminGeteuid() == 0 {
		fmt.Fprint(stderr, "admin -registry-reader runs as the database's owner, never as root.\n")
		return exitCannotRun
	}
	return opRun(configPath, io.Discard, stderr, func(e *opEnv) int {
		entries, err := e.upstreams().List(e.ctx())
		if err != nil {
			fmt.Fprintf(stderr, "registry: %v\n", err)
			return exitProblem
		}
		declared := map[string][]string{}
		for _, entry := range entries {
			for _, n := range entry.EnvVarNames {
				declared[n] = append(declared[n], entry.Name)
			}
		}
		if err := json.NewEncoder(stdout).Encode(declared); err != nil {
			fmt.Fprintf(stderr, "admin -registry-reader: %v\n", err)
			return exitProblem
		}
		return exitOK
	})
}
