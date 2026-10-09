package admin

// The console manages everything (design/adr/0050): http backends
// registered, signed and deregistered, vault values and the roles file
// written -- through ports, behind [admin] console_manages.
//
// Every rule of these operations is here and only here: the switch, the
// confirmation of a deregister, a vault name's grammar and a value's
// bounds, the roles text validated before it is written, and one operator
// row per change. The adapters (cmd/mcp-gateway) do the I/O: the
// registry and the ingestion, the `sign` child, sops, the roles file.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Operator rows of design/adr/0050. Declared interface strings: a SIEM
// rule matches on them. Every reason starts with the name it is about,
// and the secret rows never carry a value.
const (
	UpstreamRegister   = "(upstream register)"
	UpstreamDeregister = "(upstream deregister)"
	UpstreamSign       = "(upstream sign)"
	SecretSet          = "(secret set)"
	SecretDelete       = "(secret delete)"
	RolesSet           = "(roles set)"
)

// VaultStore is the Credential Vault's write side (design/adr/0050 §2):
// the encrypted file, decrypted and encrypted again in memory. No method
// returns a value, and no error may carry one.
type VaultStore interface {
	// Names lists the names the vault holds, sorted.
	Names(ctx context.Context, cfg *config.Config) ([]string, error)
	// Set writes value under name, atomically; existed says a value was
	// there before. Post-condition: on error the file is as it was.
	Set(ctx context.Context, cfg *config.Config, name string, value []byte) (existed bool, err error)
	// Delete removes name; existed false means there was nothing to
	// remove and the file was not rewritten.
	Delete(ctx context.Context, cfg *config.Config, name string) (existed bool, err error)
}

// RolesStore is the file cfg.RolesFile names.
type RolesStore interface {
	Read(cfg *config.Config) ([]byte, error)
	// Write replaces the file atomically, keeping its owner and mode.
	Write(cfg *config.Config, text []byte) error
}

// SignOutcome is what a sign did: the public key's fingerprint, whether
// signer.trusted_keys lists it, and the lines `sign` printed.
type SignOutcome struct {
	KeyFingerprint string
	Trusted        bool
	Output         []string
}

// ManageDeps are the ports of design/adr/0050, embedded in Deps. A nil
// port makes its operation answer internal: the operator socket has the
// registry ports, the accounts socket the root ones.
type ManageDeps struct {
	// UpstreamDetail reads one entry; not_found when the registry has
	// none by that name.
	UpstreamDetail func(ctx context.Context, cfg *config.Config, name string) (adminapi.UpstreamDetail, error)
	// RegisterHTTP ingests the document and registers the entry, the way
	// `upstream register -transport http` does; its refusals are
	// *adminapi.Error. The ActionResult part is the service's to fill.
	RegisterHTTP func(ctx context.Context, cfg *config.Config, req adminapi.RegisterUpstreamRequest) (adminapi.RegisterUpstreamResult, error)
	// Deregister removes the entry and everything keyed by its name.
	Deregister func(ctx context.Context, cfg *config.Config, name string) (adminapi.DeregisterResult, error)
	// Sign signs one entry with the root key.
	Sign func(ctx context.Context, cfg *config.Config, name string) (SignOutcome, error)
	// Vault writes the vault.
	Vault VaultStore
	// DeclaredSecrets maps each vault name a registered entry declares to
	// the entries declaring it. nil: the registry is not readable from
	// this backend, and the secret list carries the vault's names only.
	DeclaredSecrets func(ctx context.Context, cfg *config.Config) (map[string][]string, error)
	// Roles reads and writes the roles file.
	Roles RolesStore
	// ValidateRoles is config.ValidateRolesText over this backend's
	// configuration file.
	ValidateRoles func(text []byte) error
	// CheckPaths, when set, holds the files a root backend reads and
	// writes besides config.toml (the vault's two) to the ownership rule
	// of design/adr/0040 §1; nil checks nothing (the operator socket,
	// tests).
	CheckPaths func(paths []string) error
	// CheckAgeKey, when set, holds the vault's age identity to its own rule
	// (CheckServiceKey: the service account's file by design). nil: the age
	// identity goes through CheckPaths with the vault file.
	CheckAgeKey func(path string) error
}

// ConsoleManages reports whether the configuration turns the operations
// of design/adr/0050 on. An unreadable configuration is off: whoami must
// not advertise buttons every one of which would then fail.
func (s *Service) ConsoleManages() bool {
	cfg, err := s.d.Config()
	return err == nil && cfg.Admin.ConsoleManages
}

// managing reads the configuration and refuses when console_manages is
// off.
func (s *Service) managing() (*config.Config, error) {
	cfg, err := s.config()
	if err != nil {
		return nil, err
	}
	if !cfg.Admin.ConsoleManages {
		return nil, adminapi.NewError(adminapi.CodeFeatureDisabled,
			"this operation is off: [admin] console_manages is false in the configuration file, and with it off backends, the vault and the roles are managed from the terminal only (design/adr/0050 §1)").
			With("key", "admin.console_manages")
	}
	return cfg, nil
}

// operatorPeer refuses a change of the accounts socket by a peer that is
// neither root nor in [admin] operator_group. The accounts socket may be
// delegated to [admin] account_group (design/adr/0040 §1), and that
// delegation is of IdP accounts: signing a backend, writing the vault and
// the roles are an operator's acts, held to the rule an offboard's block
// is (design/adr/0046 item 2). On the operator socket every peer already
// passed the operator check.
func operatorPeer(a Actor, what string) error {
	if a.Root || a.Operator {
		return nil
	}
	return adminapi.NewError(adminapi.CodeForbiddenPeer, "%s is an operator's act: %s is neither root nor in [admin] operator_group, and the accounts socket's delegation covers accounts only", what, a.Name)
}

// upstreamName refuses an empty name and a name with characters no entry
// can carry, before any port sees it. The registry's own rule decides the
// rest.
func upstreamName(name string) error {
	if strings.TrimSpace(name) == "" {
		return adminapi.NewError(adminapi.CodeInvalidArgument, "a backend name is required").With("field", "name")
	}
	// The registry's own grammar: a name that does not start with a letter
	// or digit could be read as a flag by the sign child (`-h` printed the
	// usage, exited 0 and was recorded as a signature; found in review).
	if len(name) > 128 || strings.ContainsAny(name, "/\\ \t\r\n") || !registry.ValidName(name) {
		return adminapi.NewError(adminapi.CodeInvalidArgument, "%s is not a backend name", visible.Escape(fmt.Sprintf("%q", name))).With("field", "name")
	}
	return nil
}

// GetUpstream is one entry in detail, with its health.
func (s *Service) GetUpstream(ctx context.Context, name string) (adminapi.UpstreamDetail, error) {
	cfg, err := s.managing()
	if err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	if err := upstreamName(name); err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	if err := need(s.d.UpstreamDetail != nil, "upstream registry"); err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	d, err := s.d.UpstreamDetail(ctx, cfg, name)
	if err != nil {
		return adminapi.UpstreamDetail{}, s.storeErr("upstream registry", err)
	}
	if d.Tools == nil {
		d.Tools = []adminapi.Tool{}
	}
	if s.d.Health != nil {
		if h, _, err := s.health(ctx, []string{d.Name}); err == nil && len(h.Backends) == 1 {
			d.Health = &h.Backends[0]
		}
	}
	return d, nil
}

// RegisterUpstream registers an http backend from its OpenAPI document
// (design/adr/0050 §2): the same ingestion, refusals and report as
// `upstream register -transport http`. stdio and oci stay in the terminal
// (design/adr/0034).
//
// Not under the service's lock: a document URL is fetched, which may take
// the request's whole deadline, and the registry's insert is atomic on
// its own (a second register of the name is already_exists).
func (s *Service) RegisterUpstream(ctx context.Context, a Actor, req adminapi.RegisterUpstreamRequest) (adminapi.RegisterUpstreamResult, error) {
	res := adminapi.RegisterUpstreamResult{ActionResult: newResult()}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.managing()
	if err != nil {
		return res, err
	}
	if err := upstreamName(req.Name); err != nil {
		return res, err
	}
	switch {
	case req.OpenAPIURL == "" && req.OpenAPIDocument == "":
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "the OpenAPI document is required: give openapi_url or openapi_document (design/adr/0047 §3)").With("field", "openapi_url")
	case req.OpenAPIURL != "" && req.OpenAPIDocument != "":
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "give openapi_url or openapi_document, not both").With("field", "openapi_document")
	case req.OpenAPIURL != "" && !isHTTPURL(req.OpenAPIURL):
		// Never a path: the operator socket would otherwise read any file
		// the service account can, and quote it back in a parse error.
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "openapi_url must be an http:// or https:// URL; send a local document as openapi_document").With("field", "openapi_url")
	case len(req.OpenAPIDocument) > adminapi.MaxUpstreamDocumentBytes:
		return res, adminapi.NewError(adminapi.CodePayloadTooLarge, "the document is over the %d-byte limit the ingestion reads", adminapi.MaxUpstreamDocumentBytes).With("field", "openapi_document")
	}
	if before, _, found := strings.Cut(req.KeyName, "="); found {
		// The CLI's -env rule: a NAME=value pasted here would be a secret
		// in the request, and repeating it would put it in a log. Only the
		// part left of "=" is said.
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "key_name %q looks like NAME=value (the value is not repeated here): it takes the vault NAME only; set the value with PUT /v1/secrets/{name}", visible.Escape(before)).With("field", "key_name")
	}
	if req.KeyName != "" {
		if err := secretName(req.KeyName); err != nil {
			return res, err
		}
	}
	if err := need(s.d.RegisterHTTP != nil, "upstream registry"); err != nil {
		return res, err
	}
	out, err := s.d.RegisterHTTP(ctx, cfg, req)
	if err != nil {
		return res, s.storeErr("registering "+visible.Escape(req.Name), err)
	}
	out.ActionResult = res.ActionResult
	normaliseRegister(&out)
	out.Changed = true
	safe, sensitive := 0, 0
	for _, t := range out.Tools {
		if t.Class == adminapi.ClassSensitive {
			sensitive++
		} else {
			safe++
		}
	}
	out.Messages = append(out.Messages, fmt.Sprintf("Registered %q: %d %s (%d safe, %d sensitive). Each tool waits in the quarantine until it is approved; the entry is served once it is signed (POST /v1/upstreams/%s/sign on the accounts socket).",
		out.Name, len(out.Tools), plural(len(out.Tools), "tool", "tools"), safe, sensitive, out.Name))
	if out.AuthDerived {
		out.Messages = append(out.Messages, "The auth descriptor was DERIVED from the document's securitySchemes, not chosen in the request: check it, the gateway injects the secret there on every call.")
	}
	reason := fmt.Sprintf("upstream %q registered: http %s, %d %s (%d safe, %d sensitive), auth %s", out.Name, out.URL, len(out.Tools), plural(len(out.Tools), "operation", "operations"), safe, sensitive, authWords(out.Auth))
	s.record(ctx, cfg, &out.ActionResult, s.operatorRow(a, UpstreamRegister, reason+" "+a.Tag(), s.d.Now().UTC()))
	return out, nil
}

func normaliseRegister(r *adminapi.RegisterUpstreamResult) {
	if r.Tools == nil {
		r.Tools = []adminapi.UpstreamOperation{}
	}
	if r.Skipped == nil {
		r.Skipped = []string{}
	}
	if r.IngestWarnings == nil {
		r.IngestWarnings = []string{}
	}
}

func authWords(a adminapi.UpstreamAuth) string {
	w := a.Kind
	if w == "" {
		w = "none"
	}
	if a.Name != "" {
		w += " " + a.Name
	}
	if a.Secret != "" {
		w += " <" + a.Secret + ">"
	}
	return w
}

func isHTTPURL(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// DeregisterUpstream removes a backend and everything keyed by its name:
// the signature, the approvals and the health. confirm must repeat the
// name exactly: the approvals go with it (design/adr/0050 §2).
func (s *Service) DeregisterUpstream(ctx context.Context, a Actor, name string, req adminapi.DeregisterRequest) (adminapi.DeregisterResult, error) {
	res := adminapi.DeregisterResult{ActionResult: newResult(), Name: name}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.managing()
	if err != nil {
		return res, err
	}
	if err := upstreamName(name); err != nil {
		return res, err
	}
	if req.Confirm != name {
		return res, adminapi.NewError(adminapi.CodeInvalidArgument,
			"confirm must repeat the backend's name exactly: deregistering removes its signature and every approval of its tools with it").
			With("field", "confirm")
	}
	if err := need(s.d.Deregister != nil, "upstream registry"); err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.d.Deregister(ctx, cfg, name)
	if err != nil {
		return res, s.storeErr("deregistering "+visible.Escape(name), err)
	}
	out.ActionResult, out.Name = res.ActionResult, name
	out.Changed = out.Registered || out.SignatureRemoved || out.ToolsForgotten > 0
	if !out.Changed {
		out.Messages = append(out.Messages, fmt.Sprintf("No backend named %q is registered, and nothing was left under the name: it is clean.", name))
		return out, nil
	}
	if out.Registered {
		out.Messages = append(out.Messages, fmt.Sprintf("Deregistered %q. A running gateway closes it at its next round.", name))
	} else {
		out.Messages = append(out.Messages, fmt.Sprintf("Nothing was registered under %q, but state keyed by the name was, and it was removed.", name))
	}
	reason := fmt.Sprintf("upstream %q deregistered: registered %t, signature removed %t, %d quarantine %s removed", name, out.Registered, out.SignatureRemoved, out.ToolsForgotten, plural(out.ToolsForgotten, "entry", "entries"))
	s.record(ctx, cfg, &out.ActionResult, s.operatorRow(a, UpstreamDeregister, reason+" "+a.Tag(), s.d.Now().UTC()))
	return out, nil
}

// SignUpstream signs a backend with the root signing key, on the accounts
// socket (design/adr/0050 §2). The approval of each tool stays the human
// gate.
func (s *Service) SignUpstream(ctx context.Context, a Actor, name string) (adminapi.SignResult, error) {
	res := adminapi.SignResult{ActionResult: newResult(), Name: name}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.managing()
	if err != nil {
		return res, err
	}
	if err := upstreamName(name); err != nil {
		return res, err
	}
	if err := operatorPeer(a, "signing a backend"); err != nil {
		return res, err
	}
	if err := need(s.d.Sign != nil, "signer"); err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out, err := s.d.Sign(ctx, cfg, name)
	if err != nil {
		return res, s.storeErr("signing "+visible.Escape(name), err)
	}
	res.Changed, res.KeyFingerprint, res.Trusted = true, out.KeyFingerprint, out.Trusted
	for _, l := range out.Output {
		if strings.TrimSpace(l) != "" {
			res.Messages = append(res.Messages, visible.Escape(l))
		}
	}
	if !out.Trusted {
		res.Warnings = append(res.Warnings, adminapi.Warning{Code: "key_not_trusted",
			Message: "The signing key is not in signer.trusted_keys: the gateway will not serve this entry until it is, and trusted_keys needs a restart."})
	}
	reason := fmt.Sprintf("upstream %q signed with key %s", name, out.KeyFingerprint)
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, UpstreamSign, reason+" "+a.Tag(), s.d.Now().UTC()))
	return res, nil
}

// secretNameRe is an environment variable name: what the vault's names
// are, since a stdio backend receives each one as one.
var secretNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func secretName(name string) error {
	if len(name) > 128 || !secretNameRe.MatchString(name) {
		// Escaped and quoted: a name is not a value, but it is still text
		// a client chose.
		return adminapi.NewError(adminapi.CodeInvalidArgument, "%s is not a vault name: use an environment variable name, a letter or _ then letters, digits or _, at most 128", visible.Escape(fmt.Sprintf("%q", name))).
			With("field", "name")
	}
	return nil
}

// vaultPaths holds the vault's two files to the root ownership rule, when
// this backend checks paths.
func (s *Service) vaultPaths(cfg *config.Config) error {
	if s.d.CheckPaths == nil {
		return nil
	}
	if s.d.CheckAgeKey == nil {
		return s.d.CheckPaths([]string{cfg.Vault.SecretsFile, cfg.Vault.AgeKeyFile})
	}
	if err := s.d.CheckPaths([]string{cfg.Vault.SecretsFile}); err != nil {
		return err
	}
	return s.d.CheckAgeKey(cfg.Vault.AgeKeyFile)
}

// vaultErr maps a vault failure, which the adapter guarantees carries no
// value, onto the contract.
func vaultErr(what string, err error) error {
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae
	}
	return adminapi.NewError(adminapi.CodeInternal, "%s: %v", what, err)
}

// ListSecrets is the vault's names, and for each name a registered entry
// declares, whether the vault has it. Never a value.
//
// Reading is an operator's act too, like writing (design/adr/0050): a peer
// of a delegated [admin] account_group manages accounts, not the vault, and
// each listing has root decrypt the whole vault.
func (s *Service) ListSecrets(ctx context.Context, a Actor) (adminapi.SecretList, error) {
	out := adminapi.SecretList{Secrets: []adminapi.Secret{}}
	cfg, err := s.managing()
	if err != nil {
		return out, err
	}
	if err := operatorPeer(a, "reading the vault's names"); err != nil {
		return out, err
	}
	if err := need(s.d.Vault != nil, "vault"); err != nil {
		return out, err
	}
	if err := s.vaultPaths(cfg); err != nil {
		return out, err
	}
	names, err := s.d.Vault.Names(ctx, cfg)
	if err != nil {
		return out, vaultErr("reading the vault", err)
	}
	byName := map[string]*adminapi.Secret{}
	for _, n := range names {
		byName[n] = &adminapi.Secret{Name: n, InVault: true}
	}
	if s.d.DeclaredSecrets == nil {
		out.Problems = append(out.Problems, adminapi.Problem{Code: "registry_not_read", Part: "declared_by",
			Message: "This backend does not read the registry; GET /v1/upstreams on the operator socket lists each entry's env_var_names."})
	} else if declared, err := s.d.DeclaredSecrets(ctx, cfg); err != nil {
		out.Problems = append(out.Problems, adminapi.Problem{Code: "registry_not_read", Part: "declared_by", Message: "The registry could not be read: " + err.Error()})
	} else {
		out.RegistryRead = true
		for n, ups := range declared {
			sec := byName[n]
			if sec == nil {
				sec = &adminapi.Secret{Name: n}
				byName[n] = sec
			}
			sec.DeclaredBy = slices.Sorted(slices.Values(ups))
		}
	}
	for _, n := range slices.Sorted(maps.Keys(byName)) {
		out.Secrets = append(out.Secrets, *byName[n])
	}
	return out, nil
}

// SetSecret writes one vault value. The value enters here once: it is not
// in the answer, the row, the log or any error (design/adr/0050 §2).
func (s *Service) SetSecret(ctx context.Context, a Actor, name string, req adminapi.SecretValue) (adminapi.SecretResult, error) {
	res := adminapi.SecretResult{ActionResult: newResult(), Name: name}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.managing()
	if err != nil {
		return res, err
	}
	if err := secretName(name); err != nil {
		return res, err
	}
	if err := operatorPeer(a, "writing the vault"); err != nil {
		return res, err
	}
	switch {
	case req.Value == "":
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "the value is empty; to remove %s, DELETE it", name).With("field", "value")
	case len(req.Value) > adminapi.MaxSecretValueBytes:
		return res, adminapi.NewError(adminapi.CodePayloadTooLarge, "the value is over %d bytes", adminapi.MaxSecretValueBytes).With("field", "value")
	}
	if err := need(s.d.Vault != nil, "vault"); err != nil {
		return res, err
	}
	if err := s.vaultPaths(cfg); err != nil {
		return res, err
	}
	value := []byte(req.Value)
	defer clear(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	existed, err := s.d.Vault.Set(ctx, cfg, name, value)
	if err != nil {
		return res, vaultErr("writing the vault", err)
	}
	res.Changed, res.Existed = true, existed
	verb := "created"
	if existed {
		verb = "replaced"
	}
	res.Messages = append(res.Messages, fmt.Sprintf("%s %s in the vault. A connected backend keeps the value it was dialled with until it is redialled (POST /v1/upstreams/redial on the operator socket).", strings.ToUpper(verb[:1])+verb[1:], name))
	reason := fmt.Sprintf("secret %q %s", name, verb)
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, SecretSet, reason+" "+a.Tag(), s.d.Now().UTC()))
	return res, nil
}

// DeleteSecret removes one vault value. Removing a name nothing holds is
// changed: false, with no row.
func (s *Service) DeleteSecret(ctx context.Context, a Actor, name string) (adminapi.SecretResult, error) {
	res := adminapi.SecretResult{ActionResult: newResult(), Name: name}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.managing()
	if err != nil {
		return res, err
	}
	if err := secretName(name); err != nil {
		return res, err
	}
	if err := operatorPeer(a, "writing the vault"); err != nil {
		return res, err
	}
	if err := need(s.d.Vault != nil, "vault"); err != nil {
		return res, err
	}
	if err := s.vaultPaths(cfg); err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existed, err := s.d.Vault.Delete(ctx, cfg, name)
	if err != nil {
		return res, vaultErr("writing the vault", err)
	}
	res.Existed = existed
	if !existed {
		res.Messages = append(res.Messages, fmt.Sprintf("The vault holds no %s; nothing changed.", name))
		return res, nil
	}
	res.Changed = true
	res.Messages = append(res.Messages, fmt.Sprintf("Deleted %s from the vault. A backend that declares it fails to dial from its next dial on.", name))
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, SecretDelete, fmt.Sprintf("secret %q deleted %s", name, a.Tag()), s.d.Now().UTC()))
	return res, nil
}

// rolesConfigured refuses the roles operations of a configuration that
// keeps its roles in the main file: the console writes a roles file, never
// config.toml (design/adr/0050 §3).
func rolesConfigured(cfg *config.Config) error {
	if cfg.RolesFile == "" {
		return adminapi.NewError(adminapi.CodeFeatureDisabled,
			"the roles are in the main configuration file: set roles_file and move [[role]] and [group_to_role] there to edit them here (design/adr/0050 §3)").
			With("key", "roles_file")
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// GetRoles is the roles file's text.
//
// An operator's act, like writing them (see ListSecrets).
func (s *Service) GetRoles(ctx context.Context, a Actor) (adminapi.RolesText, error) {
	cfg, err := s.managing()
	if err != nil {
		return adminapi.RolesText{}, err
	}
	if err := operatorPeer(a, "reading the roles"); err != nil {
		return adminapi.RolesText{}, err
	}
	if err := rolesConfigured(cfg); err != nil {
		return adminapi.RolesText{}, err
	}
	if err := need(s.d.Roles != nil, "roles file"); err != nil {
		return adminapi.RolesText{}, err
	}
	text, err := s.d.Roles.Read(cfg)
	if err != nil {
		return adminapi.RolesText{}, adminapi.NewError(adminapi.CodeInternal, "reading the roles file: %v", err)
	}
	return adminapi.RolesText{Text: string(text), Path: cfg.RolesFile, SHA256: sha256Hex(text)}, nil
}

// PutRoles validates text as the roles file, the way the configuration
// load will, and writes it. It does not apply it: serve applies roles on a
// reload, and the console asks for one on the operator socket next.
func (s *Service) PutRoles(ctx context.Context, a Actor, req adminapi.RolesRequest) (adminapi.RolesResult, error) {
	res := adminapi.RolesResult{ActionResult: newResult()}
	if err := checkActor(a); err != nil {
		return res, err
	}
	cfg, err := s.managing()
	if err != nil {
		return res, err
	}
	if err := rolesConfigured(cfg); err != nil {
		return res, err
	}
	if err := operatorPeer(a, "writing the roles"); err != nil {
		return res, err
	}
	res.Path = cfg.RolesFile
	if len(req.Text) > adminapi.MaxRolesTextBytes {
		return res, adminapi.NewError(adminapi.CodePayloadTooLarge, "the roles text is over %d bytes", adminapi.MaxRolesTextBytes).With("field", "text")
	}
	if err := need(s.d.Roles != nil && s.d.ValidateRoles != nil, "roles file"); err != nil {
		return res, err
	}
	text := []byte(req.Text)
	if err := s.d.ValidateRoles(text); err != nil {
		return res, adminapi.NewError(adminapi.CodeInvalidArgument, "the roles text would not load, so it was not written: %v", err).With("field", "text")
	}
	res.SHA256 = sha256Hex(text)
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, err := s.d.Roles.Read(cfg); err == nil && string(cur) == req.Text {
		res.Messages = append(res.Messages, "The roles file already holds exactly this text; nothing was written.")
		return res, nil
	}
	if err := s.d.Roles.Write(cfg, text); err != nil {
		return res, adminapi.NewError(adminapi.CodeInternal, "writing the roles file: %v", err)
	}
	res.Changed, res.ReloadNeeded = true, true
	res.Messages = append(res.Messages, "Written and NOT applied: the gateway applies roles on a reload. Call POST /v1/reload on the operator socket.")
	reason := fmt.Sprintf("roles file %s set to sha256:%s", cfg.RolesFile, res.SHA256)
	s.record(ctx, cfg, &res.ActionResult, s.operatorRow(a, RolesSet, reason+" "+a.Tag(), s.d.Now().UTC()))
	return res, nil
}
