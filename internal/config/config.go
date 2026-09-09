// Package config is the gateway's configuration contract: the TOML file
// an operator writes, and the validation that refuses a bad one at
// startup rather than at the first request.
//
// Two rules govern what may appear here, both from
// design/adr/0009-configuration-in-toml.md:
//
//   - **No secret values, ever.** Fields hold paths and identifiers --
//     where the age identity lives, where the signing key lives, which
//     issuer to trust. The secrets themselves stay in the sops-encrypted
//     file and in owner-only key files. This is what makes the config
//     file safe to commit, and it is enforced by test.
//   - **Roles live here, not in the database.** An upstream is
//     operational state and belongs in the registry; a role is policy,
//     and changing who may call what should be a reviewed diff rather
//     than a command that leaves no trace.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrInvalid is returned for a configuration that parses but cannot be
// used. Callers check it with errors.Is.
var ErrInvalid = errors.New("config: invalid")

// Config is the whole configuration file.
type Config struct {
	// Listen is the address the MCP endpoint serves on, e.g.
	// "127.0.0.1:8080". Defaults to loopback deliberately: a gateway
	// holding every backend credential should not become reachable from
	// the network because someone forgot to set an address.
	Listen string `toml:"listen"`

	// Database is the path to the embedded SQLite file holding the
	// Upstream Registry, Tool Quarantine, Audit Trail and entry
	// signatures. Never holds a secret (design/adr/0001).
	Database string `toml:"database"`

	OIDC   OIDC   `toml:"oidc"`
	Vault  Vault  `toml:"vault"`
	Signer Signer `toml:"signer"`

	// Roles defines what each role may call. Order is irrelevant.
	Roles []Role `toml:"role"`

	// GroupToRole maps an IdP group claim to a role name. A group with no
	// mapping is ignored, not an error -- an IdP carries groups that have
	// nothing to do with this gateway.
	GroupToRole map[string]string `toml:"group_to_role"`
}

// OIDC identifies the self-hosted provider this gateway trusts
// (design/adr/0008). It names an issuer; it never holds a client secret,
// because a resource server does not need one -- it validates tokens, it
// does not obtain them.
type OIDC struct {
	// Issuer is the provider's base URL, used for discovery.
	Issuer string `toml:"issuer"`
	// Audience is this gateway's own resource identifier. A token minted
	// for a different service of the same IdP must not be accepted here
	// (RFC 8707), which is why this is required and has no default.
	Audience string `toml:"audience"`
	// GroupsClaim names the claim carrying group membership. Providers
	// differ; making it configurable is what keeps the gateway
	// provider-agnostic. Defaults to "groups".
	GroupsClaim string `toml:"groups_claim"`
	// AuthorizationServers is advertised in RFC 9728 protected-resource
	// metadata so a client can discover where to get a token. Defaults to
	// [Issuer].
	AuthorizationServers []string `toml:"authorization_servers"`
}

// Vault points at the sops-encrypted secrets file and the age identity
// that decrypts it (design/adr/0003, design/adr/0005). Paths only.
type Vault struct {
	// SecretsFile is the sops-encrypted JSON document. Safe to commit --
	// that is the entire point of sops.
	SecretsFile string `toml:"secrets_file"`
	// AgeKeyFile is the age identity. Must be owner-only on disk; this
	// project's one knowingly-accepted plaintext-on-disk exposure.
	AgeKeyFile string `toml:"age_key_file"`
}

// Signer points at the Ed25519 key used to sign registry entries
// (design/adr/0006).
type Signer struct {
	// KeyFile is the Ed25519 private key, PEM-wrapped PKCS#8, owner-only.
	// Optional: without it the gateway can still *verify* signatures, it
	// just cannot create them, which is the right split for a serving
	// process that never signs.
	KeyFile string `toml:"key_file"`
	// RequireSigned makes an entry without a valid signature unusable.
	//
	// **Defaults to true as of 09 Sep 2026.** It defaulted to false while
	// nothing could produce signatures at volume, and ADR-0006 recorded
	// that as debt with an explicit trigger: flip it once the Operator
	// Console ships. The console shipped in Phase 6, so it is flipped.
	//
	// A pointer rather than a bool because the zero value of a bool
	// cannot be told apart from an operator writing `require_signed =
	// false`, and silently reading "unset" as "off" is precisely how a
	// security default rots.
	//
	// An *invalid* signature is refused regardless of this setting: there
	// is no benign reading of a signature that does not match the entry.
	RequireSigned *bool `toml:"require_signed"`
}

// Role is a named set of namespaced tools, mirroring access.Role. It
// exists separately so the file format is not hostage to the domain type,
// and so a config field can carry documentation the domain type has no
// reason to.
type Role struct {
	// Name identifies the role, referenced from group_to_role.
	Name string `toml:"name"`
	// Tools are the namespaced tool names this role may call, e.g.
	// "casemgmt.list_cases". Matched exactly -- there is no wildcard, because
	// a wildcard is how a role silently gains a tool added upstream
	// later.
	Tools []string `toml:"tools"`
}

// DefaultListen is the address used when none is configured: loopback,
// so an unconfigured gateway is not exposed to the network.
const DefaultListen = "127.0.0.1:8080"

// DefaultGroupsClaim matches the most common provider convention.
const DefaultGroupsClaim = "groups"

// DefaultConnectTimeout bounds the startup connect to all upstreams.
const DefaultConnectTimeout = 30 * time.Second

// DefaultRequireSigned is what signer.require_signed means when the file
// does not say. See the field's own doc for why it changed.
const DefaultRequireSigned = true

// SignaturesRequired reports whether an unsigned registry entry may be
// served, resolving the unset case to DefaultRequireSigned.
func (s Signer) SignaturesRequired() bool {
	if s.RequireSigned == nil {
		return DefaultRequireSigned
	}
	return *s.RequireSigned
}

// Validate reports whether c can be used, applying defaults as it goes.
//
// It is deliberately strict at startup. A configuration error discovered
// on the first request is discovered during an incident, by an analyst
// who cannot fix it; the same error at startup is discovered by the
// operator who just changed the file. This is the same reasoning
// access.NewPolicy uses in refusing an undefined role mapping at
// construction time.
func (c *Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = DefaultListen
	}
	if strings.TrimSpace(c.Database) == "" {
		errs = append(errs, errors.New("database: required (path to the SQLite file)"))
	}

	if strings.TrimSpace(c.OIDC.Issuer) == "" {
		errs = append(errs, errors.New("oidc.issuer: required"))
	} else if err := requireAbsoluteURL(c.OIDC.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("oidc.issuer: %w", err))
	}
	if strings.TrimSpace(c.OIDC.Audience) == "" {
		// No default, deliberately. Defaulting an audience would mean
		// accepting tokens minted for some other service of the same IdP,
		// which RFC 8707 exists to prevent.
		errs = append(errs, errors.New("oidc.audience: required (this gateway's resource identifier; never defaulted)"))
	}
	if strings.TrimSpace(c.OIDC.GroupsClaim) == "" {
		c.OIDC.GroupsClaim = DefaultGroupsClaim
	}
	if len(c.OIDC.AuthorizationServers) == 0 && c.OIDC.Issuer != "" {
		c.OIDC.AuthorizationServers = []string{c.OIDC.Issuer}
	}

	if strings.TrimSpace(c.Vault.SecretsFile) == "" {
		errs = append(errs, errors.New("vault.secrets_file: required"))
	}
	if strings.TrimSpace(c.Vault.AgeKeyFile) == "" {
		errs = append(errs, errors.New("vault.age_key_file: required"))
	}

	seen := map[string]bool{}
	for i, r := range c.Roles {
		if strings.TrimSpace(r.Name) == "" {
			errs = append(errs, fmt.Errorf("role[%d]: name is required", i))
			continue
		}
		if seen[r.Name] {
			errs = append(errs, fmt.Errorf("role %q: defined more than once", r.Name))
		}
		seen[r.Name] = true
		if len(r.Tools) == 0 {
			// Allowed, and worth stating: a role granting nothing is a
			// legitimate way to define someone who may authenticate but
			// may not act.
			continue
		}
		for _, tool := range r.Tools {
			if strings.TrimSpace(tool) == "" {
				errs = append(errs, fmt.Errorf("role %q: contains an empty tool name", r.Name))
			}
		}
	}

	for group, role := range c.GroupToRole {
		if strings.TrimSpace(group) == "" {
			errs = append(errs, errors.New("group_to_role: contains an empty group name"))
		}
		if !seen[role] {
			errs = append(errs, fmt.Errorf("group_to_role[%q]: maps to undefined role %q", group, role))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalid}, errs...)...)
}

func requireAbsoluteURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	if !u.IsAbs() || u.Host == "" {
		return errors.New("must be an absolute URL")
	}
	return nil
}
