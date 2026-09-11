package config

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

// testTrustedKey is the base64 of a real (throwaway) Ed25519 public key, in
// the form signer.trusted_keys takes. A public key is not a secret, so a
// literal here breaks no rule of this package -- but it is a key nobody
// holds the private half of, so nothing can be signed for it either.
const testTrustedKey = "YBVP3wMTzQlOQqvDUZ31FVpYqX9Yenqw5fPVYLlQ9HE="

// completeConfig is a file that sets every field explicitly, including the
// ones that have defaults. Tests that want to exercise a specific failure
// remove exactly one thing from it, so a failing test points at the thing
// that was removed rather than at some unrelated omission.
//
// listen is a loopback address because Validate refuses anything else
// (ADR-0011, and see TestValidateRefusesANonLoopbackListen). It used to be
// "0.0.0.0:9443" here, which was accepted by this package and killed
// `serve` -- the fixture was itself an instance of the bug.
const completeConfig = `
listen   = "127.0.0.1:9443"
database = "/var/db/mcp-gateway/mcp-gateway.db"

[oidc]
issuer                = "https://id.soc.internal/realms/soc"
audience              = "https://gw.soc.internal/mcp"
groups_claim          = "soc_groups"
authorization_servers = ["https://id.soc.internal/realms/soc", "https://id2.soc.internal/realms/soc"]

[vault]
secrets_file = "/usr/local/etc/mcp-gateway/secrets.enc.json"
age_key_file = "/usr/local/etc/mcp-gateway/age.key"

[signer]
key_file       = "/usr/local/etc/mcp-gateway/signing.key"
require_signed = true
trusted_keys   = ["YBVP3wMTzQlOQqvDUZ31FVpYqX9Yenqw5fPVYLlQ9HE=", "95hrvkq5Lv2DH0yrq4V/4YgBs/0B/InLgZzpBF0+QxU="]

[response]
max_bytes = 2097152

[[role]]
name  = "n1-triage"
tools = ["casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"]

[[role]]
name  = "dfir-lead"
tools = ["casemgmt.list_cases", "docsearch.search", "threatintel.virustotal"]

[group_to_role]
"soc-n1"   = "n1-triage"
"soc-dfir" = "dfir-lead"
`

// minimalConfig sets only what is required, so the defaults are what fills
// in the rest. Deliberately does NOT set listen, groups_claim or
// authorization_servers.
//
// signer.trusted_keys is here because it *is* required: require_signed
// defaults to true, and ADR-0010 makes requiring signatures with no key to
// check them against a startup error. signer.key_file stays out -- the
// serving process verifies and never signs, so the public half is required
// and the private half is not, which is the split this fixture should show.
const minimalConfig = `
database = "/var/db/mcp-gateway/mcp-gateway.db"

[oidc]
issuer   = "https://id.soc.internal/realms/soc"
audience = "https://gw.soc.internal/mcp"

[vault]
secrets_file = "/usr/local/etc/mcp-gateway/secrets.enc.json"
age_key_file = "/usr/local/etc/mcp-gateway/age.key"

[signer]
trusted_keys = ["YBVP3wMTzQlOQqvDUZ31FVpYqX9Yenqw5fPVYLlQ9HE="]
`

// writeConfig writes contents to a temp file and returns its path.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

// withoutLine returns contents with the (single) line containing substr
// removed. It fails the test if substr is absent, so a fixture edit that
// invalidates a test's premise is caught immediately rather than turning
// the test into a tautology.
func withoutLine(t *testing.T, contents, substr string) string {
	t.Helper()
	lines := strings.Split(contents, "\n")
	out := make([]string, 0, len(lines))
	found := false
	for _, line := range lines {
		if strings.Contains(line, substr) {
			found = true
			continue
		}
		out = append(out, line)
	}
	if !found {
		t.Fatalf("fixture has no line containing %q -- the fixture changed and this test no longer tests what it says", substr)
	}
	return strings.Join(out, "\n")
}

func mustLoad(t *testing.T, contents string) *Config {
	t.Helper()
	c, err := Load(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	return c
}

func loadErr(t *testing.T, contents string) error {
	t.Helper()
	c, err := Load(writeConfig(t, contents))
	if err == nil {
		t.Fatalf("Load: expected an error, got a usable config: %+v", c)
	}
	return err
}

// -----------------------------------------------------------------------
// The happy path
// -----------------------------------------------------------------------

func TestLoadCompleteFile(t *testing.T) {
	c := mustLoad(t, completeConfig)

	if c.Listen != "127.0.0.1:9443" {
		t.Errorf("Listen = %q, want the configured value", c.Listen)
	}
	if got, want := c.Response.MaxResultBytes(), int64(2*1024*1024); got != want {
		t.Errorf("Response.MaxResultBytes() = %d, want the configured %d", got, want)
	}
	if c.Database != "/var/db/mcp-gateway/mcp-gateway.db" {
		t.Errorf("Database = %q", c.Database)
	}
	if c.OIDC.Issuer != "https://id.soc.internal/realms/soc" {
		t.Errorf("OIDC.Issuer = %q", c.OIDC.Issuer)
	}
	if c.OIDC.Audience != "https://gw.soc.internal/mcp" {
		t.Errorf("OIDC.Audience = %q", c.OIDC.Audience)
	}
	if c.OIDC.GroupsClaim != "soc_groups" {
		t.Errorf("OIDC.GroupsClaim = %q, want the configured value, not the default", c.OIDC.GroupsClaim)
	}
	wantServers := []string{
		"https://id.soc.internal/realms/soc",
		"https://id2.soc.internal/realms/soc",
	}
	if !reflect.DeepEqual(c.OIDC.AuthorizationServers, wantServers) {
		t.Errorf("OIDC.AuthorizationServers = %v, want %v", c.OIDC.AuthorizationServers, wantServers)
	}
	if c.Vault.SecretsFile != "/usr/local/etc/mcp-gateway/secrets.enc.json" {
		t.Errorf("Vault.SecretsFile = %q", c.Vault.SecretsFile)
	}
	if c.Vault.AgeKeyFile != "/usr/local/etc/mcp-gateway/age.key" {
		t.Errorf("Vault.AgeKeyFile = %q", c.Vault.AgeKeyFile)
	}
	if c.Signer.KeyFile != "/usr/local/etc/mcp-gateway/signing.key" {
		t.Errorf("Signer.KeyFile = %q", c.Signer.KeyFile)
	}
	if !c.Signer.SignaturesRequired() {
		t.Error("SignaturesRequired() = false, want true -- the file sets it, and a security setting that does not survive parsing is the whole failure mode this package guards")
	}

	if len(c.Roles) != 2 {
		t.Fatalf("len(Roles) = %d, want 2", len(c.Roles))
	}
	if c.Roles[0].Name != "n1-triage" {
		t.Errorf("Roles[0].Name = %q", c.Roles[0].Name)
	}
	wantTools := []string{"casemgmt.list_cases", "casemgmt.get_case", "threatintel.lookup_ip"}
	if !reflect.DeepEqual(c.Roles[0].Tools, wantTools) {
		t.Errorf("Roles[0].Tools = %v, want %v", c.Roles[0].Tools, wantTools)
	}
	wantMapping := map[string]string{"soc-n1": "n1-triage", "soc-dfir": "dfir-lead"}
	if !reflect.DeepEqual(c.GroupToRole, wantMapping) {
		t.Errorf("GroupToRole = %v, want %v", c.GroupToRole, wantMapping)
	}
}

// TestLoadAppliesDocumentedDefaults pins every default config.example.toml
// promises. A default that drifts from what the example file documents is
// a lie an operator has no way to detect.
func TestLoadAppliesDocumentedDefaults(t *testing.T) {
	c := mustLoad(t, minimalConfig)

	if c.Listen != DefaultListen {
		t.Errorf("Listen = %q, want the loopback default %q -- an unconfigured gateway must not be reachable from the network", c.Listen, DefaultListen)
	}
	if c.OIDC.GroupsClaim != DefaultGroupsClaim {
		t.Errorf("OIDC.GroupsClaim = %q, want %q", c.OIDC.GroupsClaim, DefaultGroupsClaim)
	}
	want := []string{"https://id.soc.internal/realms/soc"}
	if !reflect.DeepEqual(c.OIDC.AuthorizationServers, want) {
		t.Errorf("OIDC.AuthorizationServers = %v, want it defaulted to [issuer] %v", c.OIDC.AuthorizationServers, want)
	}

	// Not a default: the optional signer key stays empty, and
	// require_signed stays false. Both are asserted so that "optional"
	// cannot quietly become "invented".
	if c.Signer.KeyFile != "" {
		t.Errorf("Signer.KeyFile = %q, want empty -- a signing key must never be guessed", c.Signer.KeyFile)
	}
	// Flipped 09 Sep 2026: ADR-0006's debt had an explicit trigger -- flip
	// once the Operator Console can sign at volume -- and Phase 6 shipped
	// it, so an unset file now means signatures are required.
	if !c.Signer.SignaturesRequired() {
		t.Error("SignaturesRequired() = false with nothing in the file; the default flipped to true when the Operator Console shipped (ADR-0006 trigger)")
	}
	if c.Signer.RequireSigned != nil {
		t.Error("RequireSigned should stay nil when the file is silent, so 'unset' and 'explicitly false' remain distinguishable")
	}
}

// TestAudienceHasNoDefault is separate from the other required-field cases
// on purpose, because the reason it is required is not "we need a value"
// but a specific security property.
//
// Every other missing field could, in principle, be given a plausible
// default. Audience could not. `aud` is what distinguishes a token minted
// for THIS gateway from a token minted for some other service of the same
// IdP -- the internal wiki, Grafana, anything. Defaulting it (to the
// issuer, to the listen address, to anything at all) would mean accepting
// a token nobody issued for this resource, which is exactly the confused
// deputy RFC 8707's resource indicators exist to prevent. So: no default,
// not even a "sensible" one, and this test exists to keep someone from
// adding one later as a convenience.
func TestAudienceHasNoDefault(t *testing.T) {
	err := loadErr(t, withoutLine(t, minimalConfig, "audience"))

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "oidc.audience") {
		t.Errorf("error does not name oidc.audience: %v", err)
	}

	// And prove no value was invented on the way out: Validate must not
	// have quietly filled it in from the issuer.
	c := &Config{
		Database: "/tmp/x.db",
		OIDC:     OIDC{Issuer: "https://id.soc.internal/realms/soc"},
		Vault:    Vault{SecretsFile: "/tmp/s.json", AgeKeyFile: "/tmp/age.key"},
	}
	_ = c.Validate()
	if c.OIDC.Audience != "" {
		t.Errorf("Validate populated OIDC.Audience with %q -- an audience must never be defaulted (RFC 8707)", c.OIDC.Audience)
	}
}

// -----------------------------------------------------------------------
// Unknown keys
// -----------------------------------------------------------------------

// TestLoadRejectsUnknownKey uses a realistic typo rather than a nonsense
// key, because the realistic one is the whole argument: `require_signd`
// parses fine, is dropped by a permissive decoder, and leaves a file that
// reads as though signature enforcement were on while the process runs
// with it off.
func TestLoadRejectsUnknownKey(t *testing.T) {
	contents := strings.Replace(completeConfig, "require_signed = true", "require_signd = true", 1)
	err := loadErr(t, contents)

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "require_signd") {
		t.Errorf("error does not name the offending key %q -- an operator has to be told which key, not merely that one is wrong: %v", "require_signd", err)
	}
}

func TestLoadRejectsUnknownKeyVariants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(string) string
		wantKey  string
		wantAlso string
	}{
		{
			name:    "top level typo",
			mutate:  func(s string) string { return strings.Replace(s, "database =", "databse =", 1) },
			wantKey: "databse",
		},
		{
			name:    "nested typo keeps its table prefix",
			mutate:  func(s string) string { return strings.Replace(s, "groups_claim", "group_claim", 1) },
			wantKey: "oidc.group_claim",
		},
		{
			name:    "unknown table",
			mutate:  func(s string) string { return s + "\n[telemetry]\nendpoint = \"https://otel.soc.internal\"\n" },
			wantKey: "telemetry",
		},
		{
			name: "unknown key inside a role",
			mutate: func(s string) string {
				return strings.Replace(s, `name  = "dfir-lead"`, `name  = "dfir-lead"`+"\nallow_all = true", 1)
			},
			wantKey: "allow_all",
		},
		{
			name: "several at once are all reported",
			mutate: func(s string) string {
				s = strings.Replace(s, "require_signed = true", "require_signd = true", 1)
				return strings.Replace(s, "listen  ", "lisen   ", 1)
			},
			wantKey:  "require_signd",
			wantAlso: "lisen",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadErr(t, tc.mutate(completeConfig))
			if !strings.Contains(err.Error(), tc.wantKey) {
				t.Errorf("error does not name %q: %v", tc.wantKey, err)
			}
			if tc.wantAlso != "" && !strings.Contains(err.Error(), tc.wantAlso) {
				t.Errorf("error does not name %q as well: %v", tc.wantAlso, err)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Required fields
// -----------------------------------------------------------------------

func TestLoadRequiresEachField(t *testing.T) {
	for _, tc := range []struct {
		name      string
		omitLine  string
		wantNamed string
	}{
		{"database", "database =", "database"},
		{"oidc.issuer", "issuer   =", "oidc.issuer"},
		{"oidc.audience", "audience =", "oidc.audience"},
		{"vault.secrets_file", "secrets_file", "vault.secrets_file"},
		{"vault.age_key_file", "age_key_file", "vault.age_key_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadErr(t, withoutLine(t, minimalConfig, tc.omitLine))
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantNamed) {
				t.Errorf("error does not name the missing field %q: %v", tc.wantNamed, err)
			}
		})
	}
}

// TestRequireSignedWithoutTrustedKeysIsRefused is ADR-0010 item 3.
//
// Requiring a valid signature while listing no key to verify against asks
// for a guarantee that cannot be produced. Left to run, it is not even a
// safe failure: it is a fleet-wide outage discovered by whoever is on call,
// not by the operator who just edited the file. Failing at startup puts it
// in front of the person who caused it, which is the pattern ADR-0009
// established.
//
// require_signed defaults to true, so this is also the breaking change
// ADR-0010 accepts on purpose: every existing configuration that enforces
// signing needs one edit. The gateway has never run outside test, so there
// is no deployment to migrate.
func TestRequireSignedWithoutTrustedKeysIsRefused(t *testing.T) {
	t.Run("default require_signed, no trusted_keys", func(t *testing.T) {
		// minimalConfig carries trusted_keys precisely because this rule
		// exists; taking it away is what puts the file back in the state
		// every pre-ADR-0010 configuration is in today.
		err := loadErr(t, withoutLine(t, minimalConfig, "trusted_keys"))

		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error does not wrap ErrInvalid: %v", err)
		}
		for _, want := range []string{"require_signed", "trusted_keys"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not name %q, so it does not say which two settings contradict each other:\n%v", want, err)
			}
		}
		if !strings.Contains(err.Error(), "mcp-gateway sign") {
			t.Errorf("error does not tell the operator how to get a key to paste; a control that is annoying to enable stays disabled:\n%v", err)
		}
	})

	t.Run("explicit require_signed = false is allowed with no trusted_keys", func(t *testing.T) {
		contents := withoutLine(t, minimalConfig, "trusted_keys")
		contents += "require_signed = false\n"

		c := mustLoad(t, contents)
		if c.Signer.SignaturesRequired() {
			t.Error("SignaturesRequired() = true after an explicit false")
		}
		if len(c.Signer.TrustedKeys) != 0 {
			t.Errorf("TrustedKeys = %v, want empty", c.Signer.TrustedKeys)
		}
	})
}

// TestTrustedKeysMustDecodeToAnEd25519PublicKey covers the parse half. The
// values are 44 characters that differ from each other in no way a human
// eye picks up, so every message here has to name the offending entry --
// otherwise the operator is left diffing the list by hand.
func TestTrustedKeysMustDecodeToAnEd25519PublicKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"not base64", "this is not base64!!"},
		{"base64 of too few bytes", "YWJj"},
		{"base64 of too many bytes", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg=="},
		{"empty", ""},
		{"a PEM block rather than the raw key", "-----BEGIN PUBLIC KEY-----"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := strings.Replace(minimalConfig,
				`trusted_keys = ["`+testTrustedKey+`"]`,
				`trusted_keys = ["`+testTrustedKey+`", "`+tc.key+`"]`, 1)

			err := loadErr(t, contents)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			// Index 1, not 0: the good key must not be the one blamed.
			if !strings.Contains(err.Error(), "signer.trusted_keys[1]") {
				t.Errorf("error does not name which entry is bad:\n%v", err)
			}
		})
	}
}

func TestTrustedPublicKeysDecodesEveryKey(t *testing.T) {
	c := mustLoad(t, completeConfig)

	keys, err := c.Signer.TrustedPublicKeys()
	if err != nil {
		t.Fatalf("TrustedPublicKeys: %v", err)
	}
	if len(keys) != len(c.Signer.TrustedKeys) {
		t.Fatalf("decoded %d keys, want %d -- a dropped key is a key the gateway silently stops trusting", len(keys), len(c.Signer.TrustedKeys))
	}
	for i, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			t.Errorf("key %d is %d bytes, want %d", i, len(k), ed25519.PublicKeySize)
		}
	}
}

// TestLoadReportsEveryProblemAtOnce is the reason Validate uses
// errors.Join rather than returning on the first problem. An operator who
// fixes configuration one error per restart, on a jail they have to ssh
// into, spends an afternoon on a file they could have fixed in one pass.
func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	contents := minimalConfig
	contents = withoutLine(t, contents, "database =")
	contents = withoutLine(t, contents, "audience =")
	contents = withoutLine(t, contents, "age_key_file")

	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error does not wrap ErrInvalid: %v", err)
	}

	for _, want := range []string{"database", "oidc.audience", "vault.age_key_file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q -- all three missing fields must be reported in one run, not one per restart.\ngot: %v", want, err)
		}
	}
}

func TestLoadRejectsNonAbsoluteIssuer(t *testing.T) {
	contents := strings.Replace(minimalConfig, `"https://id.soc.internal/realms/soc"`, `"id.soc.internal/realms/soc"`, 1)
	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "oidc.issuer") {
		t.Errorf("error does not name oidc.issuer: %v", err)
	}
}

// oidcConfig returns a minimal valid file carrying the given issuer and
// audience, for the cases that need to vary exactly those two. extraOIDC is
// appended inside the [oidc] table, before any later section opens it.
func oidcConfig(issuer, audience string, extraOIDC ...string) string {
	return `
database = "/var/db/mcp-gateway/mcp-gateway.db"

[oidc]
issuer   = "` + issuer + `"
audience = "` + audience + `"
` + strings.Join(extraOIDC, "\n") + `

[vault]
secrets_file = "/usr/local/etc/mcp-gateway/secrets.enc.json"
age_key_file = "/usr/local/etc/mcp-gateway/age.key"

[signer]
trusted_keys = ["` + testTrustedKey + `"]
`
}

// TestOIDCIdentifiersMustBeUsableByTheServingProcess is GAB-30 item 1.
//
// Validate used to accept any non-empty audience and any absolute-URL
// issuer, while the thing that consumes them at boot -- the RFC 9728
// metadata document -- requires an absolute https URI with no query and no
// fragment. So `audience = "mcp-gateway"`, which is a perfectly ordinary
// JWT `aud` value, validated, worked for every operator subcommand, and
// killed serve. The operator fixed what Validate listed, restarted, and got
// a different error out of the same unchanged file.
//
// Loopback http is accepted here because it is accepted there: the rule is
// about bearer tokens crossing a network, and 127.0.0.1 crosses none.
func TestOIDCIdentifiersMustBeUsableByTheServingProcess(t *testing.T) {
	const goodIssuer = "https://id.soc.internal/realms/soc"
	const goodAudience = "https://gw.soc.internal/mcp"

	tests := []struct {
		name     string
		issuer   string
		audience string
		wantErr  string // the field the message must name; "" means it must load
	}{
		{"opaque audience", goodIssuer, "mcp-gateway", "oidc.audience"},
		{"http audience on a routable host", goodIssuer, "http://gw.soc.internal/mcp", "oidc.audience"},
		{"audience with a query string", goodIssuer, "https://gw.soc.internal/mcp?v=1", "oidc.audience"},
		{"audience with a fragment", goodIssuer, "https://gw.soc.internal/mcp#mcp", "oidc.audience"},
		{"http issuer on a routable host", "http://idp.internal:8080", goodAudience, "oidc.issuer"},
		{"issuer with a query string", "https://id.soc.internal/realms/soc?x=1", goodAudience, "oidc.issuer"},
		{"https audience and issuer", goodIssuer, goodAudience, ""},
		{"loopback http, which serve accepts", "http://127.0.0.1:8080", "http://127.0.0.1:8080/mcp", ""},
		{"localhost http, which serve accepts", "http://localhost:8080", "http://localhost:8080/mcp", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contents := oidcConfig(tc.issuer, tc.audience)
			if tc.wantErr == "" {
				mustLoad(t, contents)
				return
			}
			err := loadErr(t, contents)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error does not name %s: %v", tc.wantErr, err)
			}
		})
	}
}

// TestAuthorizationServersAreCheckedToo: the same values, one field over.
// authorization_servers goes into the same metadata document and through
// the same check, and defaults to [issuer] -- so an explicit list was the
// one way to reach that check with a value Validate had never looked at.
func TestAuthorizationServersAreCheckedToo(t *testing.T) {
	contents := oidcConfig("https://id.soc.internal/realms/soc", "https://gw.soc.internal/mcp",
		`authorization_servers = ["https://id.soc.internal/realms/soc", "http://id2.soc.internal"]`)

	err := loadErr(t, contents)
	if !strings.Contains(err.Error(), "oidc.authorization_servers") {
		t.Errorf("error does not name oidc.authorization_servers: %v", err)
	}
	if !strings.Contains(err.Error(), "id2.soc.internal") {
		t.Errorf("error does not name the offending entry: %v", err)
	}
}

// -----------------------------------------------------------------------
// Roles and the group mapping
// -----------------------------------------------------------------------

// TestUndefinedRoleInMappingRejectedAtLoad: a group mapped to a role that
// does not exist -- a renamed [[role]] with a forgotten mapping, most
// likely -- must stop the process at startup. The alternative is that it
// silently denies a real analyst their tools, and the moment they notice
// is the moment they need the tools.
func TestUndefinedRoleInMappingRejectedAtLoad(t *testing.T) {
	contents := strings.Replace(completeConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-leed"`, 1)
	err := loadErr(t, contents)

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "dfir-leed") {
		t.Errorf("error does not name the undefined role: %v", err)
	}
	if !strings.Contains(err.Error(), "soc-dfir") {
		t.Errorf("error does not name the group that points at it: %v", err)
	}
}

func TestDuplicateRoleRejected(t *testing.T) {
	contents := completeConfig + `
[[role]]
name  = "n1-triage"
tools = ["docsearch.search"]
`
	err := loadErr(t, contents)

	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "n1-triage") {
		t.Errorf("error does not name the duplicated role: %v", err)
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("error does not say the role is duplicated: %v", err)
	}
}

// TestRoleWithNoToolsIsAccepted: a role that grants nothing is a
// legitimate thing to define -- someone who may authenticate but may not
// act, which is how you confirm the identity path works before granting
// any tool. It must not be mistaken for an incomplete role.
func TestRoleWithNoToolsIsAccepted(t *testing.T) {
	contents := completeConfig + `
[[role]]
name  = "onboarding"
tools = []
`
	contents = strings.Replace(contents, "[group_to_role]", "[group_to_role]\n\"soc-onboarding\" = \"onboarding\"", 1)

	c := mustLoad(t, contents)

	var found bool
	for _, r := range c.Roles {
		if r.Name == "onboarding" {
			found = true
			if len(r.Tools) != 0 {
				t.Errorf("onboarding role has tools %v, want none", r.Tools)
			}
		}
	}
	if !found {
		t.Fatal("the empty role was dropped during load")
	}

	// And it must be fail-closed once it reaches the domain: a member of
	// that group may call nothing at all.
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}
	id := access.Identity{Subject: "u-new", Groups: []string{"soc-onboarding"}}
	if tools := policy.AllowedTools(id); len(tools) != 0 {
		t.Errorf("AllowedTools = %v, want none", tools)
	}
	if err := policy.Authorize(id, "casemgmt.list_cases"); !errors.Is(err, access.ErrForbidden) {
		t.Errorf("Authorize = %v, want ErrForbidden", err)
	}
}

func TestRoleWithEmptyToolNameRejected(t *testing.T) {
	contents := strings.Replace(completeConfig, `"threatintel.lookup_ip"`, `""`, 1)
	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "empty tool name") {
		t.Errorf("error does not describe the empty tool name: %v", err)
	}
}

// TestRoleNameWithWhitespaceRejectedAtLoad is GAB-30 item 2. Validate
// rejected a name that was empty *after* trimming; access.NewPolicy rejects
// any name not *already* trimmed. "analyst " sat in the gap: it loaded
// cleanly, survived every operator subcommand, and failed at
// ToAccessPolicy -- which only serve calls.
func TestRoleNameWithWhitespaceRejectedAtLoad(t *testing.T) {
	for _, name := range []string{"analyst ", " analyst", "analyst\t"} {
		t.Run(name, func(t *testing.T) {
			contents := minimalConfig + "\n[[role]]\nname  = \"" + name + "\"\ntools = [\"casemgmt.list_cases\"]\n"
			err := loadErr(t, contents)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), "whitespace") {
				t.Errorf("error does not say the name carries whitespace: %v", err)
			}
		})
	}
}

// TestRoleToolsMustBeNamespaced is GAB-30 item 3, and it is the quiet one:
// nothing crashes. The policy matches the namespaced names the gateway
// advertises ("casemgmt.list_cases") and there is no wildcard, so a role
// granting "list_cases" grants exactly nothing -- and the first person to
// find out is an analyst denied mid-incident, with neither the config nor
// the startup log saying why.
func TestRoleToolsMustBeNamespaced(t *testing.T) {
	for _, tool := range []string{"list_cases", ".list_cases", "casemgmt.", "*"} {
		t.Run(tool, func(t *testing.T) {
			contents := minimalConfig + "\n[[role]]\nname  = \"analyst\"\ntools = [\"" + tool + "\"]\n"
			err := loadErr(t, contents)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tool) {
				t.Errorf("error does not name the offending tool: %v", err)
			}
			if !strings.Contains(err.Error(), "namespaced") {
				t.Errorf("error does not say the name must be namespaced: %v", err)
			}
		})
	}
}

// TestDuplicateToolWithinARoleRejected: harmless to the policy, which
// deduplicates, and therefore exactly the kind of thing that stays in a
// file for a year. It is nearly always one of two edits gone wrong -- a
// paste, or a rename that only half happened -- and the reviewer who
// notices is the one reading this error.
func TestDuplicateToolWithinARoleRejected(t *testing.T) {
	contents := minimalConfig + "\n[[role]]\nname  = \"analyst\"\ntools = [\"casemgmt.list_cases\", \"casemgmt.get_case\", \"casemgmt.list_cases\"]\n"
	err := loadErr(t, contents)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error does not wrap ErrInvalid: %v", err)
	}
	if !strings.Contains(err.Error(), "casemgmt.list_cases") {
		t.Errorf("error does not name the duplicated tool: %v", err)
	}
}

// TestValidateAcceptsNothingToAccessPolicyRefuses is the whole of GAB-30 in
// one assertion, and it is the one that should outlive the three specific
// cases above.
//
// Validate's promise is that every problem in the file is reported in front
// of the operator who just edited it. A file that loads and then fails at
// ToAccessPolicy breaks that promise structurally, whatever the particular
// rule was -- and because no operator subcommand builds a policy, it breaks
// it invisibly until somebody restarts the serving process.
//
// Each body is either refused by Load (fine -- the operator was told) or
// must produce a policy. There is no third answer.
func TestValidateAcceptsNothingToAccessPolicyRefuses(t *testing.T) {
	bodies := map[string]string{
		"trailing space in the role name":                              "\n[[role]]\nname  = \"analyst \"\ntools = [\"casemgmt.list_cases\"]\n",
		"leading space in the role name":                               "\n[[role]]\nname  = \" analyst\"\ntools = [\"casemgmt.list_cases\"]\n",
		"tab in the role name":                                         "\n[[role]]\nname  = \"analyst\t\"\ntools = [\"casemgmt.list_cases\"]\n",
		"role name that is only space":                                 "\n[[role]]\nname  = \"   \"\ntools = [\"casemgmt.list_cases\"]\n",
		"empty tool name":                                              "\n[[role]]\nname  = \"analyst\"\ntools = [\"\"]\n",
		"blank tool name":                                              "\n[[role]]\nname  = \"analyst\"\ntools = [\"   \"]\n",
		"duplicate role":                                               "\n[[role]]\nname  = \"analyst\"\ntools = []\n\n[[role]]\nname  = \"analyst\"\ntools = []\n",
		"group mapped to an unknown role":                              "\n[[role]]\nname  = \"analyst\"\ntools = []\n\n[group_to_role]\n\"soc-n1\" = \"analist\"\n",
		"empty group name in the mapping":                              "\n[[role]]\nname  = \"analyst\"\ntools = []\n\n[group_to_role]\n\"\" = \"analyst\"\n",
		"role granting nothing, which is a legitimate thing to define": "\n[[role]]\nname  = \"onboarding\"\ntools = []\n",
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			c, err := Load(writeConfig(t, minimalConfig+body))
			if err != nil {
				return // Refused up front, in front of the operator. Correct.
			}
			if _, err := c.ToAccessPolicy(); err != nil {
				t.Errorf("Validate accepted a file the access policy refuses, so serve dies on a\n"+
					"restart with an error the operator never saw while editing: %v", err)
			}
		})
	}
}

// -----------------------------------------------------------------------
// ToAccessPolicy
// -----------------------------------------------------------------------

func TestToAccessPolicyMatchesTheFile(t *testing.T) {
	c := mustLoad(t, completeConfig)
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	for _, tc := range []struct {
		name   string
		groups []string
		want   []string
	}{
		{
			name:   "n1 gets exactly the n1-triage list",
			groups: []string{"soc-n1"},
			want:   []string{"casemgmt.get_case", "casemgmt.list_cases", "threatintel.lookup_ip"},
		},
		{
			name:   "dfir gets exactly the dfir-lead list",
			groups: []string{"soc-dfir"},
			want:   []string{"casemgmt.list_cases", "docsearch.search", "threatintel.virustotal"},
		},
		{
			// Overlapping tools across two roles are unioned, not doubled.
			name:   "both groups union and deduplicate",
			groups: []string{"soc-n1", "soc-dfir"},
			want: []string{
				"casemgmt.get_case", "casemgmt.list_cases", "docsearch.search",
				"threatintel.lookup_ip", "threatintel.virustotal",
			},
		},
		{
			// An IdP carries groups that have nothing to do with this
			// gateway; an unmapped one is ignored, and a caller with only
			// unmapped groups gets nothing.
			name:   "an unmapped group grants nothing",
			groups: []string{"everyone", "vpn-users"},
			want:   nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.AllowedTools(access.Identity{Subject: "u-1", Groups: tc.groups})
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AllowedTools = %v, want %v", got, tc.want)
			}
		})
	}

	// No wildcard: a near-miss on a tool the role does have is still a no.
	id := access.Identity{Subject: "u-1", Groups: []string{"soc-n1"}}
	for _, tool := range []string{"*", "casemgmt.*", "casemgmt.", "casemgmt.list_cases_extra", "docsearch.search"} {
		if err := policy.Authorize(id, tool); !errors.Is(err, access.ErrForbidden) {
			t.Errorf("Authorize(%q) = %v, want ErrForbidden -- tool names match exactly, there is no wildcard", tool, err)
		}
	}
}

// TestToAccessPolicyPropagatesNewPolicyErrors: ToAccessPolicy must not
// swallow a domain error it cannot itself diagnose.
//
// This test used to reach access.NewPolicy through a config Validate
// accepted -- a role name with a trailing space, which Validate let past
// and NewPolicy refused. That gap was GAB-30 item 2 and it is closed:
// Validate now applies access.ValidateRole, so there is no longer a file
// that loads and then fails here, which is the entire point of the fix.
//
// So the config is built directly and Validate is deliberately NOT called.
// That is not a weaker test, it is the honest one: load.go's contract is
// that Validate and NewPolicy each protect their own side and neither may
// assume the other ran, and this exercises exactly that -- a caller who
// skipped validation still gets the domain's refusal, not a nil error.
func TestToAccessPolicyPropagatesNewPolicyErrors(t *testing.T) {
	c := &Config{
		Database: "/var/db/mcp-gateway/mcp-gateway.db",
		OIDC: OIDC{
			Issuer:   "https://id.soc.internal/realms/soc",
			Audience: "https://gw.soc.internal/mcp",
		},
		Vault: Vault{
			SecretsFile: "/usr/local/etc/mcp-gateway/secrets.enc.json",
			AgeKeyFile:  "/usr/local/etc/mcp-gateway/age.key",
		},
		Signer: Signer{TrustedKeys: []string{testTrustedKey}},
		Roles:  []Role{{Name: "n1-triage ", Tools: []string{"casemgmt.list_cases"}}},
	}

	policy, err := c.ToAccessPolicy()
	if err == nil {
		t.Fatalf("ToAccessPolicy accepted a policy access.NewPolicy refuses: %+v", policy)
	}
	if !errors.Is(err, access.ErrInvalidPolicy) {
		t.Errorf("error does not wrap access.ErrInvalidPolicy: %v", err)
	}
	if policy != nil {
		t.Error("ToAccessPolicy returned both an error and a policy")
	}
}

// TestToAccessPolicyDoesNotShareSlices: the parsed config must not stay
// coupled to the live policy. access.Policy clones on both boundaries, and
// this asserts the config side does not undo that by handing over an
// aliased slice.
func TestToAccessPolicyDoesNotShareSlices(t *testing.T) {
	c := mustLoad(t, completeConfig)
	policy, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatalf("ToAccessPolicy: %v", err)
	}

	id := access.Identity{Subject: "u-1", Groups: []string{"soc-n1"}}
	before := policy.AllowedTools(id)

	// Rewrite the config's own slice after the policy was built.
	c.Roles[0].Tools[0] = "casemgmt.delete_everything"

	after := policy.AllowedTools(id)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("mutating the parsed config changed what the live policy authorizes: %v -> %v", before, after)
	}
}

// -----------------------------------------------------------------------
// File and syntax errors
// -----------------------------------------------------------------------

func TestLoadMissingFileNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.toml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load succeeded on a file that does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file it tried to read: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error does not wrap os.ErrNotExist, so a caller cannot distinguish 'no file' from 'bad file': %v", err)
	}
}

// TestLoadMalformedTOMLReportsTheLine: BurntSushi's ParseError renders as
// "toml: line N: ...", and that line number is the single most useful part
// of the message for whoever has to fix the file. Wrapping must not lose
// it.
func TestLoadMalformedTOMLReportsTheLine(t *testing.T) {
	const broken = `listen   = "127.0.0.1:8080"
database = "/var/db/mcp-gateway/mcp-gateway.db"
this line is not valid toml
`
	path := writeConfig(t, broken)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted malformed TOML")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error does not carry the line number from the parser: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error does not name the file: %v", err)
	}
}

// -----------------------------------------------------------------------
// The shipped example
// -----------------------------------------------------------------------

// exampleConfigPath is config.example.toml at the repository root, two
// levels up from internal/config.
func exampleConfigPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatalf("resolving the example config path: %v", err)
	}
	return path
}

// TestExampleConfigLoads keeps the shipped example honest against the
// parser that actually reads it.
//
// This is not ceremony. The example is the first thing an operator copies,
// and an example that has drifted -- a key renamed in Config, a section
// the loader now rejects -- is worse than no example: it teaches a file
// format that does not exist, and the person following it concludes the
// binary is broken. Because Load rejects unknown keys, this test also
// catches the reverse drift, where the example documents a setting nobody
// implemented.
func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("config.example.toml does not load -- the shipped example has drifted from the parser: %v", err)
	}

	// It must also be a *useful* example, not a file that merely parses.
	if len(c.Roles) < 2 {
		t.Errorf("the example defines %d role(s); it should show at least the n1-triage/dfir-lead split this gateway exists for", len(c.Roles))
	}
	if len(c.GroupToRole) == 0 {
		t.Error("the example maps no IdP group to a role, so it does not show how authorization is actually wired")
	}

	// Every mapped role resolves, and the whole thing survives the domain
	// type's own construction checks.
	if _, err := c.ToAccessPolicy(); err != nil {
		t.Errorf("the example's roles do not build an access.Policy: %v", err)
	}

	// ADR-0006's trigger fired on 09 Sep 2026: the Operator Console can
	// now sign at volume (`mcp-gateway sign NAME`), so the debt came due
	// and the default flipped. This assertion flipped with it -- the
	// earlier version of this test said, in as many words, that whoever
	// met the trigger must update the ADR, the default and this test
	// together, and that is what happened.
	//
	// It is asserted explicitly rather than left to the default so the
	// example *shows* an operator the setting exists and is on, rather
	// than relying on them knowing an omitted line means enforcement.
	if !c.Signer.SignaturesRequired() {
		t.Error("config.example.toml no longer requires signatures; ADR-0006's trigger has been met, so the shipped example must enforce")
	}
	if c.Signer.RequireSigned == nil {
		t.Error("config.example.toml should state require_signed explicitly rather than relying on the default -- the example is documentation")
	}

	// Same argument for the re-observation interval, and one more besides:
	// this is the setting with no off switch (ADR-0013), so the example is
	// where an operator learns that raising it is the only way to decline
	// the cost. A line that is not there teaches nothing.
	if c.Quarantine.RefreshInterval == nil {
		t.Error("config.example.toml does not state quarantine.refresh_interval -- the example is where an operator finds out that re-observation exists and that the way to make it cheaper is to raise the interval, not to switch it off")
	}
	if got := c.Quarantine.RefreshEvery(); got <= 0 {
		t.Errorf("the example's refresh interval is %v; it must be positive or the ticker cannot run", got)
	}

	// And the same argument again for the result ceiling (ADR-0014): it is
	// the one control in that ADR that runs on every call today, it also
	// has no off switch, and an operator who never sees the line has no
	// idea a refused oversized result is the gateway working as designed
	// rather than a backend failing.
	if c.Response.MaxBytes == nil {
		t.Error("config.example.toml does not state response.max_bytes -- the example is where an operator finds out that a result ceiling exists at all, and that a refusal is not a truncation")
	}
	if got := c.Response.MaxResultBytes(); got <= 0 {
		t.Errorf("the example's result ceiling is %d; it must be positive", got)
	}
}

// stripTOMLComments returns src with every `#` comment removed, leaving
// only the settings themselves. Quoted strings are respected so a `#`
// inside a value is not mistaken for a comment.
//
// It exists so the secret scan below reads values, not prose: the example
// deliberately *discusses* client secrets and private keys in its
// comments, and that discussion is the documentation, not a finding.
func stripTOMLComments(src string) string {
	var out strings.Builder
	for _, line := range strings.Split(src, "\n") {
		inQuote := false
		cut := -1
		for i, r := range line {
			switch {
			case r == '"':
				inQuote = !inQuote
			case r == '#' && !inQuote:
				cut = i
			}
			if cut >= 0 {
				break
			}
		}
		if cut >= 0 {
			line = line[:cut]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// TestExampleConfigCarriesNoSecretValues enforces ADR-0009 §3 on the file
// an operator is most likely to copy: its *values* are paths and
// identifiers, and nothing that looks like a key, a password or a token.
// This is the automated half of that ADR's Compliance section.
//
// It is a heuristic on purpose. It cannot prove the absence of a secret,
// but it does catch the realistic accident -- someone pasting a working
// value into the example while debugging and committing it.
func TestExampleConfigCarriesNoSecretValues(t *testing.T) {
	raw, err := os.ReadFile(exampleConfigPath(t))
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	settings := strings.ToLower(stripTOMLComments(string(raw)))

	for _, marker := range []string{
		"-----begin",      // any PEM block: a private key pasted in whole
		"age-secret-key-", // an age identity
		"age1",            // an age recipient or identity string
		"eyj",             // the base64 header of a JWT
		"client_secret",   // a resource server has no use for one
		"password",
		"passwd",
		"api_key",
		"apikey",
		"token =",
	} {
		if strings.Contains(settings, marker) {
			t.Errorf("config.example.toml has a setting containing %q -- this file holds paths and identifiers only; a secret value belongs in the sops-encrypted file (ADR-0009 §3)", marker)
		}
	}

	// Guard the guard: if the strip ever stops finding the settings, the
	// scan above would pass on an empty string.
	if !strings.Contains(settings, "age_key_file") {
		t.Fatal("stripTOMLComments removed the settings themselves; the scan above proves nothing")
	}
}

// -----------------------------------------------------------------------
// quarantine.refresh_interval (ADR-0013)
// -----------------------------------------------------------------------

func TestRefreshIntervalDefaultsWhenUnset(t *testing.T) {
	c := mustLoad(t, minimalConfig)

	if c.Quarantine.RefreshInterval != nil {
		t.Errorf("RefreshInterval = %v, want nil when the file is silent, so 'unset' stays distinguishable from a written value",
			c.Quarantine.RefreshInterval)
	}
	if got := c.Quarantine.RefreshEvery(); got != DefaultRefreshInterval {
		t.Errorf("RefreshEvery() = %v, want the default %v", got, DefaultRefreshInterval)
	}
}

func TestRefreshIntervalIsRead(t *testing.T) {
	c := mustLoad(t, minimalConfig+"\n[quarantine]\nrefresh_interval = \"30m\"\n")

	if got, want := c.Quarantine.RefreshEvery(), 30*time.Minute; got != want {
		t.Errorf("RefreshEvery() = %v, want %v", got, want)
	}
}

// TestRefreshIntervalCannotDisableReobservation is the config half of
// ADR-0013's rule that there is no off switch. Raising the interval is how
// an operator declines to pay the cost, and that stays visible in the file
// as a number; a zero would be a security control switched off "for a
// minute" and left off, with nothing in the file admitting it.
func TestRefreshIntervalCannotDisableReobservation(t *testing.T) {
	for _, value := range []string{`"0s"`, `"-5m"`, "0"} {
		t.Run(value, func(t *testing.T) {
			err := loadErr(t, minimalConfig+"\n[quarantine]\nrefresh_interval = "+value+"\n")
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load = %v, want ErrInvalid", err)
			}
			for _, want := range []string{"must be positive", "raise the interval"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// TestRefreshIntervalRejectsTheBareIntegerTrap covers the one mistake the
// minimum exists for: TOML reads a bare number into a time.Duration as
// nanoseconds, so `refresh_interval = 300` is 300ns -- which would hammer
// every backend in a hot loop, silently, while reading in the file as five
// minutes.
func TestRefreshIntervalRejectsTheBareIntegerTrap(t *testing.T) {
	err := loadErr(t, minimalConfig+"\n[quarantine]\nrefresh_interval = 300\n")

	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	for _, want := range []string{"NANOSECONDS", `"5m"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// -----------------------------------------------------------------------
// response.max_bytes (ADR-0014)
// -----------------------------------------------------------------------

func TestMaxResultBytesDefaultsWhenUnset(t *testing.T) {
	c := mustLoad(t, minimalConfig)

	if c.Response.MaxBytes != nil {
		t.Errorf("Response.MaxBytes = %v, want nil when the file is silent, so 'unset' stays distinguishable from a written value",
			c.Response.MaxBytes)
	}
	if got := c.Response.MaxResultBytes(); got != gateway.DefaultMaxResultBytes {
		t.Errorf("MaxResultBytes() = %d, want the default %d", got, gateway.DefaultMaxResultBytes)
	}
}

func TestMaxResultBytesIsRead(t *testing.T) {
	c := mustLoad(t, minimalConfig+"\n[response]\nmax_bytes = 4194304\n")

	if got, want := c.Response.MaxResultBytes(), int64(4*1024*1024); got != want {
		t.Errorf("MaxResultBytes() = %d, want %d", got, want)
	}
}

// TestMaxResultBytesCannotDisableTheLimit is the config half of ADR-0014's
// rule that the ceiling always applies. It is the same argument
// quarantine.refresh_interval makes: the way to decline the cost is to
// raise the number, which stays in the file as something a reviewer can
// argue with, rather than a zero that reads as "off" to the parser and as
// nothing at all to the next person.
//
// The limit is also the only control in that ADR with an effect on today's
// fleet -- no backend declares an output schema -- so an off switch here
// would switch off the whole of it.
func TestMaxResultBytesCannotDisableTheLimit(t *testing.T) {
	for _, value := range []string{"0", "-1", "-1048576"} {
		t.Run(value, func(t *testing.T) {
			err := loadErr(t, minimalConfig+"\n[response]\nmax_bytes = "+value+"\n")
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load = %v, want ErrInvalid", err)
			}
			for _, want := range []string{"must be positive", "raise the limit"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// TestMaxResultBytesRejectsAValueTooSmallToBeMeant covers the mistake this
// minimum exists for: the field is in BYTES, and somebody thinking in
// megabytes writes 1 or 8. A ceiling of one byte refuses every result the
// fleet can produce -- fail-closed, but as a total outage of every tool,
// discovered by an analyst rather than at startup.
func TestMaxResultBytesRejectsAValueTooSmallToBeMeant(t *testing.T) {
	err := loadErr(t, minimalConfig+"\n[response]\nmax_bytes = 8\n")

	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	for _, want := range []string{"BYTES", "MinResultBytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// -----------------------------------------------------------------------
// listen (ADR-0011), moved here from cmd/mcp-gateway
// -----------------------------------------------------------------------

// TestValidateRefusesANonLoopbackListen is the fourth instance of the
// GAB-30 shape, fixed the same way as the other three: a file that
// Validate accepted and that then killed `serve` three lines into
// startup, because the rule lived only in the consumer.
//
// The acceptable-listen-address rule is part of the configuration
// contract, so it lives in this package now and Validate applies it. What
// loads is what serves -- and every operator subcommand refuses the same
// file the serving process would, rather than working fine and leaving the
// discovery for the next restart.
func TestValidateRefusesANonLoopbackListen(t *testing.T) {
	err := loadErr(t, strings.Replace(minimalConfig,
		`database =`, "listen = \"0.0.0.0:9443\"\ndatabase =", 1))

	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load = %v, want ErrInvalid", err)
	}
	// The refusal's quality is the control, not merely its existence: it
	// has to say why binding wide is not "slightly weaker" here, and what
	// to do instead.
	for _, want := range []string{"0.0.0.0:9443", "loopback", "cleartext", "reverse proxy", "0011"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestValidateAcceptsTheLoopbackDefault: the defaulted address must pass
// the predicate Validate now applies, or an empty `listen` would be a
// startup failure.
func TestValidateAcceptsTheLoopbackDefault(t *testing.T) {
	c := mustLoad(t, minimalConfig)

	if c.Listen != DefaultListen {
		t.Fatalf("Listen = %q, want the default %q", c.Listen, DefaultListen)
	}
	if err := RequireLoopbackBind(c.Listen); err != nil {
		t.Errorf("the default listen address does not satisfy the rule Validate applies: %v", err)
	}
}

// TestIsLoopbackAddr moved here with the predicate it covers. Its cases
// are unchanged from the ones it had in cmd/mcp-gateway, deliberately:
// this is the same rule in a new home, not a new rule.
func TestIsLoopbackAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.9.9.9:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"LocalHost:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{"10.0.0.5:8080", false},
		{"gw.soc.internal:8080", false},
		// Unparseable is reported as exposed on purpose: a spurious
		// warning costs one line, a missed one costs an exposure.
		{"garbage", false},
		{"", false},
	} {
		if got := IsLoopbackAddr(tc.addr); got != tc.want {
			t.Errorf("IsLoopbackAddr(%q) = %t, want %t", tc.addr, got, tc.want)
		}
	}
}

// TestRequireLoopbackBind pins ADR-0011 item 1: the gateway refuses to
// start on any address that is not loopback, rather than warning and
// carrying on.
//
// The refusal is the whole control. Under ADR-0011 the gateway terminates
// no TLS and holds no certificate, so a non-loopback bind is not "less
// protected" -- it is every analyst's bearer token in cleartext, plus the
// case data and IOCs behind it. A warning delegates that to whoever is in
// a hurry; a refusal does not.
//
// Written against the pre-ADR-0011 code first, where every case below
// passed, so that the test is evidence and not decoration. Moved here from
// cmd/mcp-gateway when the rule moved.
func TestRequireLoopbackBind(t *testing.T) {
	refused := []string{
		"0.0.0.0:8080",     // the one an operator reaches for
		"10.17.89.10:8080", // a jail's own address
		"[::]:8080",        // the IPv6 equivalent of 0.0.0.0
		"192.168.1.5:8080",
	}
	for _, addr := range refused {
		t.Run("refuses "+addr, func(t *testing.T) {
			if err := RequireLoopbackBind(addr); err == nil {
				t.Errorf("RequireLoopbackBind(%q) = nil, want refusal", addr)
			}
		})
	}

	allowed := []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"}
	for _, addr := range allowed {
		t.Run("allows "+addr, func(t *testing.T) {
			if err := RequireLoopbackBind(addr); err != nil {
				t.Errorf("RequireLoopbackBind(%q) = %v, want nil", addr, err)
			}
		})
	}

	// An address that cannot be parsed is refused too. "Cannot tell" is not
	// "loopback" -- the same fail-closed reading ADR-0004 applies to an
	// unreadable registry.
	for _, addr := range []string{"", "8080", "not an address"} {
		t.Run("refuses unparseable "+addr, func(t *testing.T) {
			if err := RequireLoopbackBind(addr); err == nil {
				t.Errorf("RequireLoopbackBind(%q) = nil, want refusal", addr)
			}
		})
	}
}
