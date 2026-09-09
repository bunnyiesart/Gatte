package config

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// Load reads, parses and validates the TOML configuration file at path,
// applying the documented defaults (see [Config.Validate]).
//
// Every error it returns names path, because the process that calls this
// is usually a service manager whose only surface is a log line: "config:
// invalid" without a filename is a message an operator cannot act on when
// the deployment has a shipped example, a staging file and a live one.
//
// A TOML syntax error is wrapped, not reformatted. BurntSushi's
// [toml.ParseError] already renders as "toml: line N: ...", and that line
// number is the single most useful thing in the message -- preserving it
// is worth more than a tidier prefix.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	if err := rejectUnknownKeys(path, md); err != nil {
		return nil, err
	}

	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

// rejectUnknownKeys turns any key present in the file but absent from
// [Config] into an error naming that key.
//
// This is a security control, not tidiness. TOML decoding ignores a key it
// does not recognise, so `require_signd = true` -- one missing letter --
// parses, validates, starts, and serves with signature enforcement off,
// while the file on disk reads as though it were on. The whole class of
// "a security setting quietly failed to apply" is closed by refusing to
// start on a key nobody claimed. The cost is that adding a field to the
// file requires adding it to [Config] first, which is the intended
// direction anyway.
func rejectUnknownKeys(path string, md toml.MetaData) error {
	undecoded := md.Undecoded()
	if len(undecoded) == 0 {
		return nil
	}

	names := make([]string, 0, len(undecoded))
	for _, key := range undecoded {
		names = append(names, key.String())
	}
	slices.Sort(names)

	noun := "unknown key"
	if len(names) > 1 {
		noun = "unknown keys"
	}
	return fmt.Errorf(
		"%w: %s: %s %s -- check the spelling against config.example.toml; "+
			"an unrecognised key is refused rather than ignored, because a "+
			"misspelled security setting that is silently dropped reads as "+
			"though it were applied",
		ErrInvalid, path, noun, strings.Join(names, ", "),
	)
}

// ToAccessPolicy converts the configured roles and group mapping into an
// [access.Policy].
//
// The conversion lives here, rather than in the composition root, so that
// cmd/mcp-gateway stays a wiring file: config owns the file format and the
// domain type it maps onto, and nothing in between needs a third opinion.
//
// [access.NewPolicy] repeats some of what [Config.Validate] already
// checked -- duplicate roles, undefined role in a mapping. That
// duplication is deliberate and is not removed: Validate protects the
// operator by reporting every problem in the file at once, while NewPolicy
// protects the domain type from any caller, config or otherwise. Neither
// may assume the other ran.
func (c *Config) ToAccessPolicy() (*access.Policy, error) {
	roles := make([]access.Role, 0, len(c.Roles))
	for _, r := range c.Roles {
		// Clone Tools so the policy never shares a backing array with the
		// parsed config. access.NewPolicy clones as well; doing it here too
		// costs nothing and means this function is safe even if that
		// guarantee ever changes.
		roles = append(roles, access.Role{Name: r.Name, Tools: slices.Clone(r.Tools)})
	}

	policy, err := access.NewPolicy(roles, c.GroupToRole)
	if err != nil {
		return nil, fmt.Errorf("config: building access policy: %w", err)
	}
	return policy, nil
}
