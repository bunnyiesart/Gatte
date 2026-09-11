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
	if err := rejectCollapsedMapKeys(path, md, &c); err != nil {
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

// rejectCollapsedMapKeys refuses a file that wrote the same backend twice
// inside one role's `[role.grants]`.
//
// # Why this is not the TOML parser's job here
//
// TOML forbids a duplicate key, and BurntSushi enforces that -- at the top
// level. `name = "a"` twice is a parse error naming the line, and so is a
// group repeated in `[group_to_role]`. Inside a NESTED table it is not:
// verified directly against v1.5.0 rather than assumed, `[role.grants]`
// (and any other sub-table, array-of-tables or otherwise) accepts the
// duplicate and keeps the LAST value, silently. Nesting depth is the
// discriminator, not the destination type.
//
// That leaves `[role.grants]` as the one table in this file where a
// duplicate key survives the parser, which is why it is the only one
// checked here. TestDuplicateGroupMappingIsRefusedByTheDecoder pins the
// sibling half, so that a change in the decoder's behaviour shows up as a
// failing test naming this function rather than as a config that quietly
// stops being checked.
//
// That is the defect class this project exists to close. Written out:
//
//	[role.grants]
//	casemgmt = ["get_case"]
//	casemgmt = ["*"]
//
// loads, and grants every tool of casemgmt. The file reads as though the
// role were held to one tool. Nothing warns. The reverse ordering
// under-grants instead, which is merely an outage, but the ordering above
// is a control the file claims and does not enforce -- so the duplicate is
// refused outright rather than resolved by a rule an operator would have
// to know.
//
// # How a duplicate is detected after the fact
//
// The value is already gone by the time Validate sees the map, so this
// works from [toml.MetaData] instead: Keys reports every key as it was
// WRITTEN, duplicates included. Counting is used rather than ordering,
// because Keys flattens `[[role]]` elements -- two roles each granting
// "casemgmt" legitimately produce `role.grants.casemgmt` twice. So for
// each key path, the number of times it was written is compared against
// the number of places it SURVIVED in the decoded config; more written
// than survived means at least one was overwritten. Ordering within Keys
// is never relied on.
//
// The cost of that robustness is precision: the error names the key that
// was lost, and for a grant it cannot say which `[[role]]` swallowed it.
// It says so rather than guessing.
func rejectCollapsedMapKeys(path string, md toml.MetaData, c *Config) error {
	written := map[string]int{}
	for _, key := range md.Keys() {
		if len(key) == 3 && key[0] == "role" && key[1] == "grants" {
			written["role.grants."+key[2]]++
		}
	}

	survived := map[string]int{}
	for _, r := range c.Roles {
		for backend := range r.Grants {
			survived["role.grants."+backend]++
		}
	}

	var lost []string
	for path, n := range written {
		if n > survived[path] {
			lost = append(lost, path)
		}
	}
	if len(lost) == 0 {
		return nil
	}
	slices.Sort(lost)

	noun := "key"
	if len(lost) > 1 {
		noun = "keys"
	}
	return fmt.Errorf(
		"%w: %s: %s written more than once: %s -- TOML's duplicate-key error does not apply inside these tables, "+
			"so the decoder kept only the LAST value and dropped the others without a word. That is refused rather than "+
			"resolved: a `[role.grants]` entry repeated with a wider value (say a named list, then \"*\") reads as a limit "+
			"and would enforce none. Write each key once, with the whole list you mean. "+
			"(Two DIFFERENT [[role]] blocks granting the same backend are fine and are not this error.)",
		ErrInvalid, path, noun, strings.Join(lost, ", "),
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
		// Clone Tools and Grants so the policy never shares a backing
		// array -- or a map -- with the parsed config. access.NewPolicy
		// clones as well; doing it here too costs nothing and means this
		// function is safe even if that guarantee ever changes.
		//
		// Grants needs both levels copied: a shallow map copy would still
		// share every value slice, so `c.Roles[0].Grants["casemgmt"][0] =
		// "delete_case"` would rewrite the live policy.
		var grants map[string][]string
		if r.Grants != nil {
			grants = make(map[string][]string, len(r.Grants))
			for backend, ids := range r.Grants {
				grants[backend] = slices.Clone(ids)
			}
		}
		roles = append(roles, access.Role{Name: r.Name, Tools: slices.Clone(r.Tools), Grants: grants})
	}

	policy, err := access.NewPolicy(roles, c.GroupToRole)
	if err != nil {
		return nil, fmt.Errorf("config: building access policy: %w", err)
	}
	return policy, nil
}
