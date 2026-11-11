package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// Tests of [[preset]] (design/adr/0062): templates kept beside the roles,
// held to the shape of a role's `tools`, and never part of the policy.

const presetsText = rolesText + `
[[preset]]
name  = "Blue team analyst"
tools = ["casemgmt.list_cases", "casemgmt.get_case"]
`

func TestPresets_LoadFromTheRolesFileAndGrantNothing(t *testing.T) {
	c, err := Load(writeRolesPair(t, minimalConfig, presetsText))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Presets) != 1 || c.Presets[0].Name != "Blue team analyst" || len(c.Presets[0].Tools) != 2 {
		t.Fatalf("presets %+v", c.Presets)
	}
	if len(c.Roles) != 1 {
		t.Fatalf("a preset became a role: %+v", c.Roles)
	}
}

func TestPresets_InTheMainFileWithRolesFileAreRefused(t *testing.T) {
	extra := "\n[[preset]]\nname = \"p\"\ntools = [\"casemgmt.get_case\"]\n"
	_, err := Load(writeRolesPair(t, minimalConfig+extra, rolesText))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "[[preset]]") {
		t.Fatalf("err = %v, want a refusal naming [[preset]]", err)
	}
}

func TestPresets_MalformedAreRefused(t *testing.T) {
	for name, tc := range map[string]struct{ preset, want string }{
		"empty name":      {`name = ""` + "\ntools = [\"a.b\"]", "name is empty"},
		"edge whitespace": {`name = "p "` + "\ntools = [\"a.b\"]", "leading or trailing whitespace"},
		"no tools":        {`name = "p"` + "\ntools = []", "tools is empty"},
		"not namespaced":  {`name = "p"` + "\ntools = [\"list_cases\"]", "not a namespaced name"},
		"wildcard":        {`name = "p"` + "\ntools = [\"casemgmt.*\"]", "no wildcard"},
		"repeated tool":   {`name = "p"` + "\ntools = [\"a.b\", \"a.b\"]", "listed more than once"},
		"dotted tool id":  {`name = "p"` + "\ntools = [\"casemgmt.search.v2\"]", "the role it would create is refused"},
		"star backend":    {`name = "p"` + "\ntools = [\"*.get_case\"]", "the role it would create is refused"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeRolesPair(t, minimalConfig, rolesText+"\n[[preset]]\n"+tc.preset+"\n"))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	twice := rolesText + "\n[[preset]]\nname = \"p\"\ntools = [\"a.b\"]\n\n[[preset]]\nname = \"p\"\ntools = [\"a.c\"]\n"
	if _, err := Load(writeRolesPair(t, minimalConfig, twice)); err == nil || !strings.Contains(err.Error(), "defined more than once") {
		t.Fatalf("err = %v, want a repeated preset name refused", err)
	}
}

// The role a front writes from a preset is a text the load accepts, with
// the preset's tools as grants and no non_read.
func TestPresets_ARoleWrittenFromOneLoads(t *testing.T) {
	path := writeRolesPair(t, minimalConfig, presetsText)
	text, skipped, st := frontkit.NewRoleFromPreset(presetsText, "hunt", "Blue team analyst", []string{"soc-hunt"}, nil)
	if st != frontkit.SpliceChanged || len(skipped) != 0 {
		t.Fatalf("status %v, skipped %v", st, skipped)
	}
	if err := ValidateRolesText(path, []byte(text)); err != nil {
		t.Fatalf("written role does not load: %v\n%s", err, text)
	}
	c, err := load(path, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range c.Roles {
		if r.Name == "hunt" {
			if r.NonRead || strings.Join(r.Grants["casemgmt"], ",") != "list_cases,get_case" || c.GroupToRole["soc-hunt"] != "hunt" {
				t.Fatalf("role %+v, groups %v", r, c.GroupToRole)
			}
			return
		}
	}
	t.Fatalf("role hunt missing:\n%s", text)
}
