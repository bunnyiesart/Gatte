package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests of roles_file (design/adr/0050 §3): the [[role]] blocks and the
// [group_to_role] table in a file of their own, held to what the main
// file is held to, and found by every reader through Load.

const rolesText = `
[[role]]
name  = "n1-triage"
tools = ["casemgmt.list_cases"]

[group_to_role]
"soc-n1" = "n1-triage"
`

// writeRolesPair writes a main file pointing at roles.toml beside it (by
// a relative path) and the roles file, and returns the main file's path.
func writeRolesPair(t *testing.T, main, roles string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "roles.toml"), []byte(roles), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("roles_file = \"roles.toml\"\n"+main), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRolesFile_RolesAndGroupsComeFromIt(t *testing.T) {
	path := writeRolesPair(t, minimalConfig, rolesText)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Roles) != 1 || c.Roles[0].Name != "n1-triage" || c.GroupToRole["soc-n1"] != "n1-triage" {
		t.Fatalf("roles %+v, groups %v", c.Roles, c.GroupToRole)
	}
	// Resolved against the main file's directory and kept absolute, so
	// every later reader (reload, the admin backend) opens the same file.
	if want := filepath.Join(filepath.Dir(path), "roles.toml"); c.RolesFile != want {
		t.Errorf("RolesFile = %q, want %q", c.RolesFile, want)
	}
}

func TestRolesFile_RolesInBothFilesAreRefused(t *testing.T) {
	for _, extra := range []string{
		"\n[[role]]\nname = \"x\"\ntools = []\n",
		"\n[group_to_role]\n\"g\" = \"n1-triage\"\n",
	} {
		_, err := Load(writeRolesPair(t, minimalConfig+extra, rolesText))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "roles_file is set, and this file also has") {
			t.Errorf("roles in both files: %v", err)
		}
	}
}

func TestRolesFile_AnUnknownKeyInItIsRefusedAndNamesIt(t *testing.T) {
	path := writeRolesPair(t, minimalConfig, rolesText+"\n[signer]\nrequire_signed = false\n")
	_, err := Load(path)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "unknown key") || !strings.Contains(err.Error(), "roles.toml") {
		t.Fatalf("an unknown key in the roles file: %v", err)
	}
	// The same refusal inside a role.
	_, err = Load(writeRolesPair(t, minimalConfig, strings.Replace(rolesText, `name  = "n1-triage"`, "name = \"n1-triage\"\nnon_raed = true", 1)))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "role.non_raed") {
		t.Fatalf("a misspelled role key in the roles file: %v", err)
	}
}

func TestRolesFile_ARepeatedGrantKeyInItIsRefused(t *testing.T) {
	roles := "[[role]]\nname = \"r\"\n[role.grants]\ncasemgmt = [\"get_case\"]\ncasemgmt = [\"*\"]\n"
	_, err := Load(writeRolesPair(t, minimalConfig, roles))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "written more than once") {
		t.Fatalf("a repeated grant in the roles file: %v", err)
	}
}

func TestRolesFile_AValidationProblemNamesBothFiles(t *testing.T) {
	path := writeRolesPair(t, minimalConfig, "[group_to_role]\n\"g\" = \"nobody\"\n")
	_, err := Load(path)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "(roles from ") {
		t.Fatalf("an undefined role through the roles file: %v", err)
	}
}

func TestRolesFile_MissingIsAnErrorNamingIt(t *testing.T) {
	path := writeConfig(t, "roles_file = \"/nonexistent/roles.toml\"\n"+minimalConfig)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "/nonexistent/roles.toml") {
		t.Fatalf("a missing roles file: %v", err)
	}
}

func TestValidateRolesText_ChecksWithoutWriting(t *testing.T) {
	path := writeRolesPair(t, minimalConfig, rolesText)
	rolesPath := filepath.Join(filepath.Dir(path), "roles.toml")
	if err := ValidateRolesText(path, []byte(rolesText+"\n[[role]]\nname = \"hunt\"\ntools = []\n")); err != nil {
		t.Fatalf("a valid text: %v", err)
	}
	err := ValidateRolesText(path, []byte("not_a_key = 1\n"+rolesText))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not_a_key") {
		t.Fatalf("an invalid text: %v", err)
	}
	if b, _ := os.ReadFile(rolesPath); string(b) != rolesText {
		t.Fatal("ValidateRolesText changed the roles file")
	}
	// Without roles_file there is no roles file to validate a text for.
	if err := ValidateRolesText(writeConfig(t, minimalConfig), []byte(rolesText)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no roles_file: %v", err)
	}
}

func TestAdminConsoleManages_DefaultsOffAndLoads(t *testing.T) {
	c, err := Load(writeConfig(t, minimalConfig))
	if err != nil || c.Admin.ConsoleManages {
		t.Fatalf("default: %v, %v", c.Admin.ConsoleManages, err)
	}
	c, err = Load(writeConfig(t, minimalConfig+"\n[admin]\nconsole_manages = true\n"))
	if err != nil || !c.Admin.ConsoleManages {
		t.Fatalf("on: %+v, %v", c, err)
	}
}
