package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
)

func registerStdio(t *testing.T, configPath, name string) {
	t.Helper()
	var out, errb bytes.Buffer
	requireExit(t, cmdUpstream([]string{"register", "-config", configPath, "-name", name, "-transport", "stdio", "-command", "/usr/bin/" + name}, &out, &errb), exitOK, "register "+name+"\n"+errb.String())
}

// TestCmdSign_AllSignsWhatNeedsItAndLeavesTheRest: unsigned entries are
// signed, one already signed by this key is left alone, -dry-run writes
// nothing, and after a key rotation every entry is re-signed.
func TestCmdSign_AllSignsWhatNeedsItAndLeavesTheRest(t *testing.T) {
	keyFile := writeSigningKey(t, 0o600)
	configPath := writeOperatorConfig(t, signerSection(t, keyFile))
	for _, n := range []string{"casemgmt", "logsearch", "docsearch"} {
		registerStdio(t, configPath, n)
	}
	var out, errb bytes.Buffer
	requireExit(t, cmdSign([]string{"-config", configPath, "casemgmt"}, &out, &errb), exitOK, "sign casemgmt")

	out.Reset()
	requireExit(t, cmdSign([]string{"-config", configPath, "-all", "-dry-run"}, &out, &errb), exitOK, "sign -all -dry-run\n"+errb.String())
	requireContains(t, out.String(), "Would sign (-dry-run: nothing is written)", "dry run")
	requireContains(t, out.String(), "logsearch -- was unsigned", "dry run")
	requireContains(t, out.String(), "1 already signed by it is left alone", "dry run")
	if strings.Contains(out.String(), "casemgmt --") {
		t.Errorf("dry run lists the entry already signed:\n%s", out.String())
	}
	out.Reset()
	requireExit(t, cmdUpstream([]string{"list", "-config", configPath}, &out, &errb), exitOK, "list")
	if strings.Count(out.String(), string(sigValid)) != 1 {
		t.Fatalf("-dry-run signed something:\n%s", out.String())
	}

	out.Reset()
	requireExit(t, cmdSign([]string{"-config", configPath, "-all"}, &out, &errb), exitOK, "sign -all\n"+errb.String())
	requireContains(t, out.String(), "Signed 2 entries.", "sign -all")
	requireContains(t, out.String(), "command / url", "sign -all shows what it signs")
	out.Reset()
	requireExit(t, cmdSign([]string{"-config", configPath, "-all"}, &out, &errb), exitOK, "sign -all again")
	requireContains(t, out.String(), "All 3 registered entries are already validly signed by this key", "sign -all again")

	// Rotation: a new key, trusted beside the old one, becomes key_file.
	newKey := writeSigningKey(t, 0o600)
	rotated := writeOperatorConfig(t, "\n[signer]\nkey_file = \""+newKey+"\"\nrequire_signed = true\ntrusted_keys = [\""+
		trustedKeyFor(t, keyFile)+"\", \""+trustedKeyFor(t, newKey)+"\"]\n")
	// The same database as the first configuration.
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(rotated)
	cfg2, _ := config.Load(rotated)
	if err := os.WriteFile(rotated, []byte(strings.Replace(string(b), cfg2.Database, cfg.Database, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	requireExit(t, cmdSign([]string{"-config", rotated, "-all"}, &out, &errb), exitOK, "sign -all after rotation\n"+errb.String())
	requireContains(t, out.String(), "Signed 3 entries.", "after rotation")
	requireContains(t, out.String(), "was signed by another key", "after rotation")

	for _, args := range [][]string{{"-all", "casemgmt"}, {"-dry-run", "casemgmt"}} {
		errb.Reset()
		requireExit(t, cmdSign(append([]string{"-config", configPath}, args...), &out, &errb), exitCannotRun, strings.Join(args, " "))
	}
}

// TestCmdSign_AsRootDropsToTheDatabaseOwnerBeforeOpeningIt is the trap the
// README used to paper over with a chown: sign as root created -wal and
// -shm files owned by root in the service account's directory.
func TestCmdSign_AsRootDropsToTheDatabaseOwnerBeforeOpeningIt(t *testing.T) {
	keyFile := writeSigningKey(t, 0o600)
	configPath := writeOperatorConfig(t, signerSection(t, keyFile))
	registerStdio(t, configPath, "casemgmt")
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(cfg.Database + suffix)
	}

	var droppedTo []int
	openedBeforeDrop := false
	signGeteuid = func() int { return 0 }
	signDropTo = func(uid, gid int) error {
		droppedTo = []int{uid, gid}
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(cfg.Database + suffix); err == nil {
				openedBeforeDrop = true
			}
		}
		return nil
	}
	t.Cleanup(func() { signGeteuid, signDropTo = os.Geteuid, dropPrivileges })

	var out, errb bytes.Buffer
	requireExit(t, cmdSign([]string{"-config", configPath, "casemgmt"}, &out, &errb), exitOK, "sign as root\n"+errb.String())
	fi, err := os.Stat(filepath.Dir(cfg.Database))
	if err != nil {
		t.Fatal(err)
	}
	owner := fileOwner(t, fi)
	if len(droppedTo) != 2 || droppedTo[0] != owner[0] || droppedTo[1] != owner[1] {
		t.Fatalf("dropped to %v, want the database directory's owner %v", droppedTo, owner)
	}
	if openedBeforeDrop {
		t.Fatal("the database was opened (a -wal or -shm existed) before the drop")
	}

	// A database directory reached through a symbolic link is refused.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "db")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(configPath)
	linked := filepath.Join(t.TempDir(), "linked.toml")
	if err := os.WriteFile(linked, []byte(strings.Replace(string(b), cfg.Database, filepath.Join(link, "gateway.db"), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	droppedTo = nil
	errb.Reset()
	requireExit(t, cmdSign([]string{"-config", linked, "casemgmt"}, &out, &errb), exitCannotRun, "sign through a symlinked directory")
	requireContains(t, errb.String(), "is not a directory (a symbolic link is refused)", "symlink")
	if droppedTo != nil {
		t.Fatal("dropped privileges for a directory it refused")
	}
}
