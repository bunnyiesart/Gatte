package fitness

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// unitDirective returns every value of key in a unit file, words split.
func unitDirective(t *testing.T, file, key string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			out = append(out, strings.Fields(v)...)
		}
	}
	return out
}

// TestSystemdUnits_WriteWhereTheExampleConfigurationWrites: under
// ProtectSystem=strict a unit writes only its ReadWritePaths, so the
// shipped units must cover the database directory and the [audit.siem]
// directory of the shipped config.example.toml. Otherwise every operator
// write, and the SIEM copy of its row, hits a read-only file system.
func TestSystemdUnits_WriteWhereTheExampleConfigurationWrites(t *testing.T) {
	root := repoRoot(t)
	ex, err := os.ReadFile(filepath.Join(root, "config.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	db := regexp.MustCompile(`(?m)^database\s*=\s*"([^"]+)"`).FindSubmatch(ex)
	siem := regexp.MustCompile(`(?m)^#?\s*path\s*=\s*"(/[^"]+\.jsonl)"`).FindSubmatch(ex)
	if db == nil || siem == nil {
		t.Fatal("config.example.toml no longer names a database path and an [audit.siem] path")
	}
	want := []string{path.Dir(string(db[1])), path.Dir(string(siem[1]))}
	for _, unit := range []string{"mcp-gateway-admin.service", "mcp-gateway-admin-accounts.service", "mcp-gateway.service"} {
		rw := unitDirective(t, filepath.Join(root, "examples", "systemd", unit), "ReadWritePaths")
		for _, w := range want {
			found := false
			for _, p := range rw {
				if p == w {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: ReadWritePaths %v does not include %s, where config.example.toml writes", unit, rw, w)
			}
		}
	}
}

// TestSystemdUnits_TheAccountsBackendCanKeepTheUsersFilesGroup: the users
// file is rewritten by tmp+rename, and giving the new file the original's
// group (root:www 0640, read by Authelia) needs CAP_CHOWN.
func TestSystemdUnits_TheAccountsBackendCanKeepTheUsersFilesGroup(t *testing.T) {
	caps := unitDirective(t, filepath.Join(repoRoot(t), "examples", "systemd", "mcp-gateway-admin-accounts.service"), "CapabilityBoundingSet")
	for _, want := range []string{"CAP_CHOWN", "CAP_SETUID", "CAP_SETGID"} {
		found := false
		for _, c := range caps {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("mcp-gateway-admin-accounts.service: CapabilityBoundingSet %v lacks %s", caps, want)
		}
	}
}

// TestSystemdUnits_TheGatewayReloadsTheFileItServes: `systemctl reload`
// must run `mcp-gateway reload` against the same -config serve was started
// with (design/adr/0044) -- a bare kill -HUP would report success for a
// file serve refused, and another -config would reload a gateway that is
// not this one.
func TestSystemdUnits_TheGatewayReloadsTheFileItServes(t *testing.T) {
	unit := filepath.Join(repoRoot(t), "examples", "systemd", "mcp-gateway.service")
	start := unitDirective(t, unit, "ExecStart")
	reload := unitDirective(t, unit, "ExecReload")
	configOf := func(words []string) string {
		for i, w := range words {
			if w == "-config" && i+1 < len(words) {
				return words[i+1]
			}
		}
		return ""
	}
	if len(start) < 2 || start[1] != "serve" {
		t.Fatalf("ExecStart = %v, want mcp-gateway serve", start)
	}
	if len(reload) < 2 || reload[1] != "reload" || !strings.HasSuffix(reload[0], "mcp-gateway") {
		t.Fatalf("ExecReload = %v, want mcp-gateway reload", reload)
	}
	if c := configOf(start); c == "" || c != configOf(reload) {
		t.Fatalf("ExecStart -config %q, ExecReload -config %q: they must be the same file", c, configOf(reload))
	}
	if user := unitDirective(t, unit, "User"); len(user) != 1 || user[0] == "root" {
		t.Fatalf("User = %v, want the service account", user)
	}
}

// TestSystemdUnits_TheBackupUnitCanWriteWhereItReadsAndWrites: the backup
// unit (design/adr/0045) reads a WAL database, which writes its -shm, and
// writes into its -out directory; under ProtectSystem=strict both must be
// in ReadWritePaths or the timer fails every night.
func TestSystemdUnits_TheBackupUnitCanWriteWhereItReadsAndWrites(t *testing.T) {
	root := repoRoot(t)
	ex, err := os.ReadFile(filepath.Join(root, "config.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	db := regexp.MustCompile(`(?m)^database\s*=\s*"([^"]+)"`).FindSubmatch(ex)
	if db == nil {
		t.Fatal("config.example.toml no longer names a database path")
	}
	unit := filepath.Join(root, "examples", "systemd", "mcp-gateway-backup.service")
	exec := strings.Join(unitDirective(t, unit, "ExecStart"), " ")
	out := regexp.MustCompile(`-out (\S+)`).FindStringSubmatch(exec)
	if out == nil || !strings.Contains(exec, " backup ") {
		t.Fatalf("mcp-gateway-backup.service does not run backup -out DIR: %s", exec)
	}
	rw := unitDirective(t, unit, "ReadWritePaths")
	for _, w := range []string{path.Dir(string(db[1])), out[1]} {
		found := false
		for _, p := range rw {
			if p == w {
				found = true
			}
		}
		if !found {
			t.Errorf("mcp-gateway-backup.service: ReadWritePaths %v does not include %s", rw, w)
		}
	}
}
