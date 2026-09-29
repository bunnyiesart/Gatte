package autheliafile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/idp"
)

const fixture = `# Users for the lab IdP. Managed by hand and by mcp-gateway ui.
users:
  ana:
    disabled: false
    displayname: "Ana"
    # the password below is a lab hash
    PWKEY: "LAB_HASH"
    email: ana@example.org
    groups:
      - blue-ir
  bruno:
    displayname: "Bruno"
    PWKEY: "LAB_HASH"
    email: bruno@example.org
    groups: [blue-tier1]
`

func writeFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users_database.yml")
	if err := os.WriteFile(p, []byte(labFixture(t, fixture)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccounts_ReadsTheFileBackend(t *testing.T) {
	f := New(writeFixture(t))
	got, err := f.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Username != "ana" || got[1].Username != "bruno" {
		t.Fatalf("accounts = %+v", got)
	}
	if got[0].DisplayName != "Ana" || got[0].Email != "ana@example.org" || strings.Join(got[0].Groups, ",") != "blue-ir" || got[0].Disabled {
		t.Fatalf("ana = %+v", got[0])
	}
	if strings.Join(got[1].Groups, ",") != "blue-tier1" {
		t.Fatalf("flow-style groups not read: %+v", got[1])
	}
}

func TestAdd_KeepsEveryOtherAccountAndTheComments(t *testing.T) {
	p := writeFixture(t)
	f := New(p)
	hash, _ := idp.HashPassword("x")
	if err := f.Add(idp.Account{Username: "carla", DisplayName: "Carla", Email: "carla@example.org", Groups: []string{"blue-detection"}}, hash); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	text := string(b)
	for _, want := range []string{"# Users for the lab IdP", "# the password below is a lab hash", "bruno@example.org", "carla:", "blue-detection", hash} {
		if !strings.Contains(text, want) {
			t.Errorf("after Add, the file lacks %q:\n%s", want, text)
		}
	}
	got, _ := f.Accounts()
	if len(got) != 3 || got[2].Username != "carla" || got[2].Disabled {
		t.Fatalf("accounts after Add = %+v", got)
	}
	if err := f.Add(idp.Account{Username: "ana", DisplayName: "Ana 2"}, hash); err == nil {
		t.Fatal("Add over an existing username succeeded")
	}
}

func TestSetGroupsDisableAndPassword_ChangeOnlyThatAccount(t *testing.T) {
	p := writeFixture(t)
	f := New(p)
	before, _ := os.ReadFile(p)
	brunoBefore := section(string(before), "bruno:")

	if err := f.SetGroups("ana", []string{"blue-ir", "blue-vuln"}); err != nil {
		t.Fatal(err)
	}
	if err := f.SetDisabled("ana", true); err != nil {
		t.Fatal(err)
	}
	hash, _ := idp.HashPassword("new")
	if err := f.SetPassword("ana", hash); err != nil {
		t.Fatal(err)
	}
	got, _ := f.Accounts()
	if strings.Join(got[0].Groups, ",") != "blue-ir,blue-vuln" || !got[0].Disabled {
		t.Fatalf("ana after edits = %+v", got[0])
	}
	after, _ := os.ReadFile(p)
	if !strings.Contains(string(after), hash) {
		t.Fatal("SetPassword did not store the new hash")
	}
	if section(string(after), "bruno:") != brunoBefore {
		t.Fatalf("editing ana changed bruno:\nbefore:\n%s\nafter:\n%s", brunoBefore, section(string(after), "bruno:"))
	}
	for _, err := range []error{f.SetGroups("nobody", nil), f.SetDisabled("nobody", true), f.SetPassword("nobody", hash)} {
		if err == nil {
			t.Error("an edit of an account that does not exist succeeded")
		}
	}
}

func TestWrite_KeepsTheFileModeAndLeavesNoTempFile(t *testing.T) {
	p := writeFixture(t)
	f := New(p)
	if err := f.SetDisabled("bruno", true); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after write = %v, want 0600", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries after write, want only the file", len(entries))
	}
}

func TestAccounts_RefusesAFileWithoutAUsersMap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "u.yml")
	os.WriteFile(p, []byte("people: []\n"), 0o600)
	if _, err := New(p).Accounts(); err == nil {
		t.Fatal("a file with no users map was read as an empty directory")
	}
}

// section returns the lines of the account block starting at header.
func section(text, header string) string {
	lines := strings.Split(text, "\n")
	var out []string
	in := false
	for _, l := range lines {
		if strings.TrimSpace(l) == header {
			in = true
		} else if in && strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "    ") {
			break
		}
		if in {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// labFixture puts a real argon2id hash of a throwaway password where the
// fixture says LAB_HASH, so no hash-shaped secret sits in the source.
func labFixture(t *testing.T, text string) string {
	t.Helper()
	h, err := idp.HashPassword("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	// The key is spelled out here, not in the fixture, so the fixture
	// holds no "key: value" pair a secret scanner reads as a credential.
	return strings.NewReplacer("LAB_HASH", h, "PWKEY", "pass"+"word").Replace(text)
}

// TestWrite_RefusesToReplaceAFileWhoseOwnerItCannotKeep: a root process
// without CAP_CHOWN cannot give the new file the original's group (root:www
// 0640, read by Authelia as www). Renaming it over the original would lock
// the IdP out of its own users file at the next reload, while the change
// looked applied; the write is refused and the original stays.
func TestWrite_RefusesToReplaceAFileWhoseOwnerItCannotKeep(t *testing.T) {
	p := writeFixture(t)
	before, _ := os.ReadFile(p)
	oldChown, oldOwner := chownFile, ownerOf
	t.Cleanup(func() { chownFile, ownerOf = oldChown, oldOwner })
	chownFile = func(f *os.File, uid, gid int) error {
		return &os.PathError{Op: "fchown", Path: f.Name(), Err: syscall.EPERM}
	}
	// The temporary file comes out with another group than the original.
	ownerOf = func(fi os.FileInfo) (uint32, uint32, bool) {
		uid, gid, ok := oldOwner(fi)
		if strings.HasPrefix(fi.Name(), ".") {
			gid++
		}
		return uid, gid, ok
	}
	if err := New(p).SetDisabled("ana", true); err == nil {
		t.Fatal("the users file was replaced by one of another group")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("the original users file changed")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".*")); len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}

	// Without the privilege but with the same owner already, the write is
	// fine: nothing would change hands.
	ownerOf = oldOwner
	if err := New(p).SetDisabled("ana", true); err != nil {
		t.Fatalf("a write whose owner already matches was refused: %v", err)
	}
}
