package atomicfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/atomicfile"
)

func TestReplace_KeepsTheModeAndLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "roles.toml")
	if err := os.WriteFile(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Replace(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "new" || fi.Mode().Perm() != 0o640 {
		t.Fatalf("content %q mode %v", b, fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("left behind: %v", ents)
	}
}

func TestReplace_CreatesWithTheGivenModeAndRefusesALink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "new.json")
	if err := atomicfile.Replace(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Replace(link, []byte("y"), 0o600); err == nil {
		t.Fatal("a symbolic link was replaced")
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Fatalf("the link's target changed: %q", b)
	}
}
