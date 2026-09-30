package autheliafile

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/idp"
)

// TestDelete_RemovesOnlyThatAccountAndKeepsTheComments is design/adr/0046
// item 2 at the file.
func TestDelete_RemovesOnlyThatAccountAndKeepsTheComments(t *testing.T) {
	p := writeFixture(t)
	f := New(p)
	if err := f.Delete("ana"); err != nil {
		t.Fatal(err)
	}
	got, err := f.Accounts()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Username != "bruno" || strings.Join(got[0].Groups, ",") != "blue-tier1" {
		t.Fatalf("after deleting ana: %+v", got)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# Users for the lab IdP") || strings.Contains(string(b), "ana@example.org") {
		t.Fatalf("file after delete:\n%s", b)
	}
	if err := f.Delete("ana"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("second delete: %v, want ErrNotFound", err)
	}
}
