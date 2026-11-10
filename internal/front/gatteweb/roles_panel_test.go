package gatteweb

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// testFront builds a console wired to the seeded fake, for rendering checks.
func testFront(t *testing.T) *Front {
	t.Helper()
	c := adminapitest.Start(t)
	kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("frontkit: %v", err)
	}
	t.Cleanup(func() { _ = kit.Close() })
	f, err := New(Options{Operator: c.Operator, Accounts: c.Accounts, Kit: kit})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// TestRolesPanel_RendersTheMatrixFromTheSeededFake renders the Roles section
// against the fake's seeded roles, tools and people, and checks the structured
// view is there: both roles, the non_read badge, the safe/sensitive columns,
// and the grant form.
func TestRolesPanel_RendersTheMatrixFromTheSeededFake(t *testing.T) {
	f := testFront(t)
	html, err := f.rolesPanelFragment(httptest.NewRequest("GET", "/users", nil))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		"tier1-analyst", "ir-lead", // roles down the axis
		"close_case", "get_case", // tools across
		"sensitive",         // the class marker on a column
		"non_read",          // the marking shown and the toggle
		"/users/roles/edit", // the grant/revoke action
		"Grant", "Revoke",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered Roles section is missing %q", want)
		}
	}
}

// TestRolesPanel_SelfRegistersAtSlotTwenty checks the section is registered in
// the UsersSection registry at order 20, as the surface map assigns.
func TestRolesPanel_SelfRegistersAtSlotTwenty(t *testing.T) {
	var found *UsersSection
	for i := range usersGroups {
		if usersGroups[i].ID == "roles" {
			found = &usersGroups[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no UsersSection with ID \"roles\" is registered")
	}
	if found.Order != 20 {
		t.Errorf("roles section Order = %d, want 20", found.Order)
	}
	if found.Show == nil || found.Show(Capabilities{Manages: true, Root: false}) {
		t.Error("roles section must show only on the managing console with the accounts socket")
	}
	if !found.Show(Capabilities{Manages: true, Root: true}) {
		t.Error("roles section should show with Manages and Root")
	}
}
