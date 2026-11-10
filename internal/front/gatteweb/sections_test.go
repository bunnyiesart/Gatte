package gatteweb

import (
	"html/template"
	"net/http"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// TestNavForOrderAndGating checks the registry-built navigation: entries come
// out in nav order, the current page is marked, and the managing-only entries
// (Secrets, Roles) appear only with both capabilities.
func TestNavForOrderAndGating(t *testing.T) {
	// Tools is no longer a top-nav tab (design/adr/0051): it lives on each
	// server's detail page, registered as a DetailPanel, not a NavItem. People
	// and Access likewise moved into the Users tab as sections, not NavItems.
	full := navFor("servers", Capabilities{Manages: true, Root: true})
	var labels []string
	current := ""
	for _, n := range full {
		labels = append(labels, n.Label)
		if n.Current {
			current = n.Label
		}
	}
	want := []string{"Overview", "MCP Servers / APIs", "Users", "Audit", "Backends", "Secrets", "Roles", "Quota"}
	if len(labels) != len(want) {
		t.Fatalf("nav labels = %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("nav order = %v, want %v", labels, want)
		}
	}
	if current != "MCP Servers / APIs" {
		t.Fatalf("current = %q, want MCP Servers / APIs", current)
	}

	// Without the managing capabilities, Secrets and Roles are hidden.
	plain := navFor("overview", Capabilities{})
	for _, n := range plain {
		if n.Label == "Secrets" || n.Label == "Roles" {
			t.Fatalf("%q must not appear without manage + accounts socket", n.Label)
		}
	}
	if len(plain) != len(want)-2 {
		t.Fatalf("plain nav has %d entries, want %d", len(plain), len(want)-2)
	}
}

// The Users tab shows exactly one Roles section for every console: the editable
// matrix with the managing console and the accounts socket (design/adr/0054),
// the read-only view otherwise, so an operator without them still sees roles.
func TestRolesSlot_EditableOrReadOnlyNeverBoth(t *testing.T) {
	for _, caps := range []Capabilities{{}, {Manages: true}, {Root: true}, {Manages: true, Root: true}} {
		var shown []string
		for _, s := range orderedUsersSections() {
			if (s.ID == "roles" || s.ID == "roles-view") && (s.Show == nil || s.Show(caps)) {
				shown = append(shown, s.ID)
			}
		}
		want := "roles-view"
		if caps.Manages && caps.Root {
			want = "roles"
		}
		if len(shown) != 1 || shown[0] != want {
			t.Errorf("caps %+v: Roles sections shown = %v, want [%s]", caps, shown, want)
		}
	}
}

// The server-detail and Users containers draw their panels and sections from
// their own registries (design/adr/0051): each slice appends one from its own
// init(), and the container ranges in Order. A panel can slot between two with
// the gap-of-ten orders without renumbering, and Order ties break by ID.
func TestDetailAndUsersRegistries_OrderByOrderThenID(t *testing.T) {
	savedPanels, savedSections := detailPanels, usersGroups
	t.Cleanup(func() { detailPanels, usersGroups = savedPanels, savedSections })
	detailPanels, usersGroups = nil, nil

	noHTML := func(*Front, *http.Request, adminapi.UpstreamDetail) (template.HTML, error) { return "", nil }
	registerDetailPanel(DetailPanel{ID: "maintenance", Order: 40, Render: noHTML})
	registerDetailPanel(DetailPanel{ID: "tools", Order: 20, Render: noHTML})
	registerDetailPanel(DetailPanel{ID: "secrets", Order: 30, Render: noHTML})
	registerDetailPanel(DetailPanel{ID: "between", Order: 25, Render: noHTML})
	var got []string
	for _, p := range orderedDetailPanels() {
		got = append(got, p.ID)
	}
	want := []string{"tools", "between", "secrets", "maintenance"}
	if len(got) != len(want) {
		t.Fatalf("panel order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("panel order = %v, want %v", got, want)
		}
	}

	noSec := func(*Front, *http.Request) (template.HTML, error) { return "", nil }
	registerUsersSection(UsersSection{ID: "blocklist", Order: 30, Render: noSec})
	registerUsersSection(UsersSection{ID: "people", Order: 10, Render: noSec})
	registerUsersSection(UsersSection{ID: "roles", Order: 20, Render: noSec})
	got = nil
	for _, s := range orderedUsersSections() {
		got = append(got, s.ID)
	}
	want = []string{"people", "roles", "blocklist"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("section order = %v, want %v", got, want)
		}
	}
}
