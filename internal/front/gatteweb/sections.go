package gatteweb

import (
	"html/template"
	"net/http"
	"sort"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// A Section is one CRUD entity's self-registration into the console shell.
// Each entity declares exactly one, in its own file's init(), so adding or
// changing an entity never edits a shared route table or the navigation
// template: the shell builds both its routes (routes) and its navigation
// (navFor) from the registry alone. This is what lets several entity branches
// land without colliding on one shared file.
//
// To add an entity, add a file with an init() that calls register once. Do not
// edit this file, gatteweb.go or ui/layout.html for it.
type Section struct {
	// Nav is the entity's navigation entry. A zero Nav.Path means the entity
	// adds no top-nav link (it is reached from another page).
	Nav NavItem
	// Mount registers the entity's routes on the shell's mux. It is called
	// once, when the console starts serving, with the live Front.
	Mount func(mux *http.ServeMux, f *Front)
}

// NavItem is one entry in the console's top navigation.
type NavItem struct {
	// ID matches page.Nav, so the active page's link is marked current.
	ID string
	// Path is relative to the console base, e.g. "/tools"; "/" is the root.
	Path string
	// Label is the link text (English, no emoji).
	Label string
	// Order sorts the links left to right.
	Order int
	// Show reports whether the link appears for a request's capabilities. A
	// nil Show means the link always appears.
	Show func(Capabilities) bool
}

// Capabilities are the console powers that decide which nav links appear:
// Manages is the backend listing FeatureConsoleManages (design/adr/0050), and
// Root the console holding the accounts socket (-manage-users).
type Capabilities struct {
	Manages bool
	Root    bool
}

// sections is the registry. Entity files append to it from init(), which runs
// before any Front is built, so the set is complete by the time routes runs.
var sections []Section

// register adds one entity's section. Entity files call it from init().
func register(s Section) { sections = append(sections, s) }

// orderedSections returns the registry sorted by nav order, then label, as a
// copy, so a caller may range over it without disturbing the registry.
func orderedSections() []Section {
	out := make([]Section, len(sections))
	copy(out, sections)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Nav.Order != out[j].Nav.Order {
			return out[i].Nav.Order < out[j].Nav.Order
		}
		return out[i].Nav.Label < out[j].Nav.Label
	})
	return out
}

// navView is one rendered nav link passed to the layout template.
type navView struct {
	Path    string
	Label   string
	Current bool
}

// navFor builds the nav links visible for a request: the registered entities
// that declare a link and whose Show allows it, in order, with the current
// page marked.
func navFor(current string, c Capabilities) []navView {
	var out []navView
	for _, s := range orderedSections() {
		n := s.Nav
		if n.Path == "" {
			continue
		}
		if n.Show != nil && !n.Show(c) {
			continue
		}
		out = append(out, navView{Path: n.Path, Label: n.Label, Current: n.ID == current})
	}
	return out
}

// managesAndRoot is the Show predicate for a contribution that needs both the
// managing console and the accounts socket (the Secrets panel, the editable
// Roles section).
func managesAndRoot(c Capabilities) bool { return c.Manages && c.Root }

// The revised two-tab IA (design/adr/0051) makes two pages shared: the
// server-detail page (/servers/{name}) and the Users page (/users). So the
// console carries three registries, all here: the route registry above
// (register/Section), and the two below. Each Tab-1 slice appends one
// DetailPanel from its own reg_<slice>.go init(); each Tab-2 slice appends one
// UsersSection the same way. The two container pages (servers.go, users.go)
// range over these in order, so a slice adds its panel or section without
// editing a shared file, the shell, or another slice's work.
//
// Order uses gaps of ten so a slice can slot between two without renumbering:
// DetailPanel Tools 20, Secrets 30, Maintenance 40; UsersSection People 10,
// Roles 20.

// A DetailPanel is one Tab-1 slice's contribution to the server-detail page.
// Render draws the panel's HTML for one backend; the container embeds it. A nil
// Show means the panel always appears.
type DetailPanel struct {
	ID     string
	Order  int
	Show   func(Capabilities) bool
	Render func(f *Front, r *http.Request, d adminapi.UpstreamDetail) (template.HTML, error)
}

// A UsersSection is one Tab-2 slice's contribution to the Users page. Render
// draws the section's own HTML (it reads what it needs from the API itself). A
// nil Show means the section always appears.
type UsersSection struct {
	ID     string
	Order  int
	Show   func(Capabilities) bool
	Render func(f *Front, r *http.Request) (template.HTML, error)
}

var (
	detailPanels []DetailPanel
	usersGroups  []UsersSection
)

// registerDetailPanel adds one server-detail panel. Tab-1 slices call it from
// init().
func registerDetailPanel(p DetailPanel) { detailPanels = append(detailPanels, p) }

// registerUsersSection adds one Users-page section. Tab-2 slices call it from
// init().
func registerUsersSection(s UsersSection) { usersGroups = append(usersGroups, s) }

// orderedDetailPanels and orderedUsersSections return the registries sorted by
// order then ID, as copies, so a caller may range over them safely.
func orderedDetailPanels() []DetailPanel {
	out := make([]DetailPanel, len(detailPanels))
	copy(out, detailPanels)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func orderedUsersSections() []UsersSection {
	out := make([]UsersSection, len(usersGroups))
	copy(out, usersGroups)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// fragment is one rendered panel or section the container template prints in
// order. The HTML is the slice's own escaped output.
type fragment struct {
	ID   string
	HTML template.HTML
}
