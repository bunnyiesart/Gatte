package gatteweb

import (
	"net/http"
	"sort"
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

// manages and root are the common Show predicates: an entry only the managing
// console shows (Secrets, Roles).
func managesAndRoot(c Capabilities) bool { return c.Manages && c.Root }
