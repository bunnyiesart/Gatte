package gattetui

import (
	"context"
	"slices"
	"sort"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The terminal front has the web console's three registries
// (design/frontend-crud-surface.md, "Self-registration"): the tabs, the
// panels of the server-detail page, and the sections of the Users tab. Each
// surface appends to one of them from its own file's init(), so adding a
// surface touches only that surface's file, never a shared menu or switch.
//
// Order uses gaps of ten, as in the console: tabs Servers 10, Users 20;
// detail panels Tools 20, Secrets 30, Maintenance 40; Users sections People
// 10, Roles 20, Blocklist 30.

// A Screen is one tab. Root builds the tab's first page.
type Screen struct {
	ID    string
	Title string
	Order int
	Root  func() *page
}

// A DetailPanel is one contribution to a backend's detail page. Rows draws
// it for one backend; it may call the API (it runs off the update loop). A
// nil Show means the panel always appears.
type DetailPanel struct {
	ID    string
	Order int
	Show  func(Caps) bool
	Rows  func(e env, d adminapi.UpstreamDetail) ([]row, error)
}

// A UsersSection is one contribution to the Users tab, read on its own.
type UsersSection struct {
	ID    string
	Order int
	Show  func(Caps) bool
	Rows  func(e env) ([]row, error)
}

var (
	screens      []Screen
	detailPanels []DetailPanel
	usersGroups  []UsersSection
)

func registerScreen(s Screen)             { screens = append(screens, s) }
func registerDetailPanel(p DetailPanel)   { detailPanels = append(detailPanels, p) }
func registerUsersSection(s UsersSection) { usersGroups = append(usersGroups, s) }

// ordered returns a sorted copy of a registry, by order then ID, so callers
// may range over it without disturbing it.
func ordered[T any](in []T, key func(T) (int, string)) []T {
	out := slices.Clone(in)
	sort.SliceStable(out, func(i, j int) bool {
		oi, ii := key(out[i])
		oj, ij := key(out[j])
		if oi != oj {
			return oi < oj
		}
		return ii < ij
	})
	return out
}

func orderedScreens() []Screen {
	return ordered(screens, func(s Screen) (int, string) { return s.Order, s.ID })
}

func orderedDetailPanels() []DetailPanel {
	return ordered(detailPanels, func(p DetailPanel) (int, string) { return p.Order, p.ID })
}

func orderedUsersSections() []UsersSection {
	return ordered(usersGroups, func(s UsersSection) (int, string) { return s.Order, s.ID })
}

// Caps are the console powers that decide what is offered, as in the web
// console: Manages is the backend listing FeatureConsoleManages
// (design/adr/0050), Root the front holding the accounts socket.
type Caps struct {
	Manages bool
	Root    bool
}

func managesAndRoot(c Caps) bool { return c.Manages && c.Root }

// env is what every page and panel reads through: the two clients and what
// the operator socket last said about itself. It is passed by value into
// the commands that run off the update loop, so they never share state with
// it.
type env struct {
	op  *adminapi.Client
	acc *adminapi.Client
	me  adminapi.WhoAmI
}

func (e env) has(feature string) bool { return slices.Contains(e.me.Features, feature) }

func (e env) caps() Caps {
	return Caps{Manages: e.has(adminapi.FeatureConsoleManages), Root: e.acc != nil}
}

// ctx is the context of one API call. Each call is bounded by the client's
// own timeout; the program's context ends the program, not a call in flight.
func ctx() context.Context { return context.Background() }
