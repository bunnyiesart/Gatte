package gatteweb

// Tab 2 of the revised console (design/adr/0051): "Users". One page, two
// sections, each with its own socket gate: People/accounts (root) and Roles
// (accounts socket). Blocking a subject is not on this tab: it stays in the
// CLI (design/adr/0061 §4), and Offboard places the block it needs.
//
// This file is the tab's container: it ranges over the UsersSection registry
// (sections.go) and embeds each registered section in order; each section
// self-registers from its own file.

import (
	"net/http"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

type usersData struct {
	// Sections are the registered UsersSection contributions, rendered in
	// order (sections.go).
	Sections []fragment
	Root     bool
}

func (f *Front) usersPage(w http.ResponseWriter, r *http.Request) {
	me, _ := f.op.WhoAmI(r.Context())
	caps := Capabilities{Manages: slices.Contains(me.Features, adminapi.FeatureConsoleManages), Root: f.acc != nil}
	secs, errs := f.usersSections(r, caps)
	f.render(w, r, "users", "Users", page{Data: usersData{Sections: secs, Root: caps.Root}, Error: strings.Join(errs, "\n")})
}

// usersSections renders every registered Users section whose Show allows the
// request's capabilities, in order. A section that fails to render is left out
// and its reason surfaced; the rest of the page still shows.
func (f *Front) usersSections(r *http.Request, caps Capabilities) ([]fragment, []string) {
	var out []fragment
	var errs []string
	for _, s := range orderedUsersSections() {
		if s.Show != nil && !s.Show(caps) {
			continue
		}
		h, err := s.Render(f, r)
		if err != nil {
			errs = append(errs, s.ID+": "+err.Error())
			continue
		}
		out = append(out, fragment{ID: s.ID, HTML: h})
	}
	return out, errs
}
