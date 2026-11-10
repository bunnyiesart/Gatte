package gatteweb

// Tab 2 of the revised console (design/adr/0051): "Users". One page, several
// sections, each with its own socket gate: People/accounts (root), Roles
// (accounts socket), Blocklist (operator socket). People and Blocklist stay
// distinct, because disabling an account is not blocking a subject
// (design/adr/0038).
//
// This file is the tab's container: it ranges over the UsersSection registry
// (sections.go) and embeds each registered section in order. The People, Roles
// and Blocklist sections are later slices (M1.4a/M1.5/M1.4b) that
// self-register; this shell owns only the mount points.

import (
	"net/http"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

type usersData struct {
	// Sections are the registered UsersSection contributions, rendered in
	// order (sections.go). Empty in this slice: the sections are later slices.
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
