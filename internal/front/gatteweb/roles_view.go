package gatteweb

// The read-only Roles view of the Users tab: each role, the groups that map to
// it and the tools it reaches, as the operator socket reports them (People).
// It fills the Roles slot whenever the editable role×tool matrix
// (roles_panel.go) does not show — that one needs the managing console and the
// accounts socket (design/adr/0054) — so an operator without them still sees
// who gets what, and can change nothing from here.

import (
	"html/template"
	"net/http"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// rolesViewData is the read-only Roles section. Error is a failed read, shown
// inline in place of the list.
type rolesViewData struct {
	Roles []adminapi.Role
	Error string
}

func (f *Front) rolesViewSection(r *http.Request) (template.HTML, error) {
	var d rolesViewData
	if p, err := f.op.People(r.Context()); err != nil {
		d.Error = errText(err)
	} else {
		d.Roles = p.Roles
	}
	return f.renderFragment("section_roles_view.html", d)
}
