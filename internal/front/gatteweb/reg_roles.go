package gatteweb

import "net/http"

// Roles (the roles file). The nav link shows only on the managing console with
// the accounts socket; the routes are always mounted and the handlers gate
// themselves (manage.go).
func init() {
	register(Section{
		Nav: NavItem{ID: "roles", Path: "/roles", Label: "Roles", Order: 80, Show: managesAndRoot},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /roles", f.rolesPage)
			mux.HandleFunc("POST /roles", f.rolesApply)
		},
	})
}
