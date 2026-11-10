package gatteweb

import "net/http"

// Tab 2 — "Users" (design/adr/0051). The second of the two nav tabs the revised
// IA has; the shell owns it, and later Tab-2 slices add sections through the
// UsersSection registry (sections.go), not nav items.
func init() {
	register(Section{
		Nav: NavItem{ID: "users", Path: "/users", Label: "Users", Order: 35},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /users", f.usersPage)
		},
	})
}
