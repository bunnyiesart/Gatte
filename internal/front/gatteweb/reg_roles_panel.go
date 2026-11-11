package gatteweb

import "net/http"

// Roles section of the Users tab (design/adr/0051, 0054), slot 20 in the
// UsersSection registry (sections.go: People 10, Roles 20). It
// self-registers, so adding it edits no shared file and no shell.
//
// Two registrations, from this one init(): the UsersSection that lists the
// roles on the Users page, and a route-only Section (no nav link) that mounts
// each role's page and the POST actions. Both need the managing console and
// the accounts socket, so the section's Show is managesAndRoot and each
// handler gates through managed(..., true).
func init() {
	registerUsersSection(UsersSection{
		ID:     "roles",
		Order:  20,
		Show:   managesAndRoot,
		Render: (*Front).rolesPanelFragment,
	})
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /users/roles/view", f.rolePage)
			mux.HandleFunc("POST /users/roles/edit", f.rolesEdit)
			mux.HandleFunc("POST /users/roles/non-read", f.rolesNonRead)
		},
	})
}
