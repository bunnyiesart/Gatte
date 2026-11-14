package gatteweb

import "net/http"

// People: the identity provider's accounts (design/adr/0038), as a section of
// the Users tab (design/adr/0051), with the account detail, the Add-a-person
// assistant and the connect script (design/adr/0039) as its own sub-pages.
//
// Account edits are the accounts socket's (-manage-users, design/adr/0040 §1):
// the section draws them only with it, and every handler gates the same, so a
// console without it answers 404 for the sub-pages and the actions.
//
// Disabling an account is not blocking a subject (design/adr/0038): disable
// stops new sign-ins and lives here; the block that cuts an already-issued
// token is part of Offboard here, or the CLI's `access block`
// (design/adr/0061 §4).
func init() {
	registerUsersSection(UsersSection{ID: "people", Order: 10, Render: (*Front).peopleSection})
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /people/account", f.accountPage)
			mux.HandleFunc("GET /people/new", f.newPersonPage)
			mux.HandleFunc("GET /people/new/access", f.newPersonPage)
			mux.HandleFunc("GET /people/new/review", f.newPersonPage)
			mux.HandleFunc("GET /people/connect", f.connectPage)
			mux.HandleFunc("GET /people/connect/script", f.connectScript)
			mux.HandleFunc("POST /people/add", f.accountAdd)
			mux.HandleFunc("POST /people/groups", f.accountGroups)
			mux.HandleFunc("GET /people/disable", f.accountDisableConfirm)
			mux.HandleFunc("POST /people/disable", f.accountDisable)
			mux.HandleFunc("POST /people/enable", f.accountEnable)
			mux.HandleFunc("POST /people/reset", f.accountReset)
			mux.HandleFunc("GET /people/offboard", f.accountOffboardConfirm)
			mux.HandleFunc("POST /people/offboard", f.accountOffboard)
			mux.HandleFunc("POST /people/delete", f.accountDelete)
		},
	})
}
