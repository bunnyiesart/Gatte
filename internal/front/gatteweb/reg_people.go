package gatteweb

import "net/http"

// People (identity-provider accounts and connect instructions).
func init() {
	register(Section{
		Nav: NavItem{ID: "people", Path: "/people", Label: "People", Order: 30},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /people", f.peoplePage)
			mux.HandleFunc("GET /people/account", f.accountPage)
			mux.HandleFunc("GET /people/new", f.newPersonPage)
			mux.HandleFunc("GET /people/new/access", f.newPersonPage)
			mux.HandleFunc("GET /people/new/review", f.newPersonPage)
			mux.HandleFunc("GET /people/connect", f.connectPage)
			mux.HandleFunc("GET /people/connect/script", f.connectScript)
			mux.HandleFunc("POST /people/add", f.accountAdd)
			mux.HandleFunc("POST /people/groups", f.accountGroups)
			mux.HandleFunc("POST /people/disable", f.accountDisable)
			mux.HandleFunc("POST /people/enable", f.accountEnable)
			mux.HandleFunc("POST /people/reset", f.accountReset)
			mux.HandleFunc("POST /people/offboard", f.accountOffboard)
			mux.HandleFunc("POST /people/delete", f.accountDelete)
		},
	})
}
