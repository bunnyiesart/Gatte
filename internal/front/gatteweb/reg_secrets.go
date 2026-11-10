package gatteweb

import "net/http"

// Secrets (the vault). The nav link shows only on the managing console with the
// accounts socket; the routes are always mounted and the handlers gate
// themselves (manage.go).
func init() {
	register(Section{
		Nav: NavItem{ID: "secrets", Path: "/secrets", Label: "Secrets", Order: 70, Show: managesAndRoot},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /secrets", f.secretsPage)
			mux.HandleFunc("POST /secrets/set", f.secretSet)
			mux.HandleFunc("POST /secrets/delete", f.secretDelete)
		},
	})
}
