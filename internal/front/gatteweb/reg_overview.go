package gatteweb

import "net/http"

// Overview (the dashboard / landing page).
func init() {
	register(Section{
		Nav: NavItem{ID: "overview", Path: "/", Label: "Overview", Order: 10},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /{$}", f.overview)
		},
	})
}
