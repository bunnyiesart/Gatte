package gatteweb

import "net/http"

// Quota (per-analyst spend).
func init() {
	register(Section{
		Nav: NavItem{ID: "quota", Path: "/quota", Label: "Quota", Order: 90},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /quota", f.quotaPage)
		},
	})
}
