package gatteweb

import "net/http"

// Access (the blocklist).
func init() {
	register(Section{
		Nav: NavItem{ID: "access", Path: "/access", Label: "Access", Order: 40},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /access", f.accessPage)
			mux.HandleFunc("POST /access/block", f.accessBlock)
			mux.HandleFunc("POST /access/unblock", f.accessUnblock)
		},
	})
}
