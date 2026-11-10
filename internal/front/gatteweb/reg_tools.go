package gatteweb

import "net/http"

// Tools (the quarantine).
func init() {
	register(Section{
		Nav: NavItem{ID: "tools", Path: "/tools", Label: "Tools", Order: 20},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /tools", f.toolsPage)
			mux.HandleFunc("GET /tools/show", f.toolShowPage)
			mux.HandleFunc("POST /tools/approve", f.toolApprove)
			mux.HandleFunc("GET /tools/review-set", f.reviewSetPage)
			mux.HandleFunc("POST /tools/approve-set", f.toolApproveSet)
			mux.HandleFunc("POST /tools/revoke", f.toolRevoke)
			mux.HandleFunc("POST /tools/clear", f.toolClear)
		},
	})
}
