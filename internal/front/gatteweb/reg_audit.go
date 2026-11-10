package gatteweb

import "net/http"

// Audit (the trail and its verification).
func init() {
	register(Section{
		Nav: NavItem{ID: "audit", Path: "/audit", Label: "Audit", Order: 50},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /audit", f.auditPage)
			mux.HandleFunc("GET /audit/export", f.auditExport)
			mux.HandleFunc("POST /audit/verify", f.auditVerify)
		},
	})
}
