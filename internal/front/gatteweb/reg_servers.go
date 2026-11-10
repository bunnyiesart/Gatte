package gatteweb

import "net/http"

// Tab 1 — "MCP Servers / APIs" (design/adr/0051, 0052). One of the two nav tabs
// the revised IA has; the shell owns it, and later Tab-1 slices add panels to
// the detail page through the DetailPanel registry (sections.go), not nav items.
func init() {
	register(Section{
		Nav: NavItem{ID: "servers", Path: "/servers", Label: "MCP Servers / APIs", Order: 10},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /servers", f.serversPage)
			mux.HandleFunc("GET /servers/new", f.serverNewPage)
			mux.HandleFunc("POST /servers", f.serverRegister)
			mux.HandleFunc("POST /servers/reload", f.serverReload)
			mux.HandleFunc("GET /servers/{name}", f.serverDetail)
			mux.HandleFunc("POST /servers/{name}/redial", f.serverRedial)
			mux.HandleFunc("POST /servers/{name}/sign", f.serverSign)
			mux.HandleFunc("POST /servers/{name}/remove", f.serverRemove)
			// The Refresh link of a reload or redial still pending.
			mux.HandleFunc("GET /serve-requests", f.serveRequestPage)
		},
	})
}
