package gatteweb

import "net/http"

// Backends (registered upstreams). This page also hosts the maintenance and
// serve-control actions (reload, redial, serve requests), which act on
// backends and share the page, so they register here with it rather than in
// files of their own.
func init() {
	register(Section{
		Nav: NavItem{ID: "upstreams", Path: "/upstreams", Label: "Backends", Order: 60},
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /upstreams", f.upstreamsPage)
			mux.HandleFunc("GET /upstreams/show", f.upstreamShowPage)
			mux.HandleFunc("POST /upstreams/register", f.upstreamRegister)
			mux.HandleFunc("POST /upstreams/sign", f.upstreamSign)
			mux.HandleFunc("POST /upstreams/redial", f.upstreamRedial)
			mux.HandleFunc("POST /upstreams/remove", f.upstreamRemove)
			// Maintenance (shown on the backends page).
			mux.HandleFunc("POST /upstreams/maintenance/on", f.maintenanceOn)
			mux.HandleFunc("POST /upstreams/maintenance/off", f.maintenanceOff)
			// Serve control (reload and serve requests).
			mux.HandleFunc("POST /reload", f.reload)
			mux.HandleFunc("GET /serve-requests", f.serveRequestPage)
		},
	})
}
