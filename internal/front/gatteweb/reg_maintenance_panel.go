package gatteweb

import "net/http"

// Maintenance, as the revised IA places it (design/adr/0051, 0055): a toggle on
// each backend's own detail page, slot 40 in the DetailPanel registry. The panel
// draws nothing unless the backend lists FeatureMaintenance, and the handlers
// answer 404 the same way, so a POST that arrives anyway is not forwarded.
func init() {
	registerDetailPanel(DetailPanel{ID: "maintenance", Order: 40, Render: (*Front).maintenancePanel})
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("POST /servers/{name}/maintenance/on", f.maintenanceOn)
			mux.HandleFunc("POST /servers/{name}/maintenance/off", f.maintenanceOff)
		},
	})
}
