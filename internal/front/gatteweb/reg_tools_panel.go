package gatteweb

import (
	"html/template"
	"net/http"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Tools, the quarantine, as Tab-1's server-detail panel (design/adr/0051: the
// revised IA drops the standalone Tools tab and shows each backend's tools on
// its own detail page). This slice self-registers two things from here and owns
// nothing of the shell:
//
//   - a DetailPanel at slot 20 (the surface map's planned order), which draws the
//     backend's tools inline on /servers/{name}; and
//   - a Section with no nav link, which mounts the per-tool review and the
//     approve / revoke / clear / review-set / approve-set routes under the
//     server's own path.
//
// Every gate stays in the API (design/adr/0047/0048): generated tools are
// pending until approved, approval binds to the exact fingerprint shown
// (design/adr/0040 §3, 0032), and a sensitive (non-GET) tool needs clear plus a
// non_read role before it is served. The panel and its pages only render what
// the backend answers and confirm before sending.
func init() {
	registerDetailPanel(DetailPanel{
		ID:    "tools",
		Order: 20,
		Render: func(f *Front, r *http.Request, d adminapi.UpstreamDetail) (template.HTML, error) {
			return f.toolsPanel(r, d)
		},
	})
	register(Section{
		// No Nav: the tools live inside the server-detail page, not the top nav.
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /servers/{name}/tools/review-set", f.serverToolReviewSet)
			mux.HandleFunc("POST /servers/{name}/tools/approve-set", f.serverToolApproveSet)
			mux.HandleFunc("GET /servers/{name}/tools/{tool}", f.serverToolReview)
			mux.HandleFunc("POST /servers/{name}/tools/{tool}/approve", f.serverToolApprove)
			mux.HandleFunc("POST /servers/{name}/tools/{tool}/revoke", f.serverToolRevoke)
			mux.HandleFunc("POST /servers/{name}/tools/{tool}/clear", f.serverToolClear)
		},
	})
}
