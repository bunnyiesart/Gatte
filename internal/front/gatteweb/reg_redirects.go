package gatteweb

import (
	"net/http"
	"net/url"
)

// The console root and the paths of the pages the two-tab IA replaced
// (design/adr/0051) answer with a redirect to where that content lives now, so
// the login link and an old bookmark still land on a page. Audit and Quota have
// no successor in the console (design/adr/0056, 0057) and answer 404.
func init() {
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			to := func(path string) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, f.kit.Base()+path, http.StatusSeeOther)
				}
			}
			mux.HandleFunc("GET /{$}", to("/servers"))
			mux.HandleFunc("GET /upstreams", to("/servers"))
			mux.HandleFunc("GET /secrets", to("/vault"))
			mux.HandleFunc("GET /roles", to("/users"))
			mux.HandleFunc("GET /upstreams/show", func(w http.ResponseWriter, r *http.Request) {
				path := "/servers"
				if name := r.URL.Query().Get("name"); name != "" {
					path += "/" + url.PathEscape(name)
				}
				to(path)(w, r)
			})
		},
	})
}
