package gatteweb

import "net/http"

// The Help page: the terminal commands, what the console's words mean, and
// which docs to read. It is static text, so the pages themselves can stay
// free of explanations; the header links to it from every page.
func init() {
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("GET /help", func(w http.ResponseWriter, r *http.Request) {
				f.render(w, r, "help", "Help", page{Nav: "help"})
			})
		},
	})
}
