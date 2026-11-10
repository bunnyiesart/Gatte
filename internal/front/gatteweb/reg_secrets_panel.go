package gatteweb

import "net/http"

// Secrets, as the revised two-tab IA places them (design/adr/0051, 0053): a
// panel on the server-detail page for the names one backend declares, and a
// small global vault view for the names shared across backends or declared by
// none. This slice adds no standalone Secrets nav entry: the panel
// self-registers into the DetailPanel registry (sections.go) and the global view
// mounts its own routes without a nav item (it is reached from the panel).
//
// The whole surface is gated to managesAndRoot: the console must list
// FeatureConsoleManages and hold the accounts socket. The vault lives on the
// accounts socket, so both the reads (ListSecrets) and the writes (SetSecret,
// DeleteSecret) go to it as root, and a value is never returned or rendered
// (design/adr/0050 §2). The handlers gate themselves again, so a POST that
// arrives without the capability is not forwarded.
func init() {
	registerDetailPanel(DetailPanel{ID: "secrets", Order: 30, Show: managesAndRoot, Render: (*Front).secretsPanel})
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			// The per-server panel's writes, scoped to the backend's page.
			mux.HandleFunc("POST /servers/{name}/secrets/set", f.serverSecretSet)
			mux.HandleFunc("POST /servers/{name}/secrets/delete", f.serverSecretDelete)
			// The global vault view and its writes.
			mux.HandleFunc("GET /vault", f.vaultView)
			mux.HandleFunc("POST /vault/set", f.vaultSecretSet)
			mux.HandleFunc("POST /vault/delete", f.vaultSecretDelete)
		},
	})
}
