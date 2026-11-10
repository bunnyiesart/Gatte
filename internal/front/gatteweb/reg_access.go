package gatteweb

import "net/http"

// Blocklist: the subjects the gateway refuses, as a section of the Users tab
// (design/adr/0051), on the operator socket (design/adr/0031). Blocking a
// subject cuts off an already-issued token; it is a separate action from
// disabling an account, which only stops new sign-ins (design/adr/0038). The
// two stay distinct, each its own section of this tab.
func init() {
	registerUsersSection(UsersSection{ID: "blocklist", Order: 30, Render: (*Front).blocklistSection})
	register(Section{
		Mount: func(mux *http.ServeMux, f *Front) {
			mux.HandleFunc("POST /access/block", f.accessBlock)
			mux.HandleFunc("POST /access/unblock", f.accessUnblock)
		},
	})
}
