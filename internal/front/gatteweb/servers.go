package gatteweb

// Tab 1 of the revised console (design/adr/0051, 0052): "MCP Servers / APIs".
// The noun for a backend is "MCP server / API". This file is the tab's shell:
// the list with per-backend health and a flag for a tool changed after its
// approval (no marker for pending tools, design/adr/0061 §3), the zero-JS
// /servers/new add page (a three-way choice, design/adr/0059: REST API /
// OpenAPI -> generates MCP tools, a remote MCP server by URL, and a container
// (oci) where the backend has podman; stdio stays CLI-only,
// design/adr/0034), the register result page
// where approving the configuration (signing it) is a separate click (never
// sign-on-register, design/adr/0050 §5), and the server-detail page.
//
// The server-detail page is a container: it draws the entry, its health and the
// operator actions (Approve configuration, Reconnect, Remove: the API's sign,
// redial and deregister, design/adr/0061 §2), then ranges over the DetailPanel
// registry (sections.go) and embeds each registered panel in order. The Tools,
// Secrets and Maintenance panels self-register from their own files; this
// shell owns only the mount points.
//
// Reads (list, detail) are the operator socket's. Registering, signing,
// removing and redialling are the management actions of design/adr/0050 and gate
// themselves through managed (manage.go); the page draws a form only when the
// backend serves them.

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// serverBack is the detail page's path, for a result's Back link.
func serverBack(name string) string { return "/servers/" + url.PathEscape(name) }

// ---- the list

type serversData struct {
	Servers []adminapi.Upstream
	// Health is FeatureBackendHealth: the list shows a per-backend state.
	Health bool
	// Manages is FeatureConsoleManages: the Add button. OCI is
	// FeatureOCIRegister: the add page also offers a container.
	Manages, OCI bool
	// Reload offers the serve-control reload (FeatureConsoleManages and
	// FeatureServeControl).
	Reload bool
	// Gateway is the attention that names no backend (the gateway process not
	// reporting, a gateway-wide maintenance): shown above the list. It is the
	// gateway's state, not audit data, so it stays (design/adr/0061 §3).
	Gateway []adminapi.Attention
	// Changed counts, per backend, the tools whose definition changed after
	// they were approved. A pending tool is not flagged here, but a changed
	// one is: it signals a definition swap (design/adr/0061 §3 annotation).
	Changed map[string]int
}

func (f *Front) serversPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.ListUpstreams(r.Context())
	me, _ := f.op.WhoAmI(r.Context())
	has := func(name string) bool { return slices.Contains(me.Features, name) }
	d := serversData{
		Health:  has(adminapi.FeatureBackendHealth),
		Manages: has(adminapi.FeatureConsoleManages),
		OCI:     has(adminapi.FeatureOCIRegister),
		Reload:  has(adminapi.FeatureConsoleManages) && has(adminapi.FeatureServeControl),
	}

	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	ov, overr := f.op.Overview(r.Context())
	if overr != nil {
		errs = append(errs, "gateway state: "+errText(overr))
	}
	// The changed-tool flag and the gateway notices come from these reads:
	// when one fails, say so, so a missing flag is never read as "nothing
	// changed". The overview's other parts are not shown on this page.
	for _, p := range ov.Problems {
		switch p.Part {
		case "tools":
			errs = append(errs, "tool state could not be read: "+p.Message)
		case "health":
			errs = append(errs, "backend health could not be read: "+p.Message)
		}
	}
	d.Changed = map[string]int{}
	for _, a := range ov.Attention {
		switch {
		case a.Kind == adminapi.AttentionChanged && a.Server != "":
			d.Changed[a.Server]++
		case a.Upstream == "" && a.Server == "":
			d.Gateway = append(d.Gateway, a)
		}
	}
	d.Servers = list.Upstreams
	f.render(w, r, "servers", "MCP Servers / APIs", page{Data: d, Error: strings.Join(errs, "\n")})
}

func (f *Front) serverReload(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureServeControl) {
		return
	}
	res, err := f.op.Reload(r.Context())
	f.showResult(w, r, "servers", "Reload the configuration", "/servers", f.serveResult(res, err))
}

// ---- the detail page (the container the Tab-1 panels plug into)

type serverDetailData struct {
	D adminapi.UpstreamDetail
	// Manages, Root and Redial decide the operator actions.
	Manages, Root, Redial bool
	Sensitive             int
	// Panels are the registered DetailPanel contributions, rendered in order
	// (sections.go).
	Panels []fragment
}

func (f *Front) serverDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	me, _ := f.op.WhoAmI(r.Context())
	has := func(n string) bool { return slices.Contains(me.Features, n) }
	caps := Capabilities{Manages: has(adminapi.FeatureConsoleManages), Root: f.acc != nil}
	d, err := f.upstreamDetail(r, name, caps.Manages)
	// Only a missing entry is a 404; a failed tools read on the operator path
	// still shows the entry, with the reason.
	if d.Name == "" && adminapi.IsCode(err, adminapi.CodeNotFound) {
		http.NotFound(w, r)
		return
	}
	data := serverDetailData{D: d, Manages: caps.Manages, Root: caps.Root, Redial: has(adminapi.FeatureServeControl)}
	for _, op := range d.Operations {
		if op.Class == adminapi.ClassSensitive {
			data.Sensitive++
		}
	}
	panels, perrs := f.detailPanels(r, caps, d)
	data.Panels = panels

	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	errs = append(errs, perrs...)
	title := frontkit.VisibleText(name)
	if d.Name != "" {
		title = frontkit.VisibleText(d.Name)
	}
	f.render(w, r, "server", title, page{Nav: "servers", Data: data, Error: strings.Join(errs, "\n")})
}

// upstreamDetail reads one backend for its page. GET /v1/upstreams/{name} is a
// management read (design/adr/0050), so a console without FeatureConsoleManages
// builds the same page from the operator reads instead -- the registry entry
// and its quarantine -- and the tool review and maintenance panels stay
// reachable; only the operations list and the management actions are absent.
func (f *Front) upstreamDetail(r *http.Request, name string, manages bool) (adminapi.UpstreamDetail, error) {
	if manages {
		return f.op.GetUpstream(r.Context(), name)
	}
	list, err := f.op.ListUpstreams(r.Context())
	if err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	i := slices.IndexFunc(list.Upstreams, func(u adminapi.Upstream) bool { return u.Name == name })
	if i < 0 {
		return adminapi.UpstreamDetail{}, &adminapi.Error{Status: http.StatusNotFound, Code: adminapi.CodeNotFound, Message: "no such backend"}
	}
	d := adminapi.UpstreamDetail{Upstream: list.Upstreams[i]}
	tools, err := f.op.ListTools(r.Context(), name, "")
	d.Tools = tools.Tools
	return d, err
}

// detailPanels renders every registered server-detail panel whose Show allows
// the request's capabilities, in order. A panel that fails to render is left
// out and its reason surfaced; the rest of the page still shows.
func (f *Front) detailPanels(r *http.Request, caps Capabilities, d adminapi.UpstreamDetail) ([]fragment, []string) {
	var out []fragment
	var errs []string
	for _, p := range orderedDetailPanels() {
		if p.Show != nil && !p.Show(caps) {
			continue
		}
		h, err := p.Render(f, r, d)
		if err != nil {
			errs = append(errs, p.ID+": "+err.Error())
			continue
		}
		out = append(out, fragment{ID: p.ID, HTML: h})
	}
	return out, errs
}

func (f *Front) serverRedial(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureServeControl) {
		return
	}
	name := r.PathValue("name")
	res, err := f.op.RedialUpstream(r.Context(), adminapi.RedialRequest{Upstream: name})
	f.showResult(w, r, "servers", "Reconnect "+frontkit.VisibleText(name), serverBack(name), f.serveResult(res, err))
}

func (f *Front) serverSign(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	name := r.PathValue("name")
	res, err := f.acc.SignUpstream(r.Context(), name)
	f.showResult(w, r, "servers", "Approve the configuration of "+frontkit.VisibleText(name), serverBack(name), signResult(res, err))
}

// serverRemove deregisters (the console's Remove). The form makes the operator type the name; the
// backend refuses a confirmation that does not repeat it (it drops the
// approvals with the entry, design/adr/0050 §2), so this front forwards what
// was typed and holds no rule of its own.
func (f *Front) serverRemove(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	name, confirm := r.PathValue("name"), r.PostForm.Get("confirm")
	res, err := f.op.DeregisterUpstream(r.Context(), name, confirm)
	back := "/servers"
	if err != nil {
		back = serverBack(name)
	}
	out := actionResult(res.ActionResult, err)
	if err == nil {
		out.Output = strings.TrimSpace(out.Output + fmt.Sprintf("\nRegistry entry removed: %t. Signature removed: %t. Quarantine entries removed: %d.", res.Registered, res.SignatureRemoved, res.ToolsForgotten))
	}
	f.showResult(w, r, "servers", "Remove "+frontkit.VisibleText(name), back, out)
}

// ---- the add page and the register result

// ociForm is what the Container (oci) form carries back after a refusal.
// EnvNames is the vault names as typed, comma- or space-separated.
type ociForm struct {
	Name, Image, Network, EnvNames string
}

// remoteForm is what the Remote MCP server form carries back after a
// refusal.
type remoteForm struct {
	Name, URL, AuthKind, AuthName, KeyName, RemoteKind string
}

// remoteAuthKinds are where a remote entry can send its one secret
// (design/adr/0058 §5): no query parameter, unlike a REST API.
var remoteAuthKinds = []struct{ Value, Label string }{
	{"none", "None (keyless)"},
	{"bearer", "Bearer token (Authorization header)"},
	{"header", "Header"},
}

// remoteKinds are the MCP client transports this build dials; the form
// shows the one there is so the operator sees what will be signed.
var remoteKinds = []struct{ Value, Label string }{
	{adminapi.RemoteKindStreamable, "Streamable HTTP"},
}

// Add-page kinds, the ?kind= of /servers/new.
const (
	kindREST   = "rest"
	kindRemote = "remote"
	kindOCI    = "oci"
)

type serverNewData struct {
	// Kind is the form drawn: kindREST, kindRemote or kindOCI.
	Kind       string
	Form       registerForm
	RemoteForm remoteForm
	OCIForm    ociForm
	// OCI: the backend lists FeatureOCIRegister, so the Container form is
	// offered. Without it (no podman, as on the Docker image) the choice is
	// not drawn at all (design/adr/0059 §3).
	OCI             bool
	Root            bool
	AuthKinds       []struct{ Value, Label string }
	RemoteAuthKinds []struct{ Value, Label string }
	RemoteKinds     []struct{ Value, Label string }
	MaxDocMiB       int
}

// ociUnavailable is what the add page says when the Container form is asked
// for and the backend does not offer it.
const ociUnavailable = "Container (oci) backends cannot be added here: they need podman on the gateway's host, and this one has none (the Docker image ships without it). Register them in the terminal on a host with podman: mcp-gateway upstream register -transport oci."

func (f *Front) serverNewPage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	d := f.newServerData(r, kindREST)
	switch r.URL.Query().Get("kind") {
	case kindRemote:
		d.Kind = kindRemote
	case kindOCI:
		if !d.OCI {
			f.renderServerNew(w, r, d, ociUnavailable)
			return
		}
		d.Kind = kindOCI
	}
	f.renderServerNew(w, r, d, "")
}

// newServerData is the add page's fixed part, for the form kind.
func (f *Front) newServerData(r *http.Request, kind string) serverNewData {
	return serverNewData{Kind: kind, OCI: f.feature(r.Context(), adminapi.FeatureOCIRegister), Root: f.acc != nil,
		AuthKinds: authKinds, RemoteAuthKinds: remoteAuthKinds, RemoteKinds: remoteKinds, MaxDocMiB: adminapi.MaxUpstreamDocumentBytes >> 20}
}

// renderServerNew draws the add page; errMsg, when set, is why a register
// was refused (the form shown again as typed) or why the page cannot offer
// what was asked.
func (f *Front) renderServerNew(w http.ResponseWriter, r *http.Request, d serverNewData, errMsg string) {
	title := "Add a REST API"
	switch d.Kind {
	case kindRemote:
		title = "Add a remote MCP server"
	case kindOCI:
		title = "Add a container (oci)"
	}
	f.render(w, r, "server_new", title, page{Nav: "servers", Data: d, Error: errMsg})
}

// serverRegister registers an http backend from its OpenAPI document, a
// remote one (transport=remote) or an oci one (transport=oci), then shows
// the result page. It does NOT sign: the signature records that someone read
// what the result page shows, and approving it is a separate button there
// (design/adr/0050 §5, 0052 §3, 0059 §6). stdio is not offered here; it
// stays in the CLI.
func (f *Front) serverRegister(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	pf := r.PostForm
	switch pf.Get("transport") {
	case adminapi.UpstreamTransportOCI:
		f.serverRegisterOCI(w, r)
		return
	case adminapi.UpstreamTransportRemote:
		f.serverRegisterRemote(w, r)
		return
	}
	form := registerForm{Name: strings.TrimSpace(pf.Get("name")), URL: strings.TrimSpace(pf.Get("url")),
		OpenAPIURL: strings.TrimSpace(pf.Get("openapi_url")), OpenAPIText: pf.Get("openapi_text"),
		AuthKind: pf.Get("auth_kind"), AuthName: strings.TrimSpace(pf.Get("auth_name")), KeyName: strings.TrimSpace(pf.Get("key_name")),
		GrantRole: strings.TrimSpace(pf.Get("grant_role"))}
	value := pf.Get("key_value")
	refuse := func(text string) {
		if strings.Contains(form.KeyName, "=") {
			form.KeyName = ""
		}
		d := f.newServerData(r, kindREST)
		d.Form = form
		f.renderServerNew(w, r, d, "Not registered: "+text)
	}

	doc, uploaded, err := documentFile(r)
	if err != nil {
		refuse("The uploaded OpenAPI file could not be read: " + err.Error())
		return
	}
	given := 0
	for _, g := range []bool{form.OpenAPIURL != "", strings.TrimSpace(form.OpenAPIText) != "", uploaded} {
		if g {
			given++
		}
	}
	if given > 1 {
		refuse("Give the OpenAPI document one way: a URL, pasted text or a file, not more than one.")
		return
	}
	if strings.TrimSpace(form.OpenAPIText) != "" {
		doc = form.OpenAPIText
	}
	if value != "" && f.acc == nil {
		refuse("Nothing was registered: the key's value is written to the vault through the accounts socket, and this console was started without it. Start it with sudo mcp-gateway ui -manage-users, or leave the value empty.")
		return
	}
	keyed := form.AuthKind == "bearer" || form.AuthKind == "header" || form.AuthKind == "query"
	if form.KeyName == "" && (keyed || (form.AuthKind == "" && value != "")) {
		form.KeyName = defaultKeyName(form.Name)
	}
	if value != "" && form.KeyName == "" {
		refuse("Nothing was registered: a key's value was given for an API registered without a key. Choose an auth kind, or leave the value empty.")
		return
	}
	req := adminapi.RegisterUpstreamRequest{Name: form.Name, URL: form.URL, OpenAPIURL: form.OpenAPIURL, OpenAPIDocument: doc,
		AuthKind: form.AuthKind, AuthName: form.AuthName, KeyName: form.KeyName}
	res, err := f.op.RegisterUpstream(r.Context(), req)
	if err != nil {
		refuse(errText(err))
		return
	}
	d := registered{Res: res, Root: f.acc != nil}
	for _, t := range res.Tools {
		if t.Class == adminapi.ClassSensitive {
			d.Sensitive++
		} else {
			d.Safe++
		}
	}
	d.Warnings = append(d.Warnings, res.IngestWarnings...)
	for _, wn := range res.Warnings {
		d.Warnings = append(d.Warnings, wn.Message)
	}
	out := append([]string{}, res.Messages...)
	if f.acc != nil {
		if value != "" {
			sr, serr := f.acc.SetSecret(r.Context(), req.KeyName, value)
			step := actionResult(sr.ActionResult, serr)
			d.SecretOK = step.OK
			d.Secret = "Writing " + req.KeyName + " to the vault: " + firstLine(step.Output)
			if step.OK {
				d.Secret = "Wrote the key's value to the vault under " + req.KeyName + "."
			}
			out = append(out, d.Secret)
		}
		if form.GrantRole != "" {
			d.Grant, d.GrantOK = f.grantBackend(r, form.GrantRole, res.Name)
			out = append(out, d.Grant)
		}
	}
	d.Output = strings.Join(out, "\n")
	d.ReviewAt = serverBack(res.Name)
	f.render(w, r, "server_registered", "Registered "+frontkit.VisibleText(res.Name), page{Nav: "servers", Data: d})
}

// serverRegisterRemote registers a native MCP server by its URL. The front
// only turns the form into the request: the URL, auth and remote-kind rules
// are the backend's (design/adr/0058 §4, 0059 §2).
func (f *Front) serverRegisterRemote(w http.ResponseWriter, r *http.Request) {
	pf := r.PostForm
	form := remoteForm{Name: strings.TrimSpace(pf.Get("name")), URL: strings.TrimSpace(pf.Get("url")),
		AuthKind: pf.Get("auth_kind"), AuthName: strings.TrimSpace(pf.Get("auth_name")),
		KeyName: strings.TrimSpace(pf.Get("key_name")), RemoteKind: pf.Get("remote_kind")}
	req := adminapi.RegisterUpstreamRequest{Name: form.Name, Transport: adminapi.UpstreamTransportRemote, URL: form.URL,
		AuthKind: form.AuthKind, AuthName: form.AuthName, KeyName: form.KeyName, RemoteKind: form.RemoteKind}
	if req.KeyName == "" && (req.AuthKind == "bearer" || req.AuthKind == "header") {
		req.KeyName = defaultKeyName(form.Name)
	}
	res, err := f.op.RegisterUpstream(r.Context(), req)
	if err != nil {
		// Nothing a vendor credential is pasted as is written back into the
		// page: a NAME=value as the key's name, a header line as the header's
		// name, or the URL's userinfo, query and fragment. A URL that does not
		// parse cannot be cleaned, so it is dropped.
		if strings.Contains(form.KeyName, "=") {
			form.KeyName = ""
		}
		if strings.ContainsFunc(form.AuthName, func(c rune) bool { return c == ':' || unicode.IsSpace(c) }) {
			form.AuthName = ""
		}
		if u, perr := url.Parse(form.URL); perr != nil {
			form.URL = ""
		} else {
			u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
			form.URL = u.String()
		}
		d := f.newServerData(r, kindRemote)
		d.RemoteForm = form
		f.renderServerNew(w, r, d, "Not registered: "+errText(err))
		return
	}
	d := registered{Res: res, Root: f.acc != nil, Output: strings.Join(res.Messages, "\n"), ReviewAt: serverBack(res.Name)}
	for _, wn := range res.Warnings {
		d.Warnings = append(d.Warnings, wn.Message)
	}
	f.render(w, r, "server_registered", "Registered "+frontkit.VisibleText(res.Name), page{Nav: "servers", Data: d})
}

// serverRegisterOCI registers a container from its pinned image. The front
// only turns the form into the request: the digest pin, the network
// allowlist, the variable names' grammar and the podman gate are the
// backend's (design/adr/0059 §2, §4).
func (f *Front) serverRegisterOCI(w http.ResponseWriter, r *http.Request) {
	pf := r.PostForm
	form := ociForm{Name: strings.TrimSpace(pf.Get("name")), Image: strings.TrimSpace(pf.Get("image")),
		Network: strings.TrimSpace(pf.Get("network")), EnvNames: strings.TrimSpace(pf.Get("env_var_names"))}
	req := adminapi.RegisterUpstreamRequest{Name: form.Name, Transport: adminapi.UpstreamTransportOCI, Image: form.Image,
		EnvVarNames: strings.FieldsFunc(form.EnvNames, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })}
	// none is the default by omission, as the CLI writes it without -arg;
	// any other policy is signed in the entry's args.
	if form.Network != "" && form.Network != "none" {
		req.Args = []string{"--network=" + form.Network}
	}
	res, err := f.op.RegisterUpstream(r.Context(), req)
	if err != nil {
		if strings.Contains(form.EnvNames, "=") {
			// A NAME=value pasted as a name is not written back into the page.
			form.EnvNames = ""
		}
		d := f.newServerData(r, kindOCI)
		d.OCIForm = form
		if !d.OCI {
			// Refused because the backend does not offer it (no podman):
			// say why over the REST form, never a Container form that
			// cannot work here.
			d.Kind = kindREST
		}
		f.renderServerNew(w, r, d, "Not registered: "+errText(err))
		return
	}
	d := registered{Res: res, Root: f.acc != nil, Output: strings.Join(res.Messages, "\n"), ReviewAt: serverBack(res.Name)}
	for _, wn := range res.Warnings {
		d.Warnings = append(d.Warnings, wn.Message)
	}
	f.render(w, r, "server_registered", "Registered "+frontkit.VisibleText(res.Name), page{Nav: "servers", Data: d})
}
