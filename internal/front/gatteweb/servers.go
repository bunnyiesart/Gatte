package gatteweb

// Tab 1 of the revised console (design/adr/0051, 0052): "MCP Servers / APIs".
// The noun for a backend is "MCP server / API". This file is the tab's shell:
// the list with per-backend health and a needs-review marker, the zero-JS
// /servers/new add page (REST API / OpenAPI -> generates MCP tools; stdio and
// oci stay CLI-only, design/adr/0050 §2, 0034), the register result page where
// signing is a separate attesting click (never sign-on-register, design/adr/0050
// §5), and the server-detail page.
//
// The server-detail page is a container: it draws the entry, its health and the
// operator actions (redial, sign, deregister), then ranges over the DetailPanel
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

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// serverBack is the detail page's path, for a result's Back link.
func serverBack(name string) string { return "/servers/" + url.PathEscape(name) }

// ---- the list

type serversData struct {
	Servers []serverRow
	// Health is FeatureBackendHealth: the list shows a per-backend state.
	Health bool
	// Manages is FeatureConsoleManages: the Add button.
	Manages bool
	// Reload offers the serve-control reload (FeatureConsoleManages and
	// FeatureServeControl).
	Reload bool
	// Gateway is the attention that names no backend (the gateway process not
	// reporting, a gateway-wide maintenance): shown above the list.
	Gateway []adminapi.Attention
}

// serverRow is one backend as the list shows it: the entry, and the reasons it
// needs the operator's attention, drawn from Overview.Attention
// (design/adr/0051 keeps "needs review" inside this tab).
type serverRow struct {
	adminapi.Upstream
	Attention []string
}

func (f *Front) serversPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.ListUpstreams(r.Context())
	me, _ := f.op.WhoAmI(r.Context())
	has := func(name string) bool { return slices.Contains(me.Features, name) }
	d := serversData{
		Health:  has(adminapi.FeatureBackendHealth),
		Manages: has(adminapi.FeatureConsoleManages),
		Reload:  has(adminapi.FeatureConsoleManages) && has(adminapi.FeatureServeControl),
	}

	// The backends that need attention, and why, keyed by name. A tool's
	// attention names its Server; a backend's own (unsigned, down, in
	// maintenance) names its Upstream.
	attn := map[string][]string{}
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	ov, overr := f.op.Overview(r.Context())
	if overr != nil {
		errs = append(errs, "attention: "+errText(overr))
	}
	for _, a := range ov.Attention {
		name := a.Upstream
		if name == "" {
			name = a.Server
		}
		if name == "" {
			d.Gateway = append(d.Gateway, a)
			continue
		}
		if !slices.Contains(attn[name], a.Title) {
			attn[name] = append(attn[name], a.Title)
		}
	}
	for _, u := range list.Upstreams {
		d.Servers = append(d.Servers, serverRow{Upstream: u, Attention: attn[u.Name]})
	}
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
	f.showResult(w, r, "servers", "Redial "+frontkit.VisibleText(name), serverBack(name), f.serveResult(res, err))
}

func (f *Front) serverSign(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	name := r.PathValue("name")
	res, err := f.acc.SignUpstream(r.Context(), name)
	f.showResult(w, r, "servers", "Attest "+frontkit.VisibleText(name), serverBack(name), signResult(res, err))
}

// serverRemove deregisters. The form makes the operator type the name; the
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

type serverNewData struct {
	Form      registerForm
	Root      bool
	AuthKinds []struct{ Value, Label string }
	MaxDocMiB int
}

func (f *Front) serverNewPage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	f.renderServerNew(w, r, registerForm{}, "")
}

// renderServerNew draws the add page; form and refusal are a register the
// backend refused, shown again as typed with its reason.
func (f *Front) renderServerNew(w http.ResponseWriter, r *http.Request, form registerForm, refusal string) {
	d := serverNewData{Form: form, Root: f.acc != nil, AuthKinds: authKinds, MaxDocMiB: adminapi.MaxUpstreamDocumentBytes >> 20}
	errMsg := ""
	if refusal != "" {
		errMsg = "Not registered: " + refusal
	}
	f.render(w, r, "server_new", "Add a REST API", page{Nav: "servers", Data: d, Error: errMsg})
}

// serverRegister registers an http backend from its OpenAPI document, then
// shows the result page. It does NOT sign: the signature attests that someone
// read the URL, where the key is injected and every operation, which the result
// page shows, and signing is a separate button there (design/adr/0050 §5,
// 0052 §3). stdio and oci are not offered here; they stay in the CLI.
func (f *Front) serverRegister(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	pf := r.PostForm
	form := registerForm{Name: strings.TrimSpace(pf.Get("name")), URL: strings.TrimSpace(pf.Get("url")),
		OpenAPIURL: strings.TrimSpace(pf.Get("openapi_url")), OpenAPIText: pf.Get("openapi_text"),
		AuthKind: pf.Get("auth_kind"), AuthName: strings.TrimSpace(pf.Get("auth_name")), KeyName: strings.TrimSpace(pf.Get("key_name")),
		GrantRole: strings.TrimSpace(pf.Get("grant_role"))}
	value := pf.Get("key_value")
	refuse := func(text string) {
		if strings.Contains(form.KeyName, "=") {
			form.KeyName = ""
		}
		f.renderServerNew(w, r, form, text)
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
