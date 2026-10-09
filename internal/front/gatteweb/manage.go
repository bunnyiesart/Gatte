package gatteweb

// The console manages everything (design/adr/0050): http backends
// registered, signed, redialled and removed, a sensitive tool cleared, the
// vault's values and the roles file written, and the configuration
// reloaded -- each a call of the management API, behind [admin]
// console_manages.
//
// Every screen here exists only while the backend lists
// FeatureConsoleManages: without it nothing new is drawn and every route
// below answers 404, as the account pages do without -manage-users. What
// needs root's key or the vault -- signing, the secrets and the roles --
// is the accounts socket's, and exists only with -manage-users.
//
// A secret's value enters through a password field and goes to the
// accounts socket once. It is never put back into a page, a redirect or an
// error: a result names the secret, never what it holds.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// feature reports whether the operator socket's backend lists name. A
// backend that does not answer lists nothing optional.
func (f *Front) feature(ctx context.Context, name string) bool {
	me, err := f.op.WhoAmI(ctx)
	return err == nil && slices.Contains(me.Features, name)
}

// managed answers 404 and reports false when the backend does not list
// FeatureConsoleManages, or, with root, when the console was not given the
// accounts socket: the page draws no form then, and a POST that arrives
// anyway is not forwarded.
func (f *Front) managed(w http.ResponseWriter, r *http.Request, root bool, also ...string) bool {
	me, err := f.op.WhoAmI(r.Context())
	ok := err == nil && slices.Contains(me.Features, adminapi.FeatureConsoleManages) && (!root || f.acc != nil)
	for _, feat := range also {
		ok = ok && slices.Contains(me.Features, feat)
	}
	if !ok {
		http.NotFound(w, r)
	}
	return ok
}

// ---- registering an http backend

// registerForm is what the Add an API form carries back after a refusal,
// so nothing typed is lost -- except the key's value, which is never
// written into a page, and the file, which a browser cannot be handed back.
type registerForm struct {
	Name, URL, OpenAPIURL, OpenAPIText string
	AuthKind, AuthName, KeyName        string
	// GrantRole, when set, gets NAME = ["*"] under its [role.grants]: every
	// SAFE tool of the API once approved, as `gatte api add` does. Empty
	// grants nothing.
	GrantRole string
}

// authKinds are the form's choices, the empty one first: derive the
// descriptor from the document's securitySchemes.
var authKinds = []struct{ Value, Label string }{
	{"", "Derive from the document"},
	{"none", "None (keyless)"},
	{"bearer", "Bearer token (Authorization header)"},
	{"header", "Header"},
	{"query", "Query parameter"},
}

// defaultKeyName is the vault name a keyed API gets when the form leaves it
// empty: the backend name in capitals, then _API_KEY, as an environment
// variable name.
func defaultKeyName(name string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(strings.TrimSpace(name)) {
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	return s + "_API_KEY"
}

// documentFile reads the uploaded OpenAPI file, if one was sent, up to the
// ingestion's bound (one byte over says it is over).
func documentFile(r *http.Request) (string, bool, error) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["openapi_file"]) == 0 {
		return "", false, nil
	}
	fh := r.MultipartForm.File["openapi_file"][0]
	if fh.Size == 0 && fh.Filename == "" {
		// The browser sends an empty part for a file input left empty.
		return "", false, nil
	}
	file, err := fh.Open()
	if err != nil {
		return "", true, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, adminapi.MaxUpstreamDocumentBytes+1))
	if err != nil {
		return "", true, err
	}
	if len(b) > adminapi.MaxUpstreamDocumentBytes {
		return "", true, fmt.Errorf("the file is over the %d-byte limit the ingestion reads", adminapi.MaxUpstreamDocumentBytes)
	}
	return string(b), true, nil
}

// registered is the page after an API is registered: the ingestion's
// report, and what the console did next in the same action -- the key
// written to the vault and the entry signed, with -manage-users.
type registered struct {
	Res adminapi.RegisterUpstreamResult
	// Safe and Sensitive count the tools by class.
	Safe, Sensitive int
	// Warnings are the ingestion's and the backend's, in that order.
	Warnings []string
	Output   string
	// Root: the console holds the accounts socket.
	Root bool
	// Secret is what writing the key did, empty when no value was given.
	Secret   string
	SecretOK bool
	// Signed is what signing did; Sign is empty without -manage-users.
	Sign   string
	SignOK bool
	Signed bool
	// Grant is what granting the API to a role did, empty when no role
	// was named.
	Grant    string
	GrantOK  bool
	ReviewAt string
}

func (f *Front) upstreamRegister(w http.ResponseWriter, r *http.Request) {
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
			// NAME=value pasted as the name: the value is not written back
			// into the page (the backend's refusal does not repeat it
			// either).
			form.KeyName = ""
		}
		f.renderUpstreams(w, r, form, text)
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
			sr, err := f.acc.SetSecret(r.Context(), req.KeyName, value)
			step := actionResult(sr.ActionResult, err)
			d.SecretOK = step.OK
			d.Secret = "Writing " + req.KeyName + " to the vault: " + firstLine(step.Output)
			if step.OK {
				d.Secret = "Wrote the key's value to the vault under " + req.KeyName + "."
			}
			out = append(out, d.Secret)
		}
		// Not signed here: the signature attests that someone looked at
		// the URL, where the key is injected and every operation, and this
		// page is where they are shown. Signing is the button on it
		// (design/adr/0050; found in review: signing in the same click as
		// registering attested nothing).
		if form.GrantRole != "" {
			d.Grant, d.GrantOK = f.grantBackend(r, form.GrantRole, res.Name)
			out = append(out, d.Grant)
		}
	}
	d.Output = strings.Join(out, "\n")
	d.ReviewAt = "/tools?server=" + url.QueryEscape(res.Name)
	if f.feature(r.Context(), adminapi.FeatureToolReviewSet) {
		d.ReviewAt = "/tools/review-set?server=" + url.QueryEscape(res.Name)
	}
	f.render(w, r, "registered", "Registered "+frontkit.VisibleText(res.Name), page{Nav: "upstreams", Data: d})
}

// signResult is the result of a sign: done, and whether the key that made
// it is one the gateway trusts.
// grantBackend puts `"BACKEND" = ["*"]` in role's [role.grants], through
// the same PUT /v1/roles the Roles page uses, so the backend's validation
// decides (design/adr/0050 §2), then reloads. The front only edits text.
func (f *Front) grantBackend(r *http.Request, role, backend string) (string, bool) {
	cur, err := f.acc.GetRoles(r.Context())
	if err != nil {
		return "Not granted to " + role + ": " + firstLine(errText(err)), false
	}
	text, status := insertGrant(cur.Text, role, backend)
	switch status {
	case grantPresent:
		return "Role " + role + " already grants " + backend + ".", true
	case grantNoRole:
		return "Not granted: no [[role]] named " + role + " in the roles file. Add the grant on the Roles page.", false
	}
	if _, err := f.acc.PutRoles(r.Context(), text); err != nil {
		return "Not granted to " + role + ": " + firstLine(errText(err)), false
	}
	q, err := f.op.Reload(r.Context())
	reload := f.serveResult(q, err)
	if !reload.OK {
		return "Granted to " + role + " in the roles file; " + reload.Summary, false
	}
	return "Role " + role + " may call every safe tool of " + backend + " once you approve it.", true
}

type grantStatus int

const (
	grantAdded grantStatus = iota
	grantPresent
	grantNoRole
)

// insertGrant adds `"backend" = ["*"]` to the [role.grants] of the [[role]]
// whose name is role: under an existing [role.grants] header of that block,
// or in a new one after the block's last line. It reads TOML only as far as
// headers and `name = "..."` lines; whatever it writes is validated by the
// backend before it is kept.
func insertGrant(text, role, backend string) (string, grantStatus) {
	lines := strings.Split(text, "\n")
	start, end, grants := -1, len(lines), -1
	inRole := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			if start >= 0 && (t == "[[role]]" || !strings.HasPrefix(t, "[role.")) {
				end = i
				break
			}
			if t == "[[role]]" {
				inRole = true
				continue
			}
			if !strings.HasPrefix(t, "[role.") {
				inRole = false
			}
			if start >= 0 && t == "[role.grants]" {
				grants = i
			}
			continue
		}
		if inRole && start < 0 {
			if k, v, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == "name" && strings.Trim(strings.TrimSpace(v), "\"") == role {
				start = i
			}
		}
	}
	if start < 0 {
		return text, grantNoRole
	}
	line := fmt.Sprintf("%q = [\"*\"]", backend)
	if grants >= 0 {
		for _, l := range lines[grants+1 : end] {
			if k, _, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.Trim(strings.TrimSpace(k), "\"") == backend {
				return text, grantPresent
			}
		}
		out := append(append(append([]string{}, lines[:grants+1]...), line), lines[grants+1:]...)
		return strings.Join(out, "\n"), grantAdded
	}
	last := start
	for i := start; i < end; i++ {
		if t := strings.TrimSpace(lines[i]); t != "" && !strings.HasPrefix(t, "#") {
			last = i
		}
	}
	out := append(append(append([]string{}, lines[:last+1]...), "[role.grants]", line), lines[last+1:]...)
	return strings.Join(out, "\n"), grantAdded
}

func signResult(res adminapi.SignResult, err error) result {
	out := actionResult(res.ActionResult, err)
	if err != nil {
		out.Summary = "Not signed: " + out.Summary
		return out
	}
	if res.KeyFingerprint != "" {
		out.Output = strings.TrimSpace(out.Output + "\nSigning key: " + res.KeyFingerprint)
	}
	switch {
	case !out.OK:
	case res.Trusted:
		out.Summary = "Signed with a trusted key."
	default:
		out.OK, out.Summary = false, "Signed, with a key that is not in signer.trusted_keys: the gateway will not serve it until that key is trusted."
	}
	return out
}

// ---- one backend

type backendDetail struct {
	D adminapi.UpstreamDetail
	// Root: signing is available (-manage-users).
	Root bool
	// Redial: the backend serves serve_control.
	Redial    bool
	Sensitive int
}

func (f *Front) upstreamShowPage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	name := r.URL.Query().Get("name")
	d, err := f.op.GetUpstream(r.Context(), name)
	if adminapi.IsCode(err, adminapi.CodeNotFound) {
		http.NotFound(w, r)
		return
	}
	data := backendDetail{D: d, Root: f.acc != nil, Redial: f.feature(r.Context(), adminapi.FeatureServeControl)}
	for _, op := range d.Operations {
		if op.Class == adminapi.ClassSensitive {
			data.Sensitive++
		}
	}
	title := frontkit.VisibleText(name)
	if d.Name != "" {
		title = frontkit.VisibleText(d.Name)
	}
	f.render(w, r, "upstream", title, page{Nav: "upstreams", Data: data, Error: errText(err)})
}

func showBack(name string) string { return "/upstreams/show?name=" + url.QueryEscape(name) }

func (f *Front) upstreamSign(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	name := r.PostForm.Get("name")
	res, err := f.acc.SignUpstream(r.Context(), name)
	f.showResult(w, r, "upstreams", "Sign "+frontkit.VisibleText(name), showBack(name), signResult(res, err))
}

func (f *Front) upstreamRedial(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureServeControl) {
		return
	}
	name := r.PostForm.Get("name")
	res, err := f.op.RedialUpstream(r.Context(), adminapi.RedialRequest{Upstream: name})
	f.showResult(w, r, "upstreams", "Redial "+frontkit.VisibleText(name), showBack(name), f.serveResult(res, err))
}

// upstreamRemove deregisters. The form makes the operator type the name;
// the backend refuses a confirmation that does not repeat it, so this
// front forwards what was typed and holds no rule of its own.
func (f *Front) upstreamRemove(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false) {
		return
	}
	name, confirm := r.PostForm.Get("name"), r.PostForm.Get("confirm")
	res, err := f.op.DeregisterUpstream(r.Context(), name, confirm)
	back := "/upstreams"
	if err != nil {
		back = showBack(name)
	}
	out := actionResult(res.ActionResult, err)
	if err == nil {
		out.Output = strings.TrimSpace(out.Output + fmt.Sprintf("\nRegistry entry removed: %t. Signature removed: %t. Quarantine entries removed: %d.", res.Registered, res.SignatureRemoved, res.ToolsForgotten))
	}
	f.showResult(w, r, "upstreams", "Remove "+frontkit.VisibleText(name), back, out)
}

// ---- requests to the gateway process: reload and redial

// serveResult is a reload's or a redial's answer as `mcp-gateway reload`
// prints it; a pending one links to the page that reads it again.
func (f *Front) serveResult(q adminapi.ServeRequest, err error) result {
	if err != nil {
		text := errText(err)
		return result{Summary: firstLine(text), Output: text}
	}
	what := "The reload"
	if q.Kind == adminapi.ServeKindRedial {
		what = "The redial of " + frontkit.VisibleText(q.Upstream)
	}
	var out []string
	r := result{}
	switch {
	case q.State != adminapi.ServeStateDone:
		r.Summary = fmt.Sprintf("%s (request %d) is pending: the gateway was rung and has not answered yet.", what, q.ID)
		r.Refresh = f.kit.Base() + "/serve-requests?id=" + strconv.FormatInt(q.ID, 10)
	case q.Outcome == adminapi.ServeOutcomeApplied:
		r.OK, r.Summary = true, "Done."
		out = append(out, fmt.Sprintf("%s (request %d) was applied.", what, q.ID))
	default:
		r.Summary = fmt.Sprintf("%s (request %d) was refused (%s); what was in force stays in force.", what, q.ID, q.Refusal)
	}
	if c := q.Reload; c != nil {
		for _, ch := range c.Roles {
			label := ""
			switch {
			case ch.Added:
				label = " (new role)"
			case ch.Removed:
				label = " (role removed)"
			}
			out = append(out, "role "+ch.Role+label)
			for _, t := range ch.Gained {
				out = append(out, "  + "+t)
			}
			for _, t := range ch.Lost {
				out = append(out, "  - "+t)
			}
			if !ch.Added && !ch.Removed {
				for _, g := range ch.GrantsAdded {
					out = append(out, "  grant + "+g)
				}
				for _, g := range ch.GrantsRemoved {
					out = append(out, "  grant - "+g)
				}
			}
		}
		for _, g := range c.Groups {
			out = append(out, fmt.Sprintf("group %s: %s -> %s", g.Group, dash(g.From), dash(g.To)))
		}
		for _, qc := range c.Quota {
			line := "quota " + qc.Account + " " + qc.Change
			if qc.To != "" {
				line += ": " + qc.To
			}
			out = append(out, line)
		}
		if c.FreeToolsChanged {
			out = append(out, "quota.free_tools changed")
		}
		if len(c.NotReloaded) > 0 {
			out = append(out, "NOT applied until a restart: "+strings.Join(c.NotReloaded, ", "))
		}
	}
	if o := q.Redial; o != nil {
		line := fmt.Sprintf("was connected: %t; live now: %t", o.WasConnected, o.Live)
		if o.Cause != "" {
			line += " (" + o.Cause + ")"
		}
		out = append(out, line)
	}
	out = append(out, q.Messages...)
	for _, wn := range q.Warnings {
		out = append(out, "WARNING: "+wn.Message)
	}
	if q.Recorded && q.Audit != nil {
		out = append(out, "Recorded in the audit trail as "+q.Audit.Tool+" by "+q.Audit.Identity+".")
	}
	r.Output = strings.Join(out, "\n")
	return r
}

func (f *Front) reload(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureServeControl) {
		return
	}
	res, err := f.op.Reload(r.Context())
	f.showResult(w, r, "overview", "Reload the configuration", "/", f.serveResult(res, err))
}

// serveRequestPage reads a pending request again: the Refresh link of a
// reload or a redial that had no answer yet.
func (f *Front) serveRequestPage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureServeControl) {
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	q, err := f.op.ServeRequestByID(r.Context(), id)
	back, nav := "/", "overview"
	if q.Kind == adminapi.ServeKindRedial {
		back, nav = showBack(q.Upstream), "upstreams"
	}
	f.showResult(w, r, nav, "Request "+strconv.FormatInt(id, 10), back, f.serveResult(q, err))
}

// ---- clearing a sensitive tool

func (f *Front) toolClear(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, false, adminapi.FeatureToolClear) {
		return
	}
	server, tool := r.PostForm.Get("server"), r.PostForm.Get("tool")
	res, err := f.op.ClearTool(r.Context(), adminapi.ToolRef{Server: server, Tool: tool})
	out := actionResult(res.ActionResult, err)
	if err == nil && len(res.ClearedBy) > 0 {
		var roles []string
		for _, c := range res.ClearedBy {
			roles = append(roles, c.Role)
		}
		out.Output = strings.TrimSpace(out.Output + "\nReached by: " + strings.Join(roles, ", "))
	}
	f.showResult(w, r, "tools", "Clear "+frontkit.VisibleText(server+"."+tool),
		"/tools/show?server="+url.QueryEscape(server)+"&tool="+url.QueryEscape(tool), out)
}

// ---- secrets (accounts socket)

type secretsData struct {
	List adminapi.SecretList
	// Missing counts the names a backend declares that the vault lacks.
	Missing int
}

func (f *Front) secretsPage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	list, err := f.acc.ListSecrets(r.Context())
	d := secretsData{List: list}
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	for _, p := range list.Problems {
		errs = append(errs, p.Message)
	}
	for _, s := range list.Secrets {
		if !s.InVault && len(s.DeclaredBy) > 0 {
			d.Missing++
		}
	}
	f.render(w, r, "vault", "Secrets", page{Nav: "secrets", Data: d, Error: strings.Join(errs, "\n")})
}

// secretSet writes one value. The value is read from the form and handed
// to the accounts socket; the result page names the secret only.
func (f *Front) secretSet(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if before, _, found := strings.Cut(name, "="); found {
		// NAME=value pasted as the name: refused here, because the title
		// and the backend's refusal would both repeat the name, value and
		// all. Only the part left of "=" is said.
		text := "Nothing was written: the name looks like NAME=value (the value is not repeated here). Put " +
			frontkit.VisibleText(before) + " in Name and the value in Value."
		f.showResult(w, r, "secrets", "Set a secret", "/secrets", result{Summary: text, Output: text})
		return
	}
	res, err := f.acc.SetSecret(r.Context(), name, r.PostForm.Get("value"))
	f.showResult(w, r, "secrets", "Set "+frontkit.VisibleText(name), "/secrets", actionResult(res.ActionResult, err))
}

func (f *Front) secretDelete(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	name := r.PostForm.Get("name")
	if r.PostForm.Get("confirm") != "yes" {
		f.showResult(w, r, "secrets", "Delete "+frontkit.VisibleText(name), "/secrets",
			result{Summary: "Nothing was deleted: tick the confirmation first."})
		return
	}
	res, err := f.acc.DeleteSecret(r.Context(), name)
	f.showResult(w, r, "secrets", "Delete "+frontkit.VisibleText(name), "/secrets", actionResult(res.ActionResult, err))
}

// ---- roles (accounts socket, then a reload on the operator socket)

type rolesData struct {
	Text, Path, SHA256 string
	// Loaded: the file was read, so the form can be sent.
	Loaded bool
}

func (f *Front) rolesPage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	t, err := f.acc.GetRoles(r.Context())
	f.render(w, r, "roles", "Roles", page{Data: rolesData{Text: t.Text, Path: t.Path, SHA256: t.SHA256, Loaded: err == nil}, Error: errText(err)})
}

// rolesApply writes the roles file and, when it changed, asks the running
// gateway to apply it. A text the backend refuses is shown again as typed,
// with the backend's reason above it.
func (f *Front) rolesApply(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	text := r.PostForm.Get("text")
	res, err := f.acc.PutRoles(r.Context(), text)
	if err != nil {
		cur, _ := f.acc.GetRoles(r.Context())
		f.render(w, r, "roles", "Roles", page{Data: rolesData{Text: text, Path: cur.Path, SHA256: cur.SHA256, Loaded: true},
			Error: "Not written: " + errText(err)})
		return
	}
	out := actionResult(res.ActionResult, nil)
	if !res.ReloadNeeded {
		f.showResult(w, r, "roles", "Apply the roles", "/roles", out)
		return
	}
	q, rerr := f.op.Reload(r.Context())
	reload := f.serveResult(q, rerr)
	combined := result{OK: out.OK && reload.OK, Refresh: reload.Refresh,
		Output: strings.TrimSpace(out.Output + "\nsha256:" + res.SHA256 + "\n\n" + reload.Output)}
	switch {
	case combined.OK:
		// The write's own words ("written and NOT applied: ... call
		// POST /v1/reload") are true of the write alone and false of this
		// page, which made the reload: say what happened to both.
		combined.Summary = "Written and applied from the next call on."
		combined.Output = strings.TrimSpace("Roles file written: sha256:" + res.SHA256 + "\n\n" + reload.Output)
	case !out.OK:
		combined.Summary = out.Summary
	default:
		combined.Summary = "The roles file was written, and not applied yet: " + reload.Summary
	}
	f.showResult(w, r, "roles", "Apply the roles", "/roles", combined)
}
