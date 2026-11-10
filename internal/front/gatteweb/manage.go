package gatteweb

// The shared pieces of the management actions (design/adr/0050) that the
// Tab-1 pages use: the managed gate, the Add a REST API form, the
// quick grant, the sign and serve-request results, and the page that reads
// a pending serve request again. Each is a call of the management API,
// behind [admin] console_manages; what needs root's key or the vault is the
// accounts socket's, and exists only with -manage-users.

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	defer func() { _ = file.Close() }()
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

// grantBackend puts `"BACKEND" = ["*"]` in role's [role.grants], through
// the same PUT /v1/roles the Users tab's Roles section uses, so the backend's validation
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
	case grantNarrower:
		return "Not granted: role " + role + " already has a narrower, tool-specific grant for " + backend + ". Widen it to all tools in the roles file, then reload the configuration.", false
	case grantNoRole:
		return "Not granted: no [[role]] named " + role + " in the roles file.", false
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
	grantNarrower
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
			if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.Trim(strings.TrimSpace(k), "\"") == backend {
				// Only ["*"] is the full grant this button writes; a
				// narrower, tool-specific value must not be reported as
				// already in place (it would silently drop the widening).
				// Drop a trailing comment and all inner whitespace so a
				// full grant written as [ "*" ], with a tab, or with a
				// "# ..." note still counts as present.
				val := strings.TrimSpace(v)
				if i := strings.IndexByte(val, '#'); i >= 0 {
					val = val[:i]
				}
				if strings.Join(strings.Fields(val), "") == `["*"]` {
					return text, grantPresent
				}
				return text, grantNarrower
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

// signResult is the result of attesting a configuration: done, and whether
// the key that signed it is one the gateway trusts.
func signResult(res adminapi.SignResult, err error) result {
	out := actionResult(res.ActionResult, err)
	if err != nil {
		out.Summary = "Not attested: " + out.Summary
		return out
	}
	if res.KeyFingerprint != "" {
		out.Output = strings.TrimSpace(out.Output + "\nSigning key: " + res.KeyFingerprint)
	}
	switch {
	case !out.OK:
	case res.Trusted:
		out.Summary = "Configuration attested with a trusted key."
	default:
		out.OK, out.Summary = false, "Attested, with a key that is not in signer.trusted_keys: the gateway will not serve it until that key is trusted."
	}
	return out
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
	back := "/servers"
	if q.Kind == adminapi.ServeKindRedial {
		back = serverBack(q.Upstream)
	}
	f.showResult(w, r, "servers", "Request "+strconv.FormatInt(id, 10), back, f.serveResult(q, err))
}
