package gatteweb

// The Roles section of the Users tab (design/adr/0051, 0054): a list of the
// roles, each opening a role page with the tools as checkboxes grouped by
// backend, Grant selected / Revoke selected, and a non_read switch. It is a
// Tab-2 slice -- it self-registers a UsersSection and mounts its own routes
// (reg_roles_panel.go), and never touches the Users shell.
//
// It reads the roles file (GetRoles), the tools and their safe/sensitive
// class (ListTools) and the running roles and their groups (PeopleRoles). It
// writes by splicing entries into the roles text (pkg/frontkit) and storing
// it through PutRoles, once per action, which validates before it keeps it.
// Writing does NOT apply: a reload on the Servers tab does (design/adr/0054
// §3), so a result page prompts for that reload rather than doing it.
//
// Reading and writing roles both need the managing console and the accounts
// socket (design/adr/0054 §3), so the section's Show is managesAndRoot and
// every handler gates through managed(..., true).

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// ---- the role list (the Users tab section)

type rolesListData struct {
	Base    string
	Loaded  bool
	Roles   []roleRow
	Problem string
}

// roleRow is one role as the list shows it. Tools counts the listed tools
// the roles file grants it, which is what its role page offers to change.
type roleRow struct {
	Name, Href string
	InFile     bool
	NonRead    bool
	Groups     []string
	Tools      int
}

// rolesView is what both the list and a role page read: the roles file
// parsed, the tools by backend, and the role names in order -- the running
// configuration's first, then any the file holds that is not applied yet.
type rolesView struct {
	file    adminapi.RolesText
	blocks  []frontkit.RoleBlock
	servers []toolServer
	names   []string
	groups  map[string][]string
}

func (f *Front) readRoles(ctx context.Context) (rolesView, error) {
	var v rolesView
	file, err := f.acc.GetRoles(ctx)
	if err != nil {
		return v, err
	}
	tools, err := f.op.ListTools(ctx, "", "")
	if err != nil {
		return v, err
	}
	people, err := f.op.PeopleRoles(ctx)
	if err != nil {
		return v, err
	}
	v.file, v.blocks, v.servers = file, frontkit.ParseRoles(file.Text), serversFrom(tools.Tools)
	v.groups = map[string][]string{}
	for _, role := range people.Roles {
		v.names = append(v.names, role.Name)
		v.groups[role.Name] = role.Groups
	}
	for _, b := range v.blocks {
		if _, running := v.groups[b.Name]; !running {
			v.names = append(v.names, b.Name)
			v.groups[b.Name] = nil
		}
	}
	return v, nil
}

// rolesPanelFragment renders the role list for embedding in the Users page.
// It is the UsersSection's Render.
func (f *Front) rolesPanelFragment(r *http.Request) (template.HTML, error) {
	d := rolesListData{Base: f.kit.Base()}
	if f.acc == nil {
		// Show is managesAndRoot, so this is defensive only.
		d.Problem = "The roles file is read through the accounts socket, which this console was started without."
		return f.renderFragment("roles_panel", d)
	}
	v, err := f.readRoles(r.Context())
	if err != nil {
		d.Problem = errText(err)
		return f.renderFragment("roles_panel", d)
	}
	d.Loaded = true
	for _, name := range v.names {
		b, inFile := frontkit.FindRole(v.blocks, name)
		row := roleRow{Name: name, Href: roleBack(name), InFile: inFile, NonRead: b.NonRead, Groups: v.groups[name]}
		for _, s := range v.servers {
			for _, t := range s.Tools {
				if b.Cover(t.Server, t.Tool, t.Sensitive).Covered {
					row.Tools++
				}
			}
		}
		d.Roles = append(d.Roles, row)
	}
	return f.renderFragment("roles_panel", d)
}

// roleBack is a role page's path under the console base. The name is a
// query parameter, not a path segment: a role name may hold "/" or be "..",
// and the console's path is decoded before routing.
func roleBack(role string) string { return "/users/roles/view?name=" + url.QueryEscape(role) }

// ---- a role page

type rolePageData struct {
	Name     string
	Found    bool
	InFile   bool
	NonRead  bool
	Groups   []string
	Servers  []toolServer
	FilePath string
}

// toolServer is one backend's tools, in list order.
type toolServer struct {
	Name  string
	Tools []roleTool
}

// roleTool is one tool as a role page lists it; How is how the role reaches
// it now ("" when it does not).
type roleTool struct {
	Server, Tool string
	NS           string // "server.tool"
	Sensitive    bool
	How          string
}

// serversFrom groups the tool list by backend, keeping the list's order.
func serversFrom(tools []adminapi.Tool) []toolServer {
	var servers []toolServer
	idx := map[string]int{}
	for _, t := range tools {
		i, ok := idx[t.Server]
		if !ok {
			i = len(servers)
			idx[t.Server] = i
			servers = append(servers, toolServer{Name: t.Server})
		}
		servers[i].Tools = append(servers[i].Tools, roleTool{
			Server: t.Server, Tool: t.Tool, NS: t.Server + "." + t.Tool,
			Sensitive: t.Class == adminapi.ClassSensitive,
		})
	}
	return servers
}

func (f *Front) rolePage(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	name := r.URL.Query().Get("name")
	v, err := f.readRoles(r.Context())
	if err != nil {
		f.render(w, r, "role", name, page{Nav: "users", Data: rolePageData{Name: name}, Error: errText(err)})
		return
	}
	groups, running := v.groups[name]
	b, inFile := frontkit.FindRole(v.blocks, name)
	d := rolePageData{Name: name, Found: running || inFile, InFile: inFile, NonRead: b.NonRead, Groups: groups, FilePath: v.file.Path}
	for _, s := range v.servers {
		ts := toolServer{Name: s.Name}
		for _, t := range s.Tools {
			t.How = b.Cover(t.Server, t.Tool, t.Sensitive).How
			ts.Tools = append(ts.Tools, t)
		}
		d.Servers = append(d.Servers, ts)
	}
	f.render(w, r, "role", name, page{Nav: "users", Data: d})
}

func (f *Front) renderFragment(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := f.pages.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //#nosec G203 -- the template escapes every value
}

// ---- the actions

// rolesEdit grants or revokes the selected tools for one role: each edit is
// applied in order to the roles text, and the result is written once. It
// reads each tool's security class from the live list rather than the form,
// so a sensitive tool takes the sensitive path (non_read + explicit name) and
// a safe one the grant path, whatever the browser sent. A tool an edit
// refuses is listed as refused and the others are kept; the text is then
// validated as a whole, so if it would not load nothing is written. The
// result page lists every tool's outcome.
func (f *Front) rolesEdit(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	role := strings.TrimSpace(r.PostForm.Get("role"))
	op := r.PostForm.Get("op")
	selected := r.PostForm["tool"]
	title := opTitle(op) + " for " + visible(role)
	back := "/users"
	if role != "" {
		back = roleBack(role)
	}
	if role == "" || (op != "grant" && op != "revoke") {
		f.showResult(w, r, "users", title, back, refused("Nothing changed: choose a role and an action."))
		return
	}
	if len(selected) == 0 {
		f.showResult(w, r, "users", title, back, refused("Nothing changed: no tool selected."))
		return
	}
	list, err := f.op.ListTools(r.Context(), "", "")
	if err != nil {
		f.showResult(w, r, "users", title, back, refused("The tools could not be read: "+firstLine(errText(err))))
		return
	}
	class := map[string]bool{}
	for _, t := range list.Tools {
		class[t.Server+"."+t.Tool] = t.Class == adminapi.ClassSensitive
	}
	cur, err := f.acc.GetRoles(r.Context())
	if err != nil {
		f.showResult(w, r, "users", title, back, refused("The roles file could not be read: "+firstLine(errText(err))))
		return
	}

	text := cur.Text
	var changed, unchanged, refusals []string
	seen := map[string]bool{}
	for _, ns := range selected {
		ns = strings.TrimSpace(ns)
		if seen[ns] {
			continue
		}
		seen[ns] = true
		server, tool, ok := strings.Cut(ns, ".")
		sensitive, known := class[ns]
		if !ok || !known {
			refusals = append(refusals, visible(ns)+": no such tool")
			continue
		}
		var next string
		var st frontkit.SpliceStatus
		switch {
		case op == "revoke":
			next, st = revokeAll(text, role, server, tool, sensitive)
		case sensitive:
			next, st = frontkit.GrantSensitiveTool(text, role, server, tool)
		default:
			next, st = frontkit.GrantSafeTool(text, role, server, tool)
		}
		switch st {
		case frontkit.SpliceNoRole:
			f.showResult(w, r, "users", title, "/users", refused("Nothing changed: no [[role]] named "+visible(role)+" in the roles file."))
			return
		case frontkit.SpliceChanged:
			text = next
			item := visible(ns)
			// A "*" grant over the backend outlives every entry a revoke can
			// remove; say so rather than claim the tool is gone.
			if b, _ := frontkit.FindRole(frontkit.ParseRoles(text), role); op == "revoke" && b.Cover(server, tool, sensitive).Covered {
				item += " (still granted by *)"
			}
			if op == "grant" && sensitive {
				item += " (served once the tool is approved and cleared)"
			}
			changed = append(changed, item)
		case frontkit.SpliceAlready:
			unchanged = append(unchanged, visible(ns))
		case frontkit.SpliceWildcard:
			// A "*" grant over the backend already reaches the tool: a grant
			// has nothing to add, and a revoke cannot take one tool out of it.
			if op == "grant" {
				unchanged = append(unchanged, visible(ns)+" (granted by *)")
			} else {
				refusals = append(refusals, visible(ns)+": granted by a \"*\" grant over "+visible(server)+"; edit that grant in the roles file")
			}
		case frontkit.SpliceNeedNonRead:
			refusals = append(refusals, visible(ns)+": sensitive; turn non_read on for "+visible(role)+" first")
		}
	}
	f.showResult(w, r, "users", title, back, f.writeEdits(r.Context(), op, text, changed, unchanged, refusals))
}

// revokeAll removes every entry of the role that reaches server.tool -- a
// name in `tools` and an id under [role.grants] alike -- so a revoke does not
// leave the tool reachable by the other. It stops at a "*" grant, which no
// one-tool edit can take apart, and reports SpliceChanged if anything went.
func revokeAll(text, role, server, tool string, sensitive bool) (string, frontkit.SpliceStatus) {
	next, st := frontkit.RevokeTool(text, role, server, tool)
	if st != frontkit.SpliceChanged {
		return next, st
	}
	// Each pass removes one entry; a role holds at most one of each kind.
	for range 2 {
		b, _ := frontkit.FindRole(frontkit.ParseRoles(next), role)
		if cov := b.Cover(server, tool, sensitive); !cov.Covered || cov.How == "wildcard" {
			break
		}
		again, st2 := frontkit.RevokeTool(next, role, server, tool)
		if st2 != frontkit.SpliceChanged {
			break
		}
		next = again
	}
	return next, frontkit.SpliceChanged
}

// writeEdits stores the edited text once, when anything changed, and builds
// the result page that lists every selected tool's outcome.
func (f *Front) writeEdits(ctx context.Context, op, text string, changed, unchanged, refusals []string) result {
	done := "Granted"
	if op == "revoke" {
		done = "Revoked"
	}
	// A write that went through is a success even when some tools were
	// refused: the Refused list says which.
	res := result{OK: len(changed) > 0 || len(refusals) == 0}
	switch {
	case len(changed) > 0:
		put, err := f.acc.PutRoles(ctx, text)
		if err != nil {
			res.OK, res.Summary = false, "Not written: "+firstLine(errText(err))
			done = "Not written"
		} else {
			res.Summary = notApplied
			if put.SHA256 != "" {
				res.Output = "sha256:" + put.SHA256 + "\n"
			}
		}
	case len(refusals) > 0:
		res.Summary = "Nothing written."
	default:
		res.Summary = "No change."
	}
	for _, l := range []resultList{{done, changed}, {"No change", unchanged}, {"Refused", refusals}} {
		if len(l.Items) > 0 {
			res.Lists = append(res.Lists, l)
			res.Output += l.Title + ": " + strings.Join(l.Items, "; ") + "\n"
		}
	}
	res.Output += res.Summary
	return res
}

// notApplied is what every roles write says: the file changed, the running
// gateway did not.
const notApplied = "Written to the roles file, NOT applied yet. Reload the configuration on the Servers tab to apply it."

// rolesNonRead turns non_read on or off for a role. non_read is a security
// boundary (design/adr/0048): it is set on its own, never as a side effect of
// a grant.
func (f *Front) rolesNonRead(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	role := strings.TrimSpace(r.PostForm.Get("role"))
	on := r.PostForm.Get("on") == "true"
	title := "non_read off for " + visible(role)
	if on {
		title = "non_read on for " + visible(role)
	}
	if role == "" {
		f.showResult(w, r, "users", title, "/users", refused("Nothing changed: no role named."))
		return
	}
	back := roleBack(role)
	cur, err := f.acc.GetRoles(r.Context())
	if err != nil {
		f.showResult(w, r, "users", title, back, refused("The roles file could not be read: "+firstLine(errText(err))))
		return
	}
	text, st := frontkit.SetNonRead(cur.Text, role, on)
	switch st {
	case frontkit.SpliceNoRole:
		f.showResult(w, r, "users", title, back, refused("Nothing changed: no [[role]] named "+visible(role)+" in the roles file."))
		return
	case frontkit.SpliceAlready:
		f.showResult(w, r, "users", title, back, result{OK: true, Summary: "No change.", Output: "No change."})
		return
	}
	put, err := f.acc.PutRoles(r.Context(), text)
	if err != nil {
		f.showResult(w, r, "users", title, back, refused("Not written: "+firstLine(errText(err))))
		return
	}
	out := title + "\n"
	if put.SHA256 != "" {
		out += "sha256:" + put.SHA256 + "\n"
	}
	f.showResult(w, r, "users", title, back, result{OK: true, Summary: notApplied, Output: out + notApplied})
}

func refused(msg string) result { return result{Summary: msg, Output: msg} }

func opTitle(op string) string {
	if op == "revoke" {
		return "Revoke"
	}
	return "Grant"
}

// visible makes any hidden code point in a name visible in a message (the
// template uses the `vis` func for the same in HTML).
func visible(s string) string { return frontkit.VisibleText(s) }
