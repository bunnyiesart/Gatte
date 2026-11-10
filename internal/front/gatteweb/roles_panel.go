package gatteweb

// The Roles section of the Users tab (design/adr/0051, 0054): a structured
// role x tool view, with surgical grant/revoke and a non_read toggle. It is a
// Tab-2 slice -- it self-registers a UsersSection and mounts its own action
// routes (reg_roles_panel.go), and never touches the Users shell.
//
// It reads the role x tool matrix from GetRoles (the file), ListTools (the
// tools and their safe/sensitive class) and People (the roles and their
// groups). It writes by splicing one entry into the roles text (roles_toml.go)
// and storing it through PutRoles, which validates before it keeps it. Writing
// does NOT apply: a reload on the Servers tab does (design/adr/0054 §3), so an
// edit here prompts for that reload rather than doing it per toggle.
//
// Reading and writing roles both need the managing console and the accounts
// socket (design/adr/0054 §3), so the section's Show is managesAndRoot and
// every action gates through managed(..., true).

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// ---- the matrix view

type rolesPanelData struct {
	Base, CSRF string
	Loaded     bool
	Path, SHA  string
	Servers    []matrixServer
	Rows       []matrixRow
	// RoleNames and the server/tool columns also drive the action form's
	// selects.
	RoleNames []string
	Problem   string
}

// matrixServer is one backend's column group: its tools, in order.
type matrixServer struct {
	Name  string
	Tools []matrixTool
}

type matrixTool struct {
	Server, Tool string
	NS           string // "server.tool"
	Sensitive    bool
}

// matrixRow is one role: its non_read marking, the groups mapped to it, and
// one cell per tool column (in the same order the servers flatten to).
type matrixRow struct {
	Name     string
	NonRead  bool
	Groups   []string
	HasBlock bool
	Cells    []matrixCell
}

// matrixCell is one role x tool intersection as the grid draws it.
type matrixCell struct {
	Covered   bool
	Sensitive bool
	Mark      string // the glyph shown when covered
	Title     string // how it is covered, for the cell's hover text
}

// rolesPanelFragment renders the section's HTML for embedding in the Users
// page. It is the UsersSection's Render.
func (f *Front) rolesPanelFragment(r *http.Request) (template.HTML, error) {
	d := rolesPanelData{Base: f.kit.Base(), CSRF: f.kit.CSRFToken()}
	if f.acc == nil {
		// Show is managesAndRoot, so this is defensive only.
		d.Problem = "The roles file is read through the accounts socket, which this console was started without."
		return f.renderFragment("roles_panel", d)
	}
	ctx := r.Context()
	roles, err := f.acc.GetRoles(ctx)
	if err != nil {
		d.Problem = errText(err)
		return f.renderFragment("roles_panel", d)
	}
	d.Loaded, d.Path, d.SHA = true, roles.Path, roles.SHA256

	tools, terr := f.op.ListTools(ctx, "", "")
	if terr != nil {
		d.Problem = errText(terr)
		return f.renderFragment("roles_panel", d)
	}
	d.Servers = columnsFrom(tools.Tools)

	people, perr := f.op.People(ctx)
	if perr != nil {
		d.Problem = errText(perr)
		return f.renderFragment("roles_panel", d)
	}
	blocks := parseRoleBlocks(roles.Text)
	for _, role := range people.Roles {
		b, has := findRole(blocks, role.Name)
		row := matrixRow{Name: role.Name, Groups: role.Groups, HasBlock: has, NonRead: b.NonRead}
		for _, s := range d.Servers {
			for _, tl := range s.Tools {
				row.Cells = append(row.Cells, cellFor(b, tl))
			}
		}
		d.Rows = append(d.Rows, row)
		d.RoleNames = append(d.RoleNames, role.Name)
	}
	return f.renderFragment("roles_panel", d)
}

// columnsFrom groups the tool list into per-backend columns, keeping the
// order the list is in.
func columnsFrom(tools []adminapi.Tool) []matrixServer {
	var servers []matrixServer
	idx := map[string]int{}
	for _, t := range tools {
		i, ok := idx[t.Server]
		if !ok {
			i = len(servers)
			idx[t.Server] = i
			servers = append(servers, matrixServer{Name: t.Server})
		}
		servers[i].Tools = append(servers[i].Tools, matrixTool{
			Server: t.Server, Tool: t.Tool, NS: t.Server + "." + t.Tool,
			Sensitive: t.Class == adminapi.ClassSensitive,
		})
	}
	return servers
}

// cellFor draws one role x tool cell from the role's parsed block.
func cellFor(b roleBlock, tl matrixTool) matrixCell {
	cov := b.cover(tl.Server, tl.Tool, tl.Sensitive)
	c := matrixCell{Covered: cov.Covered, Sensitive: tl.Sensitive}
	switch cov.How {
	case "explicit":
		c.Mark, c.Title = "●", "granted explicitly by name"
	case "grant":
		c.Mark, c.Title = "●", "granted through [role.grants]"
	case "wildcard":
		c.Mark, c.Title = "✻", "granted through a \"*\" grant over "+tl.Server+" (edit the whole-backend grant to change it)"
	case "non_read":
		c.Mark, c.Title = "●", "granted explicitly on a non_read role"
	}
	return c
}

func (f *Front) renderFragment(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := f.pages.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //#nosec G203 -- the template escapes every value
}

// ---- the actions

// rolesEdit grants or revokes one tool for one role. It reads the tool's
// security class from the live list rather than the form, so a sensitive tool
// takes the sensitive path (non_read + explicit name) and a safe one the grant
// path, whatever the browser sent.
func (f *Front) rolesEdit(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	role := strings.TrimSpace(r.PostForm.Get("role"))
	ns := strings.TrimSpace(r.PostForm.Get("tool"))
	op := r.PostForm.Get("op")
	server, tool, found := strings.Cut(ns, ".")
	title := opTitle(op) + " " + visible(ns) + " for " + visible(role)
	if role == "" || !found || (op != "grant" && op != "revoke") {
		f.showResult(w, r, "users", title, "/users", refused("Nothing changed: choose a role, a tool and an action."))
		return
	}
	sensitive, ok := f.toolIsSensitive(r.Context(), server, tool)
	if !ok {
		f.showResult(w, r, "users", title, "/users", refused("Nothing changed: no tool "+visible(ns)+" is known. Register and approve it first."))
		return
	}
	cur, err := f.acc.GetRoles(r.Context())
	if err != nil {
		f.showResult(w, r, "users", title, "/users", refused("The roles file could not be read: "+firstLine(errText(err))))
		return
	}

	var text string
	var st spliceStatus
	switch op {
	case "grant":
		if sensitive {
			text, st = grantSensitiveTool(cur.Text, role, server, tool)
		} else {
			text, st = grantSafeTool(cur.Text, role, server, tool)
		}
	case "revoke":
		text, st = revokeTool(cur.Text, role, server, tool)
	}
	f.finishSplice(w, r, title, role, server, tool, op, sensitive, text, st)
}

// rolesNonRead marks or clears non_read on a role. non_read is a security
// boundary (design/adr/0048): it is set on its own, never as a side effect of
// a grant.
func (f *Front) rolesNonRead(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	role := strings.TrimSpace(r.PostForm.Get("role"))
	on := r.PostForm.Get("on") == "true"
	verb := "Mark non_read on"
	if !on {
		verb = "Clear non_read on"
	}
	title := verb + " " + visible(role)
	if role == "" {
		f.showResult(w, r, "users", title, "/users", refused("Nothing changed: no role named."))
		return
	}
	cur, err := f.acc.GetRoles(r.Context())
	if err != nil {
		f.showResult(w, r, "users", title, "/users", refused("The roles file could not be read: "+firstLine(errText(err))))
		return
	}
	text, st := setNonRead(cur.Text, role, on)
	var done string
	if on {
		done = "Role " + role + " is now marked non_read in the roles file: it may hold sensitive tools you name on it explicitly."
	} else {
		done = "Role " + role + " is no longer marked non_read in the roles file."
	}
	f.showResult(w, r, "users", title, "/users", f.spliceResult(r.Context(), st, text, done, spliceMessages{
		noRole:  "Nothing changed: no [[role]] named " + role + " in the roles file.",
		already: "Role " + role + " already has that marking.",
	}))
}

// finishSplice turns a grant/revoke splice status into a result page.
func (f *Front) finishSplice(w http.ResponseWriter, r *http.Request, title, role, server, tool, op string, sensitive bool, text string, st spliceStatus) {
	ns := server + "." + tool
	var done string
	switch op {
	case "grant":
		if sensitive {
			done = "Role " + role + " may call " + ns + " once you approve and clear it."
		} else {
			done = "Role " + role + " may call " + ns + " once you approve it."
		}
	case "revoke":
		done = "Role " + role + " may no longer call " + ns + "."
	}
	msgs := spliceMessages{
		noRole:  "Nothing changed: no [[role]] named " + role + " in the roles file.",
		already: "No change: role " + role + " already " + grantedWord(op) + " " + ns + ".",
		wildcard: "Not changed: " + ns + " is reached through a \"*\" grant over " + server +
			". Change the whole-backend grant in the roles file, then reload the configuration, to change it one tool at a time.",
		needNonRead: "Not granted: " + ns + " is a sensitive tool, reachable only by a role marked non_read that names it. " +
			"Mark " + role + " non_read first, then grant it. A sensitive tool also needs a separate clear before it is served.",
	}
	f.showResult(w, r, "users", title, "/users", f.spliceResult(r.Context(), st, text, done, msgs))
}

type spliceMessages struct {
	noRole, already, wildcard, needNonRead string
}

// spliceResult stores a changed text through PutRoles and builds the result
// page; a status other than spliceChanged is a message, with nothing written.
func (f *Front) spliceResult(ctx context.Context, st spliceStatus, text, done string, m spliceMessages) result {
	switch st {
	case spliceNoRole:
		return refused(m.noRole)
	case spliceAlready:
		return result{OK: true, Summary: m.already, Output: m.already}
	case spliceWildcard:
		return refused(m.wildcard)
	case spliceNeedNonRead:
		return refused(m.needNonRead)
	}
	res, err := f.acc.PutRoles(ctx, text)
	if err != nil {
		return refused("Not written: " + firstLine(errText(err)))
	}
	out := done
	if res.SHA256 != "" {
		out += "\nsha256:" + res.SHA256
	}
	out += "\n\nWritten to the roles file, and NOT applied yet. Reload the configuration on the Servers tab to apply it."
	return result{OK: true, Summary: done, Output: out}
}

// toolIsSensitive reports a tool's class from the live list, and whether the
// tool is known at all.
func (f *Front) toolIsSensitive(ctx context.Context, server, tool string) (sensitive, known bool) {
	list, err := f.op.ListTools(ctx, server, "")
	if err != nil {
		return false, false
	}
	for _, t := range list.Tools {
		if t.Server == server && t.Tool == tool {
			return t.Class == adminapi.ClassSensitive, true
		}
	}
	return false, false
}

func refused(msg string) result { return result{Summary: msg, Output: msg} }

func opTitle(op string) string {
	if op == "revoke" {
		return "Revoke"
	}
	return "Grant"
}

func grantedWord(op string) string {
	if op == "revoke" {
		return "does not grant"
	}
	return "grants"
}

// visible makes any hidden code point in a name visible in a message (the
// template uses the `vis` func for the same in HTML).
func visible(s string) string { return frontkit.VisibleText(s) }
