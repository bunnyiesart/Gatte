package gattetui

// Tab 1, "MCP Servers / APIs" (design/adr/0051, 0052, 0061): the list of
// backends with their health and config approval, and each backend's detail
// page. The detail page draws the entry and its operator actions (reconnect,
// approve configuration, remove), then every registered DetailPanel in
// order; the Tools, Secrets and Maintenance panels register from their own
// files.
//
// Adding a backend stays in the CLI and the web console: this front lists,
// reviews and acts on what is registered.

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func init() {
	registerScreen(Screen{ID: "servers", Title: "MCP Servers / APIs", Order: 10, Root: serversPage})
}

func serversPage() *page { return newPage("MCP Servers / APIs", fillServers) }

var serverCols = []int{16, 15, 23}

func fillServers(e env) content {
	var c content
	list, err := e.op.ListUpstreams(ctx())
	if err != nil {
		c.problems = append(c.problems, errText(err))
	}
	// Only what concerns the whole gateway (it not reporting, or in
	// maintenance) goes above the list. The list carries no per-backend
	// review marker (design/adr/0061 §3): pending tools are shown in each
	// backend's tools panel.
	ov, overr := e.op.Overview(ctx())
	if overr != nil {
		c.problems = append(c.problems, "Gateway state: "+errText(overr))
	}
	for _, a := range ov.Attention {
		if a.Upstream == "" && a.Server == "" {
			c.rows = append(c.rows, textRow(stWarn.Render(vis(a.Title)+": "+vis(a.Detail))))
		}
	}
	health := e.has(adminapi.FeatureBackendHealth)
	c.rows = append(c.rows, textRow(stDim.Render(cols(serverCols, "MCP SERVER / API", "STATE", "CONFIG", "KIND"))))
	if err == nil && len(list.Upstreams) == 0 {
		c.rows = append(c.rows, textRow(stDim.Render("No backend is registered. Register one with mcp-gateway upstream register.")))
	}
	for _, u := range list.Upstreams {
		state := "-"
		if health && u.Health != nil {
			state = stateText(u.Health.State)
		}
		name := u.Name
		c.rows = append(c.rows, row{
			text:    cols(serverCols, vis(u.Name), state, configText(u.Signature), kindText(u.Transport)),
			actions: []action{{key: "enter", label: "open", run: func() tea.Cmd { return push(serverPage(name)) }}},
		})
	}
	caps := e.caps()
	if caps.Manages && e.has(adminapi.FeatureServeControl) {
		c.actions = append(c.actions, action{key: "R", label: "reload config", run: func() tea.Cmd {
			return confirm("Re-read the configuration file and apply its roles, groups and quota?", func() tea.Cmd {
				return do(func() result { q, err := e.op.Reload(ctx()); return serveResult(e, q, err) })
			})
		}})
	}
	if managesAndRoot(caps) {
		c.actions = append(c.actions, action{key: "V", label: "vault", run: func() tea.Cmd { return push(vaultPage()) }})
	}
	return c
}

func kindText(transport string) string {
	switch transport {
	case "http":
		return "REST API"
	case "oci":
		return "Container"
	case "stdio":
		return "Process"
	case "remote":
		return "Remote MCP"
	}
	return vis(transport)
}

// ---- the detail page

func serverPage(name string) *page {
	return newPage(vis(name), func(e env) content { return fillServer(e, name) })
}

func fillServer(e env, name string) content {
	var c content
	caps := e.caps()
	d, err := upstreamDetail(e, name, caps.Manages)
	if err != nil {
		c.problems = append(c.problems, errText(err))
	}
	if d.Name == "" {
		return c
	}
	c.rows = append(c.rows, entryRows(e, d)...)
	for _, p := range orderedDetailPanels() {
		if p.Show != nil && !p.Show(caps) {
			continue
		}
		rows, perr := p.Rows(e, d)
		if perr != nil {
			c.problems = append(c.problems, p.ID+": "+errText(perr))
			continue
		}
		if len(rows) > 0 {
			c.rows = append(append(c.rows, blank()), rows...)
		}
	}
	c.actions = serverActions(e, d)
	return c
}

// upstreamDetail reads one backend, as the web console does: GET
// /v1/upstreams/{name} is a management read, so without
// FeatureConsoleManages the page is built from the registry entry and its
// quarantine instead, and only the operations and management actions are
// absent.
func upstreamDetail(e env, name string, manages bool) (adminapi.UpstreamDetail, error) {
	if manages {
		return e.op.GetUpstream(ctx(), name)
	}
	list, err := e.op.ListUpstreams(ctx())
	if err != nil {
		return adminapi.UpstreamDetail{}, err
	}
	i := slices.IndexFunc(list.Upstreams, func(u adminapi.Upstream) bool { return u.Name == name })
	if i < 0 {
		return adminapi.UpstreamDetail{}, &adminapi.Error{Status: http.StatusNotFound, Code: adminapi.CodeNotFound, Message: "no such backend"}
	}
	d := adminapi.UpstreamDetail{Upstream: list.Upstreams[i]}
	tools, err := e.op.ListTools(ctx(), name, "")
	d.Tools = tools.Tools
	return d, err
}

func entryRows(e env, d adminapi.UpstreamDetail) []row {
	kv := func(k, v string) row { return textRow(cols([]int{14}, stDim.Render(k), v)) }
	rows := []row{heading(vis(d.Name) + "  " + kindText(d.Transport))}
	switch {
	case d.URL != "":
		rows = append(rows, kv("URL", vis(d.URL)))
	case d.Image != "":
		rows = append(rows, kv("Image", vis(d.Image)))
	case d.Command != "":
		rows = append(rows, kv("Command", vis(strings.Join(append([]string{d.Command}, d.Args...), " "))))
	}
	if d.RemoteKind != "" {
		rows = append(rows, kv("Remote kind", vis(d.RemoteKind)))
	}
	rows = append(rows, kv("Config", configText(d.Signature)+stDim.Render("  an operator's approval of this entry, not a safety rating")))
	if h := d.Health; h != nil && e.has(adminapi.FeatureBackendHealth) {
		state := stateText(h.State) + stDim.Render("  since "+showTimePtr(h.Since))
		if h.Cause != "" {
			state += "  " + stBad.Render(vis(h.Cause))
		}
		rows = append(rows, kv("State", state))
	}
	net := vis(dash(d.Network))
	if d.NetworkError != "" {
		net += "  " + stBad.Render(vis(d.NetworkError))
	}
	rows = append(rows, kv("Network", net))
	if d.Auth != nil {
		auth := vis(d.Auth.Kind)
		if d.Auth.Name != "" {
			auth += " " + vis(d.Auth.Name)
		}
		if d.Auth.Secret != "" {
			auth += " from secret " + vis(d.Auth.Secret)
		}
		rows = append(rows, kv("Credential", auth))
	}
	if len(d.Operations) > 0 {
		sensitive := 0
		for _, op := range d.Operations {
			if op.Class == adminapi.ClassSensitive {
				sensitive++
			}
		}
		rows = append(rows, kv("Operations", fmt.Sprintf("%d (%d sensitive)", len(d.Operations), sensitive)))
	}
	if d.OperationsError != "" {
		rows = append(rows, kv("Operations", stBad.Render(vis(d.OperationsError))))
	}
	return rows
}

// serverActions are the backend's operator actions. Each is offered only
// when the backend serves it, and the backend checks again.
func serverActions(e env, d adminapi.UpstreamDetail) []action {
	caps := e.caps()
	name := d.Name
	var out []action
	if caps.Manages && e.has(adminapi.FeatureServeControl) {
		out = append(out, action{key: "C", label: "reconnect", run: func() tea.Cmd {
			return confirm("Drop the connection to "+vis(name)+" and connect again?", func() tea.Cmd {
				return do(func() result {
					q, err := e.op.RedialUpstream(ctx(), adminapi.RedialRequest{Upstream: name})
					return serveResult(e, q, err)
				})
			})
		}})
	}
	if managesAndRoot(caps) {
		label := "approve configuration"
		if d.Signature == "yes" {
			label = "approve configuration again"
		}
		out = append(out, action{key: "A", label: label, run: func() tea.Cmd {
			// Approving signs the entry shown above: its URL or command,
			// where its key goes and its operations (design/adr/0050 §5,
			// 0060). It does not say the backend or its tools are safe.
			return confirm("Approve the configuration of "+vis(name)+" shown above, signing it with the root key?", func() tea.Cmd {
				return do(func() result { res, err := e.acc.SignUpstream(ctx(), name); return signResult(res, err) })
			})
		}})
	}
	if caps.Manages {
		out = append(out, action{key: "X", label: "remove", run: func() tea.Cmd {
			// The backend refuses a confirmation that does not repeat the
			// name (it drops the approvals with the entry); what is typed is
			// forwarded as it is.
			return ask("Remove drops "+vis(name)+" and every approval of its tools. Type its name to confirm", "", func(typed string) tea.Cmd {
				return do(func() result {
					res, err := e.op.DeregisterUpstream(ctx(), name, typed)
					r := fromAction(res.ActionResult, err, "Removed "+name+".")
					if err == nil {
						r.output = append(r.output, fmt.Sprintf("Registry entry removed: %t. Signature removed: %t. Quarantine entries removed: %d.",
							res.Registered, res.SignatureRemoved, res.ToolsForgotten))
						r.back = true
					}
					return r
				})
			})
		}})
	}
	return out
}

func signResult(res adminapi.SignResult, err error) result {
	r := fromAction(res.ActionResult, err, "Config approved, signed with a trusted key.")
	if err != nil {
		return r
	}
	if res.KeyFingerprint != "" {
		r.output = append(r.output, "Signing key: "+res.KeyFingerprint)
	}
	if r.ok && !res.Trusted {
		r.ok, r.summary = false, "Config approved with a key that is not in signer.trusted_keys: the gateway will not serve it until that key is trusted."
	}
	return r
}

// serveResult is a reload's or a reconnect's answer. A request still pending is
// read again a few times before it is reported, since nothing on a terminal
// page refreshes it by itself.
func serveResult(e env, q adminapi.ServeRequest, err error) result {
	for i := 0; err == nil && q.State != adminapi.ServeStateDone && i < 5; i++ {
		time.Sleep(time.Second)
		q, err = e.op.ServeRequestByID(ctx(), q.ID)
	}
	if err != nil {
		text := errText(err)
		return result{summary: "Refused: " + firstLine(text), output: restLines(text)}
	}
	what := "The reload"
	if q.Kind == adminapi.ServeKindRedial {
		what = "The reconnect of " + q.Upstream
	}
	var r result
	switch {
	case q.State != adminapi.ServeStateDone:
		r.summary = fmt.Sprintf("%s (request %d) is still pending: the gateway was rung and has not answered yet.", what, q.ID)
	case q.Outcome == adminapi.ServeOutcomeApplied:
		r.ok, r.summary = true, fmt.Sprintf("%s (request %d) was applied.", what, q.ID)
	default:
		r.summary = fmt.Sprintf("%s (request %d) was refused (%s); what was in force stays in force.", what, q.ID, q.Refusal)
	}
	if ch := q.Reload; ch != nil {
		for _, rc := range ch.Roles {
			r.output = append(r.output, "role "+rc.Role)
			for _, t := range rc.Gained {
				r.output = append(r.output, "  + "+t)
			}
			for _, t := range rc.Lost {
				r.output = append(r.output, "  - "+t)
			}
		}
		for _, g := range ch.Groups {
			r.output = append(r.output, fmt.Sprintf("group %s: %s -> %s", g.Group, dash(g.From), dash(g.To)))
		}
		if len(ch.NotReloaded) > 0 {
			r.output = append(r.output, "NOT applied until a restart: "+strings.Join(ch.NotReloaded, ", "))
		}
	}
	if o := q.Redial; o != nil {
		line := fmt.Sprintf("was connected: %t; live now: %t", o.WasConnected, o.Live)
		if o.Cause != "" {
			line += " (" + o.Cause + ")"
		}
		r.output = append(r.output, line)
	}
	r.output = append(r.output, q.Messages...)
	for _, w := range q.Warnings {
		r.output = append(r.output, "WARNING: "+w.Message)
	}
	return r
}
