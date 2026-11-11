package gattetui

// "Add a backend" on the servers screen (design/adr/0059): a three-way
// choice of REST API (an OpenAPI document becomes MCP tools), a remote MCP
// server by URL, and a container (oci) where the backend lists
// FeatureOCIRegister. Each form sends POST /v1/upstreams with its transport,
// as the web console does. stdio stays in the CLI (design/adr/0034).
//
// Registering never approves the configuration: the result page shows what
// an approval covers, and Approve configuration is a separate action there
// (design/adr/0050 §5, 0061 §2). Tools arrive pending. A secret is named by
// its vault name only; this front never asks for a value here.

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

func init() {
	registerAddKind(AddKind{ID: "rest", Order: 10, Title: "REST API", Blurb: "An OpenAPI document becomes MCP tools", Form: restForm})
	registerAddKind(AddKind{ID: "remote", Order: 20, Title: "Remote MCP server (URL)", Blurb: "A native MCP server reached by URL", Form: remoteForm})
	registerAddKind(AddKind{ID: "oci", Order: 30, Title: "Container (oci)", Blurb: "An MCP server packaged as a container image, run isolated with podman",
		Show:        func(e env) bool { return e.has(adminapi.FeatureOCIRegister) },
		Unavailable: "Containers (oci) need podman on the gateway's host, and this one has none: register them in the terminal on a host with podman (mcp-gateway upstream register -transport oci).",
		Form:        ociForm})
}

// ---- the choice

func addPage() *page { return newPage("Add a backend", fillAdd) }

func fillAdd(e env) content {
	var c content
	c.rows = append(c.rows, heading("What kind of backend?"))
	var notes []string
	for _, k := range orderedAddKinds() {
		if k.Show != nil && !k.Show(e) {
			if k.Unavailable != "" {
				notes = append(notes, k.Unavailable)
			}
			continue
		}
		c.rows = append(c.rows, row{text: cols([]int{26}, stBold.Render(k.Title), stDim.Render(k.Blurb)),
			actions: []action{{key: "enter", label: "choose", run: func() tea.Cmd { return push(formPage(k.Form())) }}}})
	}
	notes = append(notes, "A stdio backend is not added here. Register it in the terminal with mcp-gateway upstream register: a stdio backend with credentials needs allow_credentialed_stdio, and a container is the isolated path.")
	if !e.caps().Root {
		notes = append(notes, "Approving a backend's configuration needs root's accounts socket: start with sudo mcp-gateway tui -manage-users. Without it, a backend added here is not served until its configuration is approved with sudo mcp-gateway sign NAME.")
	}
	for _, n := range notes {
		c.rows = append(append(c.rows, blank()), para(n, stDim)...)
	}
	return c
}

// ---- the three forms

// restAuthKinds are a REST API's choices, the empty one first: derive the
// descriptor from the document's securitySchemes.
var restAuthKinds = []choice{
	{"", "Derive from the document"},
	{"none", "None (keyless)"},
	{"bearer", "Bearer token (Authorization header)"},
	{"header", "Header"},
	{"query", "Query parameter"},
}

// remoteAuthKinds are where a remote entry can send its one secret
// (design/adr/0058 §5): no query parameter, unlike a REST API.
var remoteAuthKinds = []choice{
	{"none", "None (keyless)"},
	{"bearer", "Bearer token (Authorization header)"},
	{"header", "Header"},
}

func nameField() *field {
	return &field{id: "name", label: "Name", hint: "e.g. intel"}
}

func keyNameField() *field {
	return &field{id: "key_name", label: "Key's name in the vault", hint: "empty: NAME_API_KEY for a keyed backend", guard: vaultNameGuard}
}

func restForm() *form {
	return &form{
		title: "Add a REST API",
		intro: []string{
			"REST API / OpenAPI -> generates MCP tools. The gateway reads the OpenAPI document and turns each operation into a tool.",
			fmt.Sprintf("Give the document one way: by URL (fetched once, under the gateway's egress rules) or a file on this machine (JSON or YAML, up to %d MiB).", adminapi.MaxUpstreamDocumentBytes>>20),
			"Registering does not call the API and does not approve its configuration. Every operation becomes a tool waiting for your review; a POST, PUT, PATCH or DELETE is sensitive and also needs clearing.",
			"The key is named by its vault name only: set its value on the backend's page or in the vault.",
		},
		submitKey: "S", submitLabel: "add API",
		fields: []*field{
			nameField(),
			{id: "url", label: "Base URL", hint: "e.g. https://api.example.com", guard: userinfoGuard},
			{id: "openapi_url", label: "OpenAPI document by URL", hint: "e.g. https://api.example.com/openapi.json", guard: userinfoGuard},
			{id: "openapi_file", label: "Or a file on this machine", hint: "e.g. /home/me/openapi.yaml"},
			{id: "auth_kind", label: "Auth", choices: restAuthKinds},
			{id: "auth_name", label: "Header or parameter name", hint: "e.g. X-API-Key", guard: headerNameGuard},
			keyNameField(),
		},
		send: sendREST,
	}
}

func remoteForm() *form {
	return &form{
		title: "Add a remote MCP server",
		intro: []string{
			"A native MCP server reached by URL. The gateway connects to it and serves the tools it announces; the server runs elsewhere, so the gateway cannot isolate it or see where it connects.",
			"Auth is where the gateway sends its own key on every request: the analyst's token is never forwarded.",
			"Registering does not connect and does not approve the configuration. Its tools are listed once the gateway connects, each waiting for your review.",
		},
		submitKey: "S", submitLabel: "add remote server",
		fields: []*field{
			nameField(),
			{id: "url", label: "MCP endpoint URL", hint: "e.g. https://mcp.example.com/mcp", guard: remoteURLGuard},
			{id: "remote_kind", label: "Transport", value: adminapi.RemoteKindStreamable, choices: []choice{{adminapi.RemoteKindStreamable, "Streamable HTTP"}}},
			{id: "auth_kind", label: "Auth", value: "none", choices: remoteAuthKinds},
			{id: "auth_name", label: "Header name", hint: "e.g. X-API-Key", guard: headerNameGuard},
			keyNameField(),
		},
		send: sendRemote,
	}
}

func ociForm() *form {
	return &form{
		title: "Add a container (oci)",
		intro: []string{
			"An MCP server packaged as a container image. The gateway runs it with podman, isolated: no capabilities, a read-only root, its own user and only the network you choose here.",
			"The image must be pinned by digest (NAME@sha256:...); a tag is refused. Network is none unless you choose slirp4netns, pasta or a podman network by name; host is never allowed.",
			"Variable names are the vault names the container receives, never values. Registering does not start the container and does not approve its configuration. Its tools are listed once the gateway runs it, each waiting for your review.",
		},
		submitKey: "S", submitLabel: "add container",
		fields: []*field{
			nameField(),
			{id: "image", label: "Image, pinned by digest", hint: "e.g. ghcr.io/example/intel-mcp@sha256:..."},
			{id: "network", label: "Network", value: "none", hint: "none, slirp4netns, pasta or a podman network"},
			{id: "env_var_names", label: "Variable names (vault)", hint: "e.g. INTEL_API_KEY, comma-separated", guard: vaultNameGuard},
		},
		send: sendOCI,
	}
}

// ---- sending: each turns the form into the request, as the web console
// does; the rules are the backend's

func sendREST(e env, v map[string]string) result {
	req := adminapi.RegisterUpstreamRequest{Name: v["name"], URL: v["url"], OpenAPIURL: v["openapi_url"],
		AuthKind: v["auth_kind"], AuthName: v["auth_name"], KeyName: v["key_name"]}
	if path := v["openapi_file"]; path != "" {
		if req.OpenAPIURL != "" {
			return refused("Not registered: give the OpenAPI document one way, a URL or a file, not both.")
		}
		doc, err := readDocument(path)
		if err != nil {
			return refused("Not registered: the OpenAPI file could not be read: " + err.Error())
		}
		req.OpenAPIDocument = doc
	}
	if req.KeyName == "" && (req.AuthKind == "bearer" || req.AuthKind == "header" || req.AuthKind == "query") {
		req.KeyName = frontkit.DefaultKeyName(req.Name)
	}
	return register(e, req)
}

func sendRemote(e env, v map[string]string) result {
	req := adminapi.RegisterUpstreamRequest{Name: v["name"], Transport: adminapi.UpstreamTransportRemote, URL: v["url"],
		AuthKind: v["auth_kind"], AuthName: v["auth_name"], KeyName: v["key_name"], RemoteKind: v["remote_kind"]}
	if req.KeyName == "" && (req.AuthKind == "bearer" || req.AuthKind == "header") {
		req.KeyName = frontkit.DefaultKeyName(req.Name)
	}
	return register(e, req)
}

func sendOCI(e env, v map[string]string) result {
	req := adminapi.RegisterUpstreamRequest{Name: v["name"], Transport: adminapi.UpstreamTransportOCI, Image: v["image"],
		EnvVarNames: splitList(v["env_var_names"])}
	// none is the default by omission, as the CLI writes it without -arg;
	// any other policy is signed in the entry's args.
	if n := v["network"]; n != "" && n != "none" {
		req.Args = []string{"--network=" + n}
	}
	return register(e, req)
}

// readDocument reads an OpenAPI file the operator names, up to the
// ingestion's bound (one byte over says it is over).
func readDocument(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names a file of their own, as the CLI's -openapi does
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, adminapi.MaxUpstreamDocumentBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > adminapi.MaxUpstreamDocumentBytes {
		return "", fmt.Errorf("it is over the %d-byte limit the ingestion reads", adminapi.MaxUpstreamDocumentBytes)
	}
	return string(b), nil
}

// register sends the request and, when it is accepted, leaves the form for
// the registered page.
func register(e env, req adminapi.RegisterUpstreamRequest) result {
	res, err := e.op.RegisterUpstream(ctx(), req)
	if err != nil {
		return notRegistered(err)
	}
	r := fromAction(res.ActionResult, nil, "Registered "+res.Name+". Its configuration is not approved yet.")
	r.back = true
	r.next = push(registeredPage(res))
	return r
}

// notRegistered is a refused register, in the backend's own words (drawn
// escaped, as every result is).
func notRegistered(err error) result {
	text := errText(err)
	return result{summary: "Not registered: " + firstLine(text), output: restLines(text)}
}

// ---- guards: a value that looks like a pasted credential is not kept, so
// it is never drawn again; the reason never repeats it

func vaultNameGuard(v string) string {
	if strings.Contains(v, "=") {
		return "that looks like NAME=value. Give the vault name only; the value goes in the vault."
	}
	return ""
}

func headerNameGuard(v string) string {
	if strings.ContainsFunc(v, func(c rune) bool { return c == ':' || unicode.IsSpace(c) }) {
		return "that looks like a header line. Give the header's name only; the value comes from the vault."
	}
	return ""
}

func userinfoGuard(v string) string {
	if u, err := url.Parse(v); err == nil && u.User != nil {
		return "the URL carries a user or password. Give it without; a key comes from the vault."
	}
	return ""
}

// remoteURLGuard holds a remote endpoint to what the backend signs: no
// userinfo, query or fragment, where a vendor credential is often pasted.
func remoteURLGuard(v string) string {
	u, err := url.Parse(v)
	switch {
	case err != nil:
		return "the URL does not parse."
	case u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "":
		return "the URL carries a user, a query or a fragment. Give the endpoint alone; a key comes from the vault."
	}
	return ""
}

// ---- the registered page

func registeredPage(res adminapi.RegisterUpstreamResult) *page {
	return newPage("Registered "+vis(res.Name), func(e env) content { return fillRegistered(e, res) })
}

func fact(k, v string) row { return textRow(cols([]int{16}, stDim.Render(k), v)) }

func fillRegistered(e env, res adminapi.RegisterUpstreamResult) content {
	var c content
	caps := e.caps()
	name := res.Name
	c.rows = append(c.rows, heading(vis(name)+"  "+kindText(res.Transport)))
	intro := "Registered as a REST API. Its tools are pending your review."
	switch res.Transport {
	case adminapi.UpstreamTransportOCI:
		intro = "Registered as a container (oci). Its tools are listed once the gateway runs it, each pending your review."
	case adminapi.UpstreamTransportRemote:
		intro = "Registered as a remote MCP server. Its tools are listed once the gateway connects, each pending your review."
	}
	c.rows = append(c.rows, para(intro+" Its configuration is not approved until you approve it below.", lipgloss.NewStyle())...)

	c.rows = append(c.rows, blank(), heading("What was registered"))
	covers := "the URL or command, the arguments and the secret names"
	switch res.Transport {
	case adminapi.UpstreamTransportOCI:
		covers = "the image digest, the network and the variable names"
		c.rows = append(c.rows, fact("Image", vis(res.Image)), fact("Network", vis(dash(res.Network))),
			fact("Variable names", vis(dash(strings.Join(res.EnvVarNames, ", ")))))
	case adminapi.UpstreamTransportRemote:
		covers = "the URL, the auth and its secret name, and the transport"
		c.rows = append(c.rows, fact("MCP endpoint", vis(res.URL)), fact("Transport", vis(res.RemoteKind)), fact("Auth", authText(res.Auth, "sent")))
	default:
		doc := vis(res.Source)
		if res.FetchedBytes > 0 {
			doc += fmt.Sprintf(", %d bytes", res.FetchedBytes)
		}
		if res.BasePath != "" {
			doc += ", base path " + vis(res.BasePath)
		}
		auth := authText(res.Auth, "injected")
		if res.AuthDerived {
			auth += stDim.Render("  derived from the document")
		}
		safe := 0
		for _, t := range res.Tools {
			if t.Class != adminapi.ClassSensitive {
				safe++
			}
		}
		c.rows = append(c.rows, fact("Base URL", vis(res.URL)), fact("Document", doc), fact("Auth", auth),
			fact("Tools generated", fmt.Sprintf("%d safe, %d sensitive", safe, len(res.Tools)-safe)))
	}

	if len(res.Tools) > 0 {
		c.rows = append(c.rows, blank(), heading("Operations  each is one MCP tool, pending review"),
			textRow(stDim.Render("A POST, PUT, PATCH or DELETE is sensitive: it needs clearing and a non_read role before it is served.")),
			textRow(stDim.Render(cols(opCols, "TOOL", "METHOD", "PATH", "CLASS"))))
		for _, t := range res.Tools {
			c.rows = append(c.rows, textRow(cols(opCols, vis(t.Name), vis(t.Method), vis(t.Path), classText(t.Class))))
		}
	}

	var notes []string
	notes = append(notes, res.IngestWarnings...)
	for _, w := range res.Warnings {
		notes = append(notes, w.Message)
	}
	if len(res.Skipped) > 0 {
		notes = append(notes, "Skipped operations: "+strings.Join(res.Skipped, ", "))
	}
	if len(notes) > 0 {
		c.rows = append(c.rows, blank(), heading("Notes"))
		for _, n := range notes {
			c.rows = append(c.rows, para(vis(n), lipgloss.NewStyle())...)
		}
	}

	// The configuration's state is read again, so the page shows an approval
	// made from it.
	signature := res.Signature
	if d, err := upstreamDetail(e, name, caps.Manages); err != nil {
		c.problems = append(c.problems, errText(err))
	} else {
		signature = d.Signature
	}
	c.rows = append(c.rows, blank(), heading("Approve configuration"), fact("Config", configText(signature)))
	c.rows = append(c.rows, para("Approving signs the configuration shown above. Review "+covers+" first: the approval covers exactly that, nothing about the tools. "+
		"It is a separate step from registering, on purpose: the gateway does not serve a backend whose configuration is not approved.", stDim)...)
	if managesAndRoot(caps) {
		c.actions = append(c.actions, approveConfigAction(e, name, signature))
	} else {
		c.rows = append(c.rows, para("Approving the configuration needs root's accounts socket: start with sudo mcp-gateway tui -manage-users, or run sudo mcp-gateway sign "+vis(name)+".", stWarn)...)
	}
	c.actions = append(c.actions, action{key: "O", label: "open its page", run: func() tea.Cmd { return push(serverPage(name)) }})
	return c
}

var opCols = []int{24, 7, 32}

// authText is an auth descriptor in words: never a value, only where the
// key goes and its vault name.
func authText(a adminapi.UpstreamAuth, verb string) string {
	if a.Kind == "" || a.Kind == "none" {
		return "None (keyless)"
	}
	s := vis(a.Kind)
	if a.Name != "" {
		s += " " + vis(a.Name)
	}
	if a.Secret != "" {
		s += ", key " + verb + " from vault name " + vis(a.Secret)
	}
	return s
}
