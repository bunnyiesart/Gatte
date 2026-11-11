package gattetui

import (
	"context"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/internal/adminapitest"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// openAdd opens the add form of one kind from the servers list, as the
// operator would: a, then the kind's row.
func openAdd(t *testing.T, a *app, kind string) {
	t.Helper()
	press(a, "a")
	cursorTo(t, a, kind)
	press(a, "enter")
}

// fill replaces the value of the field whose label starts its row.
func fill(t *testing.T, a *app, label, value string) {
	t.Helper()
	cursorTo(t, a, label+" ")
	press(a, "enter")
	if a.prompt == nil {
		t.Fatalf("enter on %s opened no prompt", label)
	}
	for range a.prompt.buf {
		press(a, "backspace")
	}
	press(a, value, "enter")
}

// choose picks the n-th choice of a choice field.
func choose(t *testing.T, a *app, label, n string) {
	t.Helper()
	cursorTo(t, a, label+" ")
	press(a, "enter", n)
}

func upstream(t *testing.T, c *adminapitest.Clients, name string) (adminapi.Upstream, bool) {
	t.Helper()
	l, err := c.Operator.ListUpstreams(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(l.Upstreams, func(u adminapi.Upstream) bool { return u.Name == name })
	if i < 0 {
		return adminapi.Upstream{}, false
	}
	return l.Upstreams[i], true
}

func TestAddKindsRegisterInOrder(t *testing.T) {
	var ids []string
	for _, k := range orderedAddKinds() {
		ids = append(ids, k.ID)
	}
	if want := []string{"rest", "remote", "oci"}; !slices.Equal(ids, want) {
		t.Fatalf("add kinds %v, want %v", ids, want)
	}
}

// TestAddEachKindRegistersWithoutApproving: each of the three forms sends its
// transport, lands on the registered page with the configuration not
// approved, and only Approve configuration approves it.
func TestAddEachKindRegistersWithoutApproving(t *testing.T) {
	for _, c := range []struct {
		kind, name, transport string
		fill                  func(t *testing.T, a *app)
		shows                 []string
	}{
		{"REST API", "inventory", "http", func(t *testing.T, a *app) {
			fill(t, a, "Base URL", "https://api.example.com")
			fill(t, a, "OpenAPI document URL", "https://api.example.com/openapi.json")
			choose(t, a, "Auth", "3")
		}, []string{"REST API", "get_item", "key injected from vault name INVENTORY_API_KEY"}},
		{"Remote MCP server", "vendor", "remote", func(t *testing.T, a *app) {
			fill(t, a, "MCP endpoint URL", "https://mcp.example.com/mcp")
			choose(t, a, "Auth", "2")
			fill(t, a, "Key's name in the vault", "VENDOR_TOKEN")
		}, []string{"Remote MCP", "https://mcp.example.com/mcp", "streamable", "key sent from vault name VENDOR_TOKEN"}},
		{"Container (oci)", "intel", "oci", func(t *testing.T, a *app) {
			fill(t, a, "Image, pinned by digest", "ghcr.io/example/intel-mcp@sha256:0123")
			fill(t, a, "Network", "pasta")
			fill(t, a, "Variable names (vault)", "INTEL_API_KEY, OTHER_KEY")
		}, []string{"Container", "pasta", "INTEL_API_KEY, OTHER_KEY"}},
	} {
		t.Run(c.transport, func(t *testing.T) {
			a, f := start(t, true)
			openAdd(t, a, c.kind)
			fill(t, a, "Name", c.name)
			c.fill(t, a)
			press(a, "S")

			u, ok := upstream(t, f, c.name)
			if !ok || u.Transport != c.transport {
				t.Fatalf("after S the backend is %+v (registered %t), want transport %s", u, ok, c.transport)
			}
			if u.Signature != "no" {
				t.Fatalf("registering approved the configuration: signature %q", u.Signature)
			}
			if got := a.top().title; got != "Registered "+c.name {
				t.Fatalf("after registering the page is %q", got)
			}
			mustShow(t, a, append(c.shows, "Config not approved", "pending", "[ A Approve configuration ]")...)

			press(a, "A", "y")
			if u, _ := upstream(t, f, c.name); u.Signature != "yes" {
				t.Fatalf("Approve configuration left signature %q", u.Signature)
			}
			mustShow(t, a, "Config approved")
		})
	}
}

func TestContainerIsNotOfferedWithoutPodman(t *testing.T) {
	a, _ := start(t, true)
	a.env.me.Features = slices.DeleteFunc(slices.Clone(a.env.me.Features), func(f string) bool { return f == adminapi.FeatureOCIRegister })
	press(a, "a")
	for i, r := range a.top().rows {
		if a.top().selectable(i) && strings.Contains(r.text, "Container") {
			t.Fatalf("Container is offered without oci_register: %q", r.text)
		}
	}
	mustShow(t, a, "REST API", "Remote MCP server (URL)", "need podman on the gateway's host", "A stdio backend is not added here")
}

func TestAddIsOfferedOnlyWhenTheBackendManages(t *testing.T) {
	a, _ := start(t, false)
	mustShow(t, a, "[ a Add a backend ]")
	a.env.me.Features = slices.DeleteFunc(slices.Clone(a.env.me.Features), func(f string) bool { return f == adminapi.FeatureConsoleManages })
	settle(a, a.load(a.top()))
	mustNotShow(t, a, "Add a backend")
}

func TestRegisterRefusalIsShownEscaped(t *testing.T) {
	a, _ := start(t, true)
	hostile := "bad image\x1b[2J\u202eburied\x07"
	settle(a, func() tea.Msg { return resultMsg{notRegistered(&adminapi.Error{Message: hostile})} })
	v := a.View()
	if strings.Contains(v, "\x1b[2J") || strings.Contains(v, "\u202e") || strings.Contains(v, "\x07") {
		t.Fatalf("a control sequence from the API reached the screen:\n%q", v)
	}
	mustShow(t, a, `Not registered: bad image\u{001B}[2J`)
}

// TestPastedCredentialIsNeverDrawnBack: a value pasted where a name or an
// endpoint goes is not kept, so neither the form nor a refusal repeats it,
// and nothing is registered with it.
func TestPastedCredentialIsNeverDrawnBack(t *testing.T) {
	const secret = "sk-live-0123456789"
	a, c := start(t, true)
	openAdd(t, a, "Remote MCP server")
	fill(t, a, "Name", "vendor")
	for _, f := range []struct{ label, value string }{
		{"Key's name in the vault", "VENDOR_TOKEN=" + secret},
		{"Header name", "X-Api-Key: " + secret},
		{"Header name", "X-Api-Key=" + secret},
		{"MCP endpoint URL", "https://mcp.example.com/mcp?token=" + secret},
		{"MCP endpoint URL", "https://user:" + secret + "@mcp.example.com/mcp"},
		{"MCP endpoint URL", "https://admin:" + secret + "%zz@mcp.example.com/mcp"},
	} {
		fill(t, a, f.label, f.value)
		mustShow(t, a, "Not kept:")
		mustNotShow(t, a, secret)
	}
	press(a, "S")
	mustShow(t, a, "Not registered: a remote backend needs url")
	mustNotShow(t, a, secret)
	if _, ok := upstream(t, c, "vendor"); ok {
		t.Fatal("a refused form registered a backend")
	}

	open(a, addFormPage("oci"))
	fill(t, a, "Variable names (vault)", "INTEL_API_KEY="+secret)
	mustShow(t, a, "Not kept:")
	mustNotShow(t, a, secret)

	open(a, addFormPage("rest"))
	fill(t, a, "OpenAPI document URL", "https://api.example.com/openapi.json?api_key="+secret)
	mustShow(t, a, "Not kept:")
	mustNotShow(t, a, secret)
}

// TestSubmitIsSentOnceWhileInFlight: a second press while the first send
// has not answered sends nothing.
func TestSubmitIsSentOnceWhileInFlight(t *testing.T) {
	a, _ := start(t, true)
	open(a, addFormPage("oci"))
	f := a.top()
	var submit action
	for _, act := range f.actions {
		if act.key == "S" {
			submit = act
		}
	}
	first := submit.run()
	if second := submit.run(); second != nil {
		t.Fatal("a second press sent the form again while the first was in flight")
	}
	settle(a, first)
	if submit.run() == nil {
		t.Fatal("after the answer the form cannot be sent again")
	}
}

// TestRegisteredPageOpensOnTheTabTheFormWasOn: the answer may arrive after
// the operator switched tabs; the registered page still goes on Servers.
func TestRegisteredPageOpensOnTheTabTheFormWasOn(t *testing.T) {
	a, _ := start(t, true)
	open(a, addFormPage("remote"))
	a.origin = a.top().id
	settle(a, a.switchTab(1))
	settle(a, func() tea.Msg {
		return resultMsg{result{ok: true, summary: "done", back: true, open: registeredPage(adminapi.RegisterUpstreamResult{Name: "vendor"})}}
	})
	if got := a.stacks[0][len(a.stacks[0])-1].title; got != "Registered vendor" {
		t.Errorf("the Servers tab shows %q, want the registered page", got)
	}
	if got := a.top().title; got == "Registered vendor" {
		t.Error("the registered page went on the Users tab")
	}
}

func TestRegisteredWithoutRootPointsAtTheCLI(t *testing.T) {
	a, c := start(t, false)
	openAdd(t, a, "Container (oci)")
	fill(t, a, "Name", "intel")
	fill(t, a, "Image, pinned by digest", "ghcr.io/example/intel-mcp@sha256:0123")
	press(a, "S")
	if _, ok := upstream(t, c, "intel"); !ok {
		t.Fatal("intel was not registered")
	}
	mustShow(t, a, "Config not approved", "sudo mcp-gateway sign intel", "[ O Open its page ]")
	mustNotShow(t, a, "[ A Approve configuration ]")
	press(a, "O")
	if got := a.top().title; got != "intel" {
		t.Fatalf("O opened %q, want the backend's page", got)
	}
}
