package reload

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
)

func base() *config.Config {
	return &config.Config{
		Listen:   "127.0.0.1:8080",
		Database: "/var/db/mcp-gateway/mcp-gateway.db",
		Signer:   config.Signer{TrustedKeys: []string{"key-a"}},
		Roles: []config.Role{
			{Name: "ir", Grants: map[string][]string{"casemgmt": {"*"}}},
			{Name: "triage", Tools: []string{"logsearch.search"}},
		},
		GroupToRole: map[string]string{"blue-ir": "ir", "blue-n1": "triage"},
		Quota: config.Quota{Providers: []config.QuotaProvider{
			{Name: "virustotal", Upstream: "threatintel", Limit: 100, Window: 24 * time.Hour, Tools: []string{"threatintel.lookup_ip"}},
		}},
	}
}

var routed = []string{"casemgmt.close_case", "casemgmt.list_cases", "logsearch.search", "threatintel.lookup_ip"}

func TestDiff_NamesWhoGainsAndLosesWhichToolAndNothingElse(t *testing.T) {
	old, next := base(), base()
	next.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"casemgmt": {"list_cases"}}},
		{Name: "triage", Tools: []string{"logsearch.search", "threatintel.lookup_ip"}},
		{Name: "hunt", Tools: []string{"logsearch.search"}},
	}
	next.GroupToRole = map[string]string{"blue-ir": "ir", "blue-n1": "hunt", "blue-new": "triage"}
	next.Quota.Providers[0].Limit = 50
	c := Diff(old, next, routed)

	if len(c.Roles) != 3 {
		t.Fatalf("roles = %+v", c.Roles)
	}
	byName := map[string]RoleChange{}
	for _, r := range c.Roles {
		byName[r.Role] = r
	}
	if r := byName["ir"]; r.Added || r.Removed || len(r.Gained) != 0 || !slices.Equal(r.Lost, []string{"casemgmt.close_case"}) {
		t.Errorf("ir = %+v", r)
	}
	if r := byName["triage"]; !slices.Equal(r.Gained, []string{"threatintel.lookup_ip"}) || len(r.Lost) != 0 {
		t.Errorf("triage = %+v", r)
	}
	if r := byName["hunt"]; !r.Added || !slices.Equal(r.Gained, []string{"logsearch.search"}) {
		t.Errorf("hunt = %+v", r)
	}
	if !slices.Equal(c.Groups, []GroupChange{{Group: "blue-n1", From: "triage", To: "hunt"}, {Group: "blue-new", To: "triage"}}) {
		t.Errorf("groups = %+v", c.Groups)
	}
	if len(c.Quota) != 1 || c.Quota[0].Change != "changed" || !strings.HasPrefix(c.Quota[0].To, "50 per 24h0m0s on threatintel") {
		t.Errorf("quota = %+v", c.Quota)
	}
	if len(c.NotReloaded) != 0 || c.Empty() {
		t.Errorf("NotReloaded %v, Empty %v", c.NotReloaded, c.Empty())
	}
}

// A wildcard rewritten as the tools it reaches today moves no routed tool,
// but it is a different grant: the wildcard would have reached the next
// tool casemgmt adds (design/adr/0016). Reach is unchanged and the grant
// change is named.
func TestDiff_ARewrittenGrantThatReachesTheSameToolsNamesTheGrantOnly(t *testing.T) {
	old, next := base(), base()
	next.Roles[0].Grants = nil
	next.Roles[0].Tools = []string{"casemgmt.close_case", "casemgmt.list_cases"}
	c := Diff(old, next, routed)
	if len(c.Roles) != 1 || len(c.Roles[0].Gained) != 0 || len(c.Roles[0].Lost) != 0 ||
		!slices.Equal(c.Roles[0].GrantsRemoved, []string{"casemgmt.*"}) ||
		!slices.Equal(c.Roles[0].GrantsAdded, []string{"casemgmt.close_case", "casemgmt.list_cases"}) {
		t.Fatalf("Diff = %+v, want the grant change and no change of reachability", c.Roles)
	}
}

func TestNotReloaded_SaysWhichKeysNeedARestart(t *testing.T) {
	old, next := base(), base()
	next.Listen = "127.0.0.1:9090"
	next.Signer.TrustedKeys = []string{"key-a", "key-b"}
	next.Roles = nil // reloadable, not listed
	// Read by sign and by the management backend on every run: no restart.
	next.Signer.KeyFile = "/usr/local/etc/mcp-gateway/signing-2.key"
	next.IdP.UsersFile = "/etc/authelia/users.yml"
	next.Admin.OperatorGroup = "gatte-operators"
	got := NotReloaded(old, next)
	if !slices.Equal(got, []string{"listen", "signer.trusted_keys"}) {
		t.Fatalf("NotReloaded = %v", got)
	}
	s := Summary(Diff(old, next, routed), 0)
	if !strings.Contains(s, "NOT applied until restart: listen, signer.trusted_keys") || !strings.Contains(s, `role "ir" removed -casemgmt.close_case -casemgmt.list_cases`) {
		t.Fatalf("Summary = %q", s)
	}
}

func TestSummary_IsBoundedAndStaysValidUTF8(t *testing.T) {
	old, next := base(), base()
	var many []config.Role
	for i := 0; i < 200; i++ {
		many = append(many, config.Role{Name: "papel-ção-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("é", i%3)})
	}
	next.Roles = many
	s := Summary(Diff(old, next, routed), 300)
	if len(s) > 300 || !strings.HasSuffix(s, "(truncated; the full diff is in the request result)") {
		t.Fatalf("len %d: %q", len(s), s)
	}
	if strings.ToValidUTF8(s, "!") != s {
		t.Fatalf("Summary cut a rune: %q", s)
	}
	if got := Summary(Changes{}, 0); got != "no change to roles, groups or quota" {
		t.Fatalf("empty Summary = %q", got)
	}
}

// The operator's lines for analysts (design/adr/0042 item 3) go into
// instructions the MCP endpoint builds once, at startup, so a reload does
// not apply them and must say so rather than report success in silence.
func TestNotReloaded_NamesTheAnalystLinesAndTheAdvertisedScopes(t *testing.T) {
	old, next := base(), base()
	next.Analyst.Contact = "SOC on-call"
	next.Analyst.BackendNotes = map[string]string{"casemgmt": "Cases, alerts and tasks"}
	next.OIDC.ScopesSupported = []string{"openid", "groups"}
	got := NotReloaded(old, next)
	want := []string{"analyst.backend_notes", "analyst.contact", "oidc.scopes_supported"}
	if !slices.Equal(got, want) {
		t.Fatalf("NotReloaded = %v, want %v", got, want)
	}
}

// TestDiff_ARewrittenGrantIsRecordedEvenWhenNothingRoutedMoves: reach is
// measured over the tools routed at the reload, so widening a role to a
// backend that is down or not yet listed moves nothing in Gained. The
// grant itself changed, and the row must say so.
func TestDiff_ARewrittenGrantIsRecordedEvenWhenNothingRoutedMoves(t *testing.T) {
	old, next := base(), base()
	next.Roles = []config.Role{
		{Name: "ir", Grants: map[string][]string{"casemgmt": {"*"}}},
		{Name: "triage", Tools: []string{"logsearch.search"}, Grants: map[string][]string{"docsearch": {"*"}}},
	}
	c := Diff(old, next, routed)
	if c.Empty() {
		t.Fatal("a widened grant reads as an empty reload")
	}
	if len(c.Roles) != 1 || c.Roles[0].Role != "triage" || len(c.Roles[0].Gained) != 0 ||
		!slices.Equal(c.Roles[0].GrantsAdded, []string{"docsearch.*"}) || len(c.Roles[0].GrantsRemoved) != 0 {
		t.Fatalf("roles = %+v", c.Roles)
	}
	if s := Summary(c, 0); !strings.Contains(s, `role "triage" grant +docsearch.*`) {
		t.Fatalf("summary = %q", s)
	}
	// The same grant, written in another order, is no change.
	again := base()
	again.Roles[1].Tools = []string{"logsearch.search"}
	if c := Diff(old, again, routed); !c.Empty() {
		t.Fatalf("an unchanged grant reads as a change: %+v", c.Roles)
	}
}
