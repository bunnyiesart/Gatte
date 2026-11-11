package gatteweb

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// The signature state is shown as an approval of the configuration
// (design/adr/0061 §2): never the bare word "Signed", which reads as "safe",
// and never the old "attest" wording.
func TestApprovalBadge_NamesTheConfiguration(t *testing.T) {
	tmpl, err := template.New("").
		Funcs(template.FuncMap{"vis": frontkit.VisibleText, "vistext": visibleLines, "state": stateLabel, "since": showTimePtr}).
		ParseFS(assets, "ui/layout.html", "ui/servers.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, tc := range []struct{ state, want, class string }{
		{"yes", "Config approved", "badge ok"},
		{"no", "Config not approved", "badge pending"},
		{"INVALID", "Changed since approved", "badge danger"},
	} {
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, "approval", tc.state); err != nil {
			t.Fatalf("%s: %v", tc.state, err)
		}
		got := b.String()
		if !strings.Contains(got, tc.want) || !strings.Contains(got, `class="`+tc.class+`"`) || strings.Contains(got, "Signed") || strings.Contains(got, "INVALID") {
			t.Errorf("%s renders %q, want %q in a %q badge", tc.state, got, tc.want, tc.class)
		}
	}
}

// The words ADR-0061 retired do not come back in any template: the console
// says Approve configuration, Reconnect, Remove and Tool security, and shows
// no audit view and no blocklist.
func TestTemplates_UseTheSimplerTerms(t *testing.T) {
	entries, err := assets.ReadDir("ui")
	if err != nil {
		t.Fatal(err)
	}
	retired := []string{"attest", "Attest", "Redial<", ">Redial", "Deregister", "Tool safety", "Seen on the gateway", "Blocklist", "/access/block", "/access/unblock", "Waiting on you", "Mark non_read", "Unmark non_read", "class=\"matrix", "Who may act"}
	for _, e := range entries {
		b, err := assets.ReadFile("ui/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, word := range retired {
			if strings.Contains(string(b), word) {
				t.Errorf("ui/%s still says %q", e.Name(), word)
			}
		}
	}
}
