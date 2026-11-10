package gatteweb

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// The signature state is shown as an attestation of the configuration
// (ADR-0060): never the bare word "Signed", which reads as "safe".
func TestAttestationBadge_NamesTheConfiguration(t *testing.T) {
	tmpl, err := template.New("").
		Funcs(template.FuncMap{"vis": frontkit.VisibleText, "vistext": visibleLines, "state": stateLabel, "since": showTimePtr}).
		ParseFS(assets, "ui/layout.html", "ui/servers.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, tc := range []struct{ state, want, class string }{
		{"yes", "Config attested", "badge ok"},
		{"no", "Config not attested", "badge pending"},
		{"INVALID", "Attestation invalid", "badge danger"},
	} {
		var b bytes.Buffer
		if err := tmpl.ExecuteTemplate(&b, "attestation", tc.state); err != nil {
			t.Fatalf("%s: %v", tc.state, err)
		}
		got := b.String()
		if !strings.Contains(got, tc.want) || !strings.Contains(got, `class="`+tc.class+`"`) || strings.Contains(got, "Signed") {
			t.Errorf("%s renders %q, want %q in a %q badge", tc.state, got, tc.want, tc.class)
		}
	}
}
