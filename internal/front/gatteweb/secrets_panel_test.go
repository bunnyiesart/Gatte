package gatteweb

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// The Secrets panel is a server-detail panel at Order 30, shown only on the
// managing console that holds the accounts socket (design/adr/0051, 0053): the
// write controls never appear on a console that could not use them.
func TestSecretsPanel_RegisteredAtOrder30AndGatedToManagesAndRoot(t *testing.T) {
	var p *DetailPanel
	for _, d := range orderedDetailPanels() {
		if d.ID == "secrets" {
			d := d
			p = &d
			break
		}
	}
	if p == nil {
		t.Fatal("no secrets DetailPanel registered")
	}
	if p.Order != 30 {
		t.Fatalf("secrets panel Order = %d, want 30", p.Order)
	}
	if p.Show == nil {
		t.Fatal("secrets panel has no Show gate; it must be managesAndRoot")
	}
	cases := []struct {
		caps Capabilities
		want bool
	}{
		{Capabilities{Manages: true, Root: true}, true},
		{Capabilities{Manages: true}, false},
		{Capabilities{Root: true}, false},
		{Capabilities{}, false},
	}
	for _, c := range cases {
		if got := p.Show(c.caps); got != c.want {
			t.Errorf("Show(%+v) = %v, want %v", c.caps, got, c.want)
		}
	}
}

// declaredRows marks each name a backend declares as set or missing against the
// vault, and counts the missing. A vault read that failed leaves the state
// unknown and counts nothing missing, so the panel never cries "missing" on a
// read it could not make.
func TestDeclaredRows(t *testing.T) {
	vault := []adminapi.Secret{{Name: "A", InVault: true}, {Name: "B", InVault: false}}
	rows, missing := declaredRows([]string{"A", "B", "C"}, vault, true)
	if missing != 2 {
		t.Fatalf("missing = %d, want 2 (B and the undeclared C)", missing)
	}
	want := []panelSecretRow{{Name: "A", InVault: true}, {Name: "B"}, {Name: "C"}}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
	if _, missing := declaredRows([]string{"A", "B"}, vault, false); missing != 0 {
		t.Fatalf("missing with no vault read = %d, want 0", missing)
	}
}

// classifyVault sorts the vault into the global view's classes and counts.
func TestClassifyVault(t *testing.T) {
	list := adminapi.SecretList{
		RegistryRead: true,
		Secrets: []adminapi.Secret{
			{Name: "SIEM_TOKEN", InVault: true, DeclaredBy: []string{"casemgmt", "logsearch"}},
			{Name: "SHODAN_KEY", InVault: false, DeclaredBy: []string{"threatintel"}},
			{Name: "ORPHAN_KEY", InVault: true},
			{Name: "THREATINTEL_API_KEY", InVault: true, DeclaredBy: []string{"threatintel"}},
		},
	}
	d := classifyVault(list)
	if d.Missing != 1 || d.Shared != 1 || d.Orphan != 1 {
		t.Fatalf("counts = missing %d, shared %d, orphan %d; want 1, 1, 1", d.Missing, d.Shared, d.Orphan)
	}
	by := map[string]vaultRow{}
	for _, r := range d.Secrets {
		by[r.Name] = r
	}
	if !by["SIEM_TOKEN"].Shared || !by["SHODAN_KEY"].Missing || !by["ORPHAN_KEY"].Orphan {
		t.Fatalf("classification = %+v", d.Secrets)
	}

	// With the registry unread, DeclaredBy is absent for every name, so a name
	// in the vault is not called an orphan on a guess.
	noReg := classifyVault(adminapi.SecretList{RegistryRead: false, Secrets: []adminapi.Secret{{Name: "ORPHAN_KEY", InVault: true}}})
	if noReg.Orphan != 0 || noReg.Secrets[0].Orphan {
		t.Fatal("a name was called an orphan although the registry could not be read")
	}
}

// The panel and the global view render names, the in-vault state and write-only
// controls -- and never a value. The value field is a password input that is
// never pre-filled, so a value cannot reach the page even if one were held.
func TestSecretTemplates_RenderNamesAndWriteOnlyFields_NeverAValue(t *testing.T) {
	tmpl, err := template.New("").
		Funcs(template.FuncMap{"vis": frontkit.VisibleText, "vistext": visibleLines}).
		ParseFS(assets, "ui/layout.html", "ui/panel_secrets.html", "ui/vaultview.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	rows, missing := declaredRows([]string{"THREATINTEL_API_KEY", "SHODAN_KEY"},
		[]adminapi.Secret{{Name: "THREATINTEL_API_KEY", InVault: true}}, true)
	var panel bytes.Buffer
	if err := tmpl.ExecuteTemplate(&panel, "panel_secrets.html",
		secretsPanelData{Server: "threatintel", CSRF: "t", Rows: rows, Missing: missing, VaultRead: true}); err != nil {
		t.Fatalf("panel: %v", err)
	}
	ph := panel.String()
	for _, want := range []string{"THREATINTEL_API_KEY", "SHODAN_KEY", "Replace", "Set",
		`type="password"`, "/servers/threatintel/secrets/set", "1 name is", "/vault"} {
		if !strings.Contains(ph, want) {
			t.Errorf("panel is missing %q", want)
		}
	}

	d := classifyVault(adminapi.SecretList{RegistryRead: true, Secrets: []adminapi.Secret{
		{Name: "SIEM_TOKEN", InVault: true, DeclaredBy: []string{"casemgmt", "logsearch"}},
		{Name: "SHODAN_KEY", InVault: false, DeclaredBy: []string{"threatintel"}},
		{Name: "ORPHAN_KEY", InVault: true},
	}})
	var view bytes.Buffer
	if err := tmpl.ExecuteTemplate(&view, "vaultview.html", page{CSRF: "t", Data: d}); err != nil {
		t.Fatalf("vault: %v", err)
	}
	vh := view.String()
	for _, want := range []string{"Shared", "Orphan", "Missing", "1 name a backend declares is",
		`type="password"`, "/vault/set", "/vault/delete"} {
		if !strings.Contains(vh, want) {
			t.Errorf("vault view is missing %q", want)
		}
	}

	// The value field is never pre-filled: no password input carries a value.
	for _, out := range []string{ph, vh} {
		if strings.Contains(out, `name="value" value=`) || strings.Contains(out, `type="password" value=`) {
			t.Error("a value field was rendered with a value; it must be write-only")
		}
	}
}
