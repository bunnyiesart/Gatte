package config

// design/adr/0042: the OAuth scopes advertised to analysts' clients, and
// the operator's lines put in front of their models.

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func withScopes(scopes string) string {
	return strings.Replace(minimalConfig, `audience = "https://gw.example.internal/mcp"`,
		`audience = "https://gw.example.internal/mcp"`+"\nscopes_supported = "+scopes, 1)
}

func TestScopesSupportedLoadsAndIsOptional(t *testing.T) {
	c := mustLoad(t, withScopes(`["openid", "profile", "email", "groups", "offline_access"]`))
	if want := []string{"openid", "profile", "email", "groups", "offline_access"}; !slices.Equal(c.OIDC.ScopesSupported, want) {
		t.Errorf("ScopesSupported = %v, want %v", c.OIDC.ScopesSupported, want)
	}
	if c := mustLoad(t, minimalConfig); len(c.OIDC.ScopesSupported) != 0 {
		t.Errorf("unset scopes_supported = %v, want none", c.OIDC.ScopesSupported)
	}
}

func TestScopesSupportedRefusesWhatIsNotAScope(t *testing.T) {
	for _, bad := range []string{`["open id"]`, `[""]`, `["groups", "groups"]`, `["a\"b"]`, `["ação"]`} {
		err := loadErr(t, withScopes(bad))
		if !strings.Contains(err.Error(), "oidc.scopes_supported") {
			t.Errorf("scopes_supported = %s: error %v, want one naming the field", bad, err)
		}
	}
}

func withAnalyst(section string) string { return minimalConfig + "\n[analyst]\n" + section + "\n" }

func TestAnalystLinesLoad(t *testing.T) {
	c := mustLoad(t, withAnalyst(`contact = "Plantão do SOC, canal #soc-gatte"
[analyst.backend_notes]
casemgmt = "Casos, alertas e tarefas"
logsearch = "Busca nos logs do SIEM"`))
	if c.Analyst.Contact != "Plantão do SOC, canal #soc-gatte" || c.Analyst.BackendNotes["logsearch"] != "Busca nos logs do SIEM" {
		t.Errorf("analyst = %+v", c.Analyst)
	}
}

func TestAnalystLinesRefuseWhatCannotGoInFrontOfAModel(t *testing.T) {
	cases := map[string]string{
		"a line break":     `contact = "one\ntwo"`,
		"a quote":          `contact = "say \"hi\""`,
		"a backslash":      `contact = "a\\b"`,
		"a bidi override":  "contact = \"abc\u202edef\"",
		"a zero width":     "contact = \"ab\u200bc\"",
		"edge whitespace":  `contact = " SOC"`,
		"too long":         `contact = "` + strings.Repeat("x", MaxContactRunes+1) + `"`,
		"an unknown shape": "[analyst.backend_notes]\n\"bad name\" = \"x\"",
		"the reserved":     "[analyst.backend_notes]\ngatte = \"x\"",
		"an empty note":    "[analyst.backend_notes]\ncasemgmt = \"\"",
		"a long note":      "[analyst.backend_notes]\ncasemgmt = \"" + strings.Repeat("y", MaxBackendNoteRunes+1) + "\"",
	}
	for name, section := range cases {
		err := loadErr(t, withAnalyst(section))
		if !strings.Contains(err.Error(), "analyst.") {
			t.Errorf("%s: error %v, want one naming the analyst field", name, err)
		}
	}
}

func TestAnalystNotesAreBoundedTogether(t *testing.T) {
	var b strings.Builder
	b.WriteString("[analyst.backend_notes]\n")
	for i := range MaxBackendNotes + 1 {
		fmt.Fprintf(&b, "b%02d = \"note\"\n", i)
	}
	if err := loadErr(t, withAnalyst(b.String())); !strings.Contains(err.Error(), "notes, over") {
		t.Errorf("too many notes: %v", err)
	}
	b.Reset()
	b.WriteString("[analyst.backend_notes]\n")
	for i := range 4 {
		fmt.Fprintf(&b, "b%02d = \"%s\"\n", i, strings.Repeat("z", MaxBackendNoteRunes))
	}
	if err := loadErr(t, withAnalyst(b.String())); !strings.Contains(err.Error(), "together") {
		t.Errorf("notes over the joint limit: %v", err)
	}
}
