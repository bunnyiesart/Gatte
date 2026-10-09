package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
)

// Tests for `non_read` on a [[role]] (design/adr/0048 Decisão 5): the
// file-format half. What the marking means at the dispatch edge is tested
// in internal/gateway; that the policy carries it, in internal/access.

// nonReadConfig is completeConfig plus a role that may act: marked
// non_read and naming the sensitive tool in `tools`, mapped from a group.
const nonReadConfig = completeConfig + `
[[role]]
name     = "actor"
tools    = ["casemgmt.close_case"]
non_read = true
`

func TestLoadNonReadRoundTrip(t *testing.T) {
	c := mustLoad(t, nonReadConfig)
	var actor *Role
	for i := range c.Roles {
		if c.Roles[i].Name == "actor" {
			actor = &c.Roles[i]
		}
	}
	if actor == nil {
		t.Fatal("the role carrying non_read was dropped during load")
	}
	if !actor.NonRead {
		t.Error("non_read = true did not load")
	}
	for _, r := range c.Roles {
		if r.Name != "actor" && r.NonRead {
			t.Errorf("role %q is marked non_read without the key: the zero value must be false", r.Name)
		}
	}
}

// TestToAccessPolicyCarriesNonRead: ToAccessPolicy is the one conversion
// both boot and a reload go through, and dropping the marking there would
// deny every sensitive tool to everybody, silently. The check is the
// policy's own question, AuthorizeNonRead, so the test cannot pass on a
// field the gate does not read.
func TestToAccessPolicyCarriesNonRead(t *testing.T) {
	contents := strings.Replace(nonReadConfig, `"soc-dfir" = "dfir-lead"`, `"soc-dfir" = "dfir-lead"
"soc-act" = "actor"`, 1)
	c := mustLoad(t, contents)
	p, err := c.ToAccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	actor := access.Identity{Subject: "u1", Groups: []string{"soc-act"}}
	if err := p.AuthorizeNonRead(actor, "casemgmt.close_case"); err != nil {
		t.Errorf("the non_read role did not reach its explicit tool through the policy: %v", err)
	}
	reader := access.Identity{Subject: "u2", Groups: []string{"soc-dfir"}}
	if err := p.AuthorizeNonRead(reader, "casemgmt.close_case"); err == nil {
		t.Error("a role without non_read reached a sensitive tool through the policy")
	}
}

// TestLoadRejectsNonReadOverAnEmptyToolsList: the marking applies to names
// in `tools` and to nothing else, so over an empty list it marks nothing
// and loads -- the silent-no-op shape this package refuses (GAB-30 item
// 3). A non_read role whose grants cover the backend is the likely way to
// write it, and the message has to say that the grant is not enough.
func TestLoadRejectsNonReadOverAnEmptyToolsList(t *testing.T) {
	for name, body := range map[string]string{
		"no tools at all": `
[[role]]
name     = "actor"
non_read = true
`,
		"only grants": `
[[role]]
name     = "actor"
non_read = true

  [role.grants]
  casemgmt = ["*"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			err := loadErr(t, completeConfig+body)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error does not wrap ErrInvalid: %v", err)
			}
			for _, want := range []string{`role "actor"`, "non_read", "`tools` is empty", "[role.grants]"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not contain %q: %v", want, err)
				}
			}
		})
	}
	// The same role with one explicit name is fine, grants or not.
	mustLoad(t, completeConfig+`
[[role]]
name     = "actor"
tools    = ["casemgmt.close_case"]
non_read = true

  [role.grants]
  casemgmt = ["*"]
`)
}
