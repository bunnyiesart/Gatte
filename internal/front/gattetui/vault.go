package gattetui

// Secrets (design/adr/0051, 0053): a server-detail panel for the names one
// backend declares, and a small vault page for every name, shared or
// declared by none. Only names, whether the vault holds a value, and who
// declares each are ever read; a value is typed hidden, sent once, and
// never drawn, kept or returned. Reads and writes are root's, on the
// accounts socket, so the whole surface needs the managing console and
// -manage-users.

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func init() {
	registerDetailPanel(DetailPanel{ID: "secrets", Order: 30, Show: managesAndRoot, Rows: secretsPanel})
}

func secretsPanel(e env, d adminapi.UpstreamDetail) ([]row, error) {
	rows := []row{heading("Secrets  names only; a value is never shown")}
	if len(d.EnvVarNames) == 0 {
		return append(rows, textRow(stDim.Render("This backend declares no secret."))), nil
	}
	list, err := e.acc.ListSecrets(ctx())
	inVault := map[string]bool{}
	if err != nil {
		rows = append(rows, textRow(stBad.Render("The vault could not be read: "+vis(errText(err)))))
	}
	for _, s := range list.Secrets {
		inVault[s.Name] = s.InVault
	}
	redial := "The backend keeps the key it was dialled with until it is redialled: press D on this page."
	for _, n := range d.EnvVarNames {
		state := stDim.Render("unknown")
		if err == nil {
			state = stBad.Render("missing from the vault")
			if inVault[n] {
				state = stOK.Render("in the vault")
			}
		}
		rows = append(rows, row{text: cols([]int{28}, vis(n), state), actions: secretActions(e, n, redial)})
	}
	return rows, nil
}

// secretActions are set and delete for one name. A set points at redial,
// since a connected backend keeps the old value until then.
func secretActions(e env, name, redial string) []action {
	return []action{
		{key: "s", label: "set value", run: func() tea.Cmd { return setSecret(e, name, redial) }},
		{key: "x", label: "delete value", run: func() tea.Cmd {
			return confirm("Delete the vault's value of "+vis(name)+"? A backend that needs it cannot be dialled again without it.", func() tea.Cmd {
				return do(func() result {
					res, err := e.acc.DeleteSecret(ctx(), name)
					return fromAction(res.ActionResult, err, "Deleted the value of "+name+".")
				})
			})
		}},
	}
}

func setSecret(e env, name, redial string) tea.Cmd {
	return askHidden("Value of "+vis(name)+" (hidden, never shown again)", func(value string) tea.Cmd {
		return do(func() result {
			res, err := e.acc.SetSecret(ctx(), name, value)
			r := fromAction(res.ActionResult, err, "Wrote "+name+" to the vault.")
			if r.ok {
				r.output = append(r.output, redial)
			}
			return r
		})
	})
}

// ---- the vault page (all names)

func vaultPage() *page { return newPage("Vault", fillVault) }

func fillVault(e env) content {
	var c content
	list, err := e.acc.ListSecrets(ctx())
	if err != nil {
		c.problems = append(c.problems, errText(err))
	}
	for _, p := range list.Problems {
		c.problems = append(c.problems, vis(p.Message))
	}
	redial := "A connected backend keeps the key it was dialled with: redial each backend that uses it."
	c.rows = append(c.rows, textRow(stDim.Render(cols([]int{24, 24}, "NAME", "VALUE", "DECLARED BY"))))
	for _, s := range list.Secrets {
		state := stOK.Render("in the vault")
		switch {
		case !s.InVault && len(s.DeclaredBy) > 0:
			state = stBad.Render("missing")
		case !s.InVault:
			state = stDim.Render("absent")
		case len(s.DeclaredBy) == 0 && list.RegistryRead:
			// Only called an orphan when the registry was read, never on a
			// guess.
			state = stWarn.Render("orphan: declared by none")
		}
		by := vis(strings.Join(s.DeclaredBy, ", "))
		if len(s.DeclaredBy) > 1 {
			by += stDim.Render("  (shared)")
		}
		c.rows = append(c.rows, row{text: cols([]int{24, 24}, vis(s.Name), state, by), actions: secretActions(e, s.Name, redial)})
	}
	c.actions = append(c.actions, action{key: "n", label: "new name", run: func() tea.Cmd {
		return ask("Secret name", "", func(name string) tea.Cmd {
			name = strings.TrimSpace(name)
			if before, _, found := strings.Cut(name, "="); found {
				// NAME=value pasted as the name: refused here, because every
				// message after this would repeat it, value and all.
				return do(func() result {
					return refused("Nothing was written: the name looks like NAME=value (the value is not repeated here). Give " + vis(before) + " as the name and the value at the next prompt.")
				})
			}
			return setSecret(e, name, redial)
		})
	}})
	return c
}
