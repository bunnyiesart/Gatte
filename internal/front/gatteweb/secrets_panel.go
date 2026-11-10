package gatteweb

// The Secrets slice (design/adr/0051, 0053): a server-detail panel for the
// names one backend declares, and a small global vault view for the names
// shared across backends or declared by none. Reads list only names, whether
// the vault holds a value, and which entries declare each name; a value is
// never returned, rendered or implied. Writes go to the accounts socket as
// root (managed with root), and the result page names the secret only.
//
// A connected backend keeps the key it was dialled with until it is redialled,
// so a set or replace points the operator at Redial, which lives on the server
// page (servers.go).

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// ---- the per-server panel (DetailPanel Order 30)

type secretsPanelData struct {
	Server     string
	Base, CSRF string
	Rows       []panelSecretRow
	// Missing counts the names this backend declares that the vault lacks.
	Missing int
	// VaultRead is whether the vault names were read: without it the panel
	// shows the declared names but not their in-vault state.
	VaultRead bool
	VaultErr  string
}

// panelSecretRow is one name this backend declares. InVault is meaningful only
// when the panel read the vault; the value itself is never held or shown.
type panelSecretRow struct {
	Name    string
	InVault bool
}

// secretsPanel draws the Secrets panel for one backend: the names it declares
// (UpstreamDetail.EnvVarNames), whether each is in the vault, and write-only
// set/replace/delete controls. The vault read is the accounts socket's (the
// vault lives there); a read that fails still shows the declared names, with the
// reason.
func (f *Front) secretsPanel(r *http.Request, d adminapi.UpstreamDetail) (template.HTML, error) {
	data := secretsPanelData{Server: d.Name, Base: f.kit.Base(), CSRF: f.kit.CSRFToken()}
	if len(d.EnvVarNames) > 0 {
		var vault []adminapi.Secret
		if list, err := f.acc.ListSecrets(r.Context()); err != nil {
			data.VaultErr = errText(err)
		} else {
			data.VaultRead = true
			vault = list.Secrets
		}
		data.Rows, data.Missing = declaredRows(d.EnvVarNames, vault, data.VaultRead)
	}
	var b bytes.Buffer
	if err := f.pages.ExecuteTemplate(&b, "panel_secrets.html", data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil // #nosec G203 -- the template's own HTML-escaped output
}

// declaredRows is one backend's declared names against the vault: for each name
// whether the vault holds a value, and how many are missing. readOK is whether
// the vault read succeeded; without it the in-vault state is left unknown and
// nothing is counted missing. No value is ever part of this.
func declaredRows(names []string, vault []adminapi.Secret, readOK bool) ([]panelSecretRow, int) {
	inVault := make(map[string]bool, len(vault))
	for _, s := range vault {
		inVault[s.Name] = s.InVault
	}
	rows := make([]panelSecretRow, 0, len(names))
	missing := 0
	for _, n := range names {
		row := panelSecretRow{Name: n}
		if readOK {
			row.InVault = inVault[n]
			if !row.InVault {
				missing++
			}
		}
		rows = append(rows, row)
	}
	return rows, missing
}

// ---- the global vault view (GET /vault, no nav item; reached from the panel)

type vaultData struct {
	Secrets []vaultRow
	// Missing, Shared and Orphan are the counts the summary shows.
	Missing, Shared, Orphan int
	// RegistryRead is false when the registry could not be read: DeclaredBy is
	// then absent, so a name is not called an orphan on a guess.
	RegistryRead bool
}

// vaultRow is one vault name as the global view classes it: Missing (declared
// but absent), Orphan (present but declared by nothing), Shared (declared by
// more than one backend). The value is never part of this.
type vaultRow struct {
	Name                    string
	InVault                 bool
	DeclaredBy              []string
	Missing, Shared, Orphan bool
}

func (f *Front) vaultView(w http.ResponseWriter, r *http.Request) {
	if !f.managed(w, r, true) {
		return
	}
	list, err := f.acc.ListSecrets(r.Context())
	d := classifyVault(list)
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	for _, p := range list.Problems {
		errs = append(errs, p.Message)
	}
	f.render(w, r, "vaultview", "Vault", page{Nav: "servers", Data: d, Error: strings.Join(errs, "\n")})
}

// classifyVault sorts the vault's names into the global view's classes:
// Missing (declared but absent), Orphan (present but declared by nothing, only
// when the registry was read), and Shared (declared by more than one backend),
// with the counts the summary shows. It carries names, never values.
func classifyVault(list adminapi.SecretList) vaultData {
	d := vaultData{RegistryRead: list.RegistryRead}
	for _, s := range list.Secrets {
		row := vaultRow{Name: s.Name, InVault: s.InVault, DeclaredBy: s.DeclaredBy}
		switch {
		case !s.InVault && len(s.DeclaredBy) > 0:
			row.Missing = true
			d.Missing++
		case s.InVault && len(s.DeclaredBy) == 0 && list.RegistryRead:
			row.Orphan = true
			d.Orphan++
		}
		if len(s.DeclaredBy) > 1 {
			row.Shared = true
			d.Shared++
		}
		d.Secrets = append(d.Secrets, row)
	}
	return d
}

// ---- writes (accounts socket, root)

// secretSetTo writes one value and returns to back, with redial appended to a
// successful result (a connected backend keeps the old value until redial).
func (f *Front) secretSetTo(w http.ResponseWriter, r *http.Request, back, redial string) {
	if !f.managed(w, r, true) {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if before, _, found := strings.Cut(name, "="); found {
		// NAME=value pasted as the name: refused here, because the title and
		// the backend's refusal would both repeat the name, value and all.
		// Only the part left of "=" is said.
		text := "Nothing was written: the name looks like NAME=value (the value is not repeated here). Put " +
			frontkit.VisibleText(before) + " in Name and the value in Value."
		f.showResult(w, r, "servers", "Set a secret", back, result{Summary: text, Output: text})
		return
	}
	res, err := f.acc.SetSecret(r.Context(), name, r.PostForm.Get("value"))
	out := actionResult(res.ActionResult, err)
	if out.OK && redial != "" {
		out.Output = strings.TrimSpace(out.Output + "\n" + redial)
	}
	f.showResult(w, r, "servers", "Set "+frontkit.VisibleText(name), back, out)
}

// secretDeleteTo removes one value and returns to back. The checkbox must be
// ticked, so a stray POST deletes nothing.
func (f *Front) secretDeleteTo(w http.ResponseWriter, r *http.Request, back string) {
	if !f.managed(w, r, true) {
		return
	}
	name := r.PostForm.Get("name")
	if r.PostForm.Get("confirm") != "yes" {
		f.showResult(w, r, "servers", "Delete "+frontkit.VisibleText(name), back,
			result{Summary: "Nothing was deleted: tick the confirmation first."})
		return
	}
	res, err := f.acc.DeleteSecret(r.Context(), name)
	f.showResult(w, r, "servers", "Delete "+frontkit.VisibleText(name), back, actionResult(res.ActionResult, err))
}

func (f *Front) serverSecretSet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	redial := "The backend keeps the key it was dialled with until it is redialled: redial " +
		frontkit.VisibleText(name) + " from its page."
	f.secretSetTo(w, r, serverBack(name), redial)
}

func (f *Front) serverSecretDelete(w http.ResponseWriter, r *http.Request) {
	f.secretDeleteTo(w, r, serverBack(r.PathValue("name")))
}

func (f *Front) vaultSecretSet(w http.ResponseWriter, r *http.Request) {
	f.secretSetTo(w, r, "/vault",
		"A connected backend keeps the key it was dialled with: redial each backend that uses it from its page.")
}

func (f *Front) vaultSecretDelete(w http.ResponseWriter, r *http.Request) {
	f.secretDeleteTo(w, r, "/vault")
}
