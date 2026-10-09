package gatteweb

// The People page, the identity provider's accounts
// (design/adr/0038) and the Add person assistant with its connect script
// (design/adr/0039).
//
// Who may call the gateway is decided outside it: the IdP holds the people
// and their groups, and config.toml maps groups to roles. The account
// pages exist only when the console was given the accounts socket
// (-manage-users), which the service account can never serve or reach
// (design/adr/0040 §1).

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

type peopleData struct {
	Manage   bool
	Accounts []adminapi.Account
	Roles    []adminapi.Role
	Seen     []adminapi.Seen
}

func (f *Front) peoplePage(w http.ResponseWriter, r *http.Request) {
	p, err := f.op.People(r.Context())
	d := peopleData{Roles: p.Roles, Seen: p.Seen}
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	if f.acc != nil {
		d.Manage = true
		list, err := f.acc.ListAccounts(r.Context())
		if err != nil {
			errs = append(errs, errText(err))
		}
		d.Accounts = list.Accounts
	}
	f.render(w, r, "people", "People", page{Data: d, Error: strings.Join(errs, "\n")})
}

type accountData struct {
	Account adminapi.Account
	Groups  []adminapi.AssignableGroup
	Has     map[string]bool
	// Offboard and Delete: the accounts socket serves them (features
	// offboard and account_delete, design/adr/0046). Seen is who the trail
	// has seen, for the offboard's subject: the operator picks it.
	Offboard, Delete bool
	Seen             []adminapi.Seen
}

func (f *Front) accountPage(w http.ResponseWriter, r *http.Request) {
	if f.acc == nil {
		http.NotFound(w, r)
		return
	}
	a, err := f.acc.GetAccount(r.Context(), r.URL.Query().Get("u"))
	if adminapi.IsCode(err, adminapi.CodeNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		f.render(w, r, "account", "Account", page{Nav: "people", Error: errText(err)})
		return
	}
	d := accountData{Account: a, Has: map[string]bool{}}
	groups, err := f.acc.AssignableGroups(r.Context())
	d.Groups = groups.Groups
	for _, g := range a.Groups {
		d.Has[g] = true
	}
	if me, werr := f.acc.WhoAmI(r.Context()); werr == nil {
		d.Offboard = slices.Contains(me.Features, adminapi.FeatureOffboard)
		d.Delete = slices.Contains(me.Features, adminapi.FeatureAccountDelete)
	}
	if d.Offboard {
		if p, perr := f.op.People(r.Context()); perr == nil {
			d.Seen = p.Seen
		}
	}
	f.render(w, r, "account", frontkit.VisibleText(a.DisplayName), page{Nav: "people", Data: d, Error: errText(err)})
}

// accountAction runs one account change and shows its result. A one-time
// password is shown on this page and nowhere else, with the connect
// panel beside it: the two things to hand over.
func (f *Front) accountAction(w http.ResponseWriter, r *http.Request, title string, fn func() (username, secret string, res adminapi.ActionResult, err error)) {
	if f.acc == nil {
		http.NotFound(w, r)
		return
	}
	username, secret, ar, err := fn()
	res := actionResult(ar, err)
	back := "/people"
	if err != nil && lostAnswer(err) && username != "" {
		// A creation is not idempotent: the account may exist although the
		// answer, and the password in it, never arrived. Say so instead of
		// letting a retry fail on "already exists".
		if _, gerr := f.acc.GetAccount(r.Context(), username); gerr == nil {
			res.Summary = "The account " + frontkit.VisibleText(username) + " exists, but the answer that carried its one-time password was lost. Give them a new one with Reset password."
			back = "/people/account?u=" + username
		}
	}
	res.Secret, res.SecretFor = secret, username
	res.SecretName = strings.TrimSpace(r.PostForm.Get("displayname"))
	if res.SecretName == "" {
		res.SecretName = username
	}
	if secret != "" {
		panel := f.connectPanelFor(r, username)
		res.Connect = &panel
	}
	f.render(w, r, "result", title+" "+frontkit.VisibleText(username), page{Nav: "people", Data: res.withBack(f.kit.Base() + back)})
}

// lostAnswer reports whether err is a call that got no answer from the
// backend, rather than a refusal from it.
func lostAnswer(err error) bool {
	var ae *adminapi.Error
	return !errors.As(err, &ae) && !errors.Is(err, adminapi.ErrImpostor)
}

func (f *Front) accountAdd(w http.ResponseWriter, r *http.Request) {
	f.accountAction(w, r, "Add", func() (string, string, adminapi.ActionResult, error) {
		n := adminapi.NewAccount{
			Username:    strings.TrimSpace(r.PostForm.Get("username")),
			DisplayName: strings.TrimSpace(r.PostForm.Get("displayname")),
			Email:       strings.TrimSpace(r.PostForm.Get("email")),
			Groups:      r.PostForm["group"],
		}
		res, err := f.acc.AddAccount(r.Context(), n)
		return n.Username, res.OneTimePassword, res.ActionResult, err
	})
}

func (f *Front) accountGroups(w http.ResponseWriter, r *http.Request) {
	f.accountAction(w, r, "Groups for", func() (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		res, err := f.acc.SetAccountGroups(r.Context(), u, r.PostForm["group"])
		return u, "", res.ActionResult, err
	})
}

func (f *Front) accountDisable(w http.ResponseWriter, r *http.Request) {
	f.accountAction(w, r, "Disable", func() (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		res, err := f.acc.DisableAccount(r.Context(), u)
		return u, "", res.ActionResult, err
	})
}

func (f *Front) accountEnable(w http.ResponseWriter, r *http.Request) {
	f.accountAction(w, r, "Enable", func() (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		res, err := f.acc.EnableAccount(r.Context(), u)
		return u, "", res.ActionResult, err
	})
}

func (f *Front) accountReset(w http.ResponseWriter, r *http.Request) {
	f.accountAction(w, r, "New password for", func() (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		res, err := f.acc.ResetAccountPassword(r.Context(), u)
		return u, res.OneTimePassword, res.ActionResult, err
	})
}

// accountOffboard blocks the person in the gateway and disables their
// account in one call of the accounts socket, and shows what is left to
// do by hand.
func (f *Front) accountOffboard(w http.ResponseWriter, r *http.Request) {
	if f.acc == nil {
		http.NotFound(w, r)
		return
	}
	u := r.PostForm.Get("username")
	subject := strings.TrimSpace(r.PostForm.Get("subject_typed"))
	if subject == "" {
		subject = r.PostForm.Get("subject")
	}
	res, err := f.acc.OffboardAccount(r.Context(), u, adminapi.OffboardRequest{Subject: subject, Reason: strings.TrimSpace(r.PostForm.Get("reason"))})
	out := actionResult(res.ActionResult, err)
	if err == nil {
		out.Remaining = res.Remaining
		for _, w := range res.Warnings {
			if w.Code == adminapi.WarnOffboardIncomplete {
				out.OK, out.Summary = false, w.Message
			}
		}
	}
	f.render(w, r, "result", "Offboard "+frontkit.VisibleText(u), page{Nav: "people", Data: out.withBack(f.kit.Base() + "/people/account?u=" + url.QueryEscape(u))})
}

// accountDelete removes the account. The form carries a confirmation the
// operator ticks; the backend's rule is the same with or without it.
func (f *Front) accountDelete(w http.ResponseWriter, r *http.Request) {
	if f.acc == nil {
		http.NotFound(w, r)
		return
	}
	u := r.PostForm.Get("username")
	if r.PostForm.Get("confirm") != "yes" {
		f.showResult(w, r, "people", "Delete "+frontkit.VisibleText(u), "/people/account?u="+url.QueryEscape(u),
			result{Summary: "Nothing was deleted: tick the confirmation first."})
		return
	}
	res, err := f.acc.DeleteAccount(r.Context(), u)
	f.showResult(w, r, "people", "Delete "+frontkit.VisibleText(u), "/people", actionResult(res.ActionResult, err))
}

// ---- connect

type connectPanel struct {
	C adminapi.Connect
	// Missing says what to set when the scripts are not configured.
	Missing string
	Error   string
}

func (f *Front) connectPanelFor(r *http.Request, username string) connectPanel {
	c, err := f.op.Connect(r.Context(), username)
	p := connectPanel{C: c, Error: errText(err)}
	if err == nil && !c.Ready {
		keys := c.Missing
		if len(keys) == 0 {
			keys = []string{"client_id", "callback_port"}
		}
		p.Missing = "Set [connect] " + strings.Join(keys, " and ") + " in the configuration file: the public OAuth client your identity provider has registered for Claude Code, and the port of its redirect URI."
	}
	return p
}

func (f *Front) connectPage(w http.ResponseWriter, r *http.Request) {
	p := f.connectPanelFor(r, r.URL.Query().Get("u"))
	f.render(w, r, "connect", "Connect a computer", page{Nav: "people", Data: p, Error: p.Error})
}

var fileNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// connectScript serves a script as a download. It changes nothing, so GET
// is right; it carries no secret, so nothing is lost if it is saved.
func (f *Front) connectScript(w http.ResponseWriter, r *http.Request) {
	text, name, err := f.op.ConnectScript(r.Context(), r.URL.Query().Get("os"), r.URL.Query().Get("u"))
	if err != nil {
		var ae *adminapi.Error
		if errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 {
			http.Error(w, errText(err), http.StatusNotFound)
			return
		}
		http.Error(w, errText(err), http.StatusBadGateway)
		return
	}
	if !fileNameRe.MatchString(name) {
		name = "connect-gatte.txt"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(text)) // #nosec G705 -- a text/plain attachment, with nosniff from frontkit
}

// ---- the Add person assistant

type newPerson struct {
	Step        int
	DisplayName string
	Username    string
	Email       string
	Groups      []adminapi.AssignableGroup
	Chosen      map[string]bool
	Picked      []adminapi.AssignableGroup
}

// newPersonPage is the assistant's three GET steps: they change nothing,
// and the backend checks each one (account-check) before the next shows.
func (f *Front) newPersonPage(w http.ResponseWriter, r *http.Request) {
	if f.acc == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	d := newPerson{Step: 1, DisplayName: strings.TrimSpace(q.Get("displayname")), Username: strings.TrimSpace(q.Get("username")),
		Email: strings.TrimSpace(q.Get("email")), Chosen: map[string]bool{}}
	for _, g := range q["group"] {
		d.Chosen[g] = true
	}
	var errs []string
	groups, err := f.acc.AssignableGroups(r.Context())
	if err != nil {
		errs = append(errs, errText(err))
	}
	d.Groups = groups.Groups
	switch r.URL.Path {
	case "/people/new/access", "/people/new/review":
		draft := adminapi.AccountDraft{DisplayName: d.DisplayName, Username: d.Username, Email: d.Email}
		if r.URL.Path == "/people/new/review" {
			draft.Groups = q["group"]
		}
		chk, err := f.acc.CheckAccount(r.Context(), draft)
		if err != nil {
			errs = append(errs, errText(err))
			break
		}
		d.Username = chk.Username
		var fields, picks []string
		for _, p := range chk.Problems {
			msg := p.Message
			if p.Code == adminapi.CodeAccountExists {
				msg += ". Pick another username."
			}
			if p.Field == "groups" {
				picks = append(picks, msg)
			} else {
				fields = append(fields, msg)
			}
		}
		if len(fields) > 0 {
			errs = append(errs, fields...)
			break
		}
		d.Step = 2
		if len(picks) > 0 {
			errs = append(errs, picks...)
			break
		}
		if r.URL.Path == "/people/new/review" {
			d.Picked = chk.Groups
			d.Step = 3
		}
	}
	f.render(w, r, "newperson", "Add a person", page{Nav: "people", Data: d, Error: strings.Join(errs, "\n")})
}
