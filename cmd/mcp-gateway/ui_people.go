//go:build !nofront

// Operator Console -- "ui": the People page and, in the root-only
// -manage-users mode, the identity provider's accounts
// (design/adr/0038-contas-do-idp-pelo-console.md).
//
// Who may call the gateway is decided outside it: the IdP holds the people
// and their groups, and config.toml maps groups to roles. The People page
// shows both halves together, plus who the trail has actually seen. Editing
// accounts writes the IdP's users file, which the service account must
// never be able to do -- whoever runs code as the gateway would otherwise
// create an account and give it any role -- so it exists only in a console
// started as root, the same rule as `sign`.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Operator actions on accounts, recorded like `access block` (ADR-0031).
const (
	accountAddTool     = admin.AccountAdd
	accountGroupsTool  = admin.AccountGroups
	accountDisableTool = admin.AccountDisable
	accountEnableTool  = admin.AccountEnable
	accountResetTool   = admin.AccountReset
)

// uiRecordName is the display name a record carries, when it carries one.
func uiRecordName(r audit.Record) string { return r.AnalystName }

// enableAccounts turns on the account pages over dir. Called only by the
// root -manage-users command, and by tests.
func (s *uiServer) enableAccounts(dir idp.Directory) { s.accounts = dir }

type uiRole struct {
	Name   string
	Groups []string
	Tools  []string
}

type uiSeen struct {
	Identity string
	Name     string
	Last     time.Time
	Calls    int
	Blocked  bool
}

type uiGroup struct {
	Name, Role string
}

type peopleData struct {
	Manage   bool
	Accounts []idp.Account
	Groups   []uiGroup
	Roles    []uiRole
	Seen     []uiSeen
}

// uiKnownGroups is every group that maps to a role, sorted: the only
// groups the console lets an account be given.
func uiKnownGroups(e *opEnv) []uiGroup {
	var out []uiGroup
	for g, r := range e.cfg.GroupToRole {
		out = append(out, uiGroup{Name: g, Role: r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *uiServer) peoplePage(w http.ResponseWriter, r *http.Request) {
	var d peopleData
	var errText string
	_, stderr, _ := s.uiRun(func(e *opEnv) int {
		d.Groups = uiKnownGroups(e)
		for _, role := range e.cfg.Roles {
			ur := uiRole{Name: role.Name, Tools: append([]string(nil), role.Tools...)}
			for backend, tools := range role.Grants {
				for _, t := range tools {
					ur.Tools = append(ur.Tools, backend+"."+t)
				}
			}
			sort.Strings(ur.Tools)
			for _, g := range d.Groups {
				if g.Role == role.Name {
					ur.Groups = append(ur.Groups, g.Name)
				}
			}
			d.Roles = append(d.Roles, ur)
		}
		recs, err := e.auditTrail().List(e.ctx())
		if err != nil {
			fmt.Fprintf(e.stderr, "audit trail: %v\n", err)
			return exitCannotRun
		}
		blocked := map[string]bool{}
		if bs, err := e.blocks().Blocks(e.ctx()); err == nil {
			for _, b := range bs {
				blocked[b.Subject] = true
			}
		}
		seen := map[string]*uiSeen{}
		for _, rec := range recs {
			id := rec.AnalystIdentity
			// (gateway), (operator:x), (unauthenticated): not people.
			if id == "" || strings.HasPrefix(id, "(") {
				continue
			}
			v := seen[id]
			if v == nil {
				v = &uiSeen{Identity: id, Blocked: blocked[id]}
				seen[id] = v
			}
			v.Calls++
			if rec.Timestamp.After(v.Last) {
				v.Last = rec.Timestamp
			}
			if n := uiRecordName(rec); n != "" {
				v.Name = n
			}
		}
		for _, v := range seen {
			d.Seen = append(d.Seen, *v)
		}
		sort.Slice(d.Seen, func(i, j int) bool { return d.Seen[i].Last.After(d.Seen[j].Last) })
		return exitOK
	})
	errText = strings.TrimSpace(stderr)
	if s.accounts != nil {
		d.Manage = true
		accts, err := s.accounts.Accounts()
		if err != nil {
			errText = strings.TrimSpace(errText + "\n" + err.Error())
		}
		d.Accounts = accts
	}
	s.render(w, "people", "People", page{Data: d, Error: errText})
}

type accountData struct {
	Account idp.Account
	Groups  []uiGroup
	Has     map[string]bool
}

func (s *uiServer) accountPage(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		http.NotFound(w, r)
		return
	}
	name := r.URL.Query().Get("u")
	accts, err := s.accounts.Accounts()
	if err != nil {
		s.render(w, "account", "Account", page{Nav: "people", Error: err.Error()})
		return
	}
	var d accountData
	for _, a := range accts {
		if a.Username == name {
			d.Account = a
		}
	}
	if d.Account.Username == "" {
		http.NotFound(w, r)
		return
	}
	s.uiRun(func(e *opEnv) int { d.Groups = uiKnownGroups(e); return exitOK })
	d.Has = map[string]bool{}
	for _, g := range d.Account.Groups {
		d.Has[g] = true
	}
	s.render(w, "account", visible.Escape(d.Account.DisplayName), page{Nav: "people", Data: d})
}

// accountService is the management service over the console's account
// store: the same rules the accounts socket answers with -- groups only
// from group_to_role, a generated one-time password stored as a hash, the
// users file first and the trail second.
func (s *uiServer) accountService(e *opEnv) (*admin.Service, error) {
	return admin.New(admin.Deps{
		Config:   func() (*config.Config, error) { return e.cfg, nil },
		Record:   func(_ context.Context, _ *config.Config, rec audit.Record) error { return e.recordOperatorAction(rec) },
		Accounts: func(*config.Config) (idp.Directory, error) { return s.accounts, nil },
		IsBusy:   store.IsBusy,
	})
}

// accountAction runs one account change through the service and shows its
// result. A change the trail could not record is shown as made and
// unrecorded.
func (s *uiServer) accountAction(w http.ResponseWriter, r *http.Request, title string, fn func(e *opEnv, svc *admin.Service, a admin.Actor) (username, secret string, res adminapi.ActionResult, err error)) {
	displayName := strings.TrimSpace(r.PostForm.Get("displayname"))
	if s.accounts == nil {
		http.NotFound(w, r)
		return
	}
	var secret, username string
	out, errText, code := s.uiRun(func(e *opEnv) int {
		svc, err := s.accountService(e)
		if err != nil {
			fmt.Fprintf(e.stderr, "%v\n", err)
			return exitCannotRun
		}
		u, sec, res, err := fn(e, svc, e.actor)
		username = u
		if err != nil {
			fmt.Fprintf(e.stderr, "%s\n", cliErrText(err))
			return exitProblem
		}
		secret = sec
		for _, m := range res.Messages {
			fmt.Fprintln(e.stdout, m)
		}
		for _, wn := range res.Warnings {
			fmt.Fprintln(e.stdout, wn.Message)
		}
		if res.Changed && !res.Recorded {
			fmt.Fprintf(e.stderr, "The change was made in the identity provider, but the audit trail could not record it: %s\n", warningText(res, adminapi.WarnAuditWriteFailed))
			return exitProblem
		}
		return exitOK
	})
	res := uiResult(out, errText, code)
	res.Secret, res.SecretFor, res.SecretName = secret, username, displayName
	if res.SecretName == "" {
		res.SecretName = username
	}
	if secret != "" {
		panel := s.connectPanelFor(username)
		res.Connect = &panel
	}
	s.render(w, "result", title+" "+visible.Escape(username), page{Nav: "people", Data: res.withBack(s.basePath() + "/people")})
}

func (s *uiServer) accountAdd(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, "Add", func(e *opEnv, svc *admin.Service, a admin.Actor) (string, string, adminapi.ActionResult, error) {
		n := adminapi.NewAccount{
			Username:    strings.TrimSpace(r.PostForm.Get("username")),
			DisplayName: strings.TrimSpace(r.PostForm.Get("displayname")),
			Email:       strings.TrimSpace(r.PostForm.Get("email")),
			Groups:      r.PostForm["group"],
		}
		res, err := svc.AddAccount(e.ctx(), a, n)
		return n.Username, res.OneTimePassword, res.ActionResult, err
	})
}

func (s *uiServer) accountGroups(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, "Groups for", func(e *opEnv, svc *admin.Service, a admin.Actor) (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		groups := r.PostForm["group"]
		if groups == nil {
			groups = []string{}
		}
		res, err := svc.SetAccountGroups(e.ctx(), a, u, adminapi.GroupsRequest{Groups: groups})
		return u, "", res.ActionResult, err
	})
}

func (s *uiServer) accountDisable(w http.ResponseWriter, r *http.Request) {
	s.accountSetDisabled(w, r, true)
}

func (s *uiServer) accountEnable(w http.ResponseWriter, r *http.Request) {
	s.accountSetDisabled(w, r, false)
}

func (s *uiServer) accountSetDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	title := "Enable"
	if disabled {
		title = "Disable"
	}
	s.accountAction(w, r, title, func(e *opEnv, svc *admin.Service, a admin.Actor) (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		res, err := svc.SetAccountDisabled(e.ctx(), a, u, disabled)
		return u, "", res.ActionResult, err
	})
}

func (s *uiServer) accountReset(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, "New password for", func(e *opEnv, svc *admin.Service, a admin.Actor) (string, string, adminapi.ActionResult, error) {
		u := r.PostForm.Get("username")
		res, err := svc.ResetAccountPassword(e.ctx(), a, u)
		return u, res.OneTimePassword, res.ActionResult, err
	})
}

// keepDBOwner gives the gateway database, and the WAL and shared-memory
// files SQLite creates beside it, back to the database file's owner. A
// console run as root that opens the store can create those files owned by
// root, and the service account could then no longer write its own
// database; `sign` asks the operator to chown for the same reason.
func keepDBOwner(dbPath string) error {
	st, err := os.Stat(dbPath)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if fs, ok := fi.Sys().(*syscall.Stat_t); ok && (fs.Uid != sys.Uid || fs.Gid != sys.Gid) {
			if err := os.Chown(p, int(sys.Uid), int(sys.Gid)); err != nil {
				return fmt.Errorf("restoring the owner of %s: %w", p, err)
			}
		}
	}
	return nil
}
