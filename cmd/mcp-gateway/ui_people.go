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
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// Operator actions on accounts, recorded like `access block` (ADR-0031).
const (
	accountAddTool     = "(account add)"
	accountGroupsTool  = "(account groups)"
	accountDisableTool = "(account disable)"
	accountEnableTool  = "(account enable)"
	accountResetTool   = "(account reset password)"
)

// uiRecordName is the display name a record carries, when it carries one.
func uiRecordName(audit.Record) string { return "" }

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

// uiAccountGroups reads the groups a form ticked, refusing any that does
// not map to a role: the console hands out access through
// group_to_role, never around it.
func uiAccountGroups(e *opEnv, r *http.Request) ([]string, error) {
	known := map[string]bool{}
	for g := range e.cfg.GroupToRole {
		known[g] = true
	}
	var out []string
	for _, g := range r.PostForm["group"] {
		if !known[g] {
			return nil, fmt.Errorf("group %q maps to no role in the configuration file; the console only assigns groups that do", g)
		}
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

// accountAction runs one account change and records it. The IdP file is
// written first and the trail second, like `access block`: a change that
// happened is never hidden by a trail that could not be written, and the
// page says so.
func (s *uiServer) accountAction(w http.ResponseWriter, r *http.Request, tool, title string, fn func(e *opEnv) (username, detail, secret string, err error)) {
	if s.accounts == nil {
		http.NotFound(w, r)
		return
	}
	var secret, username string
	out, errText, code := s.uiRun(func(e *opEnv) int {
		u, detail, sec, err := fn(e)
		username = u
		if err != nil {
			fmt.Fprintf(e.stderr, "%v\n", err)
			return exitProblem
		}
		secret = sec
		reason := fmt.Sprintf("account %q", u)
		if detail != "" {
			reason += ": " + detail
		}
		reason += " [ui]"
		rec := audit.Record{AnalystIdentity: operatorIdentity(s.operator), Tool: tool, TargetUpstream: operatorTarget,
			Timestamp: time.Now().UTC(), Outcome: audit.OutcomeAllowed, Reason: reason}
		if err := e.recordOperatorAction(rec); err != nil {
			fmt.Fprintf(e.stderr, "The change was made in the identity provider, but the audit trail could not record it: %v\n", err)
			return exitProblem
		}
		fmt.Fprintf(e.stdout, "%s: %s\nRecorded in the audit trail as %s by %s.\n", tool, reason, tool, operatorIdentity(s.operator))
		fmt.Fprint(e.stdout, "The identity provider applies this when it reloads its users file (Authelia: watch: true, or a restart).\n")
		return exitOK
	})
	res := uiResult(out, errText, code)
	res.Secret, res.SecretFor = secret, username
	s.render(w, "result", title+" "+visible.Escape(username), page{Nav: "people", Data: res.withBack(s.basePath() + "/people")})
}

func (s *uiServer) accountAdd(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, accountAddTool, "Add", func(e *opEnv) (string, string, string, error) {
		a := idp.Account{
			Username:    strings.TrimSpace(r.PostForm.Get("username")),
			DisplayName: strings.TrimSpace(r.PostForm.Get("displayname")),
			Email:       strings.TrimSpace(r.PostForm.Get("email")),
		}
		groups, err := uiAccountGroups(e, r)
		if err != nil {
			return a.Username, "", "", err
		}
		a.Groups = groups
		if err := idp.ValidateAccount(a); err != nil {
			return a.Username, "", "", err
		}
		pw, err := idp.GeneratePassword()
		if err != nil {
			return a.Username, "", "", err
		}
		hash, err := idp.HashPassword(pw)
		if err != nil {
			return a.Username, "", "", err
		}
		if err := s.accounts.Add(a, hash); err != nil {
			return a.Username, "", "", err
		}
		return a.Username, "groups " + uiGroupList(groups), pw, nil
	})
}

func (s *uiServer) accountGroups(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, accountGroupsTool, "Groups for", func(e *opEnv) (string, string, string, error) {
		u := r.PostForm.Get("username")
		groups, err := uiAccountGroups(e, r)
		if err != nil {
			return u, "", "", err
		}
		if err := s.accounts.SetGroups(u, groups); err != nil {
			return u, "", "", err
		}
		return u, "groups " + uiGroupList(groups), "", nil
	})
}

func (s *uiServer) accountDisable(w http.ResponseWriter, r *http.Request) {
	s.accountSetDisabled(w, r, true)
}

func (s *uiServer) accountEnable(w http.ResponseWriter, r *http.Request) {
	s.accountSetDisabled(w, r, false)
}

func (s *uiServer) accountSetDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	tool, title := accountEnableTool, "Enable"
	if disabled {
		tool, title = accountDisableTool, "Disable"
	}
	s.accountAction(w, r, tool, title, func(e *opEnv) (string, string, string, error) {
		u := r.PostForm.Get("username")
		return u, "", "", s.accounts.SetDisabled(u, disabled)
	})
}

func (s *uiServer) accountReset(w http.ResponseWriter, r *http.Request) {
	s.accountAction(w, r, accountResetTool, "New password for", func(e *opEnv) (string, string, string, error) {
		u := r.PostForm.Get("username")
		pw, err := idp.GeneratePassword()
		if err != nil {
			return u, "", "", err
		}
		hash, err := idp.HashPassword(pw)
		if err != nil {
			return u, "", "", err
		}
		if err := s.accounts.SetPassword(u, hash); err != nil {
			return u, "", "", err
		}
		return u, "", pw, nil
	})
}

func uiGroupList(groups []string) string {
	if len(groups) == 0 {
		return "(none)"
	}
	return strings.Join(groups, ", ")
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
