//go:build !nofront

// Operator Console -- "ui": the analyst's connect script and the Add
// person assistant (design/adr/0039-script-de-conexao-do-analista.md).
//
// Adding a person ends the way adding an agent ends in a SIEM manager: with
// one command, or one downloadable script, the new analyst runs on their
// own machine. It checks for Claude Code, trusts the deployment's private
// CA when there is one, checks the gateway answers, and registers the
// gateway in Claude Code with the OAuth client the IdP knows. It carries
// nothing secret: the endpoint, a public client id, a callback port and a
// CA certificate. The one-time password travels separately.

package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// connectInfo is what a connect script is made of. The scripts are
// rendered by the management service (internal/admin), so every front
// hands out the same text.
type connectInfo = admin.ConnectInfo

func uiConnectInfo(cfg *config.Config, username string, now time.Time) (connectInfo, error) {
	return admin.ConnectInfoOf(cfg, username, now)
}

func uiConnectCommand(c connectInfo) string { return admin.ConnectCommand(c) }

func uiRenderScript(c connectInfo, os string) (string, string, error) {
	return admin.RenderScript(c, os)
}

// ---- pages

type connectPanel struct {
	Info    connectInfo
	Command string
	Scripts map[string]string
	Error   string
}

func (s *uiServer) connectPanelFor(username string) connectPanel {
	var p connectPanel
	s.uiRun(func(e *opEnv) int {
		info, err := uiConnectInfo(e.cfg, username, time.Now())
		p.Info = info
		if err != nil {
			p.Error = err.Error()
			return exitProblem
		}
		if info.Ready {
			p.Command = uiConnectCommand(info)
			p.Scripts = map[string]string{}
			for _, osName := range []string{"macos", "linux", "windows"} {
				text, _, err := uiRenderScript(info, osName)
				if err != nil {
					p.Error = err.Error()
					return exitProblem
				}
				p.Scripts[osName] = text
			}
		}
		return exitOK
	})
	return p
}

func (s *uiServer) connectPage(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("u")
	p := s.connectPanelFor(u)
	s.render(w, "connect", "Connect a computer", page{Nav: "people", Data: p, Error: p.Error})
}

// connectScript serves a script as a download. It changes nothing, so GET
// is right; it carries no secret, so nothing is lost if it is saved.
func (s *uiServer) connectScript(w http.ResponseWriter, r *http.Request) {
	p := s.connectPanelFor(r.URL.Query().Get("u"))
	if !p.Info.Ready || p.Error != "" {
		http.Error(w, "connect scripts are not configured: "+p.Info.Missing+p.Error, http.StatusNotFound)
		return
	}
	text, name, err := uiRenderScript(p.Info, r.URL.Query().Get("os"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(text))
}

// ---- the Add person assistant

type newPerson struct {
	Step        int
	DisplayName string
	Username    string
	Email       string
	Groups      []uiGroup
	Chosen      map[string]bool
	Picked      []uiGroup
	Roles       map[string]uiRole
	Error       string
}

// uiSuggestUsername turns "Ana Souza" into "ana.souza".
func uiSuggestUsername(name string) string { return admin.SuggestUsername(name) }

func (s *uiServer) newPersonPage(w http.ResponseWriter, r *http.Request) {
	if s.accounts == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	d := newPerson{Step: 1, DisplayName: strings.TrimSpace(q.Get("displayname")), Username: strings.TrimSpace(q.Get("username")),
		Email: strings.TrimSpace(q.Get("email")), Chosen: map[string]bool{}}
	for _, g := range q["group"] {
		d.Chosen[g] = true
	}
	s.uiRun(func(e *opEnv) int {
		d.Groups = uiKnownGroups(e)
		d.Roles = map[string]uiRole{}
		for _, role := range e.cfg.Roles {
			ur := uiRole{Name: role.Name, Tools: append([]string(nil), role.Tools...)}
			for backend, tools := range role.Grants {
				for _, t := range tools {
					ur.Tools = append(ur.Tools, backend+"."+t)
				}
			}
			d.Roles[role.Name] = ur
		}
		return exitOK
	})
	switch r.URL.Path {
	case "/people/new/access", "/people/new/review":
		if d.Username == "" {
			d.Username = uiSuggestUsername(d.DisplayName)
		}
		if err := idp.ValidateAccount(idp.Account{Username: d.Username, DisplayName: d.DisplayName, Email: d.Email}); err != nil {
			d.Error = err.Error()
			break
		}
		if existing, err := s.accounts.Accounts(); err == nil {
			for _, a := range existing {
				if a.Username == d.Username {
					d.Error = fmt.Sprintf("%s is already taken by %s. Pick another username.", d.Username, a.DisplayName)
				}
			}
		}
		if d.Error != "" {
			break
		}
		d.Step = 2
		if r.URL.Path == "/people/new/review" {
			for _, g := range d.Groups {
				if d.Chosen[g.Name] {
					d.Picked = append(d.Picked, g)
				}
			}
			d.Step = 3
		}
	}
	s.render(w, "newperson", "Add a person", page{Nav: "people", Data: d, Error: visible.Escape(d.Error)})
}
