package gattetui

// People: the identity provider's accounts (design/adr/0038), a section of
// the Users tab, with each account's page and the add flow. Account edits
// are the accounts socket's (-manage-users, design/adr/0040 §1); without it
// the section says how to open it. No screen reads the audit trail
// (design/adr/0061 §3): who called what is read in the SIEM.
//
// Disabling an account stops new sign-ins; it does not cut off a token
// already issued. Only a block does, and blocking lives in the CLI
// (mcp-gateway access block, design/adr/0038, 0061 §4); offboarding blocks
// the subject the operator types.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func init() {
	registerUsersSection(UsersSection{ID: "people", Order: 10, Rows: peopleSection})
}

var accountCols = []int{16, 22, 24}

func peopleSection(e env) ([]row, error) {
	rows := []row{heading("People")}
	if e.acc == nil {
		return append(rows, textRow(stDim.Render("Read-only: to edit, run sudo mcp-gateway tui -manage-users."))), nil
	}
	list, err := e.acc.ListAccounts(ctx())
	if err != nil {
		rows = append(rows, textRow(stBad.Render("The accounts could not be read: "+vis(errText(err)))))
	}
	rows = append(rows, row{text: button("+", "Add a person"),
		actions: []action{{key: "enter", label: "add", run: func() tea.Cmd { return addPerson(e) }}}})
	for _, a := range list.Accounts {
		u := a.Username
		state := stOK.Render("active")
		if a.Disabled {
			state = stWarn.Render("disabled")
		}
		rows = append(rows, row{
			text:    cols(accountCols, vis(a.Username), vis(a.DisplayName), vis(strings.Join(a.Groups, ", ")), state),
			actions: []action{{key: "enter", label: "open", run: func() tea.Cmd { return push(accountPage(u)) }}},
		})
	}
	return rows, nil
}

// ---- one account

func accountPage(username string) *page {
	return newPage(vis(username), func(e env) content { return fillAccount(e, username) })
}

func fillAccount(e env, username string) content {
	var c content
	a, err := e.acc.GetAccount(ctx(), username)
	if err != nil {
		c.problems = append(c.problems, errText(err))
		return c
	}
	kv := func(k, v string) row { return textRow(cols([]int{14}, stDim.Render(k), v)) }
	state := stOK.Render("active")
	if a.Disabled {
		state = stWarn.Render("disabled: no new sign-in")
	}
	c.rows = append(c.rows, heading(vis(a.DisplayName)),
		kv("Username", vis(a.Username)), kv("Email", vis(dash(a.Email))),
		kv("Groups", vis(dash(strings.Join(a.Groups, ", ")))), kv("State", state))
	if groups, gerr := e.acc.AssignableGroups(ctx()); gerr == nil {
		c.rows = append(c.rows, blank(), textRow(stDim.Render("Assignable groups")))
		for _, g := range groups.Groups {
			c.rows = append(c.rows, textRow("  "+vis(g.Name)+stDim.Render("  role "+vis(g.Role))))
		}
	}
	// A failed read offers neither optional action; the backend refuses them anyway.
	me, _ := e.acc.WhoAmI(ctx())
	has := func(f string) bool { return slices.Contains(me.Features, f) }
	u := a.Username
	c.actions = append(c.actions, action{key: "g", label: "groups", run: func() tea.Cmd {
		return ask("Groups for "+vis(u)+" (comma-separated; empty removes all)", strings.Join(a.Groups, ", "), func(v string) tea.Cmd {
			return do(func() result {
				res, err := e.acc.SetAccountGroups(ctx(), u, splitList(v))
				return fromAction(res.ActionResult, err, "Groups of "+u+" set.")
			})
		})
	}})
	if a.Disabled {
		c.actions = append(c.actions, action{key: "e", label: "enable", run: func() tea.Cmd {
			return confirm("Allow "+vis(u)+" to sign in again?", func() tea.Cmd {
				return do(func() result {
					res, err := e.acc.EnableAccount(ctx(), u)
					return fromAction(res.ActionResult, err, "Enabled "+u+".")
				})
			})
		}})
	} else {
		c.actions = append(c.actions, action{key: "d", label: "disable", run: func() tea.Cmd {
			return confirm("Disable "+vis(u)+"? New sign-ins are refused; a token already issued is cut off only by a block (offboard, or mcp-gateway access block).", func() tea.Cmd {
				return do(func() result {
					res, err := e.acc.DisableAccount(ctx(), u)
					return fromAction(res.ActionResult, err, "Disabled "+u+".")
				})
			})
		}})
	}
	c.actions = append(c.actions, action{key: "c", label: "connect", run: func() tea.Cmd { return push(connectPage(u)) }})
	c.actions = append(c.actions, action{key: "p", label: "new password", run: func() tea.Cmd {
		return confirm("Give "+vis(u)+" a new one-time password? The current one stops working.", func() tea.Cmd {
			return do(func() result {
				res, err := e.acc.ResetAccountPassword(ctx(), u)
				return passwordResult(e, u, res, err, "New one-time password for "+u+".")
			})
		})
	}})
	if has(adminapi.FeatureOffboard) {
		c.actions = append(c.actions, action{key: "o", label: "offboard", run: func() tea.Cmd { return offboard(e, u) }})
	}
	if has(adminapi.FeatureAccountDelete) {
		c.actions = append(c.actions, action{key: "X", label: "delete", run: func() tea.Cmd {
			return confirm("Delete the account "+vis(u)+" from the identity provider? The audit trail keeps its rows.", func() tea.Cmd {
				return do(func() result {
					res, err := e.acc.DeleteAccount(ctx(), u)
					r := fromAction(res.ActionResult, err, "Deleted "+u+".")
					r.back = err == nil
					return r
				})
			})
		}})
	}
	return c
}

// offboard asks for the subject to block as typed text: nothing is offered
// or pre-selected from the audit trail (design/adr/0046, 0061 §3).
func offboard(e env, u string) tea.Cmd {
	return ask("Analyst identity to block (the token's sub; empty if they never used the gateway)", "", func(subject string) tea.Cmd {
		return ask("Reason", "", func(reason string) tea.Cmd {
			q := "Offboard " + vis(u) + ": disable the account"
			if subject = strings.TrimSpace(subject); subject != "" {
				q += " and block " + vis(subject) + " in the gateway"
			}
			return confirm(q+"?", func() tea.Cmd {
				return do(func() result {
					res, err := e.acc.OffboardAccount(ctx(), u, adminapi.OffboardRequest{Subject: subject, Reason: strings.TrimSpace(reason)})
					r := fromAction(res.ActionResult, err, "Offboarded "+u+".")
					if err != nil {
						return r
					}
					for _, w := range res.Warnings {
						if w.Code == adminapi.WarnOffboardIncomplete {
							r.ok, r.summary = false, w.Message
						}
					}
					for _, left := range res.Remaining {
						r.output = append(r.output, "Still to do by hand: "+left)
					}
					return r
				})
			})
		})
	})
}

// passwordResult shows a one-time password once, with how the person
// connects. An answer lost on the way (not a refusal) may still have made
// the change, so the account is read back and the operator told to reset
// rather than retry.
func passwordResult(e env, u string, res adminapi.PasswordResult, err error, done string) result {
	r := fromAction(res.ActionResult, err, done)
	if err != nil {
		var ae *adminapi.Error
		if !errors.As(err, &ae) && !errors.Is(err, adminapi.ErrImpostor) {
			if _, gerr := e.acc.GetAccount(ctx(), u); gerr == nil {
				r.summary = "The account " + u + " exists, but the answer that carried its one-time password was lost. Give them a new one with p (new password)."
			}
		}
		return r
	}
	r.secret, r.label = res.OneTimePassword, "One-time password for "+u
	// A one-line command is a complete setup only without a certificate
	// authority; with one, only the script installs it. Either way the full
	// steps are on the account's connect page.
	if c, cerr := e.op.Connect(ctx(), u); cerr == nil && c.Ready {
		if !c.HasCA && c.Command != "" {
			r.output = append(r.output, "They connect with: "+c.Command)
		}
		r.output = append(r.output, "Open "+u+" and press c (connect) for the setup script and steps.")
	}
	return r
}

// ---- connect a computer
//
// The web's /people/connect flow, in the terminal (design/adr/0039): the
// same op.Connect / op.ConnectScript the console reads, the per-OS Run
// steps as rows, and a save that writes the script to a path it prints. The
// script carries no secret; with a certificate authority it is the only
// path that installs it, which the one-line command does not.

// connectFileName accepts only a plain file name from the backend, as the
// web download does, and falls back when it does not.
var connectFileName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func connectPage(username string) *page {
	return newPage("Connect a computer", func(e env) content { return fillConnect(e, username) })
}

func fillConnect(e env, username string) content {
	var c content
	conn, err := e.op.Connect(ctx(), username)
	if err != nil {
		c.problems = append(c.problems, errText(err))
		return c
	}
	who := conn.Username
	if who == "" {
		who = username
	}
	c.rows = append(c.rows, heading("Connect a computer for "+vis(dash(who))),
		textRow(stDim.Render("Sets up Claude Code on their machine to use this gateway.")))
	if !conn.Ready {
		keys := conn.Missing
		if len(keys) == 0 {
			keys = []string{"client_id", "callback_port"}
		}
		c.rows = append(c.rows, blank(), textRow(stWarn.Render("Connect scripts aren't set up.")),
			textRow("Set [connect] "+vis(strings.Join(keys, " and "))+" in the configuration file: the public OAuth client your identity provider has registered for Claude Code, and the port of its redirect URI."))
		return c
	}
	for _, sc := range conn.Scripts {
		osName := sc.OS
		install := "It adds the Gatte entry to Claude Code"
		if conn.HasCA {
			install += ", installs the team's certificate authority"
		}
		install += " and installs the gatte-status check. It holds no secret."
		c.rows = append(c.rows, blank(), heading(vis(dash(sc.Name))),
			textRow("1. Send them the script. "+stDim.Render(install)),
			row{text: "   " + button("s", "Save "+vis(dash(sc.Filename))),
				actions: []action{{key: "s", label: "save script", run: saveConnectScript(e, osName, who)}}},
			textRow("2. They run it:  "+vis(sc.Run)))
		if !conn.HasCA && conn.Command != "" {
			c.rows = append(c.rows, textRow(stDim.Render("   Or paste one line instead:  ")+vis(conn.Command)))
		}
		signin := "3. They sign in: run claude, type /mcp, choose " + vis(dash(conn.ServerName))
		if who != "" {
			signin += " and sign in as " + vis(who)
		}
		c.rows = append(c.rows, textRow(signin+". The browser opens your identity provider's login."))
	}
	if conn.HasCA {
		c.rows = append(c.rows, blank(), textRow(stWarn.Render("This team uses its own certificate authority.")),
			textRow("Only the saved script installs it; the one-line command does not. To hand this off in a browser, the web console offers the same per-OS download."))
	}
	return c
}

// saveConnectScript fetches one OS's script and writes it next to the
// operator's temporary files, printing the path. The file carries no
// secret, so saving it loses nothing.
func saveConnectScript(e env, osName, username string) func() tea.Cmd {
	return func() tea.Cmd {
		return do(func() result {
			text, name, err := e.op.ConnectScript(ctx(), osName, username)
			if err != nil {
				return refused("The script could not be fetched: " + firstLine(errText(err)))
			}
			if !connectFileName.MatchString(name) {
				name = "connect-gatte.txt"
			}
			path := filepath.Join(os.TempDir(), name)
			if werr := os.WriteFile(path, []byte(text), 0o600); werr != nil {
				return refused("The script could not be written: " + vis(werr.Error()))
			}
			r := result{ok: true, summary: "Saved the connect script to " + vis(path) + "."}
			r.output = append(r.output, "Send this file to "+username+"; it holds no secret.")
			return r
		})
	}
}

// ---- adding a person: the backend checks the draft, then creates it

func addPerson(e env) tea.Cmd {
	return ask("Display name", "", func(display string) tea.Cmd {
		return ask("Username (empty: the backend suggests one)", "", func(username string) tea.Cmd {
			return ask("Email (optional)", "", func(email string) tea.Cmd {
				draft := adminapi.AccountDraft{DisplayName: strings.TrimSpace(display), Username: strings.TrimSpace(username), Email: strings.TrimSpace(email)}
				return checkThen(e, draft, func(chk adminapi.AccountCheck) tea.Cmd {
					// A check echoes only the groups it was asked about, so the
					// choice comes from the assignable list.
					var names []string
					if groups, err := e.acc.AssignableGroups(ctx()); err == nil {
						for _, g := range groups.Groups {
							names = append(names, g.Name+" ("+g.Role+")")
						}
					}
					draft.Username = chk.Username
					return ask("Groups for "+vis(chk.Username)+"; assignable: "+vis(strings.Join(names, ", ")), "", func(groups string) tea.Cmd {
						draft.Groups = splitList(groups)
						return checkThen(e, draft, func(adminapi.AccountCheck) tea.Cmd {
							return confirm(fmt.Sprintf("Create %s (%s) in groups %s?", vis(draft.Username), vis(draft.DisplayName), vis(dash(strings.Join(draft.Groups, ", ")))), func() tea.Cmd {
								return do(func() result {
									res, err := e.acc.AddAccount(ctx(), adminapi.NewAccount{Username: draft.Username, DisplayName: draft.DisplayName, Email: draft.Email, Groups: draft.Groups})
									return passwordResult(e, draft.Username, res, err, "Added "+draft.Username+".")
								})
							})
						})
					})
				})
			})
		})
	})
}

// checkThen validates a draft with the backend (no side effect) and goes on
// only when it has no problem; otherwise it shows the backend's problems.
func checkThen(e env, d adminapi.AccountDraft, next func(adminapi.AccountCheck) tea.Cmd) tea.Cmd {
	return func() tea.Msg {
		chk, err := e.acc.CheckAccount(ctx(), d)
		if err != nil {
			return resultMsg{fromAction(adminapi.ActionResult{}, err, "")}
		}
		if len(chk.Problems) > 0 {
			r := refused("Not added: the backend refused the draft.")
			for _, p := range chk.Problems {
				r.output = append(r.output, p.Field+": "+p.Message)
			}
			return resultMsg{r}
		}
		cmd := next(chk)
		if cmd == nil {
			return nil
		}
		return cmd()
	}
}
