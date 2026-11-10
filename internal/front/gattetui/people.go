package gattetui

// People: the identity provider's accounts (design/adr/0038), a section of
// the Users tab, with each account's page and the add flow. Account edits
// are the accounts socket's (-manage-users, design/adr/0040 §1); without it
// the section shows only who the gateway has seen.
//
// Disabling an account stops new sign-ins; it does not cut off a token
// already issued. That is the Blocklist section's block, a separate action
// (design/adr/0038).

import (
	"errors"
	"fmt"
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
		rows = append(rows, textRow(stDim.Render("Accounts are edited through the accounts socket: start with sudo mcp-gateway tui -manage-users.")))
	} else {
		list, err := e.acc.ListAccounts(ctx())
		if err != nil {
			rows = append(rows, textRow(stBad.Render("The accounts could not be read: "+vis(errText(err)))))
		}
		rows = append(rows, row{text: stKey.Render("+ Add a person"),
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
	}
	p, err := e.op.People(ctx())
	if err != nil {
		return append(rows, textRow(stBad.Render("Who the gateway has seen could not be read: "+vis(errText(err))))), nil
	}
	if len(p.Seen) > 0 {
		rows = append(rows, textRow(stDim.Render("Seen by the gateway")))
		for _, s := range p.Seen {
			state := ""
			if s.Blocked {
				state = stBad.Render("blocked")
			}
			rows = append(rows, textRow(cols(accountCols, vis(s.Identity), vis(dash(s.Name)), state,
				stDim.Render(fmt.Sprintf("%d calls, last %s", s.Calls, showTime(s.LastCall))))))
		}
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
			return confirm("Disable "+vis(u)+"? New sign-ins are refused; a token already issued is cut off only by a block.", func() tea.Cmd {
				return do(func() result {
					res, err := e.acc.DisableAccount(ctx(), u)
					return fromAction(res.ActionResult, err, "Disabled "+u+".")
				})
			})
		}})
	}
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
	if c, cerr := e.op.Connect(ctx(), u); cerr == nil && c.Ready && c.Command != "" {
		r.output = append(r.output, "They connect with: "+c.Command)
	}
	return r
}

// ---- adding a person: the backend checks the draft, then creates it

func addPerson(e env) tea.Cmd {
	return ask("Display name", "", func(display string) tea.Cmd {
		return ask("Username (empty: the backend suggests one)", "", func(username string) tea.Cmd {
			return ask("Email (optional)", "", func(email string) tea.Cmd {
				draft := adminapi.AccountDraft{DisplayName: strings.TrimSpace(display), Username: strings.TrimSpace(username), Email: strings.TrimSpace(email)}
				return checkThen(e, draft, func(chk adminapi.AccountCheck) tea.Cmd {
					var names []string
					for _, g := range chk.Groups {
						names = append(names, g.Name+" ("+g.Role+")")
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
