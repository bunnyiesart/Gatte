package adminapitest

import (
	"net/http"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// username is the {username} path segment. ServeMux returns it already decoded.
func username(r *http.Request) string { return r.PathValue("username") }

func (s *Server) listAccounts(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := adminapi.AccountList{Accounts: make([]adminapi.Account, 0, len(s.acctOrder))}
	for _, u := range s.acctOrder {
		out.Accounts = append(out.Accounts, *s.accounts[u])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[username(r)]
	if !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no account %q", username(r)))
		return
	}
	writeJSON(w, http.StatusOK, *a)
}

func (s *Server) checkAccount(w http.ResponseWriter, r *http.Request) {
	var d adminapi.AccountDraft
	if !decode(w, r, &d) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := d.Username
	suggested := false
	if u == "" {
		u = suggestUsername(d.DisplayName)
		suggested = true
	}
	res := adminapi.AccountCheck{OK: true, Username: u, Suggested: suggested, Problems: []adminapi.FieldProblem{}, Groups: slices.Clone(s.groups)}
	if _, taken := s.accounts[u]; taken {
		res.OK = false
		res.Problems = append(res.Problems, adminapi.FieldProblem{Field: "username", Code: "taken", Message: "already in use"})
	}
	if u != "" {
		res.WazuhUser = wazuhUserOf(u)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) addAccount(w http.ResponseWriter, r *http.Request) {
	var n adminapi.NewAccount
	if !decode(w, r, &n) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.Username == "" {
		writeErr(w, adminapi.NewError(adminapi.CodeInvalidArgument, "an account needs a username"))
		return
	}
	if _, taken := s.accounts[n.Username]; taken {
		writeErr(w, adminapi.NewError(adminapi.CodeAccountExists, "an account named %q already exists", n.Username))
		return
	}
	a := &adminapi.Account{Username: n.Username, DisplayName: n.DisplayName, Email: n.Email, Groups: n.Groups}
	if a.Groups == nil {
		a.Groups = []string{}
	}
	s.accounts[n.Username] = a
	s.acctOrder = append(s.acctOrder, n.Username)
	res := adminapi.PasswordResult{Account: *a, OneTimePassword: "fake-otp-" + n.Username}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"created " + n.Username}
	res.Audit = s.row(rowAccountAdd, "add "+n.Username)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) setAccountGroups(w http.ResponseWriter, r *http.Request) {
	var req adminapi.GroupsRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[username(r)]
	if !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no account %q", username(r)))
		return
	}
	a.Groups = req.Groups
	if a.Groups == nil {
		a.Groups = []string{}
	}
	s.accountResult(w, *a, rowAccountGroups, "groups "+a.Username)
}

func (s *Server) disableAccount(w http.ResponseWriter, r *http.Request) { s.setDisabled(w, r, true) }
func (s *Server) enableAccount(w http.ResponseWriter, r *http.Request)  { s.setDisabled(w, r, false) }

func (s *Server) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[username(r)]
	if !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no account %q", username(r)))
		return
	}
	a.Disabled = disabled
	tool, reason := rowAccountEnable, "enable "+a.Username
	if disabled {
		tool, reason = rowAccountDisable, "disable "+a.Username
	}
	s.accountResult(w, *a, tool, reason)
}

func (s *Server) resetAccountPassword(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[username(r)]
	if !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no account %q", username(r)))
		return
	}
	res := adminapi.PasswordResult{Account: *a, OneTimePassword: "fake-otp-reset-" + a.Username}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"reset " + a.Username}
	res.Audit = s.row(rowAccountReset, "reset "+a.Username)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := username(r)
	a, ok := s.accounts[u]
	if !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no account %q", u))
		return
	}
	acct := *a
	delete(s.accounts, u)
	s.acctOrder = slices.DeleteFunc(s.acctOrder, func(n string) bool { return n == u })
	s.accountResult(w, acct, rowAccountDelete, "delete "+u)
}

func (s *Server) offboardAccount(w http.ResponseWriter, r *http.Request) {
	var req adminapi.OffboardRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := username(r)
	a, ok := s.accounts[u]
	if !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no account %q", u))
		return
	}
	a.Disabled = true
	blocked := req.Subject != ""
	if blocked && !slices.ContainsFunc(s.blocks, func(b adminapi.Block) bool { return b.Subject == req.Subject }) {
		s.blocks = append(s.blocks, adminapi.Block{Subject: req.Subject, BlockedBy: s.operator.Name,
			BlockedAt: base, Reason: "offboard of " + u + " [ui]"})
	}
	rows := []adminapi.OperatorRow{}
	if blocked {
		rows = append(rows, *s.row(rowAccessBlock, "block "+req.Subject))
	}
	rows = append(rows, *s.row(rowAccountDisable, "disable "+u), *s.row(rowAccountOffboard, "offboard "+u))
	res := adminapi.OffboardResult{Account: *a, Subject: req.Subject, Blocked: blocked, Disabled: true, Rows: rows,
		Remaining: []string{"Revoke the person's tokens at the identity provider", "Delete the account when retention allows"}}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"offboarded " + u}
	res.Audit = s.row(rowAccountOffboard, "offboard "+u)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) accountResult(w http.ResponseWriter, a adminapi.Account, tool, reason string) {
	res := adminapi.AccountResult{Account: a}
	res.Changed, res.Recorded, res.Messages = true, true, []string{reason}
	res.Audit = s.row(tool, reason)
	writeJSON(w, http.StatusOK, res)
}

func suggestUsername(display string) string {
	u := strings.ToLower(strings.TrimSpace(display))
	u = strings.ReplaceAll(u, " ", ".")
	if u == "" {
		return "new.user"
	}
	return u
}

// wazuhUserOf is the fake's [idp.wazuh_check]: the seeded accounts and
// "carla.dias" exist in Wazuh, "siem.down" shows an indexer that could not
// be asked, and any other name is not found -- so a preview shows all three.
func wazuhUserOf(u string) *adminapi.WazuhUserCheck {
	switch u {
	case "ana.lima", "bruno.sa", "carla.dias":
		return &adminapi.WazuhUserCheck{Status: adminapi.WazuhUserFound, Message: "Found in Wazuh: " + u + "."}
	case "siem.down":
		return &adminapi.WazuhUserCheck{Status: adminapi.WazuhUserUnchecked, Message: "Could not check Wazuh: no answer within 5s."}
	}
	return &adminapi.WazuhUserCheck{Status: adminapi.WazuhUserNotFound, Message: "Not found in Wazuh: " + u + ". Use the same username the person has in the SIEM."}
}
