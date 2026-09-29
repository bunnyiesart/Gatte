package admin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Identity provider accounts (design/adr/0038, moved to the accounts
// socket by 0040 §1). Every change writes the users file first and the
// trail second: a change that happened is never hidden by a trail that
// could not be written, and the answer says so.

// AccountOf is the contract's view of an account. No hash, ever.
func AccountOf(a idp.Account) adminapi.Account {
	groups := append([]string{}, a.Groups...)
	return adminapi.Account{Username: a.Username, DisplayName: a.DisplayName, Email: a.Email, Groups: groups, Disabled: a.Disabled}
}

// directory opens the IdP's account store for one operation.
func (s *Service) directory() (*config.Config, idp.Directory, error) {
	cfg, err := s.config()
	if err != nil {
		return nil, nil, err
	}
	if s.d.Accounts == nil {
		return nil, nil, adminapi.NewError(adminapi.CodeConfigUnavailable, "account editing needs [idp] users_file in the configuration file").
			With("problem", "does_not_load")
	}
	dir, err := s.d.Accounts(cfg)
	if err != nil {
		return nil, nil, adminapi.NewError(adminapi.CodeConfigUnavailable, "the identity provider's users file: %v", err).With("path", cfg.IdP.UsersFile)
	}
	return cfg, dir, nil
}

// AssignableGroupsOf is every [group_to_role] group with its role's tools.
func AssignableGroupsOf(cfg *config.Config) []adminapi.AssignableGroup {
	roles := map[string]config.Role{}
	for _, r := range cfg.Roles {
		roles[r.Name] = r
	}
	out := []adminapi.AssignableGroup{}
	for _, g := range Groups(cfg) {
		out = append(out, adminapi.AssignableGroup{Name: g.Name, Role: g.Role, Tools: RoleTools(roles[g.Role])})
	}
	return out
}

// AssignableGroups returns the groups an account may be given.
func (s *Service) AssignableGroups(ctx context.Context) (adminapi.GroupList, error) {
	cfg, err := s.config()
	if err != nil {
		return adminapi.GroupList{}, err
	}
	return adminapi.GroupList{Groups: AssignableGroupsOf(cfg)}, nil
}

// Accounts lists the IdP's accounts.
func (s *Service) Accounts(ctx context.Context) (adminapi.AccountList, error) {
	_, dir, err := s.directory()
	if err != nil {
		return adminapi.AccountList{}, err
	}
	accts, err := dir.Accounts()
	if err != nil {
		return adminapi.AccountList{}, adminapi.NewError(adminapi.CodeInternal, "reading the users file: %v", err)
	}
	out := adminapi.AccountList{Accounts: []adminapi.Account{}}
	for _, a := range accts {
		out.Accounts = append(out.Accounts, AccountOf(a))
	}
	return out, nil
}

func findAccount(dir idp.Directory, username string) (idp.Account, error) {
	accts, err := dir.Accounts()
	if err != nil {
		return idp.Account{}, adminapi.NewError(adminapi.CodeInternal, "reading the users file: %v", err)
	}
	for _, a := range accts {
		if a.Username == username {
			return a, nil
		}
	}
	return idp.Account{}, adminapi.NewError(adminapi.CodeNotFound, "no account %q", visible.Escape(username)).With("username", username)
}

// Account returns one account.
func (s *Service) Account(ctx context.Context, username string) (adminapi.Account, error) {
	_, dir, err := s.directory()
	if err != nil {
		return adminapi.Account{}, err
	}
	a, err := findAccount(dir, username)
	if err != nil {
		return adminapi.Account{}, err
	}
	return AccountOf(a), nil
}

// inReach refuses an account a delegated operator may not change
// (design/adr/0040 §1). [admin] account_group hands the accounts socket to
// a group that is not root, and what it hands over is the accounts Gatte
// manages: those with at least one group, every one of them in
// [group_to_role]. Any other account of the IdP (an administrator of other
// applications, a person with no Gatte group) is out of reach, since a
// reset would give its login to every application behind the IdP. A peer
// the kernel says is root reaches every account, as under design/adr/0038.
func inReach(a Actor, cfg *config.Config, acct idp.Account) error {
	if a.Root {
		return nil
	}
	if len(acct.Groups) == 0 {
		return adminapi.NewError(adminapi.CodeAccountNotManaged, "account %q has no group of [group_to_role]; Gatte does not manage it, and only root may change it", visible.Escape(acct.Username)).
			With("username", acct.Username)
	}
	for _, g := range acct.Groups {
		if _, ok := cfg.GroupToRole[g]; !ok {
			return adminapi.NewError(adminapi.CodeAccountNotManaged, "account %q has group %q, outside [group_to_role]; Gatte does not manage it, and only root may change it", visible.Escape(acct.Username), visible.Escape(g)).
				With("username", acct.Username).With("group", g)
		}
	}
	return nil
}

// mappedGroups refuses any group that maps to no role: accounts get access
// through group_to_role, never around it. The result is sorted.
func mappedGroups(cfg *config.Config, groups []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, g := range groups {
		if _, ok := cfg.GroupToRole[g]; !ok {
			return nil, adminapi.NewError(adminapi.CodeGroupNotMapped, "group %q maps to no role in the configuration file; only groups of [group_to_role] are assigned", visible.Escape(g)).With("group", g)
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out, nil
}

// CheckAccount validates a draft and suggests a username, with no side
// effect.
func (s *Service) CheckAccount(ctx context.Context, d adminapi.AccountDraft) (adminapi.AccountCheck, error) {
	cfg, dir, err := s.directory()
	if err != nil {
		return adminapi.AccountCheck{}, err
	}
	out := adminapi.AccountCheck{Username: strings.TrimSpace(d.Username), Problems: []adminapi.FieldProblem{}, Groups: []adminapi.AssignableGroup{}}
	display := strings.TrimSpace(d.DisplayName)
	if out.Username == "" && display != "" {
		out.Username, out.Suggested = SuggestUsername(display), true
	}
	problem := func(field, code, msg string) {
		out.Problems = append(out.Problems, adminapi.FieldProblem{Field: field, Code: code, Message: msg})
	}
	a := idp.Account{Username: out.Username, DisplayName: display, Email: strings.TrimSpace(d.Email)}
	if err := idp.ValidateAccount(idp.Account{Username: a.Username, DisplayName: "x"}); err != nil {
		problem("username", adminapi.CodeInvalidArgument, err.Error())
	}
	if err := idp.ValidateAccount(idp.Account{Username: "x", DisplayName: a.DisplayName}); err != nil {
		problem("display_name", adminapi.CodeInvalidArgument, err.Error())
	}
	if a.Email != "" {
		if err := idp.ValidateAccount(idp.Account{Username: "x", DisplayName: "x", Email: a.Email}); err != nil {
			problem("email", adminapi.CodeInvalidArgument, err.Error())
		}
	}
	if existing, err := findAccount(dir, a.Username); err == nil {
		problem("username", adminapi.CodeAccountExists, fmt.Sprintf("%s is already taken by %s", existing.Username, existing.DisplayName))
	}
	all := AssignableGroupsOf(cfg)
	for _, g := range d.Groups {
		found := false
		for _, ag := range all {
			if ag.Name == g {
				out.Groups = append(out.Groups, ag)
				found = true
			}
		}
		if !found {
			problem("groups", adminapi.CodeGroupNotMapped, fmt.Sprintf("group %q maps to no role", g))
		}
	}
	out.OK = len(out.Problems) == 0
	return out, nil
}

// accountChange runs one account change under the lock and records it.
func (s *Service) accountChange(ctx context.Context, a Actor, tool string, change func(cfg *config.Config, dir idp.Directory) (idp.Account, string, error)) (adminapi.ActionResult, idp.Account, error) {
	res := newResult()
	if err := checkActor(a); err != nil {
		return res, idp.Account{}, err
	}
	cfg, dir, err := s.directory()
	if err != nil {
		return res, idp.Account{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, detail, err := change(cfg, dir)
	if errors.Is(err, errNoChange) {
		res.Messages = append(res.Messages, fmt.Sprintf("Account %q already is so; nothing changed and nothing was recorded.", acct.Username))
		return res, acct, nil
	}
	if err != nil {
		var ae *adminapi.Error
		switch {
		case errors.As(err, &ae):
			return res, acct, ae
		case errors.Is(err, idp.ErrNotFound):
			return res, acct, adminapi.NewError(adminapi.CodeNotFound, "no account %q", visible.Escape(acct.Username)).With("username", acct.Username)
		case errors.Is(err, idp.ErrExists):
			return res, acct, adminapi.NewError(adminapi.CodeAccountExists, "an account %q already exists", visible.Escape(acct.Username)).With("username", acct.Username)
		}
		return res, acct, adminapi.NewError(adminapi.CodeInternal, "writing the users file: %v", err)
	}
	res.Changed = true
	reason := fmt.Sprintf("account %q", acct.Username)
	if detail != "" {
		reason += ": " + detail
	}
	res.Messages = append(res.Messages, fmt.Sprintf("%s: %s", tool, reason))
	res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnIdPReload,
		Message: "The identity provider applies this when it reloads its users file (Authelia: watch: true, or a restart)."})
	s.record(ctx, cfg, &res, s.operatorRow(a, tool, reason+" "+a.Tag(), s.d.Now().UTC()))
	return res, acct, nil
}

// errNoChange is a change function's way to say the request was already
// true: the answer is changed=false and nothing is recorded.
var errNoChange = errors.New("no change")

func groupList(groups []string) string {
	if len(groups) == 0 {
		return "(none)"
	}
	return strings.Join(groups, ", ")
}

// newPassword generates a one-time password and its argon2id hash. The
// password leaves this function only in the answer's one field.
func newPassword() (string, string, error) {
	pw, err := idp.GeneratePassword()
	if err != nil {
		return "", "", err
	}
	hash, err := idp.HashPassword(pw)
	if err != nil {
		return "", "", err
	}
	return pw, hash, nil
}

// AddAccount creates an account with a generated one-time password.
// Writes (account add). NOT idempotent (design/adr/0040 §3).
func (s *Service) AddAccount(ctx context.Context, a Actor, n adminapi.NewAccount) (adminapi.PasswordResult, error) {
	var pw string
	res, acct, err := s.accountChange(ctx, a, AccountAdd, func(cfg *config.Config, dir idp.Directory) (idp.Account, string, error) {
		acct := idp.Account{Username: strings.TrimSpace(n.Username), DisplayName: strings.TrimSpace(n.DisplayName), Email: strings.TrimSpace(n.Email)}
		groups, err := mappedGroups(cfg, n.Groups)
		if err != nil {
			return acct, "", err
		}
		acct.Groups = groups
		if err := idp.ValidateAccount(acct); err != nil {
			return acct, "", adminapi.NewError(adminapi.CodeInvalidArgument, "%v", err).With("field", fieldOf(err))
		}
		if _, err := findAccount(dir, acct.Username); err == nil {
			return acct, "", adminapi.NewError(adminapi.CodeAccountExists, "an account %q already exists", acct.Username).With("username", acct.Username)
		}
		p, hash, err := newPassword()
		if err != nil {
			return acct, "", err
		}
		if err := dir.Add(acct, hash); err != nil {
			return acct, "", err
		}
		pw = p
		return acct, "groups " + groupList(groups), nil
	})
	if err != nil {
		return adminapi.PasswordResult{ActionResult: res}, err
	}
	return adminapi.PasswordResult{ActionResult: res, Account: AccountOf(acct), OneTimePassword: pw}, nil
}

// fieldOf names the field an idp.ValidateAccount error is about.
func fieldOf(err error) string {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "username"):
		return "username"
	case strings.HasPrefix(msg, "display name"):
		return "display_name"
	case strings.HasPrefix(msg, "email"):
		return "email"
	}
	return "groups"
}

// SetAccountGroups replaces the account's groups. Writes (account groups).
func (s *Service) SetAccountGroups(ctx context.Context, a Actor, username string, req adminapi.GroupsRequest) (adminapi.AccountResult, error) {
	res, acct, err := s.accountChange(ctx, a, AccountGroups, func(cfg *config.Config, dir idp.Directory) (idp.Account, string, error) {
		cur, err := findAccount(dir, username)
		if err != nil {
			return idp.Account{Username: username}, "", err
		}
		if err := inReach(a, cfg, cur); err != nil {
			return cur, "", err
		}
		groups, err := mappedGroups(cfg, req.Groups)
		if err != nil {
			return cur, "", err
		}
		have := append([]string{}, cur.Groups...)
		sort.Strings(have)
		if strings.Join(have, "\x00") == strings.Join(groups, "\x00") {
			return cur, "", errNoChange
		}
		if err := dir.SetGroups(username, groups); err != nil {
			return cur, "", err
		}
		cur.Groups = groups
		return cur, "groups " + groupList(groups), nil
	})
	return adminapi.AccountResult{ActionResult: res, Account: AccountOf(acct)}, err
}

// SetAccountDisabled refuses or allows new logins. Writes (account
// disable) or (account enable).
func (s *Service) SetAccountDisabled(ctx context.Context, a Actor, username string, disabled bool) (adminapi.AccountResult, error) {
	tool := AccountEnable
	if disabled {
		tool = AccountDisable
	}
	res, acct, err := s.accountChange(ctx, a, tool, func(cfg *config.Config, dir idp.Directory) (idp.Account, string, error) {
		cur, err := findAccount(dir, username)
		if err != nil {
			return idp.Account{Username: username}, "", err
		}
		if err := inReach(a, cfg, cur); err != nil {
			return cur, "", err
		}
		if cur.Disabled == disabled {
			return cur, "", errNoChange
		}
		if err := dir.SetDisabled(username, disabled); err != nil {
			return cur, "", err
		}
		cur.Disabled = disabled
		return cur, "", nil
	})
	return adminapi.AccountResult{ActionResult: res, Account: AccountOf(acct)}, err
}

// ResetAccountPassword replaces the password with a generated one-time
// password; each call invalidates the previous one. Writes (account reset
// password).
func (s *Service) ResetAccountPassword(ctx context.Context, a Actor, username string) (adminapi.PasswordResult, error) {
	var pw string
	res, acct, err := s.accountChange(ctx, a, AccountReset, func(cfg *config.Config, dir idp.Directory) (idp.Account, string, error) {
		cur, err := findAccount(dir, username)
		if err != nil {
			return idp.Account{Username: username}, "", err
		}
		if err := inReach(a, cfg, cur); err != nil {
			return cur, "", err
		}
		p, hash, err := newPassword()
		if err != nil {
			return cur, "", err
		}
		if err := dir.SetPassword(username, hash); err != nil {
			return cur, "", err
		}
		pw = p
		return cur, "", nil
	})
	if err != nil {
		return adminapi.PasswordResult{ActionResult: res}, err
	}
	return adminapi.PasswordResult{ActionResult: res, Account: AccountOf(acct), OneTimePassword: pw}, nil
}
