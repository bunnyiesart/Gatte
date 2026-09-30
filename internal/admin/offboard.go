package admin

import (
	"context"
	"fmt"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// People lifecycle on the accounts socket (design/adr/0046 item 2).

// DeleteAccount removes an account from the IdP's users file. Same reach
// as disable (design/adr/0040 §1). Writes (account delete).
func (s *Service) DeleteAccount(ctx context.Context, a Actor, username string) (adminapi.AccountResult, error) {
	res, acct, err := s.accountChange(ctx, a, AccountDelete, func(cfg *config.Config, dir idp.Directory) (idp.Account, string, error) {
		cur, err := findAccount(dir, username)
		if err != nil {
			return idp.Account{Username: username}, "", err
		}
		if err := inReach(a, cfg, cur); err != nil {
			return cur, "", err
		}
		if err := dir.Delete(username); err != nil {
			return cur, "", err
		}
		return cur, "groups " + groupList(cur.Groups), nil
	})
	if err == nil && res.Changed {
		res.Messages = append(res.Messages, deleteCaveats...)
	}
	return adminapi.AccountResult{ActionResult: res, Account: AccountOf(acct)}, err
}

// deleteCaveats is what a deletion does not do.
var deleteCaveats = []string{
	"The audit trail keeps every row this person wrote; deleting the account erases none of it.",
	"A session already open and a token already issued are not ended by the deletion: revoke them at the identity provider. A gateway block on their subject, if there is one, stays.",
	"The identity provider may issue the same subject again to an account created later with the same username (Authelia keeps it per username); that account would inherit a block on it, and the trail would read both people as one. Give a new person a new username.",
}

// offboardReason is the block note's text for an offboard.
func offboardReason(username, reason string) string {
	r := fmt.Sprintf("offboard of account %q", username)
	if reason != "" {
		r += "; " + reason
	}
	return r
}

// Offboard blocks the person's subject in the gateway and disables their
// account, in that order, in one call. The block is placed first because
// it is the half that ends a session already open; the disable stops new
// sign-ins. Each half writes its own row, (access block) and (account
// disable), and a summary row (account offboard) says what the call did.
//
// A subject is optional (a person who never used the gateway has none),
// and a non-root peer offboarding with one must also be in [admin]
// operator_group: blocking is an operator's action (design/adr/0031), and
// the accounts socket does not hand it to [admin] account_group alone.
//
// Nothing is done when the block cannot be placed. When the block took
// effect and the disable failed, the answer is 200 with changed true and
// warning offboard_incomplete: a change in force is never an error.
func (s *Service) Offboard(ctx context.Context, a Actor, username string, req adminapi.OffboardRequest) (adminapi.OffboardResult, error) {
	res := adminapi.OffboardResult{ActionResult: newResult(), Subject: req.Subject, Rows: []adminapi.OperatorRow{}, Remaining: []string{}}
	if err := checkActor(a); err != nil {
		return res, err
	}
	var note string
	block := adminapi.BlockRequest{Subject: req.Subject, Reason: offboardReason(username, req.Reason)}
	if req.Subject != "" {
		if !a.Root && !a.Operator {
			return res, adminapi.NewError(adminapi.CodeForbiddenPeer,
				"an offboard with a subject also blocks it in the gateway, which only root or a member of [admin] operator_group may do; %s is neither. Offboard without a subject, and ask an operator to block it", a.Name)
		}
		var err error
		if note, err = s.validateBlock(a, block); err != nil {
			return res, err
		}
		if err := need(s.d.Blocks != nil, "blocklist"); err != nil {
			return res, err
		}
	}
	cfg, dir, err := s.directory()
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := findAccount(dir, username)
	if err != nil {
		return res, err
	}
	if err := inReach(a, cfg, cur); err != nil {
		return res, err
	}
	res.Account = AccountOf(cur)

	var did []string
	recorded := true
	// add folds one part's answer in: its messages and warnings, and its
	// row when it wrote one. The offboard is recorded only if every row
	// it meant to write was.
	add := func(part adminapi.ActionResult, wroteRow bool) {
		res.Messages = append(res.Messages, part.Messages...)
		res.Warnings = append(res.Warnings, part.Warnings...)
		if !wroteRow {
			return
		}
		if part.Recorded && part.Audit != nil {
			res.Rows = append(res.Rows, *part.Audit)
			res.Audit = part.Audit
		} else {
			recorded = false
		}
	}
	if req.Subject != "" {
		out := blockOutcome{ActionResult: newResult()}
		s.placeBlock(ctx, cfg, a, block, note, &out)
		if out.err != nil {
			return res, out.err
		}
		res.Blocked = true
		add(out.ActionResult, out.Changed)
		if out.Changed {
			res.Changed = true
			did = append(did, "blocked")
		}
	}

	switch {
	case cur.Disabled:
		res.Disabled = true
		res.Messages = append(res.Messages, fmt.Sprintf("Account %q was already disabled.", username))
	default:
		if err := dir.SetDisabled(username, true); err != nil {
			if !res.Changed {
				return res, adminapi.NewError(adminapi.CodeInternal, "writing the users file: %v; nothing was changed", err)
			}
			res.Warnings = append(res.Warnings, adminapi.Warning{Code: adminapi.WarnOffboardIncomplete,
				Message: fmt.Sprintf("The gateway block on %s is in force, but the account %q was NOT disabled (%v): disable it by hand.", req.Subject, username, err)})
			break
		}
		res.Disabled, res.Account.Disabled, res.Changed = true, true, true
		did = append(did, "disabled")
		part := newResult()
		part.Messages = append(part.Messages, fmt.Sprintf("Disabled account %q: the identity provider refuses their next sign-in once it reloads its users file.", username))
		part.Warnings = append(part.Warnings, adminapi.Warning{Code: adminapi.WarnIdPReload,
			Message: "The identity provider applies this when it reloads its users file (Authelia: watch: true, or a restart)."})
		s.record(ctx, cfg, &part, s.operatorRow(a, AccountDisable, fmt.Sprintf("account %q: offboard %s", username, a.Tag()), s.d.Now().UTC()))
		add(part, true)
	}

	if !res.Changed {
		res.Messages = append(res.Messages, fmt.Sprintf("%q is already offboarded; nothing changed and nothing was recorded.", username))
	} else {
		subject := "no subject"
		if req.Subject != "" {
			subject = fmt.Sprintf("subject %q", req.Subject)
		}
		reason := fmt.Sprintf("account %q, %s: %s %s", username, subject, joinWords(did), a.Tag())
		if req.Reason != "" {
			reason += " " + req.Reason
		}
		part := newResult()
		s.record(ctx, cfg, &part, s.operatorRow(a, AccountOffboard, reason, s.d.Now().UTC()))
		add(part, true)
		res.Recorded = recorded
	}
	res.Remaining = offboardRemaining(req.Subject)
	return res, nil
}

// offboardRemaining is what an offboard leaves to the operator. Never
// empty: Gatte cannot reach the identity provider's sessions.
func offboardRemaining(subject string) []string {
	out := []string{
		"Revoke their sessions and tokens at the identity provider. Disabling stops new sign-ins; a session already open there, and a token already issued, last until they expire, and every other application behind the same identity provider still accepts them.",
	}
	if subject == "" {
		out = append(out, "No gateway block was placed: no subject was given. A token they already hold keeps working here until it expires. Find their subject in the audit trail and block it in Access.")
	} else {
		out = append(out, fmt.Sprintf("The gateway block is on the subject %s only. If this person also used another account, block that subject too.", subject))
	}
	out = append(out, "Delete the account once it is no longer needed in the identity provider; the audit trail keeps their rows either way.")
	return out
}

func joinWords(ws []string) string {
	switch len(ws) {
	case 0:
		return "nothing"
	case 1:
		return ws[0]
	}
	return ws[0] + " and " + ws[1]
}
