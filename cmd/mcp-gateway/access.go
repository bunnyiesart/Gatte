// Operator Console -- the "access" subcommand: the per-analyst kill switch
// (design/adr/0031-bloqueio-imediato-por-analista.md).
//
// A token stays valid until its `exp`, and revoking the analyst at the IdP
// does not shorten a token already issued. `access block SUBJECT` does: the
// running gateway reads the blocklist on every request, so the next request
// carrying that subject is refused, with no restart and whatever token it
// carries.
//
// Every change is an operator action on the audit trail, attributed to the
// operating-system user that ran the command. The console becomes a second
// writer of the hash chain for exactly these rows; see recordOperatorAction
// for why that is safe.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"
	"unicode"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The Tool and TargetUpstream of an operator action's audit row. In
// parentheses like the gateway's other markers, so no namespaced tool name
// and no registered upstream can ever read the same. Declared interface
// strings: a SIEM rule that alerts on an unblock matches on them.
const (
	accessBlockTool   = admin.AccessBlock
	accessUnblockTool = admin.AccessUnblock
	operatorTarget    = admin.OperatorTarget
)

func cmdAccess(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		accessUsageText(stderr)
		return exitCannotRun
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "block":
		return accessChange(sub, rest, stdout, stderr)
	case "unblock":
		return accessChange(sub, rest, stdout, stderr)
	case "list":
		return accessList(rest, stdout, stderr)
	case "-h", "--help", "help":
		accessUsageText(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown \"access\" subcommand %q\n\n", sub)
		accessUsageText(stderr)
		return exitCannotRun
	}
}

func accessUsageText(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway access block   [-config FILE] [-reason TEXT] SUBJECT
  mcp-gateway access unblock [-config FILE] [-reason TEXT] SUBJECT
  mcp-gateway access list    [-config FILE] [-json]

SUBJECT is the analyst's IdP subject (the token's "sub"), exactly as the
ANALYST column of "mcp-gateway audit" shows it. Flags go before it.
Matching is exact: "block" warns when no request from SUBJECT is on the
trail, which usually means a typo, and places the block anyway.

"block" refuses that subject on its very next request to the running
gateway, with no restart, whatever token they present: the caller gets a
plain 403 "forbidden". "unblock" restores them the same way. Blocks survive
restarts. A block does NOT revoke anything at the IdP: the token stays valid
there until it expires, so revoke the session at the IdP too.

Each block and unblock is recorded in the audit trail as an operator action,
attributed to SUDO_USER, else USER, else the account running the command.
That is the login account, not necessarily the person: logged in as root
(or as the service account) every row reads (operator:root), so put who did
it in -reason. It is attribution, not authentication: whoever can run this
command can write the database.

Exit codes: 0 ok (including "already blocked" and an empty list), 1 ran and
found a problem (unblocking a subject that is not blocked, or a block that
took effect but could not be audited), 2 could not run.
`)
}

func accessChange(sub string, args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("access "+sub, stderr)
	reason := fs.String("reason", "", "why, in a few words; recorded in the audit trail and never shown to the analyst")
	if code, ok := opParse(fs, args, stdout, stderr, accessUsageText); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "%s takes exactly one argument: the subject\n\n", sub)
		accessUsageText(stderr)
		return exitCannotRun
	}
	subject := fs.Arg(0)
	// Validated before anything is opened, so a typo costs nothing and is
	// never recorded.
	if err := access.ValidateSubject(subject); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	actor, err := cliActor()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	// The reason stored is the tagged one ("[cli] ..."), so that is the one
	// validated here, as the service will.
	if err := access.ValidateBlock(access.Block{Subject: subject, Reason: admin.BlockNote(actor, *reason), By: actor.Name, At: time.Now()}); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		e.actor = actor
		if sub == "block" {
			return runAccessBlock(e, actor.Name, subject, *reason)
		}
		return runAccessUnblock(e, actor.Name, subject, *reason)
	})
}

// operatorName is who ran this command: SUDO_USER first, because the
// console runs as the service account through sudo and USER is then that
// account rather than the person, then USER, then the account database
// (user.Current) -- which is where a root-by-key login, or a script that
// cleared the environment, ends up: the name is then the account, not the
// person, and ADR-0031 §4 says -reason carries who.
//
// Refused when even the account database has no answer, or when the name
// has a space or control character in it: an operator action attributed
// to nobody, or to a name that breaks the ANALYST column, is not a record.
func operatorName() (string, error) {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		name = os.Getenv("USER")
	}
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	if name == "" || strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", fmt.Errorf("cannot tell which user is running this command (SUDO_USER=%q, USER=%q): an operator action must be attributable", os.Getenv("SUDO_USER"), os.Getenv("USER"))
	}
	return name, nil
}

// actorNamed is this command's actor when it is operator, and otherwise an
// actor of that name from the terminal.
func (e *opEnv) actorNamed(operator string) admin.Actor {
	if e.actor.Name == operator {
		return e.actor
	}
	return admin.Actor{Name: operator, Front: "cli"}
}

// runAccessBlock places the block FIRST and records it second, through the
// management service (design/adr/0031, 0040). If the record cannot be
// written the block stays: every failure of this command leaves the
// subject blocked, which is the direction an operator in the middle of an
// incident needs -- and the exit code and the message say the trail does
// not have it.
func runAccessBlock(e *opEnv, operator, subject, note string) int {
	svc, err := e.service()
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	res, err := svc.Block(e.ctx(), e.actorNamed(operator), adminapi.BlockRequest{Subject: subject, Reason: note})
	if err != nil {
		fmt.Fprintf(e.stderr, "blocklist: %v\n", cliErrText(err))
		return exitCannotRun
	}
	if !res.Changed {
		fmt.Fprintf(e.stdout, "%s is already blocked; nothing changed and nothing was recorded.\nSee %s.\n",
			subject, e.cmd("access list"))
		return exitOK
	}
	if !res.Recorded {
		fmt.Fprintf(e.stderr, "%s IS BLOCKED, but the audit trail could not record it: %s\n"+
			"The block stays in force. Record it by hand before anything else.\n", subject, warningText(res.ActionResult, adminapi.WarnAuditWriteFailed))
		return exitProblem
	}
	fmt.Fprintf(e.stdout, "Blocked %s. The running gateway refuses it from its next request, whatever\n"+
		"token it carries; no restart is needed. This does not revoke anything at the\n"+
		"IdP: revoke the session there too. Lift it with: %s %s\n",
		subject, e.cmd("access unblock"), opShellQuote(subject))
	if res.HasWarning(adminapi.WarnNeverSeen) {
		fmt.Fprintf(e.stderr, "warning: no request from this subject is on record; check the spelling against %s.\n"+
			"The block is in force either way.\n", e.cmd("audit"))
	}
	return exitOK
}

// warningText is the message of the result's warning code, or "".
func warningText(r adminapi.ActionResult, code string) string {
	for _, w := range r.Warnings {
		if w.Code == code {
			return w.Message
		}
	}
	return ""
}

// cliErrText is an error as the terminal shows it: the service's message
// without the "gatte admin: code:" prefix.
func cliErrText(err error) string {
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae.Message
	}
	return err.Error()
}

// retryBusy runs fn again when it fails because another writer -- the
// running serve, typically -- held the database's write lock for the whole
// busy_timeout (ADR-0031 §5). A busy error means nothing was written, so
// the retry cannot duplicate a row.
func retryBusy(ctx context.Context, fn func() error) error {
	backoff := 100 * time.Millisecond
	var err error
	for attempt := 0; attempt < busyAttempts; attempt++ {
		if err = fn(); err == nil || !store.IsBusy(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return err
}

// busyAttempts bounds retryBusy: with busy_timeout at five seconds, four
// attempts wait at most about twenty-one seconds before the command says
// so -- long enough to outlast a burst, short enough for an operator.
const busyAttempts = 4

// runAccessUnblock records FIRST and lifts second -- the reverse of block,
// for the same reason: the subject stays blocked on every failure. An
// unblock the trail cannot record is not performed.
func runAccessUnblock(e *opEnv, operator, subject, note string) int {
	svc, err := e.service()
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	res, err := svc.Unblock(e.ctx(), e.actorNamed(operator), adminapi.BlockRequest{Subject: subject, Reason: note})
	if err != nil {
		fmt.Fprintf(e.stderr, "%s\n", cliErrText(err))
		return exitCannotRun
	}
	if !res.Changed {
		fmt.Fprintf(e.stdout, "%s is not blocked; nothing changed and nothing was recorded.\n", subject)
		return exitProblem
	}
	fmt.Fprintf(e.stdout, "Unblocked %s. The running gateway serves it again from its next request.\n", subject)
	return exitOK
}

func accessList(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("access list", stderr)
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	if code, ok := opParse(fs, args, stdout, stderr, accessUsageText); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, accessUsageText) {
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runAccessList(e, *asJSON)
	})
}

// accessBlockJSON is the -json shape of one block.
type accessBlockJSON struct {
	Subject string    `json:"subject"`
	By      string    `json:"blocked_by"`
	At      time.Time `json:"blocked_at"`
	Reason  string    `json:"reason"`
}

func runAccessList(e *opEnv, asJSON bool) int {
	blocks, err := e.blocks().Blocks(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "blocklist: %v\n", err)
		return exitCannotRun
	}
	if asJSON {
		out := make([]accessBlockJSON, 0, len(blocks))
		for _, b := range blocks {
			out = append(out, accessBlockJSON{Subject: b.Subject, By: b.By, At: b.At, Reason: b.Reason})
		}
		if err := opJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "writing json: %v\n", err)
			return exitCannotRun
		}
		return exitOK
	}
	// Empty is the healthy state of a blocklist, so it is exit 0 -- unlike
	// the other list commands, where an empty answer usually means a
	// misconfiguration.
	if len(blocks) == 0 {
		fmt.Fprintln(e.stdout, "No subject is blocked.")
		return exitOK
	}
	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "SUBJECT\tBLOCKED AT\tBY\tREASON")
	for _, b := range blocks {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", b.Subject, opTime(b.At), b.By, opDash(b.Reason))
	}
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}
	fmt.Fprintf(e.stdout, "\n%d %s blocked. Each is refused on every request until unblocked.\n",
		len(blocks), opPlural(len(blocks), "subject", "subjects"))
	return exitOK
}
