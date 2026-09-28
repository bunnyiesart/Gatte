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
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"
	"unicode"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
)

// The Tool and TargetUpstream of an operator action's audit row. In
// parentheses like the gateway's other markers, so no namespaced tool name
// and no registered upstream can ever read the same. Declared interface
// strings: a SIEM rule that alerts on an unblock matches on them.
const (
	accessBlockTool   = "(access block)"
	accessUnblockTool = "(access unblock)"
	operatorTarget    = "(gateway)"
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
  mcp-gateway access list    [-config FILE]

SUBJECT is the analyst's IdP subject (the token's "sub"), exactly as the
ANALYST column of "mcp-gateway audit" shows it. Flags go before it.

"block" refuses that subject on its very next request to the running
gateway, with no restart, whatever token they present: the caller gets a
plain 403 "forbidden". "unblock" restores them the same way. Blocks survive
restarts. A block does NOT revoke anything at the IdP: the token stays valid
there until it expires, so revoke the session at the IdP too.

Each block and unblock is recorded in the audit trail as an operator action,
attributed to SUDO_USER, or USER when not run through sudo. That name is
attribution, not authentication: whoever can run this command can write the
database.

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
	if err := access.ValidateBlock(access.Block{Subject: subject, Reason: *reason, By: "-", At: time.Now()}); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	operator, err := operatorName()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		if sub == "block" {
			return runAccessBlock(e, operator, subject, *reason)
		}
		return runAccessUnblock(e, operator, subject, *reason)
	})
}

// operatorName is who ran this command: SUDO_USER first, because the
// console runs as the service account through sudo and USER is then that
// account rather than the person, then USER, then the account database.
//
// Refused rather than defaulted when there is no answer, or one with a
// space or control character in it: an operator action attributed to
// nobody, or to a name that breaks the ANALYST column, is not a record.
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

// operatorIdentity is the ANALYST value of an operator action's row. In
// parentheses, like "(unauthenticated)", because no IdP issues a subject in
// parentheses: this row can never be read as an analyst's.
func operatorIdentity(name string) string { return "(operator:" + name + ")" }

// operatorReason is the row's Reason: the subject acted on, quoted so a
// subject that looks like prose cannot be misread, then the operator's note.
func operatorReason(subject, note string) string {
	r := fmt.Sprintf("subject %q", subject)
	if note != "" {
		r += ": " + note
	}
	return r
}

func operatorRecord(tool, operator, subject, note string, at time.Time) audit.Record {
	return audit.Record{
		AnalystIdentity: operatorIdentity(operator),
		Tool:            tool,
		TargetUpstream:  operatorTarget,
		Timestamp:       at,
		Outcome:         audit.OutcomeAllowed,
		Reason:          operatorReason(subject, note),
	}
}

// runAccessBlock places the block FIRST and records it second. If the
// record cannot be written the block stays: every failure of this command
// leaves the subject blocked, which is the direction an operator in the
// middle of an incident needs -- and the exit code and the message say the
// trail does not have it.
func runAccessBlock(e *opEnv, operator, subject, note string) int {
	now := time.Now().UTC()
	placed, err := e.blocks().Block(e.ctx(), access.Block{Subject: subject, Reason: note, By: operator, At: now})
	if err != nil {
		fmt.Fprintf(e.stderr, "blocklist: %v\n", err)
		return exitCannotRun
	}
	if !placed {
		fmt.Fprintf(e.stdout, "%s is already blocked; nothing changed and nothing was recorded.\nSee %s.\n",
			subject, e.cmd("access list"))
		return exitOK
	}
	if err := e.recordOperatorAction(operatorRecord(accessBlockTool, operator, subject, note, now)); err != nil {
		fmt.Fprintf(e.stderr, "%s IS BLOCKED, but the audit trail could not record it: %v\n"+
			"The block stays in force. Record it by hand before anything else.\n", subject, err)
		return exitProblem
	}
	fmt.Fprintf(e.stdout, "Blocked %s. The running gateway refuses it from its next request, whatever\n"+
		"token it carries; no restart is needed. This does not revoke anything at the\n"+
		"IdP: revoke the session there too. Lift it with: %s %s\n",
		subject, e.cmd("access unblock"), opShellQuote(subject))
	return exitOK
}

// runAccessUnblock records FIRST and lifts second -- the reverse of block,
// for the same reason: the subject stays blocked on every failure. An
// unblock the trail cannot record is not performed.
func runAccessUnblock(e *opEnv, operator, subject, note string) int {
	store := e.blocks()
	blocked, err := store.Blocked(e.ctx(), subject)
	if err != nil {
		fmt.Fprintf(e.stderr, "blocklist: %v\n", err)
		return exitCannotRun
	}
	if !blocked {
		fmt.Fprintf(e.stdout, "%s is not blocked; nothing changed and nothing was recorded.\n", subject)
		return exitProblem
	}
	if err := e.recordOperatorAction(operatorRecord(accessUnblockTool, operator, subject, note, time.Now().UTC())); err != nil {
		fmt.Fprintf(e.stderr, "not unblocked: the audit trail could not record it: %v\n%s stays blocked.\n", err, subject)
		return exitCannotRun
	}
	if _, err := store.Unblock(e.ctx(), subject); err != nil {
		fmt.Fprintf(e.stderr, "blocklist: %v\nThe trail records an unblock that did not take effect: %s is STILL blocked.\n", err, subject)
		return exitCannotRun
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
