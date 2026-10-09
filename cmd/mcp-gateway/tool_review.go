// Operator Console -- "tool review -server" and "tool approve -server
// -manifest": one backend's review set, reviewed and approved in one act
// (design/adr/0043).

package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// toolReview prints every pending and changed tool of one backend and the
// manifest of that set.
func toolReview(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("tool review", stderr)
	server := fs.String("server", "", "the backend whose pending and changed tools to review (required)")
	if code, ok := opParse(fs, args, stdout, stderr, toolUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, toolUsage) {
		return exitCannotRun
	}
	if *server == "" {
		fmt.Fprint(stderr, "review takes -server NAME: a review set is one backend's pending and changed tools\n\n")
		toolUsage(stderr)
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runToolReview(e, *server)
	})
}

// readReviewSet reads the set and reports the failures review and approve
// report the same way.
func readReviewSet(e *opEnv, server string) (adminapi.ToolReviewSet, int, bool) {
	svc, err := e.service()
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return adminapi.ToolReviewSet{}, exitCannotRun, false
	}
	rs, err := svc.ReviewToolSet(e.ctx(), server)
	switch {
	case adminapi.IsCode(err, adminapi.CodeNotFound):
		fmt.Fprintf(e.stderr, "no tool has been observed on %q.\n\nThe quarantine is populated at discovery time; see what has been observed:\n\n    %s\n",
			visible.Escape(server), e.cmd("tool list"))
		return rs, exitProblem, false
	case err != nil:
		fmt.Fprintf(e.stderr, "quarantine: %v\n", cliErrText(err))
		return rs, exitCannotRun, false
	}
	return rs, exitOK, true
}

// writeReviewSet composes the whole review of a set: a warning when it
// holds changed tools, each tool as `tool show` prints it, who can call
// each once approved, and the manifest.
func writeReviewSet(b *bytes.Buffer, rs adminapi.ToolReviewSet) {
	backend := visible.Escape(rs.Server)
	fmt.Fprintf(b, "REVIEW SET  %s  %d %s waiting: %d pending, %d changed\n",
		backend, len(rs.Tools), opPlural(len(rs.Tools), "tool", "tools"), rs.Pending, rs.Changed)
	if rs.Changed > 0 {
		b.WriteString("\n")
		writeChangedWarning(b)
	}
	for i, rv := range rs.Tools {
		fmt.Fprintf(b, "\n---- %d/%d ", i+1, len(rs.Tools))
		b.WriteString(strings.Repeat("-", 60))
		b.WriteString("\n")
		b.WriteString(rv.ReviewText)
		b.WriteString("\n")
	}
	if len(rs.Tools) == 0 {
		return
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 68))
	b.WriteString("\nApproving this set makes each tool callable by:\n\n")
	wildcard := false
	sensitiveRows := 0
	for _, rv := range rs.Tools {
		roles := make([]string, 0, len(rv.CallableBy))
		for _, c := range rv.CallableBy {
			roles = append(roles, c.Role)
			wildcard = wildcard || c.Wildcard
		}
		who := strings.Join(roles, ", ")
		switch {
		case rv.Tool.Class != adminapi.ClassSafe && who == "":
			// callable_by is admin.ReachableBy: for a sensitive tool, the
			// non_read roles naming it, which is who the clearance will
			// reach -- never a wildcard (design/adr/0048 Decisão 5).
			sensitiveRows++
			who = "(SENSITIVE -- no non_read role names it; approved and NOT served, and\n" + strings.Repeat(" ", 27) + "`tool clear` will refuse until one does)"
		case rv.Tool.Class != adminapi.ClassSafe:
			sensitiveRows++
			who += "  (SENSITIVE: after `tool clear`, not on this approval)"
		case who == "":
			who = "(no role -- servable, callable by nobody)"
		}
		fmt.Fprintf(b, "  %-24s %s\n", visible.Escape(rv.Tool.Tool), who)
	}
	if wildcard {
		fmt.Fprintf(b, "\n%s\n", wildcardApprovalNotice)
	}
	if sensitiveRows > 0 {
		fmt.Fprintf(b, "\n%d %s SENSITIVE: approving a set never clears. Each is approved and NOT served\nuntil `tool clear SERVER TOOL`, one at a time; a \"*\" grant never reaches one.\n",
			sensitiveRows, opPlural(sensitiveRows, "tool is", "tools are"))
	}
	if rs.HiddenCodePoints > 0 {
		fmt.Fprintf(b, "\nWARNING: the definitions above carry %d hidden %s in all, shown as\n\\u{XXXX}. Approving the set approves every one of them.\n",
			rs.HiddenCodePoints, opPlural(rs.HiddenCodePoints, "code point", "code points"))
	}
	if rs.Changed > 0 {
		b.WriteString("\nFor each CHANGED tool you are approving a NEW definition, not restoring the\nold one: it is re-baselined to the OBSERVED definition above, and the previous\none is not served again.\n")
	}
	fmt.Fprintf(b, "\nmanifest  sha256:%s\n", rs.Manifest)
}

func runToolReview(e *opEnv, server string) int {
	rs, code, ok := readReviewSet(e, server)
	if !ok {
		return code
	}
	var b bytes.Buffer
	writeReviewSet(&b, rs)
	if len(rs.Tools) == 0 {
		fmt.Fprintf(&b, "\n%s Nothing to approve.\n", rs.Reason)
	} else if rs.Approvable {
		fmt.Fprintf(&b, "\nThe manifest names exactly the set above. If every definition in it is sound,\napprove all of it -- it is refused if any tool of %s moves before then:\n\n    %s -server %s -manifest %s\n\nOr approve them one at a time with `%s -fingerprint`.\n",
			visible.Escape(server), e.cmd("tool approve"), opShellQuote(server), rs.Manifest, e.cmd("tool approve"))
	}
	if _, err := e.stdout.Write(b.Bytes()); err != nil {
		fmt.Fprintf(e.stderr, "writing output: %v\n", err)
		return exitProblem
	}
	if len(rs.Tools) > 0 && !rs.Approvable {
		fmt.Fprintf(e.stderr, "\nThis set cannot be approved: %s\n", rs.Reason)
		return exitProblem
	}
	return exitOK
}

// runToolApproveSet approves server's review set at the manifest reviewed,
// and only at that one. Like a single approval it first prints what is
// being approved -- every definition, the diffs, who can call each -- and
// that print is of the same read the manifest is checked against: the
// service then approves only if the set it reads in its own transaction
// still hashes to it. A set with a changed tool is not approved when that
// print did not reach the operator in full.
func runToolApproveSet(e *opEnv, server, reviewed string) int {
	reviewed = admin.NormalizeManifest(reviewed)
	rs, code, ok := readReviewSet(e, server)
	if !ok {
		return code
	}
	backend := visible.Escape(server)
	if len(rs.Tools) == 0 {
		fmt.Fprintf(e.stdout, "%s Nothing was approved.\n", rs.Reason)
		return exitOK
	}
	var b bytes.Buffer
	writeReviewSet(&b, rs)
	_, werr := e.stdout.Write(b.Bytes())
	switch {
	case !rs.Approvable:
		fmt.Fprintf(e.stderr, "\nNOT approved: %s\n", rs.Reason)
		return exitProblem
	case werr != nil && rs.Changed > 0:
		fmt.Fprintf(e.stderr, "\nNOT approved: the set holds CHANGED tools and the definitions and warning above\ncould not be printed in full (%v). Re-run this command somewhere the output\nsurvives.\n", werr)
		return exitProblem
	case reviewed == "":
		fmt.Fprintf(e.stderr, "\nNOT approved: approving a set needs -manifest, the manifest of the set you\nreviewed. The set above is sha256:%s. If every definition in it is sound, run:\n\n    %s -server %s -manifest %s\n",
			rs.Manifest, e.cmd("tool approve"), opShellQuote(server), rs.Manifest)
		return exitProblem
	case reviewed != rs.Manifest:
		fmt.Fprintf(e.stderr, "\nNOT approved: the tools of %s waiting for review are now the set sha256:%s,\nnot the sha256:%s you reviewed. Something joined, left or changed since you\nlooked. Review the set shown above, then approve its manifest if it is sound.\n",
			backend, rs.Manifest, visible.Escape(reviewed))
		return exitProblem
	}

	svc, err := e.service()
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	actor, err := e.operator()
	if err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	res, err := svc.ApproveToolSet(e.ctx(), actor, adminapi.ApproveSetRequest{Server: server, Manifest: reviewed})
	switch {
	case adminapi.IsCode(err, adminapi.CodeManifestMismatch):
		fmt.Fprintf(e.stderr, "\nNOT approved: the tools of %s changed while this command ran. Nothing was\napproved. Run `%s -server %s` and review them again.\n", backend, e.cmd("tool review"), opShellQuote(server))
		return exitProblem
	case err != nil:
		fmt.Fprintf(e.stderr, "\nquarantine: approving the review set of %s: %v\n", backend, cliErrText(err))
		return exitCannotRun
	case !res.Changed:
		fmt.Fprintf(e.stdout, "\n%s\n", strings.Join(res.Messages, "\n"))
		return exitOK
	}

	fmt.Fprintf(e.stdout, "\nApproved %d %s of %s (review set sha256:%s).\n\n",
		len(res.Approved), opPlural(len(res.Approved), "tool", "tools"), backend, res.Manifest)
	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "  TOOL\tWAS\tNOW APPROVED AT")
	notUsable := false
	for _, a := range res.Approved {
		was := a.PreviousStatus
		if a.PreviousBaseline != "" {
			was += " (baseline sha256:" + opShortHash(a.PreviousBaseline) + " no longer accepted)"
		}
		now := "sha256:" + a.Tool.ApprovedHash
		if a.Tool.Class != adminapi.ClassSafe && !a.Tool.Usable {
			// Approving a set never clears (design/adr/0048 Decisão 5):
			// a sensitive tool of it is approved and held, and that is
			// the default-deny, not the bug the flag below reports. The
			// service's sensitive_uncleared warning, printed after the
			// table, names the command for each.
			now += "  (sensitive: NOT served until cleared)"
		} else {
			notUsable = notUsable || !a.Tool.Usable
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", visible.Escape(a.Tool.Tool), was, now)
	}
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}
	fmt.Fprint(e.stdout, "\nEach fingerprint is now that tool's baseline. A later change to any of them\nmarks that tool changed at the next discovery and stops it being served.\n")
	for _, w := range res.Warnings {
		if w.Code != adminapi.WarnAuditWriteFailed && w.Code != adminapi.WarnWildcardGrant {
			fmt.Fprintf(e.stdout, "\n%s\n", w.Message)
		}
	}
	if notUsable {
		fmt.Fprint(e.stdout, "\nWARNING: a tool above is still NOT usable after approval. This is a bug -- report it.\n")
		return exitProblem
	}
	if !res.Recorded {
		fmt.Fprintf(e.stderr, "\nTHE SET IS APPROVED, but the audit trail could not record all of it: %s\nRecord it by hand before anything else.\n",
			warningText(res.ActionResult, adminapi.WarnAuditWriteFailed))
		return exitProblem
	}
	return exitOK
}
