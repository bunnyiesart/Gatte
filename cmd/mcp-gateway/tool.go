// Operator Console -- the "tool" subcommand: the Tool Quarantine's
// approval queue.

package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// cmdTool implements "mcp-gateway tool": list quarantined tools, or
// approve one.
func cmdTool(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		toolUsage(stderr)
		return exitCannotRun
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return toolList(rest, stdout, stderr)
	case "approve":
		return toolApprove(rest, stdout, stderr)
	case "-h", "--help", "help":
		toolUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown \"tool\" subcommand %q\n\n", sub)
		toolUsage(stderr)
		return exitCannotRun
	}
}

func toolUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway tool list [-config FILE] [-server NAME] [-json]
  mcp-gateway tool approve [-config FILE] SERVER TOOL

"list" is the approval queue: it shows every tool the gateway has observed,
including the pending and changed ones, which are precisely the ones that
need a human. A tool is usable only when an operator approved it AND the
definition being advertised now still matches what was approved.

Exit codes: 0 ok, 1 ran and found a problem, 2 could not run.
`)
}

// toolList prints the approval queue.
func toolList(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("tool list", stderr)
	server := fs.String("server", "", "only show tools on this upstream server")
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	fs.Usage = func() { toolUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if !opNoArgs(fs, stderr) {
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runToolList(e, *server, *asJSON)
	})
}

// toolJSON is the -json shape of one quarantine entry. Usable is emitted
// as its own field rather than left to be inferred from Status: the whole
// point of quarantine.Tool.Usable is that nothing re-derives that decision
// from the status, and a JSON consumer is no exception.
type toolJSON struct {
	Server       string    `json:"server"`
	Tool         string    `json:"tool"`
	Status       string    `json:"status"`
	Usable       bool      `json:"usable"`
	ApprovedHash string    `json:"approved_hash"`
	ObservedHash string    `json:"observed_hash"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func runToolList(e *opEnv, server string, asJSON bool) int {
	tools, err := e.tools().List(e.ctx(), server)
	if err != nil {
		fmt.Fprintf(e.stderr, "quarantine: %v\n", err)
		return exitCannotRun
	}

	if asJSON {
		out := make([]toolJSON, 0, len(tools))
		for _, t := range tools {
			out = append(out, toolJSON{
				Server:       t.ServerName,
				Tool:         t.ToolName,
				Status:       string(t.Status),
				Usable:       t.Usable(),
				ApprovedHash: t.ApprovedHash,
				ObservedHash: t.ObservedHash,
				FirstSeenAt:  t.FirstSeenAt,
				UpdatedAt:    t.UpdatedAt,
			})
		}
		if err := opJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "writing json: %v\n", err)
			return exitCannotRun
		}
		if len(tools) == 0 {
			return exitProblem
		}
		return exitOK
	}

	if len(tools) == 0 {
		if server != "" {
			fmt.Fprintf(e.stdout, "No tools have been observed on %q.\n\nEither nothing is registered under that name, or the gateway has not\nconnected to it yet -- the quarantine is populated at discovery time.\n", server)
		} else {
			fmt.Fprint(e.stdout, "No tools have been observed yet.\n\nThe quarantine is populated at discovery time, when the gateway connects to\na registered upstream. Register one and start the gateway.\n")
		}
		return exitProblem
	}

	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "SERVER\tTOOL\tSTATUS\tUSABLE\tOBSERVED FINGERPRINT\tUPDATED")
	var pending, changed []string
	for _, t := range tools {
		usable := "no"
		if t.Usable() {
			usable = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ServerName, t.ToolName, t.Status, usable, opShortHash(t.ObservedHash), opTime(t.UpdatedAt))

		switch t.Status {
		case quarantine.StatusPending:
			pending = append(pending, t.ServerName+"."+t.ToolName)
		case quarantine.StatusChanged:
			changed = append(changed, t.ServerName+"."+t.ToolName)
		}
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "writing table: %v\n", err)
		return exitCannotRun
	}

	fmt.Fprintf(e.stdout, "\n%d %s. USABLE is the gateway's own gate: a tool that is not usable is\nneither listed to clients nor dispatched.\n",
		len(tools), opPlural(len(tools), "tool", "tools"))

	if len(pending) > 0 {
		fmt.Fprintf(e.stdout, "\n%d %s approval, never approved before:\n",
			len(pending), opPlural(len(pending), "tool is awaiting", "tools are awaiting"))
		for _, name := range pending {
			fmt.Fprintf(e.stdout, "    %s\n", name)
		}
	}
	if len(changed) > 0 {
		// Changed is not just "another kind of pending". It means a
		// definition a human already vetted was replaced afterwards --
		// the rug pull (OWASP MCP03) this component exists to catch -- so
		// it gets its own, louder block rather than a row in a list.
		fmt.Fprintf(e.stdout, "\n%d CHANGED %s a definition that no longer matches what was approved:\n",
			len(changed), opPlural(len(changed), "tool -- it has", "tools -- they have"))
		for _, name := range changed {
			fmt.Fprintf(e.stdout, "    %s\n", name)
		}
		fmt.Fprint(e.stdout, "A change to an approved tool's description or schema is how a poisoned tool\ngets past an approval that already happened. Read the new definition on the\nupstream server before approving it.\n")
	}
	if len(pending) > 0 || len(changed) > 0 {
		fmt.Fprint(e.stdout, "\nApprove with:\n\n    mcp-gateway tool approve SERVER TOOL\n")
	}
	return exitOK
}

// toolApprove approves one quarantined tool.
func toolApprove(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("tool approve", stderr)
	fs.Usage = func() { toolUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if fs.NArg() != 2 {
		fmt.Fprint(stderr, "approve takes exactly two arguments: the server name and the tool name\n\n")
		toolUsage(stderr)
		return exitCannotRun
	}
	server, tool := fs.Arg(0), fs.Arg(1)

	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runToolApprove(e, server, tool)
	})
}

func runToolApprove(e *opEnv, server, tool string) int {
	q := e.tools()

	// Read the state first. Approve returns the state *after* the
	// transition, and what an operator most needs to be told -- that they
	// are re-baselining a tool that changed under them -- is only visible
	// in the state before it.
	before, err := q.Get(e.ctx(), server, tool)
	switch {
	case errors.Is(err, quarantine.ErrNotFound):
		fmt.Fprintf(e.stderr, "no quarantine entry for tool %q on server %q.\n\nA tool can only be approved after the gateway has actually observed it, so\nan operator never approves a definition typed from memory. See what has\nbeen observed:\n\n    mcp-gateway tool list -server %s\n", tool, server, server)
		return exitProblem
	case errors.Is(err, quarantine.ErrInvalidStatus):
		fmt.Fprintf(e.stderr, "the stored quarantine entry for %s.%s has an unrecognised status: %v\nThat row is corrupt or was hand-edited. Refusing to approve it.\n", server, tool, err)
		return exitProblem
	case err != nil:
		fmt.Fprintf(e.stderr, "quarantine: %v\n", err)
		return exitCannotRun
	}

	name := server + "." + tool

	// Everything that makes this a decision rather than a keystroke is
	// printed before the change, not after it.
	switch before.Status {
	case quarantine.StatusChanged:
		printChangedWarning(e.stdout, name, before)
	case quarantine.StatusApproved:
		if before.Usable() {
			fmt.Fprintf(e.stdout, "%s was already approved at exactly this definition (sha256:%s).\nNothing to do; it is usable.\n", name, before.ObservedHash)
			return exitOK
		}
	}

	after, err := q.Approve(e.ctx(), server, tool)
	if err != nil {
		fmt.Fprintf(e.stderr, "quarantine: approving %s: %v\n", name, err)
		return exitCannotRun
	}

	switch before.Status {
	case quarantine.StatusPending:
		fmt.Fprintf(e.stdout, "Approved %s.\n\n", name)
		tw := opTable(e.stdout)
		fmt.Fprintf(tw, "  was\tpending (first seen %s)\n", opTime(before.FirstSeenAt))
		fmt.Fprintf(tw, "  now\tapproved\n")
		fmt.Fprintf(tw, "  approved fingerprint\tsha256:%s\n", after.ApprovedHash)
		if err := tw.Flush(); err != nil {
			fmt.Fprintf(e.stderr, "writing table: %v\n", err)
			return exitCannotRun
		}
		fmt.Fprint(e.stdout, "\nThat fingerprint is now the baseline. If this tool's name, description or\ninput schema changes on the upstream server, the gateway will mark it\nchanged at the next discovery and stop serving it until you look again.\n")
	case quarantine.StatusChanged:
		fmt.Fprintf(e.stdout, "\nApproved %s at its NEW definition.\n\n", name)
		tw := opTable(e.stdout)
		fmt.Fprintf(tw, "  previous baseline\tsha256:%s  (no longer accepted)\n", before.ApprovedHash)
		fmt.Fprintf(tw, "  new baseline\tsha256:%s\n", after.ApprovedHash)
		if err := tw.Flush(); err != nil {
			fmt.Fprintf(e.stderr, "writing table: %v\n", err)
			return exitCannotRun
		}
		fmt.Fprint(e.stdout, "\nThe tool is usable again, and future changes are detected against the new\nbaseline -- not against the definition you originally approved.\n")
	default:
		// Approved but not usable: the baseline was empty or the observed
		// fingerprint had drifted without the status following. Re-approving
		// is the fix; say what it did rather than printing nothing.
		fmt.Fprintf(e.stdout, "Re-approved %s at sha256:%s.\n", name, after.ApprovedHash)
	}

	if !after.Usable() {
		// Should not happen: Approved() sets the baseline to the observed
		// fingerprint. If it does, the operator must not be left believing
		// the tool is now being served.
		fmt.Fprintf(e.stdout, "\nWARNING: %s is still NOT usable after approval (status %s, approved %q,\nobserved %q). The gateway will keep refusing it. This is a bug -- report it.\n",
			name, after.Status, after.ApprovedHash, after.ObservedHash)
		return exitProblem
	}
	return exitOK
}

// printChangedWarning explains, before the approval happens, what
// approving a changed tool actually does.
//
// The quarantine stores fingerprints, not definitions, so there is no diff
// to show and this function does not pretend otherwise: it says what is
// known (which fingerprint was vetted, which one is being accepted, when
// the change was noticed), says plainly that the old definition was never
// kept, and says that approving moves the baseline forward. This is the
// rug-pull decision point, and "approved" on its own would be too quiet
// for it.
func printChangedWarning(w io.Writer, name string, before quarantine.Tool) {
	fmt.Fprintf(w, "CHANGED TOOL -- READ THIS BEFORE APPROVING\n\n")
	tw := opTable(w)
	fmt.Fprintf(tw, "  tool\t%s\n", name)
	fmt.Fprintf(tw, "  first seen\t%s\n", opTime(before.FirstSeenAt))
	fmt.Fprintf(tw, "  change noticed\t%s\n", opTime(before.UpdatedAt))
	fmt.Fprintf(tw, "  fingerprint approved before\tsha256:%s\n", before.ApprovedHash)
	fmt.Fprintf(tw, "  fingerprint being approved now\tsha256:%s\n", before.ObservedHash)
	tw.Flush()
	fmt.Fprint(w, `
Something in this tool's name, description or input schema changed after an
operator approved it. The quarantine stores fingerprints, not definitions,
so it cannot show you a diff: the description you approved was never kept,
only its hash. What it can tell you is that the two hashes above differ.

That matters because a tool's description is handed to an LLM as
instructions it acts on. Rewriting the description of an already-approved
tool is the rug pull (OWASP MCP03) this quarantine exists to catch.

You are approving a NEW definition, not restoring the old one. Approving
re-baselines this tool to whatever the server is advertising right now, and
the previous definition does not come back. Read the tool's current
description and input schema on the upstream server first, if you have not.
`)
}
