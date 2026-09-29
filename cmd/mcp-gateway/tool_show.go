// Operator Console -- "tool show": the definitions behind a quarantine
// entry's fingerprints (design/adr/0032-quarentena-informada-e-eventos.md).

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// toolShow prints what one quarantined tool advertises and what was
// approved.
func toolShow(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("tool show", stderr)
	if code, ok := opParse(fs, args, stdout, stderr, toolUsage); !ok {
		return code
	}
	if fs.NArg() != 2 {
		fmt.Fprint(stderr, "show takes exactly two arguments: the server name and the tool name\n\n")
		toolUsage(stderr)
		return exitCannotRun
	}
	server, tool := fs.Arg(0), fs.Arg(1)
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runToolShow(e, server, tool)
	})
}

func runToolShow(e *opEnv, server, tool string) int {
	t, code, ok := getForConsole(e, server, tool, "show")
	if !ok {
		return code
	}
	var b bytes.Buffer
	shown := writeReview(e, &b, t)
	if _, err := e.stdout.Write(b.Bytes()); err != nil {
		fmt.Fprintf(e.stderr, "writing output: %v\n", err)
		return exitProblem
	}
	if !shown {
		return exitProblem
	}
	return exitOK
}

// getForConsole reads one quarantine entry and reports the failures every
// command that reads one reports the same way.
func getForConsole(e *opEnv, server, tool, verb string) (quarantine.Tool, int, bool) {
	t, err := e.tools().Get(e.ctx(), server, tool)
	switch {
	case errors.Is(err, quarantine.ErrNotFound):
		fmt.Fprintf(e.stderr, "no quarantine entry for tool %q on server %q.\n\nA tool can only be approved after the gateway has actually observed it, so\nan operator never approves a definition typed from memory. See what has\nbeen observed:\n\n    %s -server %s\n",
			visible.Escape(tool), visible.Escape(server), e.cmd("tool list"), opShellQuote(server))
		return t, exitProblem, false
	case errors.Is(err, quarantine.ErrInvalidStatus):
		fmt.Fprintf(e.stderr, "the stored quarantine entry for %s.%s has an unrecognised status: %v\nThat row is corrupt or was hand-edited. Refusing to %s it.\n",
			visible.Escape(server), visible.Escape(tool), err, verb)
		return t, exitProblem, false
	case err != nil:
		fmt.Fprintf(e.stderr, "quarantine: %v\n", err)
		return t, exitCannotRun, false
	}
	return t, exitOK, true
}

// writeReview writes, for t, the header, the observed definition, the
// approved one when it differs, and the line diff between the two
// (admin.WriteReview, the same text the management API returns as
// review_text). It reports false when the OBSERVED definition cannot be
// shown -- the one an approval would baseline -- after saying why on
// e.stderr.
func writeReview(e *opEnv, w io.Writer, t quarantine.Tool) bool {
	return admin.WriteReview(e.ctx(), e.tools(), w, e.stderr, t)
}

// definitionLines is a definition as tool show prints it, one escaped line
// each, and the number of hidden code points in it.
func definitionLines(t quarantine.ToolIdentity) ([]string, int) {
	lines, hidden := admin.DefinitionLines(t)
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.Escaped()
	}
	return out, hidden
}

// reviewDiff is the approved-to-observed line diff as tool show prints it:
// "  " for a line in both, "- " for one only approved, "+ " for one only
// observed.
func reviewDiff(approved, observed quarantine.ToolIdentity) []string {
	a, _ := admin.DefinitionLines(approved)
	b, _ := admin.DefinitionLines(observed)
	diff, err := admin.LineDiff(a, b)
	if err != nil {
		return []string{"  (" + err.Error() + " above)"}
	}
	out := make([]string, len(diff))
	for i, d := range diff {
		mark := "  "
		switch d.Op {
		case adminapi.DiffAdd:
			mark = "+ "
		case adminapi.DiffDel:
			mark = "- "
		}
		out[i] = mark + d.Line.Escaped()
	}
	return out
}
