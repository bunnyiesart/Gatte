// Operator Console -- "tool show": the definitions behind a quarantine
// entry's fingerprints (design/adr/0032-quarentena-informada-e-eventos.md).

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
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
// approved one when it differs, and the line diff between the two. It
// reports false when the OBSERVED definition cannot be shown -- the one
// an approval would baseline -- after saying why on e.stderr.
func writeReview(e *opEnv, w io.Writer, t quarantine.Tool) bool {
	name := visible.Escape(t.ServerName + "." + t.ToolName)
	fmt.Fprintf(w, "%s\n", name)
	fmt.Fprintf(w, "  status               %s\n", t.Status)
	fmt.Fprintf(w, "  usable               %s\n", map[bool]string{true: "yes", false: "no"}[t.Usable()])
	fmt.Fprintf(w, "  observed fingerprint sha256:%s\n", t.ObservedHash)
	if t.ApprovedHash == "" {
		fmt.Fprintf(w, "  approved fingerprint (none -- not approved)\n")
	} else {
		fmt.Fprintf(w, "  approved fingerprint sha256:%s\n", t.ApprovedHash)
	}

	observed, err := e.tools().Definition(e.ctx(), t.ObservedHash)
	if err != nil {
		fmt.Fprintf(e.stderr, "\nThe observed definition (sha256:%s) cannot be shown: %v\n", t.ObservedHash, err)
		if errors.Is(err, quarantine.ErrDefinitionNotKept) {
			fmt.Fprint(e.stderr, "It was observed before this gateway kept definitions (design/adr/0032). The\nnext discovery -- a refresh or a restart -- stores it; run this again then.\n")
		}
		return false
	}
	obsLines, obsHidden := definitionLines(observed)

	if t.ApprovedHash == "" || t.ApprovedHash == t.ObservedHash {
		label := "OBSERVED"
		if t.ApprovedHash == t.ObservedHash {
			label = "OBSERVED (and APPROVED: the same definition)"
		}
		writeBlock(w, label, t.ObservedHash, obsLines)
		writeHiddenNote(w, obsHidden)
		return true
	}

	approved, err := e.tools().Definition(e.ctx(), t.ApprovedHash)
	switch {
	case errors.Is(err, quarantine.ErrDefinitionNotKept):
		fmt.Fprintf(w, "\nAPPROVED  sha256:%s\n    The approved definition was not kept: it was approved before this gateway\n    stored definitions (design/adr/0032). Only its hash survives, so what\n    changed cannot be shown -- only what is advertised now.\n", t.ApprovedHash)
		writeBlock(w, "OBSERVED", t.ObservedHash, obsLines)
		writeHiddenNote(w, obsHidden)
		return true
	case err != nil:
		fmt.Fprintf(w, "\nAPPROVED  sha256:%s\n    The approved definition cannot be shown: %s\n", t.ApprovedHash, visible.Escape(err.Error()))
		writeBlock(w, "OBSERVED", t.ObservedHash, obsLines)
		writeHiddenNote(w, obsHidden)
		return true
	}
	appLines, _ := definitionLines(approved)
	writeBlock(w, "APPROVED", t.ApprovedHash, appLines)
	writeBlock(w, "OBSERVED", t.ObservedHash, obsLines)
	writeHiddenNote(w, obsHidden)
	fmt.Fprintf(w, "\nDIFF  approved (-) -> observed (+)\n")
	for _, l := range lineDiff(appLines, obsLines) {
		fmt.Fprintf(w, "%s\n", l)
	}
	return true
}

func writeBlock(w io.Writer, label, hash string, lines []string) {
	fmt.Fprintf(w, "\n%s  sha256:%s\n", label, hash)
	for _, l := range lines {
		fmt.Fprintf(w, "    %s\n", l)
	}
}

func writeHiddenNote(w io.Writer, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(w, "\nWARNING: the observed definition carries %d hidden %s, shown above as\n\\u{XXXX}. A model reads them; a terminal would not have shown them. Text\nthat needs to be invisible to be accepted is a reason to refuse it.\n",
		n, opPlural(n, "code point", "code points"))
}

// definitionLines renders a definition as the lines tool show and the diff
// work on, every one escaped, and counts the hidden code points in it.
//
// The description keeps its line breaks, which are its own structure; any
// other control inside a line is escaped. Schemas are re-indented JSON --
// the bytes are what was fingerprinted, the indentation is only for
// reading -- and a schema that is not JSON is shown as it is.
func definitionLines(t quarantine.ToolIdentity) ([]string, int) {
	var lines []string
	hidden := 0
	// Content lines are indented under their label, so no line of a
	// description can pass for "input schema:" or any other label.
	add := func(s string) {
		hidden += visible.Hidden(s)
		lines = append(lines, "  "+visible.Escape(s))
	}
	hidden += visible.Hidden(t.Name)
	lines = append(lines, "name: "+visible.Escape(t.Name))
	lines = append(lines, "description:")
	for _, l := range strings.Split(t.Description, "\n") {
		add(l)
	}
	for _, s := range []struct {
		label string
		raw   []byte
	}{{"input schema:", t.InputSchema}, {"output schema:", t.OutputSchema}} {
		if len(s.raw) == 0 {
			lines = append(lines, s.label+" (none)")
			continue
		}
		lines = append(lines, s.label)
		body := string(s.raw)
		var buf bytes.Buffer
		if json.Indent(&buf, s.raw, "", "  ") == nil {
			body = buf.String()
		}
		for _, l := range strings.Split(body, "\n") {
			add(l)
		}
	}
	return lines, hidden
}

// maxDiffCells bounds the line diff's table. Definitions are small; one
// that is not gets both blocks and no diff rather than a stalled console.
const maxDiffCells = 4_000_000

// lineDiff is a longest-common-subsequence line diff: "  " for a line in
// both, "- " for one only in a, "+ " for one only in b.
func lineDiff(a, b []string) []string {
	if len(a)*len(b) > maxDiffCells {
		return []string{"  (too large for a line diff; compare the two blocks above)"}
	}
	// lcs[i][j] is the LCS length of a[i:] and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, "  "+a[i])
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, "- "+a[i])
			i++
		default:
			out = append(out, "+ "+b[j])
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, "- "+a[i])
	}
	for ; j < len(b); j++ {
		out = append(out, "+ "+b[j])
	}
	return out
}
