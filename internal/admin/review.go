package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Segments splits s, from its raw bytes, into text, hidden code points and
// bytes that are not UTF-8 (design/adr/0040 §3). A literal backslash
// sequence stays text: only the bytes decide.
func Segments(s string) []adminapi.Segment {
	out := []adminapi.Segment{}
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			out = append(out, adminapi.Segment{Kind: adminapi.SegmentText, Text: text.String()})
			text.Reset()
		}
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			flush()
			out = append(out, adminapi.Segment{Kind: adminapi.SegmentInvalidByte, Byte: fmt.Sprintf("%02X", s[i])})
		case visible.Hides(r):
			flush()
			out = append(out, adminapi.Segment{Kind: adminapi.SegmentHidden, CodePoint: fmt.Sprintf("U+%04X", r)})
		default:
			text.WriteString(s[i : i+size])
		}
		i += size
	}
	flush()
	return out
}

// TextOf is a value and its segments.
func TextOf(s string) *adminapi.Text { return &adminapi.Text{Raw: s, Segments: Segments(s)} }

// MultilineSegments is Segments for a field whose line breaks are its own
// structure, such as a tool's description: "\n" and "\r\n" become newline
// segments, and everything else, a lone "\r" included, is segmented as
// Segments does.
func MultilineSegments(s string) []adminapi.Segment {
	out := []adminapi.Segment{}
	for i, line := range strings.Split(s, "\n") {
		if i > 0 {
			out = append(out, adminapi.Segment{Kind: adminapi.SegmentNewline})
		}
		if i < strings.Count(s, "\n") {
			line = strings.TrimSuffix(line, "\r")
		}
		out = append(out, Segments(line)...)
	}
	return out
}

// MultilineTextOf is a multi-line value and its segments.
func MultilineTextOf(s string) *adminapi.Text {
	return &adminapi.Text{Raw: s, Segments: MultilineSegments(s)}
}

// Line is one line of a definition's canonical form: raw text and its
// display depth (0 for a label, 1 for content under one).
type Line struct {
	Depth int
	Text  string
}

// Escaped is the line as `tool show` prints it.
func (l Line) Escaped() string { return strings.Repeat("  ", l.Depth) + visible.Escape(l.Text) }

// DefinitionLines renders a definition as the lines tool show and the diff
// work on, raw, and counts the hidden code points in it as a model reads
// them.
//
// The description keeps its line breaks, which are its own structure.
// Schemas are re-indented JSON -- the bytes are what was fingerprinted, the
// indentation is only for reading -- and a schema that is not JSON is
// shown as it is. Content lines sit one level under their label, so no
// line of a description can pass for "input schema:".
func DefinitionLines(t quarantine.ToolIdentity) ([]Line, int) {
	var lines []Line
	hidden := visible.Hidden(t.Name)
	lines = append(lines, Line{0, "name: " + t.Name}, Line{0, "description:"})
	for _, l := range strings.Split(t.Description, "\n") {
		hidden += visible.Hidden(l)
		lines = append(lines, Line{1, l})
	}
	for _, s := range []struct {
		label string
		raw   []byte
	}{{"input schema:", t.InputSchema}, {"output schema:", t.OutputSchema}} {
		if len(s.raw) == 0 {
			lines = append(lines, Line{0, s.label + " (none)"})
			continue
		}
		lines = append(lines, Line{0, s.label})
		var buf bytes.Buffer
		if json.Indent(&buf, s.raw, "", "  ") != nil {
			for _, l := range strings.Split(string(s.raw), "\n") {
				hidden += visible.Hidden(l)
				lines = append(lines, Line{1, l})
			}
			continue
		}
		// A JSON string can carry a hidden code point as the ASCII escape
		// \u202e, which a screen shows as six plain characters and a model
		// decodes into the override itself. Counting the decoded strings
		// covers both spellings, once each.
		hidden += HiddenInJSON(s.raw)
		for _, l := range strings.Split(buf.String(), "\n") {
			lines = append(lines, Line{1, l})
		}
	}
	return lines, hidden
}

// HiddenInJSON counts the hidden code points in every decoded string --
// keys and values -- of a valid JSON document.
func HiddenInJSON(raw []byte) int {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return visible.Hidden(string(raw))
	}
	var walk func(any) int
	walk = func(v any) int {
		switch x := v.(type) {
		case string:
			return visible.Hidden(x)
		case []any:
			n := 0
			for _, e := range x {
				n += walk(e)
			}
			return n
		case map[string]any:
			n := 0
			for k, e := range x {
				n += visible.Hidden(k) + walk(e)
			}
			return n
		}
		return 0
	}
	return walk(v)
}

// maxDiffCells bounds the line diff's table. Definitions are small; one
// that is not gets both blocks and no diff rather than a stalled console.
const maxDiffCells = 4_000_000

// DiffOp is one line of a line diff.
type DiffOp struct {
	Op   string // adminapi.DiffContext, DiffAdd, DiffDel
	Line Line
}

// ErrDiffTooLarge is returned by LineDiff for definitions too large to
// diff line by line.
var ErrDiffTooLarge = errors.New("too large for a line diff; compare the two blocks")

// LineDiff is a longest-common-subsequence line diff of a to b.
func LineDiff(a, b []Line) ([]DiffOp, error) {
	if len(a)*len(b) > maxDiffCells {
		return nil, ErrDiffTooLarge
	}
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
	var out []DiffOp
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, DiffOp{adminapi.DiffContext, a[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, DiffOp{adminapi.DiffDel, a[i]})
			i++
		default:
			out = append(out, DiffOp{adminapi.DiffAdd, b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, DiffOp{adminapi.DiffDel, a[i]})
	}
	for ; j < len(b); j++ {
		out = append(out, DiffOp{adminapi.DiffAdd, b[j]})
	}
	return out, nil
}

// DiffHunks keeps the changed lines of a diff and ctx unchanged lines
// around each, with a gap where unchanged lines were left out. A label line
// ("input schema:") left as the last context line of a hunk heads nothing
// and is dropped.
func DiffHunks(diff []DiffOp, ctx int) []adminapi.DiffLine {
	keep := make([]bool, len(diff))
	for i, d := range diff {
		if d.Op != adminapi.DiffContext {
			for j := max(0, i-ctx); j <= min(len(diff)-1, i+ctx); j++ {
				keep[j] = true
			}
		}
	}
	type entry struct {
		op  string
		ln  Line
		gap bool
	}
	var out []entry
	gap := false
	for i, d := range diff {
		if !keep[i] {
			gap = true
			continue
		}
		if gap && len(out) > 0 {
			out = append(out, entry{gap: true})
		}
		gap = false
		out = append(out, entry{op: d.Op, ln: d.Line})
	}
	var trimmed []entry
	for i, e := range out {
		last := i == len(out)-1 || out[i+1].gap
		if last && !e.gap && e.op == adminapi.DiffContext && e.ln.Depth == 0 && strings.HasSuffix(strings.TrimSpace(e.ln.Text), ":") {
			continue
		}
		trimmed = append(trimmed, e)
	}
	for len(trimmed) > 0 && trimmed[len(trimmed)-1].gap {
		trimmed = trimmed[:len(trimmed)-1]
	}
	res := []adminapi.DiffLine{}
	for _, e := range trimmed {
		if e.gap {
			res = append(res, adminapi.DiffLine{Op: adminapi.DiffGap, Segments: []adminapi.Segment{}})
			continue
		}
		res = append(res, adminapi.DiffLine{Op: e.op, Depth: e.ln.Depth, Segments: Segments(e.ln.Text)})
	}
	return res
}

// DefinitionReader reads stored definitions by fingerprint.
type DefinitionReader interface {
	Definition(ctx context.Context, hash string) (quarantine.ToolIdentity, error)
}

// WriteReview writes, for t, the `tool show` text: the header, the
// observed definition, the approved one when it differs, and the line diff
// between the two, every untrusted byte escaped. It reports false when the
// OBSERVED definition -- the one an approval would baseline -- cannot be
// shown, after saying why on errw.
func WriteReview(ctx context.Context, defs DefinitionReader, w, errw io.Writer, t quarantine.Tool) bool {
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

	observed, err := defs.Definition(ctx, t.ObservedHash)
	if err != nil {
		fmt.Fprintf(errw, "\nThe observed definition (sha256:%s) cannot be shown: %v\n", t.ObservedHash, err)
		if errors.Is(err, quarantine.ErrDefinitionNotKept) {
			fmt.Fprint(errw, "It was observed before this gateway kept definitions (design/adr/0032). The\nnext discovery -- a refresh or a restart -- stores it; run this again then.\n")
		}
		return false
	}
	obsLines, obsHidden := DefinitionLines(observed)

	if t.ApprovedHash == "" || t.ApprovedHash == t.ObservedHash {
		label := "OBSERVED"
		if t.ApprovedHash == t.ObservedHash {
			label = "OBSERVED (and APPROVED: the same definition)"
		}
		writeBlock(w, label, t.ObservedHash, obsLines)
		writeHiddenNote(w, obsHidden)
		return true
	}

	approved, err := defs.Definition(ctx, t.ApprovedHash)
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
	appLines, _ := DefinitionLines(approved)
	writeBlock(w, "APPROVED", t.ApprovedHash, appLines)
	writeBlock(w, "OBSERVED", t.ObservedHash, obsLines)
	writeHiddenNote(w, obsHidden)
	fmt.Fprintf(w, "\nDIFF  approved (-) -> observed (+)\n")
	diff, err := LineDiff(appLines, obsLines)
	if err != nil {
		fmt.Fprintf(w, "  (%v above)\n", err)
		return true
	}
	for _, d := range diff {
		mark := "  "
		switch d.Op {
		case adminapi.DiffAdd:
			mark = "+ "
		case adminapi.DiffDel:
			mark = "- "
		}
		fmt.Fprintf(w, "%s%s\n", mark, d.Line.Escaped())
	}
	return true
}

func writeBlock(w io.Writer, label, hash string, lines []Line) {
	fmt.Fprintf(w, "\n%s  sha256:%s\n", label, hash)
	for _, l := range lines {
		fmt.Fprintf(w, "    %s\n", l.Escaped())
	}
}

func writeHiddenNote(w io.Writer, n int) {
	if n == 0 {
		return
	}
	fmt.Fprintf(w, "\nWARNING: the observed definition carries %d hidden %s, shown above as\n\\u{XXXX}. A model reads them; a terminal would not have shown them. Text\nthat needs to be invisible to be accepted is a reason to refuse it.\n",
		n, plural(n, "code point", "code points"))
}

// CallableBy names the roles that authorize server.tool, decided by
// access.Role.Allows -- the predicate the request path gates on -- so this
// is never a second opinion. The explanation beside each is best-effort
// prose about the same answer.
func CallableBy(roles []config.Role, server, tool string) []adminapi.RoleCoverage {
	name := server + "." + tool
	out := []adminapi.RoleCoverage{}
	for _, r := range roles {
		if !(access.Role{Name: r.Name, Tools: r.Tools, Grants: r.Grants}).Allows(name) {
			continue
		}
		how, wildcard := grantReason(r, name)
		out = append(out, adminapi.RoleCoverage{Role: r.Name, How: how, Wildcard: wildcard})
	}
	return out
}

// grantReason describes which line of the configuration covers name, and
// whether it does so through a wildcard. "granted" is the honest fallback.
func grantReason(r config.Role, name string) (string, bool) {
	if slices.Contains(r.Tools, name) {
		return fmt.Sprintf("tools = [%q]", name), false
	}
	for backend, ids := range r.Grants {
		rest, ok := strings.CutPrefix(name, backend+".")
		if !ok || rest == "" {
			continue
		}
		if slices.Contains(ids, access.GrantAll) {
			return fmt.Sprintf("[role.grants] %s = [%q]   <- wildcard", backend, access.GrantAll), true
		}
		if slices.Contains(ids, rest) {
			return fmt.Sprintf("[role.grants] %s names %q", backend, rest), false
		}
	}
	return "granted", false
}
