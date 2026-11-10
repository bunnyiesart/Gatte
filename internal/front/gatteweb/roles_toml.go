package gatteweb

// A minimal, standard-library-only reader and surgical editor for the roles
// file, for the Roles section of the Users tab (design/adr/0054).
//
// The file is a reviewed, versioned TOML whose comments are load-bearing:
// who approved a grant, when to review it, why a role has a tool
// (design/adr/0009). So this never regenerates the file. It reads just
// enough of it to draw the role x tool matrix, and it writes by splicing a
// single entry -- the smallest textual change that adds or removes it --
// leaving every comment and every untouched byte exactly as they were
// (design/adr/0054 §2).
//
// It is hand-rolled rather than using a TOML library because the web front
// imports nothing of this module but pkg/adminapi and pkg/frontkit
// (internal/fitness). It reads only headers, `key = ...` lines and array
// values, which is all the roles grammar (design/adr/0016) needs; a value
// it cannot make sense of is left alone, and the backend's own validation
// (PutRoles) is the authority that refuses a bad edit before it is stored.

import (
	"fmt"
	"strings"
)

// GrantAll is the one grant id that means "every tool this backend
// advertises" (design/adr/0016, mirrors access.GrantAll). A sensitive tool
// is never reached through it (design/adr/0048).
const grantAll = "*"

// roleBlock is one [[role]] as the file holds it: its parsed policy, and the
// line indices a surgical edit needs. Line indices are into the file split on
// "\n"; an absent part is -1.
type roleBlock struct {
	Name    string
	NonRead bool
	Tools   []string            // flat `tools`, namespaced "server.tool", matched exactly
	Grants  map[string][]string // [role.grants]: backend -> ids ("*" = every tool)

	start, end    int // [start,end) lines of the whole [[role]] block
	nameLine      int
	nonReadLine   int
	toolsKeyLine  int
	grantsHdrLine int
	grantsEnd     int // first line after the [role.grants] subtable
	grantsKeyLine map[string]int
}

// parseRoleBlocks reads every [[role]] in text. It tracks only enough state
// to attribute a `key = value` line to a role, to its [role.grants], or to
// neither; anything else (other tables, blank lines, comments) is skipped.
func parseRoleBlocks(text string) []roleBlock {
	lines := strings.Split(text, "\n")
	var blocks []roleBlock
	cur := -1
	inGrants := false
	for i := 0; i < len(lines); i++ {
		t := stripComment(strings.TrimSpace(lines[i]))
		if strings.HasPrefix(t, "[") {
			switch {
			case t == "[[role]]":
				if cur >= 0 {
					blocks[cur].end = i
					if blocks[cur].grantsHdrLine >= 0 && blocks[cur].grantsEnd < 0 {
						blocks[cur].grantsEnd = i
					}
				}
				blocks = append(blocks, roleBlock{
					start: i, end: len(lines), nameLine: -1, nonReadLine: -1,
					toolsKeyLine: -1, grantsHdrLine: -1, grantsEnd: -1,
					Grants: map[string][]string{}, grantsKeyLine: map[string]int{},
				})
				cur = len(blocks) - 1
				inGrants = false
			case cur >= 0 && t == "[role.grants]":
				blocks[cur].grantsHdrLine = i
				inGrants = true
			default:
				// Any other table header ends the current role block.
				if cur >= 0 {
					blocks[cur].end = i
					if blocks[cur].grantsHdrLine >= 0 && blocks[cur].grantsEnd < 0 {
						blocks[cur].grantsEnd = i
					}
				}
				cur = -1
				inGrants = false
			}
			continue
		}
		if cur < 0 {
			continue
		}
		key, afterEq, ok := cutKey(lines[i])
		if !ok {
			continue
		}
		open, closeLine, isArr := arraySpan(lines, i, afterEq)
		end := i
		if isArr {
			end = closeLine
		}
		if inGrants {
			blocks[cur].Grants[key] = parseArray(lines, i, afterEq)
			blocks[cur].grantsKeyLine[key] = i
		} else {
			switch key {
			case "name":
				blocks[cur].Name = scalarString(lines[i][afterEq:])
				blocks[cur].nameLine = i
			case "non_read":
				blocks[cur].NonRead = scalarBool(lines[i][afterEq:])
				blocks[cur].nonReadLine = i
			case "tools":
				blocks[cur].Tools = parseArray(lines, i, afterEq)
				blocks[cur].toolsKeyLine = i
			}
		}
		_ = open
		i = end
	}
	if cur >= 0 && blocks[cur].grantsHdrLine >= 0 && blocks[cur].grantsEnd < 0 {
		blocks[cur].grantsEnd = blocks[cur].end
	}
	return blocks
}

// findRole returns the first block named role.
func findRole(blocks []roleBlock, role string) (roleBlock, bool) {
	for _, b := range blocks {
		if b.Name == role {
			return b, true
		}
	}
	return roleBlock{}, false
}

// coverage of one tool by this role, in the shape the matrix draws
// (design/adr/0048 Decisão 5, mirroring access.Policy):
//
//   - A SAFE tool is covered by any grant that reaches it: a flat name, an
//     explicit grant id, or a "*" grant over its backend.
//   - A SENSITIVE tool is covered ONLY by a role marked non_read that names
//     it explicitly in `tools`. A "*" grant, an explicit grant id, or an
//     explicit name on a role that is not non_read does NOT reach it, so it
//     is not covered -- which is exactly the boundary the gateway enforces on
//     every call.
type coverage struct {
	Covered bool
	How     string // "explicit", "grant", "wildcard", or "non_read"
	// Revocable is false for a "*" grant: a single tool cannot be removed
	// from a whole-backend grant without rewriting it.
	Revocable bool
}

func (b roleBlock) cover(server, tool string, sensitive bool) coverage {
	ns := server + "." + tool
	named := false
	for _, t := range b.Tools {
		if t == ns {
			named = true
			break
		}
	}
	if sensitive {
		if b.NonRead && named {
			return coverage{Covered: true, How: "non_read", Revocable: true}
		}
		return coverage{}
	}
	if named {
		return coverage{Covered: true, How: "explicit", Revocable: true}
	}
	ids := b.Grants[server]
	for _, id := range ids {
		if id == grantAll {
			return coverage{Covered: true, How: "wildcard", Revocable: false}
		}
	}
	for _, id := range ids {
		if id == tool {
			return coverage{Covered: true, How: "grant", Revocable: true}
		}
	}
	return coverage{}
}

// ---- surgical writers. Each returns the new file text and a status; the
// text is handed to PutRoles, which validates it before it is stored.

type spliceStatus int

const (
	spliceChanged     spliceStatus = iota // the file text changed
	spliceNoRole                          // no [[role]] of that name
	spliceAlready                         // already in the asked-for state
	spliceWildcard                        // reached only by a "*" grant; not editable one tool at a time
	spliceNeedNonRead                     // a sensitive grant onto a role that is not non_read
)

// grantSafeTool adds tool id `tool` to the [role.grants] of `server`, the
// act that lets a role call one safe tool. It follows insertGrant's shape:
// into an existing grant list, or a new "server" key under an existing
// [role.grants], or a new [role.grants] at the end of the block.
func grantSafeTool(text, role, server, tool string) (string, spliceStatus) {
	lines := strings.Split(text, "\n")
	blocks := parseRoleBlocks(text)
	b, ok := findRole(blocks, role)
	if !ok {
		return text, spliceNoRole
	}
	for _, id := range b.Grants[server] {
		if id == grantAll {
			return text, spliceWildcard
		}
		if id == tool {
			return text, spliceAlready
		}
	}
	if keyLine, has := b.grantsKeyLine[server]; has {
		_, afterEq, _ := cutKey(lines[keyLine])
		return joinAfter(addElem(lines, keyLine, afterEq, tool)), spliceChanged
	}
	entry := fmt.Sprintf("%q = [%q]", server, tool)
	if b.grantsHdrLine >= 0 {
		out := splice(lines, b.grantsHdrLine+1, nil, []string{entry})
		return joinAfter(out), spliceChanged
	}
	// No [role.grants] yet: add one after the block's last meaningful line.
	at := lastMeaningful(lines, b.start, b.end) + 1
	return joinAfter(splice(lines, at, nil, []string{"[role.grants]", entry})), spliceChanged
}

// grantSensitiveTool adds the namespaced name "server.tool" to the role's
// flat `tools`, the only grant that reaches a sensitive tool -- and only when
// the role is marked non_read (design/adr/0048). The caller checks non_read
// and refuses with spliceNeedNonRead before calling this; it is checked here
// too so the rule has one home.
func grantSensitiveTool(text, role, server, tool string) (string, spliceStatus) {
	lines := strings.Split(text, "\n")
	blocks := parseRoleBlocks(text)
	b, ok := findRole(blocks, role)
	if !ok {
		return text, spliceNoRole
	}
	if !b.NonRead {
		return text, spliceNeedNonRead
	}
	ns := server + "." + tool
	for _, t := range b.Tools {
		if t == ns {
			return text, spliceAlready
		}
	}
	if b.toolsKeyLine >= 0 {
		_, afterEq, _ := cutKey(lines[b.toolsKeyLine])
		return joinAfter(addElem(lines, b.toolsKeyLine, afterEq, ns)), spliceChanged
	}
	// No `tools` line: add one right after the name line, which is always a
	// top-level key before any [role.grants] subtable, so the new flat list
	// is parsed as the role's, not as a grant.
	at := b.nameLine
	if at < 0 {
		at = b.start
	}
	return joinAfter(splice(lines, at+1, nil, []string{fmt.Sprintf("tools = [%q]", ns)})), spliceChanged
}

// revokeTool removes server.tool from the role: from the flat `tools` if it
// is named there, else the id from the [role.grants] of server. A tool
// reached only by a "*" grant cannot be removed one at a time (spliceWildcard).
func revokeTool(text, role, server, tool string) (string, spliceStatus) {
	lines := strings.Split(text, "\n")
	blocks := parseRoleBlocks(text)
	b, ok := findRole(blocks, role)
	if !ok {
		return text, spliceNoRole
	}
	ns := server + "." + tool
	for _, t := range b.Tools {
		if t == ns {
			_, afterEq, _ := cutKey(lines[b.toolsKeyLine])
			out, found, emptied := removeElem(lines, b.toolsKeyLine, afterEq, ns)
			if !found {
				return text, spliceAlready
			}
			if emptied {
				out = dropArrayLine(out, b.toolsKeyLine, afterEq)
			}
			return joinAfter(out), spliceChanged
		}
	}
	ids := b.Grants[server]
	hasWildcard, hasTool := false, false
	for _, id := range ids {
		switch id {
		case grantAll:
			hasWildcard = true
		case tool:
			hasTool = true
		}
	}
	if hasTool {
		keyLine := b.grantsKeyLine[server]
		_, afterEq, _ := cutKey(lines[keyLine])
		out, found, emptied := removeElem(lines, keyLine, afterEq, tool)
		if !found {
			return text, spliceAlready
		}
		if emptied {
			// The last entry of the grant (or flat list) is gone; drop the
			// whole key line rather than leave an empty array behind.
			out = dropArrayLine(out, keyLine, afterEq)
		}
		return joinAfter(out), spliceChanged
	}
	if hasWildcard {
		return text, spliceWildcard
	}
	return text, spliceAlready
}

// setNonRead sets or clears `non_read = true` on the role. It is its own act,
// never a side effect of a grant (design/adr/0048): making a role able to act
// is a decision, not a consequence of naming one tool.
func setNonRead(text, role string, on bool) (string, spliceStatus) {
	lines := strings.Split(text, "\n")
	blocks := parseRoleBlocks(text)
	b, ok := findRole(blocks, role)
	if !ok {
		return text, spliceNoRole
	}
	if on == b.NonRead {
		return text, spliceAlready
	}
	if !on {
		// Remove the non_read line; absence is false.
		if b.nonReadLine < 0 {
			return text, spliceAlready
		}
		return joinAfter(splice(lines, b.nonReadLine, lines[b.nonReadLine:b.nonReadLine+1], nil)), spliceChanged
	}
	if b.nonReadLine >= 0 {
		// Present as false: change the value to true in place, keeping the
		// indent and any trailing comment on that line.
		line := lines[b.nonReadLine]
		_, afterEq, _ := cutKey(line)
		if idx := strings.Index(line[afterEq:], "false"); idx >= 0 {
			lines[b.nonReadLine] = line[:afterEq+idx] + "true" + line[afterEq+idx+len("false"):]
		} else {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[b.nonReadLine] = indent + "non_read = true"
		}
		return strings.Join(lines, "\n"), spliceChanged
	}
	at := b.nameLine
	if at < 0 {
		at = b.start
	}
	return joinAfter(splice(lines, at+1, nil, []string{"non_read = true"})), spliceChanged
}

// ---- line and value helpers (standard library only)

// joinAfter re-joins lines a writer returned.
func joinAfter(lines []string) string { return strings.Join(lines, "\n") }

// splice replaces the run old (which must be the exact slice lines[at:at+len(old)])
// with ins, returning a new slice. With old nil it inserts ins at index at.
func splice(lines []string, at int, old, ins []string) []string {
	out := make([]string, 0, len(lines)-len(old)+len(ins))
	out = append(out, lines[:at]...)
	out = append(out, ins...)
	out = append(out, lines[at+len(old):]...)
	return out
}

// dropArrayLine removes the whole `key = [...]` assignment at keyLine,
// including however many lines its array value spans.
func dropArrayLine(lines []string, keyLine, afterEq int) []string {
	_, closeLine, isArr := arraySpan(lines, keyLine, afterEq)
	end := keyLine
	if isArr {
		end = closeLine
	}
	return splice(lines, keyLine, lines[keyLine:end+1], nil)
}

// lastMeaningful returns the last line index in [start,end) that is neither
// blank nor a comment, or start-1 when there is none.
func lastMeaningful(lines []string, start, end int) int {
	last := start
	for i := start; i < end && i < len(lines); i++ {
		if t := strings.TrimSpace(lines[i]); t != "" && !strings.HasPrefix(t, "#") {
			last = i
		}
	}
	return last
}

// cutKey splits a line at its first top-level '='. It returns the unquoted
// key, the byte index just after '=' on that line, and whether the line is a
// key assignment at all. A '#' or a quote before '=' means it is not.
func cutKey(line string) (string, int, bool) {
	inStr := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
		case '#':
			return "", 0, false
		case '=':
			key := strings.TrimSpace(line[:i])
			key = strings.Trim(key, `"'`)
			if key == "" {
				return "", 0, false
			}
			return key, i + 1, true
		}
	}
	return "", 0, false
}

// arraySpan reports whether the value that starts after afterEq on keyLine is
// an array ('[' first) and, if so, the line index where its matching ']'
// closes, scanning across lines with quote and comment awareness.
func arraySpan(lines []string, keyLine, afterEq int) (open, closeLine int, ok bool) {
	rest := strings.TrimLeft(lines[keyLine][afterEq:], " \t")
	if !strings.HasPrefix(rest, "[") {
		return 0, 0, false
	}
	depth := 0
	inStr := byte(0)
	for i := keyLine; i < len(lines); i++ {
		from := 0
		if i == keyLine {
			from = afterEq
		}
		s := lines[i]
		for j := from; j < len(s); j++ {
			c := s[j]
			if inStr != 0 {
				if c == inStr {
					inStr = 0
				}
				continue
			}
			switch c {
			case '"', '\'':
				inStr = c
			case '#':
				j = len(s) // rest of the line is a comment
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return keyLine, i, true
				}
			}
		}
	}
	return keyLine, len(lines) - 1, true
}

// parseArray returns the string elements of the array value beginning after
// afterEq on keyLine, across however many lines it spans. A non-array value
// yields nil.
func parseArray(lines []string, keyLine, afterEq int) []string {
	_, closeLine, ok := arraySpan(lines, keyLine, afterEq)
	if !ok {
		return nil
	}
	seg := strings.Join(lines[keyLine:closeLine+1], "\n")
	lb := strings.IndexByte(seg, '[')
	rb := matchBracket(seg, lb)
	if lb < 0 || rb < 0 {
		return nil
	}
	return splitElems(seg[lb+1 : rb])
}

// matchBracket returns the index of the ']' that closes the '[' at open, with
// quote and comment awareness, or -1.
func matchBracket(seg string, open int) int {
	depth := 0
	inStr := byte(0)
	for i := open; i < len(seg); i++ {
		c := seg[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
		case '#':
			// Skip to end of this line.
			if nl := strings.IndexByte(seg[i:], '\n'); nl >= 0 {
				i += nl
			} else {
				return -1
			}
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitElems parses the comma-separated, quoted elements inside an array,
// dropping whitespace, comments and empty entries (a trailing comma).
func splitElems(inner string) []string {
	var out []string
	var cur strings.Builder
	inStr := byte(0)
	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" {
			return
		}
		out = append(out, strings.Trim(s, `"'`))
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if inStr != 0 {
			cur.WriteByte(c)
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
			cur.WriteByte(c)
		case '#':
			if nl := strings.IndexByte(inner[i:], '\n'); nl >= 0 {
				i += nl
			} else {
				i = len(inner)
			}
		case ',':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// addElem inserts "elem" into the array at keyLine, right after its last
// element (or just inside '[' when empty), preserving every other byte --
// including any comment before the closing ']'.
func addElem(lines []string, keyLine, afterEq int, elem string) []string {
	_, closeLine, ok := arraySpan(lines, keyLine, afterEq)
	if !ok {
		return lines
	}
	seg := strings.Join(lines[keyLine:closeLine+1], "\n")
	lb := strings.IndexByte(seg, '[')
	rb := matchBracket(seg, lb)
	if lb < 0 || rb < 0 {
		return lines
	}
	if le := lastElemEnd(seg, lb+1, rb); le >= 0 {
		seg = seg[:le] + ", " + quote(elem) + seg[le:]
	} else {
		seg = seg[:lb+1] + quote(elem) + seg[lb+1:]
	}
	return splice(lines, keyLine, lines[keyLine:closeLine+1], strings.Split(seg, "\n"))
}

// removeElem deletes elem (and one adjacent comma) from the array at keyLine,
// preserving every other byte. It matches the element whether it was written
// with double or single quotes, and never matches text inside a comment, so a
// quoted name sitting in a comment is left alone. found reports whether an
// element was actually removed; emptied, that it was the last.
func removeElem(lines []string, keyLine, afterEq int, elem string) (out []string, found, emptied bool) {
	_, closeLine, ok := arraySpan(lines, keyLine, afterEq)
	if !ok {
		return lines, false, false
	}
	seg := strings.Join(lines[keyLine:closeLine+1], "\n")
	lb := strings.IndexByte(seg, '[')
	rb := matchBracket(seg, lb)
	if lb < 0 || rb < 0 {
		return lines, false, false
	}
	p, n := findElem(seg, lb+1, rb, elem)
	if p < 0 {
		return lines, false, false
	}
	end := p + n
	// Remove one adjacent comma: the one after if present, else the one
	// before, so the remaining list stays well-formed.
	if c := nextNonSpace(seg, end, rb); c >= 0 && seg[c] == ',' {
		end = c + 1
	} else if c := prevNonSpace(seg, lb+1, p); c >= 0 && seg[c] == ',' {
		p = c
	}
	seg = seg[:p] + seg[end:]
	out = splice(lines, keyLine, lines[keyLine:closeLine+1], strings.Split(seg, "\n"))
	return out, true, len(splitElems(seg[lb+1:matchBracket(seg, lb)])) == 0
}

// lastElemEnd returns the index just past the last quoted element in
// seg[lo:hi], or -1 when there is none. It skips comments and reads whole
// quoted strings, so it never points inside a comment or a string.
func lastElemEnd(seg string, lo, hi int) int {
	end := -1
	for i := lo; i < hi; i++ {
		switch seg[i] {
		case '#':
			nl := strings.IndexByte(seg[i:hi], '\n')
			if nl < 0 {
				return end
			}
			i += nl
		case '"', '\'':
			q := seg[i]
			j := i + 1
			for j < hi && seg[j] != q {
				j++
			}
			if j >= hi {
				return end
			}
			end = j + 1
			i = j
		}
	}
	return end
}

// findElem returns the start index and length of the quoted element whose
// inner text is elem, in seg[lo:hi], matching either quote style and skipping
// comments; (-1, 0) when it is not there.
func findElem(seg string, lo, hi int, elem string) (start, length int) {
	for i := lo; i < hi; i++ {
		switch seg[i] {
		case '#':
			nl := strings.IndexByte(seg[i:hi], '\n')
			if nl < 0 {
				return -1, 0
			}
			i += nl
		case '"', '\'':
			q := seg[i]
			j := i + 1
			for j < hi && seg[j] != q {
				j++
			}
			if j >= hi {
				return -1, 0
			}
			if seg[i+1:j] == elem {
				return i, j - i + 1
			}
			i = j
		}
	}
	return -1, 0
}

func nextNonSpace(s string, from, limit int) int {
	for i := from; i < limit && i < len(s); i++ {
		if c := s[i]; c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return i
		}
	}
	return -1
}

func prevNonSpace(s string, lo, from int) int {
	for i := from - 1; i >= lo; i-- {
		if c := s[i]; c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return i
		}
	}
	return -1
}

// quote renders one TOML basic string. Role, backend and tool names are
// validated by the backend and carry no quote or backslash, so a bare
// double-quote wrap is exact.
func quote(s string) string { return `"` + s + `"` }

// scalarString reads a double- or single-quoted scalar from a value (the text
// after '='), used for `name`.
func scalarString(val string) string {
	val = stripComment(strings.TrimSpace(val))
	return strings.Trim(val, `"'`)
}

// scalarBool reads a boolean value (the text after '='), used for `non_read`.
func scalarBool(val string) bool {
	return strings.TrimSpace(stripComment(val)) == "true"
}

// stripComment drops a '#' comment outside a string from a single line.
func stripComment(line string) string {
	inStr := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inStr = c
		case '#':
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return line
}
