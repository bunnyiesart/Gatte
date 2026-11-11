package frontkit

// Role creation, from nothing or from a [[preset]] (design/adr/0062). Like
// the grant writers in roles.go, these splice new lines into the roles file
// and never rewrite what is already there.

import (
	"fmt"
	"slices"
	"strings"
)

// Preset is one [[preset]] of the roles file: a name and the namespaced
// tools ("server.tool") a role created from it is granted.
type Preset struct {
	Name  string
	Tools []string
}

// Presets reads every [[preset]] in text, in file order.
func Presets(text string) []Preset {
	lines := strings.Split(text, "\n")
	var out []Preset
	cur := -1
	for i := 0; i < len(lines); i++ {
		t := stripComment(strings.TrimSpace(lines[i]))
		if strings.HasPrefix(t, "[") {
			cur = -1
			if t == "[[preset]]" {
				out = append(out, Preset{})
				cur = len(out) - 1
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
		switch key {
		case "name":
			out[cur].Name = scalarString(lines[i][afterEq:])
		case "tools":
			out[cur].Tools = parseArray(lines, i, afterEq)
		}
		if _, closeLine, isArr := arraySpan(lines, i, afterEq); isArr {
			i = closeLine
		}
	}
	return out
}

// NewRole adds an empty [[role]] named name and maps each of groups to it in
// [group_to_role]. The role grants nothing until tools are granted to it.
func NewRole(text, name string, groups []string) (string, SpliceStatus) {
	return addRole(text, name, groups, nil)
}

// NewRoleFromPreset adds a [[role]] named roleName granted the safe tools of
// the preset presetName, as [role.grants] entries, and maps groups to it.
//
// A preset never makes a role able to act: the role is not marked non_read,
// and a grant never reaches a sensitive tool (design/adr/0048). So each tool
// sensitive reports true for is left out rather than written as a grant that
// would silently reach nothing, and is returned in skipped for the front to
// show; granting it is a separate, deliberate act (SetNonRead, then
// GrantSensitiveTool). A nil sensitive treats every tool as safe. A preset
// entry that is not "server.tool" is skipped too.
func NewRoleFromPreset(text, roleName, presetName string, groups []string, sensitive func(server, tool string) bool) (out string, skipped []string, st SpliceStatus) {
	var preset *Preset
	for _, p := range Presets(text) {
		if p.Name == presetName {
			preset = &p
			break
		}
	}
	if preset == nil {
		return text, nil, SpliceNoPreset
	}
	var order []string
	grants := map[string][]string{}
	for _, ns := range preset.Tools {
		server, tool, ok := strings.Cut(ns, ".")
		if !ok || server == "" || tool == "" || tool == GrantAll || (sensitive != nil && sensitive(server, tool)) {
			skipped = append(skipped, ns)
			continue
		}
		if _, seen := grants[server]; !seen {
			order = append(order, server)
		}
		grants[server] = append(grants[server], tool)
	}
	var grantLines []string
	for _, server := range order {
		quoted := make([]string, len(grants[server]))
		for i, tool := range grants[server] {
			quoted[i] = quote(tool)
		}
		grantLines = append(grantLines, fmt.Sprintf("%s = [%s]", quote(server), strings.Join(quoted, ", ")))
	}
	out, st = addRole(text, roleName, groups, grantLines)
	if st != SpliceChanged {
		return text, nil, st
	}
	return out, skipped, st
}

// addRole writes the new role block after the last [[role]] (or at the end
// of the file when there is none), then its group mappings.
func addRole(text, name string, groups, grantLines []string) (string, SpliceStatus) {
	if !plainName(name) {
		return text, SpliceBadName
	}
	if _, exists := FindRole(ParseRoles(text), name); exists {
		return text, SpliceRoleExists
	}
	mapped := groupKeys(text)
	for i, g := range groups {
		if !plainName(g) {
			return text, SpliceBadName
		}
		if mapped[g] || slices.Contains(groups[:i], g) {
			return text, SpliceGroupTaken
		}
	}

	block := []string{"[[role]]", "name = " + quote(name)}
	if len(grantLines) > 0 {
		block = append(block, "[role.grants]")
		block = append(block, grantLines...)
	}
	lines := strings.Split(text, "\n")
	if blocks := ParseRoles(text); len(blocks) > 0 {
		last := blocks[len(blocks)-1]
		at := lastMeaningful(lines, last.start, last.end) + 1
		text = joinAfter(splice(lines, at, nil, append([]string{""}, block...)))
	} else {
		text = appendBlock(text, block)
	}

	if len(groups) == 0 {
		return text, SpliceChanged
	}
	entries := make([]string, len(groups))
	for i, g := range groups {
		entries[i] = quote(g) + " = " + quote(name)
	}
	lines = strings.Split(text, "\n")
	hdr, end := groupTable(lines)
	if hdr < 0 {
		return appendBlock(text, append([]string{"[group_to_role]"}, entries...)), SpliceChanged
	}
	at := lastMeaningful(lines, hdr, end) + 1
	return joinAfter(splice(lines, at, nil, entries)), SpliceChanged
}

// appendBlock adds block at the end of text, after one blank line.
func appendBlock(text string, block []string) string {
	body := strings.TrimRight(text, "\n")
	if body != "" {
		body += "\n\n"
	}
	return body + strings.Join(block, "\n") + "\n"
}

// groupTable returns the [group_to_role] header line and the first line
// after the table, or -1 when the file has none.
func groupTable(lines []string) (hdr, end int) {
	hdr = -1
	for i, l := range lines {
		t := stripComment(strings.TrimSpace(l))
		if hdr < 0 {
			if t == "[group_to_role]" {
				hdr = i
			}
			continue
		}
		if strings.HasPrefix(t, "[") {
			return hdr, i
		}
	}
	return hdr, len(lines)
}

// groupKeys is the set of groups [group_to_role] already maps.
func groupKeys(text string) map[string]bool {
	lines := strings.Split(text, "\n")
	keys := map[string]bool{}
	hdr, end := groupTable(lines)
	if hdr < 0 {
		return keys
	}
	for _, l := range lines[hdr+1 : end] {
		if k, _, ok := cutKey(l); ok {
			keys[k] = true
		}
	}
	return keys
}

// plainName reports whether s can be written as quote(s) and read back the
// same: not empty, no edge whitespace, no quote, backslash or control
// character. The backend validates the name itself; this only guards the
// splice from producing a file that no longer parses.
func plainName(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
