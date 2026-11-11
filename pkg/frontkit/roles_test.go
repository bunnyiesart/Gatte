package frontkit

import (
	"strings"
	"testing"
)

// sample is a roles file with the comments design/adr/0009 keeps: a file
// header, an approver note on a role, and a note on a grant. Every splice
// test asserts these survive.
const sample = `# roles for the lab
[[role]]
name = "tier1"            # approved by alice 2026-01
tools = [
  "siem.get_event",
  "cases.get_case",
]
  [role.grants]
  intel = ["*"]           # read-only lookups
  edr   = ["get_host", "list_detections"]

[[role]]
name = "ir-lead"
non_read = true
tools = ["cases.close_case"]

[group_to_role]
"blue-tier1" = "tier1"
"blue-ir"    = "ir-lead"
`

func roleByName(t *testing.T, text, name string) RoleBlock {
	t.Helper()
	b, ok := FindRole(ParseRoles(text), name)
	if !ok {
		t.Fatalf("role %q not found in:\n%s", name, text)
	}
	return b
}

func mustKeepComments(t *testing.T, text string) {
	t.Helper()
	for _, c := range []string{"# roles for the lab", "# approved by alice 2026-01", "# read-only lookups"} {
		if !strings.Contains(text, c) {
			t.Errorf("comment %q was lost (the file must never be regenerated):\n%s", c, text)
		}
	}
}

func TestParseRoleBlocks(t *testing.T) {
	blocks := ParseRoles(sample)
	if len(blocks) != 2 {
		t.Fatalf("got %d roles, want 2", len(blocks))
	}
	tier1 := roleByName(t, sample, "tier1")
	if tier1.NonRead {
		t.Error("tier1 NonRead = true, want false")
	}
	if got := strings.Join(tier1.Tools, ","); got != "siem.get_event,cases.get_case" {
		t.Errorf("tier1 tools = %q", got)
	}
	if got := strings.Join(tier1.Grants["intel"], ","); got != "*" {
		t.Errorf("tier1 intel grant = %q", got)
	}
	if got := strings.Join(tier1.Grants["edr"], ","); got != "get_host,list_detections" {
		t.Errorf("tier1 edr grant = %q", got)
	}
	ir := roleByName(t, sample, "ir-lead")
	if !ir.NonRead {
		t.Error("ir-lead NonRead = false, want true")
	}
	if got := strings.Join(ir.Tools, ","); got != "cases.close_case" {
		t.Errorf("ir-lead tools = %q", got)
	}
}

func TestCoverageClassBoundary(t *testing.T) {
	tier1 := roleByName(t, sample, "tier1")
	ir := roleByName(t, sample, "ir-lead")

	// Safe tool reached by a "*" grant: covered, as a wildcard.
	if c := tier1.Cover("intel", "lookup_ip", false); !c.Covered || c.How != "wildcard" || c.Revocable {
		t.Errorf("tier1 safe wildcard cover = %+v", c)
	}
	// Safe tool named in an explicit grant list: covered, revocable.
	if c := tier1.Cover("edr", "get_host", false); !c.Covered || c.How != "grant" || !c.Revocable {
		t.Errorf("tier1 safe grant cover = %+v", c)
	}
	// A "*" grant must NOT reach a sensitive tool (design/adr/0048).
	if c := tier1.Cover("intel", "lookup_ip", true); c.Covered {
		t.Errorf("sensitive tool reached by wildcard: %+v", c)
	}
	// An explicit name on a role that is NOT non_read must NOT reach a
	// sensitive tool.
	if c := tier1.Cover("cases", "get_case", true); c.Covered {
		t.Errorf("sensitive tool reached by a read role's explicit name: %+v", c)
	}
	// A non_read role naming it explicitly is the one way in.
	if c := ir.Cover("cases", "close_case", true); !c.Covered || c.How != "non_read" {
		t.Errorf("ir-lead sensitive cover = %+v", c)
	}
}

func TestGrantSafeTool(t *testing.T) {
	// Into an existing grant list.
	got, st := GrantSafeTool(sample, "tier1", "edr", "isolate_host")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	mustKeepComments(t, got)
	if ids := roleByName(t, got, "tier1").Grants["edr"]; strings.Join(ids, ",") != "get_host,list_detections,isolate_host" {
		t.Errorf("edr grant = %q", ids)
	}

	// A "*" grant cannot take one more named tool meaningfully.
	if _, st := GrantSafeTool(sample, "tier1", "intel", "lookup_ip"); st != SpliceWildcard {
		t.Errorf("granting into a wildcard: status = %v, want SpliceWildcard", st)
	}

	// Already present.
	if _, st := GrantSafeTool(sample, "tier1", "edr", "get_host"); st != SpliceAlready {
		t.Errorf("re-granting: status = %v, want SpliceAlready", st)
	}

	// A new backend key under the existing [role.grants].
	got, st = GrantSafeTool(sample, "tier1", "cases", "list_cases")
	if st != SpliceChanged {
		t.Fatalf("new key status = %v", st)
	}
	if ids := roleByName(t, got, "tier1").Grants["cases"]; strings.Join(ids, ",") != "list_cases" {
		t.Errorf("new cases grant = %q", ids)
	}

	// A brand-new [role.grants] on a role that has none.
	got, st = GrantSafeTool(sample, "ir-lead", "siem", "search_events")
	if st != SpliceChanged {
		t.Fatalf("new grants-table status = %v", st)
	}
	if ids := roleByName(t, got, "ir-lead").Grants["siem"]; strings.Join(ids, ",") != "search_events" {
		t.Errorf("new ir-lead grant = %q", ids)
	}
	if roleByName(t, got, "ir-lead").Tools[0] != "cases.close_case" {
		t.Error("ir-lead flat tools disturbed by adding a grants table")
	}

	if _, st := GrantSafeTool(sample, "ghost", "x", "y"); st != SpliceNoRole {
		t.Errorf("unknown role: status = %v, want SpliceNoRole", st)
	}
}

func TestGrantSensitiveTool(t *testing.T) {
	// A non_read role gains the sensitive tool as an explicit flat name.
	got, st := GrantSensitiveTool(sample, "ir-lead", "cases", "create_case")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if got := strings.Join(roleByName(t, got, "ir-lead").Tools, ","); got != "cases.close_case,cases.create_case" {
		t.Errorf("ir-lead tools = %q", got)
	}

	// A role that is not non_read is refused, and nothing is written.
	out, st := GrantSensitiveTool(sample, "tier1", "cases", "create_case")
	if st != SpliceNeedNonRead {
		t.Errorf("status = %v, want SpliceNeedNonRead", st)
	}
	if out != sample {
		t.Error("the file was changed on a refused sensitive grant")
	}

	if _, st := GrantSensitiveTool(sample, "ir-lead", "cases", "close_case"); st != SpliceAlready {
		t.Errorf("re-granting sensitive: status = %v, want SpliceAlready", st)
	}
}

func TestRevokeTool(t *testing.T) {
	// From the flat tools list.
	got, st := RevokeTool(sample, "tier1", "siem", "get_event")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if got := strings.Join(roleByName(t, got, "tier1").Tools, ","); got != "cases.get_case" {
		t.Errorf("tier1 tools after revoke = %q", got)
	}
	mustKeepComments(t, got)

	// From a grant list that keeps other entries.
	got, st = RevokeTool(sample, "tier1", "edr", "get_host")
	if st != SpliceChanged {
		t.Fatalf("grant revoke status = %v", st)
	}
	if ids := roleByName(t, got, "tier1").Grants["edr"]; strings.Join(ids, ",") != "list_detections" {
		t.Errorf("edr grant after revoke = %q", ids)
	}

	// The last id of a backend grant drops the whole key.
	twoStep, _ := RevokeTool(sample, "tier1", "edr", "get_host")
	got, st = RevokeTool(twoStep, "tier1", "edr", "list_detections")
	if st != SpliceChanged {
		t.Fatalf("last-id revoke status = %v", st)
	}
	if _, has := roleByName(t, got, "tier1").Grants["edr"]; has {
		t.Errorf("empty edr grant key was left behind:\n%s", got)
	}

	// A "*" grant cannot be revoked one tool at a time.
	if _, st := RevokeTool(sample, "tier1", "intel", "lookup_ip"); st != SpliceWildcard {
		t.Errorf("revoking from a wildcard: status = %v, want SpliceWildcard", st)
	}

	// Nothing to revoke.
	if _, st := RevokeTool(sample, "tier1", "cases", "never"); st != SpliceAlready {
		t.Errorf("revoking what is not granted: status = %v, want SpliceAlready", st)
	}
}

func TestSetNonRead(t *testing.T) {
	// Add to a role that lacks it (inserted after the name line).
	got, st := SetNonRead(sample, "tier1", true)
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if !roleByName(t, got, "tier1").NonRead {
		t.Error("tier1 not marked non_read")
	}
	mustKeepComments(t, got)

	// Remove it from a role that has it.
	got, st = SetNonRead(sample, "ir-lead", false)
	if st != SpliceChanged {
		t.Fatalf("clear status = %v", st)
	}
	if roleByName(t, got, "ir-lead").NonRead {
		t.Error("ir-lead still non_read after clear")
	}

	// Already in the asked-for state.
	if _, st := SetNonRead(sample, "ir-lead", true); st != SpliceAlready {
		t.Errorf("status = %v, want SpliceAlready", st)
	}
	if _, st := SetNonRead(sample, "tier1", false); st != SpliceAlready {
		t.Errorf("status = %v, want SpliceAlready", st)
	}
}

// TestSpliceIsMinimal checks that a grant changes only the one array it must:
// every other line of the file is byte-identical.
func TestSpliceIsMinimal(t *testing.T) {
	got, st := GrantSafeTool(sample, "tier1", "edr", "isolate_host")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	before := strings.Split(sample, "\n")
	after := strings.Split(got, "\n")
	if len(before) != len(after) {
		t.Fatalf("line count changed %d -> %d; an in-list grant edits one line", len(before), len(after))
	}
	diffs := 0
	for i := range before {
		if before[i] != after[i] {
			diffs++
		}
	}
	if diffs != 1 {
		t.Errorf("%d lines changed, want 1:\n%s", diffs, got)
	}
}

// TestRevokeIgnoresACommentedName checks that a tool name sitting in a comment
// inside the array is not mistaken for the element to remove.
func TestRevokeIgnoresACommentedName(t *testing.T) {
	const roles = `[[role]]
name = "r"
tools = [
  # "cases.get_case" was removed last week
  "cases.get_case",
  "cases.close_case",
]
`
	got, st := RevokeTool(roles, "r", "cases", "get_case")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if !strings.Contains(got, "was removed last week") {
		t.Errorf("the comment was corrupted:\n%s", got)
	}
	if tools := strings.Join(roleByName(t, got, "r").Tools, ","); tools != "cases.close_case" {
		t.Errorf("tools after revoke = %q", tools)
	}
}

// TestRevokeSingleQuoted checks that an element written with TOML literal
// (single) quotes is actually removed, not reported removed while left in place.
func TestRevokeSingleQuoted(t *testing.T) {
	const roles = `[[role]]
name = "r"
tools = ['cases.close_case', 'cases.get_case']
  [role.grants]
  intel = ['lookup_ip', 'lookup_hash']
`
	got, st := RevokeTool(roles, "r", "cases", "close_case")
	if st != SpliceChanged {
		t.Fatalf("flat status = %v", st)
	}
	if tools := strings.Join(roleByName(t, got, "r").Tools, ","); tools != "cases.get_case" {
		t.Errorf("tools after revoke = %q (single quotes not handled)", tools)
	}
	got, st = RevokeTool(got, "r", "intel", "lookup_ip")
	if st != SpliceChanged {
		t.Fatalf("grant status = %v", st)
	}
	if ids := strings.Join(roleByName(t, got, "r").Grants["intel"], ","); ids != "lookup_hash" {
		t.Errorf("intel grant after revoke = %q", ids)
	}
}

// TestSetNonReadKeepsTheComment checks that flipping a present non_read=false to
// true keeps a trailing approver comment on that line.
func TestSetNonReadKeepsTheComment(t *testing.T) {
	const roles = `[[role]]
name = "r"
non_read = false   # read-only, approved by alice 2026-10
`
	got, st := SetNonRead(roles, "r", true)
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if !roleByName(t, got, "r").NonRead {
		t.Error("role not marked non_read")
	}
	if !strings.Contains(got, "# read-only, approved by alice 2026-10") {
		t.Errorf("the approver comment was dropped:\n%s", got)
	}
}

// TestGrantSensitiveStaysTopLevel checks the new tools line lands as a
// top-level role key, before the [role.grants] subtable, on a role that has
// grants but no flat tools.
func TestGrantSensitiveStaysTopLevel(t *testing.T) {
	const roles = `[[role]]
name = "ops"
non_read = true
  [role.grants]
  intel = ["*"]
`
	got, st := GrantSensitiveTool(roles, "ops", "cases", "close_case")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	b := roleByName(t, got, "ops")
	if tools := strings.Join(b.Tools, ","); tools != "cases.close_case" {
		t.Errorf("ops flat tools = %q (new line parsed as a grant?)\n%s", tools, got)
	}
	if ids := strings.Join(b.Grants["intel"], ","); ids != "*" {
		t.Errorf("ops intel grant disturbed = %q", ids)
	}
	if !b.NonRead {
		t.Error("ops lost its non_read marking")
	}
}

// TestRevokeLastFlatToolDropsTheLine checks an emptied flat tools list is
// removed, matching the grants path.
func TestRevokeLastFlatToolDropsTheLine(t *testing.T) {
	const roles = `[[role]]
name = "r"
non_read = true
tools = ["cases.close_case"]
`
	got, st := RevokeTool(roles, "r", "cases", "close_case")
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if strings.Contains(got, "tools") {
		t.Errorf("empty tools line left behind:\n%s", got)
	}
	if len(roleByName(t, got, "r").Tools) != 0 {
		t.Error("tools not empty after revoke")
	}
}

// TestMultiLineArrayEdit adds and removes within a multi-line array (the flat
// tools list), the hardest shape to splice.
func TestMultiLineArrayEdit(t *testing.T) {
	got, st := GrantSensitiveTool(sample, "ir-lead", "cases", "create_case")
	if st != SpliceChanged {
		t.Fatalf("add status = %v", st)
	}
	// Convert ir-lead to a multi-line tools array first by granting twice,
	// then revoke the middle-ish one and re-parse.
	got, st = RevokeTool(got, "ir-lead", "cases", "close_case")
	if st != SpliceChanged {
		t.Fatalf("revoke status = %v", st)
	}
	if got := strings.Join(roleByName(t, got, "ir-lead").Tools, ","); got != "cases.create_case" {
		t.Errorf("ir-lead tools after add+revoke = %q", got)
	}
}

const withPresets = sample + `
# Templates for "New role from preset".
[[preset]]
name  = "Blue team analyst"
tools = [
  "siem.get_event",   # triage
  "cases.get_case",
  "cases.close_case", # sensitive: never granted by a preset
]

[[preset]]
name  = "Red team analyst"
tools = ["intel.lookup_ip"]
`

func TestPresetsAreRead(t *testing.T) {
	ps := Presets(withPresets)
	if len(ps) != 2 || ps[0].Name != "Blue team analyst" || ps[1].Name != "Red team analyst" {
		t.Fatalf("presets = %+v", ps)
	}
	if got := strings.Join(ps[0].Tools, ","); got != "siem.get_event,cases.get_case,cases.close_case" {
		t.Errorf("tools = %q", got)
	}
	if len(ParseRoles(withPresets)) != 2 {
		t.Error("a [[preset]] was read as part of a role")
	}
}

func TestNewRoleAddsAnEmptyRoleAndItsGroups(t *testing.T) {
	out, st := NewRole(sample, "hunt", []string{"blue-hunt", "blue-hunt-nb"})
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	mustKeepComments(t, out)
	b := roleByName(t, out, "hunt")
	if b.NonRead || len(b.Tools) != 0 || len(b.Grants) != 0 {
		t.Errorf("new role is not empty: %+v", b)
	}
	if g := groupKeys(out); !g["blue-hunt"] || !g["blue-hunt-nb"] || !g["blue-tier1"] {
		t.Errorf("groups = %v\n%s", g, out)
	}
	if !strings.Contains(out, `"blue-hunt" = "hunt"`) {
		t.Errorf("mapping not written:\n%s", out)
	}
	// The other roles are untouched.
	if roleByName(t, out, "ir-lead").NonRead != true {
		t.Error("ir-lead changed")
	}
}

func TestNewRoleWithoutGroupTableOrRoles(t *testing.T) {
	out, st := NewRole("# empty\n", "hunt", []string{"g"})
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	want := "# empty\n\n[[role]]\nname = \"hunt\"\n\n[group_to_role]\n\"g\" = \"hunt\"\n"
	if out != want {
		t.Errorf("got:\n%q\nwant:\n%q", out, want)
	}
}

func TestNewRoleRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		role   string
		groups []string
		want   SpliceStatus
	}{
		"exists":          {"tier1", nil, SpliceRoleExists},
		"empty":           {"", nil, SpliceBadName},
		"edge whitespace": {"hunt ", nil, SpliceBadName},
		"quote":           {`hu"nt`, nil, SpliceBadName},
		"group mapped":    {"hunt", []string{"blue-ir"}, SpliceGroupTaken},
		"group twice":     {"hunt", []string{"g", "g"}, SpliceGroupTaken},
		"bad group":       {"hunt", []string{"g\n"}, SpliceBadName},
	} {
		t.Run(name, func(t *testing.T) {
			out, st := NewRole(sample, tc.role, tc.groups)
			if st != tc.want || out != sample {
				t.Errorf("status = %v, want %v; text changed: %v", st, tc.want, out != sample)
			}
		})
	}
}

func TestNewRoleFromPresetGrantsSafeToolsAndSkipsSensitive(t *testing.T) {
	sensitive := func(server, tool string) bool { return server == "cases" && tool == "close_case" }
	out, skipped, st := NewRoleFromPreset(withPresets, "analyst", "Blue team analyst", []string{"blue-analyst"}, sensitive)
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	if strings.Join(skipped, ",") != "cases.close_case" {
		t.Errorf("skipped = %v", skipped)
	}
	mustKeepComments(t, out)
	b := roleByName(t, out, "analyst")
	if b.NonRead {
		t.Error("a preset marked the role non_read")
	}
	if !b.Cover("siem", "get_event", false).Covered || !b.Cover("cases", "get_case", false).Covered {
		t.Errorf("safe tools not granted: %+v\n%s", b.Grants, out)
	}
	if b.Cover("cases", "close_case", true).Covered || strings.Contains(strings.Join(b.Grants["cases"], ","), "close_case") {
		t.Errorf("sensitive tool was written: %+v", b.Grants)
	}
	// The new role sits after the last role, before the group table, and the
	// presets are still there for the next role.
	if strings.Index(out, `name = "analyst"`) > strings.Index(out, "[group_to_role]") {
		t.Errorf("role written after [group_to_role]:\n%s", out)
	}
	if len(Presets(out)) != 2 {
		t.Error("presets lost")
	}
}

func TestNewRoleFromPresetUnknownPreset(t *testing.T) {
	out, skipped, st := NewRoleFromPreset(withPresets, "x", "Purple team", nil, nil)
	if st != SpliceNoPreset || out != withPresets || skipped != nil {
		t.Errorf("status = %v, skipped %v", st, skipped)
	}
	if _, _, st := NewRoleFromPreset(withPresets, "tier1", "Red team analyst", nil, nil); st != SpliceRoleExists {
		t.Errorf("existing role: status = %v", st)
	}
}

// A new role goes after the previous role's trailing comments (they are
// that role's) and before the comments sitting on the next header.
func TestNewRoleKeepsCommentsWithTheirOwners(t *testing.T) {
	text := `[[role]]
name = "a"
tools = ["siem.get_event"]
# a: reviewed 2026-10 by alice

# Groups: left is the claim value.
[group_to_role]
"g-a" = "a"
`
	out, st := NewRole(text, "b", nil)
	if st != SpliceChanged {
		t.Fatalf("status = %v", st)
	}
	want := `[[role]]
name = "a"
tools = ["siem.get_event"]
# a: reviewed 2026-10 by alice

[[role]]
name = "b"

# Groups: left is the claim value.
[group_to_role]
"g-a" = "a"
`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestNewRoleAtTheEndKeepsTrailingComments(t *testing.T) {
	text := "[[role]]\nname = \"a\"\n# a: reviewed\n"
	out, st := NewRole(text, "b", nil)
	if st != SpliceChanged || out != "[[role]]\nname = \"a\"\n# a: reviewed\n\n[[role]]\nname = \"b\"\n" {
		t.Errorf("status %v, got:\n%q", st, out)
	}
}

func TestNewRoleFromPresetWithNothingSafeWritesNothing(t *testing.T) {
	all := func(string, string) bool { return true }
	out, skipped, st := NewRoleFromPreset(withPresets, "x", "Red team analyst", nil, all)
	if st != SpliceNothingSafe || out != withPresets || strings.Join(skipped, ",") != "intel.lookup_ip" {
		t.Errorf("status %v, skipped %v, changed %v", st, skipped, out != withPresets)
	}
}

// Forms TOML reads but this editor does not follow are refused, not edited.
func TestNewRoleRefusesLayoutsItCannotFollow(t *testing.T) {
	role := "[[role]]\nname = \"a\"\n"
	for name, text := range map[string]string{
		"spaced group header":  role + "[ group_to_role ]\n\"g\" = \"a\"\n",
		"quoted group header":  role + "[\"group_to_role\"]\n\"g\" = \"a\"\n",
		"inline group table":   "group_to_role = { \"g\" = \"a\" }\n" + role,
		"dotted top-level key": "group_to_role.g = \"a\"\n" + role,
		"spaced preset header": role + "[[ preset ]]\nname = \"p\"\ntools = [\"a.b\"]\n",
		"spaced role header":   "[[ role ]]\nname = \"a\"\n",
		"dotted group key":     role + "[group_to_role]\nsoc.g = \"a\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if out, st := NewRole(text, "b", []string{"g2"}); st != SpliceUnsupported || out != text {
				t.Errorf("status = %v, text changed: %v", st, out != text)
			}
		})
	}
	// Quoted keys inside the table are read fine.
	if _, st := NewRole(role+"[group_to_role]\n\"soc.g\" = \"a\"\n'x' = \"a\"\n", "b", []string{"g2"}); st != SpliceChanged {
		t.Errorf("quoted group keys: status = %v", st)
	}
}
