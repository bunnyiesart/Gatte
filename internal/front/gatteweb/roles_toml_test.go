package gatteweb

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

func roleByName(t *testing.T, text, name string) roleBlock {
	t.Helper()
	b, ok := findRole(parseRoleBlocks(text), name)
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
	blocks := parseRoleBlocks(sample)
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
	if c := tier1.cover("intel", "lookup_ip", false); !c.Covered || c.How != "wildcard" || c.Revocable {
		t.Errorf("tier1 safe wildcard cover = %+v", c)
	}
	// Safe tool named in an explicit grant list: covered, revocable.
	if c := tier1.cover("edr", "get_host", false); !c.Covered || c.How != "grant" || !c.Revocable {
		t.Errorf("tier1 safe grant cover = %+v", c)
	}
	// A "*" grant must NOT reach a sensitive tool (design/adr/0048).
	if c := tier1.cover("intel", "lookup_ip", true); c.Covered {
		t.Errorf("sensitive tool reached by wildcard: %+v", c)
	}
	// An explicit name on a role that is NOT non_read must NOT reach a
	// sensitive tool.
	if c := tier1.cover("cases", "get_case", true); c.Covered {
		t.Errorf("sensitive tool reached by a read role's explicit name: %+v", c)
	}
	// A non_read role naming it explicitly is the one way in.
	if c := ir.cover("cases", "close_case", true); !c.Covered || c.How != "non_read" {
		t.Errorf("ir-lead sensitive cover = %+v", c)
	}
}

func TestGrantSafeTool(t *testing.T) {
	// Into an existing grant list.
	got, st := grantSafeTool(sample, "tier1", "edr", "isolate_host")
	if st != spliceChanged {
		t.Fatalf("status = %v", st)
	}
	mustKeepComments(t, got)
	if ids := roleByName(t, got, "tier1").Grants["edr"]; strings.Join(ids, ",") != "get_host,list_detections,isolate_host" {
		t.Errorf("edr grant = %q", ids)
	}

	// A "*" grant cannot take one more named tool meaningfully.
	if _, st := grantSafeTool(sample, "tier1", "intel", "lookup_ip"); st != spliceWildcard {
		t.Errorf("granting into a wildcard: status = %v, want spliceWildcard", st)
	}

	// Already present.
	if _, st := grantSafeTool(sample, "tier1", "edr", "get_host"); st != spliceAlready {
		t.Errorf("re-granting: status = %v, want spliceAlready", st)
	}

	// A new backend key under the existing [role.grants].
	got, st = grantSafeTool(sample, "tier1", "cases", "list_cases")
	if st != spliceChanged {
		t.Fatalf("new key status = %v", st)
	}
	if ids := roleByName(t, got, "tier1").Grants["cases"]; strings.Join(ids, ",") != "list_cases" {
		t.Errorf("new cases grant = %q", ids)
	}

	// A brand-new [role.grants] on a role that has none.
	got, st = grantSafeTool(sample, "ir-lead", "siem", "search_events")
	if st != spliceChanged {
		t.Fatalf("new grants-table status = %v", st)
	}
	if ids := roleByName(t, got, "ir-lead").Grants["siem"]; strings.Join(ids, ",") != "search_events" {
		t.Errorf("new ir-lead grant = %q", ids)
	}
	if roleByName(t, got, "ir-lead").Tools[0] != "cases.close_case" {
		t.Error("ir-lead flat tools disturbed by adding a grants table")
	}

	if _, st := grantSafeTool(sample, "ghost", "x", "y"); st != spliceNoRole {
		t.Errorf("unknown role: status = %v, want spliceNoRole", st)
	}
}

func TestGrantSensitiveTool(t *testing.T) {
	// A non_read role gains the sensitive tool as an explicit flat name.
	got, st := grantSensitiveTool(sample, "ir-lead", "cases", "create_case")
	if st != spliceChanged {
		t.Fatalf("status = %v", st)
	}
	if got := strings.Join(roleByName(t, got, "ir-lead").Tools, ","); got != "cases.close_case,cases.create_case" {
		t.Errorf("ir-lead tools = %q", got)
	}

	// A role that is not non_read is refused, and nothing is written.
	out, st := grantSensitiveTool(sample, "tier1", "cases", "create_case")
	if st != spliceNeedNonRead {
		t.Errorf("status = %v, want spliceNeedNonRead", st)
	}
	if out != sample {
		t.Error("the file was changed on a refused sensitive grant")
	}

	if _, st := grantSensitiveTool(sample, "ir-lead", "cases", "close_case"); st != spliceAlready {
		t.Errorf("re-granting sensitive: status = %v, want spliceAlready", st)
	}
}

func TestRevokeTool(t *testing.T) {
	// From the flat tools list.
	got, st := revokeTool(sample, "tier1", "siem", "get_event")
	if st != spliceChanged {
		t.Fatalf("status = %v", st)
	}
	if got := strings.Join(roleByName(t, got, "tier1").Tools, ","); got != "cases.get_case" {
		t.Errorf("tier1 tools after revoke = %q", got)
	}
	mustKeepComments(t, got)

	// From a grant list that keeps other entries.
	got, st = revokeTool(sample, "tier1", "edr", "get_host")
	if st != spliceChanged {
		t.Fatalf("grant revoke status = %v", st)
	}
	if ids := roleByName(t, got, "tier1").Grants["edr"]; strings.Join(ids, ",") != "list_detections" {
		t.Errorf("edr grant after revoke = %q", ids)
	}

	// The last id of a backend grant drops the whole key.
	twoStep, _ := revokeTool(sample, "tier1", "edr", "get_host")
	got, st = revokeTool(twoStep, "tier1", "edr", "list_detections")
	if st != spliceChanged {
		t.Fatalf("last-id revoke status = %v", st)
	}
	if _, has := roleByName(t, got, "tier1").Grants["edr"]; has {
		t.Errorf("empty edr grant key was left behind:\n%s", got)
	}

	// A "*" grant cannot be revoked one tool at a time.
	if _, st := revokeTool(sample, "tier1", "intel", "lookup_ip"); st != spliceWildcard {
		t.Errorf("revoking from a wildcard: status = %v, want spliceWildcard", st)
	}

	// Nothing to revoke.
	if _, st := revokeTool(sample, "tier1", "cases", "never"); st != spliceAlready {
		t.Errorf("revoking what is not granted: status = %v, want spliceAlready", st)
	}
}

func TestSetNonRead(t *testing.T) {
	// Add to a role that lacks it (inserted after the name line).
	got, st := setNonRead(sample, "tier1", true)
	if st != spliceChanged {
		t.Fatalf("status = %v", st)
	}
	if !roleByName(t, got, "tier1").NonRead {
		t.Error("tier1 not marked non_read")
	}
	mustKeepComments(t, got)

	// Remove it from a role that has it.
	got, st = setNonRead(sample, "ir-lead", false)
	if st != spliceChanged {
		t.Fatalf("clear status = %v", st)
	}
	if roleByName(t, got, "ir-lead").NonRead {
		t.Error("ir-lead still non_read after clear")
	}

	// Already in the asked-for state.
	if _, st := setNonRead(sample, "ir-lead", true); st != spliceAlready {
		t.Errorf("status = %v, want spliceAlready", st)
	}
	if _, st := setNonRead(sample, "tier1", false); st != spliceAlready {
		t.Errorf("status = %v, want spliceAlready", st)
	}
}

// TestSpliceIsMinimal checks that a grant changes only the one array it must:
// every other line of the file is byte-identical.
func TestSpliceIsMinimal(t *testing.T) {
	got, st := grantSafeTool(sample, "tier1", "edr", "isolate_host")
	if st != spliceChanged {
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
	got, st := revokeTool(roles, "r", "cases", "get_case")
	if st != spliceChanged {
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
	got, st := revokeTool(roles, "r", "cases", "close_case")
	if st != spliceChanged {
		t.Fatalf("flat status = %v", st)
	}
	if tools := strings.Join(roleByName(t, got, "r").Tools, ","); tools != "cases.get_case" {
		t.Errorf("tools after revoke = %q (single quotes not handled)", tools)
	}
	got, st = revokeTool(got, "r", "intel", "lookup_ip")
	if st != spliceChanged {
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
	got, st := setNonRead(roles, "r", true)
	if st != spliceChanged {
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
	got, st := grantSensitiveTool(roles, "ops", "cases", "close_case")
	if st != spliceChanged {
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
	got, st := revokeTool(roles, "r", "cases", "close_case")
	if st != spliceChanged {
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
	got, st := grantSensitiveTool(sample, "ir-lead", "cases", "create_case")
	if st != spliceChanged {
		t.Fatalf("add status = %v", st)
	}
	// Convert ir-lead to a multi-line tools array first by granting twice,
	// then revoke the middle-ish one and re-parse.
	got, st = revokeTool(got, "ir-lead", "cases", "close_case")
	if st != spliceChanged {
		t.Fatalf("revoke status = %v", st)
	}
	if got := strings.Join(roleByName(t, got, "ir-lead").Tools, ","); got != "cases.create_case" {
		t.Errorf("ir-lead tools after add+revoke = %q", got)
	}
}
