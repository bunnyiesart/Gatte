package quarantine

import (
	"errors"
	"testing"
)

// reviewSetFixture is one backend with a pending tool, a changed tool and
// an approved one, plus another backend's pending tool.
func reviewSetFixture() []Tool {
	pending := NewTool("casemgmt", "list_cases", "p1", ClassSafe, testTime)
	approved := NewTool("casemgmt", "get_case", "a1", ClassSafe, testTime).Approved(testTime)
	changed := NewTool("casemgmt", "close_case", "c1", ClassSafe, testTime).Approved(testTime)
	changed, _ = changed.Observed("c2", ClassSafe, testTime)
	other := NewTool("logsearch", "search", "s1", ClassSafe, testTime)
	return []Tool{pending, approved, changed, other}
}

// A review set is what needs a human, and only that: pending and changed,
// never approved, in tool-name order (design/adr/0043).
func TestReviewSet_IsThePendingAndChangedEntriesInNameOrder(t *testing.T) {
	var mine []Tool
	for _, x := range reviewSetFixture() {
		if x.ServerName == "casemgmt" {
			mine = append(mine, x)
		}
	}
	set := ReviewSet(mine)
	if len(set) != 2 || set[0].ToolName != "close_case" || set[1].ToolName != "list_cases" {
		t.Fatalf("set = %+v, want close_case then list_cases", set)
	}
	if got := ReviewSet(nil); got == nil || len(got) != 0 {
		t.Fatalf("ReviewSet(nil) = %#v, want an empty non-nil slice", got)
	}
}

// The manifest moves with everything the operator was shown: membership,
// every observed fingerprint, status, the baseline of a diff, and the
// backend. It does not move with the order the entries were read in.
func TestManifest_ChangesWithEverythingShownAndNothingElse(t *testing.T) {
	a := NewTool("casemgmt", "a", "h1", ClassSafe, testTime)
	b := NewTool("casemgmt", "b", "h2", ClassSafe, testTime)
	base := Manifest("casemgmt", []Tool{a, b})
	if Manifest("casemgmt", []Tool{b, a}) != base {
		t.Fatal("the manifest depends on the order of the slice")
	}
	moved := b
	moved.ObservedHash = "h3"
	changedB := b
	changedB.Status, changedB.ApprovedHash = StatusChanged, "h0"
	boundary := []Tool{NewTool("casemgmt", "ab", "h", ClassSafe, testTime), NewTool("casemgmt", "c", "h", ClassSafe, testTime)}
	boundary2 := []Tool{NewTool("casemgmt", "a", "h", ClassSafe, testTime), NewTool("casemgmt", "bc", "h", ClassSafe, testTime)}
	for name, other := range map[string]string{
		"a fingerprint moved":   Manifest("casemgmt", []Tool{a, moved}),
		"a tool left the set":   Manifest("casemgmt", []Tool{a}),
		"a tool joined the set": Manifest("casemgmt", []Tool{a, b, NewTool("casemgmt", "c", "h4", ClassSafe, testTime)}),
		"a status or baseline":  Manifest("casemgmt", []Tool{a, changedB}),
		"another backend":       Manifest("logsearch", []Tool{a, b}),
		"the empty set":         Manifest("casemgmt", nil),
	} {
		if other == base {
			t.Errorf("%s: the manifest did not change", name)
		}
	}
	if Manifest("casemgmt", boundary) == Manifest("casemgmt", boundary2) {
		t.Error("two sets whose names differ only at a field boundary share a manifest")
	}
	if base == Hash(ToolIdentity{Name: "a"}) || len(base) != 64 {
		t.Errorf("manifest %q is not a distinct hex sha256", base)
	}
}

// Approving a set approves every entry at the fingerprint it was shown at,
// or nothing: one entry moving refuses the whole set.
func TestApprovedSet_ApprovesAllOrNothing(t *testing.T) {
	tools := reviewSetFixture()
	var mine []Tool
	for _, x := range tools {
		if x.ServerName == "casemgmt" {
			mine = append(mine, x)
		}
	}
	manifest := Manifest("casemgmt", ReviewSet(mine))

	got, err := ApprovedSet("casemgmt", tools, manifest, testTime)
	if err != nil || len(got) != 2 {
		t.Fatalf("ApprovedSet = %+v, %v; want two approvals", got, err)
	}
	for _, a := range got {
		if !a.After.Usable() || a.After.ApprovedHash != a.Before.ObservedHash {
			t.Errorf("%s: %+v -> %+v, want approved at the fingerprint shown", a.Before.ToolName, a.Before, a.After)
		}
		if a.Before.ServerName != "casemgmt" {
			t.Errorf("another backend's tool %+v was approved", a.Before)
		}
	}

	// One observed fingerprint moves after the review: nothing.
	moved := append([]Tool(nil), tools...)
	moved[0].ObservedHash = "p2"
	if got, err := ApprovedSet("casemgmt", moved, manifest, testTime); !errors.Is(err, ErrReviewSetMoved) || got != nil {
		t.Fatalf("after a move: %+v, %v; want ErrReviewSetMoved and nothing", got, err)
	}
	// A tool joins the set after the review: nothing.
	joined := append(append([]Tool(nil), tools...), NewTool("casemgmt", "new_tool", "n1", ClassSafe, testTime))
	if _, err := ApprovedSet("casemgmt", joined, manifest, testTime); !errors.Is(err, ErrReviewSetMoved) {
		t.Fatalf("after a join: %v; want ErrReviewSetMoved", err)
	}
	// Nothing waits: there is nothing an approval could be of.
	if _, err := ApprovedSet("nobody", tools, Manifest("nobody", nil), testTime); !errors.Is(err, ErrReviewSetEmpty) {
		t.Fatalf("empty set: %v; want ErrReviewSetEmpty", err)
	}
	// A corrupt status anywhere refuses.
	bad := append([]Tool(nil), tools...)
	bad[1].Status = "weird"
	if _, err := ApprovedSet("casemgmt", bad, manifest, testTime); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("corrupt status: %v; want ErrInvalidStatus", err)
	}
}
