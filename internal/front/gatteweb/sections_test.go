package gatteweb

import "testing"

// TestNavForOrderAndGating checks the registry-built navigation: entries come
// out in nav order, the current page is marked, and the managing-only entries
// (Secrets, Roles) appear only with both capabilities.
func TestNavForOrderAndGating(t *testing.T) {
	full := navFor("tools", Capabilities{Manages: true, Root: true})
	var labels []string
	current := ""
	for _, n := range full {
		labels = append(labels, n.Label)
		if n.Current {
			current = n.Label
		}
	}
	want := []string{"Overview", "Tools", "People", "Access", "Audit", "Backends", "Secrets", "Roles", "Quota"}
	if len(labels) != len(want) {
		t.Fatalf("nav labels = %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("nav order = %v, want %v", labels, want)
		}
	}
	if current != "Tools" {
		t.Fatalf("current = %q, want Tools", current)
	}

	// Without the managing capabilities, Secrets and Roles are hidden.
	plain := navFor("overview", Capabilities{})
	for _, n := range plain {
		if n.Label == "Secrets" || n.Label == "Roles" {
			t.Fatalf("%q must not appear without manage + accounts socket", n.Label)
		}
	}
	if len(plain) != len(want)-2 {
		t.Fatalf("plain nav has %d entries, want %d", len(plain), len(want)-2)
	}
}
