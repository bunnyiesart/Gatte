//go:build !nofront

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/front/gattetui"
)

// TestTUIHelpListsEveryCommand: the terminal console's help screen lists
// each command usage() lists, so a new command cannot be missing from it.
func TestTUIHelpListsEveryCommand(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	_, list, ok := strings.Cut(b.String(), "Commands:\n")
	if !ok {
		t.Fatal("usage() has no Commands: section")
	}
	list, _, _ = strings.Cut(list, "\n\n")
	known := map[string]bool{}
	for _, c := range gattetui.Commands {
		known[c.Name] = true
	}
	for _, line := range strings.Split(list, "\n") {
		name := strings.Fields(line)[0]
		if !known[name] {
			t.Errorf("usage() lists %q but the TUI help screen (gattetui.Commands) does not", name)
		}
		delete(known, name)
	}
	for name := range known {
		t.Errorf("the TUI help screen lists %q, which usage() does not", name)
	}
}
