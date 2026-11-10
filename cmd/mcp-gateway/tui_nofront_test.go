//go:build nofront

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestTUI_WithoutAFrontSaysSoAndExits is design/adr/0040 §6 for the
// terminal front.
func TestTUI_WithoutAFrontSaysSoAndExits(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"tui"}, &out, &errb); code != exitCannotRun || !strings.Contains(errb.String(), "without") {
		t.Fatalf("tui in a nofront build: exit %d\n%s", code, errb.String())
	}
}
