//go:build nofront

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestUI_WithoutAFrontSaysSoAndExits is design/adr/0040 §6.
func TestUI_WithoutAFrontSaysSoAndExits(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"ui"}, &out, &errb); code != exitCannotRun || !strings.Contains(errb.String(), "without") {
		t.Fatalf("ui in a nofront build: exit %d\n%s", code, errb.String())
	}
}
