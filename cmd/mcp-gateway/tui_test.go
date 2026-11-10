//go:build !nofront

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestTUI_NoManagementAPIExitsWithTheFix: with no socket to talk to, tui
// draws nothing and says how to start the management API.
func TestTUI_NoManagementAPIExitsWithTheFix(t *testing.T) {
	var out, errb bytes.Buffer
	sock := filepath.Join(t.TempDir(), "absent.sock")
	if code := run([]string{"tui", "-socket", sock}, &out, &errb); code != exitCannotRun || !strings.Contains(errb.String(), "mcp-gateway-admin.socket") {
		t.Fatalf("tui without a management API: exit %d\n%s", code, errb.String())
	}
}

func TestTUI_RefusesArguments(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"tui", "extra"}, &out, &errb); code != exitCannotRun {
		t.Fatalf("tui with an argument: exit %d\n%s", code, errb.String())
	}
}
