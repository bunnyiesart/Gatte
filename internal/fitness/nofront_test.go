package fitness

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoFrontBuildCarriesNoFront is design/adr/0040 §6: `-tags nofront`
// builds the gateway, the management backend and the CLI without any web
// front -- no page, no session code, no frontkit.
func TestNoFrontBuildCarriesNoFront(t *testing.T) {
	root := repoRoot(t)
	files, err := exec.Command("go", "list", "-C", root, "-tags", "nofront", "-f", `{{join .GoFiles " "}}`, "./cmd/mcp-gateway").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -tags nofront: %v\n%s", err, files)
	}
	got := " " + strings.TrimSpace(string(files)) + " "
	for _, front := range []string{" ui.go ", " ui_people.go ", " ui_connect.go "} {
		if strings.Contains(got, front) {
			t.Errorf("the nofront build compiles%s", front)
		}
	}
	for _, need := range []string{" admin.go ", " serve.go ", " ui_nofront.go "} {
		if !strings.Contains(got, need) {
			t.Errorf("the nofront build lacks%s: %s", need, got)
		}
	}
	deps, err := exec.Command("go", "list", "-C", root, "-tags", "nofront", "-deps", "./cmd/mcp-gateway").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, deps)
	}
	for _, pkg := range strings.Fields(string(deps)) {
		if pkg == modulePath+"/pkg/frontkit" || strings.HasPrefix(pkg, modulePath+"/internal/front") {
			t.Errorf("the nofront build depends on %s", pkg)
		}
	}
}
