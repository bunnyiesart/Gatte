package fitness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The terminal front is held to the web front's rule (design/adr/0040 §6):
// a client of the management API and nothing more. Its one difference is
// what draws it: the terminal UI libraries below, allowed for this package
// alone. They are third-party, not this module, so they cannot reach a
// store, the configuration or a command; the banned-dependency check below
// still runs over everything they pull in.

const gattetuiPkg = modulePath + "/internal/front/gattetui"

var tuiLibs = map[string]bool{
	"github.com/charmbracelet/bubbletea": true,
	"github.com/charmbracelet/lipgloss":  true,
}

func TestGatteTUIFrontImportsOnlyThePublicPackages(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("go", "list", "-C", root, "-f", "{{join .Imports \"\\n\"}}", "./internal/front/gattetui").CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./internal/front/gattetui: %v\n%s", err, out)
	}
	imports := strings.Fields(string(out))
	if len(imports) == 0 {
		t.Fatal("go list reported no import at all for the terminal front; the check would prove nothing")
	}
	for _, imp := range imports {
		if !isStdlib(imp) && !frontAllowed[imp] && !tuiLibs[imp] {
			t.Errorf("internal/front/gattetui imports %s; the terminal front imports only the standard library, pkg/adminapi, pkg/frontkit and the terminal UI libraries", imp)
		}
	}
	deps, err := exec.Command("go", "list", "-C", root, "-deps", "./internal/front/gattetui").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, deps)
	}
	for _, dep := range strings.Fields(string(deps)) {
		for _, banned := range frontBanned {
			if dep == modulePath+"/"+banned || strings.HasPrefix(dep, modulePath+"/"+banned+"/") {
				t.Errorf("internal/front/gattetui depends on %s: a front reaches the gateway's state only through the management API", dep)
			}
		}
	}
}

// TestTUICommandFileImportsOnlyTheFront is the command side, as for ui: the
// file of `mcp-gateway tui` imports no store and no service, and calls none
// of the CLI's direct ways into them.
func TestTUICommandFileImportsOnlyTheFront(t *testing.T) {
	f := filepath.Join(repoRoot(t), "cmd", "mcp-gateway", "tui.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, f, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range file.Imports {
		imp, _ := strconv.Unquote(spec.Path.Value)
		if !isStdlib(imp) && !frontAllowed[imp] && imp != gattetuiPkg {
			t.Errorf("tui.go imports %s; the tui command reaches the gateway only through the management API", imp)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && (strings.HasPrefix(id.Name, "run") && len(id.Name) > 3 && id.Name[3] >= 'A' && id.Name[3] <= 'Z' && id.Name != "runTUI" ||
			id.Name == "opEnv" || id.Name == "opRun" || id.Name == "loadConfig" || id.Name == "openStore") {
			t.Errorf("tui.go: %s uses %s, which is the CLI's direct access to the stores", fset.Position(id.Pos()), id.Name)
		}
		return true
	})
}
