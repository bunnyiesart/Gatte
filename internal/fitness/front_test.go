package fitness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The Gatte web front is a client of the management API and nothing more
// (design/adr/0040 §6): it holds no rule, so it must not be able to reach
// a store, the configuration file or a CLI command even by accident. What
// it may use from this module is the two packages a front of any other
// repository gets.

const gattewebPkg = modulePath + "/internal/front/gatteweb"

// frontAllowed is everything of this module a front's code may import.
var frontAllowed = map[string]bool{
	modulePath + "/pkg/adminapi": true,
	modulePath + "/pkg/frontkit": true,
}

// isStdlib reports whether an import path is the standard library's: its
// first element has no dot.
func isStdlib(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// TestGatteWebFrontImportsOnlyThePublicPackages checks the front package's
// import graph: its own imports are the standard library, pkg/adminapi and
// pkg/frontkit, and nothing it depends on, through them or otherwise, is a
// store, an adapter, internal/config or internal/admin.
func TestGatteWebFrontImportsOnlyThePublicPackages(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("go", "list", "-C", root, "-f", "{{join .Imports \"\\n\"}}", "./internal/front/gatteweb").CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./internal/front/gatteweb: %v\n%s", err, out)
	}
	imports := strings.Fields(string(out))
	if len(imports) == 0 {
		t.Fatal("go list reported no import at all for the front; the check would prove nothing")
	}
	for _, imp := range imports {
		if !isStdlib(imp) && !frontAllowed[imp] {
			t.Errorf("internal/front/gatteweb imports %s; a front imports only the standard library, pkg/adminapi and pkg/frontkit", imp)
		}
	}
	deps, err := exec.Command("go", "list", "-C", root, "-deps", "./internal/front/gatteweb").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, deps)
	}
	for _, dep := range strings.Fields(string(deps)) {
		for _, banned := range frontBanned {
			if dep == modulePath+"/"+banned || strings.HasPrefix(dep, modulePath+"/"+banned+"/") {
				t.Errorf("internal/front/gatteweb depends on %s: a front reaches the gateway's state only through the management API", dep)
			}
		}
	}
}

// frontBanned is what no front may depend on, directly or not.
var frontBanned = []string{
	"internal/admin", "internal/config", "internal/store", "internal/quarantine", "internal/registry",
	"internal/access", "internal/audit", "internal/idp", "internal/quota", "internal/signer",
	"internal/vault", "internal/gateway", "cmd",
}

// TestUICommandFilesImportOnlyTheFront checks the command side: the files
// of `mcp-gateway ui` in cmd/mcp-gateway, which live in the composition
// root's package, import no store and no service -- only the standard
// library, the front and the two public packages. Everything else of
// package main stays reachable to them by name, so the check is also on
// what they call: no run* command, no opEnv.
func TestUICommandFilesImportOnlyTheFront(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "cmd", "mcp-gateway")
	files, err := filepath.Glob(filepath.Join(dir, "ui*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no ui*.go in %s: %v", dir, err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, spec := range file.Imports {
			imp, _ := strconv.Unquote(spec.Path.Value)
			if !isStdlib(imp) && !frontAllowed[imp] && imp != gattewebPkg {
				t.Errorf("%s imports %s; the ui command reaches the gateway only through the management API", filepath.Base(f), imp)
			}
		}
		full, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(full, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && (strings.HasPrefix(id.Name, "run") && len(id.Name) > 3 && id.Name[3] >= 'A' && id.Name[3] <= 'Z' && id.Name != "runUI" ||
				id.Name == "opEnv" || id.Name == "opRun" || id.Name == "loadConfig" || id.Name == "openStore") {
				t.Errorf("%s: %s uses %s, which is the CLI's direct access to the stores", filepath.Base(f), fset.Position(id.Pos()), id.Name)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no non-test ui*.go file was checked")
	}
}

// TestFrontsServeOnlyThroughFrontkit is 0040 §6: a web front serves through
// kit.Serve and only through it, so none can skip the Host, session, CSRF
// and header checks by opening a listener of its own.
func TestFrontsServeOnlyThroughFrontkit(t *testing.T) {
	root := repoRoot(t)
	var files []string
	for _, pattern := range []string{"internal/front/gatteweb/*.go", "cmd/mcp-gateway/ui*.go"} {
		m, _ := filepath.Glob(filepath.Join(root, pattern))
		for _, f := range m {
			if !strings.HasSuffix(f, "_test.go") {
				files = append(files, f)
			}
		}
	}
	if len(files) == 0 {
		t.Fatal("no front file found")
	}
	servesViaKit := false
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				pkg, ok := x.X.(*ast.Ident)
				if !ok {
					return true
				}
				name := pkg.Name + "." + x.Sel.Name
				switch name {
				case "http.ListenAndServe", "http.ListenAndServeTLS", "http.Serve", "http.ServeTLS", "http.Server",
					"net.Listen", "net.ListenTCP", "net.ListenUnix", "net.FileListener", "httptest.NewServer":
					t.Errorf("%s: %s serves or listens outside frontkit (%s)", filepath.Base(f), fset.Position(x.Pos()), name)
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Serve" {
					if id, ok := sel.X.(*ast.SelectorExpr); ok && id.Sel.Name == "kit" {
						servesViaKit = true
					}
				}
			}
			return true
		})
	}
	if !servesViaKit {
		t.Error("no front file calls kit.Serve: the Gatte web front must serve through frontkit")
	}
}
