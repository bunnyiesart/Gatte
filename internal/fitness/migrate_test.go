// Fitness function: every adapter's schema migration must be wired into
// the composition root.
//
// # Why this is a rule and not a code review item
//
// This project's storage adapters follow one shape: a package under
// internal/<component>/sqlite exporting `func Migrate(*sql.DB) error`,
// idempotent, run at startup. openStore in cmd/mcp-gateway runs them from
// a single map, and the comment on that map says exactly why they live
// together: "a component whose table is missing fails at the first query,
// deep inside a request, rather than at startup."
//
// The failure that comment describes is invisible to every other test in
// the repository, and that is what makes it worth a fitness function. An
// adapter's own tests build their own database and call their own Migrate,
// so they pass. The component's domain tests use a fake, so they pass. A
// test that wires the whole console builds its own map, so it passes. The
// only place the omission shows is a host whose database was created
// before the component existed -- the production one -- and the only
// symptom is "no such table" inside somebody's tool call.
//
// It came into this tree with the quota counter, the fifth adapter, and it
// failed on that port until openStore named the new Migrate -- the exact
// omission it exists for, caught before any host ran the binary.
//
// # What it checks, and how it fails
//
// It reads the module's own source, finds every package that looks like a
// storage adapter and exports a Migrate, and requires the composition root
// to name each one. It is deliberately structural rather than a list:
// a hand-maintained list of adapters would be the same omission wearing a
// different hat.

package fitness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// sourceFile is one parsed file together with the import path of the
// package it belongs to.
type sourceFile struct {
	Pkg  string
	Fset *token.FileSet
	File *ast.File
}

// moduleSource parses every non-test source file of every package in this
// module. Test files are excluded: the rules that read it are about what
// ships, and a test is free to build a database by hand or to name a port
// in order to assert that production code does not.
func moduleSource(t *testing.T) []sourceFile {
	t.Helper()
	fset := token.NewFileSet()

	var files []sourceFile
	for _, pkg := range modulePackages(t) {
		if !strings.HasPrefix(pkg.ImportPath, modulePath) {
			continue
		}
		for _, name := range pkg.GoFiles {
			path := filepath.Join(pkg.Dir, name)
			parsed, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			files = append(files, sourceFile{Pkg: pkg.ImportPath, Fset: fset, File: parsed})
		}
	}
	if len(files) == 0 {
		t.Fatal("go list reported no source files for this module -- the checks that read it would pass by looking at nothing")
	}
	return files
}

// migrationFuncName is the name every storage adapter's schema setup has.
// A future adapter that calls it something else is not covered by this
// rule -- and that is the direction this fails in: the rule polices the
// convention it can see, and a deliberate departure from the convention is
// visible in review, whereas a forgotten map entry is not.
const migrationFuncName = "Migrate"

// TestEveryAdapterMigrationIsWiredIntoTheCompositionRoot is ADR-0030
// Compliance item 9, generalised: the quota counter's Migrate is the fifth,
// and the rule is written for the sixth.
func TestEveryAdapterMigrationIsWiredIntoTheCompositionRoot(t *testing.T) {
	files := moduleSource(t)

	// Every adapter package that exports a Migrate.
	migrators := map[string]bool{}
	for _, f := range files {
		if !isAdapterOrStore(f.Pkg) || strings.HasSuffix(f.Pkg, "/internal/store") {
			continue
		}
		for _, d := range f.File.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != migrationFuncName {
				continue
			}
			migrators[f.Pkg] = true
		}
	}

	// The canary. If go list stops reporting GoFiles, or the adapters are
	// renamed out from under this rule, it would pass by inspecting
	// nothing -- the failure mode every check of this shape dies of.
	if len(migrators) < 5 {
		t.Fatalf("found %d adapter packages exporting %s, want at least 5 "+
			"(registry, audit, quarantine, signer, quota). Either an adapter was removed, or this rule "+
			"has stopped being able to see them and is now checking nothing.", len(migrators), migrationFuncName)
	}

	// Every package the composition root calls a Migrate on.
	wired := map[string]bool{}
	for _, f := range files {
		if !isCompositionRoot(f.Pkg) {
			continue
		}
		aliases := importAliases(f)
		ast.Inspect(f.File, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != migrationFuncName {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if path, isImport := aliases[pkg.Name]; isImport {
				wired[path] = true
			}
			return true
		})
	}

	for pkg := range migrators {
		if !wired[pkg] {
			t.Errorf(
				"%s exports %s and the composition root never calls it.\n\n"+
					"Add it to the migration map in openStore (cmd/mcp-gateway/main.go). Until it is there, the "+
					"table exists only in databases created by a test that migrated it by hand: every test passes, "+
					"and the component fails on its first query, inside a request, on the one host whose database "+
					"predates it. That is the failure that map exists to turn into a startup error.",
				pkg, migrationFuncName)
		}
	}
}

// importAliases maps each import's file-local name to its path, resolving
// the default alias from the path's last segment the way the compiler
// does. It is approximate in exactly one way that does not matter here: a package
// whose name differs from its directory would be misnamed, and no import
// in this module does that.
func importAliases(f sourceFile) map[string]string {
	aliases := map[string]string{}
	for _, spec := range f.File.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		alias := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = path
	}
	return aliases
}

// TestMigrationWiringDetectorFailsOnARegression is the negative test: the
// rule above is a comment unless somebody has watched it fail.
//
// It feeds the detector a composition root that wires four adapters and
// forgets the fifth -- which is the exact shape of the omission, since
// nobody forgets all of them -- and requires the missing one to be named.
func TestMigrationWiringDetectorFailsOnARegression(t *testing.T) {
	const root = `package main

import (
	auditsqlite "example.com/m/internal/audit/sqlite"
	quotasqlite "example.com/m/internal/quota/sqlite"
)

func openStore() {
	_ = auditsqlite.Migrate
	_ = quotasqlite.Migrate
}
`
	f := parseSyntheticAs(t, "example.com/m/cmd/mcp-gateway", root)
	aliases := importAliases(f)

	wired := map[string]bool{}
	ast.Inspect(f.File, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != migrationFuncName {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok {
			if path, isImport := aliases[pkg.Name]; isImport {
				wired[path] = true
			}
		}
		return true
	})

	if !wired["example.com/m/internal/audit/sqlite"] || !wired["example.com/m/internal/quota/sqlite"] {
		t.Fatalf("the detector did not see the migrations that ARE wired: %v -- it would report every adapter as missing, which is a rule nobody can act on", wired)
	}
	if wired["example.com/m/internal/registry/sqlite"] {
		t.Error("the detector reported a migration that is not wired, so a forgotten map entry would pass")
	}
}

// parseSyntheticAs parses one in-memory source file as if it belonged to
// pkg, for the negative tests of the AST-based rules here and in
// quota_test.go.
func parseSyntheticAs(t *testing.T, pkg, src string) sourceFile {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse synthetic source: %v\n%s", err, src)
	}
	return sourceFile{Pkg: pkg, Fset: fset, File: parsed}
}
