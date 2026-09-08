// Package fitness holds architectural fitness functions
// (docs/context/07-fitness-functions.md): automated,
// continuously-run checks for structural rules that a code review would
// otherwise have to catch by hand, and easily miss.
//
// This is not a domain test -- it requires no knowledge of what a
// registry entry or an audit record means, only of the import graph. Per
// 07-fitness-functions.md §2's decisive question ("does this test require
// domain knowledge to run?"), that makes it a fitness function, not a unit
// test, even though it lives under go test like one.
package fitness

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	// Blank-imported so this test binary depends on the real source of
	// every package the fitness functions below inspect, rather than
	// only on go list's runtime output.
	//
	// This reduces, but does NOT eliminate, a real `go test` caching
	// gap confirmed by hand while writing this file: because the actual
	// check runs by shelling out to `go list -json` (see modulePackages
	// below), `go test`'s result cache can and did return a stale PASS
	// for a run where a real violation had just been added to
	// internal/registry -- reproducibly, even with these blank imports
	// in place, and even though `go list -json` itself reported the
	// violation correctly and instantly when run by hand. Only
	// `go clean -testcache` or `-count=1` reliably forced a fresh run.
	// Root cause not fully isolated; treat as a known sharp edge of
	// "test shells out to go list" rather than something fixable from
	// inside the test. `make test` (see Makefile) always passes
	// `-count=1` for exactly this reason -- do not drop that flag, and
	// do not trust a bare `go test ./...` result for this package.
	_ "github.com/bunnyiesart/Gatte/internal/audit"
	_ "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	_ "github.com/bunnyiesart/Gatte/internal/registry"
	_ "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	_ "github.com/bunnyiesart/Gatte/internal/store"
)

// sqlPackages are the direct imports that mean "this package talks to the
// database." A package importing any of these is expected to be an
// adapter (its import path ends in "/sqlite") or internal/store, which
// exists specifically to own the shared *sql.DB connection.
var sqlPackages = []string{
	"database/sql",
	"modernc.org/sqlite",
}

type goPackage struct {
	ImportPath string
	Imports    []string
	Deps       []string
}

// moduleRoot returns the directory containing this module's go.mod, so
// `go list ./...` below enumerates every package in the module regardless
// of which directory the test binary happens to run from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatal("go env GOMOD returned no module -- is this running inside the mcp-gateway module?")
	}
	return strings.TrimSuffix(gomod, "/go.mod")
}

func modulePackages(t *testing.T) []goPackage {
	t.Helper()
	root := moduleRoot(t)

	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -json ./...: %v", err)
	}

	var pkgs []goPackage
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p goPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list -json ./... returned no packages")
	}
	return pkgs
}

// isAdapterOrStore reports whether importPath is allowed to talk to the
// database directly: either it is internal/store (the one package whose
// job is exactly that), or its path ends in "/sqlite" -- this project's
// convention for "this is the adapter half of a ports & adapters pair"
// (internal/registry/sqlite, internal/audit/sqlite, and, when they exist,
// internal/quarantine/sqlite and any other component's own adapter).
func isAdapterOrStore(importPath string) bool {
	return strings.HasSuffix(importPath, "/internal/store") ||
		strings.HasSuffix(importPath, "/sqlite")
}

// TestOnlyAdaptersTouchTheDatabase is the fitness function WORKFLOW.md's
// Phase 1 names explicitly: "a dependency-direction check that nothing
// outside these two components touches their tables directly." It is
// written now, before anything violates it, per that same section's
// instruction -- it is cheaper to write before there is code to retrofit
// against than after.
//
// The rule: within this module, only internal/store and packages whose
// import path ends in "/sqlite" may directly import database/sql or the
// sqlite driver. Every domain package -- internal/registry, internal/audit,
// and any future component's domain package -- must reach the database
// only through its own port interface, never directly.
func TestOnlyAdaptersTouchTheDatabase(t *testing.T) {
	pkgs := modulePackages(t)

	for _, pkg := range pkgs {
		if isAdapterOrStore(pkg.ImportPath) {
			continue
		}
		for _, imp := range pkg.Imports {
			for _, forbidden := range sqlPackages {
				if imp == forbidden {
					t.Errorf(
						"%s imports %s directly -- only internal/store and a component's own "+
							"*/sqlite adapter package may touch the database; %s should depend on "+
							"a port interface instead (design/adr/0001 Compliance)",
						pkg.ImportPath, forbidden, pkg.ImportPath,
					)
				}
			}
		}
	}
}

// TestDomainPackagesDoNotImportTheirOwnAdapter guards the other direction
// of the same rule: a domain package (registry, audit, ...) must not
// depend on its own adapter subpackage. Go's compiler already forbids the
// reverse (an import cycle, since the adapter imports the domain) -- this
// test exists to catch the direction Go's compiler has no opinion about.
func TestDomainPackagesDoNotImportTheirOwnAdapter(t *testing.T) {
	pkgs := modulePackages(t)

	for _, pkg := range pkgs {
		if isAdapterOrStore(pkg.ImportPath) {
			continue
		}
		ownAdapter := pkg.ImportPath + "/sqlite"
		for _, imp := range pkg.Imports {
			if imp == ownAdapter {
				t.Errorf(
					"%s imports its own adapter %s -- dependencies in ports & adapters point "+
						"inward (adapter depends on domain), never the other way",
					pkg.ImportPath, ownAdapter,
				)
			}
		}
	}
}
