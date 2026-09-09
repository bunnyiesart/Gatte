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
	//
	// This list is itself hand-maintained and therefore stale-prone, and
	// it cannot ever be complete: `main` packages (cmd/mcp-gateway,
	// lab/probe, lab/servers/*) and test-only packages (internal/e2e) are
	// not importable at all, so no blank import can pin them. It covers
	// the internal/ tree the rules below actually govern; `-count=1`
	// remains the only real guarantee of a fresh run.
	_ "github.com/bunnyiesart/Gatte/internal/access"
	_ "github.com/bunnyiesart/Gatte/internal/access/oidc"
	_ "github.com/bunnyiesart/Gatte/internal/audit"
	_ "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	_ "github.com/bunnyiesart/Gatte/internal/config"
	_ "github.com/bunnyiesart/Gatte/internal/gateway"
	_ "github.com/bunnyiesart/Gatte/internal/gateway/httpapi"
	_ "github.com/bunnyiesart/Gatte/internal/gateway/stdio"
	_ "github.com/bunnyiesart/Gatte/internal/quarantine"
	_ "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	_ "github.com/bunnyiesart/Gatte/internal/registry"
	_ "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	_ "github.com/bunnyiesart/Gatte/internal/signer"
	_ "github.com/bunnyiesart/Gatte/internal/signer/sqlite"
	_ "github.com/bunnyiesart/Gatte/internal/store"
	_ "github.com/bunnyiesart/Gatte/internal/vault"
	_ "github.com/bunnyiesart/Gatte/internal/vault/sopsage"
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

// modulePath is this module's path, from go.mod. Every classifier below
// anchors on it -- without that anchor, a suffix like "/sqlite" also
// matches the third-party modernc.org/sqlite driver package itself, which
// is not one of *our* adapters and is exactly the kind of package
// internal/store is supposed to be allowed to import directly.
const modulePath = "github.com/bunnyiesart/Gatte"

// internalPrefix is where every component of this project lives. The
// shape of the tree below it is what the adapter rules are built on:
// exactly one segment under it is a component's *domain* package (the
// package that owns the port interface -- internal/registry,
// internal/vault, ...), and anything nested below one of those is that
// component's concrete infrastructure (internal/registry/sqlite,
// internal/vault/sopsage, internal/access/oidc, internal/gateway/stdio,
// internal/gateway/httpapi, ...).
const internalPrefix = modulePath + "/internal/"

// notAnAdapter lists packages under a domain package that are genuinely
// NOT adapters, and may therefore be imported like any ordinary package.
//
// It is empty today, and that is the point. isAdapter used to consult the
// mirror image of this list -- a hand-maintained set of adapter path
// suffixes ("/sqlite", "/sopsage", "/oidc", ...) -- which was fail-open:
// a brand-new adapter was simply invisible to
// TestOnlyCompositionRootImportsAdapters until somebody remembered to add
// its suffix. Verified by hand before this was inverted: adding
// internal/vault/awskms, a concrete vault adapter, and importing it
// straight from internal/registry passed the whole suite clean, which is
// precisely the "a component reaches past the Credential Vault's port"
// case ADR-0001 asks this test to make impossible.
//
// So the default is now "a package below a domain package is suspected
// infrastructure", and an exception has to be argued for here, in
// writing, by someone who has thought about it. A stale allowlist that
// fails closed costs a confusing test failure and one obvious edit; a
// stale allowlist that fails open costs the architecture silently.
var notAnAdapter = []string{}

// isAdapter reports whether importPath is one of this project's own
// adapter packages: any package of this module nested *below* a
// component's domain package, i.e. <module>/internal/<component>/<...>.
//
// This is structural rather than name-based on purpose. What makes a
// package an adapter here is not what it is called but where it sits: a
// domain package owns a port, and everything underneath it is one
// concrete way of satisfying that port -- a driver, a CLI it shells out
// to, a wire protocol. Naming conventions can be forgotten; the position
// in the tree cannot, because it is the thing being created.
//
// Scoped to internal/ deliberately: lab/ is the mock-upstream harness
// (lab/README.md), not a component of the architecture ADR-0001 governs,
// so lab/servers/threatintel is not "an adapter of lab/servers".
func isAdapter(importPath string) bool {
	rest, ok := strings.CutPrefix(importPath, internalPrefix)
	if !ok || !strings.Contains(rest, "/") {
		return false
	}
	for _, exempt := range notAnAdapter {
		if importPath == exempt {
			return false
		}
	}
	return true
}

// domainPackageOf returns the domain package that owns importPath -- the
// single-segment package under internal/ that importPath sits beneath.
// For a domain package it returns the package itself; for anything
// outside internal/ it returns "".
func domainPackageOf(importPath string) string {
	rest, ok := strings.CutPrefix(importPath, internalPrefix)
	if !ok || rest == "" {
		return ""
	}
	component, _, _ := strings.Cut(rest, "/")
	return internalPrefix + component
}

// isAdapterOrStore reports whether importPath is allowed to talk to the
// database directly: either it is internal/store (the one package whose
// job is exactly that), or it is a "/sqlite" adapter -- the naming
// convention every SQL-backed component in this project follows
// (internal/registry/sqlite, internal/audit/sqlite, ...).
//
// Unlike isAdapter, this one stays name-based, and that is safe because
// of which way it fails: a new adapter that talks to the database under
// some other name (internal/foo/postgres, say) is not exempted, so it
// fails this test and someone has to come here and decide deliberately.
// An allowlist is only dangerous when being absent from it means being
// unchecked; here it means the opposite.
func isAdapterOrStore(importPath string) bool {
	return strings.HasSuffix(importPath, "/internal/store") ||
		strings.HasSuffix(importPath, "/sqlite")
}

// isCompositionRoot reports whether importPath is allowed to wire a
// concrete adapter directly: a command package sitting *directly* under
// this module's top-level cmd/ directory. Today that's only
// cmd/mcp-gateway (Phase 1's "proves the wiring, nothing more yet") --
// every other package must depend on the relevant port interface
// (registry.Repository, audit.Recorder, vault.Provider, ...), never reach
// into a concrete adapter it doesn't itself define.
//
// "Directly under the module's own cmd/" is load-bearing. This used to be
// strings.Contains(importPath, "/cmd/"), which handed the exemption to
// any package with a path segment named cmd anywhere above it, at any
// depth, and the exemption is granted by BOTH rules in this file at once
// -- so the widest privilege in the architecture was claimable by naming
// a directory. Verified by hand before this was narrowed: a package at
// internal/gateway/cmd/helper, buried inside a domain component and
// nothing like a composition root, could import database/sql *and*
// internal/vault/sopsage with the whole suite passing clean.
//
// A privilege this large has to be granted by exact position in the tree,
// not by a substring any subdirectory can claim. Note the failure
// direction if cmd/mcp-gateway is ever renamed or moved: nothing matches,
// the real composition root starts failing these tests loudly, and
// somebody comes back here on purpose. That is the right way for this to
// break.
func isCompositionRoot(importPath string) bool {
	rest, ok := strings.CutPrefix(importPath, modulePath+"/cmd/")
	return ok && rest != "" && !strings.Contains(rest, "/")
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
		// The composition root is exempt, deliberately and narrowly.
		//
		// It must hold the one shared *sql.DB in order to hand it to each
		// adapter's Migrate and New -- that is inseparable from being the
		// place adapters get wired. The alternatives are worse: an opaque
		// handle buys nothing, because cmd/ may already import the
		// adapters themselves, which is the larger privilege; and letting
		// each adapter open its own connection would break "one embedded
		// SQLite" (ADR-0001) and the pool pinning internal/store depends
		// on for correctness.
		//
		// This widening does not weaken what the rule protects. The rule
		// exists to stop *domain* packages reaching past their ports, and
		// the composition root contains no domain logic -- it is wiring.
		// Every package that holds a business rule is still covered.
		if isAdapterOrStore(pkg.ImportPath) || isCompositionRoot(pkg.ImportPath) {
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
// of the same rule: a domain package (registry, audit, vault, ...) must
// not depend on its own adapter subpackage. Go's compiler already forbids
// the reverse (an import cycle, since the adapter imports the domain) --
// this test exists to catch the direction Go's compiler has no opinion
// about.
//
// It no longer enumerates candidate adapter names (the old
// pkg.ImportPath + "/sqlite", + "/sopsage", ... loop, which could only
// see adapters somebody had already registered by hand). Anything
// isAdapter recognizes whose owning domain package is this package is a
// violation, whatever it is called.
func TestDomainPackagesDoNotImportTheirOwnAdapter(t *testing.T) {
	pkgs := modulePackages(t)

	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			if isAdapter(imp) && domainPackageOf(imp) == pkg.ImportPath {
				t.Errorf(
					"%s imports its own adapter %s -- dependencies in ports & adapters point "+
						"inward (adapter depends on domain), never the other way",
					pkg.ImportPath, imp,
				)
			}
		}
	}
}

// TestOnlyCompositionRootImportsAdapters is the fitness function
// design/adr/0001-monolithic-modular-style.md's Compliance section names
// specifically for the Credential Vault ("nenhum componente acessa
// Credential Vault fora da interface pública dele"), generalized to
// every port/adapter pair this project has, not just the vault: an
// adapter subpackage (internal/registry/sqlite, internal/vault/sopsage,
// ...) may be imported only by cmd/mcp-gateway (the one place allowed to
// wire concrete infrastructure, per isCompositionRoot) or by its own
// package's tests (which go list -json reports separately, under
// TestImports/XTestImports, not Imports -- so they never appear here).
// Any other package -- in particular, a sibling domain package, or a
// future Gateway Endpoint reaching for vault/sopsage directly instead of
// depending on vault.Provider -- would defeat the entire reason
// Credential Vault is a separate, security-sensitive component: nothing
// should be able to touch a secret except through the interface that
// promises never to log or persist it.
func TestOnlyCompositionRootImportsAdapters(t *testing.T) {
	pkgs := modulePackages(t)

	for _, pkg := range pkgs {
		if isCompositionRoot(pkg.ImportPath) {
			continue
		}
		for _, imp := range pkg.Imports {
			// A package may always import its own subpackages: those are
			// its private implementation, not another component's
			// infrastructure, and nothing crosses a port boundary.
			//
			// This replaces a blanket "skip every adapter package"
			// exemption, which was a third fail-open in the same family
			// as the other two: it let any adapter import any *other*
			// component's adapter unchallenged -- internal/gateway/stdio
			// reaching straight into internal/vault/sopsage instead of
			// depending on vault.Provider was exactly as invisible as a
			// domain package doing it. No adapter in the module needed
			// that exemption (checked against the full import graph when
			// it was removed), and ports & adapters gives no reason one
			// ever should.
			if imp == pkg.ImportPath || strings.HasPrefix(imp, pkg.ImportPath+"/") {
				continue
			}
			if isAdapter(imp) {
				t.Errorf(
					"%s imports adapter %s directly -- only cmd/mcp-gateway may wire a concrete "+
						"adapter; %s should depend on the corresponding port interface instead "+
						"(design/adr/0001 Compliance)",
					pkg.ImportPath, imp, pkg.ImportPath,
				)
			}
		}
	}
}
