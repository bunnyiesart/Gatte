package fitness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gatePaths is the manifest: every path a GATE DOCUMENT of this repository
// tells a reader to open, plus the citations in package doc comments that
// say where a rule came from.
//
// # Why a hand-written list and not a scanner
//
// The obvious version of this check is a scanner: take every backticked
// token that looks like a relative path and require it to resolve. It was
// designed, prototyped four times, and rejected (ADR-0022 item 4). The four
// prototypes disagreed with each other -- between 269 and 676 occurrences,
// with 52 to 223 "missing" -- because `127.0.0.1`, `audit.Record`,
// `pkg/secrets/types.go` and `dfir.bunnyiesart.com` are backticked tokens
// too. Telling a claim-about-this-repository from an identifier needs
// domain knowledge, and by the decisive question this package's own doc
// comment quotes from `context/07-fitness-functions.md` §2 -- "does this
// test require domain knowledge to run?" -- that disqualifies it as a
// fitness function. It would also have needed an allowlist of 40 to 160
// entries against 127 paths that do resolve, and an allowlist that large is
// a place for a real violation to hide.
//
// So the manifest is the check. It is data, written by hand, and adding a
// path to a gate document without adding it here is the only way to evade
// it -- deliberately, because the target is "a document told me to open
// this" and not "this string looks like a file".
//
// # What it would have caught
//
// `docs/context/` was cited by fifteen files, including AGENTS.md §5 as a
// written precondition ("read this before the first class is written"), and
// the directory never existed in any of the 51 commits. Nobody tripped over
// it for seven phases, because an instruction pointing at nothing does not
// fail -- it gets skipped. This manifest would have failed on the bootstrap
// commit.
//
// # What it deliberately does not check
//
// The external corpus. `context/…` citations name material that lives
// beside this repository and is not in it (ADR-0022), so a check that
// demanded they resolve would fail by design. That is the one absence this
// file asserts rather than verifies -- see TestExternalCorpusIsNotAsserted.
var gatePaths = []string{
	// Named by AGENTS.md -- §4, §5 and §6.
	"WORKFLOW.md",
	"DEVELOPMENT-LOG.md",
	"RESEARCH-recovered.md",
	"CONCEPTS.md",
	"design/01-discovery.md",
	"design/02-components.md",
	"design/03-style.md",
	"lab/README.md",
	"lab/probe",
	"lab/servers/casemgmt",
	"lab/servers/logsearch",
	"lab/servers/docsearch",
	"lab/servers/threatintel",

	// ADRs cited by name from AGENTS.md, WORKFLOW.md or from code.
	"design/adr/0001-monolithic-modular-style.md",
	"design/adr/0002-language-runtime.md",
	"design/adr/0003-security-controls.md",
	"design/adr/0004-registry-unavailability-failure-mode.md",
	"design/adr/0005-shell-out-to-sops-cli.md",
	"design/adr/0006-signing-key-and-signature-storage.md",
	"design/adr/0007-quarantine-semantics.md",
	"design/adr/0008-identity-model-self-hosted-oidc.md",
	"design/adr/0009-configuration-in-toml.md",
	"design/adr/0010-signature-trust-anchor.md",
	"design/adr/0011-network-exposure-and-tls-termination.md",
	"design/adr/0012-audit-completeness.md",
	"design/adr/0013-quarantine-refresh-and-removal.md",
	"design/adr/0014-response-validation-scope.md",
	"design/adr/0015-audit-tamper-evidence.md",
	"design/adr/0016-per-backend-role-grants.md",
	"design/adr/0017-audit-jsonl-siem-sink.md",
	"design/adr/0018-vault-namespace-e-credencial-compartilhada.md",
	"design/adr/0019-schema-bytes-que-o-sdk-ja-decodificou.md",
	"design/adr/0020-reconciliacao-periodica-do-registro.md",
	"design/adr/0021-batimento-operacional-na-trilha.md",
	"design/adr/0022-metodologia-de-arquitetura-externa.md",
	"design/adr/0023-recarga-do-cofre-quando-o-arquivo-muda.md",
	"design/adr/0024-morte-de-um-upstream-conectado.md",

	// Deployment paths this repository's own documents send an operator to.
	"config.example.toml",
	"deploy/README.md",
	"deploy/freebsd-jail.md",
	"deploy/gateway-serve.md",
	"deploy/gatte-anchor-verify.sh",
	"deploy/gatte-audit-fluentbit.conf",
	"deploy/vm/gateway-upstreams.sh",

	// Source paths named in prose as the place a guarantee is enforced.
	"cmd/mcp-gateway",
	"internal/access",
	"internal/store",
	"internal/gateway/stdio",
	"internal/vault/sopsage",
	"internal/vault/sopsage/leak_test.go",
	"internal/e2e/checkpoint_test.go",
	"internal/fitness/fitness_test.go",
	"lab/mockutil/credcheck.go",
}

// repoRoot is this package's directory's grandparent: internal/fitness ->
// internal -> the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// TestDocumentedPathsExist is ADR-0022's compliance check.
//
// One assertion, no cleverness: everything a gate document tells a reader
// to open has to be openable from a clone of this repository.
func TestDocumentedPathsExist(t *testing.T) {
	root := repoRoot(t)

	for _, rel := range gatePaths {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("a gate document of this repository points at %q and it is not there: %v\n"+
				"Either the path moved (fix the document AND this list), or a document is telling\n"+
				"a reader to open something no clone has -- which is what happened with docs/context\n"+
				"for seven phases (ADR-0022).", rel, err)
		}
	}
}

// TestExternalCorpusIsNotAsserted pins the other half of ADR-0022: `context/…`
// names material that lives OUTSIDE this repository, so nothing here may
// claim it is inside.
//
// The check is on the spelling, because the spelling is the claim.
// `docs/context/foo.md` reads as a path in this repository; `context/foo.md`,
// with AGENTS.md §6 saying what `context/` is, does not. If the old spelling
// comes back -- by a revert, by a copy-paste from an old commit, by an agent
// "fixing" a path -- this fails.
func TestExternalCorpusIsNotAsserted(t *testing.T) {
	root := repoRoot(t)

	// Two files quote the old spelling on purpose, because recording what
	// was wrong is their job: the ADR that decided it, and this checker.
	// Nothing else is exempt -- in particular not AGENTS.md, which is the
	// file that carried the wrong spelling for seven phases and therefore
	// the file this check exists for.
	documenting := map[string]bool{
		"design/adr/0022-metodologia-de-arquitetura-externa.md": true,
		"internal/fitness/manifest_test.go":                     true,
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || documenting[rel] {
			return nil
		}
		// Skip what cannot carry prose, rather than listing what can: the
		// first version listed extensions and therefore did not read
		// .githooks/pre-commit, the Makefile, deploy/gateway-jail/mcp_gateway
		// or the .yml files -- five tracked files, exempt by accident, while
		// this test's own comment said nothing else was exempt.
		switch filepath.Ext(path) {
		case ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".db", ".sum", ".xlsx":
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(b), "docs/context/") {
			t.Errorf("%s cites docs/context/, a directory this repository has never had.\n"+
				"The corpus is external (ADR-0022); cite it as context/NN-*.md, which does not\n"+
				"claim the file is here.", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
}
