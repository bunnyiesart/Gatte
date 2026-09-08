# 0005. Credential Vault shells out to the `sops` CLI instead of importing it as a Go library

**Status:** Proposed

## Contexto

`design/adr/0003-security-controls.md` decided the Credential Vault would
be backed by sops+age, and `DEVELOPMENT-LOG.md` §9.3 gave the reasoning:
"single ~15MB binary, decrypts headlessly ... no external KMS ...
language-agnostic (Go and Python bindings both exist)." Go was chosen as
the implementation language after that reasoning was written
(`design/adr/0002-language-runtime.md`), which raised a question §9.3
didn't have to answer yet: consume sops as an embedded Go library
(`github.com/getsops/sops/v3/decrypt`), or invoke the standalone `sops`
binary as an external process.

## Decisão

**Shell out to the `sops` binary via `os/exec`; do not import
`github.com/getsops/sops/v3`.**

Verified directly, not assumed: `go install
github.com/getsops/sops/v3/cmd/sops@latest` produces a 72MB binary,
against `filippo.io/age`'s ~6MB, because sops's core package
unconditionally pulls in AWS, GCP, Azure, and HashiCorp Vault KMS client
SDKs (plus their own transitive gRPC/OpenTelemetry/MongoDB dependencies)
regardless of whether any of those key backends are ever used — our
Credential Vault only ever calls it with `SOPS_AGE_KEY_FILE` set,
never touching a cloud KMS. Importing that package would pull the exact
same dependency graph into `mcp-gateway`'s own binary and module graph.

That directly contradicts the reason sops+age won the comparison against
Vault OSS in the first place (`DEVELOPMENT-LOG.md` §9.3: "no external
KMS," "single ~15MB binary" — read, on reflection, as a description of
sops as a self-contained *external* tool the gateway shells out to, not
as license to embed its full dependency surface into the gateway's own
process). It would also work against `design/01-discovery.md`'s
Simplicity & deployability driver: a larger, cloud-SDK-laden dependency
graph is a larger attack surface and a larger thing to audit, in the one
component (`Credential Vault`) where minimizing both matters most.

Invoking the real `sops` binary as a subprocess gets full,
spec-correct sops decryption (including whatever future format changes
upstream ships) with zero addition to `go.mod` beyond what's already
there, at the cost of one new runtime prerequisite: `sops` must be
installed on the gateway host (already true of `age`/`age-keygen` for key
generation and rotation, which were never going to be Go dependencies
either).

## Consequências

**Impactos positivos:** `mcp-gateway`'s own dependency graph gains
nothing from this decision — no AWS/GCP/Azure/Vault SDKs, no added attack
surface, no added binary size. The vault adapter (`internal/vault/sopsage`)
is a thin wrapper around one `exec.Command` call.

**Impactos negativos aceitos:** the gateway host needs `sops` on `PATH`
as a deployment prerequisite, checked at Provider construction time, not
enforced by the Go compiler the way an import would be. A future sops
CLI flag/output change could break the adapter without a compile-time
signal — mitigated by pinning a minimum tested `sops` version in
deployment docs once one exists (not yet written; tracked for
`deploy/freebsd-jail.md` when Phase 2 ships).

**Trade-offs assumidos:** we chose auditable dependency-graph size over
avoiding a subprocess call — consistent with `01-discovery.md` ranking
Security and Simplicity & deployability above convenience.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: `internal/vault/sopsage`'s tests skip (not fail) when `sops`
  or `age-keygen` are not found on `PATH`, so CI/dev environments without
  them don't get a false build failure, but any environment that *does*
  have them runs the real binary, not a mock.
- Onde vive o teste: `internal/vault/sopsage/*_test.go`.
- Quando roda: a cada `make test`.

## Notas

- Autor: Claude (agente de implementação), 08 Sep 2026, durante a Fase 2
  (`WORKFLOW.md`).
- Depende de `0002` (Go) e `0003` (sops+age) — este ADR resolve apenas o
  "como consumir sops a partir de Go," não revisita a escolha de sops+age
  em si.
