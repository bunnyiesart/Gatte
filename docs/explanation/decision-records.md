# Decision records

This page is a map of [`design/adr/`](../../design/adr/), for anyone who
wants the reasoning behind a behaviour and needs to know which record to
open. It lists every decision record with its number, an English title and
one sentence on what it decided, grouped by theme, and says which ones
later records corrected or replaced.

## How to read the records

- **Language.** The records are in Portuguese, except the titles of
  `0001`, `0003` and `0004` and most of `0005`. The titles below are
  English translations; the file names of `0001` to `0017` are in English
  too.
- **Nothing is edited silently.** When a later decision changes an earlier
  one, the earlier record keeps its text and gains a dated correction block
  (`CORREÇÃO`, `FECHADO`, `Emenda`, `Revisto por`) that points at the later
  one. Read the correction blocks before trusting the body of an older
  record: they describe the system as it is.
- **Numbering.** `0028`, `0029` and `0030` bring in decisions made on an
  internal line of this project whose own numbers collide with different
  records here; each says which internal record it replaces
  (`design/adr/0028`, Context).
- **Methodology.** The architecture method the records follow lives
  outside this repository (`design/adr/0022`).

In the tables, **Later changes** names the records that corrected, closed
or revised this one. "Superseded" means a later record replaced the
decision; "corrected" means it keeps the decision and fixes what the record
claimed.

## Foundations

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0001](../../design/adr/0001-monolithic-modular-style.md) | Modular monolith | One binary, one process, domain-partitioned components and one embedded SQLite file, with fitness tests holding the module boundaries. | Corrected 28 Sep 2026: more domain packages and schemas than the original eight components; 30 Sep 2026: eight schemas. |
| [0002](../../design/adr/0002-language-runtime.md) | Go as the implementation language | Go, reversing the record's own original proposal of Python, to match the reference mechanisms and ship one static binary. | — |
| [0009](../../design/adr/0009-configuration-in-toml.md) | Configuration in TOML, roles in the file | TOML for comments beside policy; roles in the reviewed file, not the database; no secret value in the file. | Corrected by `0044`: `reload` applies roles without a restart. |
| [0022](../../design/adr/0022-metodologia-de-arquitetura-externa.md) | The architecture methodology is external | The methodology corpus is not vendored; citations say `context/`, and a manifest test checks that the paths the gate documents cite exist. | — |
| [0026](../../design/adr/0026-fechamento-do-criterio-de-v1.md) | The v1 criterion | Rewrote the third v1 condition to name the end-to-end tests that prove it, and filed `lab/probe` as a second client rather than refusing it. | Corrected 30 Sep 2026: its skipped-test count was stale (`CLOSEOUT.md`, Track 4); `make ci` now fails on any skip. |

## Credentials and the vault

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0003](../../design/adr/0003-security-controls.md) | Security controls: sops+age, per-tool quarantine, Ed25519 signing | The three core controls, plus the rule that the client's credential never reaches a backend. | Signing corrected by `0010` (trust anchor) and `0020` (checked every round); wildcard ban revised by `0016`; "never on disk" false for containers (`0028` §D); corrected 30 Sep 2026: the age key is the service account's, not root's. |
| [0005](../../design/adr/0005-shell-out-to-sops-cli.md) | Shell out to the `sops` CLI | Run the `sops` binary instead of importing its Go library and its cloud SDKs. | Corrected: `make ci` now refuses to run without `sops` and `age`. |
| [0018](../../design/adr/0018-vault-namespace-e-credencial-compartilhada.md) | Flat vault, shared credentials reported | Keep the vault keyed by variable name and report sharing at boot instead of refusing it. | Exception added by `0030`: sharing between a budgeted and an unbudgeted entry is refused. |
| [0023](../../design/adr/0023-recarga-do-cofre-quando-o-arquivo-muda.md) | The vault re-reads its file when it changes | Re-decrypt when the file's mtime or size changes, so rotation detection can fire; keep the old values if the re-read fails. | Amended for `0024` (a redialled backend takes the new value); corrected by `0044` (on-demand redial). |

## Signing and the registry

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0004](../../design/adr/0004-registry-unavailability-failure-mode.md) | Failure mode when the registry is unreadable | Fail closed with a short retry: serve nothing rather than a routing table that cannot be confirmed. | The retry did not exist until `0020`, which is its form; corrected for `0030`. |
| [0006](../../design/adr/0006-signing-key-and-signature-storage.md) | Signing key in its own file, signatures in their own table | Private key outside the database and the vault; signatures in a separate table; entry name in the signed encoding; invalid refused, missing by configuration. | Verification corrected by `0010`; `require_signed` flipped to true by default; image encoding added by `0028`. |
| [0010](../../design/adr/0010-signature-trust-anchor.md) | Trust anchor: trusted public keys in the configuration | Verify against keys in `config.toml`, never the key stored with the signature; an unknown key is invalid. | Corrected: verified every round (`0020`), still read once at start; eight schemas (30 Sep 2026). |
| [0020](../../design/adr/0020-reconciliacao-periodica-do-registro.md) | Periodic reconciliation of the registry | Each round dials new entries, closes removed or unverified ones, and suspends the fleet when the registry is unreadable, without closing healthy connections. | Corrected by `0024` (dead backends), `0041` (constant `503`) and `0044` (redial). |

## Tool quarantine

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0007](../../design/adr/0007-quarantine-semantics.md) | Quarantine semantics | `changed` is sticky until a human approves; schemas are hashed without canonicalisation; one predicate governs listing and calling. | §2 corrected by `0019`: the SDK decodes schemas first. |
| [0013](../../design/adr/0013-quarantine-refresh-and-removal.md) | Periodic re-observation and removal | Re-list backends on a timer, not on `list_changed`; `deregister` forgets approvals; `tool revoke` exists. | Window size corrected; `0024` exception; pulled-tool text (`0042`); `upstream update` keeps approvals (`0043`). |
| [0019](../../design/adr/0019-schema-bytes-que-o-sdk-ja-decodificou.md) | Schema bytes the SDK already decoded | Accept, and pin with a test, that the fingerprint covers the SDK's re-encoding, not the backend's raw bytes. | — |
| [0032](../../design/adr/0032-quarentena-informada-e-eventos.md) | Informed quarantine and trail events | Store every observed definition, escape hidden code points, require the shown fingerprint to approve, and write rows for new tools, changes and refused signatures. | "Who approved stays out of the trail" closed by `0040`. |
| [0043](../../design/adr/0043-revisao-em-lote-e-troca-de-imagem.md) | Batch review per backend, and image update | Approve a backend's whole review set bound to a manifest, all or nothing; `upstream update -image` keeps the quarantine and requires a new signature. | — |

## Identity and access

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0008](../../design/adr/0008-identity-model-self-hosted-oidc.md) | Self-hosted OIDC, gateway as resource server | Validate tokens from a provider you host, with audience checks; the gateway picks no provider. | Corrected: the promised test against a real IdP was never written. |
| [0016](../../design/adr/0016-per-backend-role-grants.md) | Per-backend role grants | Roles can grant tools per backend, including `["*"]`, which the quarantine makes defensible; its cost is named. | Integration and the name-prefix residual closed in the same record. |
| [0031](../../design/adr/0031-bloqueio-imediato-por-analista.md) | Immediate per-analyst block | A blocklist read on every request, failing closed, with audited `access block` and `unblock`. | `403` body corrected by `0042`; operator attribution by `0040`; timed blocks added by `0046`. |
| [0037](../../design/adr/0037-nome-do-analista-na-trilha.md) | The analyst's name in the trail | Record the display name for reading only, under a new chain tag so old rows keep their hashes. | — |
| [0046](../../design/adr/0046-busca-na-trilha-e-ciclo-de-vida-das-pessoas.md) | Trail search and people's lifecycle | Filter the trail by tool, backend and time range with CSV and JSON Lines export; blocks with an end; account deletion; one-call offboarding. | — |

## Network and backends

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0011](../../design/adr/0011-network-exposure-and-tls-termination.md) | Network exposure and TLS termination | Refuse any non-loopback bind with no override; TLS at a co-located reverse proxy. | Corrected: its jail, VPN and IdP topology describes an abandoned lab substrate. |
| [0028](../../design/adr/0028-transporte-oci.md) | The `oci` transport | Run a backend as an ephemeral rootless podman container pinned by digest, with the digest inside the signature. | Wrapper corrected by `0034`; network values decided by `0033`. |
| [0033](../../design/adr/0033-egresso-dos-backends.md) | Backend egress | The adapter allows only `none`, `slirp4netns`, `pasta` or a named network; destinations belong to the host firewall. | — |
| [0034](../../design/adr/0034-endurecimento-do-container-e-stdio-com-credencial.md) | Container hardening and credentialed stdio | Drop all capabilities, force a non-root uid and resource limits, refuse code-loading variable names, and refuse credentialed stdio unless opted in. | — |

## The audit trail and telemetry

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0012](../../design/adr/0012-audit-completeness.md) | Audit completeness | A failure is a second row; failed authentication is audited without the token; the source address is the right-most `X-Forwarded-For` entry. | Rate limit by `0027`; new row shapes by `0041`; chain by `0015` and `0017`. |
| [0015](../../design/adr/0015-audit-tamper-evidence.md) | Hash-chaining the trail, and its limits | Chain records by SHA-256 in insertion order, and never call the trail tamper-proof. | Corrected the same day: an unkeyed chain can be re-chained; only a head comparison detects it. |
| [0017](../../design/adr/0017-audit-jsonl-siem-sink.md) | JSONL copy for the SIEM, and the external anchor | A second sink written after each commit, carrying the chain links, so the SIEM holds the head. | Corrected for `0029` (GELF) and `0021` (heartbeat), and 30 Sep 2026 for schema `5` and `analyst_name`; the head comparison still has no owner. |
| [0021](../../design/adr/0021-batimento-operacional-na-trilha.md) | An operational heartbeat in the trail | A periodic heartbeat line on the same JSONL path, so the SIEM can alert on its absence. | Fields grown by `0032` and `0041`. |
| [0027](../../design/adr/0027-limite-de-taxa-na-auditoria-de-falha-de-autenticacao.md) | Rate limit on failed-authentication audit rows | Token buckets per source and globally before the durable write; the log keeps the exact count. | — |
| [0029](../../design/adr/0029-telemetria-gelf.md) | GELF telemetry | An optional GELF copy of each accepted record that never holds up the request. | — |

## The call path and its limits

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0014](../../design/adr/0014-response-validation-scope.md) | Response validation: what it gives and what it does not | A result size ceiling and output-schema validation when declared; explicitly not a prompt-injection defence. | Output schema added to the fingerprint; the memory-ceiling and logging claims corrected; the ceiling is now told to the caller (`0042`). |
| [0024](../../design/adr/0024-morte-de-um-upstream-conectado.md) | Death of a connected backend | The adapter reports a dead process as positive evidence; the next round closes and redials it; a slow backend is not dead. | Corrected by `0041`: routes are kept and a marked connection is not called. |
| [0025](../../design/adr/0025-prazo-por-chamada.md) | Every call has a deadline | `response.call_timeout`, default 2 minutes, with no value that disables it. | Corrected by `0042`: the timeout has its own text. |
| [0030](../../design/adr/0030-quota-por-analista.md) | Per-analyst quota per third-party account | Count calls per analyst per provider account, debit before the call, never refund. | Corrected by `0042`: the refusal names the account and reset; `gatte.status` reads the caller's own use. Since `0044` a limit changes with `reload`. |
| [0035](../../design/adr/0035-resiliencia-do-caminho-de-chamada.md) | Call-path resilience | Contain panics to one call, cap calls in flight per analyst, cap the request body at 1 MiB, and limit JWKS refetches. | Corrected by `0042`: the concurrency refusal says the limit. |

## Health and honest answers

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0041](../../design/adr/0041-saude-dos-backends-e-manutencao.md) | Backend health and maintenance | Backend states, `isError` answers instead of `internal error`, a stable tool list, the built-in `gatte.status`, planned maintenance, and health rows in the trail. | Corrected by `0042`: timeout text, instructions and the `you` block; 30 Sep 2026: no upstream `_meta` is forwarded, the CLI runs maintenance in-process, `never_reported`. |
| [0042](../../design/adr/0042-honestidade-com-o-analista-e-escopos.md) | Honesty with the analyst, and OAuth scopes | Actionable refusals for Gatte's own limits, a `403` body, "no longer available" for pulled tools, richer instructions, and advertised OAuth scopes. | Corrected 30 Sep 2026: the `60s` in the timeout example is not the default (2m). |

## Operating surfaces

| ADR | Title | Decided | Later changes |
|---|---|---|---|
| [0036](../../design/adr/0036-console-web-local.md) | Local web console | A foreground, loopback-only console with one-time login, path-bound session, CSRF and CSP defences, and no JavaScript. | Revised by `0040`: the console is a client of the management API. |
| [0038](../../design/adr/0038-contas-do-idp-pelo-console.md) | IdP accounts from the console | A People page for everyone; editing the IdP's users file only with root's authority. | Revised by `0040` (root-only accounts socket); deletion added by `0046`. |
| [0039](../../design/adr/0039-script-de-conexao-do-analista.md) | The analyst's connect script | A generated script per OS that sets up Claude Code against the gateway, carrying nothing secret. | Corrected by `0041`: it also installs `gatte-status`; 30 Sep 2026: the sh script edits each existing shell profile. |
| [0040](../../design/adr/0040-api-de-gestao-e-fronts-opcionais.md) | Management API and optional fronts | Every operator action as versioned JSON on UNIX sockets only, the operator named by the kernel, fronts as clients, `-tags nofront`. | Contract bumps recorded for `0041`, `0043`, `0044` and `0046` (`1.4.0`). |
| [0044](../../design/adr/0044-mudar-sem-reiniciar-todo-mundo.md) | Change without restarting everyone | `reload` for roles, groups and quota; `upstream redial` for one backend; `sign -all` bound to a plan; `sign` as root drops to the database owner. | Corrected 30 Sep 2026: the bare `SIGHUP` row is a `(config reload)` row by `(gateway)`, tagged `[signal]`. |
| [0045](../../design/adr/0045-comandos-de-instalacao-e-atualizacao-seguras.md) | Install and upgrade without guessing | `check` for the host, verified `backup` and `restore`, a schema guard, a `(boot)` row, and the upgrade recipe. | — |

## Superseded and corrected, at a glance

No record has been withdrawn outright. These are the places where a later
record replaced part of an earlier decision, rather than only fixing its
wording:

- **`0003`'s ban on wildcard grants** was revised by `0016`, once `0013`
  made sure a new tool is never served without approval.
- **`0006`'s verification** was replaced by `0010`: checking against the
  key stored with the signature proved nothing.
- **`0007` §2, raw schema bytes,** does not hold; `0019` accepts what the
  SDK delivers instead.
- **`0014`'s silence about the size ceiling** was reversed by `0042`.
- **`0024`'s pruning of a dead backend's routes** was replaced by `0041`'s
  stable listing.
- **`0036`'s console as an in-process caller of the CLI** and **`0038`'s
  root-run console** were replaced by `0040`'s management API.
- **"Restart to change a role" (`0009`) and "restart to apply a rotated
  credential" (`0020`, `0023`)** were replaced by `0044`.
