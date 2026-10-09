# Configuration

This page is for operators who edit `config.toml`. It lists every section
and key the loader accepts, with its type, default, whether it is
required, its constraints, and when a change takes effect. The commented
original, with the reasoning behind each key, is
[`config.example.toml`](../../config.example.toml); the loader is
`internal/config`.

## Rules for the whole file

| Rule | Detail |
|---|---|
| No secret values | The file holds paths and identifiers only. Credentials live in the sops-encrypted vault; keys live in owner-only files. |
| Unknown key | Refused at load, naming the key. A misspelled key never loads silently. Comment a key out with `#`; do not rename it. |
| Repeated key | `signer.trusted_keys`, a role's `tools` and a key inside one `[role.grants]` are refused when written twice, even where TOML itself would keep the last value. Two different `[[role]]` blocks granting the same backend are fine. |
| Every problem at once | Validation reports every problem in the file in one error, prefixed `config: invalid: PATH:` (`config: invalid: PATH (roles from ROLES_PATH):` with `roles_file`). |
| Durations | A string with a unit: `"5m"`, `"30s"`, `"24h"`. A bare integer is read as nanoseconds; the minimums below exist to catch that. |
| Paths | `database`, `vault.secrets_file`, `vault.age_key_file` and `signer.key_file` are used as written: leading or trailing whitespace is refused, not trimmed. |
| Who reads it | `serve`, every operator command (on every run), `admin` (on every operation), `admin -accounts` (on every request, after checking the file's ownership), `check`, `sign`, `backup`, `restore`. `ui` and `sign -generate-key` read no configuration file. |

## When a change takes effect

| Keys | How to apply | Takes effect |
|---|---|---|
| `[[role]]` (`tools`, `non_read`), `[role.grants]`, `[group_to_role]`, `roles_file` and the file it names, `[[quota.provider]]`, `quota.free_tools` | `mcp-gateway reload` (or `SIGHUP`) | `serve`'s next call; a client sees tools it gained after it reconnects |
| `signer.key_file` | nothing | the next `sign` run |
| `[connect]`, `[idp]`, `admin.console_manages` | nothing | the management backend's next operation |
| `admin.operator_group`, `admin.account_group` | restart the management backend | when `admin` next starts (a socket-activated backend exits after 5 minutes idle) |
| Every other key: `listen`, `database`, `[oidc]`, `[vault]`, `signer.trusted_keys`, `signer.require_signed`, `[quarantine]`, `[response]`, `[audit.siem]`, `[telemetry]`, `[oci]`, `[upstreams]`, `[analyst]` | restart `serve` | after the restart |

`reload` validates the whole file and applies only the reloadable part. It
reports every other key that differs from the file `serve` started with,
dotted (`signer.trusted_keys`, `oidc.scopes_supported`, `analyst.contact`),
as not applied until a restart. Operator commands read the file on every
run, so a key such as `audit.siem.path` or `upstreams.allow_credentialed_stdio`
already applies to them while `serve` still runs with the old value.

## Top-level keys

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `listen` | string | `"127.0.0.1:8080"` | no | The MCP endpoint's `host:port`. The host must be `localhost` or a loopback address; any other bind is refused, with no override (`design/adr/0011`). The port must be present, a number from 0 to 65535 or a known service name; an explicit `:0` is accepted. `restore` binds this address to confirm `serve` is stopped. |
| `database` | string | none | yes | Path of the SQLite file: registry, quarantine, audit trail, signatures, quota counters, blocklist, health and maintenance, operator requests. Its directory must be writable by the service account. |
| `roles_file` | string | `""` | no | A file holding the `[[role]]` blocks and the `[group_to_role]` table instead of this one (`design/adr/0050` §3). Held to this file's rules: an unknown key, or a key repeated where TOML keeps the last value, is refused, naming the roles file. With it set, this file may hold neither: a file with both is refused at load. A relative path is resolved against this file's directory. `reload` re-reads both files. With `[admin] console_manages` it is the file the console writes (`PUT /v1/roles`), after validating the text as this load would; on the accounts socket it must pass the same ownership check as `config.toml`. No leading or trailing whitespace. |

## [oidc]

The identity provider this gateway trusts as an OAuth 2.0 resource server
(`design/adr/0008`). There is no client secret.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `issuer` | string | none | yes | Base URL for discovery (`ISSUER/.well-known/openid-configuration`). An absolute URI with a host, `https`, no query, no fragment; `http` only for `localhost`, `127.0.0.1` or `::1`. `serve` does not start without discovery. |
| `audience` | string | none, never defaulted | yes | The value tokens must carry in `aud`, and the `resource` of the RFC 9728 metadata. Same URI rule as `issuer`. |
| `groups_claim` | string | `"groups"` | no | The claim carrying group membership. |
| `authorization_servers` | list of strings | `[issuer]` | no | Advertised in the RFC 9728 metadata. Each entry follows the `issuer` URI rule. |
| `scopes_supported` | list of strings | `[]` | no | Advertised as `scopes_supported` in the metadata and as `scope` in every 401 challenge (`design/adr/0042`). Each is an RFC 6749 scope-token: printable ASCII from `!` to `~`, without space, `"` or `\`; none may repeat. Empty advertises no scope. |

## [vault]

The sops-encrypted credential store and the age identity that decrypts it
(`design/adr/0003`, `0005`, `0023`).

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `secrets_file` | string | none | yes | The sops-encrypted JSON document. `serve` fails to start if it does not decrypt. It is re-read when its modification time or size changes; a connected backend keeps the old value until `upstream redial` or a restart. |
| `age_key_file` | string | none | yes | The age identity, passed to `sops` as `SOPS_AGE_KEY_FILE`. Refused unless it is a regular file with no group or other permission bits. |

## [signer]

The signing key and the trust anchor for registry signatures
(`design/adr/0006`, `0010`).

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `key_file` | string | none | no | The Ed25519 private key, PEM PKCS#8, owner-only. Read only by `sign`. Without it the host verifies signatures and cannot make them. |
| `trusted_keys` | list of strings | `[]` | when `require_signed` is true | Base64 (standard encoding, with padding) of each raw 32-byte Ed25519 public key. A signature by any other key is invalid. `sign` prints the line to add. |
| `require_signed` | boolean | `true` | no | `true`: an unsigned entry is not served. `false`: an unsigned entry is served. An invalid signature is refused either way. `true` with an empty `trusted_keys` is refused at load. |

## [quarantine]

Re-observation of connected backends and reconciliation of the registry
(`design/adr/0013`, `0020`).

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `refresh_interval` | duration | `"5m"` | no | How often `serve` re-reads the registry (dialling new entries, closing removed or no longer verified ones) and re-runs `tools/list` against every connected backend. At least `1s`; zero or negative is refused. There is no value that turns it off. It is also the heartbeat interval. |

## [response]

Bounds on one tool call (`design/adr/0014`, `0025`, `0035`). In
`config.example.toml` the last two keys follow the commented `[audit.siem]`
block; they belong to `[response]`.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `max_bytes` | integer | `1048576` (1 MiB) | no | The largest result, in bytes: serialized content blocks plus serialized `structuredContent`. A larger result is refused whole, never truncated, and recorded as `failed` / `result too large`. At least `4096`; zero or negative is refused. |
| `call_timeout` | duration | `"2m"` | no | The gateway's ceiling on one call. At least `1s`; zero or negative is refused. Recorded as `failed` / `upstream timed out`. |
| `max_concurrent_calls_per_analyst` | integer | `4` | no | Calls one IdP subject may have in flight across all sessions. A call over it is refused at once, before quota, as `denied` / `concurrency limited`. Must be positive. |

## [audit.siem]

A second copy of the audit trail as JSON Lines in a local file, for a
shipper to forward (`design/adr/0017`, `0021`). The field names are in
[Audit trail](audit-trail.md#jsonl-lines).

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `path` | string | none | with `chain` | The file lines are appended to. Setting it enables the sink. No edge whitespace. Opened `O_APPEND`, created `0600`, narrowed to `0600` if wider. If it does not open, `serve` does not start. It is not reopened on `SIGHUP`. |
| `chain` | string | none | with `path` | The chain name every line carries, e.g. `"gatte-jail-01"`. No edge whitespace. Unique per gateway. |

`path` without `chain`, or `chain` without `path`, is refused. With the
section absent, every record still goes to SQLite and nothing leaves the
host; the heartbeat goes to the log only.

## [telemetry]

A GELF copy of every audit record, over UDP or TCP (`design/adr/0029`).
The section header may be present with no keys; that means no telemetry.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `address` | string | none | to enable | The GELF input, `host:port`. The switch: empty sends nothing. Not resolved at load or at start. No whitespace around host or port. |
| `transport` | string | none | with `address` | `"udp"` or `"tcp"`; no default. |
| `tls` | boolean | `false` | no | TLS on the TCP connection. Refused with `udp`. Certificate verification cannot be turned off. |
| `tls_ca_file` | string | system pool | no | PEM CA for the input's certificate. Refused unless `tls = true`. A missing file, or one without a certificate, stops `serve` from starting. |
| `host` | string | none | with `address` | The GELF `host` field. No fallback to the host name. |
| `cliente_soc` | string | none | with `address` | The GELF `_cliente_soc` field. No edge whitespace. |
| `buffer` | integer | `4096` | no | Events that may queue while the destination is down. At least `64`; zero or negative is refused. A full queue drops the newest event and counts it. |

Any key but `tls = false` written without `address` is refused. The error
messages of this section are in Portuguese.

## [oci]

The user and limits every `oci` container runs with (`design/adr/0034`).
Every `podman run` also carries `--cap-drop=all` and
`--security-opt=no-new-privileges`, which have no key.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `user` | string | `"65534:65534"` | no | `--user`, numeric `UID:GID`, neither half `0`, each at most 4294967294. A name is refused. |
| `pids_limit` | integer | `256` | no | `--pids-limit`, from 1 to 4194304. |
| `memory` | string | `"512m"` | no | `--memory`: a whole number and one unit of `b`, `k`, `m` or `g`, at least `6m`. |
| `cpus` | float | `1.0` | no | `--cpus`, at least `0.01`. The host's maximum is checked by podman at run time. |

The limits need cgroup v2 with the `memory`, `pids` and `cpu` controllers
delegated to the service account; Gatte does not check that.

## [upstreams]

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `allow_credentialed_stdio` | boolean | `false` | no | Allows a `stdio` entry that declares `-env` credentials to be registered, signed and dialled. Read by `upstream register`, `sign` and `serve`. Every `serve` start with it on logs a WARN (`design/adr/0034`). |

## [idp]

The identity provider's account store, for the console's account editing
(`design/adr/0038`).

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `users_file` | string | `""` (account editing off) | for `admin -accounts` | Absolute path of the Authelia file-backend users database. Read and written only by `admin -accounts`, as root. The file and every directory above it must be root's, regular, not symbolic links and not writable by group or others. `serve` never reads it. |

## [admin]

Groups the management backend checks peers against (`design/adr/0040`).
The socket file's group and mode are the first barrier.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `operator_group` | string | `""` | no | The group an operator-socket peer must have, unless it is root or the service account. When set, an operator socket open to a group must be of this group. The group must exist when `admin` starts. |
| `account_group` | string | `""` | no | Delegates account editing to a group without `sudo`. Takes effect only with an accounts socket of that group and mode `0660`; a mismatch stops `admin -accounts` from starting. The group reaches only accounts whose groups are all in `[group_to_role]`. |
| `console_manages` | bool | `false` | no | Turns on the management operations of `design/adr/0050`: on the operator socket, an entry in detail, registering an http backend from its OpenAPI document and deregistering; on the accounts socket, signing, writing and deleting vault values (through `sops`, plaintext never on disk; `[vault]`'s two files held to the ownership check) and writing `roles_file`. Off, each answers `feature_disabled` and the binary's relationship with the vault stays read-only. Read on every operation. |

## [connect]

What the console's connect scripts put on an analyst's machine
(`design/adr/0039`). Everything here is public.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `client_id` | string | `""` (scripts off) | no | The public OAuth client registered at the IdP for Claude Code. `^[A-Za-z0-9._~-]{1,128}$`. |
| `callback_port` | integer | `0` | with `client_id` | The port of that client's redirect URI (`http://127.0.0.1:PORT/callback`), 1 to 65535. |
| `ca_file` | string | `""` | no | Absolute path of a PEM CA the analyst's machine must trust, for a private CA. |
| `server_name` | string | `"gatte"` | no | The server's name in the MCP client. `^[a-z0-9][a-z0-9-]{0,31}$`. |

`callback_port` or `ca_file` without `client_id` is refused.

## [analyst]

The operator's lines in the MCP server instructions, the one server text a
model always sees (`design/adr/0042`). See [What the analyst is
told](analyst-messages.md#server-instructions).

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `contact` | string | `""` | no | Whom an analyst asks when Gatte refuses them. Also closes the body of the 403 a refused account gets. At most 200 characters. |
| `backend_notes` | table of strings | `{}` | no | One line per backend, keyed by registry name (`casemgmt = "Cases, alerts and tasks"`). A caller's instructions carry only the notes of backends they have a tool of. At most 12 notes; each at most 160 characters; names and notes together at most 480 characters. A key must be a valid registry name; an empty note is refused. |

Every `[analyst]` value is one line of valid UTF-8 with no leading or
trailing whitespace, no control, line-break or hidden character, and no
`"` or `\`. `serve` refuses to start if the instructions with every note
would exceed 2000 UTF-16 code units.

## [[role]]

A role is a name and the tools it may call (`design/adr/0009`, `0016`).
Roles are policy; changing one is a reviewed diff and a `reload`.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `name` | string | none | yes | Unique; not empty; no leading or trailing whitespace. |
| `tools` | list of strings | `[]` | no | Namespaced names, `BACKEND.TOOL` (`casemgmt.list_cases`), matched exactly. No wildcard: a name ending in `.*` is refused and the message points at `[role.grants]`. An un-namespaced name, an empty name, edge whitespace and a repeated name are refused. An empty list is valid: the role may authenticate and call nothing. |
| `non_read` | bool | `false` | no | Marks the role as one that may ACT (`design/adr/0048`). A sensitive tool (a REST operation with any method but `GET`/`HEAD`/`OPTIONS`) is served only to a caller holding a role with `non_read = true` that names the tool in `tools`, checked on every call; a `"*"` or named entry under `[role.grants]`, or the name in `tools` of a role without the marking, never reaches a sensitive tool. `tool clear` refuses unless some such role exists. Safe tools are unaffected by the marking. Refused at load: `non_read = true` on a role whose `tools` is empty (the marking reaches nothing). Reloadable; applies on the next call. |

### [role.grants]

Per-backend grants inside one `[[role]]`. Both forms are unioned within the
role; roles are unioned across a caller's groups.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `BACKEND` | list of strings | none | no | The key is a registered backend name; the values are that backend's own tool ids, without the namespace. `["*"]` grants every tool the backend advertises, now and later; it does not bypass the quarantine. |

Refused at load: an empty backend key or tool id; either with edge
whitespace; either containing `.`; `*` as a backend key; `*` mixed with
names; a repeated id; the same backend written twice in one role. A key
naming no registered backend loads, grants nothing, and is logged by
`serve` at start.

## [group_to_role]

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `"GROUP"` | string | none | no | The key is the exact value in the `groups_claim` claim; the value is a `[[role]]` name. A mapping to an undefined role, an empty group and a group with edge whitespace are refused. A group with no mapping is ignored. A caller with no mapped group has no role and can call nothing. |

## [[quota.provider]]

A per-analyst limit on one third-party account (`design/adr/0030`). The
counted unit is the account, not the backend and not the tool. With no
block, nothing is charged.

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `name` | string | none | yes | The account; the key its counter is stored under. Unique; no edge whitespace. Renaming it starts a new counter. |
| `upstream` | string | none | yes | The registered backend whose credential holds the account's key. |
| `limit` | integer | none | yes | Calls one analyst may make per `window`. Must be greater than zero; never read as "no limit". |
| `window` | duration | none | yes | The accounting period. Positive. Windows are fixed, aligned by truncation in UTC. |
| `tools` | list of strings | none | yes | The namespaced tools that spend the account; each call debits one unit. Not empty; no whitespace; no repeat; each on `upstream`. |

The worst case against a provider is `limit` times twice the number of
analysts: an analyst can spend `limit` just before a window boundary and
again just after. A call refused by quota debits nothing; a call that fails
at the backend has already debited.

Checked against the registry, not at load: if a named `upstream` is not
registered, or another entry declares one of its variables without being
budgeted, `serve` refuses to start and `reload` is refused; while `serve`
runs, reconciliation stops bringing up new backends and closes the one
spending the credential uncounted, until the two agree.

## [quota]

| Key | Type | Default | Required | Constraints and meaning |
|---|---|---|---|---|
| `free_tools` | list of strings | `[]` | when a budgeted backend serves a tool no account charges | Namespaced tools that spend no budgeted account. Every served tool of a backend some account names must be in an account's `tools` or here; one in neither is not routed, and `serve` says which. Not empty; no whitespace; no repeat; not also in an account's `tools`. |
