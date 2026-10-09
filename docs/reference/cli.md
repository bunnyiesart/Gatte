# Command line

This page is for operators who need the exact form of a command. It lists
every command and subcommand of `mcp-gateway`, who runs it, every flag with
its default, the exit codes, the audit rows it writes and the decision
record behind it. The binary's own `mcp-gateway help` and
`mcp-gateway COMMAND -h` are the source of this page.

## Conventions

These rules hold for every command unless its section says otherwise.

| Rule | Detail |
|---|---|
| Command first | `mcp-gateway COMMAND [SUBCOMMAND] [flags] [arguments]`. `mcp-gateway -config FILE` with no command is refused: the first argument is read as a command name. |
| `-config` | Every command except `sign -generate-key`, `ui` and `version` takes `-config FILE`. Default: `mcp-gateway.toml`, relative to the current directory. The whole file is loaded and validated, unknown keys included, before the command does anything. |
| Flag order | Flags go before positional arguments (`access block -reason TEXT SUBJECT`). Only `maintenance on/off`, `upstream maintenance on/off`, `reload` and `upstream redial` also accept flags after their arguments. |
| Help | `-h`, `--help` or `help` prints the usage to standard output and exits `0`. A usage error prints the error and the usage to standard error and exits `2`. |
| Exit codes | `0` ok; `1` the command ran and found a problem; `2` the command could not run (bad usage, a configuration that does not load, an unreachable database or dependency). |
| Output | Aligned tables for a person; `-json` where listed prints JSON instead. Text that comes from a backend, an IdP or a caller is printed with hidden code points written as `\u{XXXX}`; `-json` carries raw values. |
| Who runs it | **As root**; **as the service account** (`sudo -u mcpgw`); **as yourself**, an operator in the operator socket's group (`gatte-operators`). |
| Attribution | A command that writes an operator row attributes it to `(operator:NAME)`. `NAME` is, in order: the Linux login uid (`/proc/self/loginuid`, which survives `sudo`), then `SUDO_USER`, then `USER`, then the account database. The row's reason carries `[cli]` when the kernel gave the name, `[cli env]` when an environment variable did, and `[via ACCOUNT]` when the login uid named a person behind a shared account. See [Audit trail](audit-trail.md). |

Commands that open the database migrate its schema first and refuse a file
written by a newer binary (`design/adr/0045`). If you run such a command as
root, SQLite can leave root-owned `-wal` and `-shm` files that the service
account cannot write. Only `sign`, `backup`, `restore` and `check` drop to
the database directory's owner first.

## Command summary

| Command | Runs as | Purpose |
|---|---|---|
| [`serve`](#serve) | service account | Run the gateway. |
| [`upstream list`](#upstream-list) | service account | List registered backends and their signature state. |
| [`upstream register`](#upstream-register) | service account | Add a backend to the registry. |
| [`upstream update`](#upstream-update) | service account | Move an `oci` backend to a new image digest. |
| [`upstream deregister`](#upstream-deregister) | service account | Remove a backend from the registry. |
| [`upstream maintenance`](#maintenance-and-upstream-maintenance) | service account | Planned maintenance of one backend. |
| [`upstream redial`](#reload-and-upstream-redial) | service account | Drop and re-dial one backend in the running gateway. |
| [`tool list`](#tool-list) | service account | The approval queue. |
| [`tool show`](#tool-show) | service account | One tool's definition and diff. |
| [`tool review`](#tool-review) | service account | One backend's waiting tools and their manifest. |
| [`tool approve`](#tool-approve) | service account | Approve one tool, or one backend's review set. |
| [`tool revoke`](#tool-revoke) | service account | Withdraw an approval. |
| [`tool clear`](#tool-clear) | service account | Clear an approved sensitive tool for serving. |
| [`sign`](#sign) | root | Sign registry entries; create a signing key. |
| [`audit`](#audit) | service account | Read or verify the audit trail. |
| [`quota list`, `quota usage`](#quota) | service account | Declared limits and per-analyst spend. |
| [`access block`, `unblock`, `list`](#access) | service account | Per-analyst kill switch. |
| [`maintenance`](#maintenance-and-upstream-maintenance) | service account | Planned maintenance of the whole gateway. |
| [`reload`](#reload-and-upstream-redial) | service account | Apply `[[role]]`, `[group_to_role]` and `[quota]` without a restart. |
| [`admin`](#admin) | service account; root with `-accounts` | The management API on a UNIX socket. |
| [`ui`](#ui) | yourself; root or `account_group` with `-manage-users` | The web console on loopback. |
| [`check`](#check) | root | Offline checks of the configuration and the host's files. |
| [`backup`](#backup) | service account | A consistent, checked copy of the database. |
| [`restore`](#restore) | root | Replace the database with a checked backup. |
| [`version`](#version) | anyone | Print the build and the database schema. |

## serve

Runs the gateway until `SIGINT` or `SIGTERM`. `SIGHUP` (or `reload`) takes
the pending operator requests; with none pending, it reloads on behalf of
the signal.

```
mcp-gateway serve [-config FILE]
```

| | |
|---|---|
| Runs as | the service account |
| Flags | `-config FILE` (default `mcp-gateway.toml`) |
| Arguments | none |
| Exit codes | `0` clean shutdown; `2` any failure before the listener serves: a configuration that does not load, a vault that does not decrypt, an unreachable IdP, an unreadable registry, an address already in use, a `[quota]` that disagrees with the registry. |
| Audit rows | `(boot)` first; then every call and every gateway event. See [Audit trail](audit-trail.md). |
| Signals | `SIGINT`, `SIGTERM`: graceful stop, HTTP shutdown bounded to 15 s, then the backends are closed. `SIGHUP`: operator requests (`design/adr/0044`). |
| Decision records | `design/adr/0001`, `0011`, `0020`, `0044`, `0045` |

## upstream list

Prints every registry entry with its transport, command or image, the
variable names it declares and its signature state.

```
mcp-gateway upstream list [-config FILE] [-json]
```

| | |
|---|---|
| Runs as | the service account |
| Flags | `-json` (default off): print JSON. Each object carries `name`, `transport`, `command`, `args`, `url`, `image`, `network`, `network_error`, `env_var_names`, `signature`, `created_at`, `updated_at`. |
| SIGNED column | `yes` (valid signature by a trusted key), `no` (unsigned), `INVALID` (the entry changed after it was signed, or a key not in `signer.trusted_keys` signed it). |
| Exit codes | `0` ok, unsigned and `INVALID` entries included (they are reported below the table); `1` no entry is registered, or the table could not be written; `2` could not run. |
| Audit rows | none |
| Decision records | `design/adr/0006`, `0010`, `0033` |

## upstream register

Adds an entry to the registry. Registering does not sign; the gateway does
not trust the entry until root runs `sign NAME`.

```
mcp-gateway upstream register [-config FILE] -name NAME -transport stdio
                              -command CMD [-arg ARG ...] [-env VARNAME ...]
mcp-gateway upstream register [-config FILE] -name NAME -transport oci
                              -image NAME@sha256:HEX [-arg PODMAN-FLAG ...] [-env VARNAME ...]
mcp-gateway upstream register [-config FILE] -name NAME -transport http
                              -url BASE-URL -openapi FILE|URL
                              [-auth-kind bearer|header|query|none [-auth-name NAME]] [-env VARNAME]
```

| Flag | Default | Meaning |
|---|---|---|
| `-name NAME` | none, required | Entry name, `^[A-Za-z0-9][A-Za-z0-9_-]*$`; `gatte` in any case is reserved. |
| `-transport T` | `stdio` | `stdio` spawns a process; `oci` runs `podman run --rm -i`; `http` is a REST API the gateway itself calls, one tool per operation of the OpenAPI document `-openapi` names (`design/adr/0047`, `0048`). |
| `-command CMD` | none | The command to spawn, for `stdio`. |
| `-image REF` | none | For `oci`: `NAME@sha256:` plus 64 hex characters. A tag is refused. |
| `-arg ARG` | none | Repeatable, in order. For `stdio`, an argument of the command; for `oci`, a podman flag the signature covers. `--network` takes `none` (the default), `slirp4netns`, `pasta` or a podman network name; `host`, `private`, `container:*`, `ns:*` and `:options` are refused. |
| `-env VARNAME` | none | Repeatable. The name of a variable the vault resolves at spawn time. A `NAME=value` argument is refused and the value is not echoed. A `stdio` entry with `-env` is refused unless `[upstreams] allow_credentialed_stdio = true`. For `http`: exactly one, the secret `-auth-kind` injects; none for a keyless entry. |
| `-url URL` | none | For `http`: the base URL (scheme, host, port, base path) the signature covers and the adapter pins its client to -- the only destination this entry dials; a host the document names is ignored, and its `servers[0]` base path is folded in when `-url` has none. No userinfo, query or fragment; a literal loopback, private or link-local host is refused. |
| `-openapi FILE\|URL` | none, required for `http` | The OpenAPI 3.0.x/3.1.x document, JSON or YAML. A URL is fetched once, now, with no credential and under the gateway's own egress guard (no private or loopback address, no redirect off its origin, no userinfo or query in the URL, at most 4 MiB); a document that needs a credential to read is downloaded by the operator and passed as a file. Refused on `stdio` and `oci`. |
| `-auth-kind K` | derived or keyless | For `http`: where the secret `-env` names is injected on every call: `bearer` (`Authorization: Bearer`), `header` or `query` (the location `-auth-name` names), or `none` (keyless: nothing is derived, and the document's parameters are checked as for a keyless entry). Left out: keyless, unless the document declares exactly one `apiKey` or `http bearer` scheme, which is then derived and printed. |
| `-auth-name NAME` | none | With `-auth-kind header` or `query`: the header or query-parameter name. A document parameter on that name is refused (the server-side value wins). A control header (`Host`, `Connection`, `Cookie`, `Proxy-*`, ...) is refused as a `header` name, given or derived; `Authorization` is allowed. |

| | |
|---|---|
| Runs as | the service account |
| Takes effect | the running gateway dials the entry within one `quarantine.refresh_interval`, once it is signed |
| Exit codes | `0` registered; `1` a name already registered, a stored signature that is already `INVALID` for the new entry, or the signature state could not be read; `2` invalid flags, a refused entry, or a document that could not be read or ingested |
| Audit rows | none |
| Decision records | `design/adr/0003`, `0020`, `0028`, `0033`, `0034`, `0047`, `0048` |

For `http`, the output lists the tools generated (name, method, path, class),
the operations the document declares that were skipped (a body with no JSON
media type or on `GET`/`HEAD`/`OPTIONS`, `TRACE`/`CONNECT`), and the
ingestion's warnings (text from the document is printed escaped). A
response schema the gateway cannot compile is dropped with a warning, and
`HEAD`/`OPTIONS` tools never declare one. The set is
frozen with the entry and signed as a digest under `canonical/v3-http`; the
document is never re-read. `POST`, `PUT`, `PATCH` and `DELETE` tools are
`sensitive`: after approval each also needs `tool clear` and a role marked
`non_read` that grants it by name. A document naming a control header
(`Host`, `Transfer-Encoding`, ...), the credential's own slot, or a path with
a scheme, authority or `..` is refused, naming the operation and parameter.

## upstream update

Replaces the image of one `oci` entry in place and keeps its quarantine.
Each approval holds only while the new image advertises the byte-identical
definition; a differing one becomes `changed` at the next discovery. The
stored signature no longer verifies the entry, so the gateway refuses it
until root runs `sign NAME`. It does not re-ingest an `http` entry's
document: a changed API is deregistered and registered again.

```
mcp-gateway upstream update [-config FILE] -image NAME@sha256:HEX NAME
```

| | |
|---|---|
| Runs as | the service account |
| Flags | `-image REF` (required): the new digest-pinned image. |
| Arguments | `NAME`: the entry. |
| Exit codes | `0` updated and recorded; `1` no such entry, or updated but the audit row could not be written; `2` could not run |
| Audit rows | `(upstream update)` |
| Decision records | `design/adr/0043` |

## upstream deregister

Removes an entry, its stored signature, its quarantine state (so its
approvals are forgotten) and its maintenance and health state. The running
gateway closes it within one `quarantine.refresh_interval`. For a name that
is not registered, it still removes any state left under that name.

```
mcp-gateway upstream deregister [-config FILE] NAME
```

| | |
|---|---|
| Runs as | the service account |
| Exit codes | `0` removed; `1` no entry of that name (state left under it is removed anyway), or some state could not be removed; `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0013`, `0020` |

## tool list

Prints every tool the gateway has observed, pending and changed ones
included. A tool is usable only when it is approved and the definition
advertised now matches the approved one.

```
mcp-gateway tool list [-config FILE] [-server NAME] [-json]
```

| Flag | Default | Meaning |
|---|---|---|
| `-server NAME` | all | Only this backend's tools. |
| `-json` | off | JSON objects with `server`, `tool`, `status`, `usable`, `approved_hash`, `observed_hash`, `first_seen_at`, `updated_at`, and -- for a sensitive tool -- `class` (`"sensitive"`; absent for a safe tool) and `sensitive_cleared_hash` (the approved fingerprint it was cleared at; absent until cleared). `usable` already folds them in. |

After the table, a block `N SENSITIVE tool(s) approved and not yet cleared`
lists every tool that is approved, sensitive and held, each with the
`tool clear SERVER TOOL` command that finishes the job (`design/adr/0048`).

| | |
|---|---|
| Runs as | the service account |
| Status values | `pending` (never approved), `approved`, `changed` (approved, then the definition moved) |
| Exit codes | `0` ok; `1` no tool observed; `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0007`, `0013`, `0032` |

## tool show

Prints the definition the tool advertises; for a changed tool, the approved
one beside it and a line diff.

```
mcp-gateway tool show [-config FILE] SERVER TOOL
```

| | |
|---|---|
| Runs as | the service account |
| Flags | none besides `-config` |
| Exit codes | `0` ok; `1` no such tool; `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0032` |

## tool review

Prints every pending and changed tool of one backend as `tool show` prints
it, who can call each once approved, and the manifest: the hash of exactly
that set.

```
mcp-gateway tool review [-config FILE] -server NAME
```

| | |
|---|---|
| Runs as | the service account |
| Flags | `-server NAME` (required) |
| Exit codes | `0` ok, including nothing to approve; `1` nothing observed on that backend, or the set cannot be approved; `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0043` |

## tool approve

Approves one tool at the fingerprint you reviewed, or one backend's whole
review set at its manifest. Both forms print what is approved first.
Approving is not granting: a tool is callable only when a role grants it.

```
mcp-gateway tool approve [-config FILE] -fingerprint SHA256 SERVER TOOL
mcp-gateway tool approve [-config FILE] -server NAME -manifest SHA256
```

| Flag | Default | Meaning |
|---|---|---|
| `-fingerprint SHA256` | none | The full hash of the definition you reviewed, with or without `sha256:`. Without it nothing is approved and the command to run is printed. If the tool advertises another fingerprint by then, the command refuses. |
| `-server NAME` | none | With `-manifest`: the backend whose review set to approve. |
| `-manifest SHA256` | none | With `-server`: the manifest `tool review` printed. If any tool of the backend joined, left or changed since, nothing is approved. |

`-server`/`-manifest` cannot be combined with `-fingerprint` or with
`SERVER TOOL`.

| | |
|---|---|
| Runs as | the service account |
| Takes effect | next call; no restart |
| Exit codes | `0` approved and recorded; `1` not approved (no `-fingerprint`, fingerprint or manifest moved, definition not kept), or approved but not recorded; `2` could not run |
| Audit rows | `(tool approve)` per tool, with ` (sensitive; not served until cleared)` for a sensitive one; `(tool approve set)` once for a set |
| Decision records | `design/adr/0007`, `0016`, `0032`, `0043`, `0048` (sensitive tools: approved, not served until `tool clear`) |

## tool revoke

Returns an approved tool to `pending`. The running gateway stops serving it
on the next call. The upstream is not touched. A `changed` tool cannot be
revoked: it is already not served, and revoking would erase the record of
the replaced definition.

```
mcp-gateway tool revoke [-config FILE] SERVER TOOL
```

| | |
|---|---|
| Runs as | the service account |
| Takes effect | next call; no restart |
| Exit codes | `0` revoked, or already pending; `1` no such tool, a `changed` tool, a corrupt row, or revoked but not recorded; `2` could not run |
| Audit rows | `(tool revoke)`; a revoke also withdraws a clearance (no row of its own) |
| Decision records | `design/adr/0007`, `0013` |

## tool clear

The second decision a sensitive tool needs, after approval
(`design/adr/0048`). Approving says the definition is not poisoned;
clearing says this backend may ACT on the team's behalf through this
operation. A sensitive tool -- a REST operation with any method but `GET`,
`HEAD` or `OPTIONS` -- is approved like any other and NOT served until
cleared; `tool approve` says so, and `tool list` lists what is held.
Approving a set (`-server -manifest`) never clears anything.

```
mcp-gateway tool clear [-config FILE] SERVER TOOL
```

Before writing, it prints the roles the clearance will reach: those with
`non_read = true` that name the tool in `tools`. It refuses when there is
none, naming role by role what covers the tool and why that does not reach
it -- a `"*"` grant, a `[role.grants]` name, or the name on a role without
the marking -- and the edit that would. The clearance is of the approved
fingerprint: a later change to the definition, or `tool revoke`, withdraws
it with the approval, and re-approving does not re-clear. Clearing an
already-cleared tool changes nothing and writes nothing.

| | |
|---|---|
| Runs as | the service account |
| Flags | none besides `-config` |
| Takes effect | next call; no restart. The gateway still asks, on every call, whether the caller holds a `non_read` role naming the tool. |
| Exit codes | `0` cleared and recorded, or already cleared; `1` not cleared -- not a sensitive tool (`not_sensitive`), not approved or the baseline moved while clearing (`not_approved`), no `non_read` role names it (`no_non_read_grant`), no such tool, a corrupt row -- or cleared but not recorded; `2` could not run |
| Audit rows | `(tool clear)` |
| Decision records | `design/adr/0047`, `0048` |

## sign

Signs registry entries with the Ed25519 key at `signer.key_file` and stores
the signatures. A signature covers what the entry runs (command or image,
arguments, variable names) and no secret value. The gateway accepts a
signature only from a key in `signer.trusted_keys`; if the signing key is
not listed, the command prints the line to add.

```
mcp-gateway sign [-config FILE] NAME
mcp-gateway sign [-config FILE] -all -dry-run
mcp-gateway sign [-config FILE] -all -manifest SHA256
mcp-gateway sign -generate-key -out PATH
```

| Flag | Default | Meaning |
|---|---|---|
| `-all` | off | Sign every entry not validly signed by this key: unsigned, `INVALID`, or signed by another key. Takes no `NAME`. |
| `-dry-run` | off | With `-all`: print each entry with the fields its signature covers, and the plan's manifest; sign nothing. |
| `-manifest SHA256` | none | With `-all`: sign exactly the plan `-dry-run` printed, and nothing if any entry joined, left or changed since. |
| `-generate-key` | off | Create a new Ed25519 key at `-out` and print the `[signer]` lines to paste. Reads no configuration file. Refuses to overwrite an existing file. Does not edit the configuration. |
| `-out PATH` | none | With `-generate-key`: the file to create, `0600`. |

| | |
|---|---|
| Runs as | root. As root, `sign` reads the configuration and the key, then becomes the owner of the database directory before it opens the database. |
| Key file | Must be owner-only; a group- or world-readable key is refused. |
| Refusals | An entry the dialer would refuse, or a credentialed `stdio` entry without `[upstreams] allow_credentialed_stdio`, is not signed. |
| Takes effect | the running gateway dials a newly valid entry within one `quarantine.refresh_interval` |
| Exit codes | `0` ok; `1` no such entry, a refused entry, or a moved plan; `2` could not run (no key configured, bad flags) |
| Audit rows | none |
| Decision records | `design/adr/0006`, `0010`, `0044`, `0045` |

## audit

Prints the most recent matching records, newest first, or verifies the hash
chain.

```
mcp-gateway audit [-config FILE] [-limit N] [-since RFC3339] [-until RFC3339]
                  [-subject IDENTITY] [-outcome allowed|denied|failed]
                  [-source ADDRESS] [-tool SERVER.TOOL] [-server SERVER] [-json]
mcp-gateway audit -verify [-config FILE] [-expect-head HASH]
```

| Flag | Default | Meaning |
|---|---|---|
| `-limit N` | `50` | Show at most this many of the most recent matches; `0` for all. Negative is refused. |
| `-since T` | none | Records at or after this RFC 3339 time (inclusive). |
| `-until T` | none | Records before this RFC 3339 time (exclusive). Must be after `-since`. |
| `-subject ID` | none | Exact match on ANALYST (the IdP `sub`, or `(operator:NAME)`, `(gateway)`, `(unauthenticated)`). Never matches NAME. |
| `-outcome O` | none | `allowed`, `denied` or `failed`. |
| `-source ADDR` | none | Exact match on SOURCE. |
| `-tool T` | none | Exact match on TOOL: `SERVER.TOOL`, or a special row such as `(access block)`. |
| `-server S` | none | Exact match on UPSTREAM. |
| `-json` | off | JSON array; see [Audit trail](audit-trail.md) for the keys. |
| `-verify` | off | Check the hash chain instead of printing records. Cannot be combined with any filter above, `-json` included. |
| `-expect-head HASH` | none | With `-verify`: fail unless the chain head equals this hash (case-insensitive). |

Filters match exactly and combine with AND.

| | |
|---|---|
| Runs as | the service account |
| Table columns | `TIME`, `ANALYST`, `NAME`, `SOURCE`, `TOOL`, `UPSTREAM`, `OUTCOME`, `REASON`; `-` means empty or older than the column. |
| Exit codes | `0` ok, or chain intact (and head as expected); `1` nothing matched, `TAMPERED` (a break in the chain), or `TRUNCATED OR REWRITTEN` (head differs from `-expect-head`); `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0012`, `0015`, `0017`, `0037`, `0046` |

## quota

Shows the declared per-analyst limits and the counters. The counted unit
is an account at a third party, not a backend and not a tool. No command
lowers a counter. A changed limit is an edit to `[[quota.provider]]`,
applied by `reload`.

```
mcp-gateway quota list  [-config FILE] [-json]
mcp-gateway quota usage [-config FILE] [-analyst SUBJECT] [-account NAME] [-since RFC3339] [-json]
```

| Subcommand | Flag | Default | Meaning |
|---|---|---|---|
| `list` | `-json` | off | Print JSON. |
| `usage` | `-analyst SUBJECT` | all | Exact match on the trail's ANALYST value. |
| `usage` | `-account NAME` | all | Exact match on a `[[quota.provider]]` name. |
| `usage` | `-since T` | none | Windows starting at or after this RFC 3339 time. |
| `usage` | `-json` | off | Print JSON. |

| | |
|---|---|
| Runs as | the service account |
| Table columns | `list`: `ACCOUNT`, `UPSTREAM`, `LIMIT`, `WINDOW`, `TOOLS`. `usage`: `WINDOW START`, `ANALYST`, `ACCOUNT`, `USED`, `LIMIT`, `REMAINING`. |
| Exit codes | `0` ok; `1` nothing to show, or the registry and the file disagree; `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0030` |

## access

Blocks or unblocks one analyst's IdP subject in the running gateway, or
lists who is blocked. A block does not revoke anything at the IdP.

```
mcp-gateway access block   [-config FILE] [-reason TEXT] [-until TIME|DURATION] SUBJECT
mcp-gateway access unblock [-config FILE] [-reason TEXT] SUBJECT
mcp-gateway access list    [-config FILE] [-json]
```

| Subcommand | Flag | Default | Meaning |
|---|---|---|---|
| `block`, `unblock` | `-reason TEXT` | none | Recorded in the audit trail, never shown to the analyst. The stored note (`[cli] TEXT`) is at most 256 bytes, with no control character. |
| `block` | `-until V` | none | End the block by itself: an RFC 3339 time, or a positive duration from now (`8h`, `90m`). `none` means no end. Must be in the future. |
| `list` | `-json` | off | JSON objects with `subject`, `blocked_by`, `blocked_at`, `reason`, `until`, `expired`. |

`SUBJECT` is the token's `sub`, exactly as the ANALYST column shows it: not
empty, no edge whitespace, at most 256 bytes, no control or invisible format
character.

| | |
|---|---|
| Runs as | the service account |
| Takes effect | the next request of that subject; no restart. Blocks survive restarts. A block with `-until` stops refusing at its end; the next maintenance round writes `(access block expired)` and removes it. A subject already blocked keeps its block and its end. |
| Exit codes | `0` ok, including "already blocked" and an empty list; `1` unblocking a subject that is not blocked, or a block in force that could not be recorded; `2` could not run |
| Audit rows | `(access block)`, `(access unblock)` |
| Decision records | `design/adr/0031`, `0046` |

## maintenance and upstream maintenance

Announces planned maintenance of one backend (`upstream maintenance`) or of
the whole gateway (`maintenance`), ends it, or lists it. A backend in
maintenance keeps its tools listed and answers each call with your message
without calling the backend. The whole gateway in maintenance is a notice:
calls are still served, and text results and `gatte.status` carry it.

```
mcp-gateway upstream maintenance on  [-config FILE] NAME -message TEXT [-until RFC3339|DURATION|none]
mcp-gateway upstream maintenance off [-config FILE] NAME
mcp-gateway upstream maintenance list [-config FILE] [-json]
mcp-gateway maintenance on   [-config FILE] -message TEXT [-until RFC3339|DURATION|none]
mcp-gateway maintenance off  [-config FILE]
mcp-gateway maintenance list [-config FILE] [-json]
```

| Flag | Default | Meaning |
|---|---|---|
| `-message TEXT` | none, required with `on` | What analysts and their models read. Trimmed; 1 to 200 characters; one line; no control, line-break or hidden character. |
| `-until V` | keep | The announced end: an RFC 3339 time or a duration from now, in the future and at most 90 days ahead. A forecast, not a deadline. Without `-until`, an `on` that updates a maintenance keeps the end already announced (dropped, with a note, if it has passed). `-until none` takes the end back. |
| `-json` | off | With `list`: print JSON. |

| | |
|---|---|
| Runs as | the service account |
| Takes effect | the running gateway's next call; no restart |
| Repeated `on` | changes the message, and the end when `-until` is given; keeps the start |
| Exit codes | `0` ok, including "already in maintenance with this message and end"; `1` `off` of something not in maintenance, or a change the trail could not record; `2` could not run (bad message or end, unknown backend) |
| Audit rows | `(maintenance on)`, `(maintenance off)` |
| Decision records | `design/adr/0041` |

## reload and upstream redial

Both file a request in the database, send `SIGHUP` to the `serve` process
recorded there, and wait for its answer.

`reload` asks `serve` to re-read its own configuration file and apply
`[[role]]`, `[group_to_role]` and `[quota]` from the next call on. The
whole file is loaded and validated first; if it does not load, or the new
`[quota]` disagrees with the registry, nothing changes. It prints who gains
and loses which tool, which grants and groups changed, and every other key
that differs from the file `serve` started with and is not applied until a
restart. See [Configuration](configuration.md) for which keys are which.

`upstream redial` drops `serve`'s connection to one backend and dials it
again with the vault as it is now. Its calls are answered as reconnecting
until the new process has been listed.

```
mcp-gateway reload [-config FILE] [-wait 2m] [-json]
mcp-gateway upstream redial [-config FILE] [-wait 2m] [-json] NAME
```

| Flag | Default | Meaning |
|---|---|---|
| `-wait D` | `2m` | How long to wait for `serve`'s answer; must be positive. `serve` takes a request later if it is busy; the command then prints `PENDING` with the request's id. |
| `-json` | off | Print `serve`'s answer as JSON. |

| | |
|---|---|
| Runs as | the service account. Run as root, the request is filed and then refused before `serve` is signalled (`serve_not_rung`). |
| Takes effect | `reload`: the next call. Clients that already listed their tools keep that list until they reconnect (Claude Code: `/mcp`); a call to a tool a role lost is refused at once. `redial`: after one round, for that backend only. |
| Refusal codes | `invalid_config`, `quota_mismatch`, `registry_unavailable` (reload); `not_servable`, `held_back` (redial); `superseded_by_restart` (answered by a restarted `serve`); `serve_not_rung` |
| Exit codes | `0` applied; `1` refused, still pending, or (redial) no such backend; `2` could not run: `serve` is not running on this database, or the file does not load here |
| Audit rows | `(config reload)`, `(upstream redial)`, written by `serve`. A bare `SIGHUP` writes `(config reload)` attributed to `(gateway)` with `[signal]`. |
| Decision records | `design/adr/0044` |

## admin

Serves the management API (`api/admin.openapi.yaml`, [Management
API](../admin-api.md)) on a UNIX socket and on nothing else. The operator
is whoever the kernel says connected.

```
mcp-gateway admin [-config FILE] [-socket PATH] [-socket-group GROUP] [-socket-mode 0660] [-idle 5m]
mcp-gateway admin -accounts [-config FILE] [-socket PATH] [-socket-group GROUP] [-socket-mode 0660] [-idle 5m]
```

| Flag | Default | Meaning |
|---|---|---|
| `-accounts` | off | Serve the accounts socket (the IdP's users file) instead of the operator socket. Root only. Needs `[idp] users_file`. |
| `-socket PATH` | `/run/mcp-gateway-admin/operator/operator.sock`; with `-accounts`, `/run/mcp-gateway-admin/accounts/accounts.sock` | The socket to create, when not socket-activated. |
| `-socket-group GROUP` | the process's group | The socket file's group. |
| `-socket-mode MODE` | `0600`; `0660` with `-socket-group` | Octal. `0600`, or `0660` with a group; nothing for others. |
| `-idle D` | `5m` | Exit after this long with no request; `0` never exits. In the foreground the default is `0` unless `-idle` is given. |
| `-audit-writer`, `-block-writer` | off | Internal: the accounts backend's children, run as the database's owner. Not for operators. |

| | |
|---|---|
| Runs as | operator socket: the service account; root is refused. `-accounts`: root only. |
| Socket rules | Under systemd the socket comes from the `.socket` unit (`examples/systemd/`). In the foreground, the socket's directory and every directory above it must be root's, not a symbolic link, and not writable by group or others; the operator socket's own directory may be the service account's. An operator socket open to others, or whose group differs from `[admin] operator_group`, refuses to start. An accounts socket open to others, or not matching `[admin] account_group` (group and `0660`), refuses to start. See [Files and permissions](files-and-permissions.md). |
| Per request | The operator backend re-reads the configuration for every operation. The accounts backend first checks that `config.toml`, `[idp] users_file` and every directory above them are root's, regular, not symbolic links and not writable by group or others. |
| Exit codes | `0` stopped cleanly (idle or signal); `2` could not run |
| Audit rows | the rows of each action it serves; see [Audit trail](audit-trail.md) |
| Decision records | `design/adr/0038`, `0040`, `0046` |

## ui

Serves the operator console as a web page on loopback. It is a client of
the management API: every page is a call over the operator socket, and
every button is the API's action of the same name. It reads no
configuration file and opens no database. Registering and signing a backend
stay in the terminal.

```
mcp-gateway ui [-socket PATH] [-listen 127.0.0.1:8090] [-manage-users [-accounts-socket PATH]]
```

| Flag | Default | Meaning |
|---|---|---|
| `-listen ADDR` | `127.0.0.1:8090` | Must be loopback. |
| `-socket PATH` | `/run/mcp-gateway-admin/operator/operator.sock` | The operator socket. |
| `-manage-users` | off | Also open the accounts socket, to edit the IdP's accounts. Refused when that socket's server is not root. |
| `-accounts-socket PATH` | `/run/mcp-gateway-admin/accounts/accounts.sock` | The accounts socket, for `-manage-users`. |
| `-config` | none | Refused if given: the console reads no configuration file. |

| | |
|---|---|
| Runs as | yourself, as a member of the operator socket's group. With `-manage-users`: with `sudo`, or as a member of `[admin] account_group` when the accounts socket is delegated. |
| Login | Prints a `/login` link carrying a random token; the browser keeps a cookie for this run. |
| Exit codes | `0` stopped; `2` could not run (socket unreachable, non-loopback `-listen`, a build with `-tags nofront`) |
| Audit rows | the API's rows, tagged `[ui]` and attributed from the kernel's peer credentials |
| Decision records | `design/adr/0036`, `0040` |

## check

Checks the configuration and this host's files before `serve` is started,
without changing anything, and prints the fix for each problem. The
database is opened read-only; no backend is started. The full list of what
it verifies is in [Files and permissions](files-and-permissions.md#what-check-verifies).

```
mcp-gateway check [-config FILE] [-user NAME] [-online] [-json]
```

| Flag | Default | Meaning |
|---|---|---|
| `-user NAME` | the owner of the database's directory, or the user running `check` when that is not root | The account `serve` runs as; the ownership checks are about it. |
| `-online` | off | Also fetch the IdP's discovery document. |
| `-json` | off | JSON object with `config`, `service_account`, `checks` (`name`, `status`, `detail`, `fix`), `failed`, `warnings`. |

| | |
|---|---|
| Runs as | root: only root can read the signing key's metadata and the age key. As root it becomes the database directory's owner before it opens the database. |
| Verdicts | `PASS`, `WARN`, `FAIL`, `SKIP` |
| Not checked | ACLs and MAC policy, the service manager's `PATH` and limits, the proxy in front, whether each backend answers |
| Exit codes | `0` no check failed (warnings allowed); `1` at least one `FAIL`; `2` could not run (bad usage, an unknown `-user`) |
| Audit rows | none |
| Decision records | `design/adr/0045` |

## backup

Writes a consistent copy of the database (SQLite `VACUUM INTO`) while
`serve` runs, then checks the copy: SQLite integrity, the audit chain, and
every registry entry's signature against this configuration's trusted keys.
It never migrates the live database, so a new binary can take the copy
before an upgrade while the old `serve` still runs. It prints the paths of
what is not in the copy.

```
mcp-gateway backup [-config FILE] -out FILE|DIR [-keep N] [-json]
```

| Flag | Default | Meaning |
|---|---|---|
| `-out PATH` | none, required | A new file, or an existing directory where the copy is named `mcp-gateway-YYYYMMDDTHHMMSSZ.db`. |
| `-keep N` | `0` (keep all) | With a directory `-out`: remove all but the newest `N` copies of that name. |
| `-json` | off | Print the result as JSON. |

| | |
|---|---|
| Runs as | the service account. As root, it first becomes the owner of the database's directory. |
| The copy | Mode `0600`, written in a private directory beside the destination and renamed into place. |
| Not in the copy | the configuration file, the vault, the age key, the signing key, the IdP's accounts, the SIEM copy of the trail, the connect scripts' CA (`connect.ca_file`), the proxy's TLS material, `oci` images |
| Exit codes | `0` ok; `1` a problem found: a copy whose chain is broken is still written and says so; a database written by a newer binary; `2` could not run |
| Audit rows | none |
| Decision records | `design/adr/0045` |

## restore

Replaces the database with a backup, with `serve` stopped. It refuses, and
changes nothing, unless the file passes SQLite's integrity check, its
schema is one this binary knows (with no object the binary did not create),
its audit chain verifies (and ends at `-expect-head`, when given), and no
registry entry carries a signature that fails against this configuration's
trusted keys.

```
mcp-gateway restore [-config FILE] -in FILE [-expect-head HASH]
```

| Flag | Default | Meaning |
|---|---|---|
| `-in FILE` | none, required | The backup to restore; a regular file, not the live database. |
| `-expect-head HASH` | none | Refuse unless the backup's audit chain ends at this hash. |

| | |
|---|---|
| Runs as | root. It opens `-in` as root, then becomes the owner of the database's directory before writing anything there. |
| Serve stopped | It binds `listen`; if something already listens there, it refuses. It does not look for the management API's sockets: stop them too. |
| Files | The replaced database, with its `-wal` and `-shm`, is kept as `FILE.pre-restore-YYYYMMDDTHHMMSSZ` beside it. |
| Exit codes | `0` restored and recorded; `1` refused (nothing changed), `serve` still running, or restored but the row could not be written; `2` could not run |
| Audit rows | `(restore)`, in the restored trail |
| Decision records | `design/adr/0045`; see also [Upgrade Gatte, and roll back](../upgrade.md) |

## version

Prints the build identity and the database schema this binary writes.

```
mcp-gateway version
```

| | |
|---|---|
| Runs as | anyone |
| Output | `mcp-gateway VERSION (database schema N)`. `VERSION` is the link-time version (`dev` by default) plus the source revision, when the binary was built from a checkout. |
| Exit codes | `0` |
| Decision records | `design/adr/0045` |
