# Audit trail

This page is for operators and SIEM engineers who read or alert on Gatte's
audit trail. It describes the record and its names in every store, the
outcomes, the hash chain and how to verify it, the heartbeat, and every
row Gatte and its operators write that is not a tool call. The code is
`internal/audit`, its `sqlite` and `jsonl` adapters, and
`internal/telemetry/gelf`.

## Where the trail lives

| Store | Configured by | Written | Holds |
|---|---|---|---|
| SQLite table `audit_records` | `database` | always, first | every record, with its hash chain; the source of truth |
| JSON Lines file | `[audit.siem]` | after the SQLite write committed | every record, with `prev_hash` and `hash`; the heartbeat |
| GELF messages | `[telemetry]` | after the SQLite write committed | every record, without hashes; a gap message after an outage |

A failure of the JSONL or GELF copy is logged at ERROR and does not refuse
the call. A call whose SQLite row cannot be written first is refused
("refusing unauditable call"). Operator commands write their rows through
the same recorder as `serve`: SQLite, then the JSONL file, then GELF.

## The record

| Field | SQLite column | `audit -json` | JSONL key | GELF field | Management API | Meaning |
|---|---|---|---|---|---|---|
| Analyst identity | `analyst_identity` | `analyst_identity` | `caller` | `_analyst_identity` | `analyst_identity` | Who: the IdP's `sub`, or a marker in parentheses (below). Required. The attribution. |
| Analyst name | `analyst_name` | `analyst_name`, omitted when empty | `analyst_name`, omitted when empty | `_analyst_name`, omitted when empty | `analyst_name` | The IdP's display name at the time of the call. Display only; never filtered on. Empty when it would repeat the subject, and on every row nobody authenticated for. At most 256 bytes; hidden code points written visibly. |
| Tool | `tool` | `tool` | `tool` | `_tool` | `tool` | `BACKEND.TOOL` for a call; a name in parentheses for a special row. Required. |
| Target upstream | `target_upstream` | `target_upstream` | `backend` | `_target_upstream` | `target_upstream` | The backend that served the call, or `(gateway)`, or `(unknown)`. Required. |
| Timestamp | `timestamp` (RFC 3339, nanoseconds, text) | `timestamp` | `ts` (RFC 3339, nanoseconds, UTC) | `timestamp` (epoch seconds) | `timestamp` | When. Required. |
| Outcome | `outcome` | `outcome` | `verdict` | `_outcome` | `outcome` | `allowed`, `denied` or `failed`. Required. |
| Reason | `reason` | `reason`, omitted when empty | `rule` | `_reason`, omitted when empty | `reason` | The operator-facing classification the caller is not told, from a closed set of the gateway's own strings. Never backend text. |
| Source address | `source_address` | `source_address`, omitted when empty | `src` | `_source_address`, omitted when empty | `source_address` | Where the request came from: the rightmost `X-Forwarded-For` entry, else the TCP peer without its port. Empty for a row with no network peer. |
| Previous hash | `prev_hash` | not shown | `prev_hash` | not sent | not shown | The hash of the record before, `""` for the first. |
| Hash | `hash` | not shown | `hash` | not sent | not shown | This record's chain hash. |
| Position | `id` | not shown | not sent | not sent | `position` | Insertion order, 1-based. |

Fixed fields of each line or message:

| Store | Field | Value |
|---|---|---|
| JSONL | `v` | `5`, the schema version shared by records and heartbeats |
| JSONL | `type` | `record` |
| JSONL | `chain` | `audit.siem.chain` |
| GELF | `version` | `1.1` |
| GELF | `host` | `telemetry.host` |
| GELF | `short_message` | `mcp-gateway OUTCOME TOOL` |
| GELF | `level` | `6` for `allowed`, `5` for `denied`, `4` for `failed` |
| GELF | `_event_kind` | `audit` |
| GELF | `_cliente_soc` | `telemetry.cliente_soc` |

No store ever carries a bearer token, a credential value, tool arguments,
tool results, backend error text or IdP group claims.

## Outcomes

| Outcome | Meaning |
|---|---|
| `allowed` | The call passed every gate and was dispatched; or a special row recording something done or observed. |
| `denied` | The gateway refused before dispatching; or a gateway event refusing to serve something (a new tool, a changed tool, a refused signature, a backend down). |
| `failed` | The call was dispatched and did not come back, or its result was refused on the way out. |

A dispatched call that fails writes two rows: `allowed` before the call and
`failed` after, never an edit of the first. Count `allowed` rows for
attempts and read a `failed` row as an annotation on the `allowed` row
before it. Heartbeat counters and SIEM message counts follow the same
rule.

## Identity markers

| ANALYST value | Meaning |
|---|---|
| an IdP `sub` | An authenticated analyst. |
| `(unauthenticated)` | A request refused at the door: no credential, or one that did not verify. The two are not told apart. |
| `(gateway)` | Gatte itself: an event it observed, a boot, an expired block, a reload rung by a bare `SIGHUP`. |
| `(operator:NAME)` | An operator action. `NAME` is the system account; see [Command line](cli.md#conventions) for how the CLI chooses it. The management API takes it from the kernel's peer credentials; for a root peer, the login uid names the person and the row carries `[via root]`. |
| `(unknown)` | An operator request for `serve` that named nobody; applied or refused like any other. |

No IdP issues a subject in parentheses, so none of these can be read as an
analyst.

## Rows for a tool call

TOOL is `BACKEND.TOOL`, or `gatte.status` for the built-in tool (UPSTREAM
`(gateway)`). A tool call that supplied no name is recorded as `(unnamed)`;
a name that does not parse into backend and tool is recorded with UPSTREAM
`(unknown)`.

### Reasons of `denied` call rows

| Reason | Cause |
|---|---|
| `authentication failed` | No usable bearer credential, or it did not verify. TOOL `(authentication)`, UPSTREAM `(gateway)`, ANALYST `(unauthenticated)`. |
| `auth failures rate-limited` | One row for a source over its budget of authentication-failure rows (5/s per source, burst 20; 50/s overall, burst 200; one such row per source per minute). Further failures in the window are logged and not written. |
| `subject blocked` | The subject is blocked (`access block`). TOOL `(authentication)` at admission. |
| `blocklist unavailable` | The blocklist could not be read; the request was refused. |
| `not visible to caller` | A `tools/call` for a name that was not on this caller's own tool list: another role's tool, an unapproved one, one skipped for its schema, or a guess. |
| `registry unavailable` | The registry could not be read; nothing is served until it can (`design/adr/0020`). |
| `unknown tool` | No route matched the name. |
| `forbidden` | The caller's roles do not reach the tool. |
| `sensitive tool requires an explicit grant in a non-read role` | The caller's roles reach the tool by name, but the tool is sensitive (it can act) and no role of the caller with `non_read = true` names it in `tools` -- a `"*"` grant or a `[role.grants]` name never reaches a sensitive tool (`design/adr/0048`). The caller is answered exactly as for `forbidden`; only this row tells the two apart. |
| `quarantined` | The tool is not approved, or changed since its approval; or it is sensitive, approved, and not yet cleared (`tool clear`). |
| `quarantine unavailable` | The approval store could not be read. |
| `backend in maintenance` | The backend has an open maintenance. The call was not sent. |
| `backend unavailable: down` | No dial is scheduled for the backend (held back by a quota mismatch). |
| `backend unavailable: reconnecting` | The backend has no live, listed connection; Gatte is re-dialling it. |
| `concurrency limited` | The caller already had `max_concurrent_calls_per_analyst` calls in flight. |
| `quota exhausted` | The caller's allowance on an account the tool spends is used up for this window. Nothing was debited. |
| `quota unavailable` | The counter could not be read or written. |
| `internal error` | A panic inside Gatte before dispatch; TOOL `(request)` when no tool had been named. |

### Reasons of `failed` call rows

| Reason | Cause |
|---|---|
| `upstream timed out` | `response.call_timeout` ran out. |
| `call cancelled` | The caller or the process went away first. |
| `upstream gone` | The backend's process was found gone during the call. |
| `upstream call failed` | Any other failure: an error from the backend, a broken transport, an unrepresentable result. |
| `result too large` | The result exceeded `response.max_bytes`; it was not delivered. |
| `result violates output schema` | `structuredContent` did not match the tool's declared `outputSchema`. |
| `internal error` | A panic inside Gatte after dispatch. |

An `allowed` call row has an empty reason.

## Special rows

Every row that is not a tool call. UPSTREAM is `(gateway)` unless the table
says otherwise. `TAG` is where the action came from: `[cli]`, `[cli env]`,
`[ui]`, `[api]`, a third-party front's name in brackets, optionally followed
by `[via ACCOUNT]`; `[signal]` for a bare `SIGHUP`.

### Operator rows

| TOOL | Written by | Outcome | Reason format |
|---|---|---|---|
| `(tool approve)` | `tool approve`; API/console approve | `allowed` | `tool "SERVER.TOOL" approved at sha256:HASH TAG`; with ` (was sha256:OLD)` after the hash when it replaced another baseline; with ` (sensitive; not served until cleared)` when the tool is sensitive (before ` (was …)` for a single approval, after it in a set); in a set, ` in review set sha256:MANIFEST` before `TAG` |
| `(tool approve set)` | `tool approve -server -manifest`; API/console | `allowed` | `review set sha256:MANIFEST of backend "NAME" approved: N tool(s) (P pending, C changed) TAG`; written after the per-tool `(tool approve)` rows. A set never clears a sensitive tool. |
| `(tool revoke)` | `tool revoke`; API/console | `allowed` | `tool "SERVER.TOOL" revoked, was approved at sha256:HASH TAG` |
| `(tool clear)` | `tool clear`; API/console (`design/adr/0048`) | `allowed` | `tool "SERVER.TOOL" cleared for sensitive serving at sha256:HASH TAG`. Written only when a role marked `non_read` names the tool in `tools`; a refused clearance writes no row. A revoke or a changed definition withdraws the clearance with the approval, and writes no row of its own beyond `(tool revoke)` or the `tool changed: …` event row of the tool. |
| `(access block)` | `access block`; API/console; the block of an offboard | `allowed` | `subject "SUB": TAG NOTE`; with ` until T` after the subject when the block has an end; with ` [replaces the expired block placed by BY at T, ended T]` when it replaces an expired, unrecorded block. For an offboard, `NOTE` is `offboard of account "USER"` and `; REASON` when given. |
| `(access unblock)` | `access unblock`; API/console | `allowed` | `subject "SUB": TAG NOTE`. Written before the block is lifted; if it cannot be written, the subject stays blocked. |
| `(maintenance on)` | `maintenance on`, `upstream maintenance on`; API/console | `allowed` | `gateway: TAG END: "MESSAGE"` or `upstream "NAME": TAG END: "MESSAGE"`; `END` is `no announced end` or `until T` |
| `(maintenance off)` | `maintenance off`, `upstream maintenance off`; API/console | `allowed` | `gateway: TAG` or `upstream "NAME": TAG` |
| `(config reload)` | `serve`, for `reload`, the API, or a bare `SIGHUP` | `allowed` when applied, `denied` when refused | `TAG applied: SUMMARY` or `TAG refused (CODE): ERROR`; a request answered by a restarted `serve` reads `TAG refused`. `SUMMARY` is `; `-separated parts: `role "R"` with ` added` or ` removed`, `+TOOL` gained, `-TOOL` lost, ` grant +G -G` for a rewritten grant, and ` non_read=true` or ` non_read=false` when the marking changed; `group "G": "FROM" -> "TO"` (`(none)` for no role); `quota "ACCOUNT" added\|removed\|changed`; `quota.free_tools changed`; or `no change to roles, groups or quota`; then `NOT applied until restart: KEYS`. Cut at 4000 bytes, ending ` ... (truncated; the full diff is in the request result)`. |
| `(upstream redial)` | `serve`, for `upstream redial` or the API | `allowed` when done, `denied` when refused | UPSTREAM is the backend's name. `TAG was connected: true\|false; live after the round: true\|false`, with ` (CAUSE)` when not live; or `TAG refused (not_servable\|held_back): ERROR` |
| `(upstream update)` | `upstream update` | `allowed` | `upstream "NAME" image OLD -> NEW; quarantine kept: A approved, P pending, C changed; approvals hold only for identical definitions; signature must be renewed TAG` |
| `(upstream register)` | API/console operator socket, with `console_manages` (`design/adr/0050`) | `allowed` | `upstream "NAME" registered: http URL, N operation(s) (S safe, K sensitive), auth KIND[ NAME][ <SECRET>] TAG`; `SECRET` is the vault name, never a value |
| `(upstream deregister)` | API/console operator socket, with `console_manages` | `allowed` | `upstream "NAME" deregistered: registered true\|false, signature removed true\|false, N quarantine entr(y\|ies) removed TAG`. A name with nothing left under it writes no row. |
| `(upstream sign)` | API/console accounts socket, with `console_manages` | `allowed` | `upstream "NAME" signed with key FINGERPRINT TAG` |
| `(secret set)` | API/console accounts socket, with `console_manages` | `allowed` | `secret "NAME" created\|replaced TAG`. The value is never in the row. |
| `(secret delete)` | API/console accounts socket, with `console_manages` | `allowed` | `secret "NAME" deleted TAG`. Deleting a name the vault does not hold writes no row. |
| `(roles set)` | API/console accounts socket, with `console_manages` | `allowed` | `roles file PATH set to sha256:HEX TAG`, the SHA-256 of the text written. The text is not applied until a `reload`, which writes its own `(config reload)` row. Writing the text already there writes no row. |
| `(restore)` | `restore` | `allowed` | `TAG restored from a backup, sha256:SUM, N audit record(s), head HEAD`; with `; the database it replaced is kept as "PATH"`. Written into the restored trail, linked to the backup's head. |
| `(account add)` | API/console accounts socket | `allowed` | `account "USER": groups G1, G2 TAG` (`(none)` for no group) |
| `(account groups)` | API/console accounts socket | `allowed` | `account "USER": groups G1, G2 TAG` |
| `(account disable)` | API/console accounts socket; offboard | `allowed` | `account "USER" TAG`; for an offboard, `account "USER": offboard TAG` |
| `(account enable)` | API/console accounts socket | `allowed` | `account "USER" TAG` |
| `(account reset password)` | API/console accounts socket | `allowed` | `account "USER" TAG` |
| `(account delete)` | API/console accounts socket | `allowed` | `account "USER": groups G1, G2 TAG` |
| `(account offboard)` | API/console accounts socket | `allowed` | `account "USER", subject "SUB": WHAT TAG` (`no subject` when none), `WHAT` being `blocked`, `disabled` or `blocked and disabled`, then ` REASON` when given. Written after its own `(access block)` and `(account disable)` rows. |

The accounts backend runs as root and never opens the database: its rows,
and the block of an offboard, are written by a short-lived child
(`admin -audit-writer`, `admin -block-writer`) running as the database's
owner. That child appends only account rows, `(access block)`, and since
`design/adr/0050` `(upstream sign)`, `(secret set)`, `(secret delete)` and
`(roles set)`.

A row that cannot be written after its change took effect leaves the
change in force; the command exits `1`, and the API answers
`recorded: false` with the warning `audit_write_failed`.

### Gateway rows

ANALYST is `(gateway)` for all of these.

| TOOL | UPSTREAM | Outcome | Reason format | When |
|---|---|---|---|---|
| `(boot)` | `(gateway)` | `allowed` | `boot: mcp-gateway VERSION, schema N` | The first row of every `serve` process. |
| `BACKEND.TOOL` | the backend | `denied` | `tool first seen: sha256:OBSERVED` | A tool observed for the first time; it is pending. |
| `BACKEND.TOOL` | the backend | `denied` | `tool changed: sha256:APPROVED -> sha256:OBSERVED` | An approved tool's definition changed; it is no longer served. |
| `(registry entry)` | the backend | `denied` | `signature refused: invalid` or `signature refused: unsigned` | An entry starts being refused for its signature. Written once per transition; again after a restart. |
| `(backend health)` | the backend | `allowed` | `backend up: first observed` | A servable backend first seen live. |
| `(backend health)` | the backend | `allowed` | `backend up: down since T` | A backend live again; `T` is RFC 3339. |
| `(backend health)` | the backend | `denied` | `backend down: CAUSE` | A backend first seen not live, or going down. `CAUSE` is `process_gone`, `not_brought_up`, `held_back`, `not_listed` or `redial`. |
| `(backend health)` | the backend | `denied` | `backend removed: no longer servable per the registry` | A backend leaves the servable set. |
| `(access block expired)` | `(gateway)` | `allowed` | `subject "SUB" until T: placed by BY at T` and `: NOTE` when the block had one | At the first maintenance round after a block's end; written before the block is removed. |
| `(config reload)` | `(gateway)` | as above | `[signal] ...` | A bare `SIGHUP` with no pending request. |

### What is not recorded

`upstream register`, `upstream deregister` and `sign` run from the
terminal write no row; the same actions through the API write
`(upstream register)`, `(upstream deregister)` and `(upstream sign)`.
A hand edit of the vault (`sops secrets.json`) or of `roles_file` writes no
row either. Reads
(`list`, `show`, `review`, `audit`, `quota`, `check`, `backup`) write no
row.

## The hash chain

Every record carries `hash = SHA-256(canonical(record) || len(prev) || prev)`
in hex, with `prev` the hash of the record before it, `""` for the first
(`design/adr/0015`).

| Element | Detail |
|---|---|
| Canonical bytes | Each field as an 8-byte big-endian length followed by its bytes, in order: tag, analyst identity, tool, target upstream, timestamp (RFC 3339 with nanoseconds), outcome, reason, source address, then the analyst name when present. |
| Tag | `mcp-gateway/audit/chain/v1` for a record with no analyst name; `mcp-gateway/audit/chain/v2` for one with a name. Older rows keep their hashes. |
| Order | Insertion order. Each append reads the head inside its own write transaction, so `serve` and operator commands share one chain. |
| Head | The hash of the last record, `(none -- the trail is empty)` when there is none. |
| Retroactive | Rows that existed before the chain was added were hashed at migration; `-verify` reports how many. |

The chain is unkeyed and stored in the table it protects. Whoever can
write the database can edit, delete or insert a record and recompute every
hash after it, and `-verify` then reports an intact chain; cutting records
off the end needs no recomputation. What no rewrite can do is leave the
head unchanged.

### audit -verify

| Result | Stream | Exit |
|---|---|---|
| `chain intact: N record(s)` and `head: HASH`, with the limits above and, when `[audit.siem]` is set, where the expected head comes from | standard output | `0` |
| `TAMPERED: the audit trail does not verify.`, the first break's position, the record as it reads now, the expected and stored hashes | standard error | `1` |
| `TRUNCATED OR REWRITTEN: head does not match the expected value.`, with `expected` and `found` | standard error | `1` |

`-expect-head HASH` compares the head case-insensitively. Take the
expected value from somewhere Gatte cannot write. In the SIEM, the head of
a chain is the line whose `hash` is no other line's `prev_hash` (filter on
`chain`), not the newest message: two records written in one tick arrive
in either order. `deploy/gatte-anchor-verify.sh` derives it that way. The
anchor detects a truncated or rewritten local trail; it does not survive an
attacker who controls this host and also forges the shipped lines, which
are not signed.

A `restore` forks the SIEM copy: the `(restore)` row links to the backup's
head, so the SIEM holds two lines after that head.

## JSONL lines

With `[audit.siem]`, the file receives one JSON object per line: a record
(`"type":"record"`, the keys in [The record](#the-record)) or a heartbeat
(`"type":"heartbeat"`). Every key is always present, except `analyst_name`
on a record. Lines written before schema 2 have no `type`: filter with
`NOT type:heartbeat`.

### Heartbeat

A heartbeat is written at boot and on every maintenance round (every
`quarantine.refresh_interval`; while the fleet is suspended, at most once
per interval). It is not an audit record: it has no hash, is not in the
chain, and is not sent over GELF. Without `[audit.siem]`, the same numbers
go to the log line `mcp-gateway: heartbeat` only, with `uptime` instead of
`boot`, and without `chain`, `head` and `records`.

| Key | Type | Meaning |
|---|---|---|
| `v` | integer | `5` |
| `type` | string | `heartbeat` |
| `ts` | string | When emitted, RFC 3339 with nanoseconds, UTC. |
| `chain` | string | `audit.siem.chain` |
| `boot` | string | When this process started, UTC. A new value is a restart. |
| `head` | string | The hash of the last record line this process emitted; `""` when none. Under concurrency it can lag the true head: a liveness signal, not an anchor. |
| `records` | integer | Record lines this process emitted since boot. |
| `allowed`, `denied`, `failed` | integer | Records written since boot, by outcome. Line counts, not call counts. |
| `upstreams` | integer | Backends connected now. |
| `tools` | integer | Routes in the routing table now. |
| `suspended` | boolean | The registry cannot be read and nothing is served. |
| `pending`, `changed` | integer | Tools in the quarantine in each state, across every backend it has seen; `-1` when it could not be read. |
| `backends_up`, `backends_reconnecting`, `backends_down` | integer | Servable backends by state of life. |
| `backends_maintenance` | integer | Backends with a maintenance row; `-1` when unreadable. |
| `gateway_maintenance` | string | `on`, `off` or `unknown`. |

## GELF gap message

After an outage in which events were dropped, the first message on the
recovered connection is a gap message (`design/adr/0029`).

| Field | Value |
|---|---|
| `short_message` | `mcp-gateway telemetry gap: N audit events were not sent` |
| `level` | `4` |
| `timestamp` | the gap's end, epoch seconds |
| `_event_kind` | `telemetry_gap` |
| `_cliente_soc`, `host`, `version` | as for records |
| `_dropped` | total events dropped |
| `_dropped_full`, `_dropped_write`, `_dropped_oversize` | dropped because the queue was full, a write failed, or a message was too large |
| `_gap_start`, `_gap_end` | RFC 3339, UTC |
| `_recover_with` | `mcp-gateway audit --since GAP_START`, the command that recovers the gap from SQLite |
