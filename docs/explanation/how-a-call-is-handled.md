# How a call is handled

This page is for operators and reviewers who want to know why one
`tools/call` goes through Gatte the way it does. It follows a single call
from the analyst's MCP client to the backend and back, says why each gate
sits where it does, and explains why the whole thing is one binary with one
SQLite file. The steps to run and configure Gatte are in the
[how-to guides](../README.md#how-to-guides); the README has the short version
of this path in [How a call is handled](../../README.md#how-a-call-is-handled).

## The path at a glance

```
 MCP client ──HTTPS──► reverse proxy      TLS, request rate, connection limits
                           │ loopback only
                           ▼
 ┌────────────────────── mcp-gateway serve ───────────────────────────────┐
 │ body over 1 MiB                                        → 413            │
 │ 1 token        signature, issuer, expiry, audience     → 401            │
 │ 2 blocklist    one read per request, no cache          → 403            │
 │   registry     fleet suspended because unreadable?     → 503            │
 │ 3 role         only granted tools are on your server   → unknown tool   │
 │ 4 quarantine   approved, and unchanged since approval  → unknown tool   │
 │ 5 backend      up? in maintenance?                     → isError: state │
 │ 6 limits       calls in flight, then quota             → isError: limit │
 │ 7 audit        write the "allowed" row, or refuse the call              │
 │ 8 call         to the backend process, already running with its keys    │
 │ 9 result       size ceiling, output schema, credential scrub            │
 └─────────────────────────────────────────────────────────────────────────┘
                           │                         │
                     backend process           audit trail (SQLite)
                     or container              ──► JSONL / GELF ──► SIEM
```

The first gate that says no ends the call. Every refusal after
authentication is a row in the audit trail with its reason, and so is every
failed authentication, within a rate limit (`design/adr/0012`,
`design/adr/0027`).

## Before the gates: the network edge

Gatte binds loopback only and refuses at startup any other address, with no
override (`design/adr/0011`). It terminates no TLS. A reverse proxy on the
same host does, and it is also where request-rate limiting belongs. The
reason is isolation: certificate material and its renewal stay out of the
process that holds every backend credential, and a bind that cannot reach
the network cannot be exposed by editing one string.

Inside Gatte, a request body over 1 MiB gets `413` before anything reads
it (`design/adr/0035`). A `tools/call` is a name and a few arguments, so the
cap is far above real traffic, and it no longer changes silently with an
SDK update.

## 1. Who are you?

Gatte is an OAuth 2.0 resource server: it issues no identity, it only
checks tokens from an OIDC provider you host (`design/adr/0008`). A token
must be a JWT signed with an asymmetric algorithm by a key the provider
publishes, from the configured issuer, unexpired, and with this gateway's
audience. The audience check is what stops a token minted for another
service of the same provider from working here (RFC 8707).

A refused token gets `401` and nothing that says which check failed. The
verifier folds its causes into one error so that it is not an oracle, and
the audit row says only that authentication failed, when, and from where
(`design/adr/0012`). The token itself never enters the row, not even
truncated.

Two measured problems shaped this gate:

- **Forged tokens used to cost a fetch each.** The OIDC library re-fetches
  the provider's keys whenever it meets an unknown key id. Gatte now allows
  at most one fetch every 30 seconds (`design/adr/0035`), so a stream of
  forged tokens does not become a stream of requests to your IdP.
- **Failed logins used to deny service.** Every failed login wrote a row
  through the same SQLite writer the call path needs. Measured, an
  unauthenticated flood exhausted the database's busy timeout, and
  analysts' calls were refused because they could not be audited. The
  durable rows for failed authentication are now rate-limited per source
  and globally; the first attempt from each source is always written, and
  a marker row says when the limit fired (`design/adr/0027`). The price is
  that the trail no longer says *how many* attempts there were; the
  operational log still does.

Nothing downstream of this gate holds the analyst's token. The identity
that the rest of the call carries has no token field, and a test fails the
build if one is added (`AGENTS.md` §2). This is why "credential stripping"
is not a step in the list: there is nothing to strip.

## 2. Are you blocked?

Right after the token is verified, and before anything else, Gatte reads
the blocklist for that subject: one primary-key read per request, with no
cache between requests (`design/adr/0031`). That is what makes
`access block` take effect on the next request without a restart or a
signal. A block that lands while a request is already admitted applies from
the next one, so a call is never cut off half-way without a row.

The blocklist fails closed. If the table cannot be read, everyone is
refused as an internal error: a kill switch that turns into a free pass
when its table disappears is off exactly when someone has a reason to make
it disappear.

A block has an optional end (`design/adr/0046`). The end applies at
admission, at the instant stated; the maintenance round then records the
expiry and removes the row.

### The registry check

If the registry cannot be read, Gatte suspends the whole fleet: nothing is
served, the backend connections are kept, and the maintenance loop retries
every 5 seconds (`design/adr/0004`, `design/adr/0020`). A suspended gateway
answers `503` with a constant sentence that says the problem is temporary
and not the request (`design/adr/0041` item 8). It does not answer with an
empty list or `unknown tool`, because an empty fleet and a fleet that
cannot be confirmed must not look the same.

## 3. Does your role allow this tool?

Groups in the token map to roles, and roles grant tools by exact name or
per backend (`design/adr/0016`). Roles live in the configuration file, not
the database, so widening one is a reviewed diff (`design/adr/0009`), which
`reload` applies without a restart (`design/adr/0044`).

The check is structural before it is a check. For each request, Gatte
builds an MCP server object that carries only the tools this caller is
granted and that an operator approved. A tool the caller may not use is not
on that object at all, so the SDK answers `unknown tool` for it, exactly as
for a name that does not exist. The dispatcher then authorizes the call
again anyway: the list was true when it was built, and the call arrives
later. That redundancy is deliberate (`internal/gateway/httpapi/httpapi.go`,
`getServer`).

## 4. Has a human approved this tool?

Every tool starts in quarantine and is served only when its current
definition matches the one an operator approved (`design/adr/0003`,
`design/adr/0007`). One predicate decides both "may it be listed" and "may
it be called", so a tool that is callable but hidden cannot exist. The
quarantine is read again on every call, which is why `tool approve` and
`tool revoke` take effect on the next call without a restart
(`design/adr/0013`).

A tool in quarantine answers `unknown tool`, the same as a tool outside the
role and a tool that does not exist. The reasons for per-definition
approval are in [Quarantine and signed backends](quarantine-and-signing.md).

## 5. Is the backend there?

Gatte keeps a state for each servable backend: up, reconnecting, down, or
in planned maintenance (`design/adr/0041`). If the backend is not up, the
call is answered without dialling it, as a tool result with `isError: true`
that names the backend, the state, since when, and when Gatte retries.

This gate sits **after** role and quarantine on purpose: only a caller who
could already use that approved tool learns anything about its backend.
Everyone else gets the same `forbidden` or `unknown tool` as before, byte
for byte. It sits **before** the limits so that a call that never leaves
the process spends no slot and no quota. Why the answer is a tool result
and not an error, and why the tools stay listed, is in
[Backend health and honest answers](health-and-honest-answers.md).

## 6. Are you within your limits?

Two limits, in this order:

1. **Calls in flight.** At most `response.max_concurrent_calls_per_analyst`
   calls per subject, default 4, refused at once with no queue
   (`design/adr/0035`). A queue would hold the same goroutine and only move
   where the pile-up happens.
2. **Quota.** Optionally, a per-analyst budget against each paid
   third-party account (`design/adr/0030`). The unit counted is the account
   at the provider, not the backend or the tool. A call that spends several
   accounts reserves all of them or none, atomically.

The order follows from one rule: the quota debit is taken before the call
and is never refunded, because a call that failed at the backend may well
have spent the provider's quota. A call refused for concurrency must
therefore be refused before it can spend anything.

There is no global or per-backend cap. Seven analysts can together hold 28
slots (`design/adr/0035`).

## 7. Record it, or refuse it

The `allowed` row is written **before** the call is forwarded, and a call
that cannot be recorded is not made (`design/adr/0012`). Under-recording is
an act nobody sees; a refused call is at least visible to the analyst who
got refused.

The row joins a hash chain: each record carries the hash of the one before,
read and written in one `BEGIN IMMEDIATE` transaction so two concurrent
calls cannot fork the chain (`design/adr/0015`). If the call later fails,
Gatte appends a second row, `failed`, rather than editing the first: a
record that can be rewritten is state, not evidence, and the pair also says
the call really was dispatched and how long it took to fail. Count
`allowed` rows to count calls.

The JSONL copy for your SIEM, and the optional GELF copy, are written only
after the SQLite write committed (`design/adr/0017`, `design/adr/0029`). A
failure of either copy is logged and swallowed: the rule "refuse what you
cannot audit" covers the durable write and stops there, because a full log
disk must not stop a SOC from working during an incident.

## 8. Run it with the real credential

The call goes to a backend process that is already running. Gatte dials
each backend when the registry says it should exist (at boot, and on each
maintenance round), not per call: one process or container per backend,
shared by every analyst, kept for the life of the connection
(`design/adr/0020`, `design/adr/0028`).

At dial time, the backend's environment is built from nothing: `PATH`,
`HOME`, and the variables its signed registry entry names, with values the
vault decrypts in memory (`design/adr/0003`, `design/adr/0005`). Nothing is
inherited from the gateway's own environment, so nothing can leak by
inheritance. Names whose value would be code (`LD_*`, `NODE_OPTIONS`,
`PYTHONPATH` and the like) are refused, because the names are signed and
the values are not (`design/adr/0034`). A container backend gets the same
environment through `--env NAME` without a value, so no secret appears on a
command line (`design/adr/0028` §D).

The call has a deadline, `response.call_timeout`, default 2 minutes, with
no value that turns it off (`design/adr/0025`). The analyst's own
cancellation still cuts the call at once; the deadline is a ceiling for
when that cancellation never comes. A backend that dies mid-call is
recognised from the error its own stream produces, and the next round
closes and redials it (`design/adr/0024`).

## 9. Check what comes back

In this order:

1. **Size.** A result over `response.max_bytes` is refused whole, never
   truncated: a document cut in the middle without saying so lies to the
   model (`design/adr/0014`). The caller is told the ceiling and to narrow
   the request (`design/adr/0042`).
2. **Output schema.** If the tool declared an `outputSchema`, its
   `structuredContent` must match it. Gatte never infers a schema from a
   sample (`design/adr/0014`).
3. **Credential scrub.** Every value Gatte injected into that backend is
   removed from the result, in raw and escaped forms, and a result that
   cannot be rewritten without it is refused (`internal/gateway/endpoint.go`,
   `scrubResult`). A backend that echoes its own API key, for example in an
   error it turned into a tool result, does not hand it to the analyst.

The size and schema checks judge the bytes the backend sent, so they run
before the scrub. The concurrency slot is released only after all three.
A refusal here is a `failed` row, not a `denied` one: the call did leave
the process and did run.

If the whole gateway is in announced maintenance, a notice is appended to
text results after these checks, so it counts against no ceiling and never
touches `structuredContent` (`design/adr/0041` item 6).

## Why this order

| Gate | Placed | Because |
|---|---|---|
| Token | first | Nothing else is meaningful without a verified subject. |
| Blocklist | right after the token | A blocked analyst must be stopped whatever token they hold, before any other work. |
| Role, then quarantine | before anything that reveals state | A tool you may not use and a tool nobody approved must look like a tool that does not exist. |
| Backend state | after role and quarantine, before limits | Only a granted caller learns it, and a call that goes nowhere costs nothing. |
| Concurrency, then quota | after quarantine, before the audit row | A quarantined tool stays opaque; the quota debit is never refunded, so the cheaper refusal comes first; the `allowed` row must mean the call left. |
| Audit | before forwarding | A call that cannot be recorded is not made. |
| Result checks, then scrub | after the call | The checks judge what the backend sent; the scrub runs on what will be forwarded. |

## One binary, one SQLite file

All of this happens in one process: a modular monolith, partitioned by
domain, with no network hop between Gatte's own components
(`design/adr/0001`). The choice came from a quantum analysis: security and
auditability apply uniformly to every call, and no component had a load
profile that justified running separately. The business reason weighed as
much: the team that runs Gatte has no platform role, and every extra
process is one more thing to diagnose at 2 a.m.

One embedded SQLite file holds the registry, the quarantine, the entry
signatures, the audit trail, the quota counters, the blocklist, backend
health and maintenance, and the requests the management API leaves for
`serve` (`cmd/mcp-gateway/main.go`, `openStore`). It never holds a secret,
and it never holds the public keys that signatures are checked against: an
anchor stored beside what it authenticates is not an anchor
(`design/adr/0010`).

What this costs, stated in the ADR rather than discovered:

- **A single point of failure.** A crash takes every analyst off every
  backend at once, and an unreadable database suspends the whole fleet
  (`design/adr/0001`, `design/adr/0004`). A panic in one call is contained
  to that call and audited (`design/adr/0035`), and `backup` and `restore`
  are how you survive losing the disk (`design/adr/0045`).
- **One writer.** Every row goes through one SQLite writer. That is what
  keeps the chain in insertion order, and it is also why an
  unauthenticated flood could once deny service (`design/adr/0027`).
- **Modularity needs enforcement.** Nothing in the language stops one
  package from reaching into another, so fitness tests in
  `internal/fitness/` check the import graph on every build
  (`design/adr/0001`).

## What this page does not cover

- What the analyst's model is told in each case:
  [What the analyst is told](../reference/analyst-messages.md).
- Every audit row and its fields: [Audit trail](../reference/audit-trail.md).
- Who the adversary is and what is not defended:
  [Security model](security-model.md).
