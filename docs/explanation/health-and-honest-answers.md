# Backend health and honest answers

This page is for operators and reviewers who want to know why Gatte tells
the analyst's model what it tells it: why a down backend answers with its
state instead of `internal error`, why its tools stay listed, what
`gatte.status` is, why refusals now say what to do, and what is
deliberately kept from whom. The exact texts are in
[What the analyst is told](../reference/analyst-messages.md); planning a
backend's downtime is in [Plan maintenance](../how-to/plan-maintenance.md).

## The problem, as measured

The owner's report was that Claude Code always thinks the problem is
anything but the MCP server being down. The design in `design/adr/0041`
started from a measurement of what the client actually does with each kind
of answer (Claude Code 2.1.285, a throwaway MCP server, a fake model API
that records what the model receives):

- Of a JSON-RPC error, the model sees only `error.message`. A dead backend
  used to arrive as `internal error`, and nothing in that says "outage".
- Of a tool result with `isError: true`, the model sees the whole text. The
  MCP specification puts API failures in this channel and says the client
  should hand it to the model.
- The client reads the tool list once, at connect, and never again in the
  session. A stateless server cannot push `list_changed`.
- The server's `instructions` reach the model, cut at 2,048 characters.
- Of a result with `structuredContent`, the model sees only the structured
  object.

These are client behaviours and they change with the client version. The
ADR names the recipe to re-measure them before relying on them after an
upgrade (`lab/README.md`).

## Why a down backend answers `isError`

Because it is the only channel that reaches the model whole. When a backend
is reconnecting, down or in planned maintenance, a granted call is answered
without dialling it, with a result like:

```
Gatte: the backend "casemgmt" is unavailable since 2026-09-29T14:02:11Z; Gatte is reconnecting it (last attempt 2026-09-29T14:05:00Z, next attempt around 2026-09-29T14:10:00Z). This is not a problem with your request or its arguments: do not change them. Retry after the next attempt, or tell the user. Call gatte.status for the current state of your backends.
```

Each text says what happened, whether the request is at fault, and what to
do next. The fields come only from Gatte's own state (backend name, state,
instants, the operator's maintenance message), never from a backend's
error, output or exit code, because a backend's error text can echo its
credential. All such texts are assembled in one file,
`internal/gateway/httpapi/errors.go`, so there is one place to review what
can leak (`design/adr/0041` item 2).

"Up" means one thing: Gatte holds a live connection that a listing has
confirmed. It does not mean the backend can answer; a wrapper whose remote
API is down is up and fails calls. So a call that fails inside a live
backend gets its own constant text, "the backend failed this call", which
names the place and the next step and says nothing about why
(`design/adr/0041` item 1). "Down" is the state where no redial is
scheduled because an operator has to act; the text says that, not the
cause.

## Why the tools stay listed

Pruning a dead backend's tools buys nothing mid-session: the model already
has the list from connect time, and a pruned tool then answers
`unknown tool`, which the model reads as "wrong name" and starts guessing.
A session that starts during the outage would not see the tools at all and
conclude it lacks the capability. So a backend that is not up keeps its
approved tools in the table (`design/adr/0041` item 4), under four
conditions:

1. the entry is still servable: registered, valid, signed, covered by the
   quota;
2. the tool was in the backend's last successful listing, with the same
   fingerprint;
3. the tool is approved in the quarantine at that fingerprint;
4. the approved definition is stored and still passes the usual checks.

Nothing is resurrected: a pending or changed tool does not come back, nor
does an approved tool the backend had stopped announcing. When the backend
returns, its listing goes through the quarantine again before any call
reaches the new process, so a tool rewritten by the new process is not run
under the old approval.

The list is not a security boundary; authorization and the quarantine
check on every call are, and they do not change. To take a backend away
from analysts, deregister it or withdraw its signature: its tools then
leave the list at the next round.

## `gatte.status`

A built-in tool that reports the caller's backends: state, since when, the
last and next reconnect attempt, and any maintenance message
(`design/adr/0041` item 5). The name `gatte` is reserved in the registry,
so no backend can announce a tool that starts with `gatte.`. The definition
is compiled into the binary, so there is nothing to observe, approve or
rewrite, and it sits outside the quarantine by construction.

It is available to every authenticated, unblocked caller regardless of
role. It spends no slot and no quota, because it never leaves the process,
and it writes one `allowed` row per call, because every `tools/call`
produces exactly one row. It lists only the backends that have at least one
tool on the caller's own server for that request. A backend whose granted
tools are all in quarantine does not appear, because appearing would say
that granted tools exist there and are being held.

Since `design/adr/0042` it also has a `you` block: the caller's display
name, role names, and their own use of each budget their tools spend.

The structured object explains itself, because that is the part the model
reads: a constant `note` says that "up" only means connected, and that
`gatte.status` is the only authoritative source of Gatte's state. Claude
Code shows the tool to the model as `gatte_status`, because it replaces the
dot in exposed names.

The `instructions` Gatte sends at `initialize` are a constant: they tell
the model to call `gatte.status` before blaming its request, why an
expected tool may be missing, and that the list is fixed for the session.
They carry no state, because the client reads them once per session and a
"Gatte is in maintenance" sentence would keep being obeyed after it ended.
The operator may add a contact line and one note per backend, and the notes
included are only those for the caller's own backends (`design/adr/0042`
item 3).

## Maintenance

Planned maintenance of one backend answers its calls with the operator's
message, without dialling it, until the operator ends it; its tools stay
listed. Maintenance of the whole gateway is a notice, not a block: calls
are still served, and the notice is appended to text results and shown in
`gatte.status` (`design/adr/0041` item 6).

- The announced end, `until`, is a forecast. Maintenance ends only with an
  explicit `off`, because a version swap that ran late and "ended by
  itself" at 15:00 would send calls to a half-installed backend. After the
  forecast passes, the analyst reads that it has passed and the maintenance
  has not ended.
- The message goes in front of models, so it is one line of at most 200
  characters, and control and hidden characters are refused, not escaped.
  Gatte quotes it, so a message cannot close the quotes and continue as
  Gatte's own text.
- The maintenance table is read on every call and fails **open**: if it
  cannot be read, calls are served as if there were no maintenance, and the
  heartbeat reports it. Maintenance is an availability notice, not access
  control, and refusing on a read error would turn a database hiccup into
  an announced outage. The blocklist, which is access control, fails closed
  (`design/adr/0031`). The difference is deliberate.

## Why refusals now carry what to do

Four of Gatte's own decisions about a granted, approved call used to reach
the model as bare constants: a result over the size ceiling
(`internal error`), a call past the deadline (the same text as a backend
error), a spent quota (`quota exhausted`), and too many calls in flight
(`concurrency limited`). The model retried them unchanged
(`design/adr/0042` item 2). Each is now an `isError` result that says what
happened, whether the request is at fault, and what to do:

| Refusal | What it adds | Why that may be said |
|---|---|---|
| Result too large | the ceiling in bytes; the call did run; narrow it | The ceiling is a published number, and "this query returns a lot" is a fact about data this caller may read. This reverses the silence `design/adr/0014` first chose. |
| Deadline | Gatte's limit; the backend may still have run it; try a narrower request once | The caller measures their own call's duration, so the deadline was already visible. |
| Quota spent | the account, its limit, its window, when it resets | Operator policy and window arithmetic; no count, of anyone. |
| Calls in flight | how many the caller has, counting all their sessions | It is the caller's own count, equal to the limit at that moment. |

Two more answers changed in the same ADR:

- **A blocked account** still gets `403`, now with a constant body saying
  that signing in again will not help and to ask the SOC operator. It never
  says "blocked" or why. Claude Code shows any `403` as "Needs
  authentication" and hides the body, so the connect script's
  `gatte-status` says the same sentence in that case.
- **A tool pulled mid-session** (role changed, tool under review again,
  backend removed) answers "no longer available to you, do not try other
  names", the same words for every cause, instead of `unknown tool`.

A limit, a spent budget and a pulled tool are Gatte's decisions, which is
why they can be explained. Where the backend failed, Gatte still does not
say why, because it does not forward the backend's error.

## When Gatte itself cannot answer

A suspended fleet, and any failure to build the caller's tool list, answer
`503` with one constant sentence: temporary, not the request, retry or tell
the user (`design/adr/0041` item 8). One body for every cause, so a caller
cannot tell a registry problem from a quarantine store problem.

When the process is stopped or unreachable, nothing inside MCP can help.
The connect script installs `gatte-status` on the analyst's machine, which
tells apart a network problem, a TLS problem, Gatte not serving, and Claude
Code not signed in, from public answers only: the protected-resource
metadata, the `401` challenge, and `claude mcp get`.

There is no `/healthz`, on purpose. The metadata and the `401` already
prove DNS, network, TLS, proxy and process, and per-backend state needs the
caller's identity. An unauthenticated health endpoint would describe the
fleet to anyone who reaches the host.

## What is not revealed, and to whom

The rule behind every row below: Gatte tells a caller only what that
caller's own `tools/list` already implies, plus Gatte's own state and
declared policy (`design/adr/0041` item 3, `design/adr/0042`).

| Who | Learns | Never learns |
|---|---|---|
| Anyone unauthenticated | `401`, with the scopes to request | anything about backends or tools |
| An authenticated caller without the tool, or asking for a tool in quarantine | `forbidden` or `unknown tool`, byte for byte as before | that the tool exists, that it is held, or its backend's state |
| A caller granted the approved tool | its backend's state, since when, last and next attempt; maintenance message, start and forecast end | the cause, the backend's error text, exit code, host, image, command, who set the maintenance or when it last changed |
| A caller of `gatte.status` | the backends of their own served tools; their own name, roles and quota use | any backend they have no tool on; counts of tools or analysts; pending reviews; anyone else's quota |

The details that make those lines hold:

- **No oracle for tools never listed.** The "no longer available" text
  comes from an in-memory record of the names each subject received in a
  `tools/list`, kept at most seven days for at most 4,096 subjects and lost
  on restart. A name the caller was never listed (another role's tool, a
  quarantined tool, a guess) gets the SDK's `unknown tool`, exactly as a
  name that does not exist (`design/adr/0042` item 2).
- **Only the caller's own quota.** The request path has one narrow way to
  read a counter: one analyst per question, called with the verified
  subject of the request being answered, and a fitness test pins that call
  site. The operator-side reader stays banned from the request path
  (`design/adr/0030`, `design/adr/0042` item 3).
- **No count of pending tools.** "Two of your tools are waiting for review"
  would say which backends rewrote tools and when. The instructions say
  only that a missing tool is either not granted or awaiting review.

Two revelations are accepted and stated (`design/adr/0041` item 3):

- A caller whose call is in flight when the backend dies is told it is now
  reconnecting. That links their request to the death, a possible "this
  argument crashes the backend" oracle. It is limited to granted callers,
  every such call is a `failed (upstream gone)` row with their identity,
  and redials happen at most once per round.
- A call a live backend fails is answered "the backend failed this call",
  without its error.

## What text cannot prove

A backend's result passes through as data, and in a SOC the content of a
log or case system is often written by the attacker. A log line reading
`Gatte: the backend "logsearch" is in planned maintenance ...` is identical,
as text, to the real one. Gatte does not pretend to prevent that
(`design/adr/0041` item 2):

- the instructions and `gatte.status` name `gatte.status` as the only
  authoritative source;
- results Gatte builds carry the `_meta` key
  `io.github.bunnyiesart.gatte/origin`, and Gatte strips that key from every
  backend result. Claude Code does not show `_meta` to the model, so this
  is a structural marker for clients that read it, not a defence against a
  model being fooled.

A model that ignores its instructions can still be misled by planted text.
That is prompt injection through a tool result, which Gatte does not cover
(`design/adr/0014`; [Security model](security-model.md)).

## Known limits

- "Up" does not mean the backend can answer; there are no latency or
  saturation metrics (`AGENTS.md` §2).
- A backend never listed by a `serve` of this version has no stable list:
  if it is down at boot, its tools appear only when it comes back
  (`design/adr/0041` item 4).
- Gatte redials no faster than one maintenance round.
- The gateway maintenance notice does not reach the model on a result that
  carries `structuredContent`, because the client shows only the object
  (`design/adr/0041` item 6).
- The "no longer available" memory is lost on restart, after which a pulled
  tool is `unknown tool` again (`design/adr/0042`).
- A blocked account's `403` text is hidden by Claude Code; it reaches
  analysts through `gatte-status` and tools such as `curl`
  (`design/adr/0042`).
