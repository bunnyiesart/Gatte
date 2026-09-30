# Security model

This page is for anyone deciding whether to trust Gatte, and for operators
who need to know which of their own controls it depends on. It explains
who the adversary is, what Gatte defends against and what it does not, and
why the line falls where it does. The README's
[Security model](../../README.md#security-model) has the same limits as a
table, threat by threat; this page is the reasoning behind it.

Gatte's rule for itself is that what it does not cover is stated next to
what it does (`PRODUCT.md`, Product Principles). Every "not covered" below
is a decision, not a to-do: each one is recorded in a decision record, and
closing it would take a new one (`CLOSEOUT.md`, "What this file is not").

## What Gatte is for

The starting point is a SOC where every analyst runs each MCP server on
their own laptop, each with its own copy of a production API key. Gatte
moves those keys to one host, encrypted with sops and age, and gives the
analysts' clients only a short-lived login token (`design/adr/0003`).

That is the core claim, and it is a reduction, not an elimination: N copies
of every key become one encrypted file plus one age identity in clear on
one host. The ADR says so plainly: this is not hardware-grade secrecy, and
no option without an external KMS would make it so. The goal is one copy
instead of seven, not an HSM.

## The actors

Gatte's controls are easiest to understand by asking, for each actor, what
they already hold and what Gatte stops them from doing next.

| Actor | Already holds | Gatte stops them from |
|---|---|---|
| An analyst | a valid token, a role | using a tool the role does not grant; seeing a tool no human approved; running away with an API budget; hiding what they did |
| Someone with a stolen laptop or token | the analyst's token, until it expires | getting any backend API key; using the token after `access block` |
| A stranger on the network | nothing | reaching Gatte except through the proxy; passing a token minted for another service; denying service with failed logins (mitigated) |
| A malicious or compromised backend | its own code and credential | changing a tool's description unnoticed; echoing its credential back to the analyst; running with capabilities, as root or unlimited, in a container |
| Someone who can write the database | the SQLite file | adding or changing a backend that Gatte will serve; editing the trail without the head changing |
| Someone running code as the service account | the process's rights | **nothing**: see below |
| Someone who controls the host | everything | **nothing**, except that a shipped copy of the trail disagrees with a rewritten local one |

The analyst is the actor the design centres on. Against them, Gatte
enforces OIDC with a validated audience, role-to-tool access, the per-tool
quarantine, per-analyst limits, and a trail of every call, refusal and
failure (`design/adr/0003`, `design/adr/0008`, `design/adr/0012`).

## Identity and the two revocation clocks

Gatte validates tokens and issues none (`design/adr/0008`). A token is
valid until its `exp`, and the IdP sets `exp`. Revoking an analyst at the
IdP stops new logins and new refreshes; it does not shorten a token that
was already issued. A stolen laptop with a live session keeps being served
for the token's whole lifetime.

So there are two clocks, and an incident needs both:

- **Gatte's clock is immediate.** `access block SUBJECT` refuses that
  subject from its next request, whatever token it holds, without a restart
  (`design/adr/0031`). A block can end by itself at a set time
  (`design/adr/0046`).
- **The IdP's clock is the token lifetime.** Revoke the session at the IdP
  too, and keep access tokens short. The reference Authelia configuration
  issues 10-minute tokens (`README.md`, Security model).

Offboarding a person does both of Gatte's halves in one audited action
(block the subject, disable the account) and always answers with what it
could not do: revoke the IdP's sessions and tokens, which every other
application behind the same IdP still accepts (`design/adr/0046`).

The subject is compared exactly, and the verifier refuses a `sub` with
control, invisible or edge-whitespace characters, so no identity can enter
that the kill switch cannot name (`design/adr/0031`). The display name in
the trail is for reading only and decides nothing, because the analyst can
often change it (`design/adr/0037`).

## The service-account boundary

Gatte is **not** a control against someone who runs code as its service
account. That actor can read the decrypted vault, write the database and
write the trail. Every control on this page that is "against a database
writer" is against someone who can write the file, not someone who is the
process.

The least trusted code in the system, third-party MCP servers, would run
as that same account if registered as stdio backends. Nothing separates a
stdio backend from the process that holds every credential: no separate
uid, no nested jail (`AGENTS.md` §2). Isolating them would be platform work
this team has no role to operate, so the gap is declared, not closed. What
Gatte does about it:

- **A stdio entry with credentials is refused** unless
  `[upstreams] allow_credentialed_stdio = true` says so, and every boot
  with that setting logs a warning (`design/adr/0034`).
- **Container backends narrow it.** A container backend runs with rootless
  podman from a digest-pinned image: read-only root, no capabilities, no
  privilege gain, a numeric non-root uid mapped to a subordinate host uid,
  pids, memory and CPU limits (`design/adr/0028`, `design/adr/0034`).
  Reading the vault then takes a container escape instead of an `open()`.
  It does not close the gap: the container runtime itself runs as the
  service account, the resource limits hold only where cgroup v2 delegates
  them, and while a container lives, podman keeps its resolved environment
  in a file under the service account's storage (`design/adr/0028` §D).

The same boundary explains who runs what:

- **Root holds what grants trust.** The signing key and `config.toml` are
  root's, and the IdP's users file is edited only through a root-only
  socket, because writing it creates accounts with any group, and so any
  role (`design/adr/0038`, `design/adr/0040`).
- **Root never opens the service account's files.** `sign`, `check`,
  `backup` and `restore` read root's files as root and then become the
  database directory's owner before opening the database. The accounts
  socket writes its audit rows and blocks through short-lived children that
  run as that owner. A service account that could plant a link where root
  writes could otherwise turn root's write into its own
  (`design/adr/0040` §1, `design/adr/0044`, `design/adr/0045`).
- **`reload` and `upstream redial` refuse to run as root.** They signal a
  process whose pid is read from a table the service account writes, so as
  root they would let that account aim root's signal at any process on the
  host (`design/adr/0044`).
- **The operator is whoever the kernel says connected.** The management
  API takes the operator's identity from the socket's peer credentials,
  never from the request (`design/adr/0040` §2).

## The database writer

Someone who can write the SQLite file, but is not the service account, is
the actor for two controls:

- **Signed backends.** Registry entries are signed with Ed25519 and checked
  against public keys in `config.toml`, outside the database. Writing the
  database is no longer enough to add or change a served backend; it also
  takes a private key that lives in a root-owned file (`design/adr/0010`).
  The details are in [Quarantine and signed backends](quarantine-and-signing.md).
- **Restore refuses a tampered copy.** `restore` refuses a copy whose
  integrity, schema, chain or signatures fail, and one that carries a
  trigger, view or index the binary did not create, since such a trigger
  would run inside the restored gateway (`design/adr/0045`).

What the writer can still do is delete an entry (denial of service, visible
by absence) and rewrite the trail, below.

## The trail's integrity limits

The trail is evidence, so its limits matter more than most:

- **The chain has no key.** Each record carries the SHA-256 of the one
  before, stored in the same table, and the hash function is public.
  Whoever writes the database can edit a row and re-chain everything after
  it, and `audit -verify` then answers "intact" (`design/adr/0015`,
  11 Sep 2026 correction). The chain catches careless edits and partial
  writes, not that actor.
- **The only detection is the head.** Any rewrite, and any truncation,
  changes the chain head. Comparing the local head with the one your SIEM
  last received (`audit -verify -expect-head HASH`) is the one check that
  works against a database writer (`design/adr/0017`). It works only while
  a shipper is actually forwarding the JSONL copy, and not against an
  attacker who also forges the shipped lines.
- **Nothing compares the two heads automatically.** The comparison has no
  owner (`CLOSEOUT.md`, Track 2). Until someone runs it on a schedule, the
  anchor is evidence only when someone looks.
- **Silence is detectable, not proof.** A heartbeat line on the same path
  lets the SIEM tell a dead shipper from a quiet night (`design/adr/0021`),
  but it is unsigned: whoever controls the host can write heartbeats too.
- **A restore without `-expect-head`** proves only that the copy agrees
  with itself; a trail rewritten whole and re-chained verifies
  (`design/adr/0045`).

## Egress is the firewall's job

A backend with network access can send data, including its own credential,
to anything that network reaches: a public API, the rest of RFC 1918, the
cloud metadata address. Gatte does not proxy a backend's traffic, so it
cannot choose destinations (`design/adr/0033`).

What Gatte decides is the network namespace. A container backend has no
network unless its signed entry grants one, and the grant is limited to
`slirp4netns`, `pasta` or a named podman network; `host` and the modes that
join another namespace are refused. A stdio backend has the host's network.

Destinations are for the host firewall: one outbound rule on the service
account's uid covers both transports, with the allowlist derived from
`upstream list -json`, which states each backend's network. Because the uid
is shared, the allowlist is a union: one backend reaches another's
destinations. Without that rule, nothing limits egress. Host podman
configuration can still open the host's loopback to an accepted mode, so
the ADR asks you to probe each mode you use.

## Prompt injection is not covered

A tool's result goes back into the model's context, and its content may be
written by an attacker: a log line, a case note, a threat-intel record.
Gatte checks a result's size and, when the tool declares one, its output
schema (`design/adr/0014`). Neither can tell a malicious result from a real
one. A string field full of instructions is still a string.

Gatte deliberately does not try: no "looks like a prompt" heuristic, no
banned phrases. Their false negatives make them useless as a control, their
false positives break legitimate work, and the combination produces a
control people turn off. The real defence is for the client and the model
to treat tool results as untrusted data. What Gatte guarantees is that the
result came from the backend the signed entry names, with the right
credential, within a sane size, and that the call was recorded.

The same limit applies to text that imitates Gatte's own messages; see
[Backend health and honest answers](health-and-honest-answers.md#what-text-cannot-prove).

## Network exposure

Gatte terminates no TLS and refuses to bind anything but loopback, with no
override (`design/adr/0011`). Everything network-facing depends on a
reverse proxy on the same host and on your network controls. Two things
follow:

- The proxy is where request-rate limiting belongs; Gatte's own bounds are
  per analyst.
- The source address in the trail is the right-most `X-Forwarded-For`
  entry, the one the proxy wrote. That is correct only while the proxy
  appends to the header and is the only path to Gatte
  (`design/adr/0012`).

## Availability

Gatte is a single point of failure, knowingly: one binary, one process, one
SQLite file (`design/adr/0001`). What bounds the damage one caller can do:
a per-call deadline and result ceiling (`design/adr/0014`,
`design/adr/0025`); at most four calls in flight per analyst by default,
with no global or per-backend cap (`design/adr/0035`); a 1 MiB request
body; at most one JWKS fetch every 30 seconds; a panic contained to the
call that hit it; and per-source rate limits on failed-login audit rows,
without which an unauthenticated flood was measured to get analysts' calls
refused (`design/adr/0027`).

## Other credential limits

- **Rotation reaches a connected backend only when it is dialled again**:
  `upstream redial NAME`, or a restart. The vault re-reads its file when it
  changes, and Gatte warns while a connected backend still uses the old
  value (`design/adr/0023`, `design/adr/0044`).
- **The vault's namespace is flat**, keyed by variable name. Two backends
  that declare the same name get the same value; Gatte reports the sharing
  at boot rather than refusing it (`design/adr/0018`).
- **Names that would make a value into code are refused**, because the
  names are signed and the values are not (`design/adr/0034`).

## Where each limit is written

The README's [threat table](../../README.md#at-a-glance) is the one-line
summary; the [decision records](decision-records.md) hold the reasoning;
`AGENTS.md` §2 keeps the list of controls still open. `CLOSEOUT.md` says
what separates "v1 declared" from "v1 running": nothing in it measures
capacity, closes the declared limits above, or makes the trail survive an
attacker who controls the host.
