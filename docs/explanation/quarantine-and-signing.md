# Quarantine and signed backends

This page is for operators who approve tools and sign backends, and for
reviewers deciding how far to trust those two controls. It explains why a
tool is approved per definition fingerprint, why a backend entry is signed
and why the key is root's, what a review-set manifest adds, what
`upstream update` keeps, and what neither control covers. The steps are in
[Review and approve tools](../how-to/review-and-approve-tools.md),
[Add a backend](../how-to/add-a-backend.md) and
[Update a backend's container image](../how-to/update-a-backend-image.md).

## Two controls, two questions

Gatte asks two different questions before a tool reaches an analyst, and
answers each with its own control (`design/adr/0003`):

- **What code runs, and with which credentials?** A backend's registry
  entry (its command or image, arguments and credential names) must carry
  an Ed25519 signature from a trusted key. This is about the entry, and it
  is checked before the backend is dialled.
- **What is the model told the tool does?** Each tool's definition (name,
  description, schemas) must match one a human approved. This is about the
  text the backend writes, and it is checked on every list and every call.

Neither answers the other's question. A correctly signed backend can still
rewrite a tool description tomorrow; an approved description says nothing
about which binary serves it.

## Why tools are approved per definition fingerprint

A tool description is untrusted text that goes straight into the model's
context. A backend, or whoever controls it, can put instructions there
("tool poisoning"), or serve an innocent description at review time and
change it later ("rug pull", OWASP MCP03). The quarantine exists for both.

**Per tool, not per server.** Approving a server once would cover every
tool it announces from then on. Gatte fingerprints each tool with SHA-256
over its name, description, input schema and, when the tool declares one,
its output schema (`design/adr/0003`, `design/adr/0014`). A new tool is
`pending`; an approved tool whose fingerprint moves becomes `changed`. Both
are invisible and uncallable until a human approves the exact definition.

**`changed` does not heal itself** (`design/adr/0007` §1). If a definition
changes back byte for byte to the approved one, the tool stays `changed`.
The obvious behaviour, returning to `approved` when the hash matches again,
is the hole: an attacker swaps in a poisoned description, waits for it to
be served, and reverts, and nothing records that there was a window. The
cost, accepted, is that an innocent reformat also needs a new approval.

**One predicate for listing and calling** (`design/adr/0007` §3). A tool
that could be called but not listed is an execution path nobody sees,
which is exactly what a poisoned tool wants to be. With one predicate, that
state cannot be represented.

**Approve what you were shown** (`design/adr/0032`). Every observed
definition is stored under its fingerprint and never rewritten. `tool show`
prints it with invisible code points escaped as `\u{XXXX}` (escaped, not
deleted, because the character is evidence) and, for a changed tool, a
diff against the approved one. `tool approve` needs the `-fingerprint` of
what was shown, and the store compares it in the same transaction that
approves. If the backend announced something else in between, nothing is
approved. A definition over 64 KiB, or a tool name outside
`[A-Za-z0-9_-]{1,64}`, is refused at discovery.

**The quarantine keeps looking** (`design/adr/0013`). Gatte re-lists every
connected backend on a timer, `quarantine.refresh_interval` (default 5
minutes), rather than trusting `notifications/tools/list_changed`: a
compromised backend simply would not send it. A failed listing changes
nothing, because failing to measure is not evidence of a change. New tools,
changed tools and refused signatures each write one `denied` row
attributed to `(gateway)`, on the transition only (`design/adr/0032`), so
your SIEM can alert on a rug pull.

**Removing a backend forgets its approvals** (`design/adr/0013` §2).
Otherwise a different backend registered under the same name, announcing
identical definitions, would be served under approvals given to the first.
The fingerprint cannot catch that case: a substitute that copies the tool
list is exactly what an attacker replacing a backend binary would arrange.

### Approving is not granting

A tool reaches an analyst only when it is approved **and** a role grants
it. The two are different judgements: approval says "this definition was
not poisoned", for the whole fleet; a grant says "this role may call it".
A per-backend wildcard grant (`casemgmt = ["*"]`) collapses them: for that
role, approval becomes the only human act between a new tool and the
analyst (`design/adr/0016`). Wildcards are allowed because the quarantine
makes them safe from silently gaining a tool, and `tool approve` prints
which roles an approval authorizes, and the wildcard's cost when one
applies.

## What a manifest adds for batch approval

A backend with forty tools arrives with forty pending approvals. Approving
them one by one is so repetitive that it trains the operator not to read,
which is the opposite of what the quarantine needs (`design/adr/0043`).

`tool review -server NAME` shows every pending and changed tool of one
backend, with diffs and who could call each, and a **manifest**: a SHA-256
over the backend's name, the number of tools in the set and, for each tool
in name order, its name, status, observed fingerprint and approved
baseline. `tool approve -server NAME -manifest SHA256` recomputes the set
and its manifest inside the write transaction and approves every tool at
the fingerprint it had, or none if any tool appeared, disappeared or
changed since the review.

What the manifest adds is a binding: the set approved is exactly the set
that was displayed, the same guarantee `-fingerprint` gives for one tool.
There is no "approve everything pending" without a manifest, in any front.
Each tool still gets its own `(tool approve)` row, plus one
`(tool approve set)` row for the act, so an alert on single approvals keeps
working.

What it does not add is reading. It removes clicks, not definitions: forty
definitions on one page are still forty definitions (`design/adr/0043`).

## Why backends are signed

The registry lives in the same SQLite file as everything else. Anyone who
can write that file could otherwise register a backend, or change an
existing entry's command to their own program, and Gatte would spawn it
with every credential the entry names.

Every registry entry is signed with Ed25519 (`design/adr/0003`,
`design/adr/0006`). The signature covers the entry's name, transport,
command, URL, image digest, arguments in order and the **names** of its
credential variables, never their values, so rotating a credential never
breaks a signature. The encoding is length-prefixed with a versioned domain
tag, because naive concatenation lets `docker` + `run` collide with
`dockerrun` + nothing. The name is covered so that the signature of one
entry cannot be transplanted onto another with the same command.

A container image must be pinned by digest, because a tag can be repointed
and a signature over a tag would attest a name, not bytes
(`design/adr/0028` §C).

The rules for what is served (`design/adr/0006`, `design/adr/0010`):

- An **invalid** signature is always refused: it is positive evidence of
  tampering.
- A signature by a key **not** in `signer.trusted_keys` is refused as
  invalid, not treated as absent.
- A **missing** signature is refused while `signer.require_signed` is true,
  which is the default.
- Verification runs at boot and on every maintenance round, so an entry
  changed after it was signed stops being served within one round
  (`design/adr/0020`).

### Why the trusted keys are in the config file

The first version checked each signature against the public key stored
next to it in the database. That proves only that the pair was generated
together. It was shown exploitable: rewrite the entry, sign it with a fresh
key, store both, and Gatte served it as `SIGNED: yes` (`design/adr/0010`).

The public keys now live in `config.toml`, which is root's and which the
service reads but cannot write. An anchor must be out of reach of whoever
tampers with what it attests. `trusted_keys` is deliberately not
reloadable: changing whom the gateway trusts to vouch for backends is the
strongest policy decision in the system, and it gets a restart and a new
`(boot)` row (`design/adr/0044`). That is why rotating the signing key
takes two restarts.

### Why the private key is root's

The signature holds only while the private key is out of reach of the
actor it defends against: whoever can write the database. The service
account writes the database, so the service account must not be able to
read the key or replace it. The key is a file owned by root, mode `0600`,
in a directory the service cannot write, never in the database and never
in the vault, which exists to serve the call path, and the call path never
needs to sign anything (`design/adr/0006`). `check` fails when the service
account can read the key or write its directory (`design/adr/0045`).

The provisioning recipe got this wrong until 16 Sep 2026 and left the key
readable by the service account (`README.md`, Security model). Signing
stays in the terminal, never in the web console or the management API,
because it needs root's key (`design/adr/0036`, `design/adr/0040`) --
unless `[admin] console_manages = true`, with which the accounts socket,
root's, signs through a child `sign` and the console started with
`-manage-users` has a Sign button (`design/adr/0050`).

`sign -all`, used after a key rotation, signs only a plan it printed
first, bound by a manifest (`design/adr/0044`). An entry that no longer
verifies is exactly the trace a database attacker leaves, so root must see
it before signing it.

## What `upstream update` keeps

Moving a container backend to a new image digest used to mean deregister,
register and sign, and deregistering forgets every approval. For a routine
update, that sent every tool back to `pending`, including the ones the new
image announces byte for byte unchanged (`design/adr/0043`).

`upstream update -image NAME@sha256:HEX NAME` changes only the image and
keeps the quarantine. That is safe for the text, by the rules that already
exist: an approval belongs to a fingerprint, so at the new image's first
discovery an identical definition stays approved, a different one becomes
`changed` and is withdrawn, and a new one is `pending`. `tool review -server`
then shows exactly those.

It keeps the signature requirement too. The signature covers the image, so
the old signature stops verifying the entry, and Gatte stops serving it
whatever `require_signed` says, until root runs `sign NAME`. The command
does not delete the old signature, because an unsigned entry would be
served under `require_signed = false`. It refuses stdio entries (their
command is what runs; changing it is a new backend) and warns when the
image repository changed, because keeping approvals is for the same
backend.

## Known limits

- **A human still has to read.** The quarantine makes hidden characters
  visible and changes diffable; nothing judges the text for you
  (`design/adr/0032`). A batch approval binds what was shown, not what was
  read (`design/adr/0043`).
- **The manifest does not bind roles.** It covers the backend, the tools,
  their status and fingerprints. Who can call each tool is shown during the
  review, but it is not in the manifest: roles are policy in `config.toml`
  and change through `reload`, independently of approvals
  (`design/adr/0044`). A grant widened between your review and your
  approval is not detected by the approval; it is a `(config reload)` row
  of its own.
- **Identical text is not identical behaviour.** A kept approval after
  `upstream update` says the new image describes its tools the same way,
  not that it does the same thing. What vouches for the new code is root's
  new signature, and a digest proves the bytes are the ones you signed,
  not that they are good (`design/adr/0028` §C, `design/adr/0043`).
- **The fingerprint cannot see a faithful copy.** A substitute backend
  announcing identical definitions keeps the approvals of the original
  unless the entry is deregistered (`design/adr/0013` §3).
- **The fingerprint sees decoded schemas, not raw bytes.** The MCP SDK
  decodes a tool's schema before Gatte sees it, so duplicate keys collapse
  and numbers normalise. Every semantic change still moves the hash; two
  schemas that another parser would read differently may share one
  approval (`design/adr/0019`).
- **There is a window.** Between two observations of the same backend,
  `quarantine.refresh_interval` plus the length of one round can pass, and
  a rewritten tool is served until the next observation
  (`design/adr/0013`, 28 Sep 2026 correction).
- **An unsigned entry under `require_signed = false` is served**, and
  `upstream update` then has no signature to invalidate
  (`design/adr/0043`).
- **The database still decides which entries exist.** Someone with write
  access can delete a legitimate entry. That is denial of service, not code
  execution, and it is visible by absence (`design/adr/0010`).
- **Signing protects against a database writer, not the service account.**
  Code running as the service account reads the decrypted vault directly;
  see [Security model](security-model.md).
