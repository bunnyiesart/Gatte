# Test hosting: a FreeBSD jail

A local, throwaway FreeBSD jail for running and smoke-testing
`mcp-gateway` as it's built -- not a production deployment target, and
not itself a `WORKFLOW.md` phase. Nothing here is a security control;
`.hardening.toml` and the ADRs in `design/` are unaffected by any of this.

## What it runs on

[`jailmachine`](https://github.com/gabrielbelli/jailmachine) (`jm`), a
`brew`-installed tool that boots a FreeBSD 15.1 VM under QEMU/HVF on the
Mac and provisions it with `bastille` for jails and `podman` for OCI
containers. State lives under `~/.jailmachine/`, entirely local to this
machine -- nothing here depends on it existing anywhere else.

```bash
jm doctor          # confirms qemu/HVF/gvproxy/etc are all present
jm start           # boot the VM (idempotent; no-op if already running)
jm ssh -- <cmd>     # run a command as root in the VM
```

## The jail

Created once, by hand, following `jailmachine`'s own README:

```bash
jm ssh -- bastille bootstrap 15.1-RELEASE
jm ssh -- bastille create mcp-gateway-test 15.1-RELEASE 10.17.89.10
```

| | |
|---|---|
| Name | `mcp-gateway-test` |
| Release | `15.1-RELEASE` (matches the VM's own version) |
| IP | `10.17.89.10`, NAT'd out through the VM's `vtnet0` via `pf` |
| Type | thin jail (base OS shared read-only via `nullfs` from `bastille`'s release cache; only `/usr/local`, `/etc`, `/var`, `/root`, `/tmp` etc. are jail-private) |

Re-creating it after a `bastille destroy mcp-gateway-test` is the same
two commands (bootstrap is a no-op if the release is already cached).

### Superseded, 09 Sep 2026: it is a VNET jail at 10.17.90.10 now

**The two rows above describe how the jail was created, not what it is.**
`bastille create ... 10.17.89.10` makes a *classic* jail, which has no
loopback of its own: a process binding `127.0.0.1` inside one has that bind
rewritten to `10.17.89.10`, and the socket is then reachable from the VM
host, from the other jails, and across the VPN in cleartext. `mcp-gateway`
refuses any non-loopback bind (ADR-0011 item 1) -- and in a classic jail that
refusal passes while meaning nothing, which is the defect ADR-0011's
CORREÇÃO block records.

So the jail was converted to **VNET**: its own network stack, its own
`lo0`, its own `127.0.0.1`, on `10.17.90.10/24` behind the `socbr0` bridge.
`deploy/gateway-vnet.md` is the current description of its networking and
supersedes the IP and Type rows here; the type is still a thin jail, and
everything below in *this* file about deploying the binary, `sops`, and
rotating credentials is unaffected.

```bash
./deploy/gateway-vnet.sh           # convert (idempotent)
./deploy/gateway-vnet-verify.sh    # the acceptance test
./deploy/gateway-vnet-rollback.sh  # back to a classic jail at 10.17.89.10
```

The two-command recreate above still works and still produces a classic
jail; run `./deploy/gateway-vnet.sh` after it, or the loopback property is
gone again with nothing to say so.

## Deploying the binary

There is no host directory sharing between the Mac and the VM
(`jailmachine`'s own limitation, no virtiofs on FreeBSD yet), so getting
a build in means: cross-compile on the Mac, `scp` into the VM over its
forwarded SSH port, then `cp` from the VM into the jail's root on disk
(a thin jail's `/usr/local` is real, jail-private storage, not part of
the shared base).

```bash
./scripts/deploy-to-jail.sh
```

for the whole cross-compile → scp → install → smoke-test sequence, or by
hand:

```bash
GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/mcp-gateway-freebsd ./cmd/mcp-gateway
scp -i ~/.jailmachine/machines/jailmachine/ssh/id_ed25519 -P 2222 \
    /tmp/mcp-gateway-freebsd root@127.0.0.1:/tmp/mcp-gateway
jm ssh -- cp /tmp/mcp-gateway /usr/local/bastille/jails/mcp-gateway-test/root/usr/local/bin/mcp-gateway
jm ssh -- bastille cmd mcp-gateway-test /usr/local/bin/mcp-gateway version
```

`CGO_ENABLED=0` is safe here specifically because `modernc.org/sqlite`
(the driver `internal/store` uses) is a cgo-free, pure-Go SQLite
implementation -- cross-compiling to `freebsd/arm64` from `darwin/arm64`
needs no C toolchain for the target at all.

## Verifying it actually ran

```bash
jm ssh -- bastille list                                          # JID, state, IP
jm ssh -- bastille cmd mcp-gateway-test /usr/local/bin/mcp-gateway version
```

**Why `version` and nothing heavier.** Since Phase 6 the binary dispatches
on a subcommand first, and *every* subcommand except `version` reads the
TOML configuration before it does anything -- `config.Validate` requires
`database`, `oidc.issuer`, `oidc.audience`, `vault.secrets_file` and
`vault.age_key_file`, and refuses to start without them. This script
installs a binary; it does not install a configuration, a vault, an age
identity, or `sops`. So there is nothing here that can legitimately open a
database, and a smoke test that pretends otherwise is a smoke test that
fails for the wrong reason.

Until 09 Sep 2026 this file and `scripts/deploy-to-jail.sh` both ran
`mcp-gateway -db /var/db/mcp-gateway.db`, a leftover from the Phase 1 stub
that took flags directly. There is no `-db` flag and there has not been one
since Phase 6: the real binary printed `unknown command "-db"` and exited
2, which under the script's `set -eu` aborted the deploy. This section then
compounded it, verifying with `file /var/db/mcp-gateway.db` a database that
had never been created.

If you want the store-and-migrate check back, it needs a real config file
in the jail first -- write one, then run any subcommand that opens the
store (`mcp-gateway upstream list -config /usr/local/etc/mcp-gateway.toml`
migrates all four schemas on the way in), and only then is
`file /var/db/mcp-gateway.db` a meaningful assertion. That is a deployment,
which this script deliberately is not.

## Checking the audit trail has not been rewritten

The trail is hash-chained (ADR-0015). Each record's hash covers its own
fields and its predecessor's, so a record edited or deleted *without the
hashes after it being recomputed* stops verifying:

```bash
mcp-gateway audit -verify -config /usr/local/etc/mcp-gateway/config.toml
```

Exit 0 and `chain intact`, or exit 1 and the position of the first break.

**The part that needs you, not the code.** Exit 0 is not "the trail was
not rewritten". The chain is an unkeyed SHA-256 living in the same table
it protects, and `audit.ChainHash` is an exported function, so somebody
with write access to `/var/db/mcp-gateway.db` can edit a record and
recompute every hash after it — `-verify` then prints `chain intact`
(ADR-0015, correction of 11 Sep 2026). Records cut off the *end* leave a
shorter chain that verifies for the same reason.

The one thing none of that survives is the **chain head** changing. So the
head is the control, and it only works if you wrote it down somewhere the
gateway cannot reach, beforehand. `-verify` prints it:

```
head: 9f2c…  ← copy this somewhere else
```

Later, hand it back:

```bash
mcp-gateway audit -verify -expect-head 9f2c… -config …
```

A mismatch means the trail is not the one that produced that head. Where
the head lives is deliberately not decided here — an operator's notebook,
a file on another host, a log shipper. Anywhere the gateway cannot write.

### Where the head lives once the SIEM sink is on (ADR-0017)

With `[audit.siem]` configured, the gateway appends one JSON object per
record to a local file, and every line carries `prev_hash` and `hash`:

```toml
[audit.siem]
path  = "/var/log/mcp-gateway/audit.jsonl"
chain = "gatte-jail-01"
```

The expected value for `-expect-head` is then the `hash` field of the
newest Graylog message matching `chain:"gatte-jail-01"`. `mcp-gateway audit
-verify` prints that instruction itself once the block is set, so nobody
has to remember the query. **Nothing compares the two automatically.**
While it is manual, the detection depends on somebody running it — and
there is no Graylog alert yet for "lines stopped arriving for this chain",
which is what a dead (or deliberately killed) shipper looks like.

Three things this deployment owns, because the gateway cannot:

**1. A shipper has to read the file.** The Graylog input is Raw/Plaintext
TCP at `10.17.90.30:5555` and expects exactly one JSON object per line,
byte-identical to what the gateway wrote — the extractor is in COPY mode
and `message` is the hash-chain anchor. A shipper must not re-wrap,
pretty-print, or batch lines. Nothing in the gateway can check that one is
installed; if none is, the sink is a file that grows and anchors nothing.

**2. Rotation, and the reopen gap.** The file grows without bound. The sink
opens with `O_APPEND`, so every write lands at the current end of the file
as the kernel sees it rather than at an offset this process remembers —
that is what makes rotation safe without a lock file. But **the process
holds the fd and does not reopen on SIGHUP**. A plain rename therefore
leaves the gateway writing into the rotated inode, and the shipper reading
a file nothing appends to any more, with no error anywhere. So:

- use `copytruncate` (newsyslog's `-C`/`R` behaviour, or logrotate's
  `copytruncate`), which keeps the inode; **or**
- rename and then restart the gateway, accepting the restart.

This is a real gap, not a detail. A reopen-on-SIGHUP is the fix and does
not exist yet.

**3. The file holds no credentials and is still not world-readable.** It is
created `0600`, and it names which analyst called which tool on which case.
Whatever user the shipper runs as needs read access to it — grant that
deliberately rather than by widening the mode.

**4. A new field is a schema decision, not an edit.** Graylog dynamically
maps a new field by its first observed value, so a field that first arrives
looking numeric or date-like becomes `long`/`date` — and from then on a
malformed value in that field drops the whole line. Pin any new field via
`PUT /api/system/indices/mappings` on index set `6aa42d7143c0e26417f2d472`
before it ships, or keep emitting strings. (The schema is versioned: `v`
is `1` today, and adding a field is a version bump by ADR-0017 item 4.)

**On first start after upgrading**, rows written before this existed are
hashed during migration, and `-verify` says how many. Those verify against
each other, which says nothing about whether they were already altered
beforehand. The chain is only evidence from the migration forward, and the
count is printed so nobody reads it as more.

## Tearing down

```bash
jm ssh -- bastille stop mcp-gateway-test
jm ssh -- bastille destroy mcp-gateway-test   # jail + its ZFS dataset
jm stop                                        # stop the whole VM, if nothing else needs it
```

## What this does and doesn't prove

Proves that a freebsd/arm64 binary cross-compiled on darwin/arm64 loads and
executes unmodified on real FreeBSD -- not just that it links.

That is *less* than this section used to claim. The old smoke test was
supposed to prove `modernc.org/sqlite` works without cgo on this target by
opening a database; it never did, because the command it ran had not
existed since Phase 6 (see "Verifying it actually ran"). The pure-Go driver
is still the reason `CGO_ENABLED=0` cross-compiles at all, but nothing in
this script exercises it at runtime any more. Proving that again needs a
config file in the jail.

**Phase 6** did change what lands there: `cmd/mcp-gateway` was the Phase 1
stub until 09 Sep 2026, so everything built in Phases 2-5 was unreachable
from the deployed binary. The composition root exists now, so this script
installs the real program -- it just does not configure it.

What this script does *not* set up, and what a real deployment needs:

  - **a configuration file.** Every subcommand but `version` reads it, and
    `config.Validate` refuses to run without `database`, `oidc.issuer`,
    `oidc.audience`, `vault.secrets_file` and `vault.age_key_file`. Copy
    `config.example.toml`.
  - **the age identity** (ADR-0005), owner-only. `serve` needs it: the
    vault decrypts at startup.
  - **`sops` on the jail's PATH.** The vault shells out to it (ADR-0005).
    Pin the version -- see "sops version" below.
  - **the OIDC issuer reachable from inside the jail.** Discovery happens
    at startup, so an unreachable issuer stops the process from coming up
    at all -- not just from authenticating. See "Rotating credentials"
    below and the operator note in ADR-0008. There is one to point at now:
    `deploy/authelia-jail.md` builds an Authelia provider in a second jail
    at `https://id.soc.internal` (10.17.89.20), issuing JWT access tokens
    with `aud` = `https://mcp.soc.internal/` and a `groups` claim. It does
    *not* add the hosts entry to this jail -- that is a deliberate boundary,
    and `id.soc.internal` will not resolve here until someone adds it.
  - **the public keys the gateway will trust for signatures.** ADR-0010
    (09 Sep 2026) moved the trust anchor out of the signature line and into
    the configuration file, and made `require_signed` -- on by default
    since Phase 6 -- refuse to start without one. So a deployment that
    serves anything needs the trusted-key list populated, not just the
    entries signed. That work is landing now; read ADR-0010 for the field
    name and format rather than trusting a copy of it here.
  - **the Ed25519 signing key** (ADR-0006), owner-only, on whatever host
    runs `mcp-gateway sign`. **`serve` does not read this file at all** --
    see below.
  - **a published port** (`bastille rdr`) for analysts to reach the
    endpoint. Note that `listen` defaults to loopback on purpose.

### Correction, 09 Sep 2026: the key-permission refusal is on `sign`, not `serve`

This section previously said "`serve` refuses to start on a signing key the
group can read, and prints the `chmod` to fix it," and listed the signing
key among the things needed "before `serve` will start". Both halves were
wrong, and wrong in the direction that matters: they described a control as
guarding a process that never touches it.

`serve` never calls `signer.LoadKey`. The only caller in the whole binary is
`cmd/mcp-gateway/sign.go`, which is why `config.Signer.KeyFile` is
documented as **optional** -- correctly, and for a real reason: a serving
process *verifies* signatures, it does not create them, so a host that only
runs `serve` has no business holding a private signing key at all.

**The control is real; it lives one command over.** `signer.LoadKey`
refuses a group- or world-readable key file and its error names both the
mode it found and the `chmod` to run, and `mcp-gateway sign` surfaces that
message verbatim and exits 2 without signing. On a shared host, anyone with
a login could otherwise sign entries. That refusal is the control working,
not an obstacle to route around -- it just fires when you sign, in front of
the operator who is signing, rather than at boot.

The practical consequence: a signing key with the wrong mode does not stop
the gateway. It stops the next signature, and every entry signed before you
noticed stays served.

### sops version

ADR-0005 accepted, as a named cost, that a change to the `sops` CLI's flags
or output could break `internal/vault/sopsage` with no compile-time signal,
and said the mitigation was pinning a minimum tested version in this file
once Phase 2 shipped. Phase 2 shipped; this is that pin.

**Minimum: sops 3.13.2**, which is what FreeBSD's `security/sops` package
installs today. Development and CI run 3.13.3, the version `make devtools`
pulls (it installs `@latest`, so the two will drift; 3.13.2 is the floor,
not the target).

```bash
jm ssh -- bastille pkg mcp-gateway-test install -y sops age
jm ssh -- bastille cmd mcp-gateway-test sops --version   # expect >= 3.13.2
```

Older is untested rather than known-broken. The adapter invokes exactly one
form -- `sops --decrypt --input-type json --output-type json <file>`, with
`SOPS_AGE_KEY_FILE` in a built-not-inherited environment -- and those flags
are about as stable as that CLI's surface gets. But "untested" is the
honest word, and ADR-0005 accepted precisely this exposure: there is no
compile-time signal if that invocation stops meaning what it means.

## Rotating credentials

**Read this before rotating anything in anger.** Rotation is almost always
a response to believing a credential is compromised, and the gap below is
the difference between that belief being true and being false.

### An upstream backend credential (the sops vault)

Edit the encrypted file directly -- there is deliberately no
`mcp-gateway rotate` subcommand, because it would give a binary that
otherwise only *reads* the encrypted store a write path into it:

    sops secrets.json

**Then restart the gateway.** This is the part that is easy to miss and
expensive to get wrong: credentials are resolved at *dial* time and passed
into the upstream subprocess's environment, so an upstream that is already
connected keeps using the old value indefinitely. Editing the vault
changes what the *next* connect will use and nothing else.

So until the gateway restarts, "I rotated the credential" means "the old
credential is still in active use by every connected upstream."

**The gateway warns about this now (GAB-20).** Once per
`quarantine.refresh_interval` it re-reads each connected upstream's
credentials and compares them against what that upstream was actually
handed at dial time, and logs a warning naming the upstream and the
variable if they differ:

    a credential was rotated in the vault but the connected upstream is
    STILL USING THE OLD VALUE -- rotation takes effect at the next dial,
    so restart the gateway to make it real

It compares keyed digests, never values, so nothing derived from a secret
is kept or logged. **It does not reconnect anything** -- the restart above
is still the step that makes a rotation real, and the warning exists to
stop that step being forgotten. A reconnect command was considered and
deliberately not built: it would need a control channel into the process
that holds every backend credential, and SIGHUP is not the cheap version
here because this service runs under `daemon -r` (see the pidfile note in
`deploy/gateway-jail/mcp_gateway`).

### The Ed25519 signing key (ADR-0006)

Replace the key file, then **re-sign every registry entry** with
`mcp-gateway sign NAME`. Entries signed with the old key will not verify
against the new one, and with `require_signed` on (the default) they will
not be served. `sign` tells you when it replaced a signature made by a
different key -- if you did not just rotate, find out whose key that was.
