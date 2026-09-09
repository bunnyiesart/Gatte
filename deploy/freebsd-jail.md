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
jm ssh -- bastille cmd mcp-gateway-test /usr/local/bin/mcp-gateway -db /var/db/mcp-gateway.db
```

`CGO_ENABLED=0` is safe here specifically because `modernc.org/sqlite`
(the driver `internal/store` uses) is a cgo-free, pure-Go SQLite
implementation -- cross-compiling to `freebsd/arm64` from `darwin/arm64`
needs no C toolchain for the target at all.

## Verifying it actually ran

```bash
jm ssh -- bastille list                                   # JID, state, IP
jm ssh -- bastille cmd mcp-gateway-test file /var/db/mcp-gateway.db  # confirms a real SQLite file
```

## Tearing down

```bash
jm ssh -- bastille stop mcp-gateway-test
jm ssh -- bastille destroy mcp-gateway-test   # jail + its ZFS dataset
jm stop                                        # stop the whole VM, if nothing else needs it
```

## What this does and doesn't prove

Proves the binary runs unmodified on real FreeBSD (not just cross-compiles
cleanly) and that `modernc.org/sqlite` works without cgo on this target.

That was *all* it proved until 09 Sep 2026, because `cmd/mcp-gateway` was
the Phase 1 stub -- everything built in Phases 2-5 was unreachable from the
binary this script deploys. **Phase 6 changed that:** the composition root
exists, so what lands in the jail is now the real program.

What this script still does *not* set up, and what a real deployment needs
before `serve` will start:

  - **the age identity** (ADR-0005) and **the Ed25519 signing key**
    (ADR-0006), both owner-only. `serve` refuses to start on a signing key
    the group can read, and prints the `chmod` to fix it -- that refusal
    is the control working, not an obstacle to route around.
  - **`sops` on the jail's PATH.** The vault shells out to it (ADR-0005).
  - **the OIDC issuer reachable from inside the jail.** Discovery happens
    at startup, so an unreachable issuer stops the process from coming up
    at all -- not just from authenticating. See "Rotating credentials"
    below and the operator note in ADR-0008.
  - **a published port** (`bastille rdr`) for analysts to reach the
    endpoint. Note that `listen` defaults to loopback on purpose.

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
credential is still in active use by every connected upstream." Nothing in
the system currently warns about this -- making it warn, or making a
reconnect possible without a full restart, is tracked as ISSUE-20.

### The Ed25519 signing key (ADR-0006)

Replace the key file, then **re-sign every registry entry** with
`mcp-gateway sign NAME`. Entries signed with the old key will not verify
against the new one, and with `require_signed` on (the default) they will
not be served. `sign` tells you when it replaced a signature made by a
different key -- if you did not just rotate, find out whose key that was.
