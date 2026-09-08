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
Does **not** exercise anything past Phase 1 -- there's no MCP-serving
behavior, no credential handling, and nothing here should be read as a
statement about production deployment shape, which hasn't been designed.
