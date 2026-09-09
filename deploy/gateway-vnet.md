# The gateway jail is a VNET jail

`mcp-gateway-test` has a network stack of its own -- its own `lo0`, its own
routing table, its own `127.0.0.1`. Read `deploy/freebsd-jail.md` first for
`jm`, `bastille`, and the conventions this follows.

| | |
|---|---|
| Jail | `mcp-gateway-test` |
| Type | thin jail, **VNET** (`if_bridge` + `epair`) |
| Address | `10.17.90.10/24` on its own `vnet0` |
| Host side | bridge `socbr0` at `10.17.90.1/24` (clone unit `bridge10`) |
| Epair | `e0a_mcpgw` (host, bridge member) ↔ `e0b_mcpgw` → renamed `vnet0` in the jail |
| Names | `mcp.soc.internal` (10.17.90.10), `id.soc.internal` (10.17.89.20) |
| Outbound | NAT out `vtnet0`, via `10.17.90.0/24` in pf's `<jails>` table |
| VPN | `10.17.90.0/24` pushed to clients alongside `10.17.89.0/24` |

```bash
./deploy/gateway-vnet.sh           # convert (idempotent)
./deploy/gateway-vnet-verify.sh    # the acceptance test
./deploy/gateway-vnet-rollback.sh  # back to a classic jail at 10.17.89.10
```

The `authelia` jail is untouched by all three. It is still a classic jail at
`10.17.89.20` on `bastille0`, and `./deploy/authelia-verify.sh` still passes.

## Why

`design/adr/0011` decides that the gateway **refuses** any bind that is not
loopback, and that nginx in the same jail terminates TLS on the jail's
routable address. The CORREÇÃO block in that ADR then records, on the same
day, that the premise underneath it was false.

A classic (non-VNET) jail has no loopback of its own. It is handed a set of
addresses on the host's stack, and a process that binds `127.0.0.1` inside it
has that bind **rewritten to the jail's routable address**. Measured in this
very jail, before the conversion:

```
$ bastille cmd mcp-gateway-test sh -c "nc -l 127.0.0.1 18080 &"
$ bastille cmd mcp-gateway-test sockstat -4 -l | grep 18080
root  nc  36216  3  tcp4  10.17.89.10:18080  *:*
$ nc -z 10.17.89.10 18080          # from the VM host, outside the jail
Connection to 10.17.89.10 18080 port [tcp/*] succeeded!
```

So `requireLoopbackBind` passed, the log said `listen=127.0.0.1:8080`, and
the socket was reachable from the host, from the other jail, and across the
VPN in cleartext -- bypassing the nginx TLS terminator entirely. That is not
a bug in the check. It is a property the environment could not provide, and
no address check inside the process can substitute for it.

This is option (1) of the three that block lists, and the only one that makes
the check mean what it says without adding a second place to verify.

## Subnet: why the jail moved to 10.17.90.10

**Because a VNET jail needs a real bridge, and the classic jails are not on
one.** `bastille0` is a *loopback clone*: the classic jail addresses live on
it as `/32` aliases, which is why `netstat -rn` shows `10.17.89.20 ... UH
bastille0` rather than a subnet route. There is no layer 2 there to attach an
epair to.

A bridge carrying `10.17.89.0/24` would technically coexist with those `/32`
host routes -- a `/32` is more specific, so the host would keep reaching
Authelia through `bastille0`. The problem is one hop further in, and it is
not about the host's routing table at all:

> A VNET jail at `10.17.89.10/24` considers `10.17.89.20` **on-link**. It
> would ARP for Authelia on `socbr0`, where nothing answers, and the OIDC
> discovery the gateway performs at startup would fail. It would need a
> host route for `10.17.89.20` installed inside the jail -- a per-address
> exception, maintained by hand, that has to be remembered for every future
> classic jail.

Giving the VNET jail its own `10.17.90.0/24` makes `10.17.89.20` simply
off-link: it goes to the default route, the host forwards it to `bastille0`,
and Authelia answers. No exceptions, no `/32` inside the jail, and a routing
table where each destination appears exactly once (`gateway-vnet-verify.sh`
step 5 asserts that).

The cost is real and is paid in three places, all of them handled:

  - **`/etc/hosts`.** `mcp.soc.internal` moves to `10.17.90.10`, in the jail
    and on the VM host. The convert script does both; the rollback undoes
    both.
  - **The VPN.** `deploy/openvpn-vm-setup.sh` now pushes *two* routes.
    Dropping the second does not fail loudly -- the client just silently has
    no route to the gateway.
  - **The TLS certificate.** When nginx lands in this jail, its certificate
    must carry `IP:10.17.90.10`, not the old address:
    `jm ssh -- /usr/local/etc/soc-ca/issue.sh mcp.soc.internal 10.17.90.10`.
    `deploy/gateway-jail/nginx.conf` already listens on the new address.

`net.inet.ip.forwarding` was already 1 and was decorative while everything
shared one stack. With VNET it is load-bearing: every packet between this
jail and anything else, Authelia included, is routed by the host. The verify
script asserts it rather than assuming it.

## What the conversion actually changes

On the VM host:

  - `cloned_interfaces` gains `bridge10`, renamed `socbr0`, addressed
    `10.17.90.1/24` -- appended to the existing `lo1`, never replacing it,
    or Authelia loses `bastille0` on the next reboot.
  - `/etc/pf.conf`'s `table <jails> persist` becomes
    `table <jails> persist { 10.17.90.0/24 }`, and the subnet is added to the
    live table. **Deliberately without `pfctl -f`:** reloading replaces a
    persist table's contents with the file's, which would drop the
    `10.17.89.x` entries bastille added at jail start -- Authelia's among
    them -- until those jails restart.
  - `/usr/local/etc/openvpn/openvpn.conf` gains a second `push "route"`,
    marker-delimited so the rollback can remove exactly it.
  - `/etc/hosts`: `mcp.soc.internal` → `10.17.90.10`.

In `jail.conf`:

  - `vnet;` and `vnet.interface = e0b_mcpgw;`, with `exec.prestart` hooks
    that create the epair and add the host half to `socbr0`, and an
    `exec.poststop` that destroys it. This mirrors bastille's own if_bridge
    VNET template (`generate_vnet_jail_netblock` in
    `/usr/local/share/bastille/common.sh`).
  - **`ip4.addr` and `ip6 = disable` are gone**, and they have to be. Both
    are IP restrictions the host imposes on a shared stack, and jail(8)
    rejects them outright on a VNET jail:

    ```
    jail: mcp-gateway-test: vnet jails cannot have IP address restrictions
    ```

    which is the same fact this whole conversion is about, said from the
    other side: the host no longer decides what this jail's addresses are.

Inside the jail, in `/etc/rc.conf`:

```
ifconfig_e0b_mcpgw_name="vnet0"
ifconfig_vnet0="inet 10.17.90.10/24"
defaultrouter="10.17.90.1"
```

Written by editing the file, not with `sysrc -R`: `sysrc -R` chroots, and a
**stopped thin jail has no `/bin/sh`** -- its base is a nullfs mount that
only exists while the jail is running. `sysrc -R` there fails with
`chroot: /bin/sh: No such file or directory`.

Two things the epair names are worth a sentence about: `e0a_mcp-gateway-test`
is 20 characters and `IFNAMSIZ` is 16, so a literal jail-name-derived epair is
impossible. Bastille falls back to a counter (`e0a_bastilleN`); this uses a
fixed short name instead, because a counter is not recognisable in `ifconfig`
output six months later.

## The acceptance test

`./deploy/gateway-vnet-verify.sh`. It is deliberately the *same* sequence
that proved the property absent, run against the converted jail, expecting
the opposite answer. Both halves, from a real run:

```
== 1. a listener on 127.0.0.1:18080 stays on 127.0.0.1
--- bastille cmd mcp-gateway-test sockstat -4 -l | grep 18080 ---
  root nc  10121  3  tcp4  127.0.0.1:18080  *:*
  ok   -- bound to 127.0.0.1:18080, not rewritten to the jail's address

== 2. that listener is unreachable from outside the jail
  ok   -- VM host cannot reach 10.17.90.10:18080
  ok   -- VM host cannot reach 10.17.90.1:18080 (the bridge address)
  ok   -- the VM host's own 127.0.0.1:18080 is silent
  ok   -- the authelia jail cannot reach 10.17.90.10:18080

== 3. control: a listener on the jail's ROUTABLE address IS reachable
  ok   -- VM host reaches 10.17.90.10:18081
```

**Step 3 is not decoration.** Without it, step 2 would pass just as happily
on a jail whose networking is simply broken, and "unreachable" would mean "no
route" rather than "isolated". A test that cannot fail for the right reason
is not evidence.

The same script also checks that the jail still reaches the IdP over TLS with
the CA (step 4 -- the gateway does OIDC discovery at startup and will not come
up without it, ADR-0008), that no `10.17.x` destination appears twice in the
routing table and forwarding is on (step 5), and that `authelia` is still a
classic jail still answering on 443 (step 6).

One trap worth recording, because it made the first run report four vacuous
passes: `sockstat` prints the endpoint as `ADDRESS:PORT`, so the port is not
a whitespace-delimited field. Grepping for `" 18080 "` matches nothing, the
listener looks absent, and every "cannot reach" below it is true for the
wrong reason. The script now greps `":18080 "` and *skips* step 2 outright,
loudly, if step 1 found no listener.

### Verified end to end

Convert → verify → **`jm stop; jm start`** → verify → rollback → confirm the
classic defect is back → convert → verify. All green, including across the
reboot: `socbr0` is re-cloned from `rc.conf`, the pf table entry comes back
from `pf.conf`, and `bastille list` shows `10.17.90.10` again with no manual
step.

## Rollback

```bash
./deploy/gateway-vnet-rollback.sh
```

**Read this before running it.** Rolling back restores the exact defect
ADR-0011 was written to close: a bind to `127.0.0.1` becomes a bind to
`10.17.89.10`, reachable from the host, from the other jails, and across the
VPN in cleartext, while the gateway's own check reports success. This is an
unblock-other-work button, not a supported configuration. It has been
exercised, and it does restore the defect -- verified:

```
root nc  7635  3  tcp4  10.17.89.10:18080  *:*
Connection to 10.17.89.10 18080 port [tcp/*] succeeded!
```

What it undoes, in order: stops the jail and reaps a leftover `e0a_mcpgw`;
restores `jail.conf` from `jail.conf.classic` (saved by the convert script
before it changed anything, and never overwritten on a re-run -- that file is
the rollback's whole basis, which is why the convert script refuses to run at
all if it finds a VNET `jail.conf` without one); strips the four VNET lines
from the jail's `rc.conf`; points `mcp.soc.internal` back at `10.17.89.10`
in both hosts files; restores `/etc/pf.conf` from `/etc/pf.conf.pre-vnet` and
drops the table entry; removes the pushed route and restarts openvpn;
destroys `socbr0` and removes it from `cloned_interfaces` -- **unless the
bridge still has members**, in which case another stream has put something on
it and taking it out is not this script's call.

Idempotent, and a no-op with exit 0 on a jail that was never converted.

## The one thing this leaves stale

The `authelia` jail's `/etc/hosts` still says `10.17.89.10 mcp.soc.internal`.
That is deliberate: the brief for this work was not to touch that jail, and
nothing in Authelia resolves the gateway's name -- OIDC redirects are
resolved by the *client*, not by the provider. `deploy/vm/authelia-host-setup.sh`
now defaults `GATEWAY_IP` to `10.17.90.10`, so the next legitimate run of the
Authelia provisioner corrects it, at a moment when restarting that jail is
somebody's intent rather than a side effect.

If you want it fixed sooner, it is one line and it does not need a restart:

```bash
jm ssh -- sh -c "sed -i '' 's/^10\.17\.89\.10\t*mcp\.soc\.internal/10.17.90.10\tmcp.soc.internal/' \
    /usr/local/bastille/jails/authelia/root/etc/hosts"
```

## What this does and does not prove

**Proves**, by measurement rather than by reading a config: the gateway jail
has a private loopback; a bind to `127.0.0.1` inside it stays on
`127.0.0.1`; that socket is unreachable from the VM host, from the host's own
loopback, and from the `authelia` jail; the jail's routable address *is*
reachable, so the previous sentence is isolation and not a dead network; the
jail still completes OIDC discovery against `https://id.soc.internal` over
TLS with the SOC CA; and all of that survives a VM reboot.

Together with `requireLoopbackBind` in the binary, that is ADR-0011 item 1
actually holding in this deployment for the first time.

**Does not prove**, and is not claimed:

  - Anything about the VPN client's view. The pushed route is in the server
    config and openvpn restarted cleanly, but no Mac client was connected
    during this work, so "a VPN client can reach 10.17.90.10 and cannot
    reach 127.0.0.1 in the jail" is untested. Reconnect and run the probes in
    `deploy/openvpn-access.md`.
  - That nginx terminates TLS in front of the gateway. Neither nginx nor a
    `mcp.soc.internal` certificate exists in this jail yet; only the CA root
    and the binary are installed. ADR-0011 item 2 remains unimplemented, and
    its certificate must be issued for `10.17.90.10`.
  - That `mcp-gateway serve` runs here. There is still no configuration file,
    vault, or age identity in the jail -- see `deploy/freebsd-jail.md`, "What
    this script does *not* set up". The conversion changes the network, not
    the deployment.
  - Anything about IPv6. The jail's `lo0` has `::1` and `vnet0` has no IPv6
    address; `ip6 = disable` could not be carried over, so IPv6 is now the
    jail's own business rather than the host's. Nothing listens on it today.
