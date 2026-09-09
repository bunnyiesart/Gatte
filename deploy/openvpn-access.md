# Reaching the jails: an OpenVPN tunnel

The jails live on `10.17.89.0/24` inside the `jailmachine` VM. The Mac has no
route there and cannot get one, because the VM's network is a **gvproxy**
userspace stack: the guest is `192.168.127.2` on a network that exists only
inside a process on the Mac, and the only way in is a port forward gvproxy
agrees to make. That is fine for one SSH port. It does not scale to "reach an
arbitrary jail on an arbitrary port", and it gives you nothing to authenticate
against.

So: one UDP port forward, carrying an OpenVPN tunnel, and the tunnel carries
the route to the jail subnet. One hole in gvproxy instead of one per service,
and the hole is useless without a client certificate.

```
  macOS                                    jailmachine VM (FreeBSD 15.1)
  ┌──────────────────────────┐             ┌─────────────────────────────────┐
  │ openvpn client           │             │ openvpn server                  │
  │   utunN  10.8.0.2        │             │   tun0   10.8.0.1               │
  │   route 10.17.89.0/24 ───┼──┐          │                                 │
  │                          │  │          │   bastille0 (lo clone)          │
  │ 127.0.0.1:1194 ──────────┼──┼─┐        │     10.17.89.10  mcp-gateway-test│
  └──────────────────────────┘  │ │        │     10.17.89.20  authelia       │
                                │ │        └─────────────────────────────────┘
              gvproxy (on the Mac, userspace)      ▲
                127.0.0.1:1194/udp ────────────────┘ 192.168.127.2:1194/udp
```

Not a security control for anything the gateway does. `.hardening.toml` and
the ADRs under `design/` are unaffected. This is lab access plumbing.

> **Correction, 09 Sep 2026: there are two jail subnets now, and the
> gateway moved.**
>
> `mcp-gateway-test` was converted to a **VNET** jail and is at
> **`10.17.90.10`**, on a real bridge (`socbr0`, host side `10.17.90.1/24`),
> not on the `bastille0` loopback clone. A VNET jail needs layer 2 to attach
> an epair to, and `bastille0` has none; it could not stay on
> `10.17.89.0/24` because a jail whose own `/24` covers `10.17.89.20` would
> treat Authelia as on-link and ARP for it on a bridge where nothing
> answers. See `deploy/gateway-vnet.md`, "Subnet".
>
> Consequences for this document:
>
>   - The server now pushes **two** routes, `10.17.89.0/24` *and*
>     `10.17.90.0/24`. `deploy/openvpn-vm-setup.sh` writes both. A client
>     connected before this change has only the first and silently has no
>     route to the gateway -- reconnect.
>   - Everywhere below that says `10.17.89.10`, read `10.17.90.10`. The
>     recorded command transcripts are left as they were run, because
>     editing captured output to match a later reality is how a lab notebook
>     stops being evidence. The diagram is the same: `mcp-gateway-test` has
>     moved off `bastille0` onto `socbr0`.
>   - `10.17.89.20 authelia` is unchanged, still a classic jail on
>     `bastille0`.
>
> Untested at the time of writing: the client's view. No Mac client was
> connected when the route was added, so "a VPN client reaches
> `10.17.90.10`" is expected, not measured. Run the probes below after
> reconnecting.

## Two CAs, on purpose

There are two certificate authorities in this lab and they must not become one.

| | VPN CA (this document) | internal TLS CA (other stream) |
|---|---|---|
| Lives at | `/usr/local/etc/openvpn/pki`, in the VM | wherever the web-cert stream puts it |
| Signs | VPN peers: one server cert, one client cert per machine | server certs for the jails' HTTPS endpoints |
| Trusted by | the OpenVPN server and the OpenVPN client, and nothing else | browsers, the gateway, anything doing HTTPS to a jail |
| Answers | "may this machine join the network?" | "am I talking to the right host?" |

They answer different questions and they have different blast radii. Merge
them and a certificate issued to let one laptop onto the VPN is also a
certificate that can impersonate `authelia` to every HTTPS client in the lab,
because nothing in a basic X.509 chain stops it -- the client cert has
`extendedKeyUsage = TLS Web Client Authentication` today only because easy-rsa
put it there for this CA's purposes, and one careless reissue removes that.
Two CAs makes that mistake impossible rather than merely unlikely.

Practical consequence: revoking a laptop's VPN access must not require
reissuing web certs, and rotating a web cert must not touch anyone's ability
to connect. That separation is the entire point.

## Setting it up

```bash
./deploy/openvpn-setup.sh
```

Idempotent. Runs `deploy/openvpn-vm-setup.sh` inside the VM (packages, PKI,
server config, `net.inet.ip.forwarding`, service), pulls the client
credentials back out into a profile, and adds the gvproxy forward. Re-running
reuses the existing CA and certificates; it does rewrite `openvpn.conf` and
restart the service, so hand-edits to that file are lost.

## Routing: what is actually required

This is the part where it is easy to add rules that do nothing. What follows
was checked against the running system, not assumed.

**`net.inet.ip.forwarding=1`** -- set, persistently, in `/etc/sysctl.conf`.
It was `0`.

**It is probably not load-bearing today, and it is still correct to set it.**
The jail addresses are `/32`s on `bastille0`, which is a *loopback clone*:

```
bastille0: flags=1008049<UP,LOOPBACK,RUNNING,...>
        inet 10.17.89.10 netmask 0xffffffff
        inet 10.17.89.20 netmask 0xffffffff
```

A packet arriving on `tun0` for `10.17.89.10` is destined for an address the
host already owns, so it is delivered locally rather than forwarded, and the
forwarding sysctl never enters the decision. The moment any jail becomes a
VNET jail on an `epair` -- a different interface with a genuinely remote
address -- that stops being true and the sysctl becomes the difference between
working and silently dropping. Setting it costs nothing and removes a trap.
If you want to know for certain, bring the tunnel up and run
`jm ssh -- sysctl net.inet.ip.forwarding=0`, retest, and set it back; that
experiment has **not** been run here.

**A pushed route** -- `push "route 10.17.89.0 255.255.255.0"`. Confirmed
arriving at the client (see "What is proven" below).

**No `pf` rule, and no NAT.** Deliberately nothing, and this was checked
rather than skipped:

```
# jm ssh -- pfctl -s rules
(empty)
```

`pf` is enabled but its filter ruleset is empty, which means default-pass;
there is nothing to punch a hole through. The existing `nat` entries are for
the `<jails>` and `<cni-nat>` tables going *out* to `vtnet0`, which is jail
egress to the internet and has nothing to do with this path. NAT is not needed
inbound either, because the jails' replies to `10.8.0.0/24` already have a
route:

```
# jm ssh -- route -n get 10.8.0.2
  interface: tun0
```

Adding a NAT rule here would work, and would also hide every client's real
tunnel address behind `10.8.0.1` in the jails' logs, for no gain. So: none.

**No `redirect-gateway`.** The Mac's normal internet traffic must not come
through a lab VM. This tunnel is the only route to `10.17.89.0/24` and is not
a route to anything else.

## The Mac already routes 10.0.0.0/8 somewhere else

Worth knowing before you debug the wrong thing. This machine has a corporate
VPN on `utun5` holding a `10/8` route:

```
Destination        Gateway            Flags               Netif
10                 10.69.71.17        UGSc                utun5
192.168.0/16       10.69.71.17        UGSc                utun5
```

Two consequences.

**The lab route wins, by being more specific.** `10.17.89.0/24` beats `10/8`
on longest-prefix match, so the tunnel takes precedence while it is up. If the
corporate VPN ever starts pushing something equally or more specific for that
range, it stops winning, and the symptom will be a tunnel that connects fine
and reaches nothing.

**It is also why the without-tunnel test times out instead of saying "no route
to host".** With the tunnel down, packets for `10.17.89.10` are handed to the
corporate VPN, which black-holes them. Unreachable either way, but the error
message is misleading.

It is also why the client connects to `127.0.0.1:1194` rather than to the
VM at `192.168.127.2:1194` directly: `192.168.0/16` is *also* pointed at
`utun5`, so the direct address would be swallowed by the corporate VPN.
Loopback plus a gvproxy forward sidesteps that entirely.

## The gvproxy UDP forward

gvproxy's control API does accept UDP -- verified, not assumed:

```bash
./deploy/openvpn-forward.sh up       # POST /services/forwarder/expose
./deploy/openvpn-forward.sh status   # GET  /services/forwarder/all
./deploy/openvpn-forward.sh down     # POST /services/forwarder/unexpose
```

```json
[{"local":"127.0.0.1:1194","remote":"192.168.127.2:1194","protocol":"udp"},
 {"local":"127.0.0.1:2222","remote":"192.168.127.2:22","protocol":"tcp"}]
```

`up` and `down` are both idempotent and `down` genuinely removes it -- after
it, nothing holds `udp/1194` on the Mac.

**It does not survive a VM restart.** The forward lives in the running gvproxy
process, not on disk. After `jm stop && jm start`, run
`./deploy/openvpn-forward.sh up` again. The server side does survive: it is in
`rc.conf`.

## The client profile

```
~/.config/mcp-gateway-lab/openvpn/mcp-gateway-lab.ovpn
```

Mode `600`, in a `700` directory, **outside this repository**, with the CA
cert, the client cert, the client key and the tls-crypt key inlined. It
contains an unencrypted private key.

**Do not move it into the repo.** `.gitignore` already covers `*.ovpn`,
`*.key` and `*.pem`, and `.githooks/pre-commit` blocks any diff containing a
`-----BEGIN ... PRIVATE KEY-----` line. Both are correct and neither is an
obstacle to route around: the profile has no business being version
controlled, and `git commit --no-verify` to force one in would be the actual
mistake. `deploy/openvpn-setup.sh` refuses outright to write the profile
anywhere under the repository root.

To issue a profile for a second machine, use a different CN so the two can be
told apart and revoked independently:

```bash
CLIENT_NAME=other-laptop OVPN_PROFILE_DIR=~/somewhere-else ./deploy/openvpn-setup.sh
```

## Connecting -- this part needs your hands

The macOS client needs root: it creates a `utun` device and installs a route.
Neither is possible without privilege escalation, and `sudo` on this machine
requires a password.

```bash
sudo openvpn --config ~/.config/mcp-gateway-lab/openvpn/mcp-gateway-lab.ovpn
```

Leave it running. In another terminal:

```bash
ping -c 3 10.17.89.10
nc -vz 10.17.89.10 443
nc -vz 10.17.89.20 443
netstat -rn -f inet | grep 10.17.89     # expect: 10.17.89/24 ... utunN
```

Nothing is listening on `443` in either jail yet. With the tunnel up you should
therefore get **`Connection refused`** from `nc`, not a timeout -- that is the
success signal, and it is a different signal from the without-tunnel case.
`ping` should succeed outright; both jails answer ICMP.

Stop the tunnel with Ctrl-C, or `sudo pkill -f 'openvpn --config'`.

## What is proven, and what is not

### Proven, by running it

**The without-tunnel case fails.** Run after the whole setup was in place, so
this is not a stale baseline -- nothing built here created a non-VPN route:

```
$ netstat -rn -f inet | grep -E "10\.17\.89|10\.8\.0"
(no route to 10.17.89.0/24)

$ ping -c 2 -t 3 10.17.89.10
2 packets transmitted, 0 packets received, 100.0% packet loss
ping exit=2

$ nc -vz -G 3 -w 3 10.17.89.10 443
nc: connectx to 10.17.89.10 port 443 (tcp) failed: Operation timed out

$ nc -vz -G 3 -w 3 10.17.89.20 443
nc: connectx to 10.17.89.20 port 443 (tcp) failed: Operation timed out
```

**The server is up, unprivileged, and listening.**

```
# service openvpn status      -> openvpn is running as pid 25767
# sockstat -4 -l | grep 1194  -> openvpn openvpn 25767 6 udp4 *:1194 *:*
# sysctl net.inet.ip.forwarding -> net.inet.ip.forwarding: 1
# ifconfig tun0               -> inet 10.8.0.1 netmask 0xffffff00
```

**A real client on the Mac completes the handshake through the gvproxy UDP
forward and is pushed the jail route.** This was run as an ordinary user with
`--dev null --ifconfig-noexec --route-noexec`, which needs no tun device and
therefore no root, so it exercises everything except the last hop:

```
VERIFY OK: depth=1, CN=mcp-gateway-lab-vpn-ca
VERIFY OK: depth=0, CN=server
[server] Peer Connection Initiated with [AF_INET]127.0.0.1:1194
PUSH: Received control message: 'PUSH_REPLY,route 10.17.89.0 255.255.255.0,
  route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,
  ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-256-GCM,...'
OPTIONS IMPORT: route options modified
Initialization Sequence Completed
```

That is: the UDP forward carries traffic both ways, tls-crypt is right, the
client cert is accepted, the server cert passes `remote-cert-tls server`, and
the client receives `route 10.17.89.0 255.255.255.0` and `10.8.0.2`.

**Traffic sourced from the VPN subnet reaches both jails, including on 443.**
Run inside the VM, sourcing from the tunnel address:

```
# ping -c 2 -S 10.8.0.1 10.17.89.10   -> 0.0% packet loss
# ping -c 2 -S 10.8.0.1 10.17.89.20   -> 0.0% packet loss
# nc -vz -s 10.8.0.1 10.17.89.10 443  -> Connection to 10.17.89.10 443 succeeded!
```

(the `443` listener for that last one was a temporary `nc` started via
`bastille cmd` and killed afterwards; nothing in the jail was modified)

### Not proven

**The final hop: IP packets from the Mac's `utun`, through the tunnel, to a
jail.** It needs `sudo` and an interactive password, which could not be
supplied. Everything on both sides of that hop is verified independently --
the tunnel establishes from the Mac, and VPN-sourced packets reach the jails
inside the VM -- but the two halves have not been observed joined up. Run the
commands under "Connecting" to close it.

**Sustained throughput and large packets.** Only control-channel traffic and a
handshake have crossed this tunnel. `tun-mtu` is 1500 over UDP over a 1500-MTU
`vtnet0`, so full-size encapsulated packets will fragment, and gvproxy is a
userspace stack whose fragment handling has not been exercised here. TCP is
protected by `mssfix 1492`, so HTTPS to `:443` should be fine; a large UDP
payload might not be. If you see small requests working and large ones hanging,
that is this: add `tun-mtu 1400` to the server config and re-run the setup.

**Whether `net.inet.ip.forwarding=1` is required.** See "Routing" above --
reasoned, not tested.

**Anything about `authelia`.** The jail exists at `10.17.89.20` and answers
ICMP. Nothing was listening on `443` there when this was written.

### A trap that was hit, and is now fixed

Worth recording because it fails in a way that looks like a network problem.
OpenVPN 2.7 defaults to **DCO**, its in-kernel data path, and DCO keeps
issuing privileged ioctls for the life of the process -- so it cannot coexist
with `user openvpn` / `group openvpn`. With both enabled the server starts
cleanly, logs `Initialization Sequence Completed`, and then dies the moment a
client connects:

```
Failed to poll for packets: Operation not permitted (errno=1)
MULTI_sva: pool returned IPv4=10.8.0.2
Failed to create new peer: Operation not permitted (errno=1)
Exiting due to fatal error
```

From the client, that looks like nothing at all: the TLS handshake succeeds,
then `PUSH_REQUEST` is sent three times to a server that no longer exists and
the connection hangs. It reads as a dropped-packet problem and it is not.

The config now sets `disable-dco` and keeps the privilege drop. Userspace
forwarding is far more capacity than two jails on a loopback will ever need,
and the alternative is running a network-reachable process as root. It also
leaves a stale `tun` interface behind when it dies this way, so the setup
script clears orphaned interfaces in the `openvpn` group before starting.

## Undoing all of it

```bash
./deploy/openvpn-teardown.sh
```

Removes the gvproxy forward, stops and disables the service, deletes the PKI,
the tls-crypt key, the server config and the local profile.

Deliberately left alone, because removing them could break something else:

- **the `openvpn` and `easy-rsa` packages.** `jm ssh -- pkg delete -y openvpn easy-rsa`.
- **`net.inet.ip.forwarding`.** `REVERT_FORWARDING=1 ./deploy/openvpn-teardown.sh`
  drops the `/etc/sysctl.conf` line and sets it back to `0`.

`KEEP_PKI=1` keeps the CA and certificates so you can tear down and rebuild
without reissuing the client profile.

Individual pieces, if you want finer control:

| To undo | Command |
|---|---|
| the Mac-side forward only | `./deploy/openvpn-forward.sh down` |
| the server, keeping the PKI | `jm ssh -- service openvpn stop` |
| autostart | `jm ssh -- sysrc -x openvpn_enable openvpn_configfile` |
| the profile | `rm ~/.config/mcp-gateway-lab/openvpn/mcp-gateway-lab.ovpn` |

## Files

| | |
|---|---|
| `deploy/openvpn-setup.sh` | Mac-side orchestrator; run this |
| `deploy/openvpn-vm-setup.sh` | runs inside the VM as root; PKI, config, service |
| `deploy/openvpn-forward.sh` | `up` / `down` / `status` for the gvproxy UDP forward |
| `deploy/openvpn-teardown.sh` | reverses the lot |
| `/usr/local/etc/openvpn/` (in the VM) | PKI, `tls-crypt.key`, `openvpn.conf` |
| `/var/log/openvpn.log` (in the VM) | first place to look when a client will not connect |
