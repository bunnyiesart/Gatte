# jailmap

A read-only live map of a FreeBSD jail host: what is running, what is
listening, who is connected to whom, and which MCP upstreams the gateway
has actually spawned. It samples continuously in the background and serves
a dashboard, or prints the same data once for scripting.

It exists because `sockstat` answers the wrong question. `sockstat` tells
you what exists *at this instant*, and the connections that matter most on
this host do not last an instant. The single most interesting edge in this
lab — nginx reaching `127.0.0.1:8080` **inside** the `mcp-gateway-test`
VNET jail, the hop
[ADR-0011](../../design/adr/0011-network-exposure-and-tls-termination.md)
exists to force — is open for a few milliseconds. Sampled by hand during
live traffic, a single `sockstat` run showed nothing; it took roughly
twenty-five tight repeats in a loop before it appeared. A tool that renders
an empty graph on a working system is worse than no tool, so jailmap keeps
a **rolling window** of everything it saw, with first- and last-seen times
so a stale edge is never mistaken for a live one.

## Strictly read-only

jailmap observes. It does not act.

The complete set of commands it will ever run is:

```
jls -h jid name path host.hostname ip4.addr vnet
sockstat -4l -j <jid>
sockstat -4c -j <jid>
ifconfig
ps -axo pid,ppid,jid,user,etime,command
pfctl -s info
pfctl -s rules
jexec <jail> ifconfig
```

That list is `readOnlyCommands` in `collect.go`, and it is **enforced**, not
documented: `execRunner.Run` refuses any other program, and pins the three
whose arguments decide what they do.

- `jexec` is refused with any inner command other than `ifconfig`.
- `pfctl` is refused in any mode but `-s`, and with any report but `info`
  and `rules`. `pfctl -s` reports and needs no write access to the
  firewall; `-e`, `-d`, `-f` and `-F` are the same binary and are refused
  here rather than merely not being called anywhere.
- `ps` is refused with anything but `-axo` and the one format string above.

There is no code path that starts, stops, restarts or reconfigures a jail,
a service, an interface or a firewall, and no file it opens for writing.
The HTTP server answers `GET` and `HEAD` and returns `405` to everything
else. `TestRunnerRefusesAnythingThatCouldChangeSomething` is where that is
checked, including `pfctl -d`.

It does need to run as root on the jail host, because `sockstat -j`,
`jexec`, and seeing other jails' processes in `ps` all do.

## Build and install

Pure Go, standard library only, `CGO_ENABLED=0`. The dashboard is compiled
in with `embed`, so the binary is the whole program.

```sh
CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -trimpath -o jailmap ./tools/jailmap
scp jailmap root@jailhost:/usr/local/bin/jailmap
```

## Running it

### Dashboard

```sh
jailmap serve                       # 127.0.0.1:8088, 5m window, 250ms sampling
jailmap serve -window 15m -interval 100ms
```

Flags: `-listen`, `-window` (how long a connection stays on the map after it
was last seen), `-interval` (socket sampling period), `-cmd-timeout`,
`-gateway-command` (the executable name whose children are reported as MCP
upstreams; default `mcp-gateway`).

`GET /api/snapshot` returns the same data as JSON, and `GET /healthz`
returns `ok`.

### One shot

```sh
jailmap snapshot                    # samples for 3s, then prints
jailmap snapshot -for 10s -max 0    # longer window, uncapped detail list
jailmap snapshot -json | jq .edges  # for scripting
```

`-for 0` does a single pass. It will usually miss the in-jail hop, which is
the whole point of the default.

## Reaching the dashboard from a workstation

**Over an SSH tunnel. There is no other way, by design.**

```sh
ssh -N -L 8088:127.0.0.1:8088 root@jailhost
# then open http://127.0.0.1:8088/ on the workstation
```

For this lab's VM, `jm ssh` already forwards to port 2222:

```sh
ssh -N -p 2222 -i ~/.jailmachine/machines/jailmachine/ssh/id_ed25519 \
    -L 8088:127.0.0.1:8088 root@127.0.0.1
```

jailmap **refuses** a non-loopback bind. It does not warn:

```
$ jailmap serve -listen 0.0.0.0:8088
jailmap: listen: "0.0.0.0:8088" is not a loopback address, and jailmap refuses to be network-reachable (design/adr/0011)
This dashboard is a live map of every jail's listeners, addresses and connections, with no auth and no TLS.
Set -listen to 127.0.0.1:8088 and reach it over an SSH tunnel: ssh -L 8088:127.0.0.1:8088 <host>
```

This is the same rule, and the same reasoning, as `requireLoopbackBind` in
`cmd/mcp-gateway/serve.go`. The dashboard is a complete reconnaissance
report on the box — every jail, every address, every listener, which ones
are in cleartext, and who is talking to whom right now — that refreshes
itself, with no authentication and no TLS. There is deliberately no
override flag, for the reason ADR-0011 gives about `allow_insecure_bind`:
it would be switched on once "so a colleague can look" and never switched
off.

## What it shows

**What is running.** Host and jails, each tagged `host` / `classic` /
`vnet`, with the addresses each one owns. The tag is not decoration: it
changes what an address *means*. A classic (non-VNET) jail shares the host
network stack, so a bind to `127.0.0.1` inside it is silently rewritten to
the jail's routable address, and jailmap says so on the card.

**Which MCP servers are actually running.** See below — this is the one
thing on the box that has no sockets at all, so it is not on the map, it is
a process tree.

**What is listening**, with the bind classified by what it means:

| verdict | meaning |
|---|---|
| `local` | loopback of a stack nothing else shares — a VNET jail's own `127.0.0.1` |
| `encrypted` | routable, on a port where transport encryption is the norm |
| `plaintext` | routable, in the clear |
| `rewritten` | "loopback" inside a classic jail: the process believes it is private and is not |

…and, separately, by whether the firewall stands in front of it:

| reachability | meaning |
|---|---|
| `filtered` | pf is up and default-denies inbound: the bind alone does not make the port reachable |
| `unfiltered` | pf is off, or up with an empty ruleset: nothing stands in front of the bind |
| `unknown` | pf could not be read, or the ruleset is one jailmap declines to interpret, or the listener is inside a VNET jail |

These are two facts and are printed as two, which is the fix for a real
piece of crying wolf — see [pf-qualified exposure](#pf-qualified-exposure).

**Who is talking to whom**, both ends resolved to participant names, in
three groups: `in-jail` (both ends inside one jail's own stack),
`internal` (between the host and its jails), and `external` (one end is not
in the address book). Every row carries an age, drawn as a bar as well as a
number, because the window shows what *was* seen, not only what *is* there.

### Address resolution, and the trap it avoids

`127.0.0.1` has no global meaning. Observed under jid 5 it is the
`mcp-gateway-test` VNET jail's private loopback; observed under jid 0 it is
the host's. jailmap resolves every loopback address **relative to the jail
whose socket table it came from**. Resolving it globally would file the
in-jail nginx → gateway hop as host traffic — silently wrong about the one
edge the tool was built to show. There is a test for exactly this
(`TestVNETJailLoopbackResolvesToTheJailNotTheHost`).

The mirror case is handled too: a classic jail's address lives on the
host's `bastille0` loopback clone as a `/32` alias, so it appears in the
host's own `ifconfig`. The jail still owns it, so jail entries override
host interface entries in the address book.

An address that belongs to nobody in the address book is printed as
sockstat printed it and marked `unknown`. It is never guessed at.

`sockstat -j <jid>` run **from the host** works for both jail kinds,
including the VNET jail, so jailmap does not `jexec` per jail for sockets.
`jexec <jail> ifconfig` is used only for a VNET jail's *addresses*, which
genuinely live in its own network stack.

## The MCP upstreams, which have no sockets

The gateway's MCP upstreams are **stdio subprocesses**. The gateway spawns
each one and speaks to it over a pipe. There is no socket anywhere in that
relationship — no address, no port, nothing for `sockstat` to report — so
for as long as jailmap only knew about sockets, the connection graph
rendered *empty* while four MCP servers were busy serving requests. "Show
me the active MCPs" was not a question the tool could answer at all.

It answers it from the process table instead:

```
MCP UPSTREAMS  (stdio subprocesses: pipes, not sockets -- inferred from the process tree)
  process table read just now
  OWNER             PID    USER  UPTIME  PROCESS
  mcp-gateway-test  63090  1001  4h43m   /usr/local/bin/mcp-gateway serve -config /usr/local/etc/mcp-gateway/config.toml  [gateway, listening on tcp4 127.0.0.1:8080]
                    63094  1001  4h43m     |- /usr/local/libexec/mcp-gateway/lab-logsearch
                    63095  1001  4h43m     |- /usr/local/libexec/mcp-gateway/lab-casemgmt
                    63096  1001  4h43m     |- /usr/local/libexec/mcp-gateway/lab-docsearch
                    63097  1001  4h43m     `- /usr/local/libexec/mcp-gateway/lab-threatintel
```

**They are not network edges and are never drawn as any.** They have their
own section in the terminal output, their own panel on the dashboard, and
their own `gateways` key in `/api/snapshot`. A pipe between a parent and
its child is a different relationship from a TCP connection; putting one in
the connection table would mean inventing an address and a port for it, and
the display would then be lying about the thing this tool exists to get
right. The one part of the gateway that *is* a socket — its own listener —
is shown on the gateway line, because that is where it belongs.

### How an upstream is identified, and why that inference holds

Two steps, and only the first involves a name:

1. A **gateway** is a process whose `argv[0]` **basename** is
   `mcp-gateway` (`-gateway-command` changes the name).
2. An **upstream** is a **direct child of that process, in the same jail**,
   as the kernel reports the parent-child link.

Only step 1 matches a string, and the string it matches is the name of the
binary jailmap ships beside — not anything read out of the gateway. Step 2
is structure, from `ps`.

**jailmap deliberately does not read the gateway's registry or database**,
though that would give it the configured upstream names. An observability
tool that depends on the health of the thing it observes is useless in
precisely the situation you reach for it: a gateway whose database is
locked, corrupt or mid-migration is when you most want to know which of its
children are still alive. The process table is the kernel's, and it is true
whatever state the gateway's own state is in.

Why the inference is sound in practice, and where it is not:

- **The basename match is not a substring match**, which matters here. The
  jail also contains `daemon: /usr/local/bin/mcp-gateway[63090] (daemon)` —
  the `daemon(8)` supervisor, whose argv contains the gateway's full path.
  A substring match picks that process, which has *no* MCP children (they
  belong to the gateway it supervises), and reports an empty tree while
  four upstreams are running. `procName` takes `argv[0]` only, and
  `daemon:` is not a path.
- **Direct children only.** The gateway forks nothing but its stdio
  upstreams, so its direct children *are* the upstream set. Anything deeper
  is counted, not listed: an upstream with descendants of its own shows
  `+N descendants`.
- **The socket table is an independent cross-check.** When `sockstat`
  attributes a listening socket to the same pid the name match picked, the
  gateway line says so (`listening on tcp4 127.0.0.1:8080`). That is a
  second command, from a different subsystem, agreeing. When it does not —
  a gateway that has not bound yet, or a slower listener poll — the tree is
  still shown and the line says `no listening socket attributed to this
  pid` rather than hiding the disagreement.
- **The names shown are executable names**, `lab-logsearch` and so on, not
  the names the gateway's registry knows those upstreams by. If the two
  differ, the process table is the one being reported.
- **A jail whose processes cannot be seen shows nothing.** With
  `security.bsd.see_jail_proc=0` the host cannot enumerate a jail's
  processes even as root, and the section is empty rather than wrong.
- **No gateway is an empty section, not an error**, and it says which:
  "no gateway process is running" once `ps` has been read, versus "the
  process table has not been read yet" before it has.

Unlike the socket views, the process tree is a **point-in-time reading that
replaces the previous one**, not a rolling window, and the output says how
long ago it was taken. The window is right for sockets, which come and go
faster than they can be sampled. It would be wrong here: an upstream that
died two minutes ago must stop being listed as running immediately, not
fade out over five minutes. `ps` is polled every 8 socket samples (2s at
the default interval), because a spawned upstream lives as long as the
gateway does.

## pf-qualified exposure

jailmap used to print `PLAINTEXT ON ROUTABLE ADDRESS` for any listener
bound to a routable address, full stop. On a host running `pf` with a
default-deny inbound policy that produced this:

```
  host   udp4   *:123            ntpd     ntpd  PLAINTEXT ON ROUTABLE ADDRESS
  host   udp4   *:514 (syslog)   syslogd  root  PLAINTEXT ON ROUTABLE ADDRESS
```

Every word of which is true about the *bind* and misleading about the
*exposure*: the ruleset's first rule is `block drop in all` and neither
port is reachable from off the box. A tool that cries wolf gets skimmed,
and then it is not doing its job on the day the finding is real.

It now reads the firewall — `pfctl -s info` and `pfctl -s rules`, both
read-only — and prints the two facts separately:

```
  firewall: pf is active with a default-deny inbound policy (block drop in all) across 7 rules; a routable bind is not by itself reachable
  OWNER  PROTO  ADDRESS          PROCESS  USER  EXPOSURE
  host   tcp4   *:22 (ssh)       sshd     root  encrypted [pf default-denies inbound]
  host   udp4   *:123            ntpd     ntpd  plaintext bind [pf default-denies inbound]
  host   udp4   *:514 (syslog)   syslogd  root  plaintext bind [pf default-denies inbound]
```

The bind is still reported as plaintext, because it is. The shout is now
reserved for a plaintext bind with nothing known to be in front of it.

**It does not overclaim in the other direction either.** jailmap does not
analyse a pf ruleset. The only thing it looks for is an unqualified
`block ... in ... all` — pf is last-match-wins, so that rule is the
fallback for every inbound packet no later rule passes, and it is the
standard idiom for a default-deny policy. Decorations that do not change
what it does to unmatched traffic (`drop`, `return`, `log`, `quick`) are
accepted; an interface, a protocol or an address makes the rule conditional
and it is not counted. Everything else is `unknown`, out loud:

- **pf unreadable** (`pfctl` missing, `/dev/pf` absent, no permission) —
  `pf state could not be read`. Not assumed off, not assumed on. This is
  not filed as a degradation either: a jail host that does not run pf would
  otherwise carry a permanent `DEGRADED` line saying so.
- **pf enabled with an empty ruleset** — `unfiltered`. "pf is running" and
  "pf is protecting this port" are different claims, and the lab VM is
  exactly this case: pf enabled, zero rules, nothing filtered.
- **pf enabled with rules but no unqualified default-deny** — `unknown`,
  and it says jailmap does not evaluate them.
- **A listener inside a VNET jail** — `unknown`. A VNET jail has its own
  `pf` instance, which the host's `pfctl` does not report on, so the host
  ruleset does not govern what reaches a socket in there. Applying the
  host's verdict would be the same overclaim in the opposite direction.
  Host and classic-jail listeners *are* governed by the host ruleset — a
  classic jail's addresses are aliases on host interfaces — and are
  qualified.

## What it cannot see

Honest limits, not caveats:

- **UDP has no connections.** `sockstat -4c` lists connected sockets, and
  UDP does not have any in the sense that matters here. The OpenVPN tunnel
  never appears as an edge however busy it is, and neither does syslog
  traffic. UDP shows up in the listener view (`*:1194`, `*:514`) and nowhere
  else.
- **Sampling can still miss things.** The window makes a millisecond-long
  connection *likely* to be caught, not certain. A connection shorter than
  the interval that opens and closes between two samples leaves no trace.
  Lowering `-interval` narrows the gap; it never closes it. Absence of an
  edge is not evidence that it did not happen.
- **`??` process attribution.** sockstat reports `??` for every process
  column of a socket it cannot attribute — `TIME_WAIT` and other detached
  sockets, which is most of what a busy short-lived hop leaves behind.
  jailmap keeps the connection and leaves the process blank. It will fill
  the name in from a later sample of the *same* connection that did have
  one, and never from a neighbouring row.
- **Command names are truncated** to what sockstat prints (`mcp-gatewa`).
- **Direction is sometimes inferred.** The server end of a connection is
  identified by matching a known listener. When neither end matches — a
  connection to something that stopped listening, or a jail whose listeners
  have not been polled yet — the lower port is taken as the server and the
  row is marked `direction inferred`.
- **IPv4 only.** Every sockstat call passes `-4`.
- **An MCP upstream is inferred, not confirmed.** It is a direct child of a
  process whose executable is named `mcp-gateway`. jailmap does not know
  what the gateway *thinks* it is running, on purpose — see above.
- **Reachability is a qualifier, not an analysis.** `filtered` means pf
  default-denies inbound, nothing more specific. jailmap never claims a
  given port is or is not reachable; it says whether anything is known to
  stand in front of the bind.
- **No history.** The window is in memory and starts empty. Nothing is
  written to disk, which is also why there is nothing to rotate.
- **A saturated host degrades the sampler.** Under a synthetic load of a
  few hundred concurrent clients on a 4-CPU VM, `sockstat` itself took
  longer than `-cmd-timeout` to start; jailmap reported that in its
  `DEGRADED` section and kept sampling the jails that answered. Raise
  `-cmd-timeout` if you see it.

## Degradation

A stopped jail, a missing binary, a jail that cannot be inspected, a kernel
with no `vnet` parameter: each becomes one plain sentence in the `DEGRADED`
section (or the "Degraded" panel on the dashboard), while everything that
still answers keeps being collected. Warnings are deduplicated and age out
of the window on the same schedule as flows, so a jail that was mid-restart
during one sample stops being reported once it stops recurring.

## Tests

```sh
go test ./tools/jailmap/
```

The parsing and address-resolution logic is pure functions over sample
text, and every fixture in the tests is real output captured from the
jailmachine VM rather than invented. That is where the bugs are, so that is
where the tests are: `jls` with and without a `vnet` column, `sockstat`
rows including the `??` form, `ifconfig` with a loopback-clone interface
carrying a jail alias, the loopback-resolution rule above, exposure
classification, window ageing and pruning, the loopback-bind refusal, and
the read-only enforcement in the runner.

For the two newer parts: `ps` output including the `daemon(8)` decoy line
that a substring match gets wrong, `etime` in all three of its shapes, a
gateway with no children, a child in another jail, a cycle in the process
table, `pfctl -s info` in all three states (enabled, disabled, unreadable),
the default-deny rule in each of its decorated forms, the qualified rules
that must *not* be read as a default policy, the reachability matrix
including the VNET case, and that `pfctl -d` is still refused.

The `ps` fixture and `listenersGateway` were captured from the VM in the
same instant, so pid 63090 is the same process in both. That is what lets
`TestCollectOnceFindsTheSpawnedMCPUpstreams` check the name-based inference
against the socket table rather than against itself.
