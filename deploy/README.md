# Pointing the deploy scripts at a jail host

Every script in `deploy/` and `scripts/` runs on the Mac and does its real
work on a **FreeBSD jail host**. Which host, and how it is reached, is one
decision made in one place: `deploy/lib/remote.sh`.

| | |
|---|---|
| Helper | `deploy/lib/remote.sh`, sourced (not executed) by each script |
| API | `remote_sh <command...>`, `remote_cp <local>... <remote-path>`, `remote_target` |
| Selector | `JAILHOST_TRANSPORT` -- `jailmachine` (default) or `ssh` |
| Default | the local `jailmachine` VM, byte-for-byte what the scripts did before the helper existed |
| Shell | POSIX `sh`. No arrays, no `local`, no `[[`. The scripts are `sh` and so is this. |

```bash
./deploy/gateway-serve.sh          # unchanged: the local jailmachine VM

JAILHOST_TRANSPORT=ssh \
JAILHOST_HOST=jails.lab.internal \
  ./deploy/gateway-serve.sh        # a real box
```

## Why this exists

The lab is moving off a VM on someone's laptop onto dedicated hardware. Until
now every script reached the host by calling `jm ssh --`, the CLI of the
`jailmachine` tool that manages that one VM. `jm` knows about exactly one
machine on exactly one Mac. It is not a transport; it is a convenience for a
development VM, and seventeen files had it baked in.

The scripts also each carried their own copy of the same `scp -P 2222 ...
root@127.0.0.1:` line, with the jailmachine SSH key path spelled out. Six
copies of one incantation is six places to fix when the port changes.

Nothing about the jail host itself is Mac-specific -- it is a FreeBSD machine
running `bastille`. Only the way we talk to it was.

## The variables

Set these in the environment. There is no config file, deliberately: a deploy
that reads hidden state from disk is a deploy you cannot reproduce from a
shell history.

| Variable | Default | Meaning |
|---|---|---|
| `JAILHOST_TRANSPORT` | `jailmachine` | `jailmachine` or `ssh`. Anything else is a hard error. |
| `JAILHOST_HOST` | *(none)* | **ssh only, required.** Hostname or IP of the jail host. |
| `JAILHOST_USER` | `root` | ssh only. The scripts do host-level work (`bastille`, `sysrc`, `install` into a jail root), so this really does want to be root or something equivalent. |
| `JAILHOST_PORT` | `22` | ssh only. |
| `JAILHOST_KEY` | *(none)* | ssh only. Path to a private key. Left empty, `ssh` uses your agent and `~/.ssh/config` as normal. |
| `JAILHOST_SSH_OPTS` | *(empty)* | ssh only. Extra `-o` flags, **word-split on purpose** so you can pass several. |

And, for the `jailmachine` transport only, the three the scripts already had:

| Variable | Default | Meaning |
|---|---|---|
| `JM_STATE_ROOT` | `~/.jailmachine` | Where `jm` keeps machine state. |
| `JM_SSH_KEY` | `$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519` | The VM's key, used by `remote_cp`. |
| `JM_SSH_PORT` | `2222` | The port gvproxy publishes the VM on. |

Host-key checking differs between the two transports, and that is intentional.
The `jailmachine` transport keeps `StrictHostKeyChecking=no` and
`UserKnownHostsFile=/dev/null`, because the VM is regenerated freely on a port
on your own loopback and pinning its key would only mean deleting the pin
every `jm rm`. The `ssh` transport adds neither: a box on a real network gets
your normal `known_hosts` behaviour, and if you want to give that up you have
to say so:

```bash
JAILHOST_SSH_OPTS='-o StrictHostKeyChecking=accept-new'
```

## Worked example: a Proxmox FreeBSD guest

The guest is `10.20.0.31`, you have `~/.ssh/soc-lab` on it as root, and it is
already a working `bastille` host (`freebsd-jail.md` covers getting it there;
none of that is transport-specific).

```bash
cat >~/.soc-lab-env <<'EOF'
export JAILHOST_TRANSPORT=ssh
export JAILHOST_HOST=10.20.0.31
export JAILHOST_USER=root
export JAILHOST_PORT=22
export JAILHOST_KEY=$HOME/.ssh/soc-lab
EOF

. ~/.soc-lab-env

./deploy/soc-ca-bootstrap.sh       # the internal CA
./deploy/authelia-jail.sh          # the IdP jail
./deploy/authelia-verify.sh        # prove it
./deploy/gateway-vnet.sh           # gateway jail -> VNET
./deploy/gateway-serve.sh          # build, stage, provision
./deploy/gateway-serve-verify.sh   # the acceptance test
```

Unset the variables (or open a fresh shell) to go back to the local VM. There
is no "current target" stored anywhere.

## Quoting -- the part that bites

`remote_sh` adds **no quoting of its own**, and that is a deliberate,
load-bearing decision. `jm ssh -- a b c` and `ssh host a b c` both join their
arguments with a single space into one string and hand that string to a shell
on the far side. Measured against this lab's VM, both transports agree
exactly: on argument flattening, on remote `$` and glob expansion, on dropping
empty arguments, on stdin passthrough, and on exit-status propagation.

Because they agree, forwarding `"$@"` verbatim is what makes this refactor
safe -- no existing call site changed meaning. Had the helper "helpfully"
quoted arguments, every call site that relies on the remote shell parsing
`rm -rf $STAGE && mkdir -p $STAGE` would have broken.

The rule when you add a call site:

```sh
remote_sh mkdir -p "$STAGE"                       # fine: plain words
remote_sh bastille cmd "$JAIL" env "K=$V" /x.sh   # fine: still plain words
remote_sh "GW_JAIL=$J STAGE=$S sh $S/run.sh"      # fine, and preferred when
                                                  # you need shell syntax
remote_sh sh -c "cmd1; cmd2"                      # BROKEN, on both transports
```

That last one loses the quotes around the `-c` argument in the flattening, so
the remote runs `sh -c cmd1` and then `cmd2` as a separate command. If the
command needs shell syntax, write the whole thing as one pre-quoted argument
and you can see exactly what the remote shell will read.

`remote_cp` takes scp's shape: the last argument is the destination, and with
more than one source it must be a directory. No recursion -- nothing here
stages a directory.

## What does not port

Be clear-eyed about the limits. Three things are still jailmachine-only, and
one of them cannot be otherwise:

- **`deploy/openvpn-forward.sh`** drives gvproxy's HTTP API over a unix socket
  in the `jm` state root. gvproxy exists because the VM's network is a
  userspace gateway on this Mac; a jail host on a real network has no such
  thing and needs no such thing. The script now refuses to run with
  `JAILHOST_TRANSPORT=ssh` rather than failing obscurely. `openvpn-setup.sh`
  and `openvpn-teardown.sh` skip the forward step accordingly, and the
  generated `.ovpn` points at `JAILHOST_HOST:1194` instead of `127.0.0.1:1194`
  -- but **opening udp/1194 on the host's firewall is then your problem**,
  where gvproxy used to make it a non-question.
- **`remote_cp` on the jailmachine transport hardcodes `root@127.0.0.1`.**
  That is correct for gvproxy and wrong for anything else, which is why the
  ssh transport has its own branch rather than sharing the code.
- **Log lines and a couple of trailing hints still say "the VM"** or print a
  literal `jm ssh -- ...` suggestion. `remote_target` exists and is used where
  the message would otherwise be actively misleading, but the docs in
  `deploy/*.md` were written for the VM and have not been swept. Cosmetic, and
  known.

Two further honest limits:

- **`deploy/openvpn-teardown.sh` has a pre-existing bug**, flagged in place
  and deliberately *not* fixed here: its `REVERT_FORWARDING=1` path uses the
  broken `sh -c "..."` shape above, so it reverts the running sysctl but never
  deletes the line from `/etc/sysctl.conf`. It behaved this way before the
  transport work; changing it is a behaviour change and belongs in its own
  commit.
- **`scripts/deploy-to-jail.sh` fails with `Text file busy`** if the gateway
  service is running, because it `cp`s over the live binary. Also
  pre-existing, also identical on both transports. Use `deploy/gateway-serve.sh`
  for anything real -- that script stops the service first.

## What is proven

Not "it looks right". Both transports were run against the live jailmachine
VM, the `ssh` one pointed at that same VM over plain `ssh` on
`root@127.0.0.1:2222` so the two could be compared output-for-output:

- `deploy/gateway-serve-verify.sh` -- the fifteen-stage end-to-end acceptance
  test -- **ALL CHECKS PASSED** on the default transport before the refactor, on
  the default transport after it, and on the `ssh` transport. The three
  outputs differ only in timestamps and PIDs.
- `deploy/gateway-serve.sh` -- the twelve-file `remote_cp` and the full
  provision -- completed over plain `ssh`, and the deployment it produced then
  passed the acceptance test on the default transport.
- `deploy/gateway-vnet-verify.sh`, `deploy/soc-ca-bootstrap.sh` and
  `deploy/authelia-verify.sh` all pass on both transports.
- `sh -n` on every script; `shellcheck -s sh -x` clean apart from one
  pre-existing `SC2012` in `gateway-serve.sh`.

## What is assumed

- The jail host is FreeBSD with `bastille`, `pf`, `openssl`, `nginx` and the
  jails the scripts expect. Nothing here provisions a bare machine.
- `JAILHOST_USER` can do host-level root work without a password prompt.
  There is no `sudo` in any of these paths.
- The jail addressing (`10.17.89.0/24` classic, `10.17.90.0/24` VNET) is still
  hardcoded in `deploy/vm/*`. Moving to hardware that already uses those
  ranges is a separate job and this helper does not touch it.
