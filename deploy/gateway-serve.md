# The gateway actually runs

`mcp-gateway serve` is up in the `mcp-gateway-test` jail, behind the nginx
already in front of it, serving a real tool list to a real Authelia token
over TLS. Before this, the binary had never been started outside its test
suite.

Read `deploy/gateway-vnet.md` first (why the jail has a private loopback)
and `deploy/authelia-jail.md` (where the tokens come from). This document
assumes both.

| | |
|---|---|
| Jail | `mcp-gateway-test`, VNET, `10.17.90.10` |
| Front door | nginx, TLS on `10.17.90.10:443`, SAN `DNS:mcp.soc.internal, IP:10.17.90.10` |
| Gateway | `127.0.0.1:8080` inside that jail, loopback only |
| Service | `service mcp_gateway start`, runs as **`mcpgw`**, not root |
| IdP | Authelia at `https://id.soc.internal`, RS256, `aud: https://mcp.soc.internal/` |
| Upstreams | the four `lab/servers/*` mocks, cross-compiled `freebsd/arm64` |
| Vault | sops + age, `/usr/local/etc/mcp-gateway/secrets.json` |
| Trust anchor | one Ed25519 key in `signer.trusted_keys`, `require_signed = true` |

```bash
./deploy/gateway-serve.sh          # provision (idempotent)
./deploy/gateway-serve-verify.sh   # the acceptance test (idempotent, re-runnable)
```

| file | runs where |
|---|---|
| `deploy/gateway-serve.sh` | Mac -- cross-compiles, stages, drives provisioning |
| `deploy/gateway-serve-verify.sh` | Mac -- stages and drives the acceptance test |
| `deploy/vm/gateway-serve-provision.sh` | VM host |
| `deploy/vm/gateway-serve-verify.sh` | VM host |
| `deploy/vm/gateway-token.sh` | VM host -- one Authelia access token on stdout |
| `deploy/vm/gateway-upstreams.sh` | VM host, **sourced** -- the four upstreams, one definition |
| `deploy/gateway-jail/config.toml.template` | rendered into the jail as `config.toml` |
| `deploy/gateway-jail/mcp_gateway` | installed as `/usr/local/etc/rc.d/mcp_gateway` |
| `deploy/gateway-jail/nginx.conf` | installed as `/usr/local/etc/nginx/nginx.conf` |

## What is on disk in the jail

```
/usr/local/bin/mcp-gateway                       0755 root:wheel
/usr/local/libexec/mcp-gateway/lab-{casemgmt,logsearch,docsearch,threatintel}
/usr/local/etc/mcp-gateway/                      0750 root:mcpgw
  config.toml                                    0644 root:wheel
  secrets.json     sops+age encrypted            0640 root:mcpgw
  age.key          the age identity              0600 mcpgw:mcpgw
  signing.key      Ed25519, PKCS#8 PEM           0600 mcpgw:mcpgw
  signing.pub      the trusted_keys base64       0644 root:wheel
/var/db/mcp-gateway/mcp-gateway.db               0750 dir, mcpgw:mcpgw
/var/log/mcp-gateway/mcp-gateway.log             0750 dir, mcpgw:mcpgw
/var/run/mcp-gateway/{mcp_gateway.pid,mcp_gateway.child.pid}
```

The configuration directory is `root:mcpgw 0750`: the service can **read**
its config, its age identity and its signing key, and cannot rewrite any of
them. That split is deliberate -- the process holding every backend
credential should not also be able to edit the trust anchor it is checked
against.

Nothing in this list is in the repository, and nothing generated in the
jail is copied back to the Mac. `deploy/vm/gateway-serve-provision.sh`
generates every secret inside the jail with `openssl rand`, pipes the
plaintext straight into `sops` through `/dev/stdin` so it never lands on
disk in the clear, and prints key *names* only.

## Five things that had to be fixed before it would start

None of these are in Go code. All five were found by starting the service
for the first time, and every one of them is the kind of thing a hand-run
`mcp-gateway serve` would have hidden.

**1. `su: unknown login: mcpgw`.** The rc.d script declares
`mcp_gateway_user="mcpgw"`, and rc.subr honours `${name}_user` by wrapping
the whole command in `su(1)`. The account did not exist. It is created now,
with `/bin/sh` rather than `nologin` -- `su` execs the target account's
shell, so a nologin shell makes rc.subr's own start path fail.

**2. The pidfile could not be written, and then the service could not be
stopped.** `/var/run` is `root:wheel 0755`, so an unprivileged `daemon(8)`
cannot create `/var/run/mcp_gateway.pid` there. Worse, the original script
used `daemon -p` (the **child's** pid) together with `-r`: `service stop`
signalled the child, the supervisor restarted it, `service start` then said
`daemon: process already running`, and the only way out was killing the
supervisor by hand. The pidfile is now the **supervisor's** (`daemon -P`)
in a directory owned by `mcpgw`, with the child's pid still written
alongside for `ps`. SIGTERM to the supervisor is forwarded to the child, so
the gateway still gets the graceful shutdown it needs to reap its stdio
upstreams.

**3. `exec: "sops": executable file not found in $PATH`, once per second,
forever.** `service(8)` runs an rc.d script with
`PATH=/sbin:/bin:/usr/sbin:/usr/bin` and no `/usr/local/bin`. The gateway
shells out to the `sops` CLI (ADR-0005) and forwards only PATH to it. With
`daemon -r` this is a tight restart loop, which is exactly the failure mode
the rc.d script's own comment warns about. `mcp_gateway_env` now sets a
PATH that includes `/usr/local/bin`.

**4. `x509: certificate signed by unknown authority` against the IdP.**
The jail "trusts the SOC CA" at `/usr/local/etc/ssl/certs/soc-ca.crt`, and
`curl --cacert` against `https://id.soc.internal` returns 200 -- but Go's
`crypto/x509` never looks in that directory. On FreeBSD it reads
`/usr/local/etc/ssl/cert.pem`, `/etc/ssl/cert.pem`, and the directories
`/etc/ssl/certs` and `/usr/local/share/certs`. The fix is deliberately
**not** `certctl rehash`: `deploy/authelia-jail.md` is explicit that this
root has no name constraints and must never enter a system-wide trust
store. `mcp_gateway_env` sets `SSL_CERT_FILE`/`SSL_CERT_DIR` for this one
process, which is what that document asks for and is also the tighter
configuration -- the gateway dials exactly one TLS endpoint, so trusting
exactly one CA is correct rather than merely sufficient.

**5. `jexec: jail "mcp-gateway-test" not found`, from a jail that `jls`
lists.** `/usr/sbin/service` reads `$JAIL` out of its environment -- that
is where its own `-j` flag lands, and it is never unset -- and re-execs
itself as `jexec -l "$JAIL" service ...`. A deploy script that exported
`JAIL` and then ran `service` *inside* that jail made `service` look for a
nested jail of the same name. Only the `service` calls failed; every other
`jexec` in the same script worked, which made it look like an intermittent
jail bug. The scripts use `GW_JAIL`, which `service(8)` cannot see. This
one also silently ate an `nginx reload`, which is how it was finally
caught.

## The 403 that ADR-0011 guarantees -- a code defect, reported not patched

With `proxy_set_header Host $host` -- which is what
`deploy/gateway-jail/nginx.conf` said, and what every reverse-proxy example
says -- **every** request through nginx got:

```
HTTP/1.1 403 Forbidden
Forbidden: invalid Host header "mcp.soc.internal"
```

The MCP Go SDK (`v1.7.0`, `mcp/streamable.go`, `StreamableHTTPHandler.ServeHTTP`)
auto-enables DNS-rebinding protection whenever the server's **own listen
address** is loopback, and then requires the `Host` header to be a loopback
name too:

```go
if !h.opts.DisableLocalhostProtection && disablelocalhostprotection != "1" {
    if localAddr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && localAddr != nil {
        if util.IsLoopback(localAddr.String()) && !util.IsLoopback(req.Host) {
            http.Error(w, fmt.Sprintf("Forbidden: invalid Host header %q", req.Host), http.StatusForbidden)
```

ADR-0011 item 1 makes this gateway **refuse** any bind that is not
loopback, and item 2 puts a TLS-terminating reverse proxy in front of it.
So the SDK's precondition is not an edge case here -- it is the mandated
topology, permanently, for every request that arrives under the service's
real name.

`StreamableHTTPOptions` exposes `DisableLocalhostProtection` for exactly
this shape. `internal/gateway/httpapi` sets `Stateless` and `Logger` and
not that. **This is a code defect and it is reported, not patched** -- the
brief for this work forbids touching Go source, and a fix here is a
one-line change plus a test plus a sentence in ADR-0011 saying why the
control being disabled is safe (the jail's private loopback, proven by
measurement in `deploy/gateway-vnet.md`, is what actually provides the
property the SDK check is reaching for).

The deployment-side workaround is `proxy_set_header Host 127.0.0.1:8080`,
and it is honest rather than a dodge: nginx really is connecting to
`127.0.0.1:8080`. Nothing in the gateway reads `Host` for anything else --
its resource identifier and its RFC 9728 metadata come from the
configuration file, not the request -- and `X-Forwarded-Host` carries the
real name for logs.

## One vault, one namespace

The Credential Vault is a **flat map keyed by environment variable name**:
`internal/gateway/endpoint.go`'s `resolveEnv` calls
`vault.Resolve(ctx, name)` with the variable name from the registry entry
and nothing else. There is no per-upstream scoping.

Every one of the four lab mocks reads the same two variables --
`MOCK_SECRET` and `MOCK_EXPECT` (`lab/mockutil/credcheck.go`), not four
different names. Those two facts together mean **"one distinct credential
per backend" is not expressible for these four upstreams**: they share one
`MOCK_SECRET` value because they share one variable name.

What is deployed works around the shape rather than pretending it is not
there. `secrets.json` holds six entries:

  - `MOCK_SECRET` and `MOCK_EXPECT`, equal to each other, the pair the
    mocks compare;
  - `CASEMGMT_API_TOKEN`, `LOGSEARCH_API_TOKEN`, `DOCSEARCH_PASSWORD`,
    `THREATINTEL_VT_KEY` -- one distinct fake credential per backend, registered
    on that upstream only, named the way that backend's real counterpart
    would name it.

The mocks ignore the four per-backend values. They are there so the
per-upstream resolution path is genuinely exercised, and so the leak grep
has a value that can only have come from one backend.

**For the real fleet this is probably fine** -- `casemgmt`, `logsearch`,
`docsearch` and `threatintel` do not all read a variable called `MOCK_SECRET`.
It is worth writing down anyway, because the day two real backends both
want `API_TOKEN`, the registry will accept both, the gateway will start,
and one of them will silently be handed the other's credential. Nothing in
the system detects that. It is a naming collision with no error path.

## Tool names were verified, not guessed

Every name in the rendered `config.toml` was read out of
`lab/servers/*/main.go`. This matters more than it sounds: a role naming a
tool that does not exist grants nothing and **fails silently** -- the
analyst simply sees a shorter list. `docsearch` self-prefixes its own
tools, so `docsearch.docsearch_search` is correct and not a typo.

The verification below closes that hole from the other side: it asserts the
analyst sees exactly **6** tools and `dfirlead` exactly **8**, so a role
that silently granted nothing would fail the test rather than look tidy.

## The `*_credcheck` tools are approved by nobody, on purpose

The four `<name>_credcheck` tools are discovered and left **pending** in
Tool Quarantine, and no role grants them. They exist to let a caller ask a
backend to describe the credential it was handed; that is a test fixture,
not a capability an analyst should have. Both gates say no independently,
which is the point.

That is the steady state, and it is what the deployment is in right now.
It was suspended once, deliberately and reversibly, to close the one gap
this arrangement creates -- see the next section.

`procstat -e` on each of the four child processes shows the variable
*names* the vault resolved into them, shows that each child sees **only**
its own declared variables, and shows that the child environment is built
rather than inherited:

```
casemgmt       [26128]: HOME CASEMGMT_API_TOKEN MOCK_EXPECT MOCK_SECRET PATH
logsearch    [26127]: LOGSEARCH_API_TOKEN HOME MOCK_EXPECT MOCK_SECRET PATH
docsearch [26129]: HOME MOCK_EXPECT MOCK_SECRET DOCSEARCH_PASSWORD PATH
threatintel      [26130]: HOME MOCK_EXPECT MOCK_SECRET PATH THREATINTEL_VT_KEY
```

No backend holds another backend's credential: `CASEMGMT_API_TOKEN` appears in
`casemgmt` and nowhere else, and so on for all four. The only shared names are
`MOCK_SECRET`/`MOCK_EXPECT`, which are shared *by construction* -- see "One
vault, one namespace".

## Credential injection, proven by value -- 09 Sep 2026

Names arriving is not values arriving. This was closed by granting the four
fixture tools for one session and taking them away again.

**The grant.** A dedicated role in the jail's `config.toml`, granting the
four `*_credcheck` tools and *nothing else*, with the `dfir-leads` group
remapped to it for the duration:

```toml
[[role]]
name = "credcheck-fixture"
tools = [
  "casemgmt.casemgmt_credcheck", "logsearch.logsearch_credcheck",
  "docsearch.docsearch_credcheck", "threatintel.threatintel_credcheck",
]
```

A separate role rather than four lines bolted onto `dfir-lead`, for two
reasons. The privilege stays minimal -- being able to ask a backend to
describe its own credential carries no other capability with it -- and
reverting is deleting a block that announces itself rather than spotting
four lines inside a role that is supposed to have eight. `analyst` was left
mapped to `analyst` throughout, so it remained the live control. There is
no third Authelia group to map to, and that jail's configuration is not
this stream's to edit, so an existing group had to be borrowed.

Borrowing `dfir-leads` costs something and it is worth naming: for the
duration, `dfirlead` was *not* a dfir-lead. It saw the six tools it gets
from `soc-analysts` -- it is in both groups, and a caller's roles union --
plus the four fixtures, and lost `threatintel.enrich` and
`docsearch.docsearch_list_indices` until the revert. Its `tools/list`
held ten names, not twelve, and that is the union working, not a bug.

**Positive.** All four called through the real path -- `POST
https://mcp.soc.internal/` from the VM host, TLS verified against the SOC
CA, nginx, then the gateway -- with an Authelia RS256 token for `dfirlead`:

```
casemgmt.casemgmt_credcheck              HTTP 200  {"received_expected_secret":true,"fingerprint":"9ae421de"}
logsearch.logsearch_credcheck        HTTP 200  {"received_expected_secret":true,"fingerprint":"9ae421de"}
docsearch.docsearch_credcheck  HTTP 200  {"received_expected_secret":true,"fingerprint":"9ae421de"}
threatintel.threatintel_credcheck            HTTP 200  {"received_expected_secret":true,"fingerprint":"9ae421de"}
```

`9ae421de` was then computed independently from the vault --
`sops --decrypt | jq -j .MOCK_SECRET | openssl dgst -sha256`, first eight
hex characters -- and matches. So the claim is not merely "the backend
received something that equalled what it was told to expect", it is "the
backend received **the value stored in the vault under that name**". The
same computation over the other four keys gives `364a3616`, `7c37447c`,
`f814cc2c`, `0c0db8d8`: different fingerprints, so `9ae421de` identifies
`MOCK_SECRET` specifically and not some other entry.

All four report the same fingerprint because all four *share* that
credential, for the reason "One vault, one namespace" gives. That is the
existing caveat showing up as a measurement rather than as prose.

**Negative controls.** A positive with no negative proves the tool can say
`true`, not that it can say `false`. Two were run, both restored:

  1. *Per-backend.* `threatintel` was deregistered and re-registered without
     `-env MOCK_SECRET` (and re-signed -- the signature covers the env
     name list, so it had to be). `threatintel` then reported
     `{"received_expected_secret":false,"fingerprint":"e3b0c442"}` -- the
     fingerprint of the empty string -- while `casemgmt`, `logsearch` and
     `docsearch` still reported `true`/`9ae421de` **in the same run**.
     The four results are independent, not one constant echoed four times.
  2. *By value.* `MOCK_EXPECT` in the vault was re-encrypted to a fresh
     random value, `MOCK_SECRET` untouched. All four then reported
     `false` -- with `fingerprint` still `9ae421de`. The boolean is a real
     comparison; the fingerprint tracks what was delivered and is not
     derived from the boolean.

Both were restored (registry re-registered and re-signed; `secrets.json`
restored from a pre-change copy) and all four returned to
`true`/`9ae421de`.

**The gates were still gates.** During the window, `analyst` -- unchanged,
mapped only to `analyst` -- saw six tools with no `*_credcheck` among them,
and calling `casemgmt.casemgmt_credcheck` by name got
`{"code":-32602,"message":"unknown tool \"casemgmt.casemgmt_credcheck\""}`. The
Audit Trail recorded every one of those calls: `allowed` for `dfirlead`,
`denied` with reason `not visible to caller` for `analyst`.

**Reverted.** `config.toml` was restored from the pre-change copy and
`diff` against it is empty; after a restart `dfirlead` sees its usual eight
tools and all four `*_credcheck` calls return `unknown tool`. The full
acceptance test was then re-run green, which also rebuilt the database and
put the four fixtures back to `pending`.

Two things the revert surfaced, neither patched:

  - **`mcp-gateway tool` has no `revoke`.** Approval is one-way from the
    CLI; the only route from `approved` back to `pending` is deleting the
    database. Here that was free, because the acceptance test deletes it
    every run anyway -- on anything real it means an operator who approves
    a tool by mistake has no supported way to un-approve it.
  - **`upstream deregister` does not clear that upstream's tool
    approvals.** Deregistering `threatintel` and re-registering it -- a new
    registry entry, a different `-env` list, a fresh signature -- left all
    three `threatintel` tools `approved` and immediately servable. Approvals are
    keyed by upstream *name* and tool definition, not by the registry
    entry that was reviewed. The definition fingerprint still catches a
    tool whose name, description or schema changed, so this is not an open
    door; what it means is that a replacement advertising *identical*
    definitions inherits the approvals of the thing it replaced, and the
    quarantine never sees a new upstream. Measured for a re-registration
    of the same binary; the same-binary case is the one that was run, and
    a different-binary case is inference from the same mechanism.

To prove the same property without any of this, run `lab/probe` against a
mock directly -- that is what it is for, and it does not need the gateway.

## The acceptance test rebuilds the database every run

`deploy/gateway-serve-verify.sh` deletes `/var/db/mcp-gateway/mcp-gateway.db`
and re-registers and re-signs the four upstreams before it starts the
service. Without that, the second run would find every tool already
approved and the "tools begin quarantined" assertion would pass by
accident.

This destroys the tool approvals **and the audit trail**. That is
defensible on a lab jail whose registry is rebuilt deterministically two
lines later, and it would be indefensible on anything real. Do not copy the
pattern into a production runbook.

## Verified, by that script, on 09 Sep 2026

Every item below is real output from `./deploy/gateway-serve-verify.sh`,
run three times in a row, green each time.

1. **It starts through rc.d.**

   ```
   time=... msg="mcp-gateway: starting" version=7a9c855 listen=127.0.0.1:8080 require_signed=true
   time=... msg="mcp-gateway: serving" listen=127.0.0.1:8080 upstreams_registered=4
       upstreams_connected=4 upstreams_failed=0 tools_discovered=12 tools_servable=0
       require_signed=true trusted_keys=1
   ```

   and `sockstat -4 -l` inside the jail shows `mcpgw mcp-gatewa ... tcp4
   127.0.0.1:8080`, on the jail's own loopback -- checked as well as logged,
   because in the classic jail this jail used to be, that log line was a lie.

2. **All four upstreams connect, 12 tools discovered**, all four registry
   entries `SIGNED yes`, each with its own env var names and no values.

3. **Tools begin quarantined.** Before: 12 `pending`, 0 usable, and a live
   `tools/list` with a valid analyst token returns HTTP 200 with an **empty
   tool list** -- the quarantine gate observed through the front door, not
   in a table. After approving the eight domain tools: 8 `approved`/usable,
   4 `pending` (the credcheck fixtures).

4. **The headline.** `POST https://mcp.soc.internal/` from the VM host,
   TLS verified against the SOC CA, through nginx, with an Authelia
   RS256 token for `analyst`:

   ```
   analyst sees:
     logsearch.search_keyword
     logsearch.search_relative
     casemgmt.get_case
     casemgmt.list_cases
     docsearch.docsearch_search
     threatintel.lookup_ip
   ```

   and `tools/call casemgmt.list_cases` returns real data from the mock
   process:

   ```json
   {"cases":[{"case_id":"57769","title":"IDS Enumeration Attack","status":"open","severity":"high"},
             {"case_id":"59456","title":"Suspicious Login From New Device","status":"closed","severity":"low"}]}
   ```

5. **Negatives.**

   - no token -> `401`, with
     `WWW-Authenticate: Bearer resource_metadata="https://mcp.soc.internal/.well-known/oauth-protected-resource"`;
   - garbage token -> `401`, body `authentication required`;
   - a **well-formed** JWT claiming `groups: ["dfir-leads"]` with a bogus
     signature -> `401`. This one is not decoration: without it, "garbage
     is rejected" could mean "the parser choked" rather than "the signature
     is checked";
   - `analyst` sees neither `threatintel.enrich` nor
     `docsearch.docsearch_list_indices`, while `dfirlead` sees both (the
     control -- otherwise the assertion would pass on a gateway where those
     tools do not exist at all);
   - `analyst` calling `threatintel.enrich` **by name** gets
     `{"code":-32602,"message":"unknown tool \"threatintel.enrich\""}`. Not
     "forbidden": the caller is not told the tool exists.

6. **The audit trail recorded it.**

   ```
   TIME                  ANALYST                               TOOL             UPSTREAM  OUTCOME  REASON
   2026-09-09 20:44:02Z  bb7502ab-cad7-45d0-8f0c-d8a5becfe4a4  threatintel.enrich     threatintel     denied   not visible to caller
   2026-09-09 20:44:02Z  bb7502ab-cad7-45d0-8f0c-d8a5becfe4a4  casemgmt.list_cases  casemgmt      allowed  -
   ```

7. **No credential leaked.** Every value in the decrypted vault, searched
   for as a fixed string (`grep -F`) in three files inside the jail:
   `/var/log/mcp-gateway/mcp-gateway.log`, `/var/log/nginx/mcp-access.log`,
   `/var/log/nginx/mcp-error.log`. Keys searched:
   `MOCK_SECRET`, `MOCK_EXPECT`, `CASEMGMT_API_TOKEN`, `LOGSEARCH_API_TOKEN`,
   `DOCSEARCH_PASSWORD`, `THREATINTEL_VT_KEY` -- all clean. The first 40
   characters of the analyst's bearer token were searched for too, in the
   gateway log and the nginx access log: clean. Only key *names* are ever
   printed; a leak check that echoes what it is hunting for has created the
   leak it was testing for.

   Re-run after the credcheck session above, with real secret values now
   having flowed through tool *results* rather than only into child
   environments: still clean, all six keys, all three files (87 request
   lines in the nginx access log by then, so the grep was not clean for
   want of anything to find). That re-run added the control the original
   lacked -- every vault value planted in a scratch file inside the jail
   and searched for with the **same** grep invocation, which found all six.
   A clean grep with a broken method is worthless; this one is now known to
   work. Same treatment for the bearer token. The re-run also passes each
   value to `grep -F -f` through a `0600` pattern file rather than on the
   command line, which is a small improvement on step 14 of
   `deploy/vm/gateway-serve-verify.sh` -- that one still puts the value in
   an argv that is visible in `ps(1)` for an instant, as its own comment
   admits.

## What this does NOT prove

  - ~~**That credential injection delivers the right value.**~~ Closed on
    09 Sep 2026 -- see "Credential injection, proven by value". All four
    backends reported `received_expected_secret: true` through TLS ->
    nginx -> gateway, with a fingerprint matching the vault's own value,
    and two negative controls showed the check can report `false`. What is
    still **not** proven by it: that a backend can be given a credential
    *no other backend has*. The four mocks all read `MOCK_SECRET`, the
    vault is keyed by variable name, so they necessarily share one value
    (see "One vault, one namespace"). The per-backend keys
    (`CASEMGMT_API_TOKEN` and friends) are correctly isolated -- `procstat -e`
    shows each in exactly one child -- but the mocks do not read them, so
    no credcheck confirms their *values*.
  - **That the acceptance test covers any of this.**
    `deploy/vm/gateway-serve-verify.sh` was **not** changed: it still
    leaves the four fixtures pending and granted to nobody, which is the
    correct steady state. The credential-injection proof above was a
    one-off session, reverted, and re-running the acceptance test will not
    reproduce it.
  - **Anything from a VPN client.** The client in every test is the VM
    host, which reaches `10.17.90.10` across `socbr0`. That is external to
    the jail, which is the property that mattered, but no Mac was connected
    over OpenVPN during this work. `deploy/gateway-vnet.md` already carries
    the same caveat.
  - **That the audit trail records `tools/list`.** It does not, and the
    trail after a full run holds exactly two records -- the `tools/call`
    that was allowed and the one that was denied. Whether listing should be
    audited is a design question, not a bug found here.
  - **That the recorded analyst identity is legible.** The trail stores the
    token's `sub` (`bb7502ab-...`), not `analyst`. Correlating a record to
    a human needs the IdP. Related to GAB-24 (no source address in the
    trail either), which is why `nginx.conf` logs `$remote_addr`.
  - **Restart survival across a VM reboot.** `mcp_gateway_enable=YES` is
    set and the service starts cleanly from `service`, but the VM was not
    rebooted during this work. Note that `daemon -r` plus a fail-closed
    startup means the gateway will spin at one restart per second until
    Authelia is up, rather than giving up -- intended, and loud in the log.
  - **Anything about load, concurrency, or a second analyst at the same
    time.** One client, one request at a time.

## Troubleshooting

```bash
jm ssh -- jexec mcp-gateway-test service mcp_gateway status
jm ssh -- jexec mcp-gateway-test tail -40 /var/log/mcp-gateway/mcp-gateway.log
jm ssh -- jexec mcp-gateway-test tail -20 /var/log/nginx/mcp-error.log
jm ssh -- jexec -U mcpgw mcp-gateway-test \
    mcp-gateway upstream list -config /usr/local/etc/mcp-gateway/config.toml
```

A gateway that never comes up means **reading the log**, not assuming it is
slow: `daemon -r` retries a genuine misconfiguration forever, and the log
will be the same three lines repeating once a second.

Do not run the Operator Console as root against this deployment. The
database is owned by `mcpgw` and SQLite in WAL mode creates `-wal`/`-shm`
siblings owned by whoever wrote first; a root-owned `-wal` leaves the
service unable to write its own database. Use `jexec -U mcpgw`.

## Rotation

Nothing here rotates automatically, and the provisioning script will never
overwrite a key that exists -- re-rolling the age identity makes
`secrets.json` undecryptable and re-rolling the signing key invalidates
every stored signature. To rotate deliberately:

  - **age identity**: delete `age.key` *and* `secrets.json`, re-run
    `./deploy/gateway-serve.sh`. New fake credentials are generated; the
    upstreams pick them up at the next start.
  - **signing key**: generate the new key at a *different* path, add its
    public half to `trusted_keys` **alongside** the old one, re-sign every
    entry, then remove the old key and its line. The list is a list for
    exactly this reason. `signing.pub` must be updated to match, or the
    next provisioning run will render a config with the old anchor.
  - **the TLS certificate**: `jm ssh -- /usr/local/etc/soc-ca/issue.sh
    mcp.soc.internal 10.17.90.10`, then reload nginx. Re-issuing generates
    a fresh key, so nginx must actually be reloaded.
