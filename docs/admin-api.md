# Writing a Gatte front

Gatte's operator console is a backend with a contract, `mcp-gateway admin`,
and any number of optional fronts that call it. This page is for someone
writing a new front: a web console with another look, a TUI, a chat bot on
the gateway host. The decision record is `design/adr/0040`; the contract is
`api/admin.openapi.yaml`.

## What you connect to

The backend speaks HTTP/1.1 and JSON over **UNIX sockets only**. It has no
TCP listener, so a front runs on the gateway host (or reaches it through
`ssh`, as the Gatte web front does).

| Socket | Default path | Who can connect | Serves |
|---|---|---|---|
| operator | `/run/mcp-gateway-admin/operator/operator.sock` | members of `gatte-operators` (file `0660`) | overview, tools, access, audit, backends, maintenance, reload and redial, quota, people, connect |
| accounts | `/run/mcp-gateway-admin/accounts/accounts.sock` | root (file `root:root 0600`), or the delegated group (below) | identity provider accounts |

Each socket has a directory of its own under a `root:root 0755`
`/run/mcp-gateway-admin`: whoever can create a file in a directory can
also replace its neighbour. The directory decides who can replace a
socket; the socket file's group and mode decide who can connect. A route of the other socket answers 404
`wrong_socket` (with `details.socket`); a route the backend does not have
answers 404 `unknown_route`.

On a systemd host both are socket-activated: the backend starts on the
first connection and exits five minutes after its last request, so nothing
runs while nobody operates. An idle open connection does not keep it up.
Elsewhere, run it in the foreground:

```sh
# once, as root
install -d -o root -g root -m 0755 /run/mcp-gateway-admin
install -d -o mcpgw -g mcpgw -m 0755 /run/mcp-gateway-admin/operator
install -d -o root -g root -m 0755 /run/mcp-gateway-admin/accounts

sudo -u mcpgw mcp-gateway admin -config /etc/mcp-gateway/config.toml \
    -socket /run/mcp-gateway-admin/operator/operator.sock \
    -socket-group gatte-operators -idle 0
sudo mcp-gateway admin -accounts -config /etc/mcp-gateway/config.toml \
    -socket /run/mcp-gateway-admin/accounts/accounts.sock -idle 0
```

The operator backend refuses to run as root, and the accounts backend
refuses to run as anything else.

The backend refuses a socket directory, or any directory above it, that is
a symbolic link, is writable by group or others, or is owned by someone
other than root (the operator socket's own directory may belong to the
service account).

The accounts backend runs as root and so trusts nothing the service
account can write. Before every request it checks that `config.toml`,
`[idp] users_file` and every directory above them are owned by root, are
not symbolic links and are not writable by group or others; otherwise it
answers `config_unavailable` with `details.path`. It never opens the
gateway database itself: the audit row of an account action is written by
a child process that runs as the database's owner.

### Delegating accounts without sudo

Set both, or the backend refuses to start:

```toml
[admin]
account_group = "gatte-accounts"
```

```ini
# /etc/systemd/system/mcp-gateway-admin-accounts.socket.d/group.conf
[Socket]
SocketGroup=gatte-accounts
SocketMode=0660
```

In the foreground, the same is `-socket-group gatte-accounts -socket-mode
0660`. A member
of that group then runs `mcp-gateway ui -manage-users` as themselves,
without root. Unit files to copy are in `examples/systemd/`.

What the group gets is the accounts Gatte manages: an account with at
least one group, every one of them in `[group_to_role]`. Changing groups,
disabling, enabling or resetting the password of any other account of the
IdP (an administrator of other applications, a person with no Gatte group)
is refused with `account_not_managed`; only a root peer reaches those.

## What you import

Two public packages:

- `github.com/bunnyiesart/Gatte/pkg/adminapi`: the request and response
  types, the error codes, and `Client`. It uses the standard library and
  `golang.org/x/sys/unix` (for the server's credentials).
- `github.com/bunnyiesart/Gatte/pkg/frontkit`: the browser protections a
  web front needs (below) and the helpers that draw review segments and
  escape text. A front that is not a web page needs only the helpers.

Import nothing else from Gatte. `internal/...` is not reachable from another
module, and the Gatte web front itself (`internal/front/gatteweb`) is held
by a fitness test to these two packages.

```go
c := adminapi.New(adminapi.DefaultOperatorSocket, adminapi.WithFront("myfront"))

me, err := c.WhoAmI(ctx)                  // who the backend says you are
rv, err := c.ReviewTool(ctx, "casemgmt", "list_cases")
res, err := c.ApproveTool(ctx, adminapi.ApproveRequest{
	Server: "casemgmt", Tool: "list_cases",
	Fingerprint: rv.Observed.Fingerprint,    // what you SHOWED, never re-read
})
var ae *adminapi.Error
if errors.As(err, &ae) && ae.Code == adminapi.CodeFingerprintMismatch {
	// the tool advertises something else now: show the review again
}
if err == nil && res.Changed && !res.Recorded {
	// approved, but the trail has no row for it: say both on screen
}
```

`Client` checks who serves the socket it connected to: on the accounts
socket it refuses a server that is not uid 0 (`adminapi.ErrImpostor`), so a
fake socket put in place by another account cannot collect account
creations. `WithServerUID` pins the operator socket's server too. It
cannot be given request headers, so it has no way to forward a browser's.

## What the backend guarantees

Every rule lives in the backend, so a front cannot forget one:

- **The operator is who the kernel says.** Identity comes from the
  socket's peer credentials, never from a request field. Every state change
  writes an operator row, `(operator:NAME)`, to the audit trail:
  `(tool approve)`, `(tool approve set)`, `(tool revoke)`, `(access block)`,
  `(access unblock)`, `(maintenance on)`, `(maintenance off)`, `(config
  reload)` and `(upstream redial)` (written by `serve`),
  `(account add|groups|disable|enable|reset password)`.
- **An approval is of the fingerprint you were shown.** Approve refuses
  without one, refuses another, and refuses if the definition moved while
  approving. A backend's whole review set is approved by its manifest,
  never "everything pending" (below).
- **Access is only through `[group_to_role]`.** Accounts get only groups
  that map to a role, and a peer that is not root changes only accounts
  whose groups all map to one (`account_not_managed` otherwise).
- **Passwords are generated, returned once and stored hashed.** No endpoint
  accepts a password. It appears in exactly one field,
  `one_time_password`, and never in `messages`, `warnings`, an error, the
  trail or the backend's log. The response's `Cache-Control: no-store` is
  advisory on a socket; `frontkit` sends `no-store` on every page.
- **A change that happened is never hidden, and neither is its result.**
  If the trail cannot record a change that was made, the answer is still
  the normal 2xx body (the password included), with `recorded: false` and
  the warning `audit_write_failed`. Say on screen that the change is in
  force and unrecorded.
- **Review text arrives in segments.** A tool's name, description,
  definition lines and diff come as `segments` the backend computed from
  the raw bytes: `text`, `hidden` (a code point such as `U+202E`) or
  `invalid_byte`. `raw` is there too, unescaped. `review_text` is already
  escaped and is only for a plain details box.
- The configuration is re-read on every request; a file that does not load
  refuses the request.

Errors are `{"error": {"code", "message", "details"}}`. Branch on `code`,
which is stable; show `message`, which is for people. Codes are an open
set: handle one you do not know by its HTTP status.

### Retrying

Approve, revoke, block, unblock, maintenance on and off, set groups, disable
and enable are safe to repeat after `internal` or a dropped connection: a repeat answers
`changed: false`. Unblock records before it lifts (`design/adr/0031`), so an
unblock the trail cannot record is not performed and answers an error:
the subject stays blocked. Creating an account is not: read the account first, and
if it exists, its password was lost with the answer, so call
`reset-password`. `reset-password` is safe to repeat, and each call
invalidates the previous password. The contract marks each operation with
`x-gatte-idempotent`.

## What a front must still do

The backend does not know what you render or who is at your screen.

1. **Name yourself** with `WithFront("name")` (`Gatte-Front` header). It
   becomes the `[name]` tag in the operator row, so the trail can tell your
   front from the CLI (`[cli]`). It decides nothing.
2. **Treat every string in every response as untrusted.** Tool names and
   definitions, backend names, command lines and URLs, IdP groups and
   display names, role names, reasons, messages: any of them may carry
   markup, terminal escapes or bidi overrides. Escape every string for
   your medium and make hidden code points visible
   (`frontkit.VisibleText`; a U+202E must show as `\u{202E}`, not reorder
   the line). For review text, draw the backend's segments
   (`frontkit.DrawSegments`) instead of re-parsing text.
3. **Never pass a browser through.** The backend refuses any request that
   carries `Origin` or `Cookie`, but a proxy that strips them would still
   get an operator's power with no CSRF or `Host` check. A web front
   terminates the browser itself and calls the API as its own process.
4. **A web front serves through `frontkit`, and only through it**, for what
   `design/adr/0036` requires of a page on loopback:

   ```go
   kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:8091"})
   // refuses a non-loopback bind; makes the one-time login token and the CSRF token
   fmt.Println(kit.LoginURL())             // print it to the terminal only
   err = kit.Serve(myMux)
   // loopback Host check, /login?token= once -> /s/ID/ + HttpOnly SameSite=Strict
   // cookie, CSRF token + same Origin on every POST, CSP default-src 'none',
   // X-Frame-Options DENY, nosniff, no-referrer, no-store, body limit
   ```

   `kit.Serve` is the only way `frontkit` serves; there is no handler to
   mount elsewhere. A deployment repository with its own web front should
   hold it to that with a fitness test, as Gatte does for its own. Put
   `kit.CSRFToken()` in every form, build links under `kit.Base()`, change
   state only on POST, and ship no script unless you widen the CSP
   knowingly: every page of the operator console has the operator's
   powers.
5. **Show a one-time password once and keep no copy**: not in a log, a
   cache, a template variable that outlives the response, or a URL.
6. **Localise on keys, not prose.** `Attention.kind`, warning and error
   codes, `Overview.problems[].code` and `Connect.missing` (the missing
   `[connect]` keys), `BackendHealth.state` and `cause`, and
   `ServeStatus.state` are for your texts; `detail`, `message` and
   `messages` are English fallbacks. A maintenance `message` is the
   operator's own text and is shown as it is (escaped).

## Review sets

With the feature `tool_review_set` (contract 1.2.0, `design/adr/0043`):
`GET /v1/tools/review-set?server=NAME` answers every pending and changed
tool of one backend, each as `reviewTool` answers it (definitions, diff,
`callable_by`), from one read, and a `manifest`: the SHA-256 over the
backend, the number of tools and each tool's name, status, observed
fingerprint and approved baseline. `POST /v1/tools/approve-set` with
`{"server": NAME, "manifest": M}` approves all of them in one transaction,
and only while the set still hashes to `M`; a tool joining, leaving or
moving refuses the whole set (`manifest_mismatch`) and approves nothing.
Draw every entry of the set before offering its button, as you would for
one tool. The answer carries one `(tool approve)` row per tool in `rows`
and the `(tool approve set)` summary row in `audit`.

## Reload and redial

With the feature `serve_control` (contract 1.3.0, design/adr/0044):

- `POST /v1/reload` (body `{}`) asks the running gateway to re-read its
  configuration file and apply `[[role]]`, `[group_to_role]` and
  `[quota]`. `POST /v1/upstreams/redial` with `{"upstream": NAME}` asks it
  to drop one backend and dial it again with the vault as it is now.
- Both answer a `ServeRequest`. The backend files the request in the
  database, rings `serve` with SIGHUP and waits up to 20 s: `state` is
  `done` with `outcome` `applied` or `refused` (and a `refusal` code), or
  `pending`, which a front reads again with `GET /v1/serve-requests/{id}`.
  `serve_not_running` (503) means nothing was filed.
- A reload's `reload` field is the diff to show: per role, the tools
  `gained` and `lost` over what is routed now, and `grants_added` /
  `grants_removed`, what its grant in the file says differently (a grant
  over a backend that is down or not yet listed moves nothing in `gained`,
  so draw both); `groups` that moved; `quota` accounts changed; and
  `not_reloaded`, the keys that differ from the file `serve` started with
  and need a restart. Show `not_reloaded` next to the success, not after
  it. A redial's `redial` says whether the backend was connected and
  whether it is live after the round.
- `serve` writes the operator rows, `(config reload)` and `(upstream
  redial)`; `recorded` and `audit` are its.

## Backend health and maintenance

With the features `backend_health` and `maintenance` (contract 1.1.0,
`design/adr/0041`):

- `GET /v1/overview` carries `health`: `serve` (is the gateway process
  running? `running`, `not_reporting`, `never_reported`), the gateway's
  maintenance if any, and every backend with its `state` (`up`,
  `reconnecting`, `down`, `maintenance`, `unknown`), `since`,
  `last_attempt`, `next_attempt` and, when it is not live, `cause`.
  `GET /v1/upstreams` carries the same `health` on each entry. The
  management backend is not the gateway process: these are what `serve`
  last wrote to the database, which is why a stopped `serve` shows as
  `not_reporting` instead of as a healthy fleet. Show it first.
- `POST /v1/maintenance/on` with `{"scope": "upstream", "upstream":
  "casemgmt", "message": "...", "until": "..."}` puts one backend in
  maintenance: from the gateway's next call, analysts' calls to it are
  answered with the maintenance text and not dialed. `{"scope": "gateway",
  ...}` adds a notice to call results instead (text-only and unavailable
  results; a client that reads only `structuredContent`, as Claude Code
  does, gets it through `gatte.status`); calls are still served.
  `POST /v1/maintenance/off` with `{"scope": ..., "upstream": ...}` ends it.
  `GET /v1/maintenance` lists what is in force.
- Exactly `message`, `until`, `until_passed` and `started_at` (shown as
  the maintenance's `since`) reach analysts and their models; `set_by` and
  `set_at` (who changed it last, and when) never do. A repeated `on` with
  another message or `until` keeps `started_at`. The backend refuses a
  message with a control character, a hidden code point or a line break
  rather than escaping it, and counts the 200 limit in Unicode code points;
  `"` and `\` are allowed, and the gateway quotes the message where it
  puts it inside its own text. `until` is a forecast: nothing ends by itself, so a
  front should show `until_passed` loudly.
- `cause` (`process_gone`, `not_brought_up`, `held_back`, `not_listed`)
  is for the operator only; analysts are told the state, never why.
  `held_back` means the gateway is not dialing anything new (the quota
  policy and the registry disagree): `down` stays `down` until an operator
  fixes that. It is also the cause of a backend found dead while dials are
  held back, so `state` is derived from `cause` alone. `not_listed` is a
  re-dialled process whose tool list has not been read yet: it takes no
  call, so it is `reconnecting`, not `up`. The set is open.
- Localise on `Attention.kind` (`backend_unavailable`,
  `backend_maintenance`, `gateway_maintenance`, `serve_not_reporting`) and
  on `state`, like every other key.

## Reading the trail

`GET /v1/audit` returns the newest `limit` matching records (at most 5000),
oldest first, each with its chain `position`. When `more` is true, pass
`next_before` as `before` to get the next older page.

With the feature `audit_filters` (contract 1.4.0, design/adr/0046) it also
takes `tool`, `server` (the record's `target_upstream`) and `until`. All
filters match exactly and combine; `since` is inclusive and `until`
exclusive. An older backend ignores parameters it does not know and would
answer the unfiltered trail, so do not send these three without the
feature. A download is the same query walked back with `before`; the Gatte
front writes CSV through `frontkit.CSVCell` (hidden code points written
visibly, a cell starting with `=`, `+`, `-`, `@`, tab or CR prefixed with
an apostrophe), and a front that offers CSV should do the same.

## Blocks that end, deleting and offboarding

With the feature `block_until` (1.4.0), `POST /v1/access/block` takes
`until`, a future instant. The gateway enforces the end at admission, to
the instant; `GET /v1/access/blocks` then marks the block `expired`, and
the gateway's next round writes `(access block expired)`, attributed to
`(gateway)`, and removes it. Show `expired` blocks as not in force.

On the accounts socket, `account_delete` adds `DELETE
/v1/accounts/{username}` (`(account delete)`), and `offboard` adds `POST
/v1/accounts/{username}/offboard` with `{"subject": ..., "reason": ...}`:
the subject is blocked in the gateway, then the account is disabled, each
with its own row plus a summary `(account offboard)`. Both keep the reach
of the other account actions (`account_not_managed`). With a subject, a
peer that is not root must also be in `[admin] operator_group`
(`forbidden_peer`): blocking is an operator's action, and the accounts
socket's delegation does not include it. Let the operator pick the
subject from `GET /v1/people`; the names there are display only. Show
`remaining` as the steps left to do by hand: revoking the sessions at the
identity provider is always one of them, because Gatte cannot. A warning
`offboard_incomplete` means the block is in force and the account was not
disabled.

## Versioning

Everything is under `/v1`. `GET /v1/whoami` returns `contract_version` (the
contract's `info.version`) and `features`, the capabilities added after
1.0. Within `/v1`, changes are additive only: new endpoints, new response
fields, new values in response enums and error codes, new optional request
fields. Ignore fields you do not know, and give every enum and code a
default branch. The backend refuses unknown request fields, so send a newer
optional field only when its feature is listed; `Client` omits optional
fields left at their zero value. A breaking change becomes `/v2`, served
beside `/v1` for at least one release.

## The Gatte web front, as an example

`mcp-gateway ui` is a front like any other: `internal/front/gatteweb` builds
its pages from `pkg/adminapi` calls and serves them through `pkg/frontkit`,
and a fitness test (`internal/fitness/front_test.go`) holds it to importing
nothing else of Gatte and to serving through `kit.Serve` only. The operator
runs it as themselves:

```sh
mcp-gateway ui [-socket PATH] [-listen 127.0.0.1:8090]
sudo mcp-gateway ui -manage-users [-accounts-socket PATH]   # also the accounts socket
```

It reads no `config.toml` and opens no database. It checks the operator
socket with `whoami` before printing its login link, and with
`-manage-users` it opens the accounts socket with `NewAccounts`, so a
socket not served by root is refused before any page exists.

## Building without a front

`go build -tags nofront ./cmd/mcp-gateway` produces the gateway, the
backend and the CLI without the Gatte web front. The `ui` subcommand then
says so and exits.
