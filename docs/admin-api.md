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
| operator | `/run/mcp-gateway-admin/operator/operator.sock` | members of `gatte-operators` (file `0660`) | overview, tools, access, audit, backends, quota, people, connect |
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
  `(tool approve)`, `(tool revoke)`, `(access block)`, `(access unblock)`,
  `(account add|groups|disable|enable|reset password)`.
- **An approval is of the fingerprint you were shown.** Approve refuses
  without one, refuses another, and refuses if the definition moved while
  approving.
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

Approve, revoke, block, unblock, set groups, disable and enable are safe to
repeat after `internal` or a dropped connection: a repeat answers
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
   `[connect]` keys) are for your texts; `detail`, `message` and
   `messages` are English fallbacks.

## Reading the trail

`GET /v1/audit` returns the newest `limit` matching records (at most 5000),
oldest first, each with its chain `position`. When `more` is true, pass
`next_before` as `before` to get the next older page.

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
