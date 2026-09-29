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
| operator | `/run/mcp-gateway-admin/operator.sock` | members of `gatte-operators` (file `0660`) | overview, tools, access, audit, backends, quota, people, connect |
| accounts | `/run/mcp-gateway-admin/accounts.sock` | root (file `0600`), or `[admin] account_group` | identity provider accounts |

A route of the other socket answers 404. On a systemd host both are
socket-activated: the backend starts on the first connection and exits
after five idle minutes, so nothing runs while nobody operates. Elsewhere,
run it in the foreground:

```sh
sudo -u mcpgw mcp-gateway admin -config /etc/mcp-gateway/config.toml \
    -socket /run/mcp-gateway-admin/operator.sock -socket-group gatte-operators -idle 0
sudo mcp-gateway admin -accounts -config /etc/mcp-gateway/config.toml \
    -socket /run/mcp-gateway-admin/accounts.sock -idle 0
```

Unit files to copy are in `examples/systemd/`.

## What you import

Two public packages, both standard library only:

- `github.com/bunnyiesart/Gatte/pkg/adminapi`: the request and response
  types, the error codes, and `Client`.
- `github.com/bunnyiesart/Gatte/pkg/frontkit`: the browser protections a
  web front needs (below). A front that is not a web page does not need it,
  except for its escaping helpers.

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
```

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
  that map to a role.
- **Passwords are generated, returned once and stored hashed.** No endpoint
  accepts a password. The response carrying one is `Cache-Control: no-store`.
- **A change that happened is never hidden.** If the trail cannot record a
  change that was made, the answer is `audit_write_failed` with
  `details.applied: true`. Say so on screen.
- The configuration is re-read on every request; a file that does not load
  refuses the request.

Errors are `{"error": {"code", "message", "details"}}`. Branch on `code`,
which is stable; show `message`, which is for people. An unknown code is
handled by its HTTP status.

## What a front must still do

The backend does not know what you render or who is at your screen.

1. **Name yourself** with `WithFront("name")` (`Gatte-Front` header). It
   becomes the `[name]` tag in the operator row, so the trail can tell your
   front from the CLI. It decides nothing.
2. **Escape every untrusted field.** Fields marked `x-gatte-untrusted` in
   the contract come raw: tool names and definitions written by backends,
   analyst subjects and names, reasons, IdP display names. Escape them for
   your medium and make hidden code points visible with
   `frontkit.Visible` / `frontkit.VisibleText` / `frontkit.Segments`
   (a U+202E must show as `\u{202E}`, not reorder the line).
3. **Never pass a browser through.** The backend refuses any request that
   carries `Origin` or `Cookie`. A web front terminates the browser itself
   and calls the API as its own process.
4. **A web front uses `frontkit`** for what `design/adr/0036` requires of a
   page on loopback:

   ```go
   kit, err := frontkit.New(frontkit.Config{Listen: "127.0.0.1:8091"})
   // refuses a non-loopback bind; makes the one-time login token and the CSRF token
   http.Serve(ln, kit.Handler(myMux))
   // loopback Host check, /login?token= once -> /s/ID/ + HttpOnly SameSite=Strict
   // cookie, CSRF token + same Origin on every POST, CSP default-src 'none',
   // X-Frame-Options DENY, nosniff, no-referrer, no-store, body limit
   fmt.Println(kit.LoginURL(ln.Addr()))    // print it to the terminal only
   ```

   Put `kit.CSRFToken()` in every form, build links under `kit.Base()`,
   change state only on POST, and ship no script unless you widen the CSP
   knowingly: every page of the operator console has the operator's
   powers.
5. **Show a one-time password once and keep no copy**: not in a log, a
   cache, a template variable that outlives the response, or a URL.

## Versioning

Everything is under `/v1`. Within it, changes are additive only: new
endpoints, new optional fields, new error codes. Ignore fields you do not
know. A breaking change becomes `/v2`, served beside `/v1` for at least one
release; `GET /v1/whoami` lists what the running backend serves.

## Building without a front

`go build -tags nofront ./cmd/mcp-gateway` produces the gateway, the
backend and the CLI without the Gatte web front. The `ui` subcommand then
says so and exits.
