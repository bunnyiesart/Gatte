# Troubleshoot a connection

This page is for analysts whose Claude Code cannot use Gatte, and for the
operators they ask. It starts from `gatte-status`, then covers "Needs
authentication", missing tools and each kind of refusal. The exact texts
are in [What the analyst is told](../reference/analyst-messages.md).
Operator commands use `CFG=/usr/local/etc/mcp-gateway/config.toml` and run
as the service account.

## Start with gatte-status

The connect script installed `gatte-status` on your machine
([Connect Claude Code](connect-claude-code.md)). It needs no token, reads
none and keeps nothing. Run it in a terminal:

```sh
gatte-status
```

It checks, in order, and stops at the first that fails: that Gatte's public
metadata answers, that Gatte's MCP endpoint asks for sign-in as it should,
and what `claude mcp get gatte` says. It runs Claude Code from a temporary
directory of its own, so a project you stand in cannot load its settings
into the check.

| Exit | Meaning | What to do |
|---|---|---|
| 0 | Gatte answers and Claude Code connects to it | Nothing is wrong with Gatte itself. If your open session shows `gatte` as failed or disconnected, type `/mcp` there, choose `gatte` and reconnect. For the backends, run `gatte-status -backends` (one model request) or ask Claude to call `gatte.status`. |
| 1 | The network does not reach Gatte: the name does not resolve, or the host does not answer | Check the VPN, DNS and route. |
| 2 | The TLS connection to Gatte failed | Run the connect script again, which reinstalls the team's certificate authority. If it persists, tell the operator. |
| 3 | Gatte, or the proxy in front of it, is not serving: nothing listens on its port, the proxy answers `502`, `503` or `504`, or Claude Code reports `HTTP 5xx` | Not your network. Retry later, or tell the operator. When the proxy sends a maintenance sentence, `gatte-status` prints it. |
| 4 | Gatte is up and Claude Code is not signed in, has no server named `gatte`, or is not installed | Type `/mcp` in Claude Code, choose `gatte` and authenticate. If there is no `gatte` server, run the connect script again. If it asks again right after you signed in, see [below](#needs-authentication-in-claude-code). |
| 5 | Unexpected: something in front of Gatte answers that is not Gatte, Claude Code could not connect for a reason the check does not know, or `curl` is missing | Tell the operator, with the output. |

## "Needs authentication" in Claude Code

Claude Code shows "Needs authentication" for several different causes.

1. **You have not signed in yet, or your refresh token expired** (after the
   identity provider's refresh-token lifetime, for example 8 hours). Type
   `/mcp`, choose `gatte`, authenticate, and sign in in the browser.
2. **It asks again right after you signed in.** Gatte refuses your account:
   an operator has blocked it. Gatte answers `403` with "Gatte refuses
   requests from this account. Signing in again will not change that: ask
   the SOC operator.", and Claude Code shows every `403` as "Needs
   authentication" without the text. Signing in again does not help; ask
   your operator.
3. **The sign-in page itself refuses you.** The identity provider refused
   the account: a wrong password, or an account an operator disabled. Ask
   your operator.

For operators:

- A blocked subject is in `access list`, and each of its requests is a
  `denied` row with the reason `subject blocked`:

  ```sh
  sudo -u mcpgw mcp-gateway access list -config "$CFG"
  sudo -u mcpgw mcp-gateway audit -config "$CFG" -subject SUBJECT -outcome denied -limit 10
  ```

- If every analyst loops on "Needs authentication", the gateway refuses the
  tokens the IdP issues: check that the IdP's client puts `oidc.audience`
  in `aud`, and signs with an asymmetric algorithm. Refused tokens are rows
  attributed to `(unauthenticated)`, from the analyst's address, and the
  `401` says nothing about which check failed.

## Tools are missing

- **You see only `gatte.status`.** Your token maps to no role. Ask Claude
  to call `gatte.status`: if it lists no role, your token carries no group
  Gatte knows. The operator checks that `[oidc] scopes_supported` includes
  the IdP's groups scope and that your group is in `[group_to_role]`.
- **One tool is missing.** It is not granted to your role, or it waits for
  an operator's review, new or changed since approval. Do not guess other
  names for it: ask your operator. The operator looks at
  `tool list -server NAME` for its state and `upstream list` for whether
  its backend is registered and signed.
- **An operator just granted or approved it.** Claude Code fetched your
  tool list when it connected: type `/mcp`, choose `gatte` and reconnect.

## A call is refused

When Gatte refuses or gives up for a reason of its own, the model receives
a sentence that says what happened, whether the request was at fault, and
what to do. Only an analyst granted and approved for the tool gets these;
anyone else gets what they got before, such as `unknown tool`.

| The answer starts or says | What happened | What to do |
|---|---|---|
| "the result of ... was larger than Gatte's limit" | The call ran at the backend; its result was over `response.max_bytes`, and none of it was delivered | Narrow the request (fewer results, a shorter range, fewer fields). If the call changes something, that change already happened. |
| "did not answer this call within Gatte's limit" | The backend was slower than the per-call time limit; it may still have run the call | Retry once with a narrower request; if that also times out, tell the operator. |
| "your quota on the ... account is spent" | Your own allowance on that third-party account is used up for this window | Wait until the reset time it gives. Tools that do not spend that account keep working. |
| "you already have N calls in flight" | You reached the per-analyst limit on calls at once, counting every session of yours | Wait for one to finish, then retry with the same arguments. |
| "is in planned maintenance" | An operator took the backend out, with the message shown | Retry after the maintenance ([Plan maintenance](plan-maintenance.md#what-analysts-see)). |
| "is unavailable since ...; Gatte is reconnecting it" | The backend is down and Gatte retries it | Retry after the next attempt it names. |
| "Gatte is not reconnecting it automatically; an operator has to act" | The backend is down and Gatte will not retry by itself | Tell the operator. |
| "the backend ... failed this call" | The backend returned an error, which Gatte does not forward | If it repeats with a request you believe is right, tell the operator. |
| "was in your tool list but is no longer available to you" | Your access to it changed during the session | Do not retry it or try other names. If an operator restores it, reconnect with `/mcp`. |
| `unknown tool` | You were never listed that tool | Check the name against your tool list. |
| `HTTP 503`, "Gatte is temporarily unable to serve tools" | Gatte is up and serves no tools for now | Retry in a few minutes. `gatte-status` exits 3. The operator looks for `suspended:true` in the heartbeat and the `serve` log. |

A result that ends with "Gatte notice: the Gatte gateway is in planned
maintenance" is not a refusal: the call was served, and the operator is
announcing work on the whole gateway.

When a call fails as unavailable or in maintenance, the model is told to
call `gatte.status` before assuming anything else. "up" in `gatte.status`
only means Gatte is connected to the backend: the backend can still fail
single calls.

## For operators: where to look

- What the analyst's requests got: `audit -config "$CFG" -subject SUBJECT -since TIME`.
- Who is blocked: `access list -config "$CFG"`.
- What is in maintenance: `maintenance list -config "$CFG"`.
- What is registered and signed: `upstream list -config "$CFG"`.
- Each backend's state (up, reconnecting, down, in maintenance), since
  when and why: the console's **Backends** page. **Overview** also shows
  `serve` as not reporting when it stopped.
- Why `serve` refuses or restarts: `journalctl -u mcp-gateway`.

Run each as the service account (`sudo -u mcpgw mcp-gateway ...`).
