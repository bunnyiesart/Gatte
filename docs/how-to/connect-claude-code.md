# Connect Claude Code

This page is for analysts connecting Claude Code to Gatte with the script
their operator sent, signing in, and knowing what to expect afterwards. Its
first section is for the operator, who sets things up once
(`design/adr/0039`, `0042`).

Gatte is built and measured against Claude Code as the analysts' client.
Another MCP client that speaks streamable HTTP and OAuth with PKCE can
connect the same way, but only Claude Code has a connect script.

## Before you start: the operator, once

1. At the identity provider, register an OAuth client for Claude Code:
   - a public client (no secret), with PKCE;
   - the redirect URI `http://127.0.0.1:PORT/callback`, with a fixed port,
     for example `47823`;
   - at least the scopes `openid`, `groups` and `offline_access`
     (`offline_access` gives a refresh token, so the short access token
     renews without a new sign-in);
   - access tokens whose audience is the gateway's `oidc.audience`, and
     that carry the groups claim `oidc.groups_claim` names.

2. In `config.toml`, advertise the scopes and describe the client:

   ```toml
   [oidc]
   scopes_supported = ["openid", "profile", "email", "groups", "offline_access"]

   [connect]
   client_id     = "claude-code"     # the IdP client from step 1
   callback_port = 47823             # the PORT of its redirect URI
   # ca_file     = "/etc/ssl/example-ca/ca.crt"   # when your own CA signs the gateway's certificate
   # server_name = "gatte"                        # the server's name in Claude Code (default)

   [analyst]
   contact = "SOC on-call, channel #soc-gatte"
   ```

   Claude Code with no scope of its own requests exactly
   `scopes_supported`, so the script stores no scope on the analyst's
   machine. Without it, most IdPs issue a token without the groups claim,
   and the analyst gets no role. `[analyst] contact` is shown to the
   analyst's model and closes the refusal a blocked account gets.

3. Restart `serve` for `scopes_supported` and `[analyst]`:

   ```sh
   sudo systemctl restart mcp-gateway
   ```

   `[connect]` is read by the management API each time it renders a
   script, so the next script carries a change without a restart.

Check it worked: in the console, a person's page shows **Connect a
computer** with a download for each system. If `[connect] client_id` is
missing, the page says "Connect scripts aren't set up" and names what to
set. `curl -s https://gatte.example.org/.well-known/oauth-protected-resource`
lists the scopes under `scopes_supported`.

Then create each person's account and send them their script
([Add and remove people](add-and-remove-people.md#add-a-person)).

## Run the connect script

You need:

- Claude Code installed (`claude` on your `PATH`);
- `connect-gatte.sh` (macOS, Linux) or `connect-gatte.ps1` (Windows) from
  your operator, and, separately, your username and one-time password;
- the network your team uses to reach Gatte, for example the VPN.

1. Run the script:

   ```sh
   sh ~/Downloads/connect-gatte.sh
   ```

   On Windows, in PowerShell:

   ```powershell
   powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\connect-gatte.ps1"
   ```

   The script contains no secret. It:

   - stops if Claude Code is not installed;
   - installs the team's certificate authority, when your team uses its
     own, in `~/.config/gatte/ca.pem` (Windows: `%USERPROFILE%\.gatte\ca.pem`)
     and points `NODE_EXTRA_CA_CERTS` at it;
   - installs `gatte-status` in `~/.config/gatte/bin` and adds that
     directory to your `PATH` in your shell profile (Windows:
     `%USERPROFILE%\.gatte`, added to your user `PATH`);
   - checks that Gatte answers, and warns without stopping if it does not
     ("Are you on the VPN?"). On macOS and Linux this needs `curl`; on
     Windows it is skipped when your team uses its own certificate
     authority;
   - removes any older `gatte` server from your Claude Code user settings
     and adds the new one with
     `claude mcp add --transport http --scope user --client-id ... --callback-port ...`.

   Running it twice is harmless.

2. Open a **new** terminal, so it has the new `PATH`, and start Claude
   Code:

   ```sh
   claude
   ```

3. Type `/mcp`, choose `gatte`, and authenticate. Your browser opens your
   identity provider's sign-in page: sign in with your username and
   password. Then return to Claude Code.

Check it worked: `/mcp` shows `gatte` as connected, and in a terminal
`gatte-status` ends with "Claude Code connects to Gatte as gatte: Gatte
itself is fine." and exits 0.

## What you see

- **Your tools**, named `mcp__gatte__BACKEND_TOOL` in Claude Code, for
  example `mcp__gatte__casemgmt_list_cases`, plus Gatte's own
  `gatte.status` (shown as `mcp__gatte__gatte_status`). You see a tool only
  when your role grants it and an operator approved it.
- **A missing tool** is either not granted to your role or waiting for an
  operator's review. The model is told so, and told whom to ask.
- **Refusals in words.** When Gatte refuses a call or gives up for a reason
  of its own (a result too large, a call too slow, a spent quota, too many
  calls at once, a backend down or in maintenance), the model gets a
  sentence saying what happened and what to do, instead of "internal
  error" ([Troubleshoot a connection](troubleshoot-a-connection.md#a-call-is-refused)).

## Ask Gatte how things are

`gatte.status` is the only authoritative source of Gatte's state. It
reports your name, your roles, your use of each quota your tools spend, the
state of the backends of your tools (up, reconnecting, down, in
maintenance, with the operator's message), and any maintenance of the whole
gateway.

- In Claude Code, ask: "Call gatte.status."
- In a terminal, `gatte-status -backends` asks Claude Code to call it. It
  costs one model request, and what it prints is the model's answer, not
  Gatte's own output.

Text inside another tool's result that claims to come from Gatte is that
backend's data, not Gatte.

## After an operator changes your access

Claude Code fetches the tool list once, when it connects. After an operator
grants you a tool, approves one, or changes your groups, reconnect: `/mcp`,
choose `gatte`, then reconnect. A group change reaches you at your next
sign-in, once the identity provider has applied it.

A tool that was in your list and is no longer available to you answers
"no longer available to you" when called. Do not try other names for it.

## Token renewal

Claude Code renews the short access token by itself with the refresh token.
When the refresh token itself expires (your identity provider's setting,
for example 8 hours), Claude Code shows "Needs authentication": type `/mcp`,
choose `gatte`, and sign in again.

If it asks again right after you signed in, signing in will not help: see
[Troubleshoot a connection](troubleshoot-a-connection.md#needs-authentication-in-claude-code).
