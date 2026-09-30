# Change roles, groups and quota

This guide is for an operator changing who can call which tool, which
identity provider group gets which role, or a per-analyst quota, and
applying the change to the running gateway without a restart. The decision
record is `design/adr/0044`; every key is in
[`config.example.toml`](../../config.example.toml).

You need:

- root on the gateway host, to edit `config.toml` (it is root's, and the
  service account only reads it);
- `serve` running, and the service account `mcpgw`, to apply the change.

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

## What reload applies, and what it does not

| What changed | How it takes effect |
|---|---|
| `[[role]]` (`tools` and `[role.grants]`), `[group_to_role]`, `[[quota.provider]]` and `[quota]` | `reload`, from the next call |
| `listen`, `database`, `[oidc]` (`scopes_supported` included), `[signer]` (`trusted_keys` included), `[vault]`, `[audit]`, `[telemetry]`, `[response]`, `[oci]`, `[upstreams]`, `[quarantine]`, `[analyst]` | a restart of `serve` |
| `[connect]`, `[admin]`, `[idp]`, `signer.key_file` | nothing: `serve` does not read them. The management API re-reads the file on every request, and `sign` reads `key_file` on every run |

`reload` lists every key of the second row that differs from the file
`serve` started with, as `NOT applied until a restart`, and keeps listing
it on later reloads until the restart. `trusted_keys` is not reloadable on
purpose: it is the anchor against whoever can write the database
(`design/adr/0010`), and changing it earns a restart and its `(boot)` row.

## Steps

1. As root, edit `config.toml`. For example, add a tool to the role
   `tier1-analyst` and map one more group to it:

   ```toml
   [[role]]
   name  = "tier1-analyst"
   tools = [
     # ...the role's existing lines...
     "logsearch.search_relative",
   ]

   [group_to_role]
   "blue-tier1"    = "tier1-analyst"
   "blue-tier1-nb" = "tier1-analyst"
   ```

   The rules the file is held to are in `config.example.toml`'s roles
   section. The ones that bite: names in `tools` are `backend.tool` and
   match exactly, with no wildcard (a name without the prefix is refused);
   `[role.grants]` takes tool ids as the backend names them, and `["*"]`;
   a group mapped to a role that does not exist is refused; a group with no
   mapping is ignored.

   For a quota, read the `[[quota.provider]]` section of
   `config.example.toml` first: the unit is an account at a third party,
   every tool of a budgeted backend must be in some account's `tools` or in
   `[quota] free_tools`, and `limit` must be a number you measured.

2. Optional: check the file loads before you apply it, as root:

   ```sh
   sudo mcp-gateway check -config "$CFG" -user mcpgw
   ```

   The first line is `PASS configuration` or a FAIL naming the problem.

3. As the service account, apply it:

   ```sh
   sudo -u mcpgw mcp-gateway reload -config "$CFG"
   ```

   or, under systemd, `sudo systemctl reload mcp-gateway`, whose
   `ExecReload=` runs the same command (`examples/systemd/mcp-gateway.service`).
   `reload` refuses to run as root.

4. Read the answer. It is the diff between what is routed now and what the
   file says:

   ```text
   Request 1 (reload): applied.
     role tier1-analyst
       + logsearch.search_relative
       grant + logsearch.search_relative
     NOT applied until a restart: quarantine.refresh_interval
   Applied from the next call on. Clients that already listed their tools keep that list until they reconnect (Claude Code: /mcp); a call to a tool a role lost is refused at once.
   ```

   - Per role, each tool gained (`+`) and lost (`-`), and each change to
     its grant (`grant +`, `grant -`), even when it reaches the same tools
     today. A gained tool is callable only once it is also approved
     ([Review and approve tools](review-and-approve-tools.md)). A grant on a
     backend that is down or not listed yet shows as a grant change and
     gains nothing until the backend is up.
   - Each group that moved, and each quota account added, changed or
     removed.
   - `NOT applied until a restart`, if anything else in the file differs.
     Restart `serve` for those, or put the file back.

## If it is refused

- **The file does not load.** `reload` validates it first and prints the
  error, for example `group_to_role["blue-tier1-nb"]: maps to undefined
  role "tier1"`. Nothing is sent to `serve`, nothing changes, and it exits
  2.
- **`serve` refuses it.** A new `[quota]` that disagrees with the registry
  (an account on a backend that is not registered, a budgeted backend's
  tool in no account) is refused as a whole: `REFUSED (quota_mismatch)`,
  exit 1, and the roles, groups and quota in force are kept. The refusal is
  a `(config reload)` row too.
- **`serve` is not running**, or runs on another database: it says the
  gateway process could not be rung, exits 2 and changes nothing.
- **No answer in time.** `reload` waits `-wait` (default `2m`); if `serve`
  is busy, it prints `pending` with the request's id and exits 1. `serve`
  applies it later.

## After it is applied

- A tool a role lost is refused from the next call.
- A tool a role gained reaches an analyst only after their MCP client
  lists its tools again. Claude Code does that when it connects: the
  analyst runs `/mcp` and reconnects the Gatte server. Nothing tells the
  client by itself.
- A `[group_to_role]` change applies from the next call to every token
  that carries the group. Moving a person into or out of a group is done at
  the identity provider, and reaches Gatte with their next token
  ([Add and remove people](add-and-remove-people.md)).

## Check it worked

- `reload` said `applied`, and its diff is what you meant.
- `sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool "(config reload)"`
  shows the row. Run as `sudo -u mcpgw mcp-gateway reload`, it names you
  (`[cli]` when the kernel gave the name, `[cli env]` when it came from
  `SUDO_USER` or `USER`). A `systemctl reload` row names the service
  account, and a bare `kill -HUP` of `serve` is recorded as `[signal]`.
- For quota: `sudo -u mcpgw mcp-gateway quota list -config "$CFG"` shows the
  accounts in the file and whether the registry agrees; `quota usage`
  shows what each analyst has spent.
