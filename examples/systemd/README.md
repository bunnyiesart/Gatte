# systemd units for the management API

`mcp-gateway admin` (design/adr/0040, docs/admin-api.md) is socket
activated: systemd owns the socket files and starts the backend on the
first connection; it exits five minutes after its last request.

| Unit | Socket | Runs as |
|---|---|---|
| `mcp-gateway-admin.socket` / `.service` | `/run/mcp-gateway-admin/operator/operator.sock`, `root:gatte-operators 0660` | the service account (`mcpgw`) |
| `mcp-gateway-admin-accounts.socket` / `.service` | `/run/mcp-gateway-admin/accounts/accounts.sock`, `root:root 0600` | root |
| `mcp-gateway.service` | none (the gateway, `serve`) | the service account (`mcpgw`) |

`mcp-gateway.service` runs `serve` itself. `systemctl reload mcp-gateway`
applies `[[role]]`, `[group_to_role]` and `[quota]` without a restart
(design/adr/0044): its `ExecReload=` is `mcp-gateway reload`, which waits
for `serve`'s answer, so a file `serve` refuses makes the reload fail and
the policy in force is kept. Every other key needs `systemctl restart`.

```sh
install -m 0644 mcp-gateway-admin*.socket mcp-gateway-admin*.service /etc/systemd/system/
groupadd --system gatte-operators
systemctl daemon-reload
systemctl enable --now mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket
```

To let a group edit accounts without sudo, copy
`mcp-gateway-admin-accounts.socket.d/group.conf` to
`/etc/systemd/system/mcp-gateway-admin-accounts.socket.d/` and set
`[admin] account_group` to the same group in `config.toml`. The accounts
backend refuses to start when the two disagree.

The accounts backend also refuses `config.toml`, `[idp] users_file` or any
directory above them that is not root's or is writable by group or others.
The units' `ReadWritePaths=` are `config.example.toml`'s: the database in
`/var/db/mcp-gateway`, the `[audit.siem]` file in `/var/log/mcp-gateway`,
and the users file in `/etc/authelia`. Adjust them to where yours live;
under `ProtectSystem=strict` anything else is read-only, and an operator
write whose row cannot reach the SIEM copy answers `recorded: false`.

The users file keeps its owner and group across every rewrite (Authelia
usually reads it through its group, e.g. `root:www 0640`). That needs
`CAP_CHOWN`, which the accounts unit keeps; a backend without it refuses
the change instead of leaving the IdP a file it cannot read.

The operator backend refuses to start when its socket file is open to
others, or belongs to a group other than `[admin] operator_group`.
