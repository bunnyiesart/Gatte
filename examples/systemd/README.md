# systemd units for the management API

`mcp-gateway admin` (design/adr/0040, docs/admin-api.md) is socket
activated: systemd owns the socket files and starts the backend on the
first connection; it exits five minutes after its last request.

| Unit | Socket | Runs as |
|---|---|---|
| `mcp-gateway-admin.socket` / `.service` | `/run/mcp-gateway-admin/operator/operator.sock`, `root:gatte-operators 0660` | the service account (`mcpgw`) |
| `mcp-gateway-admin-accounts.socket` / `.service` | `/run/mcp-gateway-admin/accounts/accounts.sock`, `root:root 0600` | root |

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
Adjust `ReadWritePaths=` to where the database and the users file live.
