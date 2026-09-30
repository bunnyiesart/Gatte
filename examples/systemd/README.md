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
the policy in force is kept. Every other key `serve` reads needs
`systemctl restart mcp-gateway`. The admin backends read `[admin]
operator_group` and `account_group` when they start, so a change there
takes effect at their next start (after their idle exit, or `systemctl
restart mcp-gateway-admin.service`).

The units name the configuration `/etc/mcp-gateway/config.toml`, while the
README and `docs/` use `/usr/local/etc/mcp-gateway/config.toml`: edit
`-config` in each `ExecStart=`/`ExecReload=` to the path your host uses.

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

## Database backup

`mcp-gateway-backup.service` and `.timer` take a copy of the database once a
day with `mcp-gateway backup` (design/adr/0045), while serve runs, and keep
the newest 14 in `/var/backups/mcp-gateway`:

```sh
install -d -m 0700 -o mcpgw -g mcpgw /var/backups/mcp-gateway
install -m 0644 mcp-gateway-backup.service mcp-gateway-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mcp-gateway-backup.timer
systemctl start mcp-gateway-backup.service     # one now, to see it work
journalctl -u mcp-gateway-backup               # sha256, audit head, what is NOT in the copy
```

The copy is the database and nothing else. The configuration file, the
encrypted vault, the age key, the signing key and the identity provider are
backed up separately; the age key and the signing key are secrets, so keep
their copies offline and apart from the database copies. The unit runs with
no network: shipping the copies off the host is a separate job of yours.
Restoring one is `docs/upgrade.md`, "Rollback".
