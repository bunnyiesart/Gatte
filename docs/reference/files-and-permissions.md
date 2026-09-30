# Files and permissions

This page is for whoever installs or audits a Gatte host. It lists every
file, directory and socket Gatte reads or writes, its owner and mode, which
process reads or writes it, what Gatte itself enforces when it uses it, and
exactly what `mcp-gateway check` verifies. Paths are the Quick start's;
the service account is `mcpgw` and the operator socket's group is
`gatte-operators`. The layout's reasoning is in the README's [Who owns
what](../../README.md#who-owns-what).

## Layout

| Path (Quick start) | Configured by | Owner:group | Mode | Read by | Written by |
|---|---|---|---|---|---|
| `/usr/local/etc/mcp-gateway/` | | `root:mcpgw` | `0750` | everyone below | root |
| `/usr/local/etc/mcp-gateway/config.toml` | `-config` | `root:mcpgw` | `0640` | `serve`, every operator command, `admin`, `admin -accounts`, `check`, `sign` | root; never Gatte |
| `/usr/local/etc/mcp-gateway/signing.key` | `signer.key_file` | `root:root` | `0600` | `sign`, as root | `sign -generate-key` (creates only) |
| `/usr/local/etc/mcp-gateway/age.key` | `vault.age_key_file` | `mcpgw:mcpgw` | `0600` | `sops`, run by `serve` and `check` | root; never Gatte |
| `/usr/local/etc/mcp-gateway/secrets.enc.json` | `vault.secrets_file` | `root:mcpgw` | `0640` | `sops`, run by `serve` and `check` | the operator with `sops`; never Gatte |
| `/var/db/mcp-gateway/` | directory of `database` | `mcpgw:mcpgw` | `0750` | | SQLite, as `mcpgw` |
| `/var/db/mcp-gateway/mcp-gateway.db`, `-wal`, `-shm` | `database` | `mcpgw:mcpgw` | the process umask | every command that opens the database | `serve` and operator commands, as `mcpgw` |
| `/var/log/mcp-gateway/` | directory of `audit.siem.path` | `mcpgw:mcpgw` | `0750` | a shipper | `mcpgw` |
| `/var/log/mcp-gateway/audit.jsonl` | `audit.siem.path` | `mcpgw:mcpgw` | `0600` | a shipper | `serve` and operator commands that write a row, as `mcpgw` |
| `/run/mcp-gateway-admin/operator/operator.sock` | `admin -socket` | `root:gatte-operators` | `0660` | `ui`, any front | `admin` |
| `/run/mcp-gateway-admin/accounts/accounts.sock` | `admin -accounts -socket` | `root:root` | `0600` | `ui -manage-users` | `admin -accounts` |
| `[idp] users_file` (e.g. `/etc/authelia/users_database.yml`) | `idp.users_file` | root, not group- or other-writable | kept as found | `admin -accounts` | `admin -accounts`, as root |
| `telemetry.tls_ca_file` | `telemetry.tls_ca_file` | readable by `mcpgw` | | `serve`, operator commands that write a row | never Gatte |
| `connect.ca_file` | `connect.ca_file` | readable by `mcpgw` | | `admin` (the connect scripts) | never Gatte |
| `/etc/subuid`, `/etc/subgid` | | system | | `check` | never Gatte |

## Per file

### Configuration file

| | |
|---|---|
| Holds | paths, identifiers, the trusted public keys, roles. No secret. |
| Enforced at use | `admin -accounts` checks, before every request, that the file and every directory above it are owned by root, are not symbolic links, are regular (the file) or directories, and are not writable by group or others; otherwise the request answers `config_unavailable`. Nothing else checks its ownership. |
| `check` | the configuration loads; the service account can read it, cannot write it, and cannot write its directory. |

### Signing key

| | |
|---|---|
| Format | Ed25519 private key, PEM PKCS#8. |
| Created by | `sign -generate-key -out PATH`, with `O_EXCL` and mode `0600`: never overwrites a file. |
| Enforced at use | `sign` refuses a key file readable by group or others. `sign` reads it as root and then becomes the database directory's owner. `serve` never reads it. |
| `check` | root owns it; no group or other bit is set; the service account cannot read it; the service account cannot write its directory. |

### Age key

| | |
|---|---|
| Enforced at use | Before running `sops`, the vault refuses the key unless it is a regular file with no group or other bit set. The path is handed to `sops` in `SOPS_AGE_KEY_FILE`; Gatte never reads its contents. |
| `check` | no group or other bit is set; the service account can read it. |

### Vault file

| | |
|---|---|
| Enforced at use | `sops --decrypt` runs with only `PATH` and `SOPS_AGE_KEY_FILE` in its environment. The file is decrypted again when its modification time or size changes. |
| `check` | the service account can read it (FAIL otherwise) and cannot write it (WARN otherwise); `sops` is on this shell's `PATH`; it decrypts; it holds every variable name a registered backend declares. No value is printed. |

### Database and its -wal and -shm

| | |
|---|---|
| Mode | Journal mode WAL, `busy_timeout` 5000 ms. Gatte does not set the files' mode; SQLite creates them with the process umask. |
| Enforced at use | `sign`, `backup`, `restore` and `check`, run as root, become the owner of the database's directory (refusing a symbolic link) before opening it, so no `-wal` or `-shm` is left owned by root. Other operator commands have no such step. `admin -accounts` requires the database's directory not to be root's: its children run as that directory's owner. |
| `check` | the directory exists and the service account can write it; each of the database, `-wal` and `-shm` that exists is writable by it; the schema is not newer than this binary's; SQLite's integrity check passes; every table, index and trigger is one this binary's migrations create; the audit chain verifies; the registry's signatures are valid. |

### SIEM copy

| | |
|---|---|
| Enforced at use | Opened `O_APPEND`, created `0600`; an existing file with a wider mode is narrowed to `0600`. If it cannot be opened, `serve` does not start. Not reopened on `SIGHUP`. |
| `check` | the directory exists; the file, if it exists, is writable by the service account; the service account can create files in the directory. |

### Identity provider's users file

| | |
|---|---|
| Enforced at use | Before every request of `admin -accounts`: the file and every directory above it are root's, not symbolic links, not writable by group or others. A rewrite goes through a temporary file in the same directory and keeps the file's mode, owner and group. |
| `check` | not checked. |

### CA files

`telemetry.tls_ca_file` must exist and hold a certificate, or `serve` does
not start. `connect.ca_file` must be an absolute path; it is read when a
connect script is built. `check` checks neither.

## Sockets

| | Operator socket | Accounts socket |
|---|---|---|
| Default path | `/run/mcp-gateway-admin/operator/operator.sock` | `/run/mcp-gateway-admin/accounts/accounts.sock` |
| Served by | `admin`, as the service account (root refused) | `admin -accounts`, as root only |
| Under systemd | `mcp-gateway-admin.socket`: `root:gatte-operators` `0660` | `mcp-gateway-admin-accounts.socket`: `root:root` `0600`; with `socket.d/group.conf`, `root:gatte-accounts` `0660` |
| In the foreground | created `0600` whatever the umask, then given `-socket-group` and `-socket-mode` (`0600`, or `0660` with a group) | same |
| Directory chain (foreground) | every directory from `/` to the socket's: no symbolic link, not writable by group or others, owned by root; the socket's own directory may be the service account's | the same, every directory root's |
| Refused at start | a file with any permission for others; a group other than `[admin] operator_group` when that is set and the group bits are open | a file with any permission for others; group bits open while `[admin] account_group` is empty; `account_group` set without `0660`, or with another group |
| Peers | root, the service account, or (when `operator_group` is set) a member of it | root, or a member of `account_group` when delegated; the service account is refused |

`ui` refuses an accounts socket whose server is not root.

## Temporary and derived files

| File | Where | Mode | Made by |
|---|---|---|---|
| `mcp-gateway-YYYYMMDDTHHMMSSZ.db` | the `backup -out` directory | `0600` | `backup` |
| `.mcp-gateway-backup-*/` | beside the backup's destination; removed after | private | `backup` |
| `.mcp-gateway-restore-*.db` | the database's directory; renamed into place or removed | `0600` | `restore` |
| `DB.pre-restore-YYYYMMDDTHHMMSSZ` with `-wal`, `-shm` | the database's directory | as they were | `restore` (the replaced database) |
| `mcp-gateway-check-*/snapshot.db` | the system temporary directory; removed after | private | `check`, for a database at an older schema |
| `.USERSFILE.*` | the users file's directory; renamed into place | the users file's | `admin -accounts` |

`serve` records its process id in the database, not in a file.

## On the analyst's machine

The connect script, run by the analyst, writes:

| Path | Content |
|---|---|
| `~/.config/gatte/bin/gatte-status` (Windows: `%USERPROFILE%\.gatte\gatte-status.ps1` and `gatte-status.cmd`) | the offline status command, rewritten on every run |
| `~/.config/gatte/ca.pem` (Windows: `%USERPROFILE%\.gatte\ca.pem`) | the CA, when `connect.ca_file` is set |
| `~/.zshrc`, `~/.bashrc`, `~/.profile`, each that exists (`~/.profile` created if none does) | `NODE_EXTRA_CA_CERTS` when a CA is set, and the `PATH` line for `gatte-status`, each once. Windows: the user's environment variables. |
| Claude Code's user settings | the MCP server entry, through `claude mcp add --scope user`, replacing one of the same name |

## What check verifies

`mcp-gateway check` runs these checks in this order and prints one line
each: `PASS`, `WARN`, `FAIL` or `SKIP`, with the fix for a `FAIL` or `WARN`.
It exits `1` if any check fails. The database is opened read-only and
nothing is written. Permission checks read owner, group and mode bits the
way the kernel applies them to the service account (owner bits, else group
bits for its primary and supplementary groups, else other bits); ACLs and
MAC policy are not read.

| # | Check | PASS | WARN | FAIL | SKIP |
|---|---|---|---|---|---|
| 1 | `configuration` | the file loads and validates | | it does not load; the loader's message is shown | |
| 2 | `service account` | the account `serve` runs as: `-user`, else the owner of the database's directory (when not root), else the user running `check` (when not root) | | it is root | none could be determined; ownership checks are skipped |
| 3 | `configuration file` | the account reads it and can write neither it nor its directory | the file or directory cannot be examined as this user | it cannot read it; it can write it; it can write its directory; it does not exist | no service account |
| 4 | `signing key` | root's, no group or other bit, unreadable by the account, directory not writable by it | the file does not exist (the key may be on another host) or cannot be examined | owned by another uid; group or other bits set; readable by the account; its directory writable by the account | `signer.key_file` is not set |
| 5 | `age key` | no group or other bit, readable by the account | it cannot be examined as this user | group or other bits set; the account cannot read it; it does not exist | |
| 6 | `vault file` | the account reads it and cannot write it (or it exists, with no service account) | the account can rewrite it; it cannot be examined | the account cannot read it; it does not exist | |
| 7 | `sops` | on this shell's `PATH` | | not on `PATH` | |
| 8 | `SIEM copy` | the account can append to the file and create files in its directory | the directory cannot be examined | the directory does not exist; the file is not writable by the account; the directory is not writable by it | `[audit.siem]` is not configured |
| 9 | `database` | the directory is writable by the account and the database does not exist yet (`serve` creates it); an existing database is reported by checks 10 to 13 | the directory cannot be examined; the file cannot be opened or read; a copy at an older schema cannot be made or read | the directory does not exist or is not writable by the account; the database, `-wal` or `-shm` is not writable by it; dropping to the directory's owner fails; SQLite's integrity check fails | |
| 10 | `database schema` | the schema is this binary's, or older (migrated at the next start) | | the schema is newer than this binary's | |
| 11 | `database schema objects` | every table, index and trigger is one this binary's migrations create | | an object differs or is extra | |
| 12 | `audit trail` | the hash chain verifies | | the chain breaks | |
| 13 | `registry signatures` | every entry is validly signed | unsigned entries with `require_signed` off; no backend registered | an `INVALID` entry; unsigned entries with `require_signed` on | |
| 14 | `vault contents` | it decrypts and holds every variable name the registry declares (or decrypts, when no registry was read) | | it does not decrypt; names are missing | `sops` is missing; the age key cannot be read as this user |
| 15 | `oci backends` | `podman` is on `PATH` and the account has subordinate uid and gid ranges of at least 65536 in `/etc/subuid` and `/etc/subgid` (on a non-Linux host, `podman` on `PATH` only) | `podman` is on `PATH` and no service account is known | `podman` is not on `PATH`; a subordinate range is missing | no `oci` backend is registered |
| 16 | `identity provider` | with `-online`: `ISSUER/.well-known/openid-configuration` answers `200` with this issuer and a `jwks_uri` | | unreachable; another status; not a discovery document; another issuer; no `jwks_uri` | without `-online` |

Checks 3 to 9 examine files as the user running `check`, root in
production. Before check 9 opens the database, `check` run as root becomes
the owner of the database's directory, so checks 10 to 16 run with the
service account's rights: `vault contents` then decrypts with the account's
access to the age key. The report ends with what is not checked: ACLs and MAC policy, the
service manager's `PATH` and limits, the proxy in front, and whether each
backend answers. `check` does not check the sockets, the users file, the CA
files, or the signing key's directory beyond the service account's write
bit.
