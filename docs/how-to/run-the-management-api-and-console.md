# Run the management API and the web console

This guide is for the operator who sets up the management API
(`mcp-gateway admin`) on a systemd host, gives operators access to it, and
opens the web console (`mcp-gateway ui`) on the host or from their own
machine. Writing another front is [Writing a Gatte front](../admin-api.md);
the decision records are `design/adr/0036`, `0040` and `0050`.

You need:

- a host set up as in the README's [Quick start](../../README.md#quick-start),
  with systemd, `serve` running as `mcpgw`, and root on it;
- the unit files in [`examples/systemd/`](../../examples/systemd/);
- for account editing (`-manage-users`) only: `[idp] users_file` set in
  `config.toml` to the identity provider's users file.

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

## How it fits together

The management API listens on two UNIX sockets and nothing else, and takes
the operator's name from the kernel's credentials of whoever connects:

| Socket | Path | Who connects | Backend runs as |
|---|---|---|---|
| operator | `/run/mcp-gateway-admin/operator/operator.sock` | members of `gatte-operators` (`root:gatte-operators 0660`) | `mcpgw` |
| accounts | `/run/mcp-gateway-admin/accounts/accounts.sock` | root (`root:root 0600`), or a delegated group | root |

systemd owns both sockets. The backend starts on the first connection and
exits five minutes after its last request (`-idle 5m` in the units), so
nothing runs while nobody operates. The console is a client of the operator
socket: it reads no configuration file and opens no database.

## 1. Create the operator group

1. As root, create the group and add each operator:

   ```sh
   sudo groupadd --system gatte-operators
   sudo usermod -aG gatte-operators OPERATOR
   ```

   `OPERATOR` is the person's login name on the host. A group change
   reaches their next login, not the shell they have open.

2. As root, name the group in `config.toml`, so the backend also checks the
   peer's groups, not only the socket file's mode:

   ```toml
   [admin]
   operator_group = "gatte-operators"
   ```

   `serve` does not read `[admin]`: no restart or reload is needed. The
   operator backend refuses to start if the socket file belongs to another
   group than `operator_group`, or is open to others.

## 2. Install the units

1. As root, copy the socket and service units:

   ```sh
   sudo install -m 0644 examples/systemd/mcp-gateway-admin*.socket \
     examples/systemd/mcp-gateway-admin*.service /etc/systemd/system/
   ```

2. Point them at your paths. The example units run
   `-config /etc/mcp-gateway/config.toml`, and their `ReadWritePaths=`
   name `/var/db/mcp-gateway`, `/var/log/mcp-gateway` and, for the accounts
   unit, `/etc/authelia`. On the Quick start's layout, change the
   configuration path in both services:

   ```sh
   sudo sed -i 's#-config /etc/mcp-gateway/config.toml#-config /usr/local/etc/mcp-gateway/config.toml#' \
     /etc/systemd/system/mcp-gateway-admin.service \
     /etc/systemd/system/mcp-gateway-admin-accounts.service
   ```

   Use the same file `serve` runs with. A backend pointed at another file
   validates one configuration while `serve` applies another.
   `ReadWritePaths=` must hold your database directory, your `[audit.siem]`
   file's directory and, for the accounts unit, the users file's directory;
   under `ProtectSystem=strict` everything else is read-only, and an
   operator action whose row cannot reach the SIEM copy answers
   `recorded: false`.

3. As root, load and start the operator socket:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now mcp-gateway-admin.socket
   ```

4. Only if `[idp] users_file` is set, start the accounts socket too:

   ```sh
   sudo systemctl enable --now mcp-gateway-admin-accounts.socket
   ```

   Without `users_file`, `admin -accounts` refuses to start. It also
   refuses a `config.toml`, a users file or any directory above them that
   is not root's or is writable by group or others.

5. Check the socket:

   ```sh
   ls -l /run/mcp-gateway-admin/operator/operator.sock
   ```

   It is `srw-rw----`, owned by `root` with group `gatte-operators`.

## 3. Open the console on the host

1. As yourself, a member of `gatte-operators`, on the gateway host:

   ```sh
   mcp-gateway ui
   ```

   It checks the operator socket first, then prints:

   ```text
   Gatte web console on /run/mcp-gateway-admin/operator/operator.sock, acting as operator "OPERATOR".

   Open this link (it logs this browser in; keep it private):

       http://127.0.0.1:8090/login?token=...
   ```

   The name after `acting as operator` is the one every row you write will
   carry, taken from the kernel, not from anything you type.

2. Open the link in a browser on the host.

The link works once: it opens one session of up to 12 hours, and a second
use is refused. For a new session, stop `ui` with Ctrl-C and run it again.
The console binds loopback only (`-listen` refuses any other address, for
example `-listen 127.0.0.1:8091` for another port), refuses a request with
another `Host`, and runs only while `ui` runs; the management API keeps
running after you stop it.

If `ui` answers `cannot use the management API at ...`, either the socket
is not running (step 2) or your login is not yet in `gatte-operators`.

## 4. Open the console from your own machine

1. On your machine, forward the port to the gateway host:

   ```sh
   ssh -L 8090:127.0.0.1:8090 gatte.example.org
   ```

2. In that ssh session, run `mcp-gateway ui` as in step 3.

3. Open the printed link in a browser on your machine. The same URL works,
   because the tunnel ends on the host's loopback.

## 5. Edit accounts, with `-manage-users`

The **People** page adds, changes, disables, offboards and deletes the
identity provider's accounts only when the console also has the accounts
socket.

- As root:

  ```sh
  sudo mcp-gateway ui -manage-users
  ```

- Or delegate it to a group, so its members run `mcp-gateway ui
  -manage-users` without `sudo`. Set both, or the accounts backend refuses
  to start:

  ```toml
  [admin]
  account_group = "gatte-accounts"
  ```

  ```sh
  sudo install -d /etc/systemd/system/mcp-gateway-admin-accounts.socket.d
  sudo install -m 0644 examples/systemd/mcp-gateway-admin-accounts.socket.d/group.conf \
    /etc/systemd/system/mcp-gateway-admin-accounts.socket.d/
  sudo systemctl daemon-reload
  sudo systemctl restart mcp-gateway-admin-accounts.socket
  ```

  The drop-in sets `SocketGroup=gatte-accounts` and `SocketMode=0660`. A
  delegated member changes only accounts whose groups all map to a role in
  `[group_to_role]`; every other account of the identity provider stays
  root's (`account_not_managed`).

`ui -manage-users` refuses an accounts socket whose server is not root,
before any page exists. The person-level steps are in
[Add and remove people](add-and-remove-people.md).

## What the console does and does not do

With `[admin] console_manages = false`, the default, the console approves,
revokes and reviews tools, blocks and unblocks, reads and verifies the
audit trail, announces maintenance, reads quota, and with `-manage-users`
edits accounts. Nothing else below appears, and its routes answer 404.

With `[admin] console_manages = true` (`design/adr/0050`) it also:

- **Adds a REST API** on **Backends**, from its OpenAPI document by URL,
  pasted or uploaded as a file (up to 4 MiB), with the auth kind (derived
  from the document, none, bearer, header or query), the header or
  parameter name and the key's vault name (`NAME_API_KEY` when left empty
  for a keyed API). The report lists each tool as safe or sensitive, the
  operations skipped and the ingestion's warnings, and links to the review.
  Registering does not call the API.
- **Shows each backend's page**: its entry, auth, operations with method,
  path and class, signature and state, and its tools in review.
- **Redials** a backend and **reloads** the configuration (Overview); a
  request `serve` has not answered yet shows a Refresh link.
- **Removes** a backend once you type its name; its signature and every
  approval of its tools go with it.
- **Clears** an approved sensitive tool from its page, when a role marked
  `non_read` names it.

With `console_manages = true` **and** `-manage-users` (the accounts socket,
root's), it also:

- **Writes the key's value** you give in the Add an API form to the vault,
  and **signs** the new backend in the same step; a backend's page has a
  **Sign** button while it is not signed.
- **Secrets**: the vault's names, the names a backend declares that the
  vault lacks, and forms to set, replace or delete a value. A value is
  entered in a password field, written once and never shown again, in a
  page, a log or the audit trail, which records the name only.
- **Roles**: the `roles_file` as text. **Apply** writes it only if the
  configuration would load with it (otherwise the text stays on the page
  with the reason) and then reloads the running gateway. This needs
  `roles_file` set; with the roles in `config.toml` the page says so.

Without `-manage-users`, the Backends page says to start the console with
`sudo mcp-gateway ui -manage-users` to sign and to write keys, and an API
added there waits unsigned until `sudo mcp-gateway sign NAME`.

The console never:

- **Registers stdio or container backends**, or moves a backend to a new
  image: those stay in the terminal ([Add a backend](add-a-backend.md),
  [Update a backend's container image](update-a-backend-image.md)).
- **Shows a secret's value**, once written.
- **Is reachable from the network**: it binds loopback, and from elsewhere
  you reach it through `ssh -L` (step 4).

## Without systemd

Run the backends in the foreground, as in
[Writing a Gatte front](../admin-api.md) ("What you connect to"): create the
socket directories root's and `0755`, then run `mcp-gateway admin` as the
service account with `-socket` and `-socket-group gatte-operators`, and
`mcp-gateway admin -accounts` as root. In the foreground the backend does
not exit when idle unless you give `-idle`. The operator backend refuses to
run as root, and the accounts backend refuses to run as anything else.

## Check it worked

- `systemctl status mcp-gateway-admin.socket` shows it `active
  (listening)`.
- `mcp-gateway ui` prints `acting as operator "YOU"` and a login link.
- An action in the console, such as an approval, appears in
  `sudo -u mcpgw mcp-gateway audit -config "$CFG"` as your operator row,
  tagged `[ui]`.
