# Add and remove people

This page is for operators who manage the analysts' identity provider
accounts from the Gatte web console: adding a person and handing over
their connect script, changing groups, disabling, offboarding and deleting
an account. Account editing supports the Authelia file backend only
(`design/adr/0038`, `0046`).

You need:

- `[idp] users_file` set in `config.toml`, and the accounts socket of the
  management API running, served by root
  ([Run the management API and the web console](run-the-management-api-and-console.md));
- `[connect] client_id` and `callback_port` set, so the console can hand out
  connect scripts ([Connect Claude Code](connect-claude-code.md#before-you-start-the-operator-once));
- an identity provider that re-reads its users file when it changes
  (Authelia: `watch: true` in its configuration, or a restart). Every
  account change below reaches the IdP only when it reloads that file.

The examples use `CFG=/usr/local/etc/mcp-gateway/config.toml`.

## Open the console with account editing

1. As root, start the console with the accounts socket:

   ```sh
   sudo mcp-gateway ui -manage-users
   ```

   It prints a `/login` link that works once. If you are not on the
   gateway host, forward the port first with
   `ssh -L 8090:127.0.0.1:8090 gateway-host` and open the same link
   locally.

2. Open **People**. Without `-manage-users`, the page shows roles and who
   has used the gateway, but no account buttons.

A member of a delegated `[admin] account_group` runs the same command
without `sudo` (see [Let a group manage accounts](#let-a-group-manage-accounts-without-sudo)).

## Add a person

1. On **People**, choose **Add person**. The assistant has four steps:
   **Person**, **Access**, **Review** and **Connect**.
2. **Person**: type the full name. Leave **Username** empty to use the
   suggested one (`Ana Souza` becomes `ana.souza`). **Email** is optional.
   Choose **Continue**.
3. **Access**: tick the groups the person gets. The page lists only groups
   that map to a role in `[group_to_role]`, each with its role's tools. A
   person with no group can sign in and sees no tool. Choose **Continue**.
4. **Review**: check the name, username and access, then choose **Create
   account**.
5. **Connect**: the result page shows two things to hand over:
   - **Their one-time password.** It is shown only on this page and stored
     only as an argon2id hash. Gatte shows it once; it does not make the
     IdP ask for a new password at the first sign-in.
   - **Connect their computer**: a download for macOS, Linux or Windows,
     and the command that runs it.
6. Send the password and the script over two separate channels you trust,
   then close the page. The script contains no secret.
7. The person runs the script and signs in
   ([Connect Claude Code](connect-claude-code.md)).

Check it worked: the trail has an `(account add)` row naming the username
and its groups.

```sh
sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool "(account add)" -limit 5
```

After the person's first sign-in and call, they appear under **People**,
**Seen on the gateway**, with their subject.

To hand the script to an existing account, open the person's page and
choose **Connect a computer**. A front of your own gets the same script
from the management API: `GET /v1/connect/script?os=linux&username=NAME`
on the operator socket ([Writing a Gatte front](../admin-api.md)).

## Give someone a new password

1. Open the person's page from **People**.
2. Choose **Reset password**. The result page shows a new one-time
   password; the previous one stops working once the IdP reloads its users
   file.
3. Hand it over as in [Add a person](#add-a-person), step 6.

The trail records it as `(account reset password)`, without the password.

## Change someone's groups

1. Open the person's page.
2. Under **Groups**, tick or untick groups, then choose **Save groups**.
   Only groups of `[group_to_role]` can be given.

The change takes effect at their next sign-in, once the IdP reloads its
users file. A token already issued keeps the groups it was issued with
until it expires, and Claude Code keeps the tool list it fetched until the
analyst reconnects (`/mcp`). If a person must lose access now, block their
subject as well ([Respond to an incident](respond-to-an-incident.md)). The
trail records the change as `(account groups)`.

To change what a role grants, rather than who has it, see
[Change roles, groups and quota](change-roles-and-quota.md).

## Disable an account

1. Open the person's page.
2. Under **Account**, choose **Disable**.

The IdP refuses their next sign-in once it reloads its users file. Disable
does not end a session already open or a token already issued: to cut
those off at the gateway, block the subject in **Access**, or use
**Offboard**, which does both. **Enable** undoes it. The trail records
`(account disable)` and `(account enable)`.

## When someone leaves: Offboard

**Offboard** blocks the person's subject in the gateway, then disables
their account, in one call.

1. Open the person's page.
2. Under **Offboard**, choose **Their subject** from the list of subjects
   the audit trail has seen, or type it under **Or type it**, exactly as
   the audit trail shows it. Pick it yourself: the names beside the
   subjects are what the IdP said, for reading only. Choose **None** only
   if the person never used the gateway; then no block is placed.
3. In **Reason**, write who is acting and why. It goes in the trail.
4. Choose **Offboard**.
5. Read **Still to do by hand** on the result page, and do each item. It
   always includes revoking their sessions at the IdP
   ([below](#revoke-their-sessions-at-the-identity-provider)).

The trail gets three rows: `(access block)`, `(account disable)` and a
summary `(account offboard)`.

If the block cannot be placed, nothing changes and the page says why. If
the block took effect and the account could not be disabled, the page
shows the warning `offboard_incomplete`: the block is in force; disable the
account by hand. Offboarding someone already offboarded changes nothing and
records nothing.

Check it worked:

```sh
sudo -u mcpgw mcp-gateway access list -config "$CFG"
```

The subject is listed, and the person's page shows **Disabled**.

## Revoke their sessions at the identity provider

Do this by hand, with the IdP's own administration tools. Gatte cannot
reach the IdP's sessions:

- disabling the account stops new sign-ins, but a session already open at
  the IdP and a refresh token already issued last until they expire;
- every other application behind the same IdP still accepts them;
- the gateway block refuses the subject at Gatte whatever token it holds,
  and nowhere else.

Short token lifetimes limit the window. The reference Authelia
configuration in `deploy/vm/` issues 10-minute access tokens and 8-hour
refresh tokens.

## Delete an account

Offboard first: deleting ends no session and places no block.

1. Open the person's page.
2. Under **Delete the account**, tick the confirmation, then choose
   **Delete**.

The account leaves the IdP's users file once the IdP reloads it. The audit
trail keeps every row the person wrote, and a gateway block on their
subject stays. The trail records `(account delete)`.

Give a new person a new username. The IdP may issue the same subject again
to an account created later with the same username (Authelia keeps it per
username); that account would inherit a block on it, and the trail would
read both people as one.

## Let a group manage accounts without sudo

By default only root edits accounts. You can delegate it to a group, here
`gatte-accounts`.

1. As root, create the group and add its members:

   ```sh
   sudo groupadd --system gatte-accounts
   sudo usermod -aG gatte-accounts ana
   ```

2. As root, install the socket drop-in from `examples/systemd/`, which sets
   `SocketGroup=gatte-accounts` and `SocketMode=0660`:

   ```sh
   sudo install -d /etc/systemd/system/mcp-gateway-admin-accounts.socket.d
   sudo install -m 0644 examples/systemd/mcp-gateway-admin-accounts.socket.d/group.conf \
     /etc/systemd/system/mcp-gateway-admin-accounts.socket.d/
   ```

3. Set the same group in `config.toml`:

   ```toml
   [admin]
   account_group = "gatte-accounts"
   ```

   The accounts backend refuses to start when the socket's group and
   `account_group` disagree.

4. Apply the socket change:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl restart mcp-gateway-admin-accounts.socket
   ```

5. A member runs the console as themself, without `sudo`:

   ```sh
   mcp-gateway ui -manage-users
   ```

What a delegated member cannot do:

- change an account that has no group, or any group outside
  `[group_to_role]` (the answer is `account_not_managed`): every other IdP
  account stays root's;
- **Offboard** with a subject, unless they are also in
  `[admin] operator_group`, because blocking is an operator's action (the
  answer is `forbidden_peer`, and nothing changes). They can offboard with
  **None** as the subject and ask an operator to block it.

Check it worked: the member's console shows the account buttons on
**People**, and each change they make is a row naming their login account,
tagged `[ui]`.
