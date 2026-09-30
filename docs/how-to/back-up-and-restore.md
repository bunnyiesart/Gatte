# Back up and restore

This page is for operators who keep copies of Gatte's database, put one
back, and rehearse doing so. `backup` takes a checked copy while `serve`
runs; `restore` puts a copy back with `serve` stopped, and refuses one it
cannot verify (`design/adr/0045`).

The examples use `CFG=/usr/local/etc/mcp-gateway/config.toml`, the service
account `mcpgw`, and `/var/backups/mcp-gateway` for the copies. To move the
whole gateway to a new host, see
[Upgrading Gatte, and rolling back](../upgrade.md#disaster-recovery-on-a-new-host).

## Take a copy by hand

1. As root, create the backup directory, the service account's and private:

   ```sh
   sudo install -d -m 0700 -o mcpgw -g mcpgw /var/backups/mcp-gateway
   ```

2. As the service account, take the copy. `serve` may keep running:

   ```sh
   sudo -u mcpgw mcp-gateway backup -config "$CFG" -out /var/backups/mcp-gateway -keep 14
   ```

   With a directory, the copy is named `mcp-gateway-YYYYMMDDTHHMMSSZ.db`,
   mode `0600`. `-keep 14` then removes all but the newest 14 files with
   exactly that name pattern, and nothing else. `-out` can also name a new
   file. `-json` prints the result as JSON.

3. Keep the two values it prints, the copy's `sha256` and the audit trail's
   `head`, somewhere this host cannot write, for example the change ticket.
   `restore -expect-head` takes the head back later.

Check it worked: the command exits 0 and prints the copy's path, its
sha256, `schema`, `audit trail: N record(s), chain intact, head ...` and
`registry: N entries: N signed by a trusted key`.

Exit 1 means a copy was written but its audit chain is broken or a registry
entry's signature fails: it is kept as evidence, and `restore` would refuse
it. Read `audit -verify` and `upstream list` before relying on any copy.

`backup` never migrates the live database, so a new binary can take the
copy before an upgrade while the old `serve` still runs. Run as root, it
first becomes the owner of the database's directory, so it leaves no
root-owned file there.

## Take one every day

The systemd units in `examples/systemd/` run the same command once a day.

1. As root, create the directory (step 1 above) and install the units:

   ```sh
   sudo install -m 0644 examples/systemd/mcp-gateway-backup.service \
     examples/systemd/mcp-gateway-backup.timer /etc/systemd/system/
   ```

2. Edit `ExecStart=` in `/etc/systemd/system/mcp-gateway-backup.service`
   if your configuration is not at `/etc/mcp-gateway/config.toml`, the path
   the example units use.

3. Enable the timer, and take one copy now to see it work:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now mcp-gateway-backup.timer
   sudo systemctl start mcp-gateway-backup.service
   sudo journalctl -u mcp-gateway-backup
   ```

The timer runs at 03:15 with up to 15 minutes of random delay, and catches
up after a stopped host (`Persistent=true`). The unit keeps the newest 14
copies. It runs without network: a copy on the same disk survives a bad
upgrade, not a lost disk, so shipping the copies off the host is a job of
yours. Without systemd, schedule the same `backup` command with your
system's scheduler.

Check it worked: `systemctl list-timers mcp-gateway-backup.timer` shows the
next run, and the journal shows the sha256, the audit head and what is not
in the copy.

## What the copy does not hold

The copy is the database and nothing else: the registry, signatures, tool
approvals, blocks, maintenance and the audit trail. `backup` prints the
paths of what it does not hold, from your configuration:

- the configuration file (roles, trusted keys);
- the encrypted vault;
- the age key that decrypts it;
- the signing key;
- the identity provider's accounts, keys and configuration;
- the SIEM copy of the trail;
- the reverse proxy's TLS certificates and configuration;
- the container images of `oci` backends;
- the `[connect] ca_file`, when set.

Back them up separately. The age key and the signing key are secrets: keep
their copies offline, apart from the database copies.

## Restore a copy

You need: the copy, the head `backup` printed for it, and a configuration
file from the same date. `restore` checks signatures against this
configuration's `trusted_keys`, so a newer file with the old key already
removed refuses legitimate entries.

1. If `serve` is running, announce it
   ([Plan maintenance](plan-maintenance.md#stop-serve-itself)).
2. As root, stop `serve` and both management API sockets. `restore` detects
   a running `serve` by its `listen` address only; a socket-activated
   `admin` with the database open is not detected:

   ```sh
   sudo systemctl stop mcp-gateway mcp-gateway-admin.socket mcp-gateway-admin.service \
     mcp-gateway-admin-accounts.socket mcp-gateway-admin-accounts.service
   ```

3. Compare the file's hash with the `sha256` you kept:

   ```sh
   sha256sum /var/backups/mcp-gateway/mcp-gateway-YYYYMMDDTHHMMSSZ.db   # FreeBSD: sha256
   ```

4. Restore, giving the head you kept:

   ```sh
   sudo -u mcpgw mcp-gateway restore -config "$CFG" \
     -in /var/backups/mcp-gateway/mcp-gateway-YYYYMMDDTHHMMSSZ.db -expect-head HEAD
   ```

   It refuses, and changes nothing, unless nothing listens on `listen`,
   the file passes SQLite's integrity check, its schema and database objects
   are exactly what this binary creates, its audit chain verifies and ends
   at `-expect-head`, and no registry entry in it carries a signature that
   fails against `trusted_keys`. Without `-expect-head` the chain only
   proves the trail agrees with itself, and `restore` says so.

5. As root, check the host, then start everything again:

   ```sh
   sudo mcp-gateway check -config "$CFG" -user mcpgw
   sudo systemctl start mcp-gateway mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket
   ```

6. End the maintenance, if the restored database has one
   (`maintenance list`). A maintenance you started after the copy was taken
   is not in it.

Check it worked: `restore` prints `Restored ...` with the copy's sha256 and
head, and names the database it replaced, kept beside it as
`DB.pre-restore-YYYYMMDDTHHMMSSZ`. The restored trail ends with a
`(restore)` row naming the copy's sha256 and head.

What a restore costs: every row written after the copy was taken is gone
from the restored database. Blocks, approvals and maintenance made since
are gone with them: place the blocks again first. The SIEM copy still holds
those rows, and its chain now forks at the copy's head, because the
`(restore)` row links to it too; `deploy/gatte-anchor-verify.sh` reports
two fragment heads. From then on, the head to compare is the one after the
`(restore)` row.

## Rehearse a restore

A copy nobody has restored is a hope. The drill restores the newest copy
into a scratch database with a configuration of its own, while the live
gateway keeps running. It proves the copy verifies against your trusted
keys; it does not test the vault, age key or signing key copies.

1. As root, make a scratch directory for the service account:

   ```sh
   sudo install -d -m 0700 -o mcpgw -g mcpgw /var/tmp/gatte-drill /var/tmp/gatte-drill/db
   ```

2. As root, copy the configuration to `/var/tmp/gatte-drill/config.toml`,
   readable by `mcpgw`, and change three things in the copy:

   ```toml
   listen   = "127.0.0.1:18080"                           # any free loopback port
   database = "/var/tmp/gatte-drill/db/mcp-gateway.db"

   [audit.siem]
   path  = "/var/tmp/gatte-drill/audit.jsonl"
   chain = "gatte-drill"
   ```

   Also remove the `[telemetry]` `address` line, if set. `restore` refuses
   while something listens on `listen`, and the live `serve` holds the
   live port. `restore` writes its `(restore)` row to the configured SIEM
   copy and GELF: left pointing at the live ones, the drill would add a
   line to your production chain.

3. Restore the copy, with its head:

   ```sh
   sudo -u mcpgw mcp-gateway restore -config /var/tmp/gatte-drill/config.toml \
     -in /var/backups/mcp-gateway/mcp-gateway-YYYYMMDDTHHMMSSZ.db -expect-head HEAD
   ```

4. Read the restored copy:

   ```sh
   sudo -u mcpgw mcp-gateway audit -verify -config /var/tmp/gatte-drill/config.toml
   sudo -u mcpgw mcp-gateway upstream list -config /var/tmp/gatte-drill/config.toml
   ```

   The chain is intact, with one more record than the copy (the drill's
   `(restore)` row), and every entry shows `yes` in SIGNED.

5. Test the secrets' copies too: decrypt your off-host copy of the vault
   with your offline copy of the age key, and discard the output:

   ```sh
   env SOPS_AGE_KEY_FILE=/path/to/age.key.copy sops decrypt /path/to/secrets.enc.json.copy >/dev/null
   ```

6. As root, remove the scratch directory:

   ```sh
   sudo rm -r /var/tmp/gatte-drill
   ```

Write the date, the copy and the result in your operations log.
