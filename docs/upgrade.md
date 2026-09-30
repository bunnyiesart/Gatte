# Upgrading Gatte, and rolling back

An upgrade is a binary swap under a planned maintenance, with a backup taken
first and checked before and after. Gatte does not update itself and nothing
here runs on a schedule except the backup timer, if you installed it
(`examples/systemd/README.md`). The commands are `design/adr/0045`.

The examples use the paths of `README.md` ("Quick start") and a serve unit
called `mcp-gateway.service`; on FreeBSD the service is `mcp_gateway`
(`service mcp_gateway stop`). Operator commands run as the service account,
`mcpgw`; `check` runs as root, because only root reads the signing key's and
the age key's metadata. Run as root, `check`, `backup` and `restore` become
the owner of the database's directory before they open the database, as
`sign` does, so none of them leaves a root-owned file beside it.

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

## What changes, and what cannot go back

`mcp-gateway version` prints the build and the database schema it writes:

```text
mcp-gateway v1.4.0 (database schema 1)
```

The database records the schema of the newest binary that opened it. A
binary opens a file at its own schema or older, migrating an older one at
start. It refuses a newer one, at `serve` and at every operator command,
and changes nothing:

```text
serve: store: the database schema is newer than this binary: the file is at schema 2 and this binary knows up to 1. ...
```

So when the new binary's schema is higher, the old binary cannot run on the
database once the new one has started: the way back is the backup taken in
step 2. When the two schemas are equal, the old binary still opens it.
Binaries before the schema guard (30 Sep 2026) do not check at all: do not
run one on a file a newer binary has opened.

## 1. Announce the maintenance

```sh
sudo -u mcpgw mcp-gateway maintenance on -config "$CFG" \
  -message "Gatte is being upgraded; back in about 15 minutes" -until 30m
```

Give open sessions a few minutes: text results and `gatte.status` carry the
notice from the next call on.

## 2. Back up

```sh
sudo install -d -m 0700 -o mcpgw -g mcpgw /var/backups/mcp-gateway
sudo -u mcpgw mcp-gateway backup -config "$CFG" -out /var/backups/mcp-gateway
```

The first time you upgrade to a binary that has `backup`, the installed one
does not: run the new binary from where you unpacked it
(`sudo -u mcpgw ./mcp-gateway.new backup ...`). `backup` never migrates or
stamps the live database, so the new binary taking the copy changes nothing
under the old serve.

It prints the copy's path, its sha256 and the audit trail's head. Keep both
where this host cannot write (the ticket of the change is fine): `restore
-expect-head` takes the head back. It also lists what is NOT in the copy,
with this configuration's paths: the configuration file, the encrypted
vault, the age key, the signing key, the IdP. An upgrade changes none of
them, so a copy of each from before is enough; take one now if you have
none.

A backup that exits 1 kept a copy whose audit chain is broken or whose
registry has an invalid signature. Stop and read `audit -verify` and
`upstream list` before going on: `restore` would refuse that copy.

## 3. Stop serve and swap the binary

```sh
sudo systemctl stop mcp-gateway          # FreeBSD: sudo service mcp_gateway stop
sudo systemctl stop mcp-gateway-admin.socket mcp-gateway-admin.service   # if installed
sudo cp /usr/local/bin/mcp-gateway /usr/local/bin/mcp-gateway.previous
sudo install -m 0755 mcp-gateway.new /usr/local/bin/mcp-gateway
```

Keep the previous binary until the upgrade is signed off; it is the first
half of a rollback.

## 4. Verify the binary is the one you built

Take the sha256 on the machine that built it (`make build`, then
`sha256sum bin/mcp-gateway`) and compare it on the host:

```sh
sha256sum /usr/local/bin/mcp-gateway     # FreeBSD: sha256 /usr/local/bin/mcp-gateway
mcp-gateway version
```

The version names the build and, when built from a checkout, the source
revision. A different hash is a different binary: stop here.

## 5. Check, offline, with the new binary

```sh
sudo mcp-gateway check -config "$CFG" -user mcpgw -online
```

Every FAIL line says how to fix it; exit 0 means none failed (warnings are
allowed). It reads the database read-only, so it runs before the new binary
has migrated anything; a file at an older schema is read through a private,
migrated copy that is then removed. A newer release may add a check; a FAIL here is
cheaper than a serve that does not start.

## 6. Start serve

```sh
sudo systemctl start mcp-gateway         # FreeBSD: sudo service mcp_gateway start
sudo journalctl -u mcp-gateway -n 50     # "mcp-gateway: starting" with version and schema
sudo -u mcpgw mcp-gateway audit -config "$CFG" -since 10m
```

The first row of every boot is `(gateway)` `(boot)` with the reason
`boot: mcp-gateway VERSION, schema N`, in the trail and in the SIEM copy:
the upgrade is on the record with the build that did it. Read the startup
summary (backends connected, tools servable per role) and approve any tool
the new build reports as changed only after reading its diff.

## 7. Check again, then end the maintenance

```sh
sudo mcp-gateway check -config "$CFG" -user mcpgw
sudo systemctl start mcp-gateway-admin.socket    # if installed
sudo -u mcpgw mcp-gateway maintenance off -config "$CFG"
```

## Rollback

When the new build misbehaves after it has started:

```sh
sudo -u mcpgw mcp-gateway maintenance on -config "$CFG" -message "Gatte is being rolled back"
sudo systemctl stop mcp-gateway mcp-gateway-admin.socket mcp-gateway-admin.service
sudo install -m 0755 /usr/local/bin/mcp-gateway.previous /usr/local/bin/mcp-gateway
mcp-gateway version                                   # the old schema number
sudo -u mcpgw mcp-gateway restore -config "$CFG" \
  -in /var/backups/mcp-gateway/mcp-gateway-YYYYMMDDTHHMMSSZ.db -expect-head HEAD
sudo mcp-gateway check -config "$CFG" -user mcpgw
sudo systemctl start mcp-gateway
sudo -u mcpgw mcp-gateway maintenance off -config "$CFG"
```

`restore` is needed when the new binary's schema was higher, and is the
safe choice when unsure: the old binary refuses the file otherwise.
`restore` refuses, and changes nothing, unless:

- nothing is listening on `listen` (serve is stopped);
- the file passes SQLite's integrity check;
- its schema is one this binary knows;
- its audit chain verifies, and ends at `-expect-head` when given;
- no registry entry in it carries a signature that fails against this
  configuration's `signer.trusted_keys`.

It keeps the database it replaced as `DB.pre-restore-TIMESTAMP` beside it
and writes a `(restore)` operator row naming the backup's sha256 and head,
to the trail and to the SIEM copy. Run it as the service account or as
root: as root it opens `-in` first (a copy brought back as root's is fine)
and then becomes the owner of the database's directory, so every file it
writes there is the service's.

What a restore costs, said plainly: every row written after the backup is
gone from the restored trail (approvals, blocks, maintenance, the calls
themselves). The SIEM copy still holds them, and its chain now forks at the
backup's head: the lines written after the backup and the `(restore)` row
both link to it. `deploy/gatte-anchor-verify.sh` then fails with two
fragment heads (its message reads as a restart or as missing lines); one
head is the `(restore)` row, which is the explanation, and the anchor to
compare from then on is the head after it. Approvals and blocks made during
the upgrade window have to be made again.

## Disaster recovery on a new host

Install the binary and the files the backup does not hold (configuration,
vault, age key, signing key) from their own copies, with the owners and
modes of `README.md` ("Who owns what"), copy the backup into
`/var/backups/mcp-gateway` as the service account's, then:

```sh
sudo -u mcpgw mcp-gateway restore -config "$CFG" -in /var/backups/mcp-gateway/mcp-gateway-YYYYMMDDTHHMMSSZ.db -expect-head HEAD
sudo mcp-gateway check -config "$CFG" -user mcpgw -online
```

A registry entry whose signature fails on the new host means the
configuration's trusted keys are not the ones the entries were signed with:
restore the configuration file from the same date, not a newer one.
