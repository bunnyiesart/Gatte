# Rotate credentials and keys

This page is for operators rotating the secrets Gatte holds: a backend's
credential in the vault, the Ed25519 signing key, and the age key that
decrypts the vault. The identity provider's secrets are out of scope
([below](#what-this-page-does-not-cover)).

The examples use the Quick start's paths:
`CFG=/usr/local/etc/mcp-gateway/config.toml`, the files under
`/usr/local/etc/mcp-gateway/`, and the service account `mcpgw`. On FreeBSD,
replace `systemctl restart mcp-gateway` with `service mcp_gateway restart`.

## A backend's credential

There is no `rotate` command, on purpose: Gatte only reads the vault, and
the edit is `sops` (`deploy/freebsd-jail.md`, "Rotating credentials").

You need: the new value, issued by the provider. Keep the old one valid
until step 4.

1. As root, edit the vault. `sops` needs the age key to open it:

   ```sh
   sudo env SOPS_AGE_KEY_FILE=/usr/local/etc/mcp-gateway/age.key \
     sops /usr/local/etc/mcp-gateway/secrets.enc.json
   ```

   Change the value of the variable, for example `EDR_CLIENT_SECRET`, save
   and quit.

2. As root, give the file back its group and mode, in case `sops` wrote it
   anew:

   ```sh
   sudo chgrp mcpgw /usr/local/etc/mcp-gateway/secrets.enc.json
   sudo chmod 0640  /usr/local/etc/mcp-gateway/secrets.enc.json
   ```

3. As the service account, re-dial the backend that uses it. A connected
   backend keeps the value it was started with until it is dialled again:

   ```sh
   sudo -u mcpgw mcp-gateway upstream redial -config "$CFG" edr
   ```

   The running gateway drops that backend's connection and dials it again
   with the vault as it is now. Its calls are answered as reconnecting until
   the new process has listed its tools; the other backends are not
   touched. The command waits for `serve`'s answer (`-wait`, default 2
   minutes) and exits 0 when applied, 1 when refused or still pending, and
   2 when `serve` is not running on this database. It refuses to run as
   root.

4. Revoke the old value at the provider.

Check it worked: `upstream redial` prints "edr was dropped and dialled
again, with the vault as it is now, and it is live.", and the trail has the
row:

```sh
sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool "(upstream redial)" -limit 1
```

Its reason ends `was connected: true; live after the round: true`. Until a
rotated credential is re-dialled, `serve` logs a warning once per
`quarantine.refresh_interval` naming the backend and the variable ("a
credential was rotated in the vault but the connected upstream is STILL
USING THE OLD VALUE"); it stops after the redial. `check` also confirms the
vault still holds every credential name a backend declares:

```sh
sudo mcp-gateway check -config "$CFG" -user mcpgw
```

A restart of `serve` re-dials every backend at once, and works too. A
backend that crashes and is re-dialled also picks up the new value, without
anyone asking.

## The signing key

`signer.trusted_keys` is not reloadable, so rotating the signing key takes
two restarts of `serve`. Between them, every entry is re-signed with the new
key (`design/adr/0006`, `0044`).

You need: root, and a moment when no one is registering backends.

1. As root, create the new key at a new path. It prints the two
   configuration lines:

   ```sh
   sudo mcp-gateway sign -generate-key -out /usr/local/etc/mcp-gateway/signing-2.key
   ```

2. Add the new public key to `signer.trusted_keys` **beside** the old one:

   ```toml
   [signer]
   key_file = "/usr/local/etc/mcp-gateway/signing.key"
   trusted_keys = [
     "OLD-PUBLIC-KEY-LINE",
     "NEW-PUBLIC-KEY-LINE-FROM-STEP-1",
   ]
   ```

3. Restart `serve`, so it trusts both keys:

   ```sh
   sudo systemctl restart mcp-gateway
   ```

   If you skip this restart, the entries you sign in step 6 are signed by a
   key the running gateway does not trust, and with `require_signed` (the
   default) they stop being served.

4. Point `signer.key_file` at the new key. Only `sign` reads it, on every
   run, so this needs no restart:

   ```toml
   key_file = "/usr/local/etc/mcp-gateway/signing-2.key"
   ```

5. Print the plan. Nothing is written:

   ```sh
   sudo mcp-gateway sign -config "$CFG" -all -dry-run
   ```

   Each entry signed by the old key shows as "was signed by another key",
   with the fields its signature covers; the output ends with the plan's
   manifest and the command that signs it. Read every entry. One shown as
   `INVALID` was changed after it was signed: find out why before you sign
   it.

6. Sign exactly that plan, with the hex the dry run printed:

   ```sh
   sudo mcp-gateway sign -config "$CFG" -all -manifest HEX
   ```

   Nothing is signed if an entry joined, left or changed since the dry run.

7. Check that every entry verifies:

   ```sh
   sudo -u mcpgw mcp-gateway upstream list -config "$CFG"
   ```

   SIGNED shows `yes` for every entry.

8. Remove the old key's line from `trusted_keys`. Before restarting, check
   that every entry verifies against the file as it now stands, then
   restart:

   ```sh
   sudo mcp-gateway check -config "$CFG" -user mcpgw
   sudo systemctl restart mcp-gateway
   ```

9. Delete the old key file (`shred -u` on Linux, `rm -P` on FreeBSD), and
   keep an offline copy of the new one, apart from the database backups.

`sign` tells you when it replaced a signature made by a different key. If
you did not just rotate, find out whose key that was.

## The age key

The age key decrypts the vault, so whoever holds it and a copy of
`secrets.enc.json` holds every backend credential. Gatte has no command for
this rotation; `sops` re-encrypts the vault to the new key. `[vault]` is not
reloadable, so it takes one restart of `serve`.

You need: `sops` and `age` on the host, and root.

1. As root, create the new identity and give it to the service account,
   owner-only:

   ```sh
   sudo age-keygen -o /usr/local/etc/mcp-gateway/age-2.key
   sudo chown mcpgw:mcpgw /usr/local/etc/mcp-gateway/age-2.key
   sudo chmod 0600 /usr/local/etc/mcp-gateway/age-2.key
   ```

2. As root, add the new key as a recipient of the vault, keeping the old
   one, so the running `serve` can still decrypt it:

   ```sh
   R_OLD=$(sudo age-keygen -y /usr/local/etc/mcp-gateway/age.key)
   R_NEW=$(sudo age-keygen -y /usr/local/etc/mcp-gateway/age-2.key)
   sudo env SOPS_AGE_KEY_FILE=/usr/local/etc/mcp-gateway/age.key \
     sops rotate -i --add-age "$R_NEW" /usr/local/etc/mcp-gateway/secrets.enc.json
   sudo chgrp mcpgw /usr/local/etc/mcp-gateway/secrets.enc.json
   sudo chmod 0640  /usr/local/etc/mcp-gateway/secrets.enc.json
   ```

   `sops rotate` also replaces the file's data key. The values do not
   change, so no backend needs a redial.

3. Point `vault.age_key_file` at the new key and restart `serve`:

   ```toml
   [vault]
   age_key_file = "/usr/local/etc/mcp-gateway/age-2.key"
   ```

   ```sh
   sudo systemctl restart mcp-gateway
   ```

4. As root, remove the old recipient, decrypting with the new key:

   ```sh
   sudo env SOPS_AGE_KEY_FILE=/usr/local/etc/mcp-gateway/age-2.key \
     sops rotate -i --rm-age "$R_OLD" /usr/local/etc/mcp-gateway/secrets.enc.json
   sudo chgrp mcpgw /usr/local/etc/mcp-gateway/secrets.enc.json
   sudo chmod 0640  /usr/local/etc/mcp-gateway/secrets.enc.json
   ```

5. Check that the old key no longer opens the vault, and that the gateway's
   does:

   ```sh
   sudo env SOPS_AGE_KEY_FILE=/usr/local/etc/mcp-gateway/age.key \
     sops decrypt /usr/local/etc/mcp-gateway/secrets.enc.json >/dev/null   # must fail
   sudo mcp-gateway check -config "$CFG" -user mcpgw
   ```

   `check` passes when the age key is the service account's and
   owner-only, and the vault decrypts and holds every credential name a
   backend declares. It prints no value.

6. Delete the old key (`shred -u` or `rm -P`). Replace your off-host copy of
   the vault with the new file and keep an offline copy of the new key:
   an older copy of the vault opens only with the old key.

If the old age key may have been exposed together with a copy of the
vault, rotating the key does not help on its own: whoever has both already
has every value. Rotate each credential too
([A backend's credential](#a-backends-credential)).

## What this page does not cover

- **The identity provider's secrets**: its OIDC client secrets, its token
  signing keys and the users' passwords. Rotate them with the IdP's own
  tools. Gatte holds none of them: it reads the IdP's published keys from
  its discovery document, and the connect script carries only a public
  client id.
- **The reverse proxy's TLS certificate and key**, which are the proxy's.
- **The `[connect] ca_file`**, a public certificate. If it changes, analysts
  run the connect script again to install the new one.
