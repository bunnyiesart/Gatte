# Add a backend

This guide is for an operator putting a new MCP server behind a running
Gatte: as a container (`-transport oci`) or as a local process
(`-transport stdio`), with its credentials in the vault, signed, its tools
approved and granted to a role. For what a backend has to be, see
[`examples/README.md`](../../examples/README.md); for why entries are
signed, see [Quarantine and signed backends](../explanation/quarantine-and-signing.md).

You need:

- a host set up as in the README's [Quick start](../../README.md#quick-start),
  with `serve` running;
- root on it, and the service account `mcpgw`;
- the backend: a container image, or a program installed on the host, that
  speaks MCP over stdio and takes its settings from arguments and
  environment variables;
- the names of the variables it reads its credentials from.

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

The examples use `edr` for a container backend and `logsearch` for a local
process. The backend's name becomes the prefix of each of its tools
(`edr.isolate_host`) and may not contain `.`.

## Choose the transport

- **`oci`**, where rootless podman runs for the service account. The
  backend runs in a container with a read-only root, no capabilities, a
  non-root uid and no network unless the entry grants one
  (`design/adr/0028`, `0034`). Use it for anything third-party.
- **`stdio`**, for a program you would trust with the service account. It
  runs as `mcpgw`, the same user that holds the vault. An `stdio` entry
  with `-env` credentials is refused unless the configuration sets
  `[upstreams] allow_credentialed_stdio = true`, and every boot then logs a
  WARN. That key needs a restart of `serve`.
- **`http`**, for a REST API the gateway calls itself, one tool per
  operation of its OpenAPI document, the credential injected server-side.
  This page walks the two MCP transports; for `-transport http` the flags
  (`-url`, `-openapi`, `-auth-kind`, `-auth-name`) are in the
  [CLI reference](../reference/cli.md#upstream-register), and steps 3 to 5
  below apply unchanged, plus a `tool clear` for each sensitive tool.

## 1. Put the credentials in the vault

1. As root, open the vault in `sops` and add one key per variable the
   backend reads, with its value:

   ```sh
   sudo env SOPS_AGE_KEY_FILE=/usr/local/etc/mcp-gateway/age.key \
       sops /usr/local/etc/mcp-gateway/secrets.enc.json
   ```

   Give every credential a name no other backend uses, such as
   `EDR_API_KEY` rather than `API_KEY`: the vault has one namespace, and two
   backends that declare the same name receive the same value
   (`design/adr/0018`). Gatte reports a shared name at boot and does not
   refuse it.

2. As root, put the file's group and mode back:

   ```sh
   sudo chgrp mcpgw /usr/local/etc/mcp-gateway/secrets.enc.json
   sudo chmod 0640  /usr/local/etc/mcp-gateway/secrets.enc.json
   ```

The running gateway re-reads the vault file when it changes
(`design/adr/0023`): the new backend gets the value when it is first
dialled, with no restart. A name the vault does not hold keeps the backend
down, with `resolve credential "NAME": vault: secret not found` in the
log.

## 2. Register the backend

Registering writes the entry to the registry. It does not sign it, and
nothing is served yet.

### A container backend

1. Put the image in the service account's own image store. Gatte runs
   podman with `--pull=never`: an image the account does not have is not
   fetched, and the backend fails with "this host does not have that
   image".

   ```sh
   sudo -u mcpgw podman pull registry.example.org/edr-mcp:1.4
   ```

2. Print the image's digest:

   ```sh
   sudo -u mcpgw podman inspect --format '{{index .RepoDigests 0}}' registry.example.org/edr-mcp:1.4
   ```

3. As the service account, register it by that digest:

   ```sh
   sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport oci \
     -image registry.example.org/edr-mcp@sha256:<64 hex> \
     -arg --network=slirp4netns \
     -env EDR_API_KEY
   ```

   - `-image` must be `NAME@sha256:` and 64 hex characters. A tag is
     refused, because a tag can be repointed at other bytes and the
     signature covers the image.
   - `-arg` carries podman flags, and they are signed. Leave out
     `--network` for no network; it accepts `none`, `slirp4netns`, `pasta`
     or a podman network name, and refuses `host`, `private`,
     `container:*` and `ns:*`. Which hosts a networked backend reaches is
     the host firewall's job (`design/adr/0033`): `upstream list -json`
     gives each entry's `network` for the allowlist.

### A local process

1. Install the program where the service account can run it and cannot
   write it, for example root-owned under `/usr/local/bin`. The signature
   covers the command's path and arguments, not the file's contents:
   whoever can replace the file changes what runs without breaking the
   signature, and only a changed tool definition would show it.

2. As the service account, register it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name logsearch -transport stdio \
     -command /usr/local/bin/logsearch-mcp \
     -arg --url -arg https://logs.example.internal \
     -env LOGSEARCH_API_TOKEN
   ```

   `-arg` is repeatable and stored in plaintext, so it carries settings,
   never secrets. To change what an `stdio` entry runs later, you
   deregister it and register it again, which puts its tools back in
   review.

### On both transports

- `-env` takes names only. `-env NAME=value` is refused, and the value is
  not echoed.
- Names whose value is code or chooses where code comes from (`LD_*`,
  `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `PATH`, `HOME`, ...) are refused.
- The backend receives its arguments, `PATH` and `HOME` from the gateway's
  environment, and the variables it declared. Nothing else is inherited,
  and the analyst's token is never passed on.

`register` ends with `This entry is NOT SIGNED` and the command to sign it.

## 3. Sign the entry

1. As root, sign it:

   ```sh
   sudo mcp-gateway sign -config "$CFG" edr
   ```

   `sign` prints the fields its signature covers (transport, command or
   image and arguments, variable names). Read them: this is what you vouch
   for. It reads the key as root, then becomes the database directory's
   owner before opening the database.

2. Check it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream list -config "$CFG"
   ```

   The entry shows `yes` in `SIGNED`.

Within one `quarantine.refresh_interval` (default `5m`) the running gateway
dials the backend and reads its tools. The log says `new tool observed; it
is pending and not served until an operator approves it` for each one, and
`backend is live`.

## 4. Review and approve its tools

As the service account, review every waiting tool of the backend and
approve the set you read:

```sh
sudo -u mcpgw mcp-gateway tool review  -config "$CFG" -server edr
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" -server edr -manifest SHA256
```

`SHA256` is the value on the `manifest` line that `tool review` printed.
To approve some tools and leave others out, approve them one at a time
instead. [Review and approve tools](review-and-approve-tools.md) covers
both, the web console's buttons and what the warnings mean.

A tool you never approve is not on the gateway. That is how you keep one
tool of a backend out of reach without changing the backend.

## 5. Grant the tools in a role

**Approving is not granting.** An approved tool is servable; it is callable
only by a role that grants it. `tool review` shows, for each tool, the roles
that can call it once approved, and `(no role -- servable, callable by
nobody)` for a tool no role grants.

1. As root, edit `config.toml` and grant the tools, by exact name in
   `tools` or per backend in `[role.grants]`:

   ```toml
   [[role]]
   name  = "ir-lead"
   tools = ["edr.get_host", "edr.isolate_host"]

   # or, for tools named as the backend names them:
   #   [role.grants]
   #   edr = ["get_host", "isolate_host"]
   ```

   Names in `tools` are namespaced (`edr.get_host`) and match exactly. A
   name without the prefix (`get_host`) is refused when the file loads; a
   namespaced name the backend does not advertise (`edr.get_hots`) loads
   and grants nothing, so take names from `tool list`. `[role.grants]` also
   accepts `["*"]` for every tool of that backend, now and later; read
   what that costs in `config.example.toml` ("O QUE `["*"]` CUSTA") before
   you write one.

2. As the service account, apply it:

   ```sh
   sudo -u mcpgw mcp-gateway reload -config "$CFG"
   ```

   `reload` prints, per role, each tool gained (`+`) and lost, and records
   one `(config reload)` row. [Change roles, groups and quota](change-roles-and-quota.md)
   has the details.

## Check it worked

- `sudo -u mcpgw mcp-gateway upstream list -config "$CFG"` shows the entry
  with `yes` in `SIGNED`.
- `sudo -u mcpgw mcp-gateway tool list -config "$CFG" -server edr` shows
  each tool you approved as `approved`, `USABLE` `yes`.
- The `reload` output names the role that gained each tool.
- An analyst in that role sees the tools after reconnecting (`/mcp` in
  Claude Code): an MCP client reads its tool list once, when it connects.

## Remove a backend

As the service account:

```sh
sudo -u mcpgw mcp-gateway upstream deregister -config "$CFG" edr
```

It removes the entry, its signature and its tools' quarantine state:
approvals are forgotten, and a backend registered later under the same
name starts from pending. The running gateway stops serving it within one
`quarantine.refresh_interval`. Remove its grants from `config.toml` and
`reload`, or every boot warns about grants that reach nothing. Remove its credentials from the vault if nothing else
uses them.
