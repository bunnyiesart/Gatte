# Putting a tool behind Gatte

Gatte fronts any program that speaks MCP over stdin/stdout. It does not
care whether that program searches a SIEM, queries an EDR or wraps a
script your team wrote last week: it spawns it, hands it the credentials
it declared, and decides per analyst which of its tools may be called.

This directory shows the same five steps for seven kinds of blue team
tooling, plus one file that combines them into a role policy.

| File | What it shows |
|---|---|
| [`base.toml`](base.toml) | Minimal configuration without roles. Every other file is appended to it. |
| [`siem-log-search.toml`](siem-log-search.toml) | SIEM / log search: search for detection engineers, a narrower subset for tier 1. |
| [`edr.toml`](edr.toml) | EDR: read access for tier 1, host isolation for the incident lead only. |
| [`threat-intel.toml`](threat-intel.toml) | Threat intel enrichment: the one place a per-backend wildcard is used, and why. |
| [`case-management.toml`](case-management.toml) | Case management / ticketing: read for tier 1, write for the incident lead. |
| [`vulnerability-scanner.toml`](vulnerability-scanner.toml) | Vulnerability scanner: keeping a scan-launching tool off the gateway by never approving it. |
| [`cloud-posture.toml`](cloud-posture.toml) | Cloud security posture: two credentials, and why their names must be unique. |
| [`byo-script.toml`](byo-script.toml) | Bring your own script: what the spawned process receives, and nothing else. |
| [`ioc_sweep.py`](ioc_sweep.py) | The script `byo-script.toml` registers: a runnable, standard-library-only MCP stdio server (newline-delimited JSON-RPC). |
| [`blue-team-roles.toml`](blue-team-roles.toml) | All of the above as one policy: tier1-analyst, detection-engineer, ir-lead, vuln-analyst, cloud-security, onboarding. |

**Every upstream name, command, flag, variable name and tool name in these
files is a placeholder.** None of them refers to a real MCP server. Where a
file says "for example, an MCP server for your SIEM", substitute whatever
server you actually run, and take tool names from `mcp-gateway tool list`
after the gateway has connected to it, never from memory.

## What an upstream has to be, in this build

- **A local process speaking MCP over stdio, or a container image that is
  one.** `-transport stdio` spawns a process; `-transport oci -image
  NAME@sha256:<digest>` runs it as an ephemeral `podman run --rm -i`
  container, pinned by digest because the signature covers the image.
  `-transport http` is recognised and refused at registration ("this build
  dials \"stdio\" and \"oci\" only"). A vendor-hosted MCP server reachable
  only over HTTP cannot be registered directly.
- **Configured by arguments and environment variables.** The process gets
  its registered arguments, `PATH` and `HOME` from the gateway's
  environment, and each variable it declared with `-env`, set from the
  vault. Nothing else is inherited, and the analyst's token is never
  passed on.
- **Trusted with the gateway's service account.** A stdio upstream runs as
  the same user as the gateway, which holds every credential; an oci
  upstream runs under the `[oci] user` uid in a container without the
  vault. See the security model in [`../README.md`](../README.md).

## The five steps

Set `CFG` to your configuration file. Every operator command takes
`-config`; the default is `mcp-gateway.toml` in the current directory.

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

The commands below are written bare. On a host laid out as in the
[quick start](../README.md#quick-start), run them as the gateway's service
account (`sudo -u mcpgw mcp-gateway ...`), except `sign`, which runs as root
because only root reads the signing key. `sign` reads the key as root and
then becomes the database directory's owner before it opens the database, so
it leaves no root-owned `-wal` or `-shm` file behind (`design/adr/0044`).

### 1. Register the upstream

```sh
mcp-gateway upstream register -config "$CFG" -name edr -transport stdio \
  -command /usr/local/bin/your-edr-mcp \
  -arg --api-url -arg https://edr.example.org \
  -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
```

- `-name` becomes the prefix of every tool the upstream advertises
  (`edr.isolate_host`). It may not contain `.`.
- `-arg` is repeatable and carries non-secret settings. Arguments are
  stored in the registry in plaintext and shown by `upstream list`.
- `-env` is repeatable and takes **names only**. `-env EDR_CLIENT_SECRET=...`
  is refused without echoing the value. A `-transport stdio` entry with
  `-env` is refused unless the configuration sets `[upstreams]
  allow_credentialed_stdio = true` (`base.toml` does, and every boot logs a
  WARN for it). Where podman exists, prefer `-transport oci`
  (`design/adr/0034`). Names whose value is code (`LD_PRELOAD`,
  `NODE_OPTIONS`, `PYTHONPATH`, ...) or that choose where code comes from
  (`PATH`, `HOME`) are refused on both transports.

`upstream list` shows what is registered and whether each entry is signed.
`upstream deregister NAME` removes an entry together with its signature and
quarantine state, so a later entry of the same name starts from scratch.

### 2. Put the credentials in the vault

The vault is one sops+age encrypted file holding a flat JSON object. Each
key is a variable name an upstream declared with `-env`:

```json
{
  "EDR_CLIENT_ID": "...",
  "EDR_CLIENT_SECRET": "..."
}
```

Encrypting a new file (the form the repository's own test fixture uses):

```sh
umask 077                          # the plaintext is never readable by anyone else
age-keygen -o age.key              # the identity; written owner-only
R=$(age-keygen -y age.key)         # its public recipient, age1...
vi secrets.json                    # the JSON object above, real values
sops --encrypt --age "$R" --input-type json --output-type json \
  secrets.json > secrets.enc.json
shred -u secrets.json              # FreeBSD and macOS: rm -P secrets.json
```

Point `vault.secrets_file` and `vault.age_key_file` at the results. The
service account must be able to read both, and it should be the only
account that reads `age.key`. Edit later with `sops` on the encrypted file,
which never writes the plaintext to disk; it needs the identity, and on the
paths the quick start uses that is (root, then restore `chgrp mcpgw` /
`chmod 0640`):

```sh
sudo env SOPS_AGE_KEY_FILE=/usr/local/etc/mcp-gateway/age.key \
    sops /usr/local/etc/mcp-gateway/secrets.enc.json
```

Only the operator's shell needs `SOPS_AGE_KEY_FILE`: `serve` sets it itself
from `vault.age_key_file`. Restart the gateway afterwards -- credentials are
read at dial time (`deploy/freebsd-jail.md`, "Rotating credentials").

Two rules that matter as soon as you have more than one tool:

- **Names must be unique across upstreams.** The vault has no per-upstream
  dimension, so two upstreams that both declare `API_KEY` receive the same
  value (`../design/adr/0018-vault-namespace-e-credencial-compartilhada.md`).
  The gateway reports a shared name at boot; it does not refuse it.
- **Rotating a value needs a restart** to reach an upstream that is already
  connected. The gateway logs a warning while a connected upstream is
  still using the old value (`../deploy/freebsd-jail.md`, "Rotating
  credentials").

If a server insists on a generic variable name, keep the unique name in the
vault and map it in a shell wrapper. The wrapper line is an argument, so it
is signed and visible, and holds no secret:

```sh
mcp-gateway upstream register -config "$CFG" -name edr -transport stdio \
  -command /bin/sh \
  -arg -c -arg 'API_KEY="${EDR_API_TOKEN}" exec /usr/local/bin/your-edr-mcp' \
  -env EDR_API_TOKEN
```

### 3. Sign the entry

```sh
mcp-gateway sign -config "$CFG" edr
```

With `signer.require_signed = true` (the default) the gateway serves only
entries signed by a key listed in `signer.trusted_keys`. The signature
covers the command, arguments and variable names, never a secret value, so
change any of those and you re-sign; rotate a credential and you do not. If
you have no key yet, `mcp-gateway sign -generate-key -out PATH` creates one
and prints the lines to paste into the configuration.

A running gateway picks up a registration, a deregistration or a signature
that stops verifying within one `quarantine.refresh_interval`. `mcp-gateway
sign -all -dry-run` lists every registered entry that is not yet validly
signed by your key, and the plan's manifest; `sign -all -manifest SHA256`
signs exactly that plan, and nothing if an entry changed in between.

### 4. Review and approve the tools

When the gateway connects to a new upstream, every tool it advertises is
**pending**: invisible and uncallable, for every role. Review each
definition and approve the ones you intend to serve:

```sh
mcp-gateway tool list    -config "$CFG" -server edr
mcp-gateway tool show    -config "$CFG" edr isolate_host   # the definition and its SHA256
mcp-gateway tool approve -config "$CFG" -fingerprint SHA256 edr isolate_host
```

An approval pins the tool's name, description, input and output schema, at
the SHA256 `tool show` printed; without `-fingerprint`, `tool approve`
shows the definition and approves nothing. If the upstream later changes any
of them, the tool is marked **changed** and stops being served until someone
approves the new definition; `tool show` then prints the diff. `tool approve`
prints which roles the approval serves; `tool revoke SERVER TOOL` returns a
tool to pending. Both take effect on the next call, without a restart.

A tool is observed only once a running gateway has connected to its
upstream, so `tool list` shows nothing to approve until `serve` has started.
Run these commands from a second shell while `serve` is running; the
console and the server share the SQLite file safely.

A tool you never approve is simply not on the gateway. That is the way to
keep, say, a scan-launching tool out of reach without modifying the server.

### 5. Grant the tools to roles

Roles live in the configuration file, so a change to who may call what is a
reviewed diff. Two forms, which a role may mix:

```toml
[[role]]
name  = "tier1-analyst"
tools = ["cases.list_cases", "cases.get_case"]   # namespaced, exact match, no wildcard
  [role.grants]
  edr   = ["get_host", "list_detections"]        # upstream's own tool ids
  intel = ["*"]                                  # every tool intel advertises

[group_to_role]
"blue-tier1" = "tier1-analyst"                   # group from the token -> role
```

An upstream a role does not name is not granted. An analyst in several
groups gets the union of their roles. A tool is callable only when a role
grants it **and** its current definition is approved. The loader refuses,
at startup, a `tools` entry without a namespace, `"upstream.*"` in `tools`,
`"*"` mixed with named tools, duplicates, and a group mapped to an
undefined role. It cannot check that a grant names a registered upstream,
because upstreams live in the database; `serve` warns about that instead.

A tool that is not callable for a caller -- no role grants it, or its
definition is pending or changed -- is not in that caller's `tools/list`,
and a `tools/call` naming it gets the same answer as a tool that does not
exist: JSON-RPC error `-32602`, `unknown tool "edr.isolate_host"`. The
gateway does not say which reason applied, so a caller cannot probe for
tools it may not see. The audit trail does: the call is recorded as denied
with reason `not visible to caller` (see `mcp-gateway audit`). When a grant
seems not to work, check `tool list` for the tool's status first and the
role in the configuration second.

Role changes take effect without a restart: `mcp-gateway reload -config
"$CFG"` (as the service account, or `systemctl reload mcp-gateway`) makes
the running gateway re-read the file, validate all of it, and apply
`[[role]]`, `[group_to_role]` and `[quota]` from the next call, printing who
gained and lost which tool (`design/adr/0044`). A file it refuses changes
nothing. An analyst sees a newly granted tool after their client reconnects.

## Checking your configuration offline

There is no separate "check" command. Every operator subcommand loads and
validates the whole file before doing anything, so this is a safe dry run
that touches only the database file named in the configuration:

```sh
mcp-gateway upstream list -config "$CFG"
```

Exit code 2 with a message means the configuration was refused; 0 or 1
means it loaded. Each `.toml` file in this directory was checked this way, appended
to `base.toml` with a real key pasted into `signer.trusted_keys`. The
unedited `base.toml` is refused on purpose: its `trusted_keys` placeholder
is not a key.

`serve` does more at startup (OIDC discovery against the issuer, decrypting
the vault with `sops`, connecting to every upstream), so a file that passes
this check can still fail there, with an error naming the step.
