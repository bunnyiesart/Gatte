# Command guide

Every command you use to run Gatte, arranged by what you want to do. Each
entry says who runs it, when it takes effect, and where to read more. For
every flag of every command, see the [command line reference](reference/cli.md);
the binary itself prints the same with `mcp-gateway help` and
`mcp-gateway COMMAND -h`.

**Contents:**
[Conventions](#conventions) ·
[All commands at a glance](#all-commands-at-a-glance) ·
[Set up a host](#set-up-a-host) ·
[Backends](#backends) ·
[Tools](#tools) ·
[People and access](#people-and-access) ·
[The audit trail and quota](#the-audit-trail-and-quota) ·
[Configuration changes](#configuration-changes) ·
[Maintenance](#maintenance) ·
[Host care](#host-care) ·
[The console and the management API](#the-console-and-the-management-api) ·
[For analysts](#for-analysts) ·
[Around Gatte](#around-gatte) ·
[Exit codes](#exit-codes)

## Conventions

The examples use the paths from the README's Quick start:

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

Every command except `sign -generate-key` and `ui` takes `-config FILE`
(default `mcp-gateway.toml` in the current directory) and validates the
whole file, refusing unknown keys, before it does anything. Flags go
before the positional arguments: `tool approve -fingerprint SHA256 edr get_host`,
not `tool approve edr get_host -fingerprint SHA256`.

Who runs a command matters, because it decides which files it can read and
what the audit trail says:

| Tag | Runs as | Why |
|---|---|---|
| **svc** | the service account: `sudo -u mcpgw mcp-gateway ...` | it writes the database `serve` writes |
| **root** | `sudo mcp-gateway ...` | it reads the signing key, or checks or replaces files the service account must not control; it drops to the database owner before opening the database |
| **you** | yourself, as a member of the operator socket's group (`gatte-operators`) | the management API names you from the kernel's credentials |

"Takes effect" uses these words: **now** (the command's own output),
**next call** (the next MCP request that reaches the gateway), **one
round** (within one `quarantine.refresh_interval`, default 5 minutes),
**restart** (the next start of `serve`).

## All commands at a glance

| Command | What it does | Runs as | Read more |
|---|---|---|---|
| `serve` | Run the gateway | svc (under systemd) | [README, Quick start](../README.md#quick-start) |
| `upstream list` | List backends, their signature and network | svc | [Add a backend](how-to/add-a-backend.md) |
| `upstream register` | Register a stdio, container or REST (OpenAPI) backend | svc | [Add a backend](how-to/add-a-backend.md) |
| `upstream update` | Move a container backend to a new image digest | svc | [Update a backend's image](how-to/update-a-backend-image.md) |
| `upstream deregister` | Remove a backend and forget its approvals | svc | [Add a backend](how-to/add-a-backend.md) |
| `upstream redial` | Re-dial one backend with the vault as it is now | svc | [Rotate credentials and keys](how-to/rotate-credentials-and-keys.md) |
| `upstream maintenance on\|off` | Answer one backend's calls with a maintenance message | svc | [Plan maintenance](how-to/plan-maintenance.md) |
| `sign` | Sign one entry, or every entry by a reviewed plan | root | [Add a backend](how-to/add-a-backend.md) |
| `sign -generate-key` | Create a signing key | root | [Rotate credentials and keys](how-to/rotate-credentials-and-keys.md) |
| `tool list` | The approval queue | svc | [Review and approve tools](how-to/review-and-approve-tools.md) |
| `tool show` | One tool's definition, escaped, with its diff | svc | [Review and approve tools](how-to/review-and-approve-tools.md) |
| `tool review` | Every waiting tool of one backend, and the set's manifest | svc | [Review and approve tools](how-to/review-and-approve-tools.md) |
| `tool approve` | Approve one fingerprint, or a backend's set by manifest | svc | [Review and approve tools](how-to/review-and-approve-tools.md) |
| `tool revoke` | Withdraw an approval | svc | [Review and approve tools](how-to/review-and-approve-tools.md) |
| `tool clear` | Clear an approved sensitive tool for serving | svc | [Review and approve tools](how-to/review-and-approve-tools.md) |
| `access block\|unblock\|list` | Cut one analyst off, for good or until a time | svc | [Respond to an incident](how-to/respond-to-an-incident.md) |
| `audit` | Read and filter the trail | svc | [Audit trail reference](reference/audit-trail.md) |
| `audit -verify` | Check the hash chain, optionally against the SIEM's head | svc | [Respond to an incident](how-to/respond-to-an-incident.md) |
| `quota list\|usage` | Declared budgets, and what each analyst spent | svc | [Change roles, groups and quota](how-to/change-roles-and-quota.md) |
| `maintenance on\|off\|list` | Announce maintenance of the whole gateway | svc | [Plan maintenance](how-to/plan-maintenance.md) |
| `reload` | Apply roles, groups and quota without a restart | svc | [Change roles, groups and quota](how-to/change-roles-and-quota.md) |
| `admin` | Serve the management API (normally socket-activated) | svc; `-accounts` as root | [Run the management API and console](how-to/run-the-management-api-and-console.md) |
| `ui` | Serve the web console on loopback | you; `-manage-users` with sudo | [Run the management API and console](how-to/run-the-management-api-and-console.md) |
| `check` | Check the configuration and this host's files | root | [Files and permissions](reference/files-and-permissions.md) |
| `backup` | Write a consistent, checked copy of the database | svc | [Back up and restore](how-to/back-up-and-restore.md) |
| `restore` | Replace the database with a checked copy | root, serve stopped | [Back up and restore](how-to/back-up-and-restore.md) |
| `version` | Print the build and the database schema | anyone | [Upgrade Gatte](upgrade.md) |

## Set up a host

The whole sequence, with its reasons, is the README's
[Quick start](../README.md#quick-start). The commands in order:

| Step | Command | Runs as |
|---|---|---|
| Create the signing key | `mcp-gateway sign -generate-key -out /usr/local/etc/mcp-gateway/signing.key` | root |
| Encrypt the vault | `sops --encrypt --age "$R" --input-type json --output-type json secrets.json` | root |
| Register a backend | `mcp-gateway upstream register -config "$CFG" -name edr -transport oci -image REPO@sha256:HEX -env EDR_CLIENT_ID` | svc |
| Sign it | `mcp-gateway sign -config "$CFG" edr` | root |
| Check the host | `mcp-gateway check -config "$CFG" -user mcpgw -online` | root |
| Start the gateway | `systemctl enable --now mcp-gateway` (or `mcp-gateway serve -config "$CFG"` in the foreground) | root / svc |
| Start the management API | `systemctl enable --now mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket` | root |
| Approve the first tools | `mcp-gateway tool review -config "$CFG" -server edr`, then `tool approve -server edr -manifest SHA256` | svc |

## Backends

**I want to see what is registered.**

```sh
sudo -u mcpgw mcp-gateway upstream list -config "$CFG"          # add -json for the network grants
```

Shows each backend's transport, command or image, credential *names* and
whether its signature is valid (`SIGNED yes`).

**I want to add a backend.** svc, then root; takes effect in one round.

```sh
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport oci \
    -image ghcr.io/example/edr-mcp@sha256:HEX -arg --network=slirp4netns \
    -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
sudo mcp-gateway sign -config "$CFG" edr
```

For a local process, `-transport stdio -command /usr/local/bin/edr-mcp`.
For a REST API the gateway calls itself, one tool per operation of its
OpenAPI document, with the credential injected server-side where
`-auth-kind` says:

```sh
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name ioc -transport http \
    -url https://api.example.com -openapi /usr/local/etc/mcp-gateway/ioc-openapi.json \
    -auth-kind header -auth-name X-API-Key -env IOC_API_KEY
sudo mcp-gateway sign -config "$CFG" ioc
```

`-openapi` also takes an `https://` URL, fetched once under the gateway's
egress guard; the operation set is frozen with the entry. `POST`/`PUT`/
`PATCH`/`DELETE` tools are sensitive and need `tool clear` after approval.
Its tools then wait in the queue ([Tools](#tools)), and a role must grant
them ([Configuration changes](#configuration-changes)).
→ [Add a backend](how-to/add-a-backend.md); for `-transport http`,
[upstream register](reference/cli.md#upstream-register)

**I want to move a container backend to a new image.** svc, then root;
takes effect after the signature, in one round.

```sh
sudo -u mcpgw mcp-gateway upstream update -config "$CFG" -image ghcr.io/example/edr-mcp@sha256:NEWHEX edr
sudo mcp-gateway sign -config "$CFG" edr
```

Tools whose definition did not change stay approved; the others wait for
review. → [Update a backend's image](how-to/update-a-backend-image.md)

**I want to remove a backend.** svc; one round. It forgets every approval
of that backend.

```sh
sudo -u mcpgw mcp-gateway upstream deregister -config "$CFG" edr
```

**I rotated a backend's credential, or restarted its container.** svc;
one round, that backend only.

```sh
sudo sops /usr/local/etc/mcp-gateway/secrets.enc.json         # edit the value
sudo -u mcpgw mcp-gateway upstream redial -config "$CFG" edr   # waits up to -wait 2m
```

## Tools

**I want to see what needs approval.**

```sh
sudo -u mcpgw mcp-gateway tool list -config "$CFG"              # -server edr for one backend
```

**I want to approve one tool.** svc; next call.

```sh
sudo -u mcpgw mcp-gateway tool show -config "$CFG" edr get_host        # read it; note its SHA256
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" -fingerprint SHA256 edr get_host
```

**I want to approve all of one backend's waiting tools.** svc; next call.
All or nothing: if any tool of the backend appeared, disappeared or
changed since the review, nothing is approved.

```sh
sudo -u mcpgw mcp-gateway tool review -config "$CFG" -server edr       # read every one; note the manifest
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" -server edr -manifest SHA256
```

**I want to withdraw an approval.** svc; next call.

```sh
sudo -u mcpgw mcp-gateway tool revoke -config "$CFG" edr get_host
```

**I want to serve a sensitive tool I approved.** svc; next call. A
sensitive tool -- one that can act, a REST operation with any method but
GET/HEAD/OPTIONS -- is approved like any other and NOT served until it is
also cleared. Clearing refuses unless a `[[role]]` with `non_read = true`
names the tool in its `tools` list; a `"*"` grant never reaches it.
Approving a set never clears.

```sh
sudo -u mcpgw mcp-gateway tool clear -config "$CFG" edr isolate_host
```

Approving is not granting: a tool is callable only when it is approved and
a role grants it. `tool review` says "callable by nobody" when no role
does. → [Review and approve tools](how-to/review-and-approve-tools.md)

## People and access

**I want to cut an analyst off now.** svc; next request. Also revoke their
session at the identity provider: the block does not.

```sh
sudo -u mcpgw mcp-gateway access block -config "$CFG" -reason "incident 42" SUBJECT
sudo -u mcpgw mcp-gateway access block -config "$CFG" -until 8h -reason "incident 42" SUBJECT   # ends by itself
sudo -u mcpgw mcp-gateway access unblock -config "$CFG" -reason "cleared" SUBJECT
sudo -u mcpgw mcp-gateway access list -config "$CFG"
```

`SUBJECT` is the token's `sub`, exactly as the ANALYST column of `audit`
shows it; `-until` takes a duration (`8h`) or a time
(`2026-10-01T08:00:00Z`).

**I want to add, change, offboard or delete a person's account.** These
live in the web console, not the CLI, because they edit the identity
provider through the root-only accounts socket:

```sh
sudo mcp-gateway ui -manage-users
```

**People → Add person** creates the account with a one-time password and
a connect script; a person's page has **Save groups**, **Disable**, **Enable**, **Reset
password**, **Offboard** (disable + block, one action) and **Delete**.
→ [Add and remove people](how-to/add-and-remove-people.md)

## The audit trail and quota

**I want to read the trail.** svc.

```sh
sudo -u mcpgw mcp-gateway audit -config "$CFG"                                    # newest first
sudo -u mcpgw mcp-gateway audit -config "$CFG" -subject SUBJECT -outcome denied
sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool edr.isolate_host \
    -since 2026-09-29T14:00:00Z -until 2026-09-29T16:00:00Z
sudo -u mcpgw mcp-gateway audit -config "$CFG" -server edr -limit 500 -json       # for jq or a ticket
```

`-until` is exclusive. The web console's **Audit** page has the same
filters and exports the filtered rows as CSV or JSON Lines.

**I want to prove the trail was not edited.** svc.

```sh
sudo -u mcpgw mcp-gateway audit -config "$CFG" -verify
sudo -u mcpgw mcp-gateway audit -config "$CFG" -verify -expect-head HASH   # the head your SIEM last received
```

**I want to see quota spend.** svc.

```sh
sudo -u mcpgw mcp-gateway quota list  -config "$CFG"                     # declared budgets
sudo -u mcpgw mcp-gateway quota usage -config "$CFG" -analyst SUBJECT    # or -account NAME, -since TIME
```

→ [Audit trail reference](reference/audit-trail.md)

## Configuration changes

**I changed roles, groups or quota in `config.toml`.** svc; next call.
Nothing changes if the file does not load.

```sh
sudo -u mcpgw mcp-gateway reload -config "$CFG"      # or: sudo systemctl reload mcp-gateway
```

It prints which role gained and lost which tool, and every changed key it
did **not** apply. Analysts see tools they gained after they reconnect
(`/mcp` in Claude Code).

**I changed anything else** (`listen`, `[oidc]`, `[analyst]`,
`[signer]`, `[vault]`, `[audit]`, `[telemetry]`, `[response]`, `[oci]`,
`[upstreams]`, `[quarantine]`). root; restart.

```sh
sudo mcp-gateway check -config "$CFG" -user mcpgw && sudo systemctl restart mcp-gateway
```

`[connect]`, `[admin]`, `[idp]` and `signer.key_file` need nothing: `serve`
does not read them, and the management API and `sign` read them on every
use.

→ [Change roles, groups and quota](how-to/change-roles-and-quota.md),
[Configuration reference](reference/configuration.md)

## Maintenance

**I want to take one backend out.** svc; next call. Its tools stay listed
and answer with your message.

```sh
sudo -u mcpgw mcp-gateway upstream maintenance on  -config "$CFG" edr -message "EDR vendor upgrade" -until 2h
sudo -u mcpgw mcp-gateway upstream maintenance off -config "$CFG" edr
```

**I want to announce maintenance of the whole gateway.** svc; next call.
It is a notice, not a block: calls are still served.

```sh
sudo -u mcpgw mcp-gateway maintenance on   -config "$CFG" -message "Gateway upgrade at 18:00 UTC" -until 2026-10-01T18:30:00Z
sudo -u mcpgw mcp-gateway maintenance off  -config "$CFG"
sudo -u mcpgw mcp-gateway maintenance list -config "$CFG"
```

Running `on` again changes the message and keeps the announced end;
`-until none` takes the end back. → [Plan maintenance](how-to/plan-maintenance.md)

## Host care

**I want to know whether this host is right.** root; now. Exit 0 means no
check failed.

```sh
sudo mcp-gateway check -config "$CFG" -user mcpgw            # -online also asks the IdP; -json for scripts
```

**I want a copy of the database.** svc; serve may keep running.

```sh
sudo -u mcpgw mcp-gateway backup -config "$CFG" -out /var/backups/mcp-gateway -keep 14
```

It prints the copy's sha256 and audit head, and lists what is not in it
(configuration, vault, age key, signing key, IdP): keep those separately.

**I want to put a copy back.** root; restart. `serve` and the management
sockets must be stopped.

```sh
sudo systemctl stop mcp-gateway mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket
sudo mcp-gateway restore -config "$CFG" -in /var/backups/mcp-gateway/FILE -expect-head HASH
sudo mcp-gateway check -config "$CFG" -user mcpgw
sudo systemctl start mcp-gateway mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket
```

→ [Back up and restore](how-to/back-up-and-restore.md)

**I want to re-sign every backend** (after rotating the signing key). root;
one round.

```sh
sudo mcp-gateway sign -config "$CFG" -all -dry-run               # read the plan; note its manifest
sudo mcp-gateway sign -config "$CFG" -all -manifest SHA256
```

→ [Rotate credentials and keys](how-to/rotate-credentials-and-keys.md)

**I want to upgrade the binary.** Under a maintenance notice, with a
backup and two `check` runs. → [Upgrade Gatte, and roll back](upgrade.md)

```sh
mcp-gateway version                                              # build and database schema
```

## The console and the management API

**I want the web console.** you; runs until Ctrl-C.

```sh
mcp-gateway ui                                     # prints a one-time login link for 127.0.0.1:8090
sudo mcp-gateway ui -manage-users                  # also the identity provider's accounts
ssh -L 8090:127.0.0.1:8090 gateway-host            # from your own machine, then open the same link
```

**I want the management API running.** On systemd it starts on the first
connection and exits when idle:

```sh
sudo systemctl enable --now mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket
sudo usermod -aG gatte-operators OPERATOR          # who may use the operator socket
```

In the foreground, for another service manager:

```sh
sudo -u mcpgw mcp-gateway admin -config "$CFG" \
    -socket /run/mcp-gateway-admin/operator/operator.sock -socket-group gatte-operators
sudo mcp-gateway admin -accounts -config "$CFG" -socket /run/mcp-gateway-admin/accounts/accounts.sock
```

→ [Run the management API and console](how-to/run-the-management-api-and-console.md),
[Writing a Gatte front](admin-api.md)

## For analysts

**I want to connect Claude Code.** Run the connect script the operator
gave you, then, in Claude Code:

```text
/mcp                      pick the gateway's server, sign in in the browser
```

**I want to know whether the gateway is fine.**

```sh
gatte-status              # exit 0: reachable and signed in; see the table below
gatte-status -backends    # also asks gatte.status (costs one model request)
```

In a Claude Code session, ask the model to call `gatte.status`: it reports
your roles, your budget use and the state of your backends.

**Tools I expected are missing, or new ones do not show.** The tool list is
fetched once per connection: run `/mcp` and reconnect. If a tool is still
missing, it is either not granted to your role or waiting for an operator's
review. → [Connect Claude Code](how-to/connect-claude-code.md),
[Troubleshoot a connection](how-to/troubleshoot-a-connection.md)

## Around Gatte

Commands that are not Gatte's but that you use with it:

| Task | Command |
|---|---|
| Edit a credential in the vault | `sudo sops /usr/local/etc/mcp-gateway/secrets.enc.json` |
| Start, stop, restart the gateway | `sudo systemctl start\|stop\|restart mcp-gateway` |
| Reload roles, groups and quota | `sudo systemctl reload mcp-gateway` (runs `mcp-gateway reload`) |
| Follow the gateway's log | `journalctl -u mcp-gateway -f` |
| Enable the daily backup | `sudo systemctl enable --now mcp-gateway-backup.timer` |
| Pin a container image to its digest | `podman inspect --format '{{index .RepoDigests 0}}' IMAGE:TAG` |
| Build the binary | `make build` (without the web console: `go build -tags nofront ./cmd/mcp-gateway`) |
| Build the lab's mock backends | `make lab-build` |
| Run the full test gate | `make ci` (needs `sops` and `age` on `PATH`) |

On FreeBSD the service is `mcp_gateway` (`service mcp_gateway restart`);
see [`deploy/gateway-serve.md`](../deploy/gateway-serve.md).

## Exit codes

Every `mcp-gateway` command: **0** ok, **1** it ran and found a problem
(a refusal, a failed check, a chain that does not verify), **2** it could
not run (bad flags, unreadable configuration, the database or socket not
reachable).

`gatte-status`, on the analyst's machine:

| Exit | Meaning | What to do |
|---|---|---|
| 0 | Gatte answers and Claude Code is signed in | nothing |
| 1 | the network does not reach Gatte | VPN, DNS, route |
| 2 | TLS failed | the CA, the certificate |
| 3 | Gatte, or the proxy in front of it, is not serving | tell the operator |
| 4 | Gatte is up and Claude Code is not signed in, or the account is refused | `/mcp` and sign in; if it persists, ask the operator |
| 5 | unexpected: something that is not Gatte answered at its address, an error the check does not recognise, `curl` missing, or `claude -p` failed under `-backends` | tell the operator, with the line it printed |
