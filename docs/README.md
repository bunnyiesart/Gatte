# Gatte documentation

Gatte is a self-hosted MCP gateway for blue teams: one authenticated
endpoint in front of the team's MCP servers, with the API keys on one host,
every tool approved by a human, and every call in a hash-chained audit
trail. The project's [README](../README.md) is the overview; these pages
are the manual.

The pages are of four kinds ([how they are written](STYLE.md)): a
**tutorial** to learn, **how-to guides** for a task, **reference** to look
something up, and **explanation** to understand why.

## Start here

| You are... | Read first |
|---|---|
| new to Gatte | [Your first gateway, in the lab](tutorials/first-gateway-in-the-lab.md) |
| installing it for a team | the README's [Quick start](../README.md#quick-start), then [Files and permissions](reference/files-and-permissions.md) |
| an operator, at work | the [Command guide](command-guide.md), then the how-to guides below |
| an analyst | [Connect Claude Code](how-to/connect-claude-code.md) |
| writing your own console or bot | [Writing a Gatte front](admin-api.md) |
| deciding whether to trust it | [Security model](explanation/security-model.md) |

## Tutorial

- [Your first gateway, in the lab](tutorials/first-gateway-in-the-lab.md) --
  build Gatte, put a mock backend behind it, approve its tools and make a
  first call, on one machine.

## How-to guides

**Backends and tools**

- [Add a backend](how-to/add-a-backend.md)
- [Review and approve tools](how-to/review-and-approve-tools.md)
- [Update a backend's container image](how-to/update-a-backend-image.md)
- [Change roles, groups and quota](how-to/change-roles-and-quota.md)
- [Plan maintenance](how-to/plan-maintenance.md)

**People**

- [Add and remove people](how-to/add-and-remove-people.md)
- [Respond to an incident](how-to/respond-to-an-incident.md)

**The host**

- [Run the management API and the web console](how-to/run-the-management-api-and-console.md)
- [Rotate credentials and keys](how-to/rotate-credentials-and-keys.md)
- [Back up and restore](how-to/back-up-and-restore.md)
- [Upgrade Gatte, and roll back](upgrade.md)
- [Alert from the SIEM](how-to/alert-from-the-siem.md)

**For analysts**

- [Connect Claude Code](how-to/connect-claude-code.md)
- [Troubleshoot a connection](how-to/troubleshoot-a-connection.md)

## Reference

- [Command guide](command-guide.md) -- every command, arranged by what you
  want to do, with who runs it and when it takes effect.
- [Command line](reference/cli.md) -- every command and flag.
- [Configuration](reference/configuration.md) -- every section of
  `config.toml`; the full reference with comments is
  [`config.example.toml`](../config.example.toml).
- [Audit trail](reference/audit-trail.md) -- the record's fields, and every
  row Gatte and operators write.
- [What the analyst is told](reference/analyst-messages.md) -- each refusal
  and status text, and who can see it.
- [Files and permissions](reference/files-and-permissions.md) -- owners,
  modes and what `check` verifies.
- [Management API](admin-api.md) and its contract,
  [`api/admin.openapi.yaml`](../api/admin.openapi.yaml).

## Explanation

- [How a call is handled](explanation/how-a-call-is-handled.md)
- [Quarantine and signed backends](explanation/quarantine-and-signing.md)
- [Backend health and honest answers](explanation/health-and-honest-answers.md)
- [Security model](explanation/security-model.md)
- [Decision records](explanation/decision-records.md) -- a map of
  `design/adr/`.
