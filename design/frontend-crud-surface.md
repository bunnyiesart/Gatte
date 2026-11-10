# Frontend CRUD surface map

The surface both Gatte frontends code against: the web console
(`internal/front/gatteweb`, front tag `ui`) and the terminal console (the
planned `mcp-gateway tui` subcommand, front tag `tui`).

Both are thin clients over `pkg/adminapi`, which talks to the management API on
the operator and accounts UNIX sockets (`api/admin.openapi.yaml`). All business
logic and security gates stay in the API: upstream signing, tool quarantine and
clearing, the secret vault, roles validation, and the audit hash chain. A
frontend only renders what the API returns and confirms an action before
sending it.

A frontend calls an operation marked with a feature only when
`WhoAmI.Features` lists it. Each front names itself to the audit trail through
`adminapi.WithFront` (`"ui"` or `"tui"`); that tag is display only and decides
nothing.

For local UI work, `make preview-console` serves the real console against the
in-memory fake (`internal/adminapitest`) with sample rows for every entity
below, including empty and error states. The fake is also the test double both
tracks build on (`adminapitest.Start`).

## How to read this

Each entity below is a self-contained slice one agent can own end to end across
both fronts. Each section lists:

- **adminapi ops** — the client methods (socket: **op** operator, **acc**
  accounts).
- **Console** — the page and route prefix, and the files that slice owns.
- **TUI** — that slice's screen responsibility (to build in Track A).

Socket and feature apply as noted; a one-time password is shown once and never
kept; secret values are never returned.

---

## Dashboard (overview)

Read-only landing: identity, attention items, counts, recent denials, health.

- **adminapi ops:** `WhoAmI` (op), `Overview` (op), `People` (op), `QuotaUsage`
  (op). `WhoAmI.Features` drives what every other slice shows.
- **Console:** route `/` (and `/quota` for the quota view). Owns
  `reg_overview.go`, `reg_quota.go`, the overview/quota handlers in `pages.go`,
  `ui/overview.html`, `ui/quota.html`.
- **TUI:** the home screen — identity and feature set, attention list, counts,
  recent denials, backend health; the entry point to every other screen.

## Tools (quarantine)

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listTools | GET /v1/tools | `ListTools` | op |
| reviewTool | GET /v1/tools/review | `ReviewTool` | op |
| approveTool | POST /v1/tools/approve | `ApproveTool` | op |
| reviewToolSet | GET /v1/tools/review-set | `ReviewToolSet` | op (`tool_review_set`) |
| approveToolSet | POST /v1/tools/approve-set | `ApproveToolSet` | op (`tool_review_set`) |
| revokeTool | POST /v1/tools/revoke | `RevokeTool` | op |
| clearTool | POST /v1/tools/clear | `ClearTool` | op (`tool_clear`) |

- **Console:** route `/tools`. Owns `reg_tools.go`, tool handlers in
  `pages.go`, `ui/tools.html`, `ui/tool.html`, `ui/reviewset.html`.
- **TUI:** the quarantine list with per-tool review (definition, diff,
  callable-by), and the approve / revoke / clear / review-set actions, each
  confirming on the fingerprint shown.

## Access (blocklist)

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listBlocks | GET /v1/access/blocks | `ListBlocks` | op |
| blockSubject | POST /v1/access/block | `BlockSubject` | op (expiry: `block_until`) |
| unblockSubject | POST /v1/access/unblock | `UnblockSubject` | op |

- **Console:** route `/access`. Owns `reg_access.go`, access handlers in
  `pages.go`, `ui/access.html`.
- **TUI:** the blocklist with block (optional expiry) and unblock.

## Audit

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listAudit | GET /v1/audit | `ListAudit` | op (filters: `audit_filters`) |
| verifyAudit | POST /v1/audit/verify | `VerifyAudit` | op |

- **Console:** route `/audit`. Owns `reg_audit.go`, `audit.go`,
  `ui/audit.html`.
- **TUI:** the trail with filters and paging, and the verify action showing the
  chain head and any break.

## Backends (upstreams, maintenance, serve control)

In both fronts these share one page: maintenance and serve control act on
backends and are shown with them.

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listUpstreams | GET /v1/upstreams | `ListUpstreams` | op |
| getUpstream | GET /v1/upstreams/{name} | `GetUpstream` | op |
| registerUpstream | POST /v1/upstreams | `RegisterUpstream` | op (`console_manages`) |
| deregisterUpstream | DELETE /v1/upstreams/{name} | `DeregisterUpstream` | op (`console_manages`) |
| signUpstream | POST /v1/upstreams/{name}/sign | `SignUpstream` | acc (`console_manages`) |
| redialUpstream | POST /v1/upstreams/redial | `RedialUpstream` | op (`serve_control`) |
| reloadConfig | POST /v1/reload | `Reload` | op (`serve_control`) |
| serveRequest | GET /v1/serve-requests/{id} | `ServeRequestByID` | op (`serve_control`) |
| listMaintenance | GET /v1/maintenance | `ListMaintenance` | op (`maintenance`) |
| startMaintenance | POST /v1/maintenance/on | `StartMaintenance` | op (`maintenance`) |
| endMaintenance | POST /v1/maintenance/off | `EndMaintenance` | op (`maintenance`) |

- **Console:** route `/upstreams` (plus `/reload`, `/serve-requests`). Owns
  `reg_backends.go`, `backends.go`, upstream/serve parts of `manage.go`,
  `ui/upstreams.html`, `ui/upstream.html`, `ui/registered.html`.
- **TUI:** the backend list with per-backend detail and health, register /
  deregister / sign / redial, maintenance on/off, and reload — each returning a
  serve request that may be pending and read back by id.

## Secrets (vault)

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listSecrets | GET /v1/secrets | `ListSecrets` | op (`console_manages`) |
| setSecret | PUT /v1/secrets/{name} | `SetSecret` | acc (`console_manages`) |
| deleteSecret | DELETE /v1/secrets/{name} | `DeleteSecret` | acc (`console_manages`) |

Values are never returned: show only names, whether a value is in the vault, and
which entries declare each name.

- **Console:** route `/secrets` (nav link only with `console_manages` and the
  accounts socket). Owns `reg_secrets.go`, secret parts of `manage.go`,
  `ui/vault.html`.
- **TUI:** the vault names with set and delete; never a value.

## Roles

| Op | Method / path | Client | Socket |
|---|---|---|---|
| getRoles | GET /v1/roles | `GetRoles` | op (`console_manages`) |
| putRoles | PUT /v1/roles | `PutRoles` | acc (`console_manages`) |

Writing validates and stores; it does not apply. A reload (Backends) applies it.

- **Console:** route `/roles` (nav link only with `console_manages` and the
  accounts socket). Owns `reg_roles.go`, roles parts of `manage.go`,
  `ui/roles.html`.
- **TUI:** the roles file text with a validated write, then a prompt to reload.

## People (identity-provider accounts)

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listAccounts | GET /v1/accounts | `ListAccounts` | acc |
| getAccount | GET /v1/accounts/{username} | `GetAccount` | acc |
| checkAccount | POST /v1/account-check | `CheckAccount` | acc |
| addAccount | POST /v1/accounts | `AddAccount` | acc |
| setAccountGroups | POST /v1/accounts/{username}/groups | `SetAccountGroups` | acc |
| disableAccount | POST /v1/accounts/{username}/disable | `DisableAccount` | acc |
| enableAccount | POST /v1/accounts/{username}/enable | `EnableAccount` | acc |
| resetAccountPassword | POST /v1/accounts/{username}/reset-password | `ResetAccountPassword` | acc |
| deleteAccount | DELETE /v1/accounts/{username} | `DeleteAccount` | acc (`account_delete`) |
| offboardAccount | POST /v1/accounts/{username}/offboard | `OffboardAccount` | acc (`offboard`) |
| assignableGroups | GET /v1/groups | `AssignableGroups` | acc |
| connect | GET /v1/connect | `Connect` | op |
| connectScript | GET /v1/connect/script | `ConnectScript` | op |

- **Console:** route `/people`. Owns `reg_people.go`, `people.go`,
  `ui/people.html`, `ui/account.html`, `ui/newperson.html`, `ui/connect.html`.
- **TUI:** the account list with per-account detail, the add flow (check then
  create, one-time password shown once), groups, disable / enable / reset /
  delete / offboard, and the connect instructions.

---

## Self-registration (how the two shells stay merge-clean)

The goal: adding or changing an entity touches only that entity's own files, so
the ~10 Phase-1 branches do not collide on one shared route table or nav menu.

### Console — implemented

The console shell builds its routes and its navigation from a registry
(`internal/front/gatteweb/sections.go`), not from a hand-maintained list:

```go
register(Section{
    Nav:   NavItem{ID: "tools", Path: "/tools", Label: "Tools", Order: 20},
    Mount: func(mux *http.ServeMux, f *Front) { mux.HandleFunc("GET /tools", f.toolsPage); /* ... */ },
})
```

Each entity calls `register` once from its own `reg_<entity>.go` file's `init()`.
`routes()` ranges over the registry and calls each `Mount`; the layout ranges
over `navFor(...)` to draw the nav, with `NavItem.Show` gating a link (Secrets
and Roles use `managesAndRoot`). To add an entity: add a `reg_<entity>.go`, its
handlers (ideally in their own file), and its templates. Nav order uses gaps of
ten so a new entity can slot between two without renumbering.

### TUI — recommended (build this in Track A)

Mirror the same shape in the `tui` package: a `Screen` registry each entity
appends to from its own file's `init()`, and the TUI shell builds its menu and
routes keystrokes to screens from that registry. Do not hand-maintain a menu or
a switch over screens — register each screen in its own file, so entity branches
never edit a shared TUI menu.

```go
// Shape only; define concretely when the shell lands.
register(Screen{ID: "tools", Title: "Tools", Order: 20, New: func(c *adminapi.Client) tea.Model { /* ... */ }})
```

## Frozen shared files — consume, never edit

Entity agents must treat these as read-only. If a slice needs a change here,
flag it for the shell owner rather than editing it, so branches do not collide:

- `pkg/adminapi/*` — the API client and contract types. Already complete (see
  Coverage); consume it.
- `internal/adminapitest/*` — the fake. Add seed rows for your entity only if
  genuinely missing; do not change another entity's rows or the routing.
- `internal/front/gatteweb/gatteweb.go` — the console shell (`routes`, `render`,
  `page`, `Front`).
- `internal/front/gatteweb/sections.go` — the registry types and helpers.
- `internal/front/gatteweb/ui/layout.html`, `ui/app.css` — the shared shell and
  styles.
- The TUI shell and its registry file, once Track A creates them.

## Coverage

`pkg/adminapi` already wraps every operation above; the test
`TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend` holds the
client to exactly the contract's operation set. No client gap blocks either
track.
