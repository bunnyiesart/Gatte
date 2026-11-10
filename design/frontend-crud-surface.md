# Frontend CRUD surface map

The surface both Gatte frontends code against: the web console
(`internal/front/gatteweb`, front tag `ui`) and the terminal console
(`internal/front/gattetui`, the `mcp-gateway tui` subcommand, front tag `tui`).

Both are thin clients over `pkg/adminapi`, which talks to the management API on
the operator and accounts UNIX sockets (`api/admin.openapi.yaml`). All business
logic and security gates stay in the API: upstream signing, tool quarantine and
clearing, the secret vault, roles validation, quota, and the audit hash chain. A
frontend only renders what the API returns and confirms an action before
sending it.

A frontend calls an operation marked with a feature only when
`WhoAmI.Features` lists it. Each front names itself to the audit trail through
`adminapi.WithFront` (`"ui"` or `"tui"`); that tag is display only and decides
nothing.

For local UI work, `make preview-console` serves the real console against the
in-memory fake (`internal/adminapitest`) with sample rows for every surface
below, including empty and error states; `make preview-tui` runs the terminal
console against it (`ARGS=-gallery` prints every screen and state). The fake is
also the test double both tracks build on (`adminapitest.Start`). **Never build
or host the real image on a workstation** — the mock preview is the only thing
that runs locally; real builds and tests run in CI or on the server.

## The 2-tab IA (ADR-0051)

The console is **two tabs and nothing else in the menu**. The operator's
identity sits in the shared header (not a page); items that "need review" show
inside the Servers tab.

```
Header: identity · [ MCP Servers / APIs ] [ Users ]

Tab 1  /servers                 list of "MCP server / API" + per-backend health
       /servers/new             add a REST API / OpenAPI -> generates MCP tools
       /servers/{name}          server detail (panels below)

Tab 2  /users                   People/accounts + Roles + Blocklist (sections)
```

### Tab 1 — MCP Servers / APIs

The noun is **"MCP server / API"** (ADR-0052). The list shows each backend with
its health (ADR-0041). Add is a dedicated zero-JS sub-page, never a modal
(ADR-0036). The **server-detail page absorbs** what used to be the Tools,
Secrets, and Backends/maintenance tabs, as panels.

### Tab 2 — Users

One tab, three sections, each with its own socket gate (ADR-0040 §1):
People/accounts (accounts socket, root), Roles (accounts socket), Blocklist
(operator socket). People and Blocklist stay distinct: **disabling an account is
not blocking a subject** (ADR-0038) — both actions exist, separately.

### Removed from the UI

| Removed page | Where it goes | ADR |
|---|---|---|
| Overview (as a page) | identity -> header; attention -> Servers tab | 0051 |
| Tools (standalone tab) | server-detail panel | 0051 |
| Secrets (standalone tab) | server-detail panel + small global vault view | 0053 |
| Roles (standalone tab) | Users tab section | 0051/0054 |
| Audit | the SIEM; integrity verify stays CLI + scheduled | 0056 |
| Quota | CLI / `gatte.status`; the control stays active server-side | 0057 |
| Gateway-wide maintenance + the notice appended to every result | removed; per-backend maintenance stays (/v2) | 0055 |

The `pkg/adminapi` client still wraps the removed operations (it is frozen and
complete — see Coverage); the console simply does not surface them. `ListAudit`/
`VerifyAudit` are reached from the CLI and the scheduled chain-head check, not
the console; `QuotaUsage` from the CLI.

## How to read this

Each surface below is a slice an agent can own end to end across both fronts.
Each lists its **adminapi ops** (socket: **op** operator, **acc** accounts) and
where it lives in the IA. Socket and feature apply as noted; a one-time password
is shown once and never kept; secret values are never returned.

---

## Tab 1 · Servers list + Add + detail shell (slice M1.1)

The list page, the `/servers/new` add page, and the server-detail **container**
(the shell the other Tab-1 slices hang panels on).

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listUpstreams | GET /v1/upstreams | `ListUpstreams` | op |
| getUpstream | GET /v1/upstreams/{name} | `GetUpstream` | op |
| registerUpstream | POST /v1/upstreams | `RegisterUpstream` | op (`console_manages`) |
| signUpstream | POST /v1/upstreams/{name}/sign | `SignUpstream` | acc (`console_manages`) |
| deregisterUpstream | DELETE /v1/upstreams/{name} | `DeregisterUpstream` | op (`console_manages`) |
| redialUpstream | POST /v1/upstreams/redial | `RedialUpstream` | op (`serve_control`) |
| reloadConfig | POST /v1/reload | `Reload` | op (`serve_control`) |
| serveRequest | GET /v1/serve-requests/{id} | `ServeRequestByID` | op (`serve_control`) |

Health comes with each `Upstream` and from `Overview` (ADR-0041). Add (ADR-0052):
`/servers/new` takes an OpenAPI by URL, pasted text, or upload — the http path of
ADR-0050 §2; stdio/oci stay CLI-only. **Signing is a separate attesting click on
the result page, never sign-on-register** (ADR-0050 §5). Deregister asks the
operator to type the name, because it drops approvals (ADR-0050 §2).

> **M5 extends Add to a 3-way choice** (REST API / Remote MCP server (URL) /
> Container (oci); ADR-0059) and relabels the signed/unsigned state to "Config
> attested" (ADR-0060). That work (M5.4, M5.5) touches these M1.1-owned Servers
> files and must be coordinated with M1.1 — see "M5 · Remote + oci Add" below.

- **Console:** owns `reg_servers.go`, the list/add/detail handlers, the detail
  **container** template, `ui/servers.html`, `ui/server_new.html`,
  `ui/server.html`. Registers the two nav tabs and the `DetailPanel`/
  `UsersSection` registries (see Self-registration).
- **TUI:** the Servers screen — list with health, the add flow, and the
  per-server detail that hosts the same panels.

## Tab 1 · Tools panel (slice M1.2)

The quarantine review/approve/revoke/clear for one backend, as a panel in the
server-detail page.

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listTools | GET /v1/tools | `ListTools` | op |
| reviewTool | GET /v1/tools/review | `ReviewTool` | op |
| approveTool | POST /v1/tools/approve | `ApproveTool` | op |
| reviewToolSet | GET /v1/tools/review-set | `ReviewToolSet` | op (`tool_review_set`) |
| approveToolSet | POST /v1/tools/approve-set | `ApproveToolSet` | op (`tool_review_set`) |
| revokeTool | POST /v1/tools/revoke | `RevokeTool` | op |
| clearTool | POST /v1/tools/clear | `ClearTool` | op (`tool_clear`) |

Generated tools stay **pending until approved** (ADR-0036/0032); approval is on
the **reviewed fingerprint** (segments drawn, never re-escaped). A **sensitive**
(non-GET) tool needs `clear` **and** a `non_read` role that names it (ADR-0048
§5); the console does not bypass this gate.

- **Console:** owns `reg_tools.go`, the tools panel handlers,
  `ui/panel_tools.html`, `ui/tool.html`, `ui/reviewset.html`. Registers a
  `DetailPanel` (Order 20).
- **TUI:** the per-server tools section with the same review and actions.

## Tab 1 · Secrets panel + global vault view (slice M1.3)

The secret names one backend declares, inline, plus a small global view for
shared/orphan secrets (ADR-0053).

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listSecrets | GET /v1/secrets | `ListSecrets` | op (`console_manages`) |
| setSecret | PUT /v1/secrets/{name} | `SetSecret` | acc (`console_manages`) |
| deleteSecret | DELETE /v1/secrets/{name} | `DeleteSecret` | acc (`console_manages`) |

**Values are never returned**: show only names, whether a value is present, and
which entries declare each name. Writes are **root, on the accounts socket**; the
plaintext never touches disk (sops over stdio); the trail line carries the name,
never the value (ADR-0050 §2).

- **Console:** owns `reg_secrets.go`, the secrets panel + a small global-vault
  partial, `ui/panel_secrets.html`, `ui/vault.html`. Registers a `DetailPanel`
  (Order 30) and the small global view on the Servers list.
- **TUI:** the per-server secret names with set/delete, and the global names
  view; never a value.

## Tab 1 · Maintenance toggle (slice M2.1)

Per-backend maintenance only. **Gateway-wide maintenance and the notice appended
to every result are removed** (ADR-0055).

| Op | Client | Socket | Note |
|---|---|---|---|
| per-backend maintenance on/off/list | `StartMaintenance`/`EndMaintenance`/`ListMaintenance` (reshaped) | op (`maintenance`) | **/v2** — see below |

Contract (ADR-0055, ADR-0040 §7): removing `GET /v1/maintenance`,
`POST /v1/maintenance/on`, `POST /v1/maintenance/off` and the `(gateway)` target
is **not additive**, so the per-backend surface that stays is served as **/v2**,
alongside `/v1` for at least one version. The feature `maintenance` and the
per-backend `maintenance` state in `gatte.status` remain; the gateway target and
its appended notice go. The exact /v2 route shape is M2.1 work — this map fixes
that it is /v2, not the signature.

- **Console:** owns `reg_maintenance.go`, a maintenance toggle on the
  server-detail page (state, since, on/off with CSRF). Registers a `DetailPanel`
  (Order 40).
- **TUI:** the per-server maintenance toggle.

## Tab 2 · People / accounts (slice M1.4a)

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

**Disable is not block** (ADR-0038): disabling an account is a People action;
blocking a subject is the Blocklist section — both stay.

- **Console:** owns `reg_people.go`, the People section + account detail + add +
  connect, `ui/section_people.html`, `ui/account.html`, `ui/newperson.html`,
  `ui/connect.html`. Registers a `UsersSection` (Order 10).
- **TUI:** the account list with detail, add (check then create, one-time
  password shown once), groups, disable/enable/reset/delete/offboard, connect.

## Tab 2 · Roles — structured (slice M1.5)

A **role × tool** view with surgical grant/revoke. **The UI never regenerates the
roles file** (ADR-0054): a grant/revoke is the smallest textual edit, so the
load-bearing approver/review comments of ADR-0009 survive byte for byte.

| Op | Method / path | Client | Socket |
|---|---|---|---|
| getRoles | GET /v1/roles | `GetRoles` | op (`console_manages`) |
| putRoles | PUT /v1/roles | `PutRoles` | acc (`console_manages`) |

Writing **validates and stores; it does not apply**. A reload (Servers tab,
`serve_control`) applies; no auto-reload per edit (ADR-0050/0044).

- **Console:** owns `reg_roles.go`, the role×tool view + grant/revoke,
  `ui/section_roles.html`. Registers a `UsersSection` (Order 20).
- **TUI:** the role×tool matrix with grant/revoke, then a prompt to reload.

## Tab 2 · Blocklist (slice M1.4b)

| Op | Method / path | Client | Socket |
|---|---|---|---|
| listBlocks | GET /v1/access/blocks | `ListBlocks` | op |
| blockSubject | POST /v1/access/block | `BlockSubject` | op (expiry: `block_until`) |
| unblockSubject | POST /v1/access/unblock | `UnblockSubject` | op |

- **Console:** owns `reg_access.go`, the Blocklist section, `ui/section_access.html`.
  Registers a `UsersSection` (Order 30).
- **TUI:** the blocklist with block (optional expiry) and unblock.

---

## Self-registration (how the two shells stay merge-clean)

The goal: adding or changing a surface touches only that surface's own files, so
the parallel M1/M2 slices do not collide on one shared route table, nav menu, or
aggregate page. The 2-tab IA makes **two** pages shared (the server-detail page
and the Users page), so each gets its own panel/section registry on top of the
existing route registry.

### Console — three registries, all in `sections.go`

1. **The two nav tabs** are defined once by the shell (M1.1). Slices do not add
   nav items; there are only two.
2. **Route registry** (today's `register(Section{...})`): each slice mounts its
   own action routes from its own `reg_<slice>.go` `init()`. `routes()` ranges
   over it and calls each `Mount`.
3. **`DetailPanel` registry** for `/servers/{name}`: each Tab-1 slice appends a
   panel from its own file's `init()`, with an `Order` and a `Show` gate; the
   server-detail container ranges over registered panels in order. Tools (20),
   Secrets (30), Maintenance (40).
4. **`UsersSection` registry** for `/users`: each Tab-2 slice appends a section
   the same way. People (10), Roles (20), Blocklist (30).

```go
// Route mount (unchanged shape), from reg_tools.go init():
register(Section{
    Mount: func(mux *http.ServeMux, f *Front) { mux.HandleFunc("POST /servers/{name}/tools/approve", f.approveTool); /* ... */ },
})

// Panel contribution to the server-detail page, from reg_tools.go init():
registerDetailPanel(DetailPanel{ID: "tools", Order: 20, Show: managesOrAlways, Render: (*Front).toolsPanel})

// Section contribution to the Users page, from reg_roles.go init():
registerUsersSection(UsersSection{ID: "roles", Order: 20, Show: managesAndRoot, Render: (*Front).rolesSection})
```

Order uses gaps of ten so a slice can slot between two without renumbering. A
slice adds a `reg_<slice>.go`, its handlers (own file), and its templates — and
nothing else. It never edits another slice's files, the shell, or the two
container pages.

### TUI — mirror the same shape (Track A / M4)

The `tui` package mirrors this: a `Screen` registry for the two screens (Servers,
Users), and within each, a panel/section registry each slice appends to from its
own file's `init()`. Do not hand-maintain a menu or a switch over screens.

```go
// internal/front/gattetui/registry.go; each from its own file's init():
registerScreen(Screen{ID: "servers", Title: "MCP Servers / APIs", Order: 10, Root: serversPage})
registerDetailPanel(DetailPanel{ID: "tools", Order: 20, Rows: toolsPanel})
registerUsersSection(UsersSection{ID: "roles", Order: 20, Rows: rolesSection})
```

The roles splice rules are in `pkg/frontkit` (`roles.go`) for any front. The
console still carries the same rules in `gatteweb/roles_toml.go` until it
switches to them.

## Frozen shared files — consume, never edit

Entity agents treat these as read-only. If a slice needs a change here, flag it
for the shell owner (M1.1 / M1.6) rather than editing it, so branches do not
collide:

- `pkg/adminapi/*` — the API client and contract types. Complete (see Coverage);
  consume it.
- `internal/adminapitest/*` — the fake. Add seed rows for your surface only if
  genuinely missing; do not change another slice's rows or the routing.
- `internal/front/gatteweb/gatteweb.go` — the console shell (`routes`, `render`,
  `page`, `Front`).
- `internal/front/gatteweb/sections.go` — the route registry, and the
  `DetailPanel` and `UsersSection` registry types, helpers (`registerDetailPanel`,
  `registerUsersSection`, `orderedDetailPanels`, `orderedUsersSections`) and the
  `fragment` view. A slice appends to these from its own `reg_<slice>.go`; it
  never edits this file.
- `internal/front/gatteweb/ui/layout.html`, `ui/app.css` — the shared shell and
  styles.
- The two nav tabs and the Tab-1/Tab-2 containers, owned by M1.1: the
  `reg_servers.go`/`reg_users.go` registrations, the handlers in `servers.go`
  and `users.go`, and the templates `ui/servers.html`, `ui/server_new.html`,
  `ui/server.html`, `ui/server_registered.html`, `ui/users.html`. Other slices
  add panels/sections through the registries, never by editing these; they add
  no nav items (there are only the two tabs).
- The TUI shell and its registries, once Track A creates them.

## Coverage

`pkg/adminapi` already wraps every operation the contract defines, including the
ones no longer surfaced in the console (audit, quota, the current /v1
maintenance). `TestClient_CoversEveryOperationOfTheContractAgainstTheRealBackend`
holds the client to exactly the contract's operation set. No client gap blocks
either track. The /v2 per-backend maintenance surface (ADR-0055) is added to the
contract and the client as part of M2.1, before its panel is built.

---

## M5 · Remote + oci Add, 3-way Add menu, attestation relabel

M5 adds two new ways to register a backend from the console and clarifies the
signed/unsigned labels. ADRs: 0058 (remote transport), 0059 (oci + remote from
the console, 3-way Add), 0060 (attestation relabel).

### New transport: `remote` (ADR-0058)

A native MCP server reached by URL, held as a **live connection** (adapter
`internal/gateway/remotemcp`, mirroring stdio — not the stateless resthttp
shape). Streamable HTTP now, SSE deferred. Signed by a new `v4-remote` canonical
tag covering the full URL + auth descriptor + `remote_kind` (no op-set digest).
Static bearer/header auth resolved from the vault at dial; the gateway→remote
hop reuses the resthttp egress/SSRF guard, lifted into a shared package both
adapters import. A remote backend is un-isolatable and its downstream egress is
invisible to ADR-0033 — declared, gated on operator trust in the endpoint. This
is backend work (M5.2); the console only gains a form for it (M5.4).

### The 3-way Add menu (ADR-0059) — slice M5.4

`/servers/new` becomes a transport-aware choice: **REST API** / **Remote MCP
server (URL)** / **Container (oci)**. stdio stays CLI-only (console stdio is a
declared regression, default NO). The register request gains `transport` and the
per-transport fields; the service branches to a `RegisterEntry` port reusing the
transport-agnostic `validateEntry` + `credentialedStdioRefusal`. oci requires
podman: on the Docker image (no podman) the Container option is **not offered**
(feature `oci_register`), and a direct call is refused gracefully — never a
broken button. oci keeps full ADR-0034 hardening + digest pin, unchanged.

| Op | Method / path | Client | Socket |
|---|---|---|---|
| registerUpstream (extended: transport + per-transport fields) | POST /v1/upstreams | `RegisterUpstream` | op (`console_manages`) |
| signUpstream | POST /v1/upstreams/{name}/sign | `SignUpstream` | acc (`console_manages`) |

- **Console:** M5.4 extends the **M1.1-owned** `/servers/new` page and handler,
  `ui/server_new.html`, and `reg_servers.go`. **These are M1.1 frozen files** —
  M5.4 coordinates with the M1.1 shell owner, it does not fork them.
- **TUI:** the Servers add flow gains the same 3-way choice.

### Attestation relabel (ADR-0060) — slice M5.5

Rename the backend state labels: `Signed` -> `Config attested`, `Unsigned` ->
`Config not attested`; the register-result button `Sign` -> `Attest this
configuration`. "Attested" means an operator signed the config (URL/command/args
+ secret names); it is **not** a tool-safety claim — tool safety is the separate
approve/clear gate in the tools panel. Exact copy is in ADR-0060 §2. This is
template + text only, no new logic.

- **Console:** M5.5 edits the servers **list, detail, and register-result**
  templates/copy and the tools-panel header — these live in the **M1.1-owned**
  Servers files and the **M1.2-owned** tools panel. Coordinate with those
  owners; do not fork the files.
- **TUI:** mirror the same labels on the Servers screen.

### Dependency / ownership flags

- M5.1 (ADRs + this surface update) blocks M5.2–M5.5.
- M5.4 depends on M5.2 (remote transport) **and** M5.3 (oci-from-console
  contract/service/front).
- M5.4 and M5.5 touch files **owned by M1.1** (Servers list/add/detail) and, for
  M5.5, by M1.2 (tools panel). They are not independent slices: they extend
  frozen shared files and must be sequenced with the M1.1/M1.2 owners.
