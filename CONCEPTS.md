# Concepts — MCP, gateways, API keys, and security fundamentals

An educational primer, not a project decision record. Everything specific
to *this* project's gateway build (which candidates were tested, what
architecture was chosen, why) lives in `DEVELOPMENT-LOG.md` and `design/`.
This file is the underlying foundation those decisions were built on —
read it first if the terms in those documents feel unfamiliar, or any time
you want the "why does this work this way" underneath a decision already
made.

Three parts: MCP itself, MCP gateways specifically, and the general API/
security concepts (API keys, HTTP, authN/authZ, secrets, OWASP) that
apply whether or not MCP is involved at all.

---

# Part 1 — MCP (Model Context Protocol)

## 1.1 What MCP is and why it exists

MCP is Anthropic's open standard (released 25 Nov 2024) for connecting AI
applications to external tools and data. The problem it replaces: before
MCP, connecting **M** AI applications to **N** data sources/tools meant
**M×N** custom integrations — every application writing its own connector
to every system it needs. Anthropic's framing: "every new data source
requires its own custom implementation, making truly connected systems
difficult to scale." MCP collapses this to **M+N**: build the client side
once per AI application, the server side once per tool/data source, and
any MCP client can talk to any MCP server.

Early adopters at launch: Block, Apollo, Zed, Replit, Codeium,
Sourcegraph. Since then OpenAI and Google DeepMind have adopted it too —
it's no longer an Anthropic-only standard.

*Sources: [Anthropic — Introducing MCP](https://www.anthropic.com/news/model-context-protocol), [modelcontextprotocol.io](https://modelcontextprotocol.io/docs/getting-started/intro)*

## 1.2 The architecture: Host, Client, Server

Not client-server — **client-host-server**. The **Host** (e.g., Claude
Code) is the container process: it creates and manages multiple **Client**
instances, enforces security policy, handles user consent, and owns the
full conversation. Each **Client** has a strict 1:1 relationship with one
**Server** — negotiates capabilities, routes messages, and is itself a
security boundary. A **Server** exposes tools/resources/prompts and, per
spec, **must not** be able to read the whole conversation or see into
other servers.

This is the real structural difference from a plain API call or library
import: calling a library directly gives that code no isolation from the
rest of your process. MCP servers are architecturally prevented from
seeing each other or your full chat history, and can run as fully separate
OS processes (local) or over a network (remote).

**Without MCP:** connecting an AI app to a database means someone writes
bespoke code *inside the AI app* that knows that database's schema and
driver. **With MCP:** a database MCP server exposes generic `tools/list` /
`tools/call` operations any MCP-speaking client can use — the AI app never
needs database-specific code at all.

*Source: [modelcontextprotocol.io — architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture)*

## 1.3 The three primitives — who decides

| Primitive | For | Controlled by | Example |
|---|---|---|---|
| **Tools** | Actions with side effects | **Model** — the LLM decides when to call it (subject to user-approval UI) | `searchFlights(origin, destination, date)` |
| **Resources** | Read-only context data | **Application** — the host decides what to fetch and how much to inject | `calendar://events/2024`, a file's contents |
| **Prompts** | Reusable instruction templates | **User** — explicit invocation only | `/plan-vacation destination=Barcelona` |

The three-way split exists so each actor keeps the control appropriate to
it. You don't want the model silently deciding to read your entire
calendar (that's the application's job to scope), and you don't want a
tool with real-world side effects (booking a flight) firing without
something closer to explicit trust than "the model felt like it."

*Source: [modelcontextprotocol.io — server concepts](https://modelcontextprotocol.io/docs/learn/server-concepts)*

## 1.4 Transports: stdio vs. Streamable HTTP

**stdio** — the client *spawns the server as a child process* and both
sides exchange newline-delimited JSON-RPC over the subprocess's
stdin/stdout. Nothing more exotic than a pipe. This is why it's inherently
local-only: there's no network layer, so there's no remote-access story,
no auth-over-the-wire concern, and no way for a second machine to reach
it — the spec's own security model for stdio is literally "OS process
isolation." Simple and fast, doesn't scale past one machine.

**Streamable HTTP** — the current remote transport (it replaced an earlier
HTTP+SSE design, now deprecated). Each client message is a plain HTTP POST
to one MCP endpoint; the server replies either as a single JSON object or
a request-scoped SSE stream when it needs to push incremental updates.
This is what makes a shared, multi-user, network-reachable MCP server
possible — and it's exactly where authentication, TLS, and audience
validation become someone's job (the gateway's, in this project) rather
than something "OS isolation" gives for free.

*Sources: [transports overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)*

## 1.5 What building an MCP server actually looks like

Minimal Python example (official `mcp` SDK, `FastMCP` helper):

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")

@mcp.tool()
async def get_forecast(latitude: float, longitude: float) -> str:
    """Get the weather forecast for a location."""
    # ... call a real weather API, format the result ...
    return forecast_text

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

A decorator turns a plain async function into a tool: its name, its
docstring (becomes the tool's `description`, which the model reads to
decide when to call it), and its typed parameters (become the JSON-schema
`inputSchema` the protocol requires) are all derived automatically.
`mcp.run(transport="stdio")` handles the JSON-RPC framing over
stdin/stdout. Official SDKs exist for Python, TypeScript, and others at
[github.com/modelcontextprotocol](https://github.com/modelcontextprotocol).

*Source: [build-server tutorial](https://modelcontextprotocol.io/docs/develop/build-server)*

## 1.6 Where this project's four servers fit

`casemgmt`, `logsearch`, `docsearch`, and `threatintel` are ordinary MCP servers by
every definition above: each is a process a client (Claude Code, via
`.mcp.json`) spawns over stdio, each exposes a set of tools with
JSON-schema inputs, and each is architecturally isolated from the others
per the spec's server-isolation guarantee. What makes them "MCP servers"
specifically, versus a REST API someone points an LLM at via a general
HTTP-calling tool, is exactly the standardization: any MCP-speaking client
can talk to them with zero backend-specific code, tool discovery is a
protocol-level operation (`tools/list`) rather than baked into a prompt —
which is the entire reason a credential-broker gateway in front of them is
a coherent idea at all.

---

# Part 2 — MCP gateways, mechanically

Part 1 explained MCP itself. This part explains **why a gateway sits in
front of multiple MCP servers**, and how each of its jobs actually works
under the hood — not a product comparison (that's `DEVELOPMENT-LOG.md`),
the underlying mechanisms.

## 2.1 The core problem, concretely

Without a gateway, "N MCP servers" means N config entries, N local
processes, and — the part that actually bites — **N places holding a real
credential**. At 20 analysts × 4 servers, that's 80 copies of production
API keys sitting in `.env` files on laptops. The failure mode isn't
inconvenience, it's **unrevocable, unattributable access**: if one analyst
leaves or one laptop is compromised, you cannot rotate "their" access,
because there is no "their" access — everyone shares the same static key.
You can't tell which analyst's query hit a threat-intel API at 3am. This
is credential sprawl with zero audit trail, not a config-management
annoyance.

## 2.2 Aggregation (fan-in), mechanically

A gateway opens N persistent connections to backend MCP servers, collects
each one's `tools/list` response, and re-exposes a merged list over a
single client-facing session. The client only ever sees and calls the
gateway.

The mechanical snag is naming: tool-name uniqueness is only guaranteed
*within* one server, so if two backends both expose a `search` tool, a
naive merge collides. The fix — per the spec's own guidance — is
**namespacing**: reflect the origin server in the name (`casemgmt.search`,
`threatintel.search`) or an equivalent prefix scheme. The gateway maintains a
routing table (`namespaced_name → (backend_connection, original_name)`)
and rewrites each call before forwarding. Session state (which backend
connections are alive, which tools came from where) lives entirely in the
gateway; the client's one session never needs to know four backend
sessions exist underneath it.

## 2.3 Credential brokering, mechanically

The client authenticates to the **gateway** — one credential, one
identity. The gateway holds a mapping table: `(client identity, target
backend) → real backend credential`, resolved from a secret store, not
from the request. On each call, the gateway looks up the right backend
secret and injects it into the *outbound* leg — a header, an env var, a
connection string — that the client never constructs and never sees a
response containing.

Two properties have to hold for "the client never sees it" to be true, not
aspirational:

1. The client-presented credential (if any) must be **explicitly stripped**
   before the outbound call is built, not just ignored — otherwise it can
   ride along by accident.
2. The backend credential must **never appear in anything that flows back**
   to the client — logs, error messages, tool output.

This is structurally the same shape as two well-known patterns: a
**secrets vault/broker** (HashiCorp Vault, 1Password Connect), where an
app authenticates once and the vault injects per-target credentials it
alone holds; and **OAuth token exchange** (RFC 8693), where a service
presents its own token and receives a *different*, narrower token scoped
to a specific downstream resource, minted on its behalf rather than
forwarded. The MCP spec explicitly forbids the naive shortcut — forwarding
the client's own token upstream unmodified — for the same reason token
exchange exists: passthrough breaks per-backend audit, breaks downstream
rate-limiting, and makes every request to every backend look like it came
from the gateway, not from the actual caller.

## 2.4 Composition, mechanically — a worked example

Aggregation is a **router**: one call in, one call out, same shape.
Composition is an **orchestrator with domain logic**: one call in, N calls
out, and a merge step that requires understanding what the results *mean*.

Worked example, deliberately outside this project's domain (IT ops, not
security) to show the pattern is general: an on-call engineer calls
`diagnose_service(name)`. A composing gateway doesn't just proxy this to
one backend — it fans out to a metrics backend (CPU/memory over the last
hour), a logging backend (recent error-level entries), and a
deploy-history backend (last 3 releases), then applies business logic: *if
error rate spiked within 10 minutes of a deploy, surface the deploy as the
probable cause; otherwise rank by anomaly score.* That correlation step is
why composition needs domain-specific code — aggregation's router has no
opinion about what "probable cause" means, and can't, because it never
looks at payload semantics.

## 2.5 Governance, mechanically

**RBAC over tools** means a role is a named *subset of the aggregated tool
list*, not a set of abstract API scopes — e.g. "N1 triage analyst" maps to
12 read-only lookup tools out of 65; "DFIR lead" maps to all 65 including
destructive/write tools. The gateway resolves caller identity → role →
allowed-tool-set at request time, and a call for a tool outside that set
is rejected **before** it ever reaches a backend, not filtered after the
fact.

**Audit logging**, from general practice: a useful record needs *who*
(authenticated identity, not just an IP), *what* (exact tool + parameters,
or a hash if parameters are sensitive), *when* (timestamp, ideally with a
correlation ID tying it to the client session), *target* (which backend
actually served it), and *outcome* (success/failure, error class). All
five matter together — "who called what" alone can't answer "did this
analyst's lookup at 03:14 correlate with the incident we're now
investigating"; you need target and outcome too, or the log is decoration,
not evidence.

## 2.6 Lineage: this is not a new pattern

API gateways (Kong, Envoy, Zuul) have done exactly this — single entry
point, cross-cutting auth/rate-limiting/routing/observability pulled out
of individual services and centralized — for over a decade, for plain
REST/gRPC microservices. An MCP gateway is that same pattern retargeted at
MCP's JSON-RPC-over-tools shape instead of REST endpoints.

What's genuinely new, with **no REST-gateway equivalent**: **tool-poisoning
defense**. A REST endpoint's OpenAPI description isn't fed to an LLM as
trusted operational context it acts on; an MCP tool's description *is* —
so adversarial instructions hidden in a description field, or a "rug pull"
where a previously-approved tool's description silently changes after
approval, are attack classes unique to gateways sitting in front of an
LLM-driven client. A REST gateway has nothing analogous to defend, because
a REST client doesn't read documentation and autonomously decide to act on
it.

---

# Part 3 — API keys, API servers, and security fundamentals

General concepts that apply whether or not MCP is involved at all — the
foundation underneath Parts 1 and 2.

## 3.1 What an API key actually is, mechanically

A static bearer secret: a random string presented on every request
(`Authorization: Bearer <key>` or a custom header like `X-Api-Key`). The
server looks it up — ideally comparing a **hash** of the presented key
against a stored hash, not a plaintext match — and if it matches, grants
whatever that key is scoped to. Possession *is* authorization; there's no
separate identity proof.

Contrast with **OAuth 2.0 access tokens** (RFC 6749): obtained via a
defined flow between four roles (resource owner, client, authorization
server, resource server), short-lived, scoped, issued *after* an
authentication/consent step — not generated once and reused forever.
**JWTs** (RFC 7519) are one common access-token encoding: three
base64url parts — header, payload/claims, signature. A standard
JWS-signed JWT is **signed, not encrypted** — the payload is trivially
decodable by anyone holding the token. Never put a secret *inside* a JWT
payload; the signature proves the issuer didn't tamper with it, it does
nothing for confidentiality.

**When a static API key is still the right tool:** when the counterparty
is a machine, not a user, and there's no OAuth authorization server to
negotiate with — exactly the case for VirusTotal, Shodan, and similar
third-party threat-intel APIs this project's `threatintel` server wraps. OAuth
solves "a user delegates limited access to their account without sharing
their password"; a static key solves "this integration always needs this
scope, forever, until rotated." Forcing OAuth onto a service that only
offers API keys adds nothing.

## 3.2 API key lifecycle and hygiene

- **Generation** — cryptographically random (CSPRNG), sufficient entropy
  (128+ bits). Not a UUID used as a secret, not anything derived from
  predictable input.
- **Storage** — hashed at rest server-side (a DB leak shouldn't hand out
  live keys); encrypted at rest client-side.
- **Rotation** — the real design requirement is supporting **two
  simultaneously-valid keys** during the rotation window: the old key
  keeps working while the new one propagates to every consumer, then the
  old one is revoked. Without dual-validity, rotation means a coordinated
  cutover outage — which is exactly why rotation gets deferred
  indefinitely in practice.
- **Scoping** — least privilege per key: a key that only needs to read
  should not also be able to write, even if the underlying account could.
- **Revocation** — only as good as the fastest path to "no longer
  accepted." A live DB lookup revokes immediately. JWT-signature-only
  validation (no DB round trip, by design, for speed) can't be revoked
  before natural expiry without a separate mechanism (short expiry +
  refresh, or a checked denylist).

## 3.3 What an API server is, structurally

Client-server, request/response. REST is typically **stateless**: each
request carries everything needed to process it (including auth) — the
server holds no per-client session between requests, which is what makes
horizontal scaling trivial (any instance can handle any request).

**Idempotency**: GET, HEAD, OPTIONS, TRACE, PUT, DELETE are idempotent —
calling twice has the same effect as once. POST and PATCH are not. This is
why safe retry logic can blindly retry a PUT/DELETE after a timeout but
must not blindly retry a POST (risk of double-processing).

**Status codes as contract, not decoration:** **401 Unauthorized** means
"I don't know who you are" (missing/invalid credentials); **403
Forbidden** means "I know who you are, and you're not allowed."
Collapsing this distinction in a gateway leaks information either
direction — returning 401 for an authorization failure tells an attacker
their credential *might* work with different permissions; returning 403
for a missing credential confirms a resource exists to someone who never
authenticated at all.

## 3.4 Authentication vs. authorization

**AuthN** answers "who is this." **AuthZ** answers "what can they do." A
system can nail one and fail the other independently — most commonly,
correct AuthN (real SSO, real MFA) paired with missing per-resource AuthZ:
the app confirms *a* valid logged-in user made the request, then fetches
`/api/invoices/{id}` without checking that `{id}` actually belongs to
*that* user. That's **Broken Object Level Authorization** — OWASP
API1:2023, and it's been the #1 API risk across multiple editions
specifically because authentication bugs get caught in testing far more
often than authorization-scoping bugs do.

## 3.5 Secrets management as a discipline

Core, provider-agnostic principles (the specific tool this project chose,
sops+age, is covered in `design/adr/0003-security-controls.md` — this is
the discipline underneath any tool choice): never in source control (not
even "temporarily" — history persists); never in logs or error
messages/stack traces (a caught exception that prints request headers is
a leak); encrypted at rest **and** in transit; least-privilege access to
the secret store itself (the store having a secret doesn't mean every
service should read every secret in it).

**The "secret zero" problem:** whatever credential bootstraps access to
the secrets manager is itself a secret that has to live somewhere
unencrypted-by-that-system. There's no infinite regress out of this — only
a smaller, more auditable blast radius for that one remaining exposed
credential.

## 3.6 OWASP API Security Top 10 (2023) — a short primer

High relevance to a gateway/broker system like this project's:

- **API1 Broken Object Level Authorization** — caller reaches an object
  they shouldn't via ID manipulation.
- **API2 Broken Authentication** — weak or misimplemented token handling.
- **API5 Broken Function Level Authorization** — a regular user reaches
  admin-only functions because role checks aren't enforced per-endpoint.
- **API4 Unrestricted Resource Consumption** — no rate/size limits → DoS
  or cost blowup.
- **API8 Security Misconfiguration** — permissive CORS, verbose errors,
  default credentials left on.

Lower relevance here, shorter mention: **API3** Broken Object *Property*
Level Authorization (over-fetching/mass assignment at the field level);
**API6** Unrestricted Access to Sensitive Business Flows (bots abusing a
legitimate business process); **API7** SSRF (fetching a URL from
unvalidated user input); **API9** Improper Inventory Management
(forgotten/undocumented API versions still live); **API10** Unsafe
Consumption of APIs (trusting third-party API responses without
validation).

*Sources: [RFC 6749 §1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-1.2), [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), [MDN — HTTP request methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods)*

---

## How this connects back to the project

Every mechanism above shows up concretely in this project's own decisions:

- Part 1's server isolation and stdio transport → why the four existing
  servers (`casemgmt`, `logsearch`, `docsearch`, `threatintel`) behave the way they
  do, and why moving them to a shared gateway is a transport-and-trust
  change, not a rewrite (`DEVELOPMENT-LOG.md` §3).
- Part 2's credential-brokering mechanics → `design/adr/0003-security-controls.md`'s
  Credential Vault design, and exactly why `mcp-gateway-registry`'s
  OAuth-only `egress_auth` couldn't satisfy this project's requirement
  (`DEVELOPMENT-LOG.md` §10.1a — static API keys, not OAuth-delegatable).
- Part 2's tool-poisoning explanation → why `Tool Quarantine` and
  `Definition Signer` exist at all (`design/02-components.md`).
- Part 3's 401-vs-403 and secret-zero material → the exact reasoning
  behind `Access Control`'s credential-stripping requirement and why the
  Credential Vault never persists a resolved secret to disk.
