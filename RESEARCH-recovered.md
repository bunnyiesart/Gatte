# MCP Gateway Research - recovered transcript

Session `51abc60d-3176-4bed-966c-c1feddef1b9d`, 2026-08-26 16:16-17:05 (ended on session limit).
Recovered 2026-08-27 from the Claude Code transcript + subagent logs.

---

## Main thread

### MAINTAINER - 2026-08-26T16:16:49

we will start a research into mcp gateways for us to use inside my company , use the dev-context to see what will be usefull and wha twont be usefull i need a lot of differente gateways for consolidating api keys and mcp servers that one call will call lothers , i dontunderstand a lot of this concept so we will have to look onto it

### CLAUDE - 2026-08-26T16:16:54

I'll start by looking at what's in your working directory, especially this "dev-context".

### CLAUDE - 2026-08-26T16:17:35

No `dev-context` file or MCP resource exists in this project — I'll note what I used instead at the end. Starting the research.

### CLAUDE - 2026-08-26T16:18:01

Good landscape signal. Now let me get past the vendor blogs to primary sources.

### CLAUDE - 2026-08-26T16:19:59

Now let me ground this in your actual setup — the MCP servers you already run.

### CLAUDE - 2026-08-26T16:20:34

Confirmed — you already run 4 stdio MCP servers (~72 tools total), and `threatintel` is already consolidating 10 threat-intel API keys. That changes the picture a lot. Two more sources to round out coverage:

### CLAUDE - 2026-08-26T16:21:08

I have what I need. Let me build this as a proper reference doc for your team.

### CLAUDE - 2026-08-26T16:22:39

Research is done. Now building the deliverable.

### MAINTAINER - 2026-08-26T16:24:15

[Request interrupted by user]

### MAINTAINER - 2026-08-26T16:24:18

i dont want an artifact

### CLAUDE - 2026-08-26T16:25:42

Understood — here it is in the terminal.

First, a correction on scope: there's no `dev-context` file or MCP resource anywhere in this project (it's empty except `.claude/settings.local.json`). So I used what I take to be the actual dev context — your real MCP setup in `~/workspace/.mcp.json` and the `threatintel` server. If `dev-context` is something else, point me at it.

---

# Part 1 — What an MCP gateway actually is

The word "gateway" is doing four unrelated jobs in this market. Almost all the confusion comes from mixing them up. Keep them separate:

**Job 1 — Fan-in (aggregation).** N MCP servers behind 1 endpoint. Your client config goes from 4 entries to 1. The gateway re-exports the upstream tools under one namespace and resolves name collisions. This is what most tools calling themselves "gateways" actually do, and it's the *least* valuable of the four.

**Job 2 — Credential broker.** API keys live in the gateway, not on every laptop. Client authenticates to the gateway (OIDC/JWT/token); the gateway injects the real upstream secret. This is the one you asked for, and it's the strongest reason to run one.

**Job 3 — Composition.** One tool call fans out to many downstream calls — "enrich this IP" hits VirusTotal + Shodan + AbuseIPDB + your logs in parallel and returns one merged result. This is a **separate feature** that most gateways do *not* have. Only ToolHive vMCP and (partially) ContextForge do it as a first-class thing.

**Job 4 — Governance.** Per-user RBAC, audit log of who called what, rate limits, tool allowlists, prompt-injection / secret-leak scanning on the traffic.

## The misconception to kill first

**Fan-in does not reduce token cost.** Putting 65 tools behind one endpoint still ships 65 tool definitions into the model's context. Aggregation changes *config ergonomics*, not *context economics*.

For reference, a measurement circulating this year puts 7 MCP servers at ~67,300 tokens of tool definitions — 33.7% of a 200k window — before anyone types anything. Composio users reported 70 tools ≈ 49,351 tokens. Your ~65 tools are in exactly that band.

What *does* fix it, in increasing order of effectiveness:
- **Tool filtering / groups** — expose only the 12 tools a triage analyst needs. Every gateway can do this.
- **Tool search** — Anthropic's Tool Search Tool (shipped Nov 2025) loads a search interface at startup and fetches schemas on demand. Vendor-claimed ~85% reduction.
- **Code mode** — the agent writes a script that calls tools, instead of the tools being individually exposed. Cloudflare claims 99.9% input-token reduction (treat that number as marketing; the direction is real). ToolHive vMCP implements this with Starlark; Bifrost has a version of it.

If context bloat is your real pain, **you want filtering + tool search, not aggregation.** Those are different buttons.

---

# Part 2 — Your actual stack, and what a gateway would and wouldn't buy you

From `~/workspace/.mcp.json`:

| Server | Transport | Tools | Secrets |
|---|---|---|---|
| `casemgmt` | stdio, `docker run -i casemgmt-mcp:dev` | 10 | `~/.config/mcp-docsearch/.env.docker` |
| `logsearch` | stdio, `docker run -i logsearch-mcp:dev` | 10 | same env file |
| `docsearch` | stdio, `docker run -i docsearch-mcp:dev` | 17 | same env file |
| `threatintel` | stdio, `docker run -i threatintel` | 28 | `~/threatintel/.env.docker` — 10 threat-intel keys |

≈ **65 tools**, all stdio, all local containers, all secrets in plaintext env files on your laptop.

## What you already have (so don't buy it twice)

This is the "what won't be useful" half of your question, and it's bigger than you'd expect:

- **`threatintel` is already an API-key gateway.** It holds VirusTotal, AbuseIPDB, Shodan, IPinfo, AlienVault, urlscan, Project Honeypot, MalwareBazaar, ThreatFox, URLhaus behind one MCP server. The "consolidate API keys" job is *done* for threat intel. A gateway would consolidate one more secret (threatintel's own), not ten.
- **`threatintel` already does composition.** `enrich` and `recon` are composite tools — one call, many upstream APIs. You independently invented Job 3.
- **REST→MCP translation is largely done.** ContextForge and Unla's headline feature is turning existing REST APIs into MCP tools without writing a server. You already wrapped CASEMGMT, Logsearch, Docsearch and 10 TI APIs by hand.
- **Container isolation is done.** ToolHive's and Docker MCP Gateway's main pitch is one container per MCP server with minimal privileges. That's already your deployment model.

## What you'd genuinely gain

1. **Keys off analyst laptops.** Right now every analyst who runs this stack needs a copy of `.env.docker` with production VT/Shodan/Logsearch/CASEMGMT credentials. This is your real problem, and it's a distribution problem, not an MCP problem.
2. **stdio → HTTP.** stdio means one process per client, local only. HTTP means one shared deployment, remote analysts, and non-Claude-Code clients.
3. **Per-analyst audit.** For a SOC this is arguably the biggest win: a log of which analyst ran which VT lookup against which IOC. You currently have no such record.
4. **Per-role tool views.** An N1 triage analyst gets 12 tools; a DFIR lead gets all 65. Fixes context bloat *and* least-privilege in one move.
5. **One more genuinely useful REST→MCP target.** `fortigate_report.py`, `patrus_report.py`, `kerberos_report.py` are sitting there as scripts. ContextForge/Unla could expose those as tools via config instead of you writing three more MCP servers.

## The category to rule out immediately

**Every managed SaaS gateway.** Composio, Arcade, MintMCP, Lunar MCPX, Cloudflare MCP Server Portals, Merge, Nango, Bedrock AgentCore. Your traffic is customer CASEMGMT case data, Logsearch telemetry and IOCs. Routing that through a third-party control plane is a data-egress decision, not a convenience decision — and for a Brazilian security provider it's an LGPD conversation with your customers, not a tooling choice. Arcade won the one hands-on comparison I found (only product to finish a multitenant B2B build in 60 min) and it's still the wrong shape for you.

That eliminates roughly half the market before you evaluate anything.

---

# Part 3 — The landscape

Self-hostable, verified against primary sources:

| Tool | Owner / License | Stars | Fan-in | Keys | Composition | Governance | Fit for you |
|---|---|---|---|---|---|---|---|
| **IBM ContextForge** | IBM, Apache-2.0 | 4.4k | Virtual servers + mDNS federation | Encrypted creds, JWT/OAuth, SSRF protection | Partial | Strong: RBAC, OTel, rate limit, Admin UI | **Strong** — only one with real federation + REST/gRPC→MCP |
| **ToolHive + vMCP** | Stacklok, Apache-2.0 | ~2k | vMCP virtual servers, conflict resolution | Encrypted secrets, OIDC, per-client policies | **Yes** — composite tools, workflow engine, Starlark code mode | Cedar-style policies, audit log, K8s operator | **Strong** — the only one that does your Job 3 properly |
| **agentgateway** | Linux Foundation, Apache-2.0 | 4.6k | MCP tool federation | JWT/API key/OAuth | No | RBAC via CEL, TLS, OTel, K8s Gateway API | Good if you want LF-governed infra and LLM routing too |
| **MetaMCP** | MIT | 2.6k | Servers→Namespaces→Endpoints (3-level) | `${VAR}` refs, OIDC, MCP OAuth | No | Middleware hooks, tool overrides | Good mid-weight; rate limits don't cluster |
| **MCPJungle** | MPL-2.0 | 1.2k | Single `/mcp`, Tool Groups | `${VAR}`, bearer tokens, per-client allowlist | No | Enterprise mode: tokens + OTel | **Best cheap pilot** — no OAuth yet, groups immutable |
| **Docker MCP Gateway** | Docker, MIT | 1.5k | Catalog-based, dynamic discovery | Docker Desktop secrets, OAuth flows | No | Container isolation, interceptors | Local dev only — **Docker Desktop dependency kills server deploy** |
| **Unla** | AmoyLab, MIT | 2.2k | Server grouping, multi-tenant | OAuth pre-auth | No | Web UI, hot-reload YAML | Best if REST→MCP is the priority; "rapid development" |
| **Lasso MCP Gateway** | MIT | 386 | Wraps servers via `mcp.json` | Central secret store | No | **Secret masking, PII (Presidio), prompt-injection detection, server scanner** | Interesting as a *sidecar*, too small to be your gateway |
| **Obot** | Open source | — | Yes + private registry | OAuth (external IdP required) | No | Strong governance | Credible; one reviewer was blocked by mandatory external OAuth setup |
| **Bifrost** | Maxim AI | — | Flat | Virtual keys | Code Mode | Minimal | Pick only if latency is the binding constraint |
| **MCP Mesh** | deco.cx | — | Virtual MCPs | — | Smart tool selection | Multi-level RBAC | No federation docs; unverified |
| **mcp-proxy** (tbxark) | OSS | — | Flat + tool filtering | — | No | None | Fine as a 100-line-of-config stopgap |
| **Supergateway** | OSS | — | No | No | No | No | **Transport bridge only** — stdio→SSE/HTTP. Useful as a component |
| **Kong / Portkey / TrueFoundry** | Commercial | — | Yes | Yes | Varies | Enterprise | Kong needs a licensed data plane; TrueFoundry's identity setup failed in a 30-min hands-on test |
| **Microsoft MCP Gateway** | Microsoft | — | K8s-native session routing | — | No | — | **Not verified this pass** — flag for round 2 |

Worth knowing: the most careful survey of this space (Q1 2026) concludes that **no tool yet combines** a three-level hierarchy, 1:many endpoint-to-namespace mapping, first-class federation, per-client tool visibility, *and* lightweight self-hosting. Expect to compromise on one axis.

---

# Part 4 — What I'd pilot

**Tier 1, this week — MCPJungle.** Cheapest way to learn the concept with your own stack. Single binary or compose, SQLite, registers your 4 stdio servers, exposes one `/mcp`. Build two Tool Groups — `n1-triage` (~12 tools) and `dfir-full` (65) — and measure the context difference. You'll understand fan-in and filtering in an afternoon. Limits: no OAuth, tool groups can't be edited (delete + recreate).

**Tier 2, if the pilot proves the value — ContextForge or ToolHive.** These are the two real answers, and they split cleanly:

- **ContextForge** if the priority is *federation and getting more of your stack into MCP* — virtual servers, REST/gRPC→MCP for your report scripts, Postgres + Redis + Helm, and IBM sells 24×7 support with a 2h SLA if that ever matters to a customer contract. Cost: 55+ DB tables, 894 open issues, a real operations burden.
- **ToolHive** if the priority is *composition and policy* — it's the only one that gives you "one call fans out to many" as a supported feature, plus Starlark code mode for the token problem and Cedar-style per-client authorization. Cost: smaller ecosystem than IBM's.

Given you explicitly asked for "one call will call others," **ToolHive vMCP is the closest match to what you described.** Given your `threatintel` server already does that for threat intel, ContextForge may be the better long-term platform.

**Wildcard — Lasso as a sidecar.** Not your gateway, but its plugin set (secret masking, Presidio PII detection, prompt-injection scanning, MCP server reputation scanner) is aimed exactly at a security team. Worth reading even if you never deploy it.

---

# Part 5 — Risks the gateway introduces

Adding a gateway is not free. For a security team these should be in the evaluation from day one:

- **Confused deputy.** The gateway holds broad credentials and acts on behalf of users who don't have them. Get audience-bound tokens (OAuth 2.1 + PKCE) or you've built a privilege-escalation box. This is the settled guidance in the spec and in OWASP's MCP cheat sheet.
- **Tool poisoning.** Malicious instructions hidden in tool descriptions, parameter schemas, or return values. A gateway *helps* (you can scrub and pin descriptions) but a gateway that auto-discovers upstream servers *hurts* — it widens what can inject into your analysts' context. Don't enable auto-discovery from public registries.
- **Blast radius.** Today a poisoned `threatintel` tool can't reach CASEMGMT. Behind one gateway with one credential set, it can. The current guidance is to keep sensitive servers isolated from general-purpose ones — which argues for *two* gateways (internal-data vs external-TI), not one.
- **Single point of failure.** Your whole SOC tooling stops when the gateway does. stdio has no such failure mode.

---

# Part 6 — Three decisions I need from you before round 2

These change the answer materially and I can't derive them:

1. **Who consumes it?** Just you, or N analysts with different privileges? If it's just you, honestly — a gateway may not be worth it, and the right fix is a secrets manager for those `.env.docker` files.
2. **One gateway or two?** Given the blast-radius argument, splitting internal (CASEMGMT/Logsearch/Docsearch) from external (threatintel) is defensible. Doubles the ops cost.
3. **What's the actual pain — config, keys, or context?** Config → any aggregator works. Keys → this is a secrets-management problem wearing a gateway costume. Context bloat → you want tool search / code mode, and the shortlist collapses to ToolHive or Bifrost.

Tell me which of those matter and I'll do a hands-on round 2 against your real stack.

**Sources:**
[MCP Aggregation, Gateway, and Proxy Tools: State of the Ecosystem Q1 2026](https://www.heyitworks.tech/blog/mcp-aggregation-gateway-proxy-tools-q1-2026) · [Best MCP Gateways: A Hands-On Comparison](https://manveerc.substack.com/p/best-mcp-gateways) · [IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge) · [stacklok/toolhive](https://github.com/stacklok/toolhive) · [ToolHive Virtual MCP Server docs](https://docs.stacklok.com/toolhive/guides-vmcp/) · [docker/mcp-gateway](https://github.com/docker/mcp-gateway) · [metatool-ai/metamcp](https://github.com/metatool-ai/metamcp) · [agentgateway/agentgateway](https://github.com/agentgateway/agentgateway) · [mcpjungle/MCPJungle](https://github.com/mcpjungle/MCPJungle) · [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway) · [mcp-ecosystem/mcp-gateway (Unla)](https://github.com/mcp-ecosystem/mcp-gateway) · [Best Open Source MCP Gateways](https://www.scalekit.com/blog/best-open-source-mcp-gateways) · [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) · [The state of MCP security in 2026 (Microsoft)](https://techcommunity.microsoft.com/blog/microsoft-security-blog/the-state-of-mcp-security-in-2026/4531327) · [MCP Security Notification: Tool Poisoning Attacks (Invariant Labs)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) · [MCP Context Bloat Fix 2026](https://mcp.directory/blog/mcp-context-bloat-fix-2026-tool-search-code-mode-progressive-disclosure)

### MAINTAINER - 2026-08-26T16:36:33

there is a few question that i dotn have answered so we will put in two differente scenarios , habving a central mcp server being the api keys will be stored in that server and the other s will have on ekey to this central mcp server

### CLAUDE - 2026-08-26T16:37:33

Before we split into scenarios, there's one thing in that description I need to flag, because it decides whether the design is safe or not.

## The fork hiding in "the others will have one key to the central server"

Your sentence describes two very different topologies, and only one of them is safe.

**Central node *in front* (a gateway/proxy) — safe.** The agent calls `virustotal(ip=…)`. The gateway looks up the real VT key internally, makes the outbound HTTP call itself, and returns only results. The key never appears in any MCP message, never enters a tool argument, never enters a tool response, never touches the model's context. Clients hold exactly one credential: a token to the gateway.

**Central node *beside* (a secrets service exposed over MCP) — dangerous.** If the central server exposes anything shaped like `get_secret(name)`, then every connected agent can read your VirusTotal, Shodan and Logsearch credentials *into its context window*. That context gets logged, cached, and shipped to a model provider. Worse: your agents read untrusted input all day — Logsearch log lines, IOC reports, tool descriptions from upstream servers. A prompt injection in any of those can induce the agent to fetch a key and leak it. You'd have built Vault with an LLM holding the root token.

So: **credentials must be injected, never served.** That's the invariant. Everything else is a deployment detail.

There's also a consequence you may not have noticed: if the central node is in front and makes the outbound calls, the other servers need *zero* keys — not even one. The "one key each" only makes sense if the other servers are calling *through* the central node, which means the central node is a gateway and the other servers are its clients. That's a valid design (it's how you'd federate), just a different one from "central key store."

## Which two scenarios

I can model this properly, but I'd be guessing at the axis you have in mind, and guessing wrong means the whole comparison is off-target.

### CLAUDE - 2026-08-26T16:39:25

What would you like to clarify?

For context, the thing I'm unsure about is narrow: you said "two different scenarios," but the only architecture you described was the central key store. So I don't know whether the two scenarios are meant to be two variations of that design, two different team sizes it has to serve, or something else entirely — and I'd rather not guess.

Tell me what you had in mind and I'll work from that.

### MAINTAINER - 2026-08-26T16:39:35

i dont really now i was asked to create one that kinda does that

### CLAUDE - 2026-08-26T16:39:55

That's the most useful thing you could have told me — it reframes the whole question. You were handed a solution ("build a central MCP server that holds the keys"), not a problem. So let me draw the two scenarios along the axis that actually matters for you: **configure an existing gateway, or write one.**

### CLAUDE - 2026-08-26T16:40:37

---

# The two scenarios

Both deliver what you were asked for: one central MCP endpoint that holds the API keys, with everything else holding a single credential pointing at it. They differ in how you get there.

## Scenario A — Configure an existing gateway

You deploy something off the shelf and spend your time on config, not code.

Concretely, with your stack:

```
                       ┌─ keys: VT, Shodan, AbuseIPDB … (10)
analyst ──token──> [ gateway ] ──> threatintel        ─┘
                        │  ├──────> casemgmt
                        │  ├──────> logsearch
                        │  └──────> docsearch
                        └─ keys: CASEMGMT, Logsearch, Docsearch creds
```

- The 4 servers stay exactly as they are — same Dockerfiles, same stdio, no changes.
- The env files move off laptops and onto the gateway host.
- Each analyst gets one token. Revoking someone is one command.
- You get audit logging, per-role tool groups and health checks for free.

**What you'd actually do:** register 4 servers in a config file, define 2–3 tool groups, put it behind TLS, point clients at one URL. Days of work, most of it deployment rather than development.

**The catch:** you inherit someone else's operational surface. ContextForge is 55+ database tables, Postgres + Redis, and ~900 open issues. MCPJungle is a single binary with SQLite but has no OAuth yet. You're accepting an upstream dependency on a project that's 6–18 months old.

## Scenario B — Write it yourself

You build the central MCP server literally as described. This is what the request said, so it deserves a fair hearing.

**What you'd be signing up to write:**

| Piece | Difficulty | Notes |
|---|---|---|
| Serve MCP over HTTP | Easy | SDK handles it |
| Spawn/manage 4 stdio children | Moderate | Lifecycle, restarts, zombie containers |
| Proxy `tools/list` + `tools/call` | Easy | Mostly forwarding |
| Namespace tools, resolve collisions | Easy | Prefix names |
| Inject credentials outbound | **Easy to get catastrophically wrong** | This is the invariant from my last message |
| Client auth + token issuance | Moderate | Don't hand-roll crypto |
| Per-client tool filtering | Moderate | Where the real value is |
| Audit log | Easy | But needed for SOC |
| Health, reconnect, backpressure | Hard | Where homegrown proxies die |
| Keep up with MCP spec changes | Ongoing | Spec moved 3× in 18 months |

**Honest assessment:** a working prototype is a weekend. Something you'd trust holding production VirusTotal and CASEMGMT credentials for a team of analysts is months, and it never stops needing maintenance. The first 70% is genuinely easy, which is exactly why this gets underestimated.

**When B is still right:** if the requirement is that no third-party code touches customer security data, or the thing has to run somewhere you can't deploy Postgres. Those are legitimate reasons, and you're a security company, so they might apply.

---

# My recommendation

**Scenario A, with a specific twist:** start with MCPJungle this week — single binary, SQLite, registers your 4 stdio servers as-is. Not because it's the final answer, but because it makes the concept concrete in an afternoon and gives you something to show whoever asked. You'll learn more from one working gateway than from any more research.

Then you'll know enough to have the real conversation about ContextForge vs ToolHive vs building.

The thing I'd push back on: **you were asked for a key store, but the valuable part is the audit log.** Right now nobody can tell which analyst ran which VirusTotal lookup against which customer IOC. Consolidating keys is the stated goal; provable attribution is probably the actual value, and it's the easier sell internally.

---

# Questions to take back

You don't need to answer these — whoever asked you does. Paste them:

1. Is the goal getting credentials off analyst laptops, or getting an audit trail of who queried what? Both are achievable; they point at different designs.
2. How many people will use this, and do they all get the same access? If N1 analysts and DFIR leads should see different tools, say so now — it's cheap to design in, expensive to retrofit.
3. Is running an existing open-source gateway acceptable, or does this have to be our own code? This is the single biggest scoping question.
4. Does customer case data (CASEMGMT/Logsearch) need to stay isolated from external threat-intel calls (VirusTotal/Shodan)? If yes, we need two gateways, not one.
5. Who operates it when it breaks? A central gateway means every analyst's tooling stops when it does.

Question 3 is the one that decides whether this is a week or a quarter.

One correction to something in the original request, worth passing along: `threatintel` is *already* the central key store they're describing — it holds all 10 threat-intel keys behind one MCP server. So part of what's being asked for exists. The gap is that it's on your laptop instead of on a server, and there's no per-analyst identity in front of it.

### MAINTAINER - 2026-08-26T16:51:46

i need more trade offs analise with different agents to check what is worth and what isnt worth for a team with max 7 people

### CLAUDE - 2026-08-26T16:52:13

You asked for agents, so I'll fan out. Five independent analyses, each on a different trade-off axis, all sized to a 7-person team.

### CLAUDE - 2026-08-26T16:53:44

Five agents running in parallel, each on a different axis, all constrained to "team of 7, no platform engineer":

| Agent | Axis | Core question |
|---|---|---|
| 1 | **Ops cost / TCO** | Which candidates are over-engineered at 7 people? Real service counts, stand-up hours, monthly maintenance, upgrade breakage. |
| 2 | **Security controls** | Which controls earn their keep at 7 people and which are theater? Is per-user OIDC justified? One gateway or two? |
| 3 | **Build vs adopt** | Honest effort sizing for writing your own broker, plus MCP spec churn as the maintenance argument. Includes a third option: extend `threatintel`. |
| 4 | **Token economics** | Baseline cost of your 65 tools, and which mechanism actually helps — filtering, tool search, code mode, or composite tools. |
| 5 | **The skeptic** | Argues the cheapest path: is a gateway worth it at all, or is this a secrets-manager problem wearing a gateway costume? |

Agent 5 is the one I'd read first when it lands. Your stated problem is "keys scattered on laptops," and that has a much cheaper solution than a gateway — I want that argued properly rather than assumed away, because the risk here is building infrastructure to solve a problem `sops` or `op run` handles in an afternoon.

Agent 3 also has an angle worth flagging in advance: you already built `threatintel`, which is a working key-consolidating MCP server with composite tools. "Extend the thing that already works" is a real third option that management's framing skips over, and it's the one that most often wins for small teams.

I'll consolidate all five into a single trade-off matrix when they report — including where they disagree, which is usually the most informative part.

### CLAUDE - 2026-08-26T16:55:17

Agent 2 (security) is back, and it overturns something I told you earlier. Worth flagging now rather than burying it in the final consolidation.

**I was wrong about the two-gateway split.** I suggested separating internal case data from external threat intel to limit blast radius. That doesn't work, and the reasoning is clean: the attack path is a poisoned string in a Logsearch line or IOC report → agent reads it → agent calls `list_case_iocs` → agent submits case data to `urlscan`/`virustotal`, where public submission *is* the exfiltration channel. Both toolsets sit in **one model context**, so two gateways don't interrupt anything. You'd double the ops cost for a boundary the agent walks straight through.

The fix is to split the **context**, not the infrastructure: one gateway, two session profiles. A `triage` profile (threatintel + read-only logsearch/docsearch) and a `casework` profile (casemgmt + read-only logsearch/docsearch, no threatintel egress). Enrichment and case data never co-occur. Same gateway, two allowlists, near-zero extra ops.

Other findings that matter at your scale:

- **Insist on three things:** credential injection (keys resolved server-side, never in tool arguments or results), per-analyst tokens with audit shipped to your own Logsearch — you already run the SIEM, so attribution is nearly free — and a two-tier allowlist separating the ~5 mutating tools from the ~60 read tools, with human confirmation on writes.
- **Skip Cedar/CEL policy engines.** 65 tools × 2 roles is a 65-line list. A policy DSL is something nobody on a 7-person team will remember how to debug at 3am.
- **Skip prompt-injection detection as a relied-upon control.** There's published evasion research against the commercial and OSS detectors, including the ones Lasso wraps. Constrain the *capability* (allowlist, no writes without a human), not the *string*.
- **Skip Presidio PII masking.** Your team's job is triaging PII-bearing customer telemetry; masking it breaks the work. Handle LGPD through retention and access logs instead.
- **Per-user OIDC is conditional:** worth it if you already have Google Workspace or Entra (couple of hours of config), not worth standing up Keycloak for 7 people. Named static tokens, revocable at offboarding, are adequate.

One useful spec detail it surfaced: the gateway must act as its own OAuth client upstream and **must not** pass the analyst's token through to backends. That's the confused-deputy guard, and it's a spec requirement, not a preference.

Four agents still running — ops cost, build vs adopt, token economics, and the skeptic. I'll hold the full matrix until they land.

### CLAUDE - 2026-08-26T16:56:23

Agent 1 (ops cost) is back, and it's blunt: **ContextForge is disqualified at your scale.**

The numbers: its default compose stack is **8 services** — nginx, gateway, Postgres, pgbouncer, migrations, Redis, plus demo containers — and the documented "full stack" runs 3 gateway replicas. There's no supported SQLite production path. Releases land every 1–2 weeks with Alembic migrations, so Postgres backups become mandatory. Recent releases have already broken startup (`AUTH_ENCRYPTION_SECRET` now refuses to boot), dropped Python 3.11, and flipped root URIs to deny-by-default. You'd be running a replicated Postgres/Redis/pgbouncer stack with fortnightly breaking upgrades to front four containers. I put it on the shortlist earlier on federation strength and IBM's support SLA; on operational grounds at 7 people that was the wrong call.

Its ranking:

| | Services | Stand-up | Ongoing | Verdict |
|---|---|---|---|---|
| **mcp-proxy** | 1 stateless container | 2–4 h | <1 h/mo | **Best value** |
| **Docker MCP Gateway** | 0 stateful | 2–4 h | ~1 h/mo | Good — your images are already `docker run -i` |
| **ToolHive + vMCP** | 1 process, no DB, no K8s | 4–8 h | 2–4 h/mo | **Best upgrade path** |
| MCPJungle | 1–2 containers | 4–6 h | 1–2 h/mo | Credible, pre-1.0 (v0.4.6), no OAuth |
| MetaMCP | 2 containers + custom nginx | 1 day | 2–3 h/mo | Last release ~8 months stale, 105 open issues, forked the SDK's stdio transport |
| agentgateway | 1 Rust binary | 1–2 days | 2–4 h/mo | Wrong shape — proxy-shaped config |
| ContextForge | **8** | 3–5 days | 4–8 h/mo | **Avoid** |
| Build your own | — | 2–4 weeks | 4+ h/mo forever | Unpaid on-call forever |

Two things that correct my earlier report: nothing here actually *mandates* Kubernetes or an external IdP — ContextForge, MetaMCP, ToolHive and Unla all authenticate with internal auth, so the "you'll need Keycloak" cost I implied isn't real. And ToolHive turns out to be the only candidate that directly kills your plaintext `.env` problem, via an OS-keyring-encrypted secret store injected per container. Its price is weekly pre-1.0 breakage.

Note this partly agrees with where I expect the skeptic to land — `mcp-proxy` on `dfir.bunnyiesart.com` gets the 10 keys off 7 laptops for half a day of work and no database. Whether that's *sufficient* is exactly what agents 3 and 5 are arguing.

Three still running: build vs adopt, token economics, the skeptic.

### CLAUDE - 2026-08-26T16:57:43

Agent 5 (the skeptic) is back and it argues **no gateway**, concretely enough to act on today.

Its core move: your finding is "plaintext secrets at rest on 7 laptops," and that closes in about a day with SOPS + age — no daemon, nothing new that can be down at 3am during an incident.

```sh
# ~/bin/mcp-run
exec sops exec-env "$REPO/secrets/mcp.enc.env" \
  "docker run --rm -i -e THREATINTEL_VIRUSTOTAL_API_KEY -e THREATINTEL_SHODAN_API_KEY ... threatintel:latest"
```

One age keypair per analyst as recipients in `.sops.yaml`; one encrypted env file committed to a private repo; `.mcp.json` becomes `"command": "mcp-run"`. `sops exec-env` decrypts into the child process environment only — plaintext never touches disk — and `docker run -e VAR` with no `=` forwards from the caller's environment. Both `.env.docker` files stop existing. Git history becomes your key-change audit log for free.

One operational detail it caught that's easy to get backwards: on offboarding, run `sops updatekeys` to drop the recipient **then** `sops rotate -i`. The docs are explicit that reversing that order can leave the removed key with access.

On "one call calls others" it's equally direct: put composite tools in `threatintel`. It already fans one call out to 10 APIs via `enrich`/`recon`. A cross-server `triage_ioc` (threatintel enrich + docsearch search + casemgmt lookup) is a function in a codebase your team owns, in a language they know. A gateway workflow engine gets you the same call graph plus a DSL, a config format, and a new failure domain — and at 65 tools you aren't orchestrating enough to amortise it.

**The honest limit it states plainly:** SOPS still puts the plaintext key into a process on the analyst's laptop at runtime. That's acceptable while every analyst is a trusted DFIR engineer already authorised to query VirusTotal. It stops being acceptable when a machine you don't control needs the tools, or when you must attribute quota burn per analyst.

Where it converges with agent 1: if management needs to *see* a central MCP server, `mcp-proxy` on `dfir.bunnyiesart.com` is the honest answer — one stateless container, per-server bearer tokens, `toolFilter` allow/block lists, request logging, and `-expand-env` so secrets come from the host's systemd `EnvironmentFile` rather than a config file. Take it as an ops change, not a governance platform. It gives you no per-analyst identity (tokens are shared strings), no rate limiting, no quota accounting, no approval gates.

**The trigger that I think most likely applies to you.** It lists seven conditions that flip the answer, and calls out multi-tenant separation as the strongest — analysts being prevented from querying the wrong customer's Docsearch indices. SOPS cannot touch that. You're a managed security provider with Logsearch and Docsearch presumably carrying more than one customer's telemetry, so this may already be true rather than hypothetical. The others: headcount past ~15, a customer audit or DPA demanding per-user attribution, non-employees using the tools, vendor quota enforcement, an actual key leak, or approval gates on writes.

That's the question I'd want answered before choosing, and it's a question about your customer contracts, not about MCP.

Two agents left: build vs adopt, and token economics.

### CLAUDE - 2026-08-26T17:05:12

Agent 4 (token economics) came back with measured numbers rather than estimates — it actually spawned your four containers and counted the real `tools/list` output. **This corrects a claim I made in my first report.**

I said your ~65 tools sat in the same band as the "70 tools ≈ 49,351 tokens" figure. They don't. Measured with `o200k_base`:

| Server | Tools | Tokens |
|---|---|---|
| docsearch | 17 | 3,860 |
| threatintel | 28 | 2,848 |
| casemgmt | 10 | 2,307 |
| logsearch | 10 | 1,156 |
| **Total** | **65** | **10,171** |

**~10k tokens, not ~50k.** That's ~5% of a 200k window and ~1% of the 1M window you're actually running. Your servers are lean — 156 tokens per tool average against the bloated wrappers those horror-story numbers come from. So context bloat is not one of your problems, and I overstated it by roughly 5×.

Consequences:

- **Fan-in is measurably *worse* for tokens.** Every candidate forwards the union of upstream `tools/list`, and five of six prefix tool names (`vmcp_iris_list_cases`, `Server__tool`). Re-serializing your actual schemas with a gateway prefix: **+195 tokens, +1.9%**. Aggregation buys auth and audit, never context.
- **Tool search is already on.** `ENABLE_TOOL_SEARCH` defaults on in Claude Code, which takes your 10,171 down to roughly a 435-token names-only index — about 96%. You have the best available mechanism already, for free, with no gateway.
- **One tool is 8% of your entire surface.** `casemgmt/list_cases` is 847 tokens — a 2,016-character description plus 13 filter params. Trimming that one description is a bigger win than any gateway.
- **A trap worth knowing:** Claude Code *disables* tool search when `ANTHROPIC_BASE_URL` points at a non-first-party host, because most proxies don't forward `tool_reference` blocks. So putting Bifrost or a similar LLM proxy in front would turn your 435-token surface back into ~10,400. A gateway sold on token savings would cost you the savings you already have.
- It also corrected a thing I'd have gotten wrong: tool search does **not** break prompt caching — deferred tools are excluded from the cached prefix by design.

Its recommendation is half a day of work and no infrastructure: trim `casemgmt/list_cases`, mark your ~8 always-used tools `"anthropic/alwaysLoad": true` in `_meta`, and split into two role-based projects via `enabledMcpjsonServers` (N1 triage = threatintel + casemgmt; hunting = logsearch + docsearch). A curated 13-tool triage set measures at 1,884 tokens, down 81%.

Bottom line from this axis: **ignore all six gateways, code mode, and embedding-based optimizers for context reasons.** At 10k tokens that's roughly $0.03 per full-context Opus call. Revisit past ~150 tools. Any gateway you adopt has to be justified on security and custody grounds, priced separately — which is exactly what agents 2 and 5 were arguing about.

Last agent still running: build vs adopt.

### CLAUDE - 2026-08-26T17:05:13

You've hit your session limit · resets 3:10pm (America/Sao_Paulo)

### MAINTAINER - 2026-08-26T19:04:48

Continue from where you left off.

### CLAUDE - 2026-08-26T19:04:48

No response requested.

### MAINTAINER - 2026-08-26T19:04:51

ok continue

### CLAUDE - 2026-08-26T19:06:29

Four of five agents landed. Agent 3 (build vs adopt) died on a session limit before reporting — I'll cover that axis myself below and mark it as my own analysis rather than pretend it's research. One agent also spawned a sub-agent that did a deep source-level read of ContextForge, and it turned out to be the most decision-relevant thing in the batch.

---

# The finding that reframes the whole question

**All four of your servers are stdio, and stdio is the blind spot of nearly every MCP gateway.**

From the ContextForge source read — a maintainer states it directly in [discussion #1086](https://github.com/IBM/mcp-context-forge/discussions/1086):

> "gateways are network-accessible HTTP endpoints — they have a `url` field pointing to a remote (or local) MCP server. STDIO requires spawning a local process"

So to put `casemgmt`, `logsearch`, `docsearch` and `threatintel` behind ContextForge you must run **one `mcpgateway.translate` process per server**, supervised by you, and *you* supply each process's environment. The verified consequence: **the gateway's database stores no env vars for stdio children.** Its AES-256-GCM encrypted credential store, per-user OAuth and Vault backend — the entire reason you'd tolerate its weight — apply only to HTTP/SSE upstreams. Your keys would end up in systemd, not in ContextForge.

Generalize that and the shortlist collapses. "The gateway holds the keys" is only true if the gateway **spawns the containers itself**. That's the real axis:

| | Who spawns your containers | Can it actually hold your keys? |
|---|---|---|
| **ToolHive** | ToolHive does | **Yes** — OS-keyring-encrypted store, injected per container |
| **Docker MCP Gateway** | Docker does | Yes, via Docker Desktop secrets (but Desktop dependency) |
| mcp-proxy | it spawns children, env inherited from host | Partly — secret lives in systemd `EnvironmentFile` |
| ContextForge / agentgateway / MetaMCP / MCPJungle / Unla | you do, out of band | **No** — you supply the env anyway |

If the goal management gave you is "central server stores the API keys," most of the market cannot do that for your stack. That single fact eliminates more candidates than every other criterion combined.

---

# Where the agents agreed

All four converged, from different directions:

1. **Context bloat is a non-problem for you.** Measured, not estimated: 10,171 tokens for 65 tools. Tool search is already on and takes that to ~435. Aggregation *adds* 1.9% via name prefixing.
2. **ContextForge is wrong at 7 people.** 66 DB tables, a 2,740-line compose with 40 services (8 default, including pgbouncer), an `.env.example` carrying ~1,150 settings, releases every ~2 weeks each with breaking changes, ~895 open issues and ~298 open PRs. Its Rust runtime shipped and was deprecated within months — architectural direction is still moving.
3. **Composite tools belong in `threatintel`.** It already fans one call out to 10 APIs. A cross-server `triage_ioc` is a function in a codebase you own. A workflow engine buys you the same call graph plus a DSL and a new failure domain.
4. **The real finding is plaintext secrets at rest on 7 laptops** — and that is cheaper to fix than to platform around.

One correction between agents worth noting: the ops agent said ContextForge has no documented SQLite path; the source read found one (`DATABASE_URL=sqlite:///./mcp.db`, single container). So it *can* run light. It's the 1,150 config knobs and fortnightly breaking changes that disqualify it, not the database.

---

# Where they disagreed, and how it resolves

The skeptic says no gateway: 7 named people, just ask who ran the query. The security agent says per-analyst attribution is non-negotiable for a managed security provider, because "who queried customer X's case data on the 14th" is the question a customer audit actually asks.

**Both are right, conditionally.** It resolves entirely on one question: *do your customer contracts, or any certification you hold or want, require per-user attribution of queries against customer data?* That's a contracts question, not an MCP question, and it's the only input that changes the answer.

The security agent also overturned the two-gateway split I proposed earlier — worth restating because it's counterintuitive. Splitting internal-vs-external gateways doesn't cut the attack path, because both toolsets still land in **one model context**: poisoned Logsearch line → agent reads it → agent calls `list_case_iocs` → agent submits case data to `urlscan`, where public submission *is* the exfil channel. Split the **context**, not the infrastructure: a `triage` profile (threatintel + read-only logs) and a `casework` profile (casemgmt + read-only logs, no threatintel egress). Same gateway, two allowlists, near-zero extra ops.

---

# Consolidated: worth it / not worth it at 7 people

| Thing | Verdict | Why |
|---|---|---|
| Getting keys out of plaintext `.env` on laptops | **Worth it — do first** | The only confirmed finding. ~1 day with SOPS+age |
| Credential injection (keys never in tool args/results) | **Worth it — non-negotiable if you build anything** | Spec-aligned; gateway must be its own OAuth client upstream and must not pass the analyst's token through |
| Per-analyst tokens + audit → your own Logsearch | **Worth it** | You already run the SIEM. Attribution is nearly free and it's the audit answer |
| Two-tier tool allowlist, human confirm on the ~5 write tools | **Worth it** | 65 tools × 2 roles is a 65-line list. Constrains capability, which is what actually works |
| Role-based tool sets (`enabledMcpjsonServers`) | **Worth it — free** | Curated 13-tool N1 set measures 1,884 tokens, −81%. No infrastructure |
| Trimming `casemgmt/list_cases` | **Worth it — 30 min** | One tool is 847 tokens, 8.3% of your whole surface |
| Composite tools for "one call calls others" | **Worth it — in threatintel** | Already built, in-process, no extra hop |
| Aggregation / fan-in for its own sake | **Not worth it** | Costs +1.9% tokens, buys config ergonomics only |
| A gateway for token savings | **Not worth it — actively harmful** | An LLM proxy on `ANTHROPIC_BASE_URL` *disables* tool search; your 435-token surface reverts to ~10,400 |
| ContextForge | **Not worth it** | Can't hold stdio creds; 1,150 knobs; fortnightly breaking changes |
| Cedar / CEL / OPA policy engines | **Not worth it** | A DSL nobody will remember how to debug at 3am |
| Prompt-injection detection as a relied-upon control | **Not worth it** | Published evasion research against the detectors these gateways wrap |
| Presidio PII masking on egress | **Not worth it** | Your job is triaging PII-bearing telemetry; masking breaks the work |
| Full OIDC/Keycloak | **Not worth it unless you already have an IdP** | If you have Workspace or Entra, take it — ~2h. Otherwise it's a new prod dependency |
| Two separate gateways | **Not worth it** | Doesn't cut the attack path. Two session profiles instead |
| MetaMCP | **Not worth it** | Last release ~8 months stale, 105 open issues, forked the SDK's stdio transport |
| Building your own | **Not worth it** | See below |

---

# Build vs adopt — my analysis, since that agent failed

You *can* build this; you already built `threatintel`, which is the same shape. Two arguments against, and I'd weight the second heavily:

**The 80/20 cliff.** Transport, proxying `tools/list`/`tools/call`, and namespacing are genuinely easy. What kills homegrown proxies is the rest: stdio child lifecycle and zombie containers, reconnect, cancellation and timeouts, backpressure, session management for stateful servers, and health checks. A prototype is a weekend. Something you'd trust holding live VirusTotal and CASEMGMT credentials for 7 analysts is months.

**The maintenance tail.** The MCP spec has revised its transport and authorization models roughly annually — HTTP+SSE has already been deprecated in favour of Streamable HTTP, corroborated in-session by ContextForge's own deprecations page. Every revision is work that lands on whoever wrote your gateway, and that person will be on a customer incident when it does.

**Recommendation: extend, don't build.** `threatintel` already consolidates 10 keys and already has composite tools. Growing it beats writing a fifth server, and it beats adopting a platform whose credential store can't reach your stdio containers anyway.

---

# What I'd actually do

**This week — no new services.** SOPS + age: one keypair per analyst as recipients in `.sops.yaml`, one encrypted env file in a private repo, a `~/bin/mcp-run` wrapper using `sops exec-env`. `.mcp.json` becomes `"command": "mcp-run"`. Then shred both `.env.docker` files on all 7 machines. Offboarding is `sops updatekeys` **then** `sops rotate -i` — that order matters; reversing it can leave the removed key with access. Same week: trim `casemgmt/list_cases`, and split into two role-based projects.

That closes your confirmed finding, gives you revocation in seconds, and adds nothing that can be down at 3am.

**If management needs to see a central MCP server:** `mcp-proxy` on `dfir.bunnyiesart.com`. One stateless container, per-server bearer tokens, `toolFilter` allowlists, request logging, `-expand-env` so secrets come from systemd rather than a config file. Half a day. Present it as an ops change, not a governance platform — it gives you no per-analyst identity, no rate limiting, no quota accounting.

**The real gateway, when a trigger fires: ToolHive + vMCP.** It's the only candidate that both spawns your containers (so it can genuinely hold the keys) and runs as a single process with no database, Redis or Kubernetes. Price: weekly pre-1.0 breakage.

**Triggers that flip it:** multi-tenant separation (analysts must be prevented from querying the wrong customer's Docsearch indices — the strongest one, and SOPS cannot touch it); a customer contract, DPA or certification demanding per-user attribution; headcount past ~15; contractors or customer staff using the tools; vendor quota enforcement; an actual key leak; approval gates on writes.

Given you're an MSSP, I'd check the multi-tenant one first — it may already be true, in which case skip straight to ToolHive.

**One question for whoever asked you to build this:** do any customer contracts or certifications require per-user attribution of queries against their data? Yes → ToolHive now. No → SOPS this week, revisit when a trigger fires.

### MAINTAINER - 2026-08-26T20:08:30

we will use internally on the team

### CLAUDE - 2026-08-26T20:09:10

That settles it. Internal team, 7 trusted engineers, no customer-facing access, no contractors — none of the triggers fire.

**The answer is: no gateway. Fix the secrets, keep everything else as-is.**

Building a gateway here would mean standing up a new production dependency, one that can be down at 3am during an incident, to solve a problem that a day of work closes without it. The one legitimate finding you have is plaintext keys at rest on 7 laptops.

## The plan

**1. Secrets — SOPS + age** (~1 day)

```sh
# each analyst, once
age-keygen -o ~/.config/sops/age/keys.txt   # prints the public key
```

Collect the 7 public keys into `.sops.yaml` in a private repo on `github.com`:

```yaml
creation_rules:
  - path_regex: secrets/.*\.enc\.env$
    age: age1abc...,age1def...,   # 7 recipients
```

Put all credentials in one encrypted file — the 10 `THREATINTEL_*` keys plus the CASEMGMT/Logsearch/Docsearch creds:

```sh
sops secrets/mcp.enc.env    # opens $EDITOR, encrypts on save
git add secrets/mcp.enc.env .sops.yaml && git commit
```

Then `~/bin/mcp-run`:

```sh
#!/bin/sh
exec sops exec-env "$MCP_SECRETS_REPO/secrets/mcp.enc.env" \
  "docker run --rm -i \
     -e THREATINTEL_VIRUSTOTAL_API_KEY -e THREATINTEL_SHODAN_API_KEY -e THREATINTEL_ABUSEIPDB_API_KEY \
     ... \
     -v $HOME/threatintel/config.json:/app/config.json:ro \
     $1"
```

`-e VAR` with no `=` forwards the value from the caller's environment, and `sops exec-env` decrypts only into the child process — plaintext never touches disk. `.mcp.json` becomes `"command": "mcp-run", "args": ["threatintel"]`. Keep threatintel's `config.json` bind mount as-is; it isn't a secret.

Then shred `~/.config/mcp-docsearch/.env.docker` and `~/threatintel/.env.docker` on all 7 machines. Git history becomes your key-change log for free.

Offboarding: `sops updatekeys` to drop the recipient, **then** `sops rotate -i` to re-key. That order is load-bearing — reversing it can leave the removed key with access.

**2. Free wins** (~1 hour, unrelated to secrets)

Trim `casemgmt/list_cases`'s description from 2,016 chars to ~400 — it's 847 tokens, 8.3% of your entire tool surface. Then split into two project configs via `enabledMcpjsonServers`: triage = `threatintel` + `casemgmt`, hunting = `logsearch` + `docsearch`. Measured at 1,884 tokens for a curated N1 set, down 81%.

**3. "One call calls others"** — add composite tools to `threatintel`. A `triage_ioc` that chains enrich + docsearch search + casemgmt lookup is a function in a codebase you already own. That's where this belongs.

## What to tell whoever asked

Not "we decided not to build it." Rather: the goal was consolidating credentials, and `threatintel` already consolidates the 10 threat-intel keys — the actual gap was that the keys sat unencrypted on every laptop. That's now closed, with revocation in seconds and no new service to operate. A gateway becomes the right call when analysts need scoping to specific customers, or a customer audit requires per-user attribution — and at that point the answer is ToolHive, not a homegrown server.

If you want a visible central endpoint anyway, `mcp-proxy` on `dfir.bunnyiesart.com` is half a day and honest about what it is.

## One thing worth checking

"Internal" answers *who uses it*, not *what it reaches*. If your Docsearch and Logsearch carry multiple customers' telemetry and any analyst is supposed to be scoped to a subset, that's the one trigger that still fires — and SOPS can't touch it. If all 7 are already authorized across the whole estate, ignore this.

---

Want me to set up the SOPS repo structure and the `mcp-run` wrapper here in `~/aprendizado/mcp-gateway`? I'd scaffold `.sops.yaml`, the wrapper, a `README` with the onboarding/offboarding runbook, and a rewritten `.mcp.json` — but I'd leave generating keys and encrypting real credentials to you, since that touches live secrets on machines I shouldn't be reaching into.

---

## Agent reports (full)

### Ops cost and TCO analysis

# MCP Gateway TCO — 7 people, no platform engineer

## 1. Cost table

| Candidate | Services to run | Stand-up | Ongoing/month | Over-engineered at 7? |
|---|---|---|---|---|
| **IBM ContextForge** | **8 default compose services** (nginx, gateway, postgres, **pgbouncer**, migration, redis, + 2 demo) — "full stack" runs **3 gateway replicas**; no documented SQLite production path | 3–5 days | 4–8 h (releases every 1–2 wks, Alembic migrations → PG backups mandatory) | **Yes, badly** |
| **ToolHive + vMCP** | 1 process (`thv`) + your 4 server containers. No DB, no Redis, **no K8s** (`thv vmcp` runs standalone) | 4–8 h | 2–4 h (weekly releases, pre-1.0 breakage) | No |
| **MCPJungle** | 2 containers (server + Postgres), or 1 with SQLite | 4–6 h | 1–2 h | No, but immature (v0.4.6) |
| **MetaMCP** | 2 containers (app + Postgres), 2–4 GB RAM, custom nginx for SSE | 1 day | 2–3 h + unpatched-bug risk | Borderline |
| **agentgateway** | 1 Rust binary, flat YAML, no DB; K8s/Gateway API optional | 1–2 days | 2–4 h | Yes (wrong shape) |
| **Unla** | 1 "allinone" container; DB and Redis both optional | 4–8 h | 2–4 h ("rapid development", breaking changes between versions) | No, but risky |
| **Docker MCP Gateway** | 0 extra stateful services; a `docker` CLI plugin | 2–4 h | ~1 h | No |
| **mcp-proxy** | 1 container, stateless, 4 named servers on one port | 2–4 h | <1 h | No |
| **Supergateway** | **4 processes** (one per stdio server) + your own TLS/authn | 3–6 h | 1–2 h | No, but you build the missing half |
| **Build your own** | Whatever you write | 2–4 wks | 4+ h forever | Yes |

Nothing here **mandates** Kubernetes or an external OIDC provider. ContextForge ships a Keycloak compose profile but authenticates fine with internal JWT; MetaMCP's OIDC is optional (Better Auth internally); ToolHive and Unla use internal auth.

## 2. Verdicts

**Worth it**
- **mcp-proxy** — one stateless container exposes all four stdio servers as named HTTP endpoints; bearer-token auth; the 10 API keys live on `dfir.bunnyiesart.com` instead of 7 laptops.
- **Docker MCP Gateway** — your servers are already `docker run --rm -i` images, so a custom catalog YAML is near-zero migration, with no database at all.
- **ToolHive + vMCP** — the only candidate that directly kills the plaintext `.env` problem (OS-keyring-encrypted secret store or 1Password, injected per-container), with zero stateful services.

**Not worth it**
- **IBM ContextForge** — 8 services and a connection pooler to front 65 tools, plus 1–2-week releases that have already broken startup (`AUTH_ENCRYPTION_SECRET` now refuses to boot), dropped Python 3.11, flipped root URIs to deny-by-default, and moved schema management to Alembic.
- **agentgateway** — a fine L7 agent proxy, but its config surface is proxy-shaped; v1.4.1 alone broke listener port sharing and OAuth token-exchange fallback.
- **MetaMCP** — last tagged release is ~8 months stale with 105 open issues, and it forked the official SDK's stdio transport, so you own its transport bugs.
- **Unla** — its headline feature is REST→MCP conversion, which you don't need, and upstream warns of breaking changes between versions.
- **Supergateway** — one process per server means 4 supervised processes and you still hand-roll TLS and access control.
- **MCPJungle / build-your-own** — MCPJungle is credible but pre-1.0 with no OAuth; a bespoke gateway is unpaid on-call forever.

## 3. Bottom line

**Best value: mcp-proxy on `dfir.bunnyiesart.com`** — one stateless container, no Postgres, no Redis, no Helm, no IdP, ~half a day to stand up, and it removes the 10 third-party keys from every laptop, which is your actual LGPD-relevant risk. Keep **ToolHive + vMCP** as the upgrade path if you later need per-analyst tool policy or audit; accept its weekly pre-1.0 breakage as the price. **Avoid IBM ContextForge**: it is an enterprise fleet product, and at 7 people you'd be running a replicated Postgres/Redis/pgbouncer stack with fortnightly breaking upgrades to serve four containers.

Sources: [ContextForge repo](https://github.com/IBM/mcp-context-forge), [compose file](https://raw.githubusercontent.com/IBM/mcp-context-forge/main/docker-compose.yml), [releases](https://github.com/IBM/mcp-context-forge/releases), [deployment docs](https://ibm.github.io/mcp-context-forge/deployment/), [ToolHive](https://github.com/stacklok/toolhive) / [releases](https://github.com/stacklok/toolhive/releases) / [vMCP](https://docs.stacklok.com/toolhive/guides-vmcp/) / [secrets](https://docs.stacklok.com/toolhive/guides-cli/secrets-management), [MCPJungle](https://github.com/mcpjungle/MCPJungle) / [releases](https://github.com/mcpjungle/MCPJungle/releases), [MetaMCP](https://github.com/metatool-ai/metamcp) / [releases](https://github.com/metatool-ai/metamcp/releases), [agentgateway](https://github.com/agentgateway/agentgateway), [Unla](https://github.com/mcp-ecosystem/mcp-gateway), [Docker MCP Gateway docs](https://docs.docker.com/ai/mcp-gateway/) / [repo](https://github.com/docker/mcp-gateway) / [catalog](https://github.com/docker/mcp-gateway/blob/main/docs/catalog.md), [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy), [Supergateway](https://github.com/supercorp-ai/supergateway).

### MCPJungle + MetaMCP deep dive

Research complete. Findings below, with the URL backing each claim.

---

# PROJECT A — MCPJungle

**1. stdio wrapping → HTTP: yes, first-class, since v0.2 (Aug 2025)**
Supports `stdio` and `streamable_http` upstreams (SSE "limited", deprecated) and re-exposes everything on a single Streamable HTTP `/mcp` endpoint. It spawns the child process itself, initializes it, and loads its tools. Registration is config-file-only (no CLI flags) via `mcpjungle register -c ./config.json`; fields are `name`, `transport: "stdio"`, `command`, `args`, `env`, `session_mode` (`stateless` default / `stateful`).
The historical premise is outdated: PR **#37 "Add support for STDIO MCP servers" merged 2025-08-01**, followed by #39 "Stdio refinements" (2025-08-02) and #49 (timeouts, 2025-08-13) — landing in release **0.2 (Aug 2, 2025)**, i.e. the second-ever minor release. Later stdio hardening: #208, #210 (init timeout → 30s), #211 (bounded child shutdown), Apr 2026.
Real gotcha: **the default Docker image has no `npx`/`uvx`** — you must run `MCPJUNGLE_IMAGE_TAG=latest-stdio docker compose up -d`. `docker run -i` as the command isn't shown in docs (examples are `npx`/`uvx`); host-filesystem access requires mounting into the container and referencing the mount path in `args`.
- https://github.com/mcpjungle/MCPJungle
- https://docs.mcpjungle.com/guides/register-stdio-servers.md
- https://docs.mcpjungle.com/support-matrix.md
- https://github.com/mcpjungle/MCPJungle/pulls?q=is%3Apr+stdio
- https://github.com/mcpjungle/MCPJungle/releases?page=4

**2. Credential injection: yes, all three shapes, documented syntax**
- Remote bearer: `mcpjungle register --name huggingface --url https://huggingface.co/mcp --bearer-token <tok>` or `"bearer_token": "<tok>"`.
- Arbitrary headers: `"headers": {"Authorization": "token <tok>", "Custom-Header": "v"}` — explicit `headers.Authorization` beats `bearer_token`.
- stdio env injection: `"env": {"API_TOKEN": "${API_TOKEN}"}`.
- `${VAR_NAME}` interpolation works in **any** string field (URL, token, env), so secrets stay out of configs.
- OAuth to upstreams: **beta**, HTTP transport only, gateway-level not per-user (`oauth_redirect_uri`, `oauth_client_id`, `oauth_scopes`).
- Security fix worth knowing: since 0.4.3, client-sent headers are **not** forwarded upstream (PR #253).
- https://docs.mcpjungle.com/governance/upstream-authentication.md
- https://github.com/mcpjungle/MCPJungle/releases

**3. Per-client auth: yes, "MCP client" is a first-class object — but only in enterprise mode**
Dev mode = **auth entirely disabled**, open access to every registered server. Enterprise mode = gateway auth **required**. Two distinct identity types: **MCP clients** (machine consumers: Cursor, Claude, agents) each with a name, bearer token, and an allow-list of upstream servers; and **users** (humans using CLI/API, roles admin vs read-only-ish user). `mcpjungle create mcp-client cursor-local --allow "calculator, github"` mints the token; client sends `Authorization: Bearer <tok>`. You may supply your own token instead of the generated one (Vault/KMS integration). Bootstrap is `mcpjungle init-server` (creates first admin, writes `~/.mcpjungle.conf`). **Static tokens only — no OAuth/OIDC/SSO for downstream clients**; docs list that as a known limitation with "planned soon".
- https://docs.mcpjungle.com/governance/overview.md
- https://docs.mcpjungle.com/governance/access-control.md
- https://docs.mcpjungle.com/governance/clients-and-users.md
- https://docs.mcpjungle.com/reference/cli-enterprise.md
- https://docs.mcpjungle.com/limitations.md

**4. Tool subsets: "Tool Groups", available in both modes**
A group is defined by `included_tools` (canonical `server__tool` names), `included_servers` (all tools from a server), `excluded_tools` (applied last, overrides inclusions). The group gets its own endpoint: **`/v0/groups/{group-name}/mcp`** — the client points at that URL instead of `/mcp`. In enterprise mode only admins can create groups.
Two important caveats: **prompts and resources are not exposed via group endpoints** (tools only), and the docs never state that group endpoints enforce the per-client allow-list — access control and tool groups are documented as separate, non-composed mechanisms. Treat "client X sees only tool set Y" as requiring you to verify that intersection yourself.
- https://docs.mcpjungle.com/guides/tool-groups.md
- https://docs.mcpjungle.com/limitations.md

**5. Namespacing:** `{server_name}__{tool_name}` — **double underscore** separator, applied to all upstream tools, and it's the canonical name used in tool-group configs.
- https://github.com/mcpjungle/MCPJungle · https://docs.mcpjungle.com/guides/tool-groups.md

**6. Observability: metrics good, audit logging weak**
OpenTelemetry → Prometheus-format `/metrics`. Two metrics: `mcpjungle_tool_calls_ratio_total` (counter) and `mcpjungle_tool_call_latency_seconds` (histogram), both labeled by server, tool, and success/error. On by default in enterprise, `OTEL_ENABLED=true` in dev. **No OTLP export.** Health check at `GET /health`. **Audit logging is explicitly rated "limited" in the support matrix** with improvements only planned — this is the notable gap if you need per-client call attribution.
- https://docs.mcpjungle.com/deployment/observability.md
- https://docs.mcpjungle.com/support-matrix.md

**7. Deployment: genuinely light**
`docker-compose.yaml` = **2 services** (`postgres:17`, `ghcr.io/mcpjungle/mcpjungle:latest-stdio`). SQLite is the default for a bare binary; Postgres recommended for production. `docker-compose.prod.yaml` = **4 services** (postgres 17, pgadmin4, mcpjungle in `SERVER_MODE=enterprise`, prometheus v2.53.0). No Redis, no pgvector, no separate auth service. Standing up dev: curl the compose file, `docker compose up -d`, `curl localhost:8080/health` — minutes. Enterprise adds one `mcpjungle init-server`. Prebuilt binaries for macOS/Linux/Windows on amd64+arm64.
- https://docs.mcpjungle.com/deployment/docker.md
- https://raw.githubusercontent.com/mcpjungle/MCPJungle/main/docker-compose.yaml
- https://raw.githubusercontent.com/mcpjungle/MCPJungle/main/docker-compose.prod.yaml

**8. Maturity**
Current **0.4.6, released 2026-08-02**; first release **v0.1.0, 2025-05-29** (~15 months old, ~50 releases). Latest commit on main also 2026-08-02 — **but it's from an outside contributor (goodmai); the lead maintainer duaraghav8's last commit was 2026-05-20**, so there's a ~3-month gap in maintainer activity. Still pre-1.0 (`0.x`), and release notes are near-useless ("Release server & cli version X") — no changelog, so breaking changes are undiscoverable without reading diffs. Signals of churn: 0.4.3 was a security fix, 0.4.2 added upstream OAuth, an open "mcp go migration" PR (#198) since Mar 2026. ~1.2k stars.
**License: MPL-2.0 — and enterprise mode is in the same repo under the same license.** No pricing page, no cloud tier, no CLA/BSL/dual-license found; "enterprise" is a runtime mode (`SERVER_MODE=enterprise`), **not a paid gate**. MPL-2.0 is file-level copyleft: you can embed it in a proprietary product, but modifications to MCPJungle's own source files must be published.
- https://github.com/mcpjungle/MCPJungle/releases.atom
- https://github.com/mcpjungle/MCPJungle/commits/main.atom
- https://github.com/mcpjungle/MCPJungle/releases?page=6
- https://docs.mcpjungle.com/roadmap.md

---

# PROJECT B — MetaMCP

**1. stdio wrapping → HTTP: yes, stdio is the primary/default case**
Three upstream types: **STDIO** (documented as "most common", `uvx`/`npx`), **SSE**, **Streamable HTTP**. Config: `{"type": "STDIO", "command": "uvx", "args": ["mcp-server-package"]}`. Downstream it exposes SSE + Streamable HTTP + an **OpenAPI/REST** surface (for Open WebUI etc.). Docs show `uvx`/`npx`; there is a `v2.5.7-docker-per-mcp` tag suggesting per-MCP container work, but it's a side tag not on the release line. `TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL=true` exists to fix localhost routing from inside the container.
- https://github.com/metatool-ai/metamcp
- https://docs.metamcp.com/en/concepts/mcp-servers.md
- https://docs.metamcp.com/en/concepts/endpoints.md

**2. Credential injection: yes, both directions**
Required fields `name`, `type`, plus `command`/`args` (STDIO) or `url` (remote); optional `description`, `env`, `bearerToken`, `headers`. `${ENV_VAR}` interpolation resolves from the container environment at runtime; MetaMCP also **auto-matches container env vars to the variables a server expects**, and a missing variable logs a warning rather than crashing. Bulk JSON import/export of server configs. Upstream OAuth-enabled MCP servers are supported and tested (with a dedicated OAuth troubleshooting page — and open bugs, see #8).
- https://docs.metamcp.com/en/concepts/mcp-servers.md
- https://docs.metamcp.com/en/troubleshooting/oauth-troubleshooting.md

**3. Per-client auth: richer than MCPJungle, but keyed to *users*, not clients**
API keys with prefix **`sk_mt_`**, shown once, sent as `Authorization: Bearer …`; scoped private or public. Plus session cookies for internal/UI, standard **OAuth per MCP Spec 2025-06-18**, and **OIDC SSO** (Auth0, Keycloak, Azure AD, Google, Okta) via `OIDC_*` env vars with PKCE. Better Auth is the underlying framework. Registration can be locked down independently for UI and SSO (`BOOTSTRAP_DISABLE_REGISTRATION_UI`, `BOOTSTRAP_DISABLE_REGISTRATION_SSO`). Rate limiting at endpoint level (shared bucket) and per-user (IP- or header-identified), in-memory token bucket.
Key structural difference: **there is no first-class "client" object.** Credentials belong to *users*; isolation comes from endpoint + namespace + API key, and there's no per-client allow-list primitive. Auth is a property of each endpoint you configure, so it is effectively **optional per endpoint** (API keys are "recommended", not enforced) — the opposite posture from MCPJungle's hard dev/enterprise split. Note open issue **#345 "Missing access control on oauth.get and oauth.upsert"** (Aug 2026) — an unfixed authz bug in the OAuth surface.
- https://github.com/metatool-ai/metamcp
- https://docs.metamcp.com/en/quickstart.md
- https://raw.githubusercontent.com/metatool-ai/metamcp/main/example.env
- https://github.com/metatool-ai/metamcp/issues

**4. Tool subsets: namespaces + endpoints, with per-tool toggles (the strongest feature here)**
Chain is **MCP servers → Namespace → Endpoint → client**. A namespace groups servers and lets you enable/disable **at both server level and individual tool level**; disabled tools vanish from `tools/list`. Namespaces are private (creator-only) or public (org-wide; public namespaces may only contain public servers). An **Endpoint** publishes one namespace at four URLs: `/metamcp/{name}/sse`, `/metamcp/{name}/mcp`, `/metamcp/{name}/api`, `/metamcp/{name}/api/openapi.json`, with its own API-key auth. So a restricted client = its own namespace with tools toggled off + its own endpoint + its own API key. Namespaces also support **per-namespace tool name/title/description overrides** and custom MCP annotations (e.g. `readOnlyHint`) with override badges in the UI — MCPJungle has no equivalent.
**Middleware is the weak spot**: docs say it intercepts/transforms requests and responses at namespace level for "filtering, logging, validation, and security", but the page names **no built-in middleware, shows no code blocks, and gives no configuration instructions**, and states "Middleware is still under active development." The README's only concrete example is "Filter inactive tools". Do not plan on middleware as an extension point.
- https://docs.metamcp.com/en/concepts/namespaces.md
- https://docs.metamcp.com/en/concepts/endpoints.md
- https://docs.metamcp.com/en/concepts/middleware.md

**5. Namespacing:** `{ServerName}__{originalToolName}` — **double underscore**, same convention as MCPJungle (e.g. `WebSearch__search`). Applied automatically to prevent collisions; overridable per namespace.
- https://docs.metamcp.com/en/concepts/namespaces.md

**6. Observability: notably thinner**
File/console logging only — `app.log`, `error.log`, levels DEBUG/INFO/WARN/ERROR via `LOG_LEVEL` (`example.env` uses `'errors-only'`, options `all`/`info`/`errors-only`/`none`). **No Prometheus endpoint, no OpenTelemetry, no metrics, and no audit log** anywhere in README, architecture, or deployment docs. Operational features are session-oriented instead: idle session invalidation, session lifetime auto-cleanup (v2.4.15), tool-sync caching (v2.4.22), global tool timeout (v2.4.6). There's an **Inspector** for debugging endpoints. Postgres has a compose healthcheck; no documented app health endpoint.
- https://github.com/metatool-ai/metamcp
- https://docs.metamcp.com/en/development/architecture.md
- https://raw.githubusercontent.com/metatool-ai/metamcp/main/example.env

**7. Deployment: 2 containers, but heavier and more config**
`docker-compose.yml` = **2 services**: `app` (`ghcr.io/metatool-ai/metamcp:latest`, port 12008) and `postgres` (`postgres:16-alpine`, `depends_on: service_healthy`). **No Redis** despite what some deployment prose implies — I checked the compose file directly. **2–4 GB RAM recommended** (vs MCPJungle's Go binary), and production needs **nginx with SSE-specific 86400s timeouts** + Let's Encrypt, so realistically 3 moving parts. Setup requires `git clone` (no standalone compose-file download), `cp example.env .env`, `docker compose up -d`, then create an account at `localhost:12008` — minutes locally, but you must set `POSTGRES_PASSWORD`, `BETTER_AUTH_SECRET`, `APP_URL`/`NEXT_PUBLIC_APP_URL`. `example.env` is large (~35 vars, heavy `BOOTSTRAP_*` block for declarative users/API keys/namespaces/endpoints) — more powerful IaC story than MCPJungle, more surface to get wrong. Then the UI walk-through (server → namespace → endpoint → API key) is ~4 manual steps before a client can connect.
- https://raw.githubusercontent.com/metatool-ai/metamcp/main/docker-compose.yml
- https://docs.metamcp.com/en/quickstart.md
- https://docs.metamcp.com/en/deployment/custom-deployment.md
- https://raw.githubusercontent.com/metatool-ai/metamcp/main/example.env

**8. Maturity: this is the real red flag — releases have stalled ~8 months**
- Latest release **v2.4.22, 2025-12-19** — **over 8 months before today (2026-08-26)**.
- Latest commit on `main`: **2026-02-08** (dependency bumps) — **~6.5 months stale**.
- Development moved to an **`ai-dev` branch** ("contains ai agent changes"), whose last commit is **2026-06-22** — also 2 months stale. So the *documented* branch and the *actual* branch are both quiet, and the two have diverged.
- README carries a maintainer admission: **"Apologize for some recent maintainence delay, but will at least keep merging PRs"** — i.e. PR-merging only, no feature ownership.
- **93 open issues**, actively filed through Aug 2026 — users are still using it while nobody ships. Most damning: **#338 "Please cut a release: the OAuth `refresh_token` grant" (2026-07-30)** — a fix exists in the repo that users cannot get. Also open: #345 authz gap on `oauth.*`, #342 `client_secret_basic` rejected, #331 `StreamableHTTPServerTransport` never sets `enableJsonResponse`, #333 Inspector sends invalid defaults.
- A **community fork exists: `Umbrella-IT-Group/metamcp`** — pointed to from the upstream README, which is the clearest signal upstream isn't keeping up.
- ~2.6k stars, MIT license (permissive, no copyleft or commercial gating — the one place it beats MCPJungle legally).
- https://github.com/metatool-ai/metamcp/releases.atom
- https://github.com/metatool-ai/metamcp/commits/main.atom
- https://github.com/metatool-ai/metamcp/commits/ai-dev.atom
- https://github.com/metatool-ai/metamcp/issues
- https://raw.githubusercontent.com/metatool-ai/metamcp/main/README.md

---

## Head-to-head, briefly

| | MCPJungle | MetaMCP |
|---|---|---|
| stdio | first-class since v0.2 (Aug 2025); needs `latest-stdio` image | first-class, primary case |
| Secret injection | `bearer_token`, `headers`, stdio `env`, `${VAR}` anywhere | `bearerToken`, `headers`, `env`, `${ENV_VAR}` + auto-match |
| Client identity | **MCP client = first-class object w/ token + allow-list** (enterprise only) | user-scoped `sk_mt_` API keys; no client object |
| Auth optional? | dev = no auth at all; enterprise = required | per-endpoint, API key "recommended" |
| Tool subsetting | Tool Groups → `/v0/groups/{name}/mcp`; tools only | Namespace + Endpoint, per-tool toggles + overrides |
| Prefix | `server__tool` | `Server__tool` |
| Observability | Prometheus `/metrics`, 2 metrics, `/health`; audit logging "limited" | logs only; **no metrics, no audit** |
| Containers | 2 (dev) / 4 (prod incl. Prometheus); Go binary | 2 + nginx; 2–4 GB RAM |
| License | **MPL-2.0** (file-level copyleft; enterprise mode NOT paywalled) | MIT |
| Momentum | release + commit 2026-08-02, but maintainer quiet since 2026-05-20 | **release 2025-12-19, main 2026-02-08, ai-dev 2026-06-22 — stalled** |

Two corrections to the brief's premises worth flagging: MCPJungle's "streamable-HTTP-only" history is wrong (stdio landed in its second minor release, ~3 weeks after v0.1.0), and MetaMCP does **not** need Redis or pgvector. The decisive difference for a gateway that must hand different clients different tool sets is that MCPJungle models the client as an authenticated object with an allow-list while MetaMCP does not — but MetaMCP's per-tool toggles and OIDC/OAuth are more mature, and its stall is the more serious risk.

### ToolHive + vMCP deep dive

I have enough to report.

# ToolHive / Virtual MCP (vMCP) — factual research report

All findings from WebFetch/WebSearch only; no files written, nothing cloned.

## 1. Runtime model: containers + transport translation — YES

- `thv run <SERVER>` "pulls the image and launches a container" labeled `toolhive: true` / `toolhive-name: <NAME>`, and "starts an HTTP proxy process on a random port to forward client requests to the container." For stdio servers, "ToolHive redirects SSE or Streamable HTTP traffic from the client to the container's standard input and output. This acts as a secure proxy, ensuring that the container doesn't have direct access to the network or the host machine." (https://docs.stacklok.com/toolhive/guides-cli/run-mcp-servers)
- Transports: `--transport stdio|sse|streamable-http`. stdio is the container-side transport (default); `sse`/`streamable-http` mean the container itself speaks HTTP and ToolHive is a reverse proxy. For those, ToolHive picks a random container port and sets `MCP_PORT` and `FASTMCP_PORT` in the container.
- **Proxy mode**: "As of ToolHive CLI version 0.6.0, the default proxy mode for `stdio` MCP servers is `streamable-http`" (`--proxy-mode sse` for legacy SSE). Client-facing paths are `/mcp` (streamable) vs `/sse` (see https://github.com/stacklok/toolhive/issues/2920).
- Mechanism per the arch docs: the proxy-runner attaches to the container's stdin/stdout (`docker attach`-style); SSE/streamable-http backends get a *transparent* proxy with no protocol conversion. Two binaries in Kubernetes: `thv-operator` (reconciles CRDs) + `thv-proxyrunner` (in-pod, proxies MCP traffic). (https://raw.githubusercontent.com/stacklok/toolhive/main/docs/arch/README.md, https://github.com/stacklok/toolhive/blob/main/cmd/thv-operator/README.md)
- Kubernetes: each `MCPServer` yields a proxy pod + backend pod + RBAC (ServiceAccount/Role/RoleBinding); stdio backends are driven via the pod's stdin/stdout and "support only a single client connection at a time." (https://docs.stacklok.com/toolhive/guides-k8s/run-mcp-k8s)

## 2. Secrets / credential injection — env vars into the container, 3 CLI backends + K8s Secrets

https://docs.stacklok.com/toolhive/guides-cli/secrets-management

- Providers (one active at a time; `thv secret setup` or `thv secret provider <NAME>`):
  1. **encrypted** — local encrypted file, "ToolHive encrypts secrets using a password stored in your operating system's keyring" (macOS Keychain, Windows Credential Manager, Linux dbus/Gnome Keyring); `thv secret reset-keyring`.
  2. **1password** — read-only; needs `OP_SERVICE_ACCOUNT_TOKEN`, references use `op://<vault>/<item>/[section/]<field>`. Cannot create/delete via ToolHive.
  3. **environment** — reads `TOOLHIVE_SECRET_*` env vars (CI/CD).
- Commands: `thv secret set|get|list|delete|provider|setup|reset-keyring` (also https://github.com/stacklok/toolhive/blob/main/docs/cli/thv_secret.md).
- **Injection is as environment variables into the child container**, exact syntax: `thv run --secret <SECRET_NAME>,target=<ENV_VAR_NAME> <SERVER>`; e.g. `thv run github --secret GITHUB_TOKEN,target=GITHUB_PERSONAL_ACCESS_TOKEN`. Multiple `--secret` flags allowed. "The target parameter specifies the name of the environment variable in the MCP server's container."
- **Kubernetes operator**: references existing K8s Secrets and injects them as env vars:
  ```yaml
  spec:
    secrets:
      - name: github-token
        key: token
        targetEnvName: GITHUB_PERSONAL_ACCESS_TOKEN
  ```
  (https://docs.stacklok.com/toolhive/guides-k8s/run-mcp-k8s)
- There is also a HashiCorp Vault integration page (https://docs.stacklok.com/toolhive/integrations/vault) and an open issue reworking the secret store into "core providers and system key isolation" (https://github.com/stacklok/toolhive/issues/4224) — i.e. the secrets layer is still being restructured.

## 3. Virtual MCP (vMCP)

Docs: **https://docs.stacklok.com/toolhive/concepts/vmcp** (concept), **https://docs.stacklok.com/toolhive/guides-vmcp/** (guides index), **https://docs.stacklok.com/toolhive/guides-vmcp/local-cli** (CLI).

- **What**: the "Gateway" component of ToolHive — aggregates multiple backend MCP servers (`MCPServer`, `MCPRemoteProxy`, `MCPServerEntry`) behind one endpoint (`/mcp`, health at `/health`). Docs cite 10–20+ backends.
- **Where the code lives**: same monorepo `stacklok/toolhive` — `cmd/vmcp/` (confirmed: `cmd/` contains `help`, `thv`, `thv-operator`, `thv-proxyrunner`, `vmcp`) and `pkg/vmcp/...` (e.g. https://pkg.go.dev/github.com/stacklok/toolhive/pkg/vmcp/auth). Operator examples at https://github.com/stacklok/toolhive/blob/main/examples/operator/virtual-mcps/.
- **Status**: **not labeled experimental/alpha/beta/preview anywhere in the docs**, but also **not declared GA**. It shipped in the 2025-12-08 update (https://docs.stacklok.com/toolhive/updates/2025/12/08/updates) and the whole product is pre-1.0 (see §7). Only the UI's "Registry groups and tool customization" carries an explicit "(GA)" tag in that update. CLI-local vMCP requires ToolHive CLI **v0.24.0+** and arrived in the 2026-04-27 update. Treat it as young-but-shipping, ~9 months old.
- **Virtual servers / subsetting**: yes — per-backend tool filtering, renaming, annotation overrides, and default-deny (https://docs.stacklok.com/toolhive/guides-vmcp/tool-aggregation):
  ```yaml
  spec:
    config:
      aggregation:
        conflictResolution: prefix           # prefix | priority | manual
        conflictResolutionConfig:
          prefixFormat: '{workload}_'        # {workload}, {workload}_, {workload}.
        defaultToolVisibility: deny          # opt-in only
        tools:
          - workload: github
            filter: ['create_issue', 'list_issues']
            overrides:
              create_issue:
                name: gh_new_issue
                description: 'Create a new GitHub issue'
                annotations: { destructiveHint: true, readOnlyHint: false }
  ```
  `priority` uses `priorityOrder: ['github','jira','slack']` and drops duplicates from lower-priority backends; `manual` requires overrides for every conflict or **vMCP fails to start**. Filtered tools are hidden from `tools/list`; note filtered tools were previously still callable — fixed as a breaking change in v0.42.1 ("hidden vMCP tools no longer directly callable") and see https://github.com/stacklok/toolhive/issues/3636.
  CLI config equivalent (`thv vmcp init|validate|serve`, quick mode `thv vmcp serve --group my-group` binding loopback `127.0.0.1:4483` with anonymous auth):
  ```yaml
  aggregation:
    tools:
      - workload: fetch
        filter: [fetch]
  ```
- **Important nuance on "per client"**: the tool subset is configured **per vMCP instance/group, not per connecting client**. Per-identity narrowing comes from Cedar authorization, which filters `tools/list` responses by policy (see §4). So "one endpoint per client persona" = one VirtualMCPServer per persona, plus Cedar for identity-based filtering.
- Extras: composite tools + agent-authored Starlark workflows, parameter defaults, "code mode" (server-side tool calls), and an **MCP Optimizer** (on-demand tool discovery, claimed 60–85% token reduction) with 3 tiers: SQLite FTS5 keyword (no extra container), FTS5+semantic via a managed HuggingFace TEI container, or an external embedding service (https://docs.stacklok.com/toolhive/guides-vmcp/optimizer).

## 4. Per-client auth, token exchange, authz, audit

- **Two-boundary auth model** (https://docs.stacklok.com/toolhive/guides-vmcp/authentication):
  - `incomingAuth`: **anonymous** (dev only), **OIDC** (JWT validation of issuer/audience/expiry/signature, or opaque-token introspection, via `MCPOIDCConfig`; unique `audience` per server ref to prevent token replay; K8s SA tokens supported), plus OAuth 2.1 client auth per MCP spec and **OAuth 2.0 Dynamic Client Registration (RFC 7591)**.
  - `outgoingAuth`: `discovered` (each backend's own `externalAuthConfigRef`), header injection (static API key/bearer), **RFC 8693 token exchange**, AWS STS, and passthrough headers.
- **CLI-level**: `thv run --oidc-issuer --oidc-audience --oidc-client-id --oidc-jwks-url` (https://docs.stacklok.com/toolhive/guides-cli/auth); token exchange flags `--token-exchange-url`, `--token-exchange-client-id/-secret`, `--token-exchange-audience`, `--token-exchange-scopes`, `--token-exchange-subject-token-type` (default `access_token`, `id_token` for Google STS), `--token-exchange-header-name`; exchanged token injected per-request as `Authorization: Bearer` (https://docs.stacklok.com/toolhive/guides-cli/token-exchange). AWS variant: https://docs.stacklok.com/toolhive/tutorials/aws-sts-integration.
- **Authorization = Cedar** (https://docs.stacklok.com/toolhive/reference/authz-policy-reference, K8s: https://docs.stacklok.com/toolhive/guides-k8s/authorization-k8s): principal `Client::"<sub>"`, actions `call_tool`, `get_prompt`, `read_resource`; resources `Tool::`/`Prompt::`/`Resource::`. All JWT claims exposed as `claim_*` (+ `claimset_*` for multi-valued); group claims resolved into `THVGroup::"engineering"` parents (from configured claim, `groups`, `roles`, or `cognito:groups`). Resource attrs include `arg_<key>` and tool annotations (`readOnlyHint`, `destructiveHint`, …). "List methods bypass request-level authorization entirely" and are instead **filtered per identity**. Enabled with `--authz-config` (CLI) or `MCPAuthzConfig` (K8s). Note v0.42.0 breaking change: "Cedar policy now evaluates post-mutation requests."
- **Audit logging** (https://docs.stacklok.com/toolhive/guides-vmcp/audit-logging, pkg: https://pkg.go.dev/github.com/stacklok/toolhive/pkg/audit): structured JSON at a custom `AUDIT` log level. Fields: `time, level, msg, audit_id, type (e.g. mcp_tool_call), logged_at, outcome (success|failure|error|denied), component, source{type,value,extra.user_agent}, subjects{user,user_id,client_name,client_version}, target{endpoint,method,type,name}, metadata{duration_ms,transport,backend_name}, data`. Config: `spec.config.audit: {enabled(false), component, includeRequestData(false), includeResponseData(false), maxDataSize(1024), logFile("" = stdout)}`.

## 5. Health checks and observability

- **Backend health + circuit breaker** (https://docs.stacklok.com/toolhive/guides-vmcp/failure-handling): `healthCheckInterval` 30s, `healthCheckTimeout` 10s, `unhealthyThreshold` 3; states ready/degraded/unavailable/unknown. Circuit breaker **disabled by default** (`failureThreshold` 5, `timeout` 60s, closed/open/half-open). Partial-failure mode `fail` (default) vs `best_effort`. vMCP exposes `/health` and a `/status` endpoint (status omits circuit-breaker detail); circuit state visible via `kubectl get virtualmcpserver … -o yaml`.
- **OTel** built in, no server modification (https://docs.stacklok.com/toolhive/concepts/observability, https://docs.stacklok.com/toolhive/guides-cli/telemetry-and-metrics, https://docs.stacklok.com/toolhive/integrations/opentelemetry): traces + metrics over OTLP and/or Prometheus `/metrics` simultaneously. Flags: `--otel-endpoint` (host[:port], no scheme/path), `--otel-service-name`, `--otel-insecure`, `--otel-enable-prometheus-metrics-path`, `--otel-sampling-rate` (default 0.1), `--otel-custom-attributes`, `--otel-env-vars`; globals via `thv config otel set-endpoint|set-sampling-rate|set-metrics-enabled|set-tracing-enabled`. Metrics e.g. `toolhive_mcp_requests_total` (with `status="error"`), duration histograms, active-connection gauges, per-tool counters; follows OTel MCP semantic conventions. Secret-looking tool args (password/token/secret) are redacted to `[REDACTED]`. Backends: OTel Collector (recommended), Prometheus, Jaeger, Honeycomb, Datadog, Grafana Cloud. Deployment walkthrough: https://stacklok.com/blog/from-black-box-to-observable-deploying-toolhive-with-otel-prometheus-in-kubernetes/

## 6. Deployment complexity

- **Three ways to run**: CLI (`thv`), desktop UI (**ToolHive Studio**, separate repo https://github.com/stacklok/toolhive-studio, Windows/macOS/Linux, Apache-2.0, manages a bundled CLI), and **Kubernetes operator** (https://docs.stacklok.com/toolhive/guides-k8s/, Helm or kubectl). Plus a Cloud UI/Portal in Stacklok Enterprise.
- **CRDs**: `MCPServer`, `MCPRemoteProxy`, `MCPServerEntry`, `VirtualMCPServer`, `MCPToolConfig`, `MCPGroup`, `MCPOIDCConfig`, `MCPAuthzConfig`, `MCPExternalAuthConfig`, `EmbeddingServer` (optimizer), plus a Config CRD. Each MCPServer = 2 pods (proxy + backend) as a StatefulSet.
- **Datastores**: none for single-node CLI/vMCP single replica. **Redis is required for multi-replica vMCP** — "If you configure multiple replicas without session storage, the operator sets a `SessionStorageWarning`" and requests routed to the wrong pod fail; per-pod session cache is a "node-local LRU cache capped at 1,000 concurrent sessions" with a 30-min inactivity TTL, ~10–50 KB/session in Redis. ClientIP affinity is "unreliable behind NAT or shared egress IPs." (https://docs.stacklok.com/toolhive/guides-vmcp/scaling-and-performance)
- **PostgreSQL is required only for the Registry Server** (separate repo https://github.com/stacklok/toolhive-registry-server; docs https://docs.stacklok.com/toolhive/guides-registry/, https://docs.stacklok.com/toolhive/guides-registry/deploy-operator) — optional component; recent releases moved to "PostgreSQL-only storage."
- **Small-team footprint**: minimum is one binary (`thv`) + Docker/Podman/Colima/Rancher Desktop, no DB — genuinely light. Adding vMCP locally = still one binary (`thv vmcp serve`) + a YAML, optionally +1 TEI container for semantic optimizer. Production K8s shape = operator + N×2 pods per server + vMCP pods + Redis + (optional) Registry Server + Postgres + OTel Collector/Prometheus + an IdP: realistically 5–8 moving parts.

## 7. Maturity red flags

- **Pre-1.0 and fast-moving**: latest CLI release **v0.45.0 (2026-08-26, today)**; v0.44.0 Aug 18, v0.43.0 Aug 14, v0.42.1 Aug 10, v0.42.0 Aug 5, v0.41.0 Jul 28, v0.40.1 Jul 20, v0.40.0 Jul 17 — **a release every 3–5 days**, still 0.x (https://github.com/stacklok/toolhive/releases).
- **Frequent breaking changes in the 0.4x line**: v0.45.0 rejects cross-origin requests to the `thv serve` management API + package-name charset restriction; v0.42.1 rejects non-JSON POSTs when authz enabled, hidden vMCP tools no longer callable, OIDC URL validation now required; v0.42.0 removed Config CRD status fields and moved Cedar evaluation post-mutation; v0.41.0 enabled the storage-version migrator by default, rejects JSON-RPC batches, moved rate-limit errors to HTTP 429. Also spec churn: v0.41.0 adds MCP `2026-07-28` spec support.
- **Open-core, not neutral governance (yet)**: Apache-2.0 OSS core, but "Stacklok Enterprise is a hardened, **semantically versioned** distribution of ToolHive built for production use" — implying the OSS 0.x stream carries weaker versioning/stability guarantees (https://docs.stacklok.com/toolhive/faq). CTO Joe Beda: "The core of Stacklok's offering is open source currently with Toolhive… the platform that ties these components together is proprietary" (https://fossforce.com/2026/04/beda-and-mcluckie-reunited-and-securing-ai-at-stacklok/).
- **Foundation donation: intent only.** Stacklok's own LLM-info page states it **intends to donate ToolHive to an open source foundation** (no foundation named, no date); it also notes external maintainers from Red Hat. That page 403s to WebFetch — the claim is visible only via search snippets of https://stacklok.com/llm-info/, and no docs page or README repeats it. Precedent: Stacklok donated its earlier **Minder** project to the OpenSSF in 2024. **No evidence Stacklok has been acquired**; company is founder-led (Craig McLuckie CEO, Joe Beda CTO — Kubernetes co-creators), $17.5M Series A (2023), no newer round found (https://stacklok.com/company/, https://www.crunchbase.com/organization/stacklok).
- **Nothing in the docs is explicitly flagged "experimental"** — including vMCP, the optimizer, code mode, and Starlark workflows. Given the 0.x versioning and weekly breaking changes, the absence of such labels is itself a caution: the maturity signal must be read from the changelog, not the docs.
- Other soft signals: stdio backends are single-connection-only; auth is **off by default** ("Authentication is not enabled by default… the proxy accepts all requests reaching it"); operator bug reverting manual StatefulSet replica scaling (https://github.com/stacklok/toolhive/issues/3329); secret-store redesign in flight (#4224); status-URL `/sse` vs `/mcp` mismatch bug (#2920). Repo scale: ~2,000 stars, 283 forks.

### URLs fetched (WebFetch)
https://docs.stacklok.com/toolhive/ · /faq · /contributing · /concepts/vmcp · /concepts/observability · /guides-cli/run-mcp-servers · /guides-cli/secrets-management · /guides-cli/telemetry-and-metrics · /guides-cli/token-exchange · /guides-k8s/ · /guides-k8s/run-mcp-k8s · /guides-vmcp/ · /guides-vmcp/quickstart · /guides-vmcp/local-cli · /guides-vmcp/tool-aggregation · /guides-vmcp/authentication · /guides-vmcp/audit-logging · /guides-vmcp/failure-handling · /guides-vmcp/scaling-and-performance · /guides-vmcp/optimizer · /reference/authz-policy-reference · /updates/2025/12/08/updates · https://github.com/stacklok/toolhive · /tree/main/cmd · /releases · https://raw.githubusercontent.com/stacklok/toolhive/main/README.md · /main/docs/arch/README.md · https://github.com/stacklok/toolhive-studio · https://fossforce.com/2026/04/beda-and-mcluckie-reunited-and-securing-ai-at-stacklok/
Fetched but blocked (HTTP 403): https://stacklok.com/llm-info/ , https://stacklok.com/blog/introducing-virtual-mcp-server-unified-gateway-for-multi-mcp-workflows/ — content for those two comes from search snippets only.

### Minimal alternatives KISS check

# Skeptic's read: you do not need a gateway

## 1. The cheapest credible architecture

**Zero new services. One encrypted file + a 3-line wrapper.** Roughly one day of work.

1. **One age keypair per analyst** (7 public keys), listed as recipients in `.sops.yaml` in a private repo.
2. **One encrypted env file**, `secrets/mcp.enc.env`, holding all 10 TI keys plus the docsearch/logsearch/casemgmt creds. Encrypted at rest, committed to git. Git history becomes your key-change audit log for free.
3. **A wrapper on each laptop**, `~/bin/mcp-run`:
   ```sh
   exec sops exec-env "$REPO/secrets/mcp.enc.env" \
     "docker run --rm -i -e VIRUSTOTAL_API_KEY -e SHODAN_API_KEY -e ABUSEIPDB_KEY ... threatintel:latest"
   ```
   `sops exec-env` decrypts into the child process environment only — plaintext never touches disk. `docker run -e VAR` with no `=` forwards the value from the caller's environment (documented Docker behaviour). So the `.env.docker` files stop existing.
4. **`.mcp.json` becomes** `"command": "mcp-run", "args": ["threatintel"]`. Same for the other three servers.
5. **Delete and shred** `~/.config/mcp-docsearch/.env.docker` and `~/threatintel/.env.docker` on all 7 laptops.
6. **Offboarding / compromise**: `sops updatekeys` to drop that analyst's recipient, *then* `sops rotate -i` to re-key. Order matters — the docs are explicit that reversing it can leave the removed key with access. That is revocation of *access to the file* in seconds, without visiting any laptop.

**"One call calls others": add composite tools to threatintel.** threatintel already fans one call out to 10 APIs via `enrich`/`recon`. A cross-server composite (`triage_ioc` = threatintel enrich + docsearch search + casemgmt case lookup) is a function in a codebase your team already owns, in a language they already know. A gateway with a workflow engine gets you the same call graph plus a DSL, a config format, and a new failure domain. At 65 tools you are not orchestrating enough to amortise a workflow engine.

**Honest limit:** SOPS still puts the plaintext key in a process on the analyst's laptop at runtime. That is fine here — the analyst is a trusted DFIR engineer who is *already* authorised to query VirusTotal. It stops being acceptable the moment a machine you don't control (contractor, BYOD, customer-side) needs the tools, or you must attribute quota burn per-analyst.

**Middle path, if you want keys off laptops entirely:** tbxark's `mcp-proxy` on one internal host. It aggregates all four stdio servers behind one HTTP endpoint, supports per-server bearer `authTokens`, `toolFilter` allow/block lists, per-server request logging, and `-expand-env` so secrets come from the host's systemd `EnvironmentFile` (fed by SOPS) and never from the config file. Claude Code connects with `type: "http"` + `${MCP_TOKEN}` header expansion. What it does **not** give you: per-analyst identity (tokens are shared strings), rate limiting, quota accounting, approval gates, or tenant separation. Supergateway is one stdio process per instance with no aggregation — strictly worse here.

## 2. Problem-by-problem

| Stated problem | Cheapest fix | Gateway better? | Worth it at 7 people? |
|---|---|---|---|
| API keys scattered on laptops | SOPS+age encrypted env + `exec-env` wrapper | Yes — keys never reach the laptop at all | **No.** SOPS removes plaintext-at-rest, which is the actual finding |
| Revoke a departing analyst | `updatekeys` + `rotate`, one commit | Marginally — revoke a token vs. re-key a file | **No.** Both are one action |
| Rotate a leaked vendor key | Edit file, re-encrypt, commit | Slightly — no client restart | **No.** All 10 vendors rotate by hand in their console anyway; distribution was never the bottleneck |
| "One call calls others" | More composite tools in threatintel | No — threatintel already does it, in-process, no extra hop | **No** |
| Management wants "central server storing keys" | `mcp-proxy` on one host, secrets from systemd | It *is* the gateway, minus governance | **Maybe** — this is the only line where I'd spend money |
| Who called what, when | mcp-proxy `logEnabled` | Yes — real per-user audit | **No.** 7 named people; ask them |

## 3. Trigger conditions that flip this

- **Headcount past ~15**, or SOC analysts on rotating shifts you don't personally know.
- **A customer contract or audit** (ISO 27001, a Brazilian financial client, LGPD DPA) demanding per-user attribution of queries against customer data.
- **Multi-tenant separation** — analysts must be prevented from querying the wrong customer's Docsearch indices. This is the strongest trigger and SOPS cannot touch it.
- **Non-employees**: contractors, interns, or a customer's own staff using the tools.
- **Vendor quota enforcement** — you get rate-limited and cannot tell who burned the VirusTotal quota.
- **A key actually leaks** from a laptop, making runtime exposure a real incident rather than a theoretical one.
- **Approval gates** — a tool that writes (closes an CASEMGMT case, blocks an IP) and needs a second pair of eyes.

## 4. Bottom line

**No.** Not now. The finding is "plaintext secrets at rest on 7 laptops"; SOPS+age closes it in a day with no daemon to run, no platform engineer, and no new thing that can be down at 3am during an incident. Composite tools belong in threatintel, where they already live. If management needs to see "a central MCP server", `mcp-proxy` on one internal host is the honest, ~$0 answer — take it as an *ops* change, not as a governance platform. Build the real gateway when multi-tenant separation or a customer audit forces it, and not one sprint earlier.

**Sources read:** [docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) · [SOPS advanced usage](https://getsops.io/docs/usage/advanced/) · [SOPS key management](https://getsops.io/docs/usage/key-management/) · [tbxark/mcp-proxy configuration](https://github.com/tbxark/mcp-proxy/blob/master/docs/CONFIGURATION.md) · [tbxark/mcp-proxy usage](https://github.com/tbxark/mcp-proxy/blob/master/docs/USAGE.md) · [Supergateway](https://github.com/supercorp-ai/supergateway) · [Claude Code MCP docs](https://code.claude.com/docs/en/mcp) · [docker mcp secret](https://docs.docker.com/reference/cli/docker/mcp/secret/) · [OpenBao single-node deploy](https://ramnode.com/guides/openbao)

### Research gateway vendor claims

## Cross-cutting answer to (a) — verified

**Plain fan-in does not reduce the number of tool definitions sent to the model. Confirmed for all six.** Every one of these gateways, in default aggregation mode, forwards the union of upstream `tools/list` results. Worse: **five of six actively ADD tokens** via name-mangling, because every tool name gets a server prefix in every `tools/list` payload:

| Gateway | Default aggregated tool name | Evidence |
|---|---|---|
| ToolHive vMCP | `github_create_issue` (`prefixFormat: '{workload}_'`, default strategy = `prefix`) | tool-aggregation.mdx |
| MetaMCP | `Server__tool` — `createToolName()` in `tool-name-parser.ts` | source |
| MCPJungle | `<mcp-server-name>__<tool-name>`, "**must** be referred to by its canonical name" | README |
| ContextForge | gateway-slug + `GATEWAY_TOOL_NAME_SEPARATOR=-` | `.env.example:2668` |
| agentgateway | `time_get_current_time` — "namespaces tool and prompt names with the target name"; `prefixMode` field | docs/mcp/connect/virtual |
| Bifrost | not globally prefixed; tools stay grouped per `mcp_client_name` | docs/mcp/gateway |

So the claim holds, and the sharper version is true too: aggregation is token-**negative** before you turn on a reduction feature.

---

## Per-target findings

### 1. ToolHive vMCP (stacklok/toolhive) — the only one with all three mechanisms

- **(b) Three distinct, independent mechanisms:**
  - **Optimizer** (dynamic search). Clients "see only `find_tool` and `call_tool` instead of the full backend toolset." `find_tool` does hybrid semantic+keyword search, returns "up to 8 by default." This is the real context-reduction lever.
  - **Code Mode** (Starlark). Adds **one** virtual tool `execute_tool_script`. Critical nuance: docs say clients see it "**alongside** the backend tools" — so code mode **alone does not shrink the tool list at all**. It cuts *round-trips and intermediate reasoning tokens*, not definition tokens. Docs are explicit about the division of labour: "Filter the advertised tool set per request to save context tokens → **Optimizer**". They also document composing both: "the optimizer narrows the advertised set per request, and code mode lets the agent combine the surfaced tools into a single round-trip."
  - **Composite tools** — operator-authored declarative YAML workflows (`VirtualMCPCompositeToolDefinition`), no scripting. Docs do not say they hide the underlying backend tools, so they likely *add* to the surface.
  - **Static filtering** also exists: `filter: ['create_issue', ...]` per workload, plus name/description/annotation `overrides`.
- **(c) VENDOR CLAIM.** README: "semantic tool search to reduce your token usage by **up to 85%**." Docs pages carry **no** percentage. The DEV/Stacklok article gives a 4-row table — 76% (46.8k→11.2k), 68% (102k→32.4k), 64% (240.6k→86.8k), 85% (93.6k→13.7k) — with **no disclosed methodology, model, or run count**. Their own docs quietly say 60–85%. Treat as marketing.
- **(d) Adoption cost — highest of the six for the optimizer:**
  - Optimizer **requires an embedding service**: either a managed TEI container (`kind: EmbeddingServer`, `ghcr.io/huggingface/text-embeddings-inference`) or an external OpenAI-compatible `/embeddings` endpoint. On K8s the `EmbeddingServer` is required even for keyword-only search. ARM64 needs an image override.
  - Code mode needs **no sandbox container** — Starlark runs in-process in the vMCP Go process. Bounded by `stepLimit`, `parallelMaxConcurrency`, `toolCallTimeout: 30s`, plus a **non-configurable 1-minute wall-clock cap**. Opt-in, off by default. No Python stdlib. Cannot recurse.
  - **vMCP backends must be HTTP**: `url` "must be `http://` or `https://`", `transport` ∈ {`sse`, `streamable-http`}. It cannot front a stdio server directly — you front it with a ToolHive-managed workload first. K8s CRDs (`v1beta1`) are the primary surface; local CLI (`thv vmcp serve`) exists.
  - Known bug: filtered tools cannot be used in composite tool steps (issue #3636).

### 2. Bifrost (maximhq/bifrost) — best-documented code mode, all numbers self-run

- **(b) Two mechanisms.** (i) **Static filtering per virtual key**: `mcp_configs[].tools_to_execute: ["read_file","list_directory"]` or `["*"]` — per-VK, so per-role config is required. (ii) **Code Mode**, which is the real lever: exposes exactly **4 meta-tools** (`listToolFiles`, `readToolFile`, `getToolDocs`, `executeToolCode`) over a virtual filesystem of `.pyi` stubs, server-level by default (`servers/youtube.pyi`) or tool-level. Unlike ToolHive, this **replaces** the tool list.
- **(c) VENDOR CLAIM (all of it).** getbifrost.ai and getmaxim.ai are both Maxim AI — every "independent-looking" article in search results is first-party. Their own benchmark table: 96 tools/6 servers → **-58.2%** input tokens, -55.7% cost; 251/11 → **-84.5%**/-83.4%; 508/16 → **-92.8%**/-92.2%; pass rate 100% at all three. "1.15M tokens to 83K." Methodology (task set, judge, model) is not published. The "up to 92.8%" figure is the ceiling at 508 tools, not a typical result — at a realistic 96 tools it's 58%.
- **(d)** Sandbox is a **Starlark interpreter** (Python subset), no imports/file I/O/network, 30s default timeout — so no container runtime to operate. Upstreams: **STDIO, HTTP, or SSE**, so it *can* front stdio servers. Tool filtering costs one config block per virtual key. MCP is listed under enterprise/advanced features in the README.

### 3. MetaMCP (metatool-ai/metamcp) — static filtering only, verified in source

- **(b) Static filtering, DB-backed.** I read `filter-tools.functional.ts`: a `ListTools` middleware parses each aggregated name via `parseToolName` (`Server__tool`), resolves the server UUID, then reads `namespaceToolMappingsTable.status` ∈ `ACTIVE`/`INACTIVE` from Postgres. `INACTIVE` tools are dropped from the list; there is a parallel `CallTool` guard. **It is purely static per-namespace config (a toggle you flip in the UI, persisted in Postgres), not dynamic per-request selection.** Behaviour worth knowing: it is **fail-open** — no mapping row, unknown server, unparseable name, or a DB error all cause the tool to be **included**. Cache TTL defaults to **1000 ms**, so it re-queries the DB constantly under load. Also `tool-overrides.functional.ts` lets you override name/title/description and merge annotations — the description override is a real (if manual) token lever since descriptions dominate schema size.
- **(c) No numbers at all.** README only says the middleware "optimizes tool context for LLMs." Nothing quantified anywhere.
- **(d)** Docker Compose + **Postgres** required. Fronts stdio servers (`npx`/`uvx` inside the container) but documents a **"Cold Start Problem"** and tells you to build a custom Dockerfile for other dependencies. Serves SSE / Streamable HTTP / OpenAPI. Maturity: docs state plainly **"Middleware is still under active development."** Per-role cost: one namespace + one endpoint per role, and you toggle tools by hand.

### 4. MCPJungle — static filtering, group = separate URL

- **(b) Static filtering only.** Two layers: global `mcpjungle disable tool context7__get-library-docs` ("not available via the MCPJungle Proxy or any of the Tool Groups, so no MCP clients can view or call it"), and **Tool Groups**.
- **How a client consumes a group — answered: yes, a separate endpoint per group.** `http://127.0.0.1:8080/v0/groups/<group-name>/mcp`, streamable HTTP. You point the client at that URL instead of the main `/mcp`. Group membership is declared in a JSON file with `included_tools` (canonical `server__tool` names), `included_servers` (all tools from a server), `excluded_tools` — "The exclusion is always applied at the end."
- **(c) No numbers.** Only a qualitative rationale: "If your MCP client is exposed to hundreds of tools through the gateway MCP, its performance may degrade."
- **(d)** Fronts **stdio and streamable HTTP** upstreams, but stdio needs the larger `latest-stdio` Docker image ("significantly larger… recommended for running locally"), a custom image if your server needs anything beyond `npx`/`uvx`, and a new process is spawned per stdio tool call ("this slows down the tool call"). **Maturity warnings, explicit:** prompts are "currently not supported in Tool Groups"; **you cannot update an existing group — delete and recreate**; in enterprise mode only an admin can create one. Per-role cost is a JSON file + a distinct URL per role.

### 5. IBM ContextForge / mcp-context-forge — yes, but static only

- **(a)+(b) Yes, a virtual server genuinely reduces exposed tool count per client.** "A Virtual Server is a MCP Server composed from Tools/Resources/Prompts from multiple servers" — you POST `associated_tools: [<tool ids>]` and the client connects to `http://localhost:4444/servers/<UUID>/mcp`, which advertises only that curated set. This is **static, ID-based, admin-curated filtering** — the mechanism, not a search or code mode.
- **Important negative finding:** ContextForge has **no dynamic tool-discovery / meta-tool / code-mode capability today.** I enumerated all 35 shipped plugins — none does tool search or code execution. The "Virtual meta-server — comprehensive tool discovery and execution layer" that would expose "only 4-6 tools" is **issue #2230, still OPEN**, opened 2026-01-20, labeled `enhancement` / `WOULD`. Any writeup citing that 4-6-tool design as a ContextForge feature is citing a wishlist item. (There is a `toon_encoder` plugin, but that compresses tool *responses*, not tool definitions.)
- **(c) No token numbers published.** None in README, FAQ, or docs.
- **(d)** Lowest-friction on transport: streamable HTTP + SSE, and `mcpgateway.wrapper` bridges **stdio clients** to HTTP endpoints with JWT preserved (note: that's stdio on the *client* side). Self-hosting is the heaviest of the six (JWT issuance via `create_jwt_token`, DB, admin UI, Docker/K8s). Per-role cost: one virtual server + one UUID URL per client. Repo carries a security caveat that `mcp-servers/` are "**unsupported sample and test servers**" lacking session management, multi-tenancy, and auth.

### 6. agentgateway — refuting "purely transport/auth/observability"

- **(b) It has no token-economics feature, but it does have a tool-count reduction feature — as a side effect of RBAC.** The README feature list is indeed transport/auth/observability only (LLM gateway, MCP gateway with tool federation + stdio/HTTP/SSE/Streamable HTTP, A2A, inference routing, guardrails, RBAC/OTel). **But** authorization is MCP-aware and filters discovery: "During discovery, agentgateway removes capabilities the client cannot use from MCP list responses." The K8s tool-access tutorial demonstrates exactly this — a JWT without the matching claim sees an **empty** tool list, not an access-denied error. Policies are CEL, evaluated against `list_tools` and `call_tools`, with `allow`/`deny`/`require` effects.
- So: **effectively static, identity-scoped filtering** — equivalent in token effect to MetaMCP/MCPJungle/ContextForge, but framed as security, not context economics. **No** dynamic search, **no** code mode, **no** composite tools, **no** tool-description overrides. "Virtual MCP" in agentgateway is just multiplexing — "All targets are exposed together"; it is *not* a curated subset like ContextForge's virtual server. Don't be misled by the shared name.
- **(c) No token numbers anywhere.** Their only published metric is proxy overhead-shaped, not context-shaped.
- **(d)** Cheapest transport story: fronts **stdio/HTTP/SSE/Streamable HTTP** upstreams. Prefixing is tunable via `prefixMode`. Per-role cost is one `AgentgatewayPolicy` with a CEL expression per role. Two doc trees (standalone vs kubernetes) and a Solo Enterprise variant; URL churn suggests docs are moving fast.

---

## Independent measurement — the honest answer

**There is no independent, third-party benchmark of any of these six gateways' filtering or code mode.** Every number attached to a named gateway here is first-party. What does exist, in descending order of independence:

| Source | Measured | Independence |
|---|---|---|
| **AIMultiple**, `aimultiple.com/code-execution-with-mcp` | Code execution vs regular MCP, GPT-4.1, Bright Data MCP, **50 runs per task**: input tokens **15,417 → 3,310 avg = -78.5%**; total **-77.4%** (175K vs 775K); 100% success both arms | **Closest to independent** — run by AIMultiple's own research team, not a gateway vendor. **But** their footer discloses "Subscribers of AIMultiple's benchmarking services in Model Context Protocol include **Bright Data**" — the sole MCP server tested. Also tests the *pattern*, not a gateway. |
| **Speakeasy**, `speakeasy.com/blog/how-we-reduced-token-usage-by-100x-dynamic-toolsets-v2/` | Dynamic toolsets vs static, **Claude Sonnet 4.5**, **40–400 tools**: input tokens **-96.7%** simple / **-91.2%** complex; total -96.4%/-90.7%; 100% success; **tool calls increase ~2x (2–3x)** | Vendor (Gram) self-benchmark — but a vendor of *dynamic filtering*, so it's third-party to all six gateways here, and it's the only one that publishes the **cost** side (more round-trips). Notable: it argues search-first beats code mode. |
| **StackOne**, `stackone.com/blog/mcp-token-optimization/` | Own: schema compression 17,600→~500 tokens; code-exec 55,000 chars→416 chars; MCP Atlas accuracy Sonnet 4.6 **42% native → 80% Code Mode**. Cites Anthropic 150k→2k (98.7%) and Cloudflare 1.17M→~1k | Vendor, mixed own + citations, clearly attributed |
| **Anthropic / Cloudflare** engineering posts | 98.7% and 99.9% reductions; 30–40% latency improvement | First-party to the *pattern*, and both are about writing code against MCP, not about a gateway product |

**Reading of the evidence:** the direction is real and consistently reproduced across unrelated parties, but the headline percentages are all ceiling numbers from deliberately bloated tool catalogs (400–508 tools). At a realistic 6-server / ~96-tool setup even Bifrost's own table drops to 58%. And the only source that reports the downside — Speakeasy's 2–3x increase in tool calls — is measuring dynamic search, which is the mechanism most of these gateways actually ship.

## Evidence table — URLs I fetched

| # | URL | Used for |
|---|---|---|
| 1 | `raw.githubusercontent.com/stacklok/toolhive/main/README.md` | "up to 85%" vendor claim |
| 2 | `docs.stacklok.com/toolhive/guides-vmcp/optimizer` + `raw.githubusercontent.com/stacklok/docs-website/main/docs/toolhive/guides-vmcp/optimizer.mdx` | `find_tool`/`call_tool` only, 8 tools, EmbeddingServer/TEI/OpenAI requirement, no % in docs |
| 3 | `.../docs/toolhive/guides-vmcp/code-mode.mdx` | `execute_tool_script` "alongside the backend tools", Starlark in-process, limits, optimizer composition, limitations |
| 4 | `docs.stacklok.com/toolhive/guides-vmcp/tool-aggregation` | default `{workload}_` prefix, manual strategy, `filter:`, description overrides |
| 5 | `docs.stacklok.com/toolhive/guides-vmcp/composite-tools` | composite tools = declarative YAML, no Starlark |
| 6 | `.../docs/toolhive/guides-vmcp/backend-discovery.mdx` | backends must be http/https, `sse` or `streamable-http` |
| 7 | `dev.to/stacklok/cut-token-waste-...-3oo6` | 76/68/64/85% table, no methodology |
| 8 | `docs.getbifrost.ai/mcp/overview` | "up to 92.8%", STDIO/HTTP/SSE upstreams |
| 9 | `docs.getbifrost.ai/mcp/code-mode` | 4 meta-tools, `.pyi` virtual FS, Starlark sandbox, full benchmark table |
| 10 | `docs.getbifrost.ai/mcp/gateway` | `tools_to_execute` per virtual key |
| 11 | `raw.githubusercontent.com/metatool-ai/metamcp/main/README.md` | filter-inactive middleware, overrides, SSE/HTTP, Postgres, cold start |
| 12 | `.../metamcp/main/apps/backend/src/lib/metamcp/metamcp-middleware/filter-tools.functional.ts` | **static DB status, fail-open, 1000ms cache** |
| 13 | `.../metamcp/main/apps/backend/src/lib/metamcp/tool-name-parser.ts` | `Server__tool` prefixing |
| 14 | `.../metamcp/main/docs/en/concepts/middleware.mdx` | "still under active development" |
| 15 | `raw.githubusercontent.com/mcpjungle/MCPJungle/main/README.md` | group endpoint `/v0/groups/<name>/mcp`, `server__tool`, disable tool, stdio image, group-update limitation |
| 16 | `raw.githubusercontent.com/IBM/mcp-context-forge/main/README.md` | virtual server creation, `/servers/UUID/mcp`, `mcpgateway.wrapper` |
| 17 | `.../mcp-context-forge/main/.env.example` (line 2668) | `GATEWAY_TOOL_NAME_SEPARATOR=-` |
| 18 | `ibm.github.io/mcp-context-forge/latest/faq/` | virtual server definition |
| 19 | GitHub API: `IBM/mcp-context-forge` issue 2230 + `plugins/*` tree | meta-server **open/unshipped**; no tool-search plugin among 35 |
| 20 | `agentgateway.dev/docs/kubernetes/latest/mcp/tool-access/` | disallowed tools removed from `tools/list` (empty list for Bob) |
| 21 | `agentgateway.dev/docs/standalone/main/mcp/connect/virtual/` | "All targets are exposed together", `time_get_current_time`, `prefixMode` |
| 22 | `raw.githubusercontent.com/agentgateway/agentgateway/main/README.md` | full feature list, no context feature |
| 23 | `aimultiple.com/code-execution-with-mcp` | -78.5% / 50 runs / GPT-4.1 + **Bright Data sponsorship disclosure** |
| 24 | `speakeasy.com/blog/how-we-reduced-token-usage-by-100x-dynamic-toolsets-v2/` | -96.7%/-91.2%, 40–400 tools, Sonnet 4.5, **2–3x more tool calls** |
| 25 | `stackone.com/blog/mcp-token-optimization/` | compression + code-exec numbers, Anthropic/Cloudflare citations |

Two claims I could not fully substantiate: agentgateway's `prefixMode` option values (the `docs/mcp/connect/multiplex/` page 404s on both doc trees I tried), and whether ContextForge virtual-server tools keep the gateway prefix inside a virtual server's own `tools/list` (the separator env var is global, but I found no doc stating the in-virtual-server behaviour).

### Token and context economics

# Token economics of an MCP gateway for a 65-tool DFIR stack

**Verdict: a gateway does not help your context economics, and one class of gateway actively hurts it. Your baseline is ~10k tokens, and Claude Code already solves it for free.**

## 1. Measured baseline (not estimated)

Method: I spawned all four stdio servers from `/Users/bunnyiesart/.mcp.json` directly (docker, `initialize` + `tools/list`), serialized each tool as the API sends it — `{name: "mcp__srv__tool", description, input_schema}`, compact JSON — and counted with `tiktoken` `o200k_base` (public proxy; Claude's tokenizer typically runs a few percent higher). Script + raw schemas: `/private/tmp/claude-501/.../scratchpad/dump_tools.py`, `tools.json`.

| Server | Tools | Tokens | Avg/tool |
|---|---|---|---|
| docsearch | 17 | 3,860 | 227 |
| threatintel | 28 | 2,848 | 101 |
| casemgmt | 10 | 2,307 | 230 |
| logsearch | 10 | 1,156 | 115 |
| **Total** | **65** | **10,171** | **156** |

That is **~5% of a 200k window, ~1% of the 1M window you run** — an order of magnitude below the "55k tokens" horror stories, because your servers are lean. Descriptions are 36% of the bytes. One tool, `casemgmt/list_cases`, is 847 tokens (8.3% of everything) — a 2,016-char description plus 13 filter params.

**Fan-in is token-neutral or worse — refuted, verified.** All six candidates forward the union of upstream `tools/list`; five prefix names (`vmcp_iris_list_cases`, MetaMCP `Server__tool`, MCPJungle canonical `server__tool`). Re-serializing my schemas with a gateway prefix: **+195 tokens (+1.9%)**. Aggregation buys auth/audit, never context.

## 2. Mechanisms

| Mechanism | Est. savings (this stack) | Adoption cost | What it breaks | Needs a gateway? | Worth it here? |
|---|---|---|---|---|---|
| **(b) Tool search / deferred loading** — already ON | 10,171 → ~435 (names-only index) = **~96%** | Zero. `ENABLE_TOOL_SEARCH` default on in Claude Code | +1 round-trip on first discovery; selection accuracy at scale is contested (see below) | **No** — client-side | **Yes, already have it** |
| **(a) Static filtering / role tool sets** | triage 5,155 / hunting 5,016; curated 13-tool N1 set = **1,884 (-81%)** | Minutes: `enabledMcpjsonServers` per project + subagent `tools:` allowlists | Analyst must switch context; hidden tool = silent dead end | **No** | **Yes — do this** |
| **(d) Composite tools** | `threatintel/enrich` = 108 tok replaces ~8 primitives ≈ 600 tok; also collapses 8 calls → 1 | Already built | Loses per-source control | No | **Yes — already yours** |
| **(c) Code mode / code execution** | vendor/pattern claims 58–99% | Sandbox (Starlark runtime or container), rewrite workflows | ToolHive code mode exposes tools *alongside* backends — **saves zero definition tokens alone** | Yes | **No** |
| Gateway "optimizer" (ToolHive) | claim only | Embedding service (TEI or OpenAI-compatible) + HTTP-ify all four stdio servers | Duplicates a client feature | Yes | **No** |
| MetaMCP / MCPJungle / ContextForge / agentgateway | same as (a) | Postgres/Docker/JWT/K8s | MetaMCP filtering is **fail-open**; MCPJungle groups can't be updated (delete+recreate) | Yes | **No** |

Evidence, labelled:
- **Anthropic claim:** Tool Search Tool — 58 tools/~55k tokens → ~8.7k, "**85% reduction**"; MCP-eval accuracy **Opus 4.5 79.5% → 88.1%** (internal eval, no published methodology). ([blog](https://www.anthropic.com/engineering/advanced-tool-use), [docs](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool))
- **Anthropic claim:** code execution **150,000 → 2,000 tokens (98.7%)** — one illustrative example, plus an explicit warning that it "requires a secure execution environment with appropriate sandboxing." ([blog](https://www.anthropic.com/engineering/code-execution-with-mcp))
- **Vendor claims:** ToolHive "up to 85%" (README only; docs carry no figure); Bifrost -58.2% at 96 tools, -92.8% at 508 tools — the headline is the 508-tool ceiling. MetaMCP, MCPJungle, ContextForge, agentgateway publish **no numbers at all**.
- **Third-party:** [Speakeasy](https://speakeasy.com/blog/how-we-reduced-token-usage-by-100x-dynamic-toolsets-v2/) -91–97% but **2–3× more tool calls**; [Stacklok's own head-to-head](https://dev.to/stacklok/stackloks-mcp-optimizer-vs-anthropics-tool-search-tool-a-head-to-head-comparison-2f32) puts Tool Search BM25 at 33.7% selection accuracy — at **2,792 tools**, 43× your scale, so it doesn't transfer.
- **Correction:** tool search does **not** break prompt caching — deferred tools are excluded from the cached prefix by design.

**The trap:** Claude Code disables tool search when `ANTHROPIC_BASE_URL` points to a non-first-party host ("most proxies don't forward `tool_reference` blocks"). Putting Bifrost in front as an LLM proxy would turn your 435-token surface back into 10,366. A gateway sold on token savings would cost you them.

## 3. Ranked recommendation

1. **Confirm tool search is live and fix schema hygiene.** Run `/context`; leave `ENABLE_TOOL_SEARCH` unset. Cut `casemgmt/list_cases`'s description to ~400 chars and mark the ~8 always-used tools `"anthropic/alwaysLoad": true` in `_meta`. Half a day, ~1,000 tokens, no infrastructure.
2. **Two role-based projects.** `.mcp.json` + `enabledMcpjsonServers`: N1 triage = threatintel+casemgmt; hunting = logsearch+docsearch. You already have the mechanism. Add subagent `tools:` allowlists for the curated 13-tool triage set.
3. **Ignore for context reasons:** all six gateways, code mode, embedding-based optimizers. At 7 people and 10k tokens, that's premature optimization — roughly 0.03 USD per full-context Opus call. Revisit only if you cross ~150 tools or need per-analyst audit/secret custody, which is a **security** justification, priced separately.

### Security controls worth it at 7 people

## Verdict: most of the "enterprise MCP gateway" checklist is theater at 7 people. Three controls carry ~90% of the risk reduction.

| Control | Threat it addresses | Worth it at 7? | Cheapest adequate implementation |
|---|---|---|---|
| **Credential injection at gateway** (keys resolved server-side, never in tool args/results/context) | 70 plaintext key-copies across 7 laptops; key exfil via injected log line asking the agent to "print your config" | **Yes — non-negotiable** | Gateway holds the 10 threatintel keys + casemgmt/logsearch/docsearch creds in one place; injects into the `docker run` env of the stdio child. Spec-aligned: gateway acts as its own OAuth client upstream and **MUST NOT** pass the client's token through ([spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)) |
| Secrets backend | Laptop theft, git-committed `.env`, ex-employee | Yes | One backend (Vault/Infisical/SOPS+age), or ToolHive's OS-keychain path. Cheat sheet: "Never store secrets in MCP server code, configs, or environment variables" |
| **Per-analyst identity + attribution** | "Who ran `list_case_iocs` on customer X on the 14th?" — the question an MSSP customer audit actually asks | **Yes** | 7 named static tokens minted by the gateway, one per analyst, revocable, rotated on offboarding. Not an IdP. |
| Full per-user OIDC/SSO | Credential sharing, token sprawl | **No, unless you already have Google Workspace/Entra** | If you do, OIDC is ~2h of config in ContextForge/agentgateway — take it. If you don't, standing up Keycloak for 7 people is a new prod dependency you'll be paged for. Note stdio servers **SHOULD NOT** do OAuth at all |
| **Two-tier tool allowlist** (read-only vs mutating) | Agent under injection writing to CASEMGMT, deleting cases, burning API quota | **Yes** | Static YAML: tier-1 (N1) = 60 read tools; tier-2 (DFIR lead) = + the ~5 write tools. Plus human confirm on writes |
| Cedar/CEL/OPA fine-grained policy | Per-field, per-customer, per-time authz | **No** | 65 tools × 2 roles is a 65-line list. A policy engine here is a DSL nobody on a 7-person team will remember how to debug at 03:00 |
| Audit log of every call (tool, params, identity, ts) → SIEM | Auditor evidence; insider misuse; post-incident reconstruction | **Yes** | JSONL → their own Logsearch. They already run the SIEM; this is free |
| Tool-definition pinning (hash + alert on change) | Rug-pull / poisoned descriptions from threatintel's 28 tools and any future third-party server ([MCP03](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning)) | **Yes — cheap** | Hash the `tools/list` output at startup; fail loud on drift. ~40 lines |
| Prompt-injection classifier plugin (Lasso-style) | Injected instructions in Logsearch lines / IOC reports | **No — false comfort** | Evasion research shows commercial and OSS detectors (Azure filter, LLM Guard, ProtectAI DeBERTa) fall to straightforward evasion ([arXiv 2504.11168](https://arxiv.org/pdf/2504.11168)); indirect injection routinely slips filters. Fix the *capability* (allowlist + no write-without-human), not the *string* |
| Presidio PII masking on egress | LGPD exposure | **No** | Their job is customer PII-bearing telemetry — masking it breaks triage, and round-trip unmasking is documented-broken in practice. Scope LGPD via retention + access logs instead |
| Secret masking on egress | Keys leaking back through tool output | Marginal — keep as **defence-in-depth only** | Free regex tier (AWS/GitHub/HF patterns). Never counted as the control |
| Tool-output sanitisation (strip `<IMPORTANT>`, `<system>`) | Tool-poisoning via results | Yes, trivial | Cheat sheet explicitly recommends it |

**Insist on:** credential injection + single secrets store; per-analyst tokens with full audit to Logsearch; two-tier allowlist with human confirmation on the ~5 mutating tools.
**Skip:** Cedar/CEL policy engine; prompt-injection detection as a relied-upon control; Presidio PII masking.

## One gateway or two?

**One gateway. Two *session profiles*.** Splitting into internal-vs-external gateways is the appealing-but-wrong answer, because it doesn't cut the actual attack path. That path is: attacker-controlled string in a Logsearch line or IOC report → agent reads it → agent calls `list_case_iocs` → agent calls `urlscan`/`virustotal` with the case data (public submission = exfiltration channel). Both toolsets live in **one model context**, so two gateways stop nothing; you'd double ops cost (two configs, two secret sets, two upgrade paths) for a boundary the agent walks straight through.

What actually limits blast radius is splitting the *context*: a `triage` profile (threatintel + logsearch/docsearch read) and a `casework` profile (casemgmt + logsearch/docsearch read, no threatintel egress). Enrichment and case data never co-occur. Same gateway, two allowlists, near-zero extra ops.

On confused deputy ([spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)): one gateway holding broad creds for 7 users is fine *if* every request is authenticated to a named analyst, authorised against that analyst's tier before injection, and logged — the failure mode is a gateway that authenticates nobody and injects everything.

Sources read: [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) · [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) · [OWASP MCP03 Tool Poisoning](https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning) · [arXiv 2504.11168](https://arxiv.org/pdf/2504.11168) · [Lasso MCP Gateway](https://github.com/lasso-security/mcp-gateway) (no auth/RBAC — it's a local wrapper, not a central gateway). Incident background surfaced via search: [MCP breach timeline (Asana cross-tenant, June 2025)](https://authzed.com/blog/timeline-mcp-breaches), [CSA tool-poisoning note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/).

### Research Anthropic tool search + code exec

## Evidence list

### 1. Tool Search Tool (API feature)

**Sources actually fetched**
- Blog: https://www.anthropic.com/engineering/advanced-tool-use
- Docs: https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool

**Token numbers — Anthropic's own claims (blog)**
- Setup: 5 MCP servers / 58 tools (GitHub, Slack, Sentry, Grafana, Splunk). "58 tools consuming approximately 55K tokens before the conversation even starts"; the traditional path is described as "~72K tokens for 50+ MCP tools" and "~77K tokens before any work begins".
- With tool search: search tool "~500 tokens" + "3-5 relevant tools, ~3K tokens" → "~8.7K tokens" total. Headline: **"85% reduction in token usage"**.
- Restated as context preserved: **"Tool Search Tool preserves 191,300 tokens of context compared to 122,800 with Claude's traditional approach."**
- Docs version of the same claim: a multiserver setup (GitHub, Slack, Sentry, Grafana, Splunk) "can consume ~55k tokens in definitions before Claude does any work. Tool search typically reduces this by over 85 percent, loading only the 3–5 tools Claude needs."

**Accuracy numbers — Anthropic's own claims (blog)**
- Verbatim: **"Opus 4 improved from 49% to 74%, and Opus 4.5 improved from 79.5% to 88.1% with Tool Search Tool enabled."** The eval is described only as "MCP evaluations when working with large tool libraries" — Anthropic does **not** name a public benchmark; treat it as an internal MCP eval.
- Docs give the mechanism claim behind it: "Claude's ability to pick the right tool degrades once you exceed 30–50 available tools."
- Same blog, adjacent features (useful context, not tool search): Programmatic Tool Calling "Average usage dropped from 43,588 to 27,297 tokens, a 37% reduction on complex research tasks"; accuracy "Internal knowledge retrieval improved from 25.6% to 28.5%; GIA benchmarks from 46.5% to 51.2%". Tool Use Examples: "improved accuracy from 72% to 90% on complex parameter handling."

**Mechanics (docs)**
- Two server-side variants: `tool_search_tool_regex_20251119` (Claude writes Python `re.search()` patterns, max 200 chars) and `tool_search_tool_bm25_20251119` (natural language, max 500 chars). Both search names, descriptions, argument names, argument descriptions.
- Per-tool `defer_loading: true`. **"You still send every tool's full definition in the `tools` array on every request, including the deferred ones"** — deferral controls context, not request payload.
- At least one tool must be non-deferred; all-deferred returns 400 `"At least one tool must have defer_loading=false."` Never defer the search tool itself.
- Search returns `tool_reference` blocks, **up to 5 by default**, `limit` 1–10,000; max **10,000** deferred tools per request.
- MCP connector path: you do *not* set `defer_loading` per tool — set it on the `mcp_toolset` entry's `default_config` (whole server) or per tool in `configs`.
- Custom client-side search is supported: return `tool_reference` blocks from your own tool's `tool_result` (this is the hook a gateway/embedding search would use).

**Caveats (correcting one premise)**
- **Prompt caching is NOT invalidated.** Docs: "the API excludes deferred tools from the system-prompt prefix… appends a `tool_reference` block inline in the conversation… The prefix is untouched, so prompt caching is preserved." Blog: "Tool Search Tool doesn't break prompt caching because deferred tools are excluded from initial prompt entirely."
- But: **a tool with `defer_loading: true` cannot also carry `cache_control` — 400.** Put the breakpoint on a non-deferred tool.
- Latency: the Claude Code/SDK doc (below) is where the round-trip cost is stated: "Tool search adds one extra round-trip the first time Claude discovers a tool."
- When NOT to use (docs): fewer than 10 tools, every tool used in every request, or definitions under ~100 tokens total. Blog phrasing: small tool library (<10), all tools used frequently, compact definitions.
- Not metered as a server tool; discovered definitions bill as ordinary input tokens.
- Platform gaps: Bedrock only via InvokeModel (not Converse); rejected server-side on Microsoft Foundry deployments hosted on Azure. Opus 4.1 and earlier unsupported.

**Independent (not Anthropic) — mark clearly as third-party**
- https://github.com/zhang-liz/mcp-token-benchmark (measured 2026-07-08, o200k_base tokenizer, real `tools/list` handshakes): Notion official 24 tools = 17,161 tokens (8.6% of 200K); Firecrawl 26 = 16,565; GitHub archived npm 26 = 3,546; Slack 8 = 679. "A realistic 5-server setup consumes 26,224 tokens (13.1%)." 25× spread across servers; "for the worst server, 97% is inputSchema, not descriptions." Note this is **lower** than Anthropic's 55–72K figure for comparable setups.
- https://dev.to/stacklok/stackloks-mcp-optimizer-vs-anthropics-tool-search-tool-a-head-to-head-comparison-2f32 (vendor benchmark, 2025-12-10, 2,792 tools, Claude Sonnet 4.5, one synthetic query per tool): Tool Search Tool BM25 **33.70% selection / 47.85% retrieval**; regex **30.01% / 39.00%**; their own optimizer 93.95% / 98.03%. Tokens per request: BM25 2,823, regex 3,679, optimizer 3,296. Vendor-run and unfavorable-by-construction (2,792 tools is far past Anthropic's illustrated scale), but it's the only public head-to-head accuracy measurement I found — Anthropic's 74%/88.1% has no published methodology to compare against.

### 2. Claude Code / Agent SDK support (this is the big finding)

**Sources fetched**
- https://code.claude.com/docs/en/agent-sdk/tool-search
- https://code.claude.com/docs/en/mcp (section "Scale with MCP tool search")

Tool search is **native and ON BY DEFAULT in Claude Code today** — no API-level integration work needed.

- "Tool search is on by default." / "Tool search keeps MCP context usage low by deferring tool definitions until Claude needs them. Only tool names and server instructions load at session start, so adding more MCP servers has minimal impact on your context window. Claude Code doesn't impose a fixed per-server tool cap; the practical limit is your context window budget."
- Setting name: **`ENABLE_TOOL_SEARCH`** (env var, or `settings.json` `env` field). Values: unset = on; `true` = always on; `auto` = activates once deferrable definitions reach **10% of the context window**; `auto:N` = custom percent (`auto:5`); `false` = off.
- Scope: "Tool search applies to all registered tools, whether they come from remote MCP servers or custom SDK MCP servers." Core built-ins (Bash, Read, Edit) always load upfront and don't count toward the `auto` threshold.
- Latency caveat, verbatim: "Tool search adds one extra round-trip the first time Claude discovers a tool (the search step), but for large tool sets this is offset by smaller context on every turn. With fewer than ~10 tools whose definitions fit comfortably in the context window, loading everything upfront is typically faster."
- Discovered tools persist: "Up to five of the most relevant tools are loaded into context by default, where they stay available for subsequent turns. When the SDK compacts earlier messages… it keeps the discovered tools loaded."
- **Gateway-relevant caveat:** "The SDK disables tool search when `ANTHROPIC_BASE_URL` points to a non-first-party host, since most proxies don't forward `tool_reference` blocks." Also off under `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS` (which `ENABLE_TOOL_SEARCH` cannot override); orgs can force it on via managed settings (v2.1.227+).
- Model floor: Sonnet 4.5 / Haiku 4.5 / Opus 4.5 and later. Limits: 10,000 tools, 5 results per search.
- Escape hatches: `alwaysLoad: true` on a server in `.mcp.json` exempts it from deferral (all its tools load at session start; also makes startup wait, capped at the 5s connect timeout); a server can mark individual tools with `"anthropic/alwaysLoad": true` in the tool's `_meta`. The search tool itself can be denied: `{"permissions": {"deny": ["ToolSearch"]}}`.
- Discoverability advice for server authors: server instructions matter more with tool search on; **Claude Code truncates tool descriptions and server instructions at 2KB each**.

### 3. Other context-reduction levers in Claude Code today

- `/context [all]` — https://code.claude.com/docs/en/commands: "Visualize current context usage as a colored grid. Shows optimization suggestions for context-heavy tools, memory bloat, and capacity warnings." `/usage` (alias `/cost`) shows session token usage. `/mcp` manages servers and has `enable`/`disable [server|all]`.
- MCP **output** (not definitions) limits — https://code.claude.com/docs/en/mcp: warning above **10,000 tokens**, hard default cap **25,000 tokens**, raise with `MAX_MCP_OUTPUT_TOKENS`; per-tool override via the `anthropic/maxResultSizeChars` annotation (text only; image results always subject to the env var).
- Server on/off: `enabledMcpjsonServers` / `disabledMcpjsonServers` (`.mcp.json` approval, not context tuning), `enabledMcpServers`/`disabledMcpServers` (connection state, explicitly documented as unrelated to the `*Mcpjson*` pair), `disableClaudeAiConnectors`.
- Org connector controls: a tool set to `blocked` is "filtered out before Claude sees it, so it never appears in the tool list."
- Per-subagent allowlists — https://code.claude.com/docs/en/sub-agents: `tools:` frontmatter is an allowlist ("Inherits every tool available to subagents if omitted"); `disallowedTools` supports `mcp__<server>`, `mcp__<server>__*`, `mcp__*`.

### 4. Code execution with MCP / progressive disclosure

**Source fetched:** https://www.anthropic.com/engineering/code-execution-with-mcp

- Headline, Anthropic's own claim, verbatim: **"This reduces the token usage from 150,000 tokens to 2,000 tokens—a time and cost saving of 98.7%."**
- Scenario: two problems compounding — (a) "Tool definitions overload the context window": agents connected to thousands of tools process "hundreds of thousands of tokens before reading a request"; (b) "Intermediate tool results consume additional tokens": a 2-hour sales meeting transcript costs "an additional 50,000 tokens" when routed through context. The worked example is Google Drive → Salesforce: `gdrive.getDocument()` pulls the full transcript into context, then the agent re-emits the whole transcript in the `salesforce.updateRecord()` call — paying for it twice.
- Mechanism: MCP servers presented as a filesystem of TypeScript modules under `./servers/`, "each tool corresponds to a file". The agent "discovers tools by exploring the filesystem: listing the `./servers/` directory… then reading the specific tool files it needs… This lets the agent load only the definitions it needs for the current task." Data containment: "intermediate results stay in the execution environment by default. This way, the agent only sees what you explicitly log or return."
- Costs, verbatim: **"Running agent-generated code requires a secure execution environment with appropriate sandboxing, resource limits, and monitoring. These infrastructure requirements add operational overhead and security considerations."** And: "The benefits of code execution—reduced token costs, lower latency, and improved tool composition—should be weighed against these implementation costs."
- Who implements it: **the MCP client**, not the servers — existing MCP servers need no changes. So it is implementable client-side (or in a gateway that fronts the client's tool surface); no gateway is *required*. Extra benefits claimed with no numbers attached: privacy (client can tokenize sensitive values before they reach the model), state persistence via files, and saving working code as reusable skills.
- No independent reproduction of the 150k→2k figure was found; it's a single illustrative example, not a benchmark.

### Two things worth flagging to the user

1. Their premise that tool search invalidates the prompt cache is **backwards** — Anthropic explicitly designed it to preserve the cached prefix. The only real caching constraint is that `defer_loading: true` + `cache_control` on the same tool is a 400.
2. Claude Code already ships this natively and on by default, so "add deferred tool loading" is not a gap to fill — the remaining gaps a gateway could address are retrieval *quality* (the third-party 30–34% selection accuracy figure at ~2,800 tools), the fact that all definitions still travel in every request, and the fact that tool search auto-disables behind a non-first-party `ANTHROPIC_BASE_URL`.

Sources: [Advanced tool use (Anthropic Engineering)](https://www.anthropic.com/engineering/advanced-tool-use), [Tool search tool (Claude Platform Docs)](https://platform.claude.com/docs/en/agents-and-tools/tool-use/tool-search-tool), [Code execution with MCP (Anthropic Engineering)](https://www.anthropic.com/engineering/code-execution-with-mcp), [Scale to many tools with tool search (Claude Code Docs)](https://code.claude.com/docs/en/agent-sdk/tool-search), [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp), [Claude Code commands reference](https://code.claude.com/docs/en/commands), [Subagents](https://code.claude.com/docs/en/sub-agents), [mcp-token-benchmark (third party)](https://github.com/zhang-liz/mcp-token-benchmark), [Stacklok MCP Optimizer vs Tool Search Tool (third party)](https://dev.to/stacklok/stackloks-mcp-optimizer-vs-anthropics-tool-search-tool-a-head-to-head-comparison-2f32)

### Build vs adopt effort analysis

The candidate survey agent is still running, but my own research is conclusive. Delivering now.

---

# Build vs Adopt: MCP Gateway — Verdict

**Don't build. Don't adopt a platform either. Extend `threatintel`.**

## 1. Component-by-component build cost

One competent Python dev, interrupt-driven. "Free?" = does an adopted gateway (ContextForge as reference) hand it to you.

| Component | Effort | Risk if done wrong | Free? |
|---|---|---|---|
| Streamable HTTP transport, Origin→403, resumability | 5–8d | Unauthed LAN access, DNS rebinding | Yes |
| stdio child lifecycle (`docker run -i`, stderr drain, zombie reap, restart) | 4–8d | **stderr pipe fills → child deadlocks forever**; orphaned containers | Yes |
| `tools/list`/`tools/call` proxy, `list_changed`, pagination | 3–5d | Stale tool cache, silent truncation | Yes |
| Namespacing/collisions (prefix within 64-char + charset limits) | 2–4d | Renames break every saved prompt; wrong-server routing | Yes |
| Per-client auth: issue/hash/rotate/revoke + tool scoping | 5–10d | One leaked key = all 65 tools + 10 upstream API keys | Yes (virtual servers) |
| Credential storage + injection into children | 5–10d | **`docker run -e KEY=…` leaks the key via `ps aux`**; keys in logs | Partly |
| Audit log (caller, tool, args, correlation ID, retention) | 4–8d | A DFIR shop with no trail of its own tooling | Yes (OTel) |
| Health checks, reconnect, circuit-break | 3–6d | One dead child hangs every client | Yes |
| Backpressure/multiplexing over a single stdin pipe | 4–8d | Head-of-line blocking: one Docsearch query stalls 7 analysts | Yes |
| Cancellation + timeout budgets | 3–6d | Runaway VirusTotal quota burn, orphaned queries | Yes |
| Session mgmt (`Mcp-Session-Id`) for stateful servers | 5–10d | Cross-user session hijack | Yes — **and deleted by the 2026-07-28 spec** |
| Version negotiation across 5 revisions + client matrix | 3–8d, recurring | New client silently won't connect | Yes |
| Deploy, TLS, secret bootstrap, backup, conformance tests | 9–18d | — | Yes |

**Total: 55–110 dev-days ≈ 11–22 dev-weeks.** Calendar, for an incident-interrupted team: **5–9 months.**

**MVP is 4–6 days** (rows 1–4 happy path, one shared bearer token). That is the trap: the MVP demos as 80% done and is ~5% of the work. **The 80/20 cliff is per-client auth, credential-at-rest, pipe multiplexing, and sessions** — i.e. the moment a second concurrent analyst and one live VirusTotal key coexist.

## 2. Spec churn, quantified

MCP defines its version string as *"the last date backwards incompatible changes were made."* There have been **five dated revisions in 21 months**:

| Revision | Date | What broke |
|---|---|---|
| 2024-11-05 | Nov 2024 | Baseline: stdio + HTTP+SSE |
| 2025-03-26 | Mar 2025 | HTTP+SSE **deprecated** → Streamable HTTP; OAuth 2.1 added; `Mcp-Session-Id` |
| 2025-06-18 | Jun 2025 | JSON-RPC batching **removed**; servers become OAuth Resource Servers; RFC 8707 required |
| 2025-11-25 | Nov 2025 | OIDC Discovery; Client ID Metadata Docs replace dynamic registration; JSON Schema 2020-12 |
| 2026-07-28 | Jul 2026 | **`initialize` handshake removed. Sessions and `Mcp-Session-Id` removed.** New `Mcp-Method`/`Mcp-Name` headers; `server/discover` mandatory; roots/sampling/logging deprecated |

Mean gap **5.2 months**. On top of that, **Python SDK v2.0.0** (Jul 2026) renamed `FastMCP`→`MCPServer`, moved `mcp.server.fastmcp.*`, snake_cased every field, and **removed WebSocket transport** — breaking servers across the ecosystem on upgrade.

**The maintenance argument:** IBM — with a funded team — has an open *epic* to migrate ContextForge to SDK v2 and had to file a separate issue to pin `mcp>=1.28.1,<2` before the deadline. Every migration is worse for a *proxy* than a server: a proxy must speak both sides and support a mixed client fleet. Budget 2–10 dev-days per revision, arriving unannounced. On a 7-person DFIR team, spec migration always loses to a customer incident. Your gateway will be two revisions stale within a year, and then it blocks every new client.

## 3. Three options, ranked

**1. Extend `threatintel` — recommended (1–2 weeks).** Management's ask is already ~80% built. `threatintel` consolidates the 10 third-party keys behind one server; the actual remainder is **three** infra credentials (casemgmt/logsearch/docsearch), each a single service account, not per-user. Host those three on one internal box behind `mcp-proxy`/Supergateway with a docker `--env-file`, and you're done. Better: `threatintel`'s composite tools (`enrich`, `recon`) are the *right* pattern — 65 flat tools already bloats every request's context, and a gateway makes that worse by aggregating. Grow composites; shrink the surface.

**2. Adopt ContextForge (2–4 weeks + upkeep).** Python (fits the team), Apache-2.0, virtual servers, per-user Vault credential resolution, stdio wrapper, OTel. But: Postgres, mandatory `JWT_SECRET_KEY`/`AUTH_ENCRYPTION_SECRET`, and **biweekly releases each carrying breaking changes** (v1.0.8, 18 Aug 2026 dropped Python 3.11). Real upgrade tax, no platform team to pay it. MetaMCP/MCPJungle are 1:1-endpoint-limited; agentgateway lacks namespace hierarchy; ToolHive's secret store is OS-keyring/per-workstation — the opposite of "central".

**3. Build new — reject.** 11–22 dev-weeks to reach trustworthy, then own five revisions' worth of churn forever, to reimplement what `threatintel` already does for the credentials that matter.

**Flip condition:** if this becomes client-facing or multi-tenant, or an audit obligation requires per-analyst identity on every tool call, or the fleet passes ~10 upstream servers — **adopt ContextForge**. Never build. If you think you only need a stdio→HTTP bridge, that's `mcp-proxy`; write zero lines.

**Sources:** [MCP versioning](https://modelcontextprotocol.io/specification/versioning) · [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog) · [2026-07-28 RC](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) · [2026 breaking changes](https://stacktr.ee/blog/mcp-2026-spec-changes) · [version timeline](https://hidekazu-konishi.com/entry/mcp_specification_version_timeline.html) · [SDK betas](https://blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/) · [security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) · [ContextForge FAQ](https://ibm.github.io/mcp-context-forge/latest/faq/) · [releases](https://github.com/IBM/mcp-context-forge/releases) · [SDK v2 pin issue #5839](https://github.com/IBM/mcp-context-forge/issues/5839) · [ToolHive secrets](https://docs.stacklok.com/toolhive/guides-cli/secrets-management) · [ecosystem survey Q1 2026](https://www.heyitworks.tech/blog/mcp-aggregation-gateway-proxy-tools-q1-2026)

### agentgateway + Unla deep dive

Research complete. Findings below.

---

# PROJECT A — agentgateway

**1. Governance / backing**
- **Linux Foundation directly — NOT CNCF.** No sandbox/incubating tier (LF top-level projects don't use CNCF's maturity ladder). Announced **2025‑08‑25** at Open Source Summit Europe, Amsterdam.
  - https://www.linuxfoundation.org/press/linux-foundation-welcomes-agentgateway-project-to-accelerate-ai-agent-adoption-while-maintaining-security-observability-and-governance
  - https://agentgateway.dev/blog/2025-08-25-solo-contributes-agentgateway-to-lf/
  - https://www.solo.io/blog/solo-contributes-agentgateway-linux-foundation
- **Main corporate backer: Solo.io** — created it (originally "Gloo AI Gateway"), wrote it from scratch in Rust after abandoning an Envoy-based approach, and donated it. CEO Idit Levine quoted in the press release. Named contributors/supporters: AWS, Microsoft, Red Hat, IBM, Cisco, Huawei, Shell, Zayo, Dell, CoreWeave, Akamai, T‑Mobile, UBS, Nirmata. Apache 2.0.
- Note: the GitHub sidebar sponsor is **Blacksmith** (CI credits), not the governance backer — https://github.com/agentgateway/agentgateway

**2. stdio child processes → HTTP/SSE/Streamable HTTP — YES, first-class**
- https://agentgateway.dev/docs/standalone/latest/mcp/connect/stdio.md — `mcp.targets[].stdio` with `cmd` + `args`; documented example `cmd: npx`, `args: ["@modelcontextprotocol/server-everything"]`. Exposed over the HTTP listener (default port 3000); tool playground UI at `:15000/ui/`.
- `uvx` confirmed in the multiplexing example: `cmd: uvx, args: ["--with","mcp<2","mcp-server-time"]` — https://agentgateway.dev/docs/standalone/latest/mcp/connect/virtual.md
- Also supports Streamable HTTP/SSE remote backends (https://agentgateway.dev/docs/standalone/latest/mcp/connect/http.md) and OpenAPI→MCP (https://agentgateway.dev/docs/standalone/latest/mcp/connect/openapi.md).
- Caveat: the stdio page does **not** document an `env:` block for injecting secrets into the child process. Credential injection is documented for HTTP backends (see #3). This is the one gap worth verifying against the source config schema.

**3. Credential injection into upstreams — strong, for remote backends**
- `backendAuth` methods: **static API key, passthrough, AWS (SigV4), GCP (ADC), OAuth 2.0 token exchange (RFC 8693), Cross App Access / ID‑JAG**. Secret references: inline `value: $ENV_VAR`, or `value: { file: /path/to/key }`. Delivery via header (Authorization or custom), query param, or cookie.
  - https://agentgateway.dev/docs/standalone/latest/configuration/security/backend-authn/
  - https://agentgateway.dev/docs/standalone/latest/configuration/security/backend-authn/oauth-token-exchange/
  - https://agentgateway.dev/docs/standalone/latest/configuration/security/backend-authn/cross-app-access/
- **Per-target** overrides: `backends[].mcp.targets[].policies` supports `backendAuth`, `backendTLS`, `requestHeaderModifier` — so each federated MCP server can carry its own API key. Not allowed at target level: `mcpAuthorization`, `ai`, `a2a`, response header modification. https://agentgateway.dev/docs/standalone/latest/mcp/mcp-target-policies.md
- Header manipulation + transformations: https://agentgateway.dev/docs/standalone/latest/configuration/traffic-management/manipulation.md , https://agentgateway.dev/docs/standalone/latest/configuration/traffic-management/transformations.md

**4. Per-client inbound auth**
- Acts as an **OAuth 2.0/2.1 resource server**: validates tokens, serves protected-resource metadata for MCP client discovery, per-IdP adaptation. Documented IdP guides: Auth0, authentik, Descope, Microsoft Entra ID, Keycloak, Okta. https://agentgateway.dev/docs/standalone/latest/mcp/mcp-authn.md
- JWT authn: https://agentgateway.dev/docs/standalone/latest/configuration/security/jwt-authn.md ; API keys also supported.
- **Authorization via CEL** evaluated against MCP method invocations (`tools/call`, etc.) — tool/prompt/resource-level allow/deny, RBAC off JWT claims, per-target rules. https://agentgateway.dev/docs/standalone/latest/mcp/mcp-authz.md ; CEL reference https://agentgateway.dev/docs/standalone/latest/reference/cel/variables.md , playground https://agentgateway.dev/docs/standalone/latest/reference/cel/playground.md
- External authz callout: https://agentgateway.dev/docs/standalone/latest/configuration/security/external-authz.md
- Multi-tenancy is expressed through JWT claims + CEL policies and (in k8s) per-namespace Gateway/Route resources rather than a built-in tenant object.

**5. Tool namespacing / federation — explicitly solved**
- "Virtual MCP" multiplexes multiple targets into one MCP server. Default behavior prefixes tool/prompt names with the target name (`time_get_current_time`, `everything_echo`). `prefixMode`: **`conditional`** (default — prefix only when >1 target), **`always`**, **`never`** (never = startup *fails* on a name collision, which is the right failure mode). https://agentgateway.dev/docs/standalone/latest/mcp/connect/virtual.md

**6. Audit logging / observability**
- Structured stdout access logs with MCP-specific fields: `mcp.method.name`, `mcp.session.id`, `mcp.target`, `gen_ai.tool.name`, `mcp.resource.type`/`uri`; tool arguments/results/errors addable via CEL in access-log policies — a real audit trail. https://agentgateway.dev/docs/standalone/latest/mcp/mcp-observability.md
- Prometheus metrics at `:15020/metrics` incl. `mcp_requests_total` (labels: server, method, resource name/type). https://agentgateway.dev/docs/standalone/latest/reference/observability/metrics.md
- OTel traces (`otlpEndpoint`, OTLP 4317), spans like `call_tool`; Jaeger integration. https://agentgateway.dev/docs/standalone/latest/reference/observability/traces.md , https://agentgateway.dev/docs/standalone/latest/integrations/observability/opentelemetry.md , https://agentgateway.dev/docs/standalone/latest/integrations/observability/jaeger.md
- Dedicated health-check endpoints are not documented on the observability page (k8s probes presumably via Helm chart).

**7. Deployment complexity — low**
- Standalone: **single Rust binary + one YAML file** (`agentgateway -f config.yaml`), or Docker. Data plane :3000, admin/UI :15000, metrics :15020. **No Postgres/Redis/etcd documented anywhere.** https://agentgateway.dev/docs/standalone/latest/mcp/connect/stdio.md , https://agentgateway.dev/docs/
- Kubernetes: built-in control plane + **Kubernetes Gateway API** (v1.6 as of 1.4.0), Helm install, CRDs `AgentgatewayPolicy`, `AgentgatewayBackend`, `AgentgatewayParameters`, experimental `AgentgatewayModel`.
  - https://agentgateway.dev/docs/kubernetes/latest/about/gateway-api.md
  - https://agentgateway.dev/docs/kubernetes/latest/install/helm.md
  - https://agentgateway.dev/docs/kubernetes/latest/reference/api-kubespec/policies.md
  - https://agentgateway.dev/docs/kubernetes/latest/about/architecture.md

**8. Maturity**
- **Post‑1.0.** Latest stable **v1.4.1 (2026‑07‑29)**; **v1.5.0‑beta.1 (2026‑08‑25)** in flight. Roughly monthly minors with alpha→beta→stable train. https://github.com/agentgateway/agentgateway/releases
- Very high activity: **~25 commits in the 2 days 2026‑08‑24 → 2026‑08‑26**. https://github.com/agentgateway/agentgateway/commits/main.atom
- Breaking changes do happen across minors (v1.4.0: Gateway API v1.6 + TCPRoute v1, MCP guardrail rejections now return HTTP 200 instead of an error code, standalone `auth.location` flattened from nested, musl container images dropped). Pin your minor version.
- 4.6k stars, 256 open issues, weekly public community meetings.

---

# PROJECT B — Unla

**1. Governance / backing / origin**
- Maintained by **AmoyLab**, a small GitHub org (no foundation, no named corporate sponsor). https://github.com/AmoyLab/Unla
- **Renamed**: org `mcp-ecosystem` → `amoylab`, repo `mcp-gateway` → `unla`. Old URLs still redirect (https://github.com/mcp-ecosystem/mcp-gateway/blob/main/README.md serves the Unla README). Go module is `github.com/amoylab/unla` (https://pkg.go.dev/github.com/amoylab/unla); images at `ghcr.io/amoylab/unla/allinone:latest`. Route prefixes also moved `/mcp` → `/gateway`.
- 2.2k stars, 180 forks, 55 open issues, ~574 commits total. Docs: https://docs.unla.amoylab.com

**2. stdio child processes → HTTP/SSE — YES, and it does both jobs**
- Confirmed at https://docs.unla.amoylab.com/en/configuration/gateways.md — `mcpServers[].type: "stdio"` with `command`, `args`, `env`. Documented example is exactly the npx pattern:
  ```yaml
  mcpServers:
    - type: "stdio"
      name: "amap-maps"
      command: "npx"
      args: ["-y", "@amap/amap-maps-mcp-server"]
      env:
        AMAP_MAPS_API_KEY: "{{.Request.Headers.Apikey}}"
  ```
- Three upstream transports: `stdio`, `sse`, `streamable-http`. Exposed downstream per route prefix: `${prefix}/sse`, `${prefix}/mcp`, `${prefix}/message` (e.g. `http://localhost:5235/gateway/user/sse`). https://docs.unla.amoylab.com/en/quickstart.md
- So it is **not** only REST→MCP — it does REST/OpenAPI→MCP *and* proxies stdio/SSE/HTTP MCP servers. (gRPC and WebSocket conversion are listed as planned, not shipped.)

**3. Credential injection — yes, via Go templates; secret handling is weak**
- **Env vars into stdio children**: `env:` map with Go template values. **Headers/bearer to remote upstreams**: `headers: { Authorization: "{{.Config.Authorization}}", Cookie: "{{.Config.Cookie}}" }`, and `'Bearer {{ env "AUTH_TOKEN" }}'`. Templates can read `.Request.Headers`, `.Args`, `.Config`, and `{{ env "VAR" "default" }}` with defaults. https://docs.unla.amoylab.com/en/configuration/gateways.md , https://docs.unla.amoylab.com/en/configuration/templates.md
- Config-level `${VAR:default}` interpolation from `.env`. https://docs.unla.amoylab.com/en/configuration/mcp-gateway.md
- **Red flag:** there is no secrets manager, no encrypted-at-rest secret store, no KMS/Vault integration documented. Secrets live in the gateway config (DB or YAML) and in `.env`. The documented pattern `{{.Request.Headers.Apikey}}` pushes the credential onto the *client*, which is the opposite of gateway-held credential injection.
- OAuth "pre-authentication for MCP Servers" exists for upstreams that need an OAuth dance. https://docs.unla.amoylab.com/en/configuration/oauth-login.md

**4. Per-client inbound auth**
- Management plane: JWT (`APISERVER_JWT_SECRET_KEY`, 24h default TTL), auto-created super admin (`SUPER_ADMIN_USERNAME`/`PASSWORD`), OAuth2 login via Google/GitHub, PKCE added in v0.9.1. https://docs.unla.amoylab.com/en/configuration/apiserver.md , https://github.com/AmoyLab/Unla/releases/tag/v0.9.1
- Multi-tenancy is a listed feature (tenants own route prefixes) with persistent/recoverable sessions, but there is **no CEL/RBAC policy engine, no per-tool authorization, no JWT-claim-based tool gating** documented anywhere. Data-plane inbound auth is effectively "protect the prefix", not fine-grained.
- Security controls that do exist: internal-network allowlist that **blocks tool access by default** and permits only configured targets (v0.9.1) — genuinely good SSRF defense; plus SSRF-bypass hardening for 302 redirects, DNS rebinding, IPv4-mapped IPv6 CGNAT (2026‑03‑11) and a path-traversal fix in tool endpoint rendering.

**5. Tool namespacing — essentially absent**
- Tool names are **not prefixed**. Isolation is achieved only by giving each MCP service its own route prefix (`/gateway/<prefix>/sse`), so each client connects to one service. https://docs.unla.amoylab.com/en/configuration/gateways.md
- Practical consequence: if you put multiple upstream MCP servers behind one prefix, there is no documented collision detection or renaming strategy. No `prefixMode` equivalent.

**6. Audit logging / observability**
- **Prometheus metrics** (MCP API request counts, status codes, tool execution timing) — added in v0.9.1 and **disabled by default**. https://github.com/AmoyLab/Unla/releases/tag/v0.9.1
- **OpenTelemetry tracing** → Jaeger, added v0.9.0 (2025‑09‑17); optional request-body and full-response capture. https://docs.unla.amoylab.com/en/configuration/mcp-gateway.md
- Structured logging (zap-style: levels, JSON/console, rotation, stack traces). "Operation logs" stored in the web DB. https://docs.unla.amoylab.com/en/configuration/apiserver.md
- No dedicated tool-call audit-log schema documented (nothing comparable to agentgateway's `gen_ai.tool.name` access-log fields + CEL enrichment). Health monitoring is mentioned as a recommendation, not a documented endpoint.

**7. Deployment complexity — meaningfully heavier**
- **All-in-one container** exists and is the quickstart path: one image running **API Server + MCP Gateway + Mock User Service + Web frontend + Nginx under Supervisor**. Ports 8080 (web), 5235 (gateway), internal 5234 (apiserver), 5335 (gateway mgmt — docs warn *do not expose*), 5236 (mock). Mounts `/app/configs`, `/app/data`, `/app/.env`. https://docs.unla.amoylab.com/en/deployment/docker.md
- **docker-compose (the production path) requires, exactly:** `postgres:16`, `redis:7`, `web` (frontend + API backend, ports 8080 + 5234), `mcp-gateway` (5235), `mock-server` (5236) — **five services**, plus an Nginx reverse proxy recommended to route `/api/`, `/ws/`, `/gateway/`, `/mock/` with WebSocket upgrade headers. So: **Postgres + Redis + a separate web UI container + a separate apiserver + nginx.** https://docs.unla.amoylab.com/en/deployment/docker.md
- Redis is needed for config pub/sub hot-reload and for session storage in clustered mode; single-node can use SQLite + OS-signal notifier and memory sessions. Storage options: disk/SQLite/Postgres/MySQL, or an external API. No etcd. https://docs.unla.amoylab.com/en/configuration/mcp-gateway.md
- Binary deploy and a Helm chart also exist. https://docs.unla.amoylab.com/en/deployment/binary.md , https://docs.unla.amoylab.com/en/deployment/k8s.md
- Even the minimal path requires setting three secrets (`APISERVER_JWT_SECRET_KEY`, `SUPER_ADMIN_USERNAME`, `SUPER_ADMIN_PASSWORD`) before it will run. https://docs.unla.amoylab.com/en/quickstart.md

**8. Maturity red flags — your sparse-commit suspicion is CONFIRMED**
- **Pre‑1.0: latest is v0.10.0, released 2026‑08‑04.** Verified from the atom feed: v0.10.0 2026‑08‑04, v0.9.2 2026‑01‑21, v0.9.1 2026‑01‑09, v0.9.0 2025‑09‑17, v0.8.6 2025‑07‑16, v0.8.5 2025‑07‑14, v0.8.4 2025‑07‑13, v0.8.3 2025‑07‑09, v0.8.2 2025‑07‑03, v0.8.1 2025‑06‑27. https://github.com/AmoyLab/Unla/releases.atom
- **Cadence has collapsed.** Six releases in ~3 weeks of June–July 2025, then only *four* releases in the following 13 months. Seven-month gap between v0.9.2 (Jan 2026) and v0.10.0 (Aug 2026).
- **Last commit 2026‑08‑04** ("fix: stabilize redis session stream startup") — **22 days stale as of today (2026‑08‑26)**. The 20 most recent commits span **2026‑02‑28 → 2026‑08‑04**, i.e. ~20 commits in 5+ months, and they arrive in bursts on single days (2026‑02‑28, 03‑11, 03‑19, 04‑17, 04‑22, 06‑08, 08‑04) — the signature of one maintainer doing occasional weekend passes. https://github.com/AmoyLab/Unla/commits/main.atom
- Commit content is dominated by **CVE bumps and security patches** rather than features: "bump vulnerable go modules", "upgrade packages to fix new CVEs", "prevent SSRF bypass via 302 redirect, DNS rebinding and IPv4-mapped IPv6 CGNAT evasion". Maintenance mode, not development.
- The rename (`mcp-ecosystem/mcp-gateway` → `AmoyLab/Unla`) is itself a discontinuity: stale docs/blogs/images across the internet, changed route prefixes (`/mcp` → `/gateway`), changed Go module path.
- 55 open issues against a ~1-maintainer cadence.

---

## Bottom line for your evaluation

| | agentgateway | Unla |
|---|---|---|
| Governance | Linux Foundation (direct, 2025‑08‑25), Solo.io-built, 15+ enterprise contributors | Single small org (AmoyLab), no foundation |
| stdio wrapping | Yes (`cmd`/`args`; npx + uvx documented) | Yes (`command`/`args`/**`env`**) |
| Env-var secret injection into stdio child | **Not documented** — verify in source | **Yes**, explicitly |
| Remote credential injection | Excellent: API key, passthrough, AWS/GCP, RFC 8693 token exchange, ID‑JAG, per-target | Basic: Go-template headers/bearer from env or client headers |
| Inbound authz | OAuth 2.1 RS + JWT + **CEL per-tool policy** | JWT/OAuth on mgmt plane; no per-tool policy engine |
| Tool namespacing | `prefixMode` conditional/always/never with fail-fast | None — prefix-per-service only |
| Observability | OTel + Prometheus + CEL-enriched tool-call audit logs | OTel + Prometheus (metrics off by default), thinner audit |
| Deps | Single binary + YAML, no datastore | Postgres + Redis + web + apiserver + nginx (5 compose services) |
| Maturity | v1.4.1 stable, ~25 commits/2 days, monthly minors (breaking changes across minors) | v0.10.0 pre‑1.0, ~20 commits in 5 months, last commit 22 days ago, renamed once |

The one thing Unla does better for your likely use case is the explicit **`env:` injection into stdio children**, which agentgateway's stdio docs don't show. If that is your core requirement, confirm agentgateway's stdio schema in the Rust source before ruling it out — everything else (governance, activity, policy depth, namespacing, deployment weight) favors agentgateway decisively.

### ContextForge docs deep dive

# IBM ContextForge (mcp-context-forge) — Research Report

Note: I read source files (`db.py`, `config.py`, `translate.py`, `docker-compose.yml`, `.env.example`, `pyproject.toml`) via `raw.githubusercontent.com` fetches — no clone, no files written (one temp compose copy in the scratchpad, deleted).

---

## 1. Stdio wrapping → SSE / Streamable HTTP

**Two separate CLI processes, neither in-process in the gateway.**

- **`mcpgateway.translate`** — a standalone CLI: `python3 -m mcpgateway.translate --stdio "uvx mcp-server-git" --expose-sse --port 9001`. Bridges bidirectionally: stdio→HTTP (`--expose-sse` → `/sse` + `/message`; `--expose-streamable-http` → `/mcp`) and HTTP→stdio (`--connect-sse`, `--connect-streamable-http`, `--stdioCommand`). Also has gRPC modes (`--grpc`, `--connect-grpc`), `--oauth2Bearer`, `--keepAlive` (default 30s), `--stateless`, `--jsonResponse`, `--cors`.
- **`mcpgateway.reverse_proxy`** — outbound WebSocket tunnel from a local box: `python3 -m mcpgateway.reverse_proxy --local-stdio "uvx mcp-server-git" --gateway https://gateway.example.com --token …`. Good for NAT/firewall traversal; "Reverse-proxied servers automatically appear in the gateway's server catalog."
- **`mcpgateway.wrapper`** — the opposite direction (gateway → stdio for clients like Claude Desktop), not for upstream registration.

**Can a stdio server be a persistent gateway "peer"? No.** Direct answer from a maintainer in [discussion #1086](https://github.com/IBM/mcp-context-forge/discussions/1086):

> "gateways are network-accessible HTTP endpoints — they have a `url` field pointing to a remote (or local) MCP server. STDIO requires spawning a local process"

So: **one `translate` (or `reverse_proxy`) process per stdio server**, run and supervised by you, then register the resulting `http://host:port/sse` or `/mcp` URL in the Admin UI/API with transport `SSE` or `STREAMABLEHTTP`. The gateway core never spawns stdio children for upstream MCP servers. (ADR-037 "external plugin stdio launch" is about *plugins*, a separate subsystem.)

## 2. Virtual servers

Definition (FAQ): **"A Virtual Server is a MCP Server composed from Tools/Resources/Prompts from multiple servers."** UI-concepts: **"A virtual server is a logical wrapper that combines selected tools, resources, and prompts under one context-specific endpoint."**

Composition is by explicit ID list:
```
POST /servers
{"server": {"name": "my-virtual-server", "description": "...",
            "associated_tools": ["tool-id-1", "tool-id-2"]}}
```
plus optional `visibility` and `team_id`. Clients connect at `/servers/{id}/sse` or `/servers/{id}/mcp`.

**Auth to a specific virtual server: there is no per-virtual-server API key today.** It's a single platform JWT/Bearer (`Authorization: Bearer $TOKEN`) plus a two-layer model:
- **Layer 1 — token scoping (visibility):** JWT carries a `teams` claim (`"teams": ["team-uuid-1"]`; `[]` = public only; `null` + `is_admin` = admin bypass). Resources have `visibility` ∈ `private` / `team` / `public`.
- **Layer 2 — RBAC permissions:** `servers.read`, `servers.use`, `tools.read`, `tools.execute`, etc., via roles (`platform_admin`, `team_admin`, `developer`, `viewer`) assigned at global/team/personal scope.

Per-server scoped tokens are **roadmap, not shipped**: "#2712 Virtual Server token enforcement - require scoped tokens for access" is listed ⏳ for 1.1.0. So today a valid team token that can see a virtual server can generally also reach other resources of the same visibility — isolation is by team/visibility, not by server endpoint.

## 3. Credential injection into upstream servers — the strongest area

**Yes for HTTP/SSE upstreams. No native mechanism for stdio children.**

Per-gateway (and per-tool) auth stored in the DB, encrypted:
- `auth_type` ∈ `basic`, `bearer`, `authheaders`, `oauth`, `none`.
- `authheaders` supports N arbitrary headers:
  ```json
  {"name":"My Gateway","url":"http://mcp-server.example.com","auth_type":"authheaders",
   "auth_headers":[{"key":"X-API-Key","value":"secret-key-123"},{"key":"X-Client-ID","value":"client-456"}]}
  ```
  Legacy `auth_header_key`/`auth_header_value` still supported; multi-header wins.
- Encryption: **"All authentication headers are encrypted before being stored in the database using AES-256-GCM encryption. The encryption key is derived from the `AUTH_ENCRYPTION_SECRET` environment variable."** `AUTH_ENCRYPTION_SECRET` is **REQUIRED in all environments**, ≥32 chars, high entropy; startup fails on weak/placeholder values (hardened in 1.0.7/1.0.8). Generate via `python3 -m mcpgateway.scripts.init_secrets`.

**OAuth 2.0** (`auth_type: "oauth"`): both `client_credentials` and `authorization_code` grants. Fields: `client_id`, `client_secret`, `token_url`, `authorization_url`, `redirect_uri` (`/oauth/callback`), `scopes`, `grant_type`. PKCE (RFC 7636) automatic on auth-code. Tokens encrypted at rest, auto-refreshed, and **scoped per user**: unique per gateway + `app_user_email`, "preventing token sharing across users." Env: `OAUTH_REQUEST_TIMEOUT=30`, `OAUTH_DEFAULT_TIMEOUT=3600`. RFC 8693 token exchange added in 1.0.6.

**External secret manager: HashiCorp Vault is supported** as an OAuth token backend — `OAUTH_TOKEN_BACKEND=database|vault`, `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_KV_MOUNT=secret`, `VAULT_KV_PATH_PREFIX=contextforge/oauth`, `VAULT_TLS_VERIFY`, `VAULT_TOKEN_CACHE_ENABLED/TTL/MAX_SIZE`. Path structure: `{mount}/data/{prefix}/{team_id}/{server_id}/{email}`. 1.0.6 added "per-user credential resolution from HashiCorp Vault for **all auth types**." KV v2 is described as "recommended for enterprise."

**Header passthrough** (client → upstream), off by default:
- `ENABLE_HEADER_PASSTHROUGH=true`, `DEFAULT_PASSTHROUGH_HEADERS=["X-Tenant-Id","X-Trace-Id"]` (JSON array or CSV), `PASSTHROUGH_HEADERS_SOURCE` ∈ `db` (default) / `env` / `merge`, per-gateway override highest priority, `ENABLE_OVERWRITE_BASE_HEADERS=false` (needed to let passthrough clobber `Authorization`/`Content-Type`).
- Docs: **"Feature disabled by default for security reasons. Only enable this feature if you understand the security implications."** and **"Be extremely careful when forwarding authentication tokens."**
- **`X-Upstream-Authorization`** is the two-layer escape hatch: gateway renames it to `Authorization` when forwarding upstream, and it is **"always forwarded regardless of the `ENABLE_HEADER_PASSTHROUGH` flag."**
- Guards: header names must match `^[A-Za-z0-9-]+$`, values newline-stripped and capped at 4KB, auth-conflicting headers skipped, config endpoints rate-limited 20–30 req/min. Loopback transports never forward gateway-internal headers.
- `ENABLE_SENSITIVE_HEADER_PASSTHROUGH` exists for A2A. `MASKED_AUTH_VALUE=*****` masks secrets in logs.

**Env-var injection into stdio children — be precise:** not a gateway feature at all. It lives only in `mcpgateway.translate`, and there is **no static `--env` flag**. `StdIOEndpoint.start()` does `env = os.environ.copy()` then `env.update(self._env_vars)` — i.e. the child inherits whatever environment *you* gave the translate process. On top of that, per-request dynamic injection: `--enable-dynamic-env` plus repeatable `--header-to-env "HEADER=ENV_VAR"` maps incoming HTTP headers into the child's env, with unmapped vars deliberately `pop()`'d each start so credentials don't leak across requests (system-critical vars like `PATH`/`HOME` are protected). Case-insensitive duplicate mappings are rejected. **The gateway DB stores no env vars for stdio children** — that secret lives in your process supervisor, not in ContextForge's encrypted store.

## 4. Tool name namespacing (ADR-011)

Scheme: `{slugified_gateway_name}{separator}{original_tool_name}`, e.g. `gateway-1-get_system_time` and `gateway-2-get_system_time` coexist. Separator is `GATEWAY_TOOL_NAME_SEPARATOR`, default `-`, validated against `^(-{1,2}|[_.])$` — so only `-`, `--`, `_`, `.` are legal; anything else logs a warning and falls back to `-`. DB keeps `original_name` (sent on invocation), `gateway_slug`, and a computed `name` property. **Collisions across gateways are therefore prevented rather than resolved** — no rename/suffix logic needed. There is a startup slug-refresh job (`slug_refresh_batch_size=1000`).

## 5. Audit, health, observability

**Health (ADR-009, accepted 2025-02-21):** `/health` (DB connectivity + response time, optional Redis/in-memory cache ping), `/ready`, `/healthz`. Upstream peers polled by a background task in `GatewayService`: **"Every `HEALTH_CHECK_INTERVAL`, we ping all registered peers via HTTP."** Env: `HEALTH_CHECK_INTERVAL=300`, `HEALTH_CHECK_TIMEOUT=30`, `UNHEALTHY_THRESHOLD=3`, `MAX_CONCURRENT_HEALTH_CHECKS=10`, `GATEWAY_VALIDATION_TIMEOUT=5`. Failing peers get tagged `Offline` and auto-return to `Active` on recovery.

**Audit:** two things, both **off by default for performance**: `AUDIT_TRAIL_ENABLED=false` ("Enable audit trail logging to database for compliance") and `PERMISSION_AUDIT_ENABLED=false` ("writes a row per permission check"). `SECURITY_LOGGING_ENABLED=false`. SIEM export is independent: `SIEM_EXPORT_EVENT_SOURCES=["auth","security","audit"]`. Separately, always-on **metadata tracking** on every entity — `created_by/at/from_ip/via/user_agent`, `modified_*`, `import_batch_id`, `federation_source`, `version` — "No environment variables needed - uses existing `AUTH_REQUIRED` setting."

**Tracing:** `OTEL_ENABLE_OBSERVABILITY` (default false), `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (grpc | http/protobuf), `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_TRACES_EXPORTER` (otlp/jaeger/zipkin/console/none), `OTEL_SERVICE_NAME`, `OTEL_DEPLOYMENT_ENVIRONMENT`. Documented backends: Langfuse, Arize Phoenix, Jaeger, Grafana Tempo; also Datadog/New Relic/Honeycomb/Zipkin. Spans cover tool invocations, prompt rendering, resource fetching, gateway federation, plugin execution, errors.

**Prometheus — caveat.** ADR-010 is "Accepted" (2025-02-21) and calls for a "Prometheus-compatible `/metrics` endpoint," and `prometheus-fastapi-instrumentator>=8.1.0` + `prometheus_client>=0.26.0` are hard dependencies. But `main.py`'s `/metrics` is `APIRouter(prefix="/metrics", tags=["Metrics"])` — an authenticated JSON metrics API — and I found no `Instrumentator()` wiring in `main.py` and no prometheus references in `observability.py`. Built-in metrics are DB-backed: **"All trace data is stored in your database (SQLite/PostgreSQL) and visualized through the Admin UI"** (`ObservabilityTrace` / `ObservabilitySpan` tables). The compose Prometheus stack scrapes *sidecar exporters* (`postgres_exporter`, `redis_exporter`, `pgbouncer_exporter`, `nginx_exporter`, `cadvisor`), which is consistent with the gateway not exposing native Prometheus text. Treat Prometheus-format app metrics as unverified. Related env: `ENABLE_METRICS=true`, `METRICS_RETENTION_DAYS=7`, `DB_METRICS_RECORDING_ENABLED`, `METRICS_AGGREGATION_AUTO_START`, `OBSERVABILITY_TRACE_RETENTION_DAYS`.

## 6. Deployment weight

**`docker-compose.yml` is 2,740 lines with 40 services.** 8 run by default (no `profiles:` key): `nginx`, `gateway`, `postgres`, `pgbouncer`, `migration`, `redis`, plus two demo services `fast_time_server` and `register_fast_time`. So the real default stack is **6 infra containers + 2 demo**. PgBouncer is "enabled by default." The other 32 are profile-gated: `keycloak`, `prometheus`, `grafana`, `loki`, `tempo`, `promtail`, 4 exporters, `cadvisor`, `pgadmin`, `redis_commander`, `web_ui`+`web_ui_redis`, `locust`/`locust_worker`, `mcp_inspector`, `zap`, `nginx_tls`/`cert_init`, more demo servers/A2A agents. README says compose fronts 3 gateway replicas behind nginx on 8080.

**SQLite single-container is viable and documented** — `deployment/container/` shows a one-liner `docker run` with `DATABASE_URL=sqlite:///./mcp.db`. Postgres is "recommended for production"; Redis is optional (caching + federation). PostgreSQL via psycopg3 (`postgresql+psycopg://`, ADR-027).

**Heaviness:** **66 `__tablename__` declarations in `mcpgateway/db.py`.** `.env.example` is **4,114 lines** with **58 active `KEY=VALUE`** lines and **1,095 commented-out documented settings** (~1,150 knobs total). This is a large, enterprise-shaped system, not a thin proxy. Also FastAPI/Pydantic, async SQLAlchemy, orjson, Granian option, and a partially-adopted Rust workspace.

## 7. Maturity

- **Past 1.0. Current: 1.0.8, 2026-08-18** (PyPI and GitHub Releases agree). Cadence ~2 weeks: 1.0.0 GA → 1.0.1 (May 13) → … → 1.0.8 (Aug 18, 2026).
- **Docs are inconsistent about version.** README badge still shows `1.0.0-RC-3`; `deployment/container/` examples still pin `ghcr.io/ibm/mcp-context-forge:1.0.0-RC-2`; the roadmap page still says "next major release is 1.0.0-GA (due 28 Mar 2026)". The docs site itself is dated 2026-08-13. Expect stale snippets.
- **Requires Python >=3.12,<3.14** (1.0.8 dropped 3.11 — a breaking change).
- **Breaking changes per release, actively:** 1.0.8 — `AUTH_ENCRYPTION_SECRET` ≥32 chars unconditional, Python 3.11 dropped, OAuth routes require named permissions; 1.0.7 — weak-secret rejection at startup, root URI policy defaults to deny; 1.0.5 — environment-bound JWT validation; 1.0.2 — outbound HTTP redirect following disabled (SSRF defense). Migration notes accompany each.
- **Formal deprecations page** (as of 2026-06-11): Rust MCP runtime sidecar deprecated with **sunset 2026-07-07** (`RUST_MCP_MODE`, `EXPERIMENTAL_RUST_MCP_*`, `MCP_RUST_*`) — "Use the default Python MCP transport path"; `ValidationMiddleware` deprecated (no sunset), keep `VALIDATION_MIDDLEWARE_ENABLED=false`; legacy HTTP+SSE transport deprecated by MCP spec — "Use Streamable HTTP for new gateway registrations."
- **Explicitly experimental:** gRPC services; PostgreSQL 18 migration (1.3.0); the Rust runtime shipped and was deprecated within months (ADR-038 vs. the deprecation page) — a signal that architectural direction is still moving.
- **Issue/PR signals:** ~4.4k stars, **~895 open issues and ~298 open PRs**, 3,146 commits on main (GitHub rate-limited my API confirmation, so these come from the repo page render). Very high open-PR count relative to size.
- Docs warn `mcp-servers/` sample servers "lack production concerns (session management, auth, multi-tenancy)" and should not run in production; and "Do not use it with insecure MCP servers." Securing guide: "Never store secrets in environment variables directly… Use a secrets management system (Vault, AWS Secrets Manager, etc.)."

---

### Bottom line for your use case
Credential injection into **HTTP/SSE** upstreams is genuinely strong (AES-256-GCM at rest, per-user OAuth, Vault backend, multi-header). Credential injection into **stdio children is out of scope for the gateway** — you run one `mcpgateway.translate` process per stdio server and supply its environment yourself; only per-request header→env mapping is offered, and only inside that CLI. Per-virtual-server API keys don't exist yet; isolation is team + visibility + RBAC.

### URLs fetched
Docs: [/latest/](https://ibm.github.io/mcp-context-forge/latest/) · [/using/mcpgateway-translate/](https://ibm.github.io/mcp-context-forge/using/mcpgateway-translate/) · [/using/mcpgateway-wrapper/](https://ibm.github.io/mcp-context-forge/using/mcpgateway-wrapper/) · [/using/reverse-proxy/](https://ibm.github.io/mcp-context-forge/using/reverse-proxy/) · [/using/multi-auth-headers/](https://ibm.github.io/mcp-context-forge/using/multi-auth-headers/) · [/overview/ui-concepts/](https://ibm.github.io/mcp-context-forge/overview/ui-concepts/) · [/overview/passthrough/](https://ibm.github.io/mcp-context-forge/overview/passthrough/) · [/latest/faq/](https://ibm.github.io/mcp-context-forge/latest/faq/) · [/manage/oauth/](https://ibm.github.io/mcp-context-forge/manage/oauth/) · [/manage/rbac/](https://ibm.github.io/mcp-context-forge/manage/rbac/) · [/manage/teams/](https://ibm.github.io/mcp-context-forge/manage/teams/) · [/manage/api-usage/](https://ibm.github.io/mcp-context-forge/manage/api-usage/) · [/manage/securing/](https://ibm.github.io/mcp-context-forge/manage/securing/) · [/manage/metadata-tracking/](https://ibm.github.io/mcp-context-forge/manage/metadata-tracking/) · [/manage/observability/observability/](https://ibm.github.io/mcp-context-forge/manage/observability/observability/) · [/manage/observability/internal-observability/](https://ibm.github.io/mcp-context-forge/manage/observability/internal-observability/) · [/deployment/compose/](https://ibm.github.io/mcp-context-forge/deployment/compose/) · [/deployment/container/](https://ibm.github.io/mcp-context-forge/deployment/container/) · [/howto/rbac-tool-authorization/](https://ibm.github.io/mcp-context-forge/howto/rbac-tool-authorization/) · [/architecture/roadmap/](https://ibm.github.io/mcp-context-forge/architecture/roadmap/) · [ADR-009](https://ibm.github.io/mcp-context-forge/architecture/adr/009-built-in-health-checks/) · [ADR-010](https://ibm.github.io/mcp-context-forge/architecture/adr/010-observability-prometheus/) · [ADR-011](https://ibm.github.io/mcp-context-forge/architecture/adr/011-tool-federation/) · [/latest/deprecations/](https://ibm.github.io/mcp-context-forge/latest/deprecations/) · [sitemap.xml](https://ibm.github.io/mcp-context-forge/sitemap.xml)

GitHub/PyPI: [repo](https://github.com/IBM/mcp-context-forge) · [releases](https://github.com/IBM/mcp-context-forge/releases) · [discussion #1086](https://github.com/IBM/mcp-context-forge/discussions/1086) · [PyPI mcp-contextforge-gateway](https://pypi.org/project/mcp-contextforge-gateway/) · raw `main`: `README.md`, `.env.example`, `docker-compose.yml`, `pyproject.toml`, `mcpgateway/db.py`, `mcpgateway/config.py`, `mcpgateway/translate.py`, `mcpgateway/main.py`, `mcpgateway/observability.py`

### Survey MCP gateway candidates

_(no report - agent died before delivering)_
