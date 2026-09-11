# MCP gateway lab

Tests a gateway against mock MCP servers shaped like the team's real ones,
without touching production credentials or backends.

## Why mocks
Each mock exposes `<name>_credcheck`, which reports **whether** it received its
expected credential plus a fingerprint — never the credential itself. That makes
it possible to prove credential injection worked while guaranteeing the secret
cannot leak into a test transcript.

## Go implementation (08 Sep 2026) — the harness for the new build

`AGENTS.md` §5.4 says to reuse this lab as the test harness for the custom
gateway itself, not just for evaluating third-party candidates. The Python/
Docker harness described in the rest of this file (below) was built for the
candidate evaluation in Round 3/5 (`DEVELOPMENT-LOG.md` §5, §10.1a) and never
made it into this repository — only this README did. Since the project
settled on Go (`design/adr/0002`), the mocks and probe were rebuilt in Go
rather than resurrecting the Python originals, using the same `<name>_credcheck`
pattern and the official `github.com/modelcontextprotocol/go-sdk`:

| Path | What it is |
|---|---|
| `lab/mockutil/` | Shared `AddCredCheck(server, toolName)` — the one place the `<name>_credcheck` logic exists, used by every mock below. Reads `MOCK_SECRET`/`MOCK_EXPECT` from its process environment, returns `{received_expected_secret, fingerprint}` — never the secret. |
| `lab/servers/casemgmt/`, `lab/servers/logsearch/`, `lab/servers/docsearch/`, `lab/servers/threatintel/` | One fake MCP server per real backend, each with 2 canned domain tools (no network calls, no real data) plus `<name>_credcheck`. |
| `lab/probe/` | The verification tool: spawns a mock over stdio with a freshly-generated secret in `MOCK_SECRET`/`MOCK_EXPECT`, calls its credcheck tool, and — independent of that result — scans every raw byte of MCP wire traffic (via `mcp.LoggingTransport`) for the secret. Exit codes: `0` pass, `1` a real problem was found (bad credcheck result and/or a leak — a leak always forces `1`, never masked by a usage-error code), `2` the probe itself couldn't run (bad args, spawn/connect/parse failure). |

### Tool naming: the mocks mirror the real fleet, warts included

A mock's tools carry the names its **real counterpart** uses, not a tidy
invented scheme, because the point of a mock is to be shaped like the
thing it stands in for.

That means the real fleet's inconsistency shows through, deliberately:

| Upstream | Tool names | Client-facing, after namespacing |
|---|---|---|
| `casemgmt` | `list_cases`, `get_case` | `casemgmt.list_cases` |
| `logsearch` | `search_relative`, `search_keyword` | `logsearch.search_relative` |
| `threatintel` | `lookup_ip`, `enrich` | `threatintel.lookup_ip` |
| `docsearch` | `docsearch_search`, `docsearch_list_indices` | `docsearch.docsearch_search` |

`docsearch` really does self-prefix its own tools, so `docsearch.docsearch_search`
is the genuine production name and not a bug to tidy away. The mocks
briefly all self-prefixed, which made `casemgmt.casemgmt_list_cases` the name a
role would have had to grant -- wrong for three of the four backends, and
wrong in the silent direction: a role written against the real names would
authorize nothing, and the analyst would simply see an empty tool list.

The `<name>_credcheck` tools keep their prefix regardless. That convention
predates namespacing, `lab/probe` is invoked with those exact names, and it
is what lets a credcheck result say which upstream answered.

Build and run:

```bash
go build -o /tmp/lab-bin/casemgmt ./lab/servers/casemgmt        # and logsearch, docsearch, threatintel
go build -o /tmp/lab-bin/probe ./lab/probe
/tmp/lab-bin/probe --tool casemgmt_credcheck -- /tmp/lab-bin/casemgmt
```

This is what `WORKFLOW.md` Phase 5 means by "run `probe.py`'s clean-environment
credential-injection + leak check exactly as done for every external
candidate" — same test, same property, Go instead of Python, real subprocess
spawning rather than in-memory (each package also has its own `go test`
suite using `mcp.NewInMemoryTransports()` for fast unit-level coverage; the
probe binary above is the true end-to-end check, same as it was for every
third-party candidate below).

## The rest of this file: the original (Python/Docker) evaluation harness

Everything below documents the harness and results from evaluating six
third-party gateway candidates (Round 1–5, `DEVELOPMENT-LOG.md`), kept for the
historical record. Its Python (`probe.py`) and Docker mock servers were never
committed to this repository — only this README survived the handoff. Do not
try to resurrect them; use the Go implementation above instead.

## The two scenarios

**A — today.** The client spawns the server and passes the key itself:

    LAB_SECRETS="vt-KEY-abc123" python3 probe.py stdio -- \
      docker run --rm -i -e MOCK_NAME=threatintel -e MOCK_SECRET=vt-KEY-abc123 \
      -e MOCK_EXPECT=vt-KEY-abc123 lab-threatintel:dev

**B — target.** The gateway holds the keys; the probe runs with a clean
environment and still gets working tools:

    ./bin/thv secret provider environment
    export TOOLHIVE_SECRET_THREATINTEL_VT_KEY=vt-KEY-abc123   # etc
    ./bin/thv run --name threatintel --transport stdio --group soc \
      --secret THREATINTEL_VT_KEY,target=MOCK_SECRET \
      -e MOCK_NAME=threatintel -e MOCK_EXPECT=vt-KEY-abc123 lab-threatintel:dev
    ./bin/thv vmcp serve --group soc
    python3 probe.py http http://127.0.0.1:4483/mcp

## Results — four gateways tested, 29 Aug 2026

Same harness for all: four mock stdio servers as Docker images, probe run with a
**clean environment** (no service credential present client-side).

| | ToolHive v0.46.0 | tbxark/mcp-proxy v0.58.0 | MCPJungle 0.4.6 | mcpproxy-go v0.62.0 | Wirken v1.18.0 |
|---|---|---|---|---|---|
| Single endpoint, all 4 servers | **YES** — 66 tools | **NO** — 4 routes | **YES** — 66 tools | **YES** — via meta-tools | n/a |
| Credential injection | PASS ×4 | PASS ×4 | PASS ×4 | n/a (quarantined) | n/a |
| Secret leaked to client | CLEAN | CLEAN | CLEAN | CLEAN | n/a |
| Client needs a service credential | No | No | No | No | n/a |
| Auth on the MCP endpoint | **NONE** in quick mode | **YES** — 401 without token | **NONE** in dev mode | **NONE** — key guards UI only |  n/a |
| Credentials readable by others | no | no | **YES — unauthenticated API** | no | n/a |
| Containers for 4 servers | 12 | 4 | 4 | 4 | n/a |
| Token reduction feature | `--optimizer`: 66 -> 2 | no | no | built-in: 66 -> 12 meta-tools | n/a |
| Release checksums | yes | yes | yes | yes | yes + sig + SLSA |

### Wirken is not an MCP gateway
`wirken run -p PORT` starts a **WebChat**, not an MCP endpoint. Wirken is a personal
AI-agent platform that *consumes* MCP servers as a client via its own `mcp.json`.
Its credential vault and hash-chained audit serve its own agent; an MCP client such
as Claude Code cannot connect to it. It was shortlisted on documented features
(vault, signed audit chain, single binary) without verifying it serves MCP —
testing corrected that.

Worth stealing regardless: `wirken mcp sign` / `wirken mcp verify` cryptographically
sign each MCP server entry in `mcp.json` and report valid/invalid/unsigned. That is
exactly the tool-definition pinning control recommended in the decision document.

### MCPJungle — credential exposure in default mode
With no authentication configured (the documented quickstart), an unauthenticated
`GET /api/v0/servers` returns every registered server's environment, **including the
injected credentials in plaintext**:

    threatintel       MOCK_SECRET = vt-KEY-abc123
    casemgmt        MOCK_SECRET = casemgmt-TOK-xyz789
    logsearch     MOCK_SECRET = gl-TOK-qqq111
    docsearch  MOCK_SECRET = os-PWD-zzz222

Secrets are also stored unencrypted in `mcpjungle.db`, mode 0644 (world-readable).
This inverts the goal: instead of one credential per analyst, anyone who reaches the
port gets all of them. Enterprise mode adds auth, but development mode is the default.

### ToolHive — no authentication in quick mode
`thv vmcp serve --group` has no authentication flags at all. An unauthenticated POST
returns HTTP 200 with full access to every tool and injected credential. Auth requires
the full `--config` file. Also: the `encrypted` secrets provider prompts for a keyring
password and fails on a non-TTY, so a headless server needs that password at boot.

### tbxark/mcp-proxy — no aggregation
It multiplexes onto one *port*, not one *endpoint*. Routes are `/threatintel/mcp`,
`/casemgmt/mcp`, `/logsearch/mcp`, `/docsearch/mcp`; `/mcp`, `/`, `/soc/mcp` all return 404.
The client config goes from four docker commands to four URLs. It has the best
authentication of the four tested: 401 without a token, 401 with a wrong token,
200 with the right one.

### mcpproxy-go — quarantine by default
New upstreams are quarantined pending human inspection, so their tools are not
exposed until approved — a genuine tool-poisoning defence. It exposes 12 meta-tools
(`retrieve_tools`, `call_tool`, …) rather than backend tools, BM25-searched. Its
auto-generated API key guards the web UI; the `/mcp` endpoint still answered without it.

## Round 2 — `agentic-community/mcp-gateway-registry`, 31 Aug 2026

Found in a follow-up web/GitHub scan (DEVELOPMENT-LOG.md §10.1) claiming
OAuth2/OIDC auth on by default plus per-user credential brokering — the
exact combination none of the five candidates above had. Different harness
than round 1: this project ships its own multi-container platform
(`docker-compose.prebuilt.yml`), so the mock servers/probe.py setup above
wasn't reused as-is — tested against the platform's documented Quick Start
directly instead, with a real Keycloak OAuth2 client-credentials flow.

| | mcp-gateway-registry (git 7f54d79, 31 Aug 2026) |
|---|---|
| Single endpoint, aggregation | Yes — nginx reverse proxy in front of registered servers |
| Auth on the MCP endpoint (documented Quick Start) | **YES** — 401 with no token, 401 with a garbage token, on both `/api/servers` and the live `tools/list`/`tools/call` path |
| Valid OAuth2 token works | **YES** — confirmed end-to-end: `init-keycloak.sh` → M2M client-credentials grant → HTTP 200 with real tool list |
| Credential injection to backend (static API key) | **NO** — `auth_scheme`/`auth_credential`/`auth_header_name` set at registration are never applied on the live `tools/call` path; confirmed both live (header dump below) and in source (see "Round 2 completed" below) |
| Platform container count (before any backend registered) | **9** — nginx/registry, auth-server, mcpgw-server, Keycloak, Keycloak's Postgres, MongoDB, OpenBao, Prometheus, Grafana |
| Release checksums | **None found** — no release assets on GitHub; ships as container images (ECR Public/DockerHub), signatures not checked this pass |
| Setup friction | `sudo` required by the setup script for a host log directory (worked around); Quick Start skips an embeddings-model pre-download step the full install guide requires |

### The one real defect found
The bundled default tool server (`airegistry-tools`, mcpgw's own
introspection server) was security-scanned at startup, flagged **HIGH
severity / UNSAFE**, and registered and enabled anyway — contradicting the
README's claim that "unsafe items are held for review." Not confirmed
whether a genuinely third-party server registration is actually held (the
registration flow itself wasn't exercised this pass).

### Round 2 completed — credential injection, live-tested and traced in source (31 Aug 2026)

Brought the stack back up, wrote a purpose-built streamable-HTTP mock
(`mockhttp_credcheck`, header-based rather than env-based — this platform's
backend model is "already-running HTTP server, credential injected
per-request," not "spawn a process with env vars" like the stdio gateways
tested in round 1), registered it via the actual REST flow (`/api/register`
→ session-cookie auth → CSRF token → `auth_scheme=api_key`,
`auth_credential=<fabricated test key>`, `auth_header_name=X-Threatintel-Api-Key`),
enabled it (needed an SSRF-allowlist entry for the docker-network hostname —
a real, working, fail-closed-by-default control, not a defect), and called
`tools/call` through the gateway with a valid M2M OAuth token from a clean
environment.

**Result: the credential was never injected.** The mock's header dump showed
only gateway-internal identity/audit headers (`x-user`, `x-username`,
`x-scopes`, `x-server-name`, `x-tool-name`, `x-auth-method`,
`x-client-id-auth`, `x-internal-token`) — no `X-Threatintel-Api-Key`, no
`Authorization`. Traced in source: `auth_credential`/`auth_header_name` are
read only by `registry/core/mcp_client.py` and `registry/health/service.py`
(the registry's own discovery/health-check connections) and by
`registry/services/skill_service.py` (an unrelated feature — fetching
"skill" content from GitHub/GitLab repos). **Zero references to either field
in `auth_server/server.py`'s `mcp_proxy` function — the actual code path
that handled this live request.** The only mechanism that injects a
credential into a live proxied call is `egress_auth` (OpenBao-backed,
`EGRESS_AUTH_ENABLED=false` by default), and it is OAuth-on-behalf-of-user
only (GitHub/Google/Atlassian/Microsoft/Slack/custom-OIDC) — structurally
inapplicable to a static third-party API key like VirusTotal's, Shodan's, or
our own `casemgmt`/`logsearch`/`docsearch` service credentials, which have no
OAuth authorize/token endpoint to broker.

Non-blocking friction hit along the way, noted for completeness: a fresh
`docker compose up` after `down -v` requires re-running
`keycloak/setup/init-keycloak.sh`, which regenerates client secrets that
`auth-server`'s own `.env`-sourced copy doesn't automatically pick up
without a container recreate — a real quickstart gap for anyone restarting
this stack, not a security finding.

### Verdict
**Ingress auth is real; the credential-consolidation problem is not
solved.** The security claim that disqualified the other five *is*
live-verified for the front door — no auth-bypass found anywhere, valid
tokens genuinely required and genuinely work. But the actual reason this
whole investigation started (`DEVELOPMENT-LOG.md` §2, Job 2 — "keys live in
the gateway, not on every laptop") is not solved by this platform for our
kind of backend: there is no live mechanism to inject a static per-server
API key into a proxied tool call. Combined with the 9-container operational
weight for a 7-person team with no platform role, this candidate is now a
**clear no** — not "adopt vs. build," it doesn't do the one thing the
custom build exists to do. Full writeup: `DEVELOPMENT-LOG.md` §10.1a.

## Teardown

    ./teardown.sh
    # for mcp-gateway-registry: docker compose -f docker-compose.prebuilt.yml down -v
    # (run from a clone of github.com/agentic-community/mcp-gateway-registry — not vendored into this repo)
