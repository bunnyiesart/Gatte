# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

A few operators on one SOC team share the operator role and take turns. They
run the gateway for about seven analysts. They reach the operator console at
a laptop, on the gateway host or through `ssh -L`, to work the tool approval
queue (reading a changed tool's definition and diff before approving it),
manage backends, and add, change or offboard people. Reading the audit trail
and blocking a subject happen in the SIEM and the CLI, not in the console
(design/adr/0061).

## Product Purpose

Gatte is a self-hosted MCP gateway for blue teams: one authenticated endpoint
in front of the team's MCP servers, so the production API keys behind those
tools live encrypted on one host instead of on every analyst's laptop. Every
call is checked (token, blocklist, role, quarantine, limits), recorded in a
hash-chained audit trail before it runs, and shipped to the SIEM. The
operator console is where a human makes the decisions the gateway cannot:
which configurations and tool definitions are trusted, and who has access.

## Positioning

It brokers static API keys rather than only OAuth, pins every tool to a
human-approved fingerprint of its definition, and treats its own limits as
part of the claim: what it does not cover is stated next to what it does.

## Operating Context

- The console is `mcp-gateway ui`, a foreground command the operator runs as
  themselves; it binds loopback only and lives only while an operator runs
  it. It is an optional client of the management API (`mcp-gateway admin`),
  and a binary built with `-tags nofront` has no console at all.
- Every action on the page is the management API's action of the same name,
  the one the CLI commands call too, and the page shows what the backend
  answered.
- Tool definitions are untrusted text written by backends; hidden code points
  are shown as `\u{XXXX}` and a changed tool is shown as a diff against the
  approved one.
- Incidents are the high-stakes moments; in the console that means
  offboarding a person or taking a backend out. The block, the trail and its
  verification are CLI and SIEM work.

## Capabilities and Constraints

- Server-rendered HTML (`html/template`), one embedded stylesheet, no
  JavaScript. Content-Security-Policy `default-src 'none'; style-src 'self'`:
  no inline styles, no external fonts or assets.
- Embedded in a single Go binary that runs on a deliberately light Linux VM;
  no new dependency, no build step.
- Two tabs (design/adr/0051): MCP Servers / APIs (each backend's page holds
  its tools, secrets and maintenance) and Users (People and Roles), plus the
  per-tool review and an action result page.
- The public tree is sanitized (`internal/fitness/sanitize_test.go`): no real
  deployment names, hosts or addresses in any file, including design files.

## Brand Commitments

- Name: Gatte. No logo exists.
- Look (design/adr/0061): classic system UI, the same in the console and the
  TUI. Grey panels, bevelled edges, plain system font, square buttons. It
  replaced the earlier Apple-style direction.
- Words: plain operator terms (Approve configuration, Reconnect, Remove,
  Tool security), not the gateway's internal ones.

## Evidence on Hand

- Lab upstream names for demonstration: `casemgmt`, `logsearch`,
  `docsearch`, `threatintel`. Addresses and hosts use RFC 5737 / RFC 2606
  stand-ins.
- No screenshots, customers or metrics exist and none may be invented.

## Product Principles

1. The operator approves exactly what they were shown, nothing more.
2. Say what is not covered as plainly as what is.
3. Nothing hidden: untrusted text is made visible, never rendered raw.
4. The page adds no rule and skips none; it is the console, in a browser.
5. Keep the host light: nothing always-on, nothing to install.
