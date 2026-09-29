# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

A few operators on one SOC team share the operator role and take turns. They
run the gateway for about seven analysts. They reach the operator console at
a laptop, on the gateway host or through `ssh -L`, to work the tool approval
queue (reading a changed tool's definition and diff before approving it),
cut off an analyst during an incident, and read or verify the audit trail.

## Product Purpose

Gatte is a self-hosted MCP gateway for blue teams: one authenticated endpoint
in front of the team's MCP servers, so the production API keys behind those
tools live encrypted on one host instead of on every analyst's laptop. Every
call is checked (token, blocklist, role, quarantine, limits), recorded in a
hash-chained audit trail before it runs, and shipped to the SIEM. The
operator console is where a human makes the decisions the gateway cannot:
which tool definitions are trusted, who is cut off, whether the trail is
intact.

## Positioning

It brokers static API keys rather than only OAuth, pins every tool to a
human-approved fingerprint of its definition, and treats its own limits as
part of the claim: what it does not cover is stated next to what it does.

## Operating Context

- The console is `mcp-gateway ui`, a foreground command run as the service
  account; it binds loopback only and lives only while an operator runs it.
- Every action on the page is the CLI command of the same name, and the page
  shows what the command printed. Registering and signing a backend stay in
  the terminal.
- Tool definitions are untrusted text written by backends; hidden code points
  are shown as `\u{XXXX}` and a changed tool is shown as a diff against the
  approved one.
- Incidents are the high-stakes moments: blocking an analyst, reading
  refusals, verifying the chain against the SIEM's head.

## Capabilities and Constraints

- Server-rendered HTML (`html/template`), one embedded stylesheet, no
  JavaScript. Content-Security-Policy `default-src 'none'; style-src 'self'`:
  no inline styles, no external fonts or assets.
- Embedded in a single Go binary that runs on a deliberately light Linux VM;
  no new dependency, no build step.
- Pages: Overview, Tools (queue and per-tool review), Access, Audit,
  Backends, Quota, and an action result page.
- The public tree is sanitized (`internal/fitness/sanitize_test.go`): no real
  deployment names, hosts or addresses in any file, including design files.

## Brand Commitments

- Name: Gatte. No logo exists.
- Palette: blue and black shades (owner's commitment, 29 Sep 2026).
- Standing preference (owner, 29 Sep 2026): Apple-style simplicity, with App
  Store Connect as the reference product: the familiar standard, done at full
  craft. The signal-box direction was built, found confusing, and replaced.

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
