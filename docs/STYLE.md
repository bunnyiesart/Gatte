# How Gatte's documentation is written

This page is for anyone who writes or changes a page under `docs/`. It is
short on purpose: follow it, and a reader can tell what kind of page they
are on and trust what it says.

## Four kinds of page

The documentation follows [Diátaxis](https://diataxis.fr/): every page is
exactly one of four kinds, because each serves a different moment.

| Kind | Folder | The reader is... | The page... | Keep out of it |
|---|---|---|---|---|
| Tutorial | `tutorials/` | learning, with time to spare | walks them through one complete, safe path that is known to work, from nothing to a result they can see | choices, alternatives, background, every flag |
| How-to guide | `how-to/` | at work, with a goal | gives the steps for one task, in order, from a stated starting point | teaching, history, why the design is this way |
| Reference | `reference/` | looking something up | describes the thing as it is, completely, in the same shape each time | instructions, opinions, narrative |
| Explanation | `explanation/` | stepping back to understand | explains why, the trade-offs, and what is not covered | step-by-step procedures |

When a page starts to need content of another kind, link to the page of
that kind instead of writing it in place. A how-to guide that needs a
paragraph of "why" links to the explanation.

## Voice

- Address the reader as **you**. Use the active voice and the present
  tense: "`reload` applies the new roles", not "the new roles will be
  applied".
- Put the condition before the instruction: "If the backend is an image,
  pin it by digest", not the other way round.
- Say who runs a command: **as root**, **as the service account**
  (`sudo -u mcpgw`), or **as yourself** (an operator in the operator
  socket's group).
- Headings are in sentence case. Commands, flags, paths, keys and audit
  row names are in `code`. Buttons and page names in the web console are
  in **bold**.
- Be exact and brief. One idea per sentence; no filler ("simply", "just",
  "easily").

## Honesty is part of the product

Gatte's rule for itself is that what it does not cover is stated next to
what it does (`PRODUCT.md`, "Product Principles"). The documentation keeps
that rule:

- If a step has a limit, a race or a manual follow-up, say it in the step,
  not in a footnote. Example: "`access block` does not revoke the session
  at the IdP; do that too."
- Never describe a control as working unless a test or a measurement
  shows it. Name the decision record (`design/adr/00NN`) behind a claim
  when the reader might want the reasoning.
- Say when a command needs a restart, and when it takes effect ("next
  call", "within one refresh interval").

## Procedures

- A procedure is a numbered list. Each step is one action, with the
  command in a code block right under it when there is one.
- State the starting point first ("You need: ..."), and end with how to
  check it worked ("`upstream list` shows `yes` in SIGNED").
- Use the Quick start's paths and variables: `CFG=/usr/local/etc/mcp-gateway/config.toml`,
  the service account `mcpgw`, the operator socket's group
  `gatte-operators`.

## Names and examples

The public tree is sanitized by `internal/fitness/sanitize_test.go`. Use
only:

- backend names `casemgmt`, `logsearch`, `docsearch`, `threatintel`,
  `edr`, `ioc-sweep`;
- hosts under `example.org` or `example.internal` (RFC 2606), addresses
  from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737);
- no real deployment names, hosts, people or keys, and no secret value,
  not even a fake one that looks real.

## Keeping it true

- Commands and flags come from the binary: `mcp-gateway help` and
  `mcp-gateway COMMAND -h`. Configuration keys come from
  `config.example.toml`. The management API comes from
  `api/admin.openapi.yaml`. When those change, the reference pages change
  in the same commit.
- Link to files with paths relative to the page.
- Every page starts with a `#` title and one or two sentences saying who
  it is for and what it covers.
