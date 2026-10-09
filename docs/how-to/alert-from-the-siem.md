# Alert from the SIEM

This page is for operators who set up alerts on Gatte in their SIEM. Gatte
sends no alerts itself: it writes every audit row to a copy your SIEM
reads, JSON Lines or GELF, and the SIEM decides what wakes someone up. The
page lists which fields and rows to alert on.

You need: a SIEM that receives one of the copies below, and a restart of
`serve` after you change `[audit.siem]` or `[telemetry]`. The queries are
written in Graylog's syntax; translate them to your SIEM. The commands
use `CFG=/usr/local/etc/mcp-gateway/config.toml`.

## Choose the copy

| | JSON Lines (`[audit.siem]`) | GELF (`[telemetry]`) |
|---|---|---|
| How it leaves the host | a local file; a shipper you run forwards it | Gatte sends it over UDP or TCP to a GELF input |
| Carries the hash chain (`prev_hash`, `hash`) | yes: your SIEM holds the head (`design/adr/0017`) | no |
| Carries a heartbeat | yes, at boot and every round (`design/adr/0021`) | no |
| Says when it lost messages | no: a missing line shows as a gap in the chain | yes: a `telemetry_gap` message after an outage |

The silence alert and the chain comparison need the JSON Lines copy. You
can run both copies at once.

```toml
[audit.siem]
path  = "/var/log/mcp-gateway/audit.jsonl"
chain = "gatte-01"            # one name per gateway; every line carries it
```

`config.example.toml` documents `[telemetry]` (`address`, `transport`,
`tls`, `host`, `cliente_soc`) and what goes wrong with each key.

## The fields

Every audit row carries the same values in both copies, under these names:

| Meaning | JSON Lines | GELF |
|---|---|---|
| Kind of line | `type`: `record` or `heartbeat` | `_event_kind`: `audit` or `telemetry_gap` |
| Who | `caller`: the subject, `(gateway)`, `(operator:NAME)` or `(unauthenticated)` | `_analyst_identity` |
| Display name, for reading only | `analyst_name` (absent when there is none) | `_analyst_name` |
| Tool, or the row's name | `tool`: `casemgmt.list_cases`, `(access block)`, ... | `_tool` |
| Backend, or `(gateway)` | `backend` | `_target_upstream` |
| Outcome | `verdict`: `allowed`, `denied` or `failed` | `_outcome` |
| Reason | `rule` | `_reason` |
| Source address | `src` | `_source_address` |
| Chain | `chain`, `prev_hash`, `hash` | none |
| Schema version | `v` (5) | none (`version` is GELF's own, `1.1`) |

Graylog stores GELF's additional fields without the leading underscore
(`_outcome` is searched as `outcome`); check the field list of your stream
before you save a query. The full list of rows Gatte writes is in the
[Audit trail](../reference/audit-trail.md) reference.

Two rules for every query that counts:

- A call that ran and then failed leaves two rows, `allowed` then
  `failed`. Count `allowed` rows for attempts.
- Rows Gatte writes about itself are attributed to `(gateway)`, and
  operator actions to `(operator:NAME)`. Leave both out when you count
  analysts' calls or refusals.

## What to alert on

### Silence

The heartbeat arrives whether or not anyone calls anything, so its absence
means the gateway, the shipper or the disk stopped.

```
chain:gatte-01 AND type:heartbeat
condition: fewer than 1 message
window:    3 × quarantine.refresh_interval (15 minutes at the default 5m)
```

One missed round does not fire; two do. Before trusting it, run the query
on a healthy gateway: it must return at least one line. Zero results while
lines arrive means your SIEM does not extract `type` as a field, and the
alert would fire forever.

The heartbeat is unsigned: whoever controls the host can emit heartbeats
for a gateway that does nothing. The alert catches a failure, not an
attacker.

### A restart

- The heartbeat's `boot` field changes value: a new process.
- Or the row that starts every boot: `tool:"(boot)"`, with the reason
  `boot: mcp-gateway VERSION, schema N`.

Expected after an upgrade or a planned restart; worth a question when
neither happened.

### What the heartbeat says

Each field arrives with every heartbeat, so these cost nothing extra:

| Field | Alert when |
|---|---|
| `suspended` | `true`: the gateway is up and serves nothing, because it cannot read its registry (`design/adr/0020`) |
| `changed` | above `0`: an approved tool was rewritten on its backend and nobody has reviewed it |
| `pending`, `changed`, `backends_maintenance` | `-1`: the gateway could not read that state for this beat; never read it as "all clear" |
| `backends_down` | above `0` for more than two heartbeats |
| `gateway_maintenance` | `on` outside a planned window, or `unknown` |

### A backend down

Each change of a backend's state is one row, written on the transition
only:

```
tool:"(backend health)" AND verdict:denied
```

Open one alert per `backend`, and close it on the next
`tool:"(backend health)" AND verdict:allowed` row of the same backend. The
reason says what happened: `backend down: CAUSE` (`process_gone`,
`not_brought_up`, `held_back`, `not_listed`, `redial`), `backend up: down
since TIME`, `backend up: first observed`, or `backend removed: no longer
servable per the registry`. Every boot writes one row per backend, so a
restart closes what it should.

### A tool changed, a new tool, a refused signature

These rows have `caller:"(gateway)"`, `verdict:denied`, and a reason
prefix:

| Query | Means |
|---|---|
| `caller:"(gateway)" AND rule:"tool changed*"` | a backend rewrote a tool you approved; it is not served until someone reviews the diff |
| `caller:"(gateway)" AND rule:"tool first seen*"` | a new tool waits for review |
| `tool:"(registry entry)" AND rule:"signature refused*"` | a registry entry is unsigned or its signature fails; it is not served |

A changed tool is the rug pull the quarantine exists for: read the diff
before re-approving it
([Review and approve tools](review-and-approve-tools.md)).

### Configuration and access changes

Operator actions are rows with `caller:"(operator:NAME)"`, tagged in the
reason with where they came from (`[cli]`, `[cli env]`, `[ui]`,
`[signal]`):

- `(config reload)`: roles, groups or quota changed. `verdict:denied` is a
  reload `serve` refused.
- `(access block)`, `(access unblock)`, and `(access block expired)`
  (attributed to `(gateway)`).
- `(account add)`, `(account groups)`, `(account disable)`,
  `(account enable)`, `(account reset password)`, `(account delete)`,
  `(account offboard)`.
- `(tool approve)`, `(tool approve set)`, `(tool revoke)`, `(tool clear)`,
  `(upstream update)`, `(upstream redial)`, `(maintenance on)`,
  `(maintenance off)`, `(restore)`.

`upstream register`, `upstream deregister` and `sign` write no operator
row. A deregistered backend shows as `backend removed` in
`(backend health)`; a newly served one as `backend up: first observed`.

### Refusal spikes

```
verdict:denied AND NOT caller:"(gateway)" AND NOT caller:"(operator*"
```

Split it by `rule` and by `caller`:

- `caller:"(unauthenticated)"`: requests with no valid token. These rows
  are rate-limited per source address, so they undercount a flood.
- `rule:"subject blocked"`: a blocked analyst still trying.
- One `caller` from two `src` addresses: what a stolen token looks like.

### Lost GELF messages

```
_event_kind:telemetry_gap
```

Gatte sends it when a GELF outage that lost messages ends, with how many rows were dropped
and, in `_recover_with`, the `mcp-gateway audit --since TIME` command that
reads them from the trail.

## Check the alerts work

1. Run the silence query on a gateway that has been up for a few minutes:
   it returns at least one heartbeat.
2. Make a row of each kind you alert on, on a quiet backend. A redial writes
   a `(backend health)` pair (`backend down: redial`, then `backend up`)
   and an `(upstream redial)` row:

   ```sh
   sudo -u mcpgw mcp-gateway upstream redial -config "$CFG" casemgmt
   ```

3. Confirm each alert fired, and each open one closed.

## Keep the file flowing

`serve` keeps the JSON Lines file open and does not reopen it on SIGHUP.
Rotate it with copy-and-truncate (which can lose a line written in between,
and the chain will show the gap), or rename it and restart `serve`. The
shipper must forward each line byte for byte. Both are covered in
[`deploy/freebsd-jail.md`](../../deploy/freebsd-jail.md), "Where the head
lives once the SIEM sink is on". Comparing the chain head against the
SIEM's is a separate check: [Respond to an incident](respond-to-an-incident.md#check-the-trail-was-not-edited).
