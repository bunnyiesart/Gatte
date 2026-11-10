# Shipping the audit sink to Wazuh

Wazuh is the primary SIEM path for the audit sink. A Wazuh agent tails
`audit.jsonl`, and a ruleset on the manager turns its lines into alerts. It
reads the file the gateway already writes. Nothing changes in the gateway or
in `config.toml`.

The fluent-bit -> Graylog path (`deploy/gatte-audit-fluentbit.conf`) stays
in place during the migration to Wazuh and reads the same file. It is not
removed by this path.

| File | Goes to | What it is |
|---|---|---|
| `gatte-audit-wazuh-localfile.xml` | the agent on the VM host, inside `<ossec_config>` in `/var/ossec/etc/ossec.conf` | the input: tail `audit.jsonl`, `log_format json` |
| `gatte-audit-wazuh-rules.xml` | the manager, `/var/ossec/etc/rules/gatte_audit_rules.xml` | the rules, IDs 110700-110742 |
| `gatte-audit-wazuh-monitor.json` | the Wazuh indexer, Alerting plugin | the heartbeat-absence alert |
| `gatte-audit-wazuh-samples.jsonl` | nowhere; input for `wazuh-logtest` | one v5 line of each kind the rules handle, and one v6 line |

The rules need Wazuh 4.3 or later.

## The two rules this path keeps

**It is a JSONL copy, not a GELF one.** The lines arrive with `prev_hash`
and `hash`, so the Wazuh copy holds the chain the same way Graylog does
(`design/adr/0017`). GELF carries no chain link and never feeds the anchor
(`design/adr/0029`). `deploy/gatte-anchor-verify.sh` still reads the head
from Graylog, so keep the Graylog path running until that check reads from
Wazuh.

**Every line is kept, heartbeats included.** Every v5 line ends on a rule of
level 3 or more, so Wazuh indexes it in `wazuh-alerts-*`. A walk over the
chain needs every record line, and the absence alert needs every heartbeat.
Do not lower a Gatte rule to level 0 and do not add `<ignore>`: Wazuh does
not index a level-0 match unless archives are on, and the line is then gone
from the SIEM copy.

## Install

On the VM host, with the Wazuh agent already enrolled:

1. Paste the `<localfile>` block of `gatte-audit-wazuh-localfile.xml` inside
   `<ossec_config>` in `/var/ossec/etc/ossec.conf`. Change the path if the
   jail is not `gatte`.
2. Restart the agent: `service wazuh-agent restart`.

The sink is `0600`, owned by the gateway's service user, on purpose
(`deploy/freebsd-jail.md`, item 3: the file says which analyst called which
tool). `wazuh-logcollector` runs as root, so it reads the file as it is. If
your build runs it as another user, add that user to the service user's
group. Do not widen the mode. A collector that cannot read the file looks
started and ships nothing: check `/var/ossec/logs/ossec.log` for
`Analyzing file: '.../audit.jsonl'` and no permission error.

On the manager:

1. Copy `gatte-audit-wazuh-rules.xml` to
   `/var/ossec/etc/rules/gatte_audit_rules.xml`, owned `wazuh:wazuh`, mode
   `0660`.
2. Check it before restarting. `/var/ossec/bin/wazuh-logtest` reads one line
   at a time; paste each line of `gatte-audit-wazuh-samples.jsonl`. Each
   must decode as `json` and end on the rule in the table below.
3. `systemctl restart wazuh-manager`.

| Sample line | Rule | Level |
|---|---|---|
| 1, `(boot)` | 110710 | 3 |
| 2 and 8, `(backend health)` allowed | 110731 | 3 |
| 3 and 4, an analyst's call allowed, then failed | 110710 | 3 |
| 5, an analyst's call denied | 110720 | 5 |
| 6, `(unauthenticated)` | 110721 | 5 |
| 7, `(backend health)` denied | 110730 | 10 |
| 9, `tool changed` | 110732 | 12 |
| 10, `signature refused` | 110733 | 12 |
| 11, an operator's `(config reload)` denied | 110710 | 3 |
| 12, a heartbeat | 110740 | 3 |
| 13, a heartbeat with `suspended:true` | 110741 | 12 |
| 14, a heartbeat with `changed` above 0 | 110742 | 10 |
| 15, a v6 line | 110701 | 10 |

110722 fires on top of 110720 when one caller has 10 denied calls in 5
minutes; a single paste does not show it.

## What the rules alert on

The same signals as [Alert from the SIEM](../docs/how-to/alert-from-the-siem.md),
written for Wazuh:

- **110720, 110721, 110722**: an analyst's call denied, a request with no
  valid token, and a burst of denials by one caller. Rows from `(gateway)`
  and `(operator:NAME)` are left out of these.
- **110730, 110731**: `(backend health)` transitions. Open one incident per
  `backend` on 110730 and close it on the next 110731 of the same backend.
  Every boot writes one row per backend, so a restart closes what it should.
- **110732, 110733**: an approved tool rewritten on its backend, and a
  registry entry refused for its signature.
- **110741, 110742**: a heartbeat that says the fleet is suspended, or that
  approved tools changed and nobody reviewed them.

Wazuh fires one rule per line, so the sibling rules are written to never
match the same line. A line that matches no child stays on its parent rule
(110710 or 110740) and is still indexed.

## The absence alert

Wazuh rules run when a line arrives, so they cannot fire on a line that did
not. The absence check runs in the Wazuh indexer, as an Alerting monitor,
over the heartbeats that came through this same tail. That is the point of
the heartbeat (`design/adr/0021`): it crosses the same file, agent and
manager as the records, so its silence means the gateway, the agent, the
manager or the disk stopped.

`gatte-audit-wazuh-monitor.json` counts `rule.groups:gatte_heartbeat` for
one chain in the last 15 minutes, every 5 minutes, and triggers below 1.
Before loading it:

- Replace `gatte-jail-01` (three places) with the chain's `audit.siem.chain`.
- Set the window to 3 times `quarantine.refresh_interval` (15 minutes at the
  default 5m). One missed heartbeat does not fire; two do.
- Add an action with your notification channel to the trigger.

Load it in Dashboards (Alerting, Monitors, Create monitor, Extraction query
editor) or through the indexer API:

```sh
curl -sS -u USER --cacert CA.pem -H 'Content-Type: application/json' \
  -X POST "https://INDEXER:9200/_plugins/_alerting/monitors" \
  -d @deploy/gatte-audit-wazuh-monitor.json
```

Before trusting it, run its query on a gateway that has been up a few
minutes: it must count at least one heartbeat. Zero while lines arrive means
the rules are not loaded, or the chain name is wrong, and the monitor would
fire forever.

The heartbeat is unsigned. Whoever controls the gateway's host can write
heartbeats for a gateway that does nothing. The alert catches a failure,
not an attacker.

## Schema version: change it in both places

The rules match schema 5, `jsonl.Version` in `internal/audit/jsonl/jsonl.go`.
Rule 110701 catches any line whose `v` is not 5 and raises a level-10 alert
naming the version. The line is still indexed. A v6 heartbeat lands on 110701,
not 110740, so the absence monitor fires too. Both alerts mean: the gateway
moved, the ruleset did not.

A change of `jsonl.Version` must update, in the same change:

- the Graylog side: the extractor and the saved searches in
  [Alert from the SIEM](../docs/how-to/alert-from-the-siem.md) and
  `deploy/freebsd-jail.md`;
- this ruleset: every `^5$` in `gatte-audit-wazuh-rules.xml`, any rule a new
  field or reason needs, and `gatte-audit-wazuh-samples.jsonl` with a line of
  the new shape.

## Rotation

`serve` keeps the file open. The two safe ways to rotate it are the ones in
`deploy/freebsd-jail.md`: copy-and-truncate, or rename and restart `serve`.
The agent follows both. A line written during a copy-and-truncate can be
lost, and the chain shows the gap.
