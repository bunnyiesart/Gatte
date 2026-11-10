# Scheduling the audit anchor check

`gatte-anchor-verify.sh` compares the gateway's audit chain head against the
copy shipped to the SIEM. It is the only detection this design has against a
rolled-back or truncated trail. For a long time it had one gap, stated in
`freebsd-jail.md`: nothing ran it. A check that is only *checkable* is not a
control. `gatte-anchor-check.sh` closes that gap.

## What it does and does not touch

The wrapper only schedules the existing comparison and turns its result into an
alert. It does **not** change how the trail ships:

- the anchor still travels the JSONL sink + fluent-bit -> Graylog path
  (ADR-0017), which stays the one byte-faithful shipping path;
- the heartbeat/absence alert stays on that same channel (ADR-0021);
- nothing here goes through GELF (ADR-0029);
- all the hash-chain walking stays inside `gatte-anchor-verify.sh`. The wrapper
  never reads a hash and never recomputes one from a shipped line -- `ts` is
  normalised in the shipped copy, so recomputing is not a supported operation
  (ADR-0017 item 6).

## Where it runs

On the **operator box**, the same host `gatte-anchor-verify.sh` already
requires: it must reach Graylog and be able to `ssh` to the gateway. Never on
the gateway -- the whole point is that the expected head comes from somewhere
the gateway cannot write.

## Install

Pick cron or systemd; both run the same script.

1. Place both scripts and the env file:

   ```
   install -d -m 0755 /usr/local/libexec/gatte
   install -m 0755 deploy/gatte-anchor-check.sh  /usr/local/libexec/gatte/
   install -m 0755 deploy/gatte-anchor-verify.sh /usr/local/libexec/gatte/
   install -d -m 0750 /usr/local/etc/gatte
   install -m 0600 deploy/gatte-anchor-check.env.example /usr/local/etc/gatte/anchor.env
   $EDITOR /usr/local/etc/gatte/anchor.env     # fill in GRAYLOG_USER / GRAYLOG_PASS
   ```

2a. **cron** (FreeBSD or Linux): edit `MAILTO` in
    `deploy/gatte-anchor-check.crontab`, then `crontab gatte-anchor-check.crontab`
    as the operator user.

2b. **systemd** (Linux): copy `gatte-anchor-check.service` and
    `gatte-anchor-check.timer` to `/etc/systemd/system/`, set `User=` to the
    operator identity, then `systemctl enable --now gatte-anchor-check.timer`.

## How it alerts

Both examples run the check hourly. With the default threshold of 2, a
persistent mismatch pages within about two hours.

A healthy run is silent: it writes one line to syslog and updates its stamp
file, and nothing to stdout, so cron sends no mail.

A failing run is **not** paged immediately. A single mismatch is usually the
shipper lagging, not tampering -- the verify script distinguishes the two in its
output, but one run cannot. So failures are counted, and the alert fires only
after `ANCHOR_FAIL_THRESHOLD` runs in a row have failed (default 2), mirroring
the heartbeat-absence alert's two-strike window. The alert is a non-zero exit
with the full comparison output on stderr: cron mails it, systemd marks the unit
failed. Below the threshold, every failed run is still logged to syslog at
`warning` and its full output kept in `/var/db/gatte-anchor/last-run.log`, so a
site watching syslog sees strike one.

When it does page, read the output the way `freebsd-jail.md` describes: a
genesis-plus-fragments shape means a rolled-back database, fragments with no
genesis mean the shipper dropped lines, and a head mismatch with the sink ahead
of the SIEM means lag. Same findings, same fixes.

## Detecting that the check itself died

A dead cron entry is invisible: it looks exactly like a healthy gateway, because
both are silent. So every run emits one syslog line (tag `gatte-anchor`,
override with `ANCHOR_SYSLOG_TAG`) and touches
`/var/db/gatte-anchor/last-run.stamp`. On a box whose syslog reaches the SIEM,
alert on the absence of that marker the same way the heartbeat-absence alert
works -- a window of a few run intervals with no `gatte-anchor` line means the
check stopped running. Where syslog is not collected, monitor the stamp file's
age instead.
