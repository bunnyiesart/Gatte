#!/bin/sh
# The scheduled half of the audit anchor. gatte-anchor-verify.sh does the whole
# chain-head comparison -- it fetches the shipped lines, derives the head the
# correct way (the hash that is no other line's prev_hash), and feeds it to
# `audit -verify -expect-head` on the gateway. What it never did was run
# itself; deploy/freebsd-jail.md says so outright ("nothing schedules it, and
# that half is still a human's job"). This wrapper is that half.
#
# It changes nothing about how the trail ships. The anchor still travels the
# JSONL sink + fluent-bit -> Graylog path (ADR-0017), the heartbeat/absence
# alert still lives on that same channel (ADR-0021), and nothing here goes
# through GELF (ADR-0029). All the crypto -- walking prev_hash/hash across the
# shipped lines -- stays inside gatte-anchor-verify.sh; this script never reads
# a hash and never recomputes one.
#
# Runs on the OPERATOR box, same as the verify script: the host that can reach
# Graylog and can ssh to the gateway. Never on the gateway.
#
# WHAT IT ADDS over calling the verify script from cron directly:
#
#   1. Quiet on success. A healthy run writes only to syslog, nothing to
#      stdout/stderr, so cron's MAILTO mailbox stays empty until something is
#      actually wrong. A mailbox that only rings for real findings gets read.
#
#   2. A consecutive-failure threshold before it pages. A single mismatch is
#      most often the shipper lagging, not tampering -- the verify script
#      spends paragraphs on exactly that ambiguity. Paging on the first blip
#      would train the operator to ignore it. So failures are counted, and the
#      alert (output to stderr -> cron mail, and a syslog line at err) fires
#      only once ANCHOR_FAIL_THRESHOLD runs in a row have failed. This mirrors
#      the heartbeat-absence alert's "one missed round does not wake anybody;
#      two do" window. A tamper signal is not silent in the meantime: every
#      failed run is logged to syslog at warning and the full output is kept on
#      disk, so a site that watches syslog sees strike one.
#
#   3. A run-marker on every run. The check's own death is otherwise invisible:
#      a dead cron entry looks exactly like a healthy gateway, because both are
#      silent. Each run emits one syslog line (tag $ANCHOR_SYSLOG_TAG) and
#      touches a stamp file, so the absence of the marker is alertable the same
#      way the absence of heartbeats is -- see gatte-anchor-check.md.
#
# Alerting is deliberately plain: a non-zero exit with the detail on stderr, so
# cron mails it and a systemd timer marks the unit failed. There is no webhook,
# no second daemon, nothing new to keep alive. Point it at whatever already
# reads cron mail or the journal.
set -eu

HERE=$(dirname "$0")

# The verify script this wraps. Default: next to this one, which is how the
# install instructions place both.
VERIFY="${VERIFY:-$HERE/gatte-anchor-verify.sh}"

# Credentials (GRAYLOG_USER/GRAYLOG_PASS) and any host/jail/chain overrides
# live here, mode 0600, never in the crontab. `set -a` exports everything the
# file sets so the verify child process inherits it; the file is plain
# KEY=value, which is also what a systemd EnvironmentFile accepts, so one file
# serves both schedulers. A missing file is fine when the scheduler supplies
# the environment itself (systemd EnvironmentFile, or a cron that sources it).
ANCHOR_ENV="${ANCHOR_ENV:-/usr/local/etc/gatte/anchor.env}"
if [ -f "$ANCHOR_ENV" ]; then
	set -a
	# shellcheck source=/dev/null
	. "$ANCHOR_ENV"
	set +a
fi

# State the check keeps between runs: the consecutive-failure counter, the full
# output of the last run (for the operator to read after a mail), and a stamp
# of the last run time (for liveness).
STATE_DIR="${STATE_DIR:-/var/db/gatte-anchor}"
THRESHOLD="${ANCHOR_FAIL_THRESHOLD:-2}"
TAG="${ANCHOR_SYSLOG_TAG:-gatte-anchor}"

case "$THRESHOLD" in
'' | *[!0-9]*) THRESHOLD=2 ;;
esac
[ "$THRESHOLD" -ge 1 ] || THRESHOLD=1

mkdir -p "$STATE_DIR"
COUNTER="$STATE_DIR/consecutive-failures"
LAST="$STATE_DIR/last-run.log"
STAMP="$STATE_DIR/last-run.stamp"

# syslog only -- never stdout -- so the run-marker and progress never reach
# cron mail. Best-effort: a box without logger must not fail the check.
note() { logger -t "$TAG" -p "$1" "$2" 2>/dev/null || true; }

# Run the comparison. Capture everything; the verify script's own stdout is for
# a human reading it interactively, not for cron.
set +e
OUT=$(sh "$VERIFY" 2>&1)
RC=$?
set -e

printf '%s\n' "$OUT" > "$LAST"
date -u +%Y-%m-%dT%H:%M:%SZ > "$STAMP"

FAILS=$(cat "$COUNTER" 2>/dev/null || echo 0)
case "$FAILS" in
'' | *[!0-9]*) FAILS=0 ;;
esac

if [ "$RC" -eq 0 ]; then
	echo 0 > "$COUNTER"
	note info "ok: local trail verifies and its head matches the SIEM-shipped copy"
	exit 0
fi

FAILS=$((FAILS + 1))
echo "$FAILS" > "$COUNTER"

if [ "$FAILS" -lt "$THRESHOLD" ]; then
	# Below the threshold: most likely shipper lag that the next run clears.
	# Record it loudly in syslog and on disk, but say nothing to cron.
	note warning "chain-head check failed ($FAILS/$THRESHOLD before alerting); detail in $LAST"
	exit 0
fi

# Threshold reached: this is the alert. stderr goes to cron mail / the journal,
# and err-level syslog gives a second path for whoever watches it.
note err "chain-head check failed $FAILS runs in a row (>= $THRESHOLD) -- ALERT; detail in $LAST"
printf '%s\n' "$OUT" >&2
printf '\ngatte-anchor-check: %s consecutive failures (threshold %s). Full output above and in %s on the operator box.\n' \
	"$FAILS" "$THRESHOLD" "$LAST" >&2
exit 1
