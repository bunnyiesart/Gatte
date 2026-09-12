#!/bin/sh
# Runs on the OPERATOR's machine -- the one that can reach Graylog and can
# ssh to the VM host. Not on the gateway: the whole point is that the
# expected value comes from somewhere the gateway cannot write.
#
# `mcp-gateway audit -verify` proves the chain is internally consistent,
# and its own usage text says why that is nearly worthless on its own:
# whoever can write the database can re-chain it, and cutting records off
# the END needs no re-chaining at all. The head is the control. That same
# text ends with "Nothing compares the two automatically either." This
# script is that comparison.
#
# What it does:
#   1. asks Graylog for every line shipped for this chain;
#   2. derives the head as the hash that is no other line's prev_hash --
#      NOT the newest message, for the reason audit.go spells out: Graylog
#      orders by arrival, ts is the caller's clock, and neither is the
#      chain's insertion order, so "newest" is wrong half the time when two
#      records land in one tick;
#   3. feeds that head back to `audit -verify -expect-head` on the gateway.
#
# WHAT A FAILURE HERE MEANS, and it is not one thing. A mismatch says the
# local trail and the shipped copy disagree. The innocent cause is lag: the
# shipper has not caught up, so the SIEM's head is an OLDER record and the
# gateway's head has moved on. From the SIEM's side that is indistinguish-
# able from a truncation, which is a real property of this design and not a
# gap in the script -- so the script reports the sink/SIEM line counts to
# let a human tell them apart, and says plainly that an actor who controls
# the host controls that number too.
#
# WHAT IT IS STILL WORTH, unchanged from audit.go: it detects a rolled-back
# or truncated database, and an attacker who ignored the sink. It does
# nothing against one who noticed it -- the lines are unsigned, so whoever
# holds the host can truncate and append a forged line that chains cleanly.
set -eu

CHAIN="${CHAIN:-gatte-jail-01}"
GW_HOST="${GW_HOST:-root@192.168.1.4}"
GW_JAIL="${GW_JAIL:-gatte}"
GRAYLOG="${GRAYLOG:-http://localhost:9100/api}"
GW_CONFIG="${GW_CONFIG:-/usr/local/etc/mcp-gateway/config.toml}"
RANGE="${RANGE:-86400}"
# Credentials come from the environment, never from this file.
: "${GRAYLOG_USER:?set GRAYLOG_USER}"
: "${GRAYLOG_PASS:?set GRAYLOG_PASS}"

WORK=$(mktemp -d /tmp/gatte-anchor.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM

say()  { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok    %s\n' "$1"; }
fail() { printf '   FAIL  %s\n' "$1" >&2; exit 1; }

# ------------------------------------------------------------ the SIEM side
say "Graylog: fetching the shipped lines for chain $CHAIN"
curl -sS -u "$GRAYLOG_USER:$GRAYLOG_PASS" \
	-H 'X-Requested-By: gatte-anchor-verify' -H 'Accept: application/json' \
	-G "$GRAYLOG/search/universal/relative" \
	--data-urlencode "query=chain:$CHAIN" \
	--data-urlencode "range=$RANGE" \
	--data-urlencode "fields=hash,prev_hash" > "$WORK/siem.json" \
	|| fail "Graylog query failed"

SIEM_N=$(jq '.total_results' < "$WORK/siem.json")
[ "$SIEM_N" -gt 0 ] || fail "Graylog has no lines for chain $CHAIN -- nothing to anchor against"
ok "$SIEM_N messages"

# The SIEM holds duplicates whenever the shipper re-read a file it had
# already sent (a restart before its offset DB was writable does exactly
# this). Deriving the head is set arithmetic, so duplicates are harmless
# here -- but they are worth printing, because a growing gap between these
# two numbers is the shipper misbehaving.
jq -r '.messages[].message.hash'      < "$WORK/siem.json" | sort -u > "$WORK/hashes"
jq -r '.messages[].message.prev_hash' < "$WORK/siem.json" | sort -u > "$WORK/prevs"
DISTINCT=$(wc -l < "$WORK/hashes" | tr -d ' ')
ok "$DISTINCT distinct records ($(( SIEM_N - DISTINCT )) duplicate deliveries)"

# The head: present as a hash, absent as anyone's prev_hash. A record whose
# prev_hash is EMPTY is the chain's genesis and links back to nothing, so the
# empty string must not be treated as a predecessor -- it is filtered out
# here, and counted separately below, because more than one genesis is a
# finding in its own right.
grep -v '^$' "$WORK/prevs" > "$WORK/prevs.real" || true
comm -23 "$WORK/hashes" "$WORK/prevs.real" > "$WORK/heads"
NHEADS=$(wc -l < "$WORK/heads" | tr -d ' ')

# Fragments have two kinds of beginning and the difference is the diagnosis:
#
#   GENESIS   prev_hash empty. The gateway declared this record the start of
#             the chain. Exactly one is normal -- the first record ever
#             written. A SECOND one means the chain restarted, which means
#             the database was emptied or replaced while the sink file, which
#             is append-only and was not, kept the older lines. That is a
#             rolled-back trail, and detecting it is the entire reason this
#             anchor exists.
#
#   DANGLING  prev_hash names a record the SIEM does not have. Either the
#             shipper missed a line, or the predecessor genuinely predates
#             the sink file (true for the oldest fragment on a gateway where
#             [audit.siem] was switched on after the trail had started).
# Graylog represents an empty prev_hash by OMITTING the field, so match on
# absent-or-empty rather than on the empty string alone.
jq -r '.messages[].message | select((.prev_hash // "") == "") | .hash' \
	< "$WORK/siem.json" | sort -u > "$WORK/genesis"
NGENESIS=$(wc -l < "$WORK/genesis" | tr -d ' ')

# One fragment is the healthy shape. More than one means the shipped copy
# has more than one beginning, and WHICH KIND of beginning decides the
# diagnosis:
#
#   a genesis is only legitimate as the OLDEST beginning. If any other
#   fragment exists, something older than this "first" record was shipped,
#   so the record is not the chain's start -- the chain RESTARTED. That
#   holds whether the older fragment's own genesis was shipped or predates
#   the sink; a genesis can only ever sit at the start of a database.
#
#   with no genesis at all, every fragment begins at a record whose
#   predecessor the SIEM does not have, which is the shipper missing lines.
if [ "$NHEADS" -gt 1 ] && [ "$NGENESIS" -ge 1 ]; then
	printf '   FAIL  %s fragments and a genesis record -- the chain RESTARTED.\n' "$NHEADS" >&2
	printf '         A record with an empty prev_hash claims to be the first in the\n' >&2
	printf '         chain, but older lines were shipped before it. So the audit\n' >&2
	printf '         DATABASE was emptied or replaced, while this sink file, being\n' >&2
	printf '         append-only, kept the lines from before. The shipped copy is\n' >&2
	printf '         evidence of a trail the gateway no longer has -- which is the\n' >&2
	printf '         entire reason this anchor exists.\n' >&2
	printf '\n' >&2
	printf '         Not a shipper fault; re-running will not clear it. Find what\n' >&2
	printf '         reset the database. A known cause in this repo is\n' >&2
	printf '         deploy/gateway-serve-verify.sh, which wipes the DB by design on\n' >&2
	printf '         every run and now warns before doing it.\n' >&2
	printf '\n         genesis records (empty prev_hash):\n' >&2
	sed 's/^/           /' "$WORK/genesis" >&2
	printf '         fragment heads:\n' >&2
	sed 's/^/           /' "$WORK/heads" >&2
	exit 1
fi

case "$NHEADS" in
0)	fail "no head: every shipped hash is some other line's prev_hash, which
         means the chain loops or the newest line is missing" ;;
1)	: ;;
*)	printf '   FAIL  %s fragments and no genesis -- lines are MISSING.\n' "$NHEADS" >&2
	printf '         Every fragment begins at a record whose predecessor the SIEM\n' >&2
	printf '         does not have. With no genesis among them the database did not\n' >&2
	printf '         restart, so the shipper dropped lines -- check fluent-bit and\n' >&2
	printf '         its offset DB. The exception is a gateway that had\n' >&2
	printf '         [audit.siem] switched on mid-trail: there the OLDEST fragment\n' >&2
	printf '         is expected and any other is not.\n' >&2
	printf '\n         fragment heads:\n' >&2
	sed 's/^/           /' "$WORK/heads" >&2
	exit 1 ;;
esac
HEAD=$(cat "$WORK/heads")
ok "head derived from the SIEM: $HEAD"

# ----------------------------------------------------------- the gateway side
say "gateway: verifying the local chain against that head"
set +e
ssh -o BatchMode=yes "$GW_HOST" \
	"jexec $GW_JAIL /usr/local/bin/mcp-gateway audit -verify -config $GW_CONFIG -expect-head $HEAD" \
	> "$WORK/verify.out" 2>&1
RC=$?
set -e
sed 's/^/   /' "$WORK/verify.out"

if [ "$RC" -eq 0 ]; then
	say "BATEM -- a ancora externa esta viva"
	ok "the local trail verifies AND its head matches the copy the gateway cannot write"
	exit 0
fi

# ------------------------------------------------------ telling lag from tamper
say "MISMATCH -- and the next number decides what it means"
SINK="/usr/local/bastille/jails/$GW_JAIL/root/var/log/mcp-gateway/audit.jsonl"
SINK_N=$(ssh -o BatchMode=yes "$GW_HOST" "wc -l < $SINK" 2>/dev/null | tr -d ' ') || SINK_N="?"
printf '   lines in the sink on the gateway: %s  (the whole file)\n' "$SINK_N"
printf '   distinct records in the SIEM:     %s  (last %ss only)\n' "$DISTINCT" "$RANGE"
printf '\n'
# Only comparable when RANGE spans the whole trail. A short window makes the
# SIEM look behind when it is merely narrower, so refuse to call it.
if [ "$RANGE" -lt 86400 ] 2>/dev/null; then
	printf '   RANGE is %ss, narrower than the sink file covers, so these two\n' "$RANGE"
	printf '   numbers are not comparable and no lag conclusion is drawn here.\n' >&2
	printf '   Re-run with RANGE spanning the whole trail to get one.\n'
elif [ "$SINK_N" != "?" ] && [ "$SINK_N" -gt "$DISTINCT" ] 2>/dev/null; then
	printf '   The sink is AHEAD of the SIEM, so the likely cause is the shipper\n'
	printf '   lagging or stopped -- check fluent-bit -- and not tampering. Re-run\n'
	printf '   once it has drained before drawing any conclusion.\n'
else
	printf '   The sink is NOT ahead of the SIEM, so lag does not explain this.\n'
	printf '   Treat the local trail as truncated or rewritten until proven\n'
	printf '   otherwise.\n'
fi
printf '\n   Either way: this number comes from the gateway host, so an actor who\n'
printf '   controls that host controls it. It narrows the question; it does not\n'
printf '   settle it.\n'
exit 1
