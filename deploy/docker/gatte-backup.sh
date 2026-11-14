#!/bin/sh
# Host-side backup for the Dockerised Gatte (deploy/docker/README.md).
#
# Runs `gatte mcp backup` INSIDE the container -- a consistent copy of the
# database, checked (integrity, audit chain, signatures) while Gatte runs --
# and then copies it OFF the volume. A backup on the same disk as the thing it
# backs up is not a backup.
#
# It backs up the DATABASE only. The keys, the vault, the private CA and the
# identity provider's accounts are the rest of the volume; the README's
# "Upgrade" step 4 has the full-volume tar for those, which must run with the
# container stopped.
#
# It runs on the HOST over the Docker CLI, and is deliberately NOT a Compose
# sidecar: a sidecar that reaches into this container would need the Docker
# socket mounted, and the README ("Backends from an MCP JSON file") spells out
# why Gatte is never given that -- the socket is root on the host. Point cron
# or a systemd timer at this script instead; it needs only `docker`.
set -eu

# The container name (`docker run --name`, or compose `container_name`).
CONTAINER="${GATTE_CONTAINER:-gatte}"
# Where off-volume copies land on the host. Put it on storage separate from the
# Docker volume for a real off-box backup; a sibling directory is still better
# than a copy that shares the volume's fate.
DEST="${GATTE_BACKUP_DIR:-/var/backups/gatte}"
# How many timestamped copies to keep -- in the volume (via `backup -keep`) and
# on the host (pruned below). 0 keeps all, as it does for `backup -keep`.
KEEP="${GATTE_BACKUP_KEEP:-7}"

case "$KEEP" in
'' | *[!0-9]*) echo "gatte-backup: GATTE_BACKUP_KEEP must be a number, got '$KEEP'" >&2; exit 2 ;;
esac

mkdir -p "$DEST"

# 1. Consistent, checked copy inside the volume. `-keep` prunes older copies
#    there, so /gatte/backup never grows without bound. It prints the audit
#    head it reached -- worth keeping with the copy for a later -expect-head
#    restore.
docker exec "$CONTAINER" gatte mcp backup -out /gatte/backup -keep "$KEEP"

# 2. Off the volume, into a timestamped directory. UTC, so the names sort
#    chronologically. The volume-side -keep has already bounded what this copies.
stamp=$(date -u +%Y%m%dT%H%M%SZ)
docker cp "$CONTAINER:/gatte/backup" "$DEST/$stamp"

# 3. Bound the host copies the same way -keep bounds the volume's: keep the
#    newest KEEP timestamped directories, drop the rest; 0 keeps all. Only
#    names in this script's own stamp format are candidates, so anything else
#    stored under DEST is never touched.
[ "$KEEP" -eq 0 ] && exit 0
find "$DEST" -mindepth 1 -maxdepth 1 -type d \
	-name '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z' |
	sort -r | {
	kept=0
	while IFS= read -r dir; do
		kept=$((kept + 1))
		if [ "$kept" -gt "$KEEP" ]; then
			rm -rf "$dir"
		fi
	done
}
