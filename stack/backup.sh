#!/usr/bin/env bash
# Back central up to an S3 bucket — Cloudflare R2 — once. Run hourly by the
# systemd timer in systemd/ (README.md, "Backups").
#
# Two halves, in this order:
#
#   1. The database: a dump of the three schemas that hold anything
#      (public, auth, storage) into db/hourly/. The first run of a UTC day
#      also copies it to db/daily/, the first of an ISO week to db/weekly/.
#   2. Storage's files: an incremental sync into files/current/. Only what is
#      new is sent. A file that has left the server since the last run is not
#      deleted from the backup but moved to files/deleted/<date>/, so every
#      dump still in the bucket can be restored with the files it names.
#
# Dump first, then files: a file uploaded between the two is merely early,
# while the other order would leave a dump naming a file the backup lacks.
#
# The bucket prunes itself. This script never deletes: expiry rules on the
# bucket remove db/hourly after a day, db/daily after 14, db/weekly after 28
# and files/deleted after 30, and bucket locks stop anybody — this machine
# included — deleting them sooner. `./backup.sh --rules` prints the four.
#
# Everything is encrypted before it leaves (rclone crypt), with
# BACKUP_PASSWORD from .env. Under files/ every name is, folders included —
# they are user ids. Under db/ the three folder names stay readable for the
# rules to match, and only the dump names, which are dates, are encrypted.
# files/deleted is matched by its encrypted name, which is fixed for a given
# password; --rules works it out. Lose the password and every backup is noise:
# keep it with the offline copy of .env.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

source ./backup_remote.sh
log() { echo "[backup] $*"; }

# One run at a time: a slow upload must not meet the next hour's.
exec 9>"${TMPDIR:-/tmp}/rift-central-backup.lock"
flock -n 9 || { log "another backup is still running"; exit 0; }

if [[ ${1:-} == --rules ]]; then
  bucket=$(env_value BACKUP_BUCKET)
  deleted=$(rc -- cryptdecode --reverse files: deleted | awk "{print \$NF}")
  echo "Bucket $bucket — an expiry rule and a lock rule for each prefix:"
  printf '  %-45s %s\n' "db/hourly/" "1 day" "db/daily/" "14 days" "db/weekly/" "28 days" \
    "files/$deleted/" "30 days  (files/deleted)"
  exit 0
fi

# ── 1. The database ─────────────────────────────────────────
# To the second: a locked bucket refuses to overwrite, so a run by hand in
# the same minute as the timer's must not reuse its name.
now=$(date -u +%Y-%m-%dT%H%M%SZ)
day=$(date -u +%F)
week=$(date -u +%G-W%V)
hourly="hourly/$now.dump"

# Custom format, which pg_restore can pick tables out of. Written to the host
# first rather than streamed, so a dump that fails half way is never uploaded
# looking like a whole one.
work=$(mktemp -d); chmod 700 "$work"
trap 'rm -rf "$work"' EXIT
docker exec central-db pg_dump -U supabase_admin -d postgres -Fc \
  -n public -n auth -n storage > "$work/central.dump"
log "dumped the database ($(stat -c %s "$work/central.dump") bytes)"

# Handed to rclone on stdin rather than mounted, so this needs no directory
# Docker can see — Docker Desktop, for one, cannot see /tmp.
rc -- rcat "db:$hourly" < "$work/central.dump"
log "uploaded db/$hourly"

if [[ -z $(rc -- lsf "db:daily/" --include "$day.dump") ]]; then
  rc -- copyto "db:$hourly" "db:daily/$day.dump"
  log "kept it as db/daily/$day.dump"
fi
if [[ -z $(rc -- lsf "db:weekly/" --include "$week.dump") ]]; then
  rc -- copyto "db:$hourly" "db:weekly/$week.dump"
  log "kept it as db/weekly/$week.dump"
fi

# ── 2. Storage's files ──────────────────────────────────────
# The file backend keeps `<tenant>/<bucket>/<name>/<version>`, and a version
# is never rewritten — an upload is a new one — so a file already in the
# backup never has to be sent again. Metadata (-M) carries the extended
# attributes Storage keeps each file's content type in.
rc -v "$STORAGE_VOLUME:/data:ro" -- sync /data files:current \
  --backup-dir "files:deleted/$day" -M --log-level INFO 2>&1 |
  sed -n 's/^.*INFO  : \(.*\): Copied (new).*/[backup] storage: copied \1/p
          s/^.*INFO  : \(.*\): Moved into backup dir.*/[backup] storage: kept aside \1/p' | tail -20
log "synced storage"

# ── A heartbeat, if one is configured ───────────────────────
# A URL pinged only on success, so a monitor (healthchecks.io, Uptime Kuma)
# notices the hour that did not arrive. Given to curl on stdin: such URLs
# carry their secret in the path.
ping_url=$(env_value BACKUP_PING_URL)
if [[ -n $ping_url ]]; then
  printf 'url = "%s"\n' "$ping_url" | curl -fsS -m 10 -K - >/dev/null || log "heartbeat failed"
fi
log "done"
