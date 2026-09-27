#!/usr/bin/env bash
# Put central back as it was at one of its backups.
#
#   ./restore.sh --list              what there is to restore from
#   ./restore.sh                     the newest backup
#   ./restore.sh 2026-09-26T210700Z  an hourly one; or 2026-09-26 (daily),
#                                    2026-W39 (weekly)
#
# Onto a new machine: the same .env as the old one (the offline copy — it
# holds the backup password and the keys every client and session trusts),
# then `./up.sh` once so the schema exists, then this.
#
# What it does:
#
#   1. Stops everything but the database, so nothing writes mid-restore.
#   2. Empties the tables of the three schemas the backup holds (public, auth,
#      storage) and loads the dump's rows into them. The schema itself comes
#      from the migrations and the services, which is why up.sh runs first;
#      only rows travel. Each service's own record of its migrations is left
#      alone, so it does not try to run them again.
#   3. Copies Storage's files back: files/current, plus every files/deleted
#      folder from the dump's day on — the files that left the server after
#      the dump was taken, which the dump still names. Then removes every
#      file the restored database does not name: those folders hold whole
#      days, so they bring back versions older than the dump too, and an
#      in-place restore leaves behind what was uploaded after it.
#   4. Runs up.sh, which starts everything and re-applies the migrations and
#      the function config rows.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./backup_remote.sh
log() { echo "[restore] $*"; }

list_dumps() {
  for kind in hourly daily weekly; do
    rc -- lsf "db:$kind/" 2>/dev/null | sed "s|^|$kind/|"
  done
}

if [[ ${1:-} == --list ]]; then
  list_dumps | sed 's/\.dump$//' | sort -t/ -k2
  exit 0
fi

yes=false
wanted=""
for arg in "$@"; do
  case $arg in
    --yes) yes=true ;;
    -*) echo "Unknown option $arg" >&2; exit 1 ;;
    *) wanted=$arg ;;
  esac
done

# ── Which dump, and from which day ──────────────────────────
dumps=$(list_dumps)
if [[ -n $wanted ]]; then
  dump=$(grep -E "^(hourly|daily|weekly)/${wanted}\.dump$" <<<"$dumps" | head -1 || true)
  [[ -n $dump ]] || { echo "No backup called $wanted. ./restore.sh --list shows them." >&2; exit 1; }
else
  dump=$(grep '^hourly/' <<<"$dumps" | sort | tail -1 || true)
  [[ -n $dump ]] || dump=$(grep '^daily/' <<<"$dumps" | sort | tail -1 || true)
  [[ -n $dump ]] || { echo "There are no backups in the bucket." >&2; exit 1; }
fi
name=$(basename "$dump" .dump)
case $name in
  # The Monday of ISO week N: 4 January is always in week 1.
  *W*) jan4="${name%%-W*}-01-04"; week=$((10#${name##*W}))
       day=$(date -u -d "$jan4 -$(( $(date -u -d "$jan4" +%u) - 1 )) days +$(( (week - 1) * 7 )) days" +%F) ;;
  *T*) day=${name%%T*} ;;
  *)   day=$name ;;
esac

echo "This replaces every account, message, listing and stored file on this"
echo "machine with the backup $dump (files from $day on)."
if ! $yes; then
  read -rp "Type 'restore' to go on: " answer
  [[ $answer == restore ]] || { echo "Nothing changed."; exit 1; }
fi

# ── 1. Quiet ────────────────────────────────────────────────
docker compose stop kong auth rest realtime storage functions >/dev/null 2>&1
log "stopped the services"

# ── 2. The database ─────────────────────────────────────────
work=$(mktemp -d); chmod 700 "$work"
trap 'rm -rf "$work"; docker exec central-db rm -f /tmp/restore.dump /tmp/restore.list' EXIT
rc -- cat "db:$dump" > "$work/central.dump"
log "downloaded $dump ($(stat -c %s "$work/central.dump") bytes)"
docker exec -i central-db sh -c 'umask 077; cat > /tmp/restore.dump' < "$work/central.dump"

# Every table's rows except each service's migration record.
docker exec -i central-db sh -c \
  "pg_restore -l /tmp/restore.dump |
   grep -vE ' TABLE DATA (auth schema_migrations|storage migrations) ' > /tmp/restore.list"

docker exec -i central-db psql -U supabase_admin -d postgres -q -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE v_tables TEXT;
BEGIN
  SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
    INTO v_tables
    FROM pg_tables
   WHERE schemaname IN ('public', 'auth', 'storage')
     AND (schemaname, tablename) NOT IN (('auth', 'schema_migrations'),
                                         ('storage', 'migrations'));
  EXECUTE 'TRUNCATE ' || v_tables || ' CASCADE';
END $$;
SQL
docker exec central-db pg_restore -U supabase_admin -d postgres --data-only \
  --disable-triggers --single-transaction -L /tmp/restore.list /tmp/restore.dump
log "loaded the database"

# ── 3. Storage's files ──────────────────────────────────────
rc -v "$STORAGE_VOLUME:/data" -- copy files:current /data -M
for folder in $(rc -- lsf --dirs-only files:deleted/ | tr -d /); do
  if [[ ! $folder < $day ]]; then
    rc -v "$STORAGE_VOLUME:/data" -- copy "files:deleted/$folder" /data -M
    log "brought back the files that left on $folder"
  fi
done
# Storage keeps a file at <tenant>/<global bucket>/<bucket>/<name>/<version>
# — "stub/stub" for the tenant and global bucket set in docker-compose.yml —
# and the database names exactly those.
docker exec central-db psql -U supabase_admin -d postgres -tAc \
  "select bucket_id || '/' || name || '/' || version from storage.objects" > "$work/wanted"
removed=$(docker run --rm -i -v "$STORAGE_VOLUME:/data" --entrypoint sh "$RCLONE_IMAGE" -c '
    cd /data/stub/stub 2>/dev/null || exit 0
    sort > /tmp/wanted
    find . -type f | sed "s|^\./||" | sort > /tmp/have
    comm -23 /tmp/have /tmp/wanted > /tmp/extra
    while IFS= read -r f; do rm -f -- "$f"; done < /tmp/extra
    find . -mindepth 1 -type d -empty -delete
    wc -l < /tmp/extra' < "$work/wanted")
log "restored storage (removed $removed file(s) the backup does not name)"

# ── 4. Back up ──────────────────────────────────────────────
./up.sh
log "restored $dump"
