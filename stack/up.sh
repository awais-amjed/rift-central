#!/usr/bin/env bash
# Bring central up: secrets on the first run, the containers, then every
# migration in filename order.
#
# The migrations are applied on every run, not only the first. Each file states
# the shape it is meant to have and is written to be re-run — that is how the
# hosted project has been kept current too — so this is also how a change to
# one reaches a running stack.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

python3 setup.py
docker compose up -d --wait

for f in ../migrations/[0-9][0-9][0-9]_*.sql; do
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' central-db \
    psql -U postgres -q -v ON_ERROR_STOP=1 -f - < "$f" >/dev/null
  echo "applied $(basename "$f")"
done

# Realtime's seed writes its tenant row, and on every later boot would reset
# that row's limits to the free tier's (see rift-self-host's compose file). So
# it runs once: the row exists now, and the next boot must leave it alone.
if grep -q "^REALTIME_SEED='true'" .env; then
  sed -i "s/^REALTIME_SEED='true'/REALTIME_SEED='false'/" .env
  docker compose up -d --wait realtime >/dev/null
fi

echo "Central is up on $(grep '^API_EXTERNAL_URL=' .env | cut -d"'" -f2)"
