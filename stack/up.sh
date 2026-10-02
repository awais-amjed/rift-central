#!/usr/bin/env bash
# Bring central up: secrets on the first run, the containers, then each
# migration this database has not run yet, in filename order.
#
# Each file runs once, and is recorded with its checksum in rift_central.migrations
# in the same transaction. The files are locked once they ship
# (migrations/locked.sha256): a change to the schema is a new file, never an
# edit, so a recorded file that has changed since it ran here stops the run
# rather than being applied on top of a database it did not build.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Kong and Caddy read their config files once, at start, and Compose only
# recreates a container when its own settings change — not when a mounted
# file does. So what they last loaded is recorded, and they are restarted
# when Kong's template or start script changed, or setup.py rendered a
# different Caddyfile. (A changed key is Kong's environment, which Compose
# does notice.)
python3 setup.py

# Realtime's seed writes its tenant row, and on every later boot would reset
# that row's limits to the free tier's (see rift-self-host's compose file). So
# it runs only while the database has no tenant — which is a fact about the
# database, not about .env: a machine restored from backup has the same .env
# as the old one and an empty database. So ask the database.
docker compose up -d --wait db
tenants=$(docker exec central-db psql -U supabase_admin -d postgres -tAc \
  "select count(*) from _realtime.tenants" 2>/dev/null || echo 0)
if [[ $tenants == 0 ]]; then
  REALTIME_SEED=true docker compose up -d --wait
  # And straight back off, now that the row exists.
  docker compose up -d --wait realtime >/dev/null
  echo "seeded Realtime's tenant"
else
  docker compose up -d --wait
fi
# A profile that is off does not stop what it started; back on a local stack,
# Caddy would keep holding 80 and 443.
if ! grep -q "^COMPOSE_PROFILES='tls'" .env; then
  docker compose --profile tls rm -sf caddy >/dev/null 2>&1
fi
rendered=$({ cat templates/kong.yml templates/kong_start.sh volumes/caddy/Caddyfile 2>/dev/null || true; } | sha256sum)
if [[ $rendered != "$(cat volumes/.loaded 2>/dev/null)" ]]; then
  docker compose restart kong >/dev/null
  if grep -q "^COMPOSE_PROFILES='tls'" .env; then docker compose restart caddy >/dev/null; fi
  docker compose up -d --wait >/dev/null
  echo "$rendered" > volumes/.loaded
  echo "restarted the gateway for its new config"
fi

# The ledger sits outside the schemas PostgREST publishes (public, storage),
# so no key reaches it, as rift-self-host's console keeps its own.
psql_db() {
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' central-db \
    psql -U postgres -q -v ON_ERROR_STOP=1 "$@"
}
psql_db >/dev/null <<'SQL'
CREATE SCHEMA IF NOT EXISTS rift_central;
CREATE TABLE IF NOT EXISTS rift_central.migrations (
  name       TEXT PRIMARY KEY,
  checksum   TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE ALL ON SCHEMA rift_central FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA rift_central FROM PUBLIC, anon, authenticated;
SQL
for f in ../migrations/[0-9][0-9][0-9]_*.sql; do
  name=$(basename "$f")
  sum=$(sha256sum "$f" | cut -d' ' -f1)
  ran=$(psql_db -tA -c "SELECT checksum FROM rift_central.migrations WHERE name = '$name'")
  if [[ -z $ran ]]; then
    { cat "$f"; echo; echo "INSERT INTO rift_central.migrations (name, checksum) VALUES ('$name', '$sum');"; } |
      psql_db -1 -f - >/dev/null
    echo "applied $name"
  elif [[ $ran != "$sum" ]]; then
    echo "$name has changed since it ran here. A shipped migration is never edited:" >&2
    echo "put the change in a new numbered file. Stopping before anything else runs." >&2
    exit 1
  fi
done

# The two rows the database reads to call its own functions (README, "The two
# config rows"): where to send, and the secret to send with it. Written on
# every run, so a changed secret or a newly added Firebase key lands here too.
# Addressed on the internal network — the database and the functions are
# neighbours, and a round trip through Caddy and back would only add a way
# for it to break. Piped rather than passed, so no secret is an argument.
env_value() { sed -n "s/^$1='\(.*\)'\$/\1/p" .env; }
{
  echo "INSERT INTO attachment_sweep_config (endpoint, secret)"
  echo "  VALUES ('http://functions:9000/sweep_dm_attachments', '$(env_value ATTACHMENT_SWEEP_SECRET)')"
  echo "  ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, secret = EXCLUDED.secret;"
  # Push only once there is a Firebase key: without the row a DM rings nobody
  # and says nothing, which is right; with it and no key, every DM would call
  # a function that cannot start.
  if [[ -n $(env_value FCM_SERVICE_ACCOUNT) ]]; then
    echo "INSERT INTO push_config (endpoint, secret)"
    echo "  VALUES ('http://functions:9000/push_send', '$(env_value PUSH_SECRET)')"
    echo "  ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, secret = EXCLUDED.secret;"
  else
    echo "DELETE FROM push_config;"
  fi
} | docker exec -i central-db psql -U postgres -q -v ON_ERROR_STOP=1 >/dev/null
echo "wrote the function config rows"

echo "Central is up on $(env_value API_EXTERNAL_URL)"
if [[ -z $(env_value FCM_SERVICE_ACCOUNT) ]]; then
  echo "  Push is off: no Firebase key (./setup.py --fcm key.json, then ./up.sh)."
fi
if [[ -n $(env_value DOMAIN) && -z $(env_value SMTP_HOST) ]]; then
  echo "  No SMTP in .env: nobody can confirm an address and finish signing up."
fi
