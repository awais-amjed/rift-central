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

# Kong and Caddy read their config files once, at start, and Compose only
# recreates a container when its own settings change — not when a mounted
# file does. So what they last loaded is recorded, and they are restarted
# when setup.py has rendered something different, whoever ran it.
python3 setup.py
docker compose up -d --wait
# A profile that is off does not stop what it started; back on a local stack,
# Caddy would keep holding 80 and 443.
if ! grep -q "^COMPOSE_PROFILES='tls'" .env; then
  docker compose --profile tls rm -sf caddy >/dev/null 2>&1
fi
rendered=$({ cat volumes/api/kong.yml volumes/caddy/Caddyfile 2>/dev/null || true; } | sha256sum)
if [[ $rendered != "$(cat volumes/.loaded 2>/dev/null)" ]]; then
  docker compose restart kong >/dev/null
  if grep -q "^COMPOSE_PROFILES='tls'" .env; then docker compose restart caddy >/dev/null; fi
  docker compose up -d --wait >/dev/null
  echo "$rendered" > volumes/.loaded
  echo "restarted the gateway for its new config"
fi

for f in ../migrations/[0-9][0-9][0-9]_*.sql; do
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' central-db \
    psql -U postgres -q -v ON_ERROR_STOP=1 -f - < "$f" >/dev/null
  echo "applied $(basename "$f")"
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

# Realtime's seed writes its tenant row, and on every later boot would reset
# that row's limits to the free tier's (see rift-self-host's compose file). So
# it runs once: the row exists now, and the next boot must leave it alone.
if grep -q "^REALTIME_SEED='true'" .env; then
  sed -i "s/^REALTIME_SEED='true'/REALTIME_SEED='false'/" .env
  docker compose up -d --wait realtime >/dev/null
fi

echo "Central is up on $(env_value API_EXTERNAL_URL)"
if [[ -z $(env_value FCM_SERVICE_ACCOUNT) ]]; then
  echo "  Push is off: no Firebase key (./setup.py --fcm key.json, then ./up.sh)."
fi
if [[ -n $(env_value DOMAIN) && -z $(env_value SMTP_HOST) ]]; then
  echo "  No SMTP in .env: nobody can confirm an address and finish signing up."
fi
