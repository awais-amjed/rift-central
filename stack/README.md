# Central, self-hosted

Everything central is, as containers: Postgres, Supabase Auth, PostgREST,
Realtime, Storage, the edge runtime with central's three functions, Kong in
front of them, and Caddy for TLS. Upstream images, at the versions
`rift-self-host` pins.

```bash
./setup.py --domain central.example.com --fcm firebase-service-account.json
# fill in SMTP_* in .env
./up.sh
```

Without `--domain` it is a local stack on `127.0.0.1:28000`, for testing.

## Deploying on a fresh server

1. **DNS and ports.** An A record for the domain pointing at the server, and
   ports 80 and 443 open (TCP, and UDP 443). Caddy gets the certificate on the
   first request; nothing else is exposed.
2. **Docker** with Compose v2, **Python 3** with `cryptography`
   (`apt install python3-cryptography`).
3. **Two checkouts, side by side:**
   ```bash
   git clone <rift-central> rift-central
   git clone <rift-website> rift-website   # the email templates live there
   ```
   Elsewhere is fine too: set `EMAIL_TEMPLATES_DIR` in `.env` to the
   templates folder.
4. **Setup:**
   ```bash
   cd rift-central/stack
   ./setup.py --domain central.example.com --fcm /path/to/firebase-service-account.json
   ```
   This generates every secret into `.env` (mode 600, never committed). Keep a
   copy somewhere safe: the database trusts these keys, and a lost `.env`
   means re-keying every client.
5. **SMTP**, by hand in `.env` — Amazon SES as on the hosted project:
   ```
   SMTP_HOST='email-smtp.ap-southeast-1.amazonaws.com'
   SMTP_PORT='587'
   SMTP_USER='…'
   SMTP_PASS='…'
   SMTP_SENDER='no-reply@joinrift.app'
   ```
   A stack with a domain requires addresses to be confirmed, so without this
   nobody can finish signing up. `up.sh` says so.
6. **Start:** `./up.sh`. It starts everything, applies every migration, and
   writes the rows the database uses to call its own functions.
7. **A moderator:** `../scripts/add_admin.sh --stack you@example.com "Name"`,
   then sign in on the admin site built against this domain.
8. **Clients:** the app's `SupabaseConfig` and the admin site's `.env` take the
   new URL and `PUBLISHABLE_KEY` from `.env`. The push relay
   (`../relay/wrangler.toml`) forwards to `https://<domain>/functions/v1/push_send`.

**Updating** is `git pull` and `./up.sh` again. Every migration file is safe to
re-run, the containers that changed are recreated, and Kong and Caddy are
restarted if their rendered config changed.

## What `up.sh` does, and why each part

- **Runs `setup.py`**, which keeps an existing `.env` and only adds what a newer
  version needs. Options can be added later: `./setup.py --fcm key.json` then
  `./up.sh` turns push on; `--no-fcm` turns it off.
- **Applies all seven migrations** in order, every run.
- **Writes the two config rows** (`attachment_sweep_config`, `push_config`),
  addressed to the functions on the internal network. Push's row is written
  only when there is a Firebase key: without one, `push_send` cannot start,
  and a missing row makes a DM ring nobody instead of failing.
- **Seeds Realtime's tenant** only when the database has none — a fresh stack,
  or a new machine restoring from backup — and never again after, as
  rift-self-host explains.

## Checking it

```bash
docker compose ps                                   # everything healthy
docker exec central-db psql -U postgres -c "select request_attachment_sweep();"
docker exec central-db psql -U postgres -c \
  "select status_code, content from net._http_response order by id desc limit 1;"
# 200 {"swept":0,"icons":0}
```

## What is here and what is not

| Here | Not here |
|---|---|
| TLS (Caddy, Let's Encrypt) | **Off-box backups** — a `pg_dump` that leaves the machine; needed before real users |
| Email with Rift's templates, over your SMTP | Monitoring and alerts |
| Push, the nightly sweep, publishing servers | Studio (Supabase's dashboard) — `psql` in the db container instead |
| The second-factor lockout for moderators | |

The emails are fetched by Auth from `mail-templates`, a file server on the
internal network over `rift-website/email-templates`. Their subjects are in
`docker-compose.yml`.

`functions/main/` is Supabase's router for the edge runtime; see its README.
`volumes/db/` holds Supabase's first-boot scripts; see that README.
