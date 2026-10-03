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
3. **A checkout:** `git clone <rift-central> rift-central`. Everything the
   stack runs is in it, the email templates included.
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
7. **Backups** — see [Backups](#backups) below. Do this before anybody signs
   up.
8. **A moderator:** `../scripts/add_admin.sh you@example.com "Name"`,
   then sign in on the admin site built against this domain.
9. **Clients:** the app's `SupabaseConfig` and the admin site's `.env` take the
   new URL and `PUBLISHABLE_KEY` from `.env`. The push relay
   (`../relay/wrangler.toml`) forwards to `https://<domain>/functions/v1/push_send`.

**Updating** is `git pull` and `./up.sh` again. Migrations this database has
not run yet are applied, the containers that changed are recreated, and Kong and Caddy are
restarted if their config changed. Kong's config holds the API keys, so it is
never written to disk: `templates/kong.yml` is mounted as it is, and Kong
fills the keys in from its environment at every start (`kong_start.sh`).

## What `up.sh` does, and why each part

- **Runs `setup.py`**, which keeps an existing `.env` and only adds what a newer
  version needs. Options can be added later: `./setup.py --fcm key.json` then
  `./up.sh` turns push on; `--no-fcm` turns it off.
- **Applies each migration once**, in filename order, recording its name and
  checksum in `rift_central.migrations` in the same transaction (a schema no
  key reaches). A file that has changed since it ran stops the run: shipped
  migrations are locked, and a change to the schema is a new file.
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
| TLS (Caddy, Let's Encrypt) | Monitoring and alerts (beyond the backup heartbeat) |
| Per-address limits on signing in, verifying and refreshing — Caddy hands Auth each client's address, IPv6 included | |
| Email with Rift's templates, over your SMTP | Studio (Supabase's dashboard) — `psql` in the db container instead |
| Push, the nightly sweep, publishing servers | |
| The second-factor lockout for moderators | |
| Hourly encrypted backups to R2, and restore | |

The emails are fetched by Auth from `mail-templates`, a file server on the
internal network over `../email-templates`. Their subjects are in
`docker-compose.yml`.

`functions/main/` is Supabase's router for the edge runtime; see its README.
`volumes/db/` holds Supabase's first-boot scripts; see that README.

## Backups

Every hour, to a Cloudflare R2 bucket (any S3 service works):

- **The database** — accounts, DMs, the directory, the auth tables with every
  password hash and authenticator — as a dump. Kept: the last **24 hourly**,
  **14 daily**, **4 weekly**.
- **Storage's files** — vault backups, DM attachments, icons — synced: only
  what is new is sent. A file that leaves the server (a vault backup replaced,
  an attachment expired) is moved aside in the bucket and kept **30 days**, so
  the oldest dump can still be restored with every file it names. That also
  keeps each account's previous vault backups for a month.

Everything is encrypted on this machine before it is sent, names included,
with `BACKUP_PASSWORD` from `.env`. **Without that password no backup can be
read** — keep it with the offline copy of `.env`.

### Setting it up

1. **In Cloudflare, R2:** create a bucket, `rift-central-backups`.
2. **An API token** (R2 → Manage API tokens): *Object Read & Write*, applied to
   that bucket only. Put its values in `.env`:
   ```
   BACKUP_S3_ENDPOINT='https://<account id>.r2.cloudflarestorage.com'
   BACKUP_S3_ACCESS_KEY_ID='…'
   BACKUP_S3_SECRET_ACCESS_KEY='…'
   ```
   A bucket created with the EU jurisdiction has its own endpoint,
   `https://<account id>.eu.r2.cloudflarestorage.com`. Keep the bucket in the
   Standard storage class: Infrequent Access bills every object for at least
   30 days, and an hourly dump lives for one.
3. **Run it once by hand:** `./backup.sh`.
4. **The bucket's rules:** `./backup.sh --rules` prints four prefixes. For
   each, in the bucket's settings, add
   - an **object lifecycle rule** deleting objects under that prefix after the
     days shown, and
   - a **bucket lock rule** on the same prefix for the same days.

   The lifecycle rules are what prune old backups: this script never deletes
   anything. The locks are what make a stolen server harmless to the backups —
   its key can write, but nothing under a locked prefix can be deleted or
   replaced until its time is up. One prefix is an encrypted name: that is
   `files/deleted`, whose name is encrypted like everything else under
   `files/`.
5. **Hourly from now on:** `sudo ./install_backup_timer.sh`. It runs at seven
   minutes past; `journalctl -u rift-central-backup` shows each run.
6. **Optional, a heartbeat:** a URL in `BACKUP_PING_URL` (healthchecks.io,
   Uptime Kuma) is called after every successful run, so a monitor notices the
   hour that did not arrive.

**One gap, stated plainly:** `files/current` — the up-to-date copy of the
files — cannot be locked, because the sync has to move things out of it. The
dumps and everything that has left the server are protected; somebody holding
this machine could delete the current copy of the files from the bucket. Most
of it lives on users' own devices too (a vault backup is a copy of a vault),
and DM attachments expire in 30 days regardless.

### Restoring

```bash
./restore.sh --list                 # what there is
./restore.sh                        # the newest
./restore.sh 2026-09-26T210700Z     # a particular one (or 2026-09-26, 2026-W39)
```

It asks before it replaces anything. It stops the services, loads the dump's
rows into the tables, copies back the files that dump names — including ones
that had already left the server — removes files it does not name, and runs
`up.sh`. The schema comes from the migrations, not the dump, so restoring onto
a new machine is: this checkout, the offline `.env`, `./up.sh` once, then
`./restore.sh`.

Proved locally on 26 September 2026 against a stand-in bucket: a stack wiped
to nothing and restored came back with every account signing in with its
password, the moderator's authenticator working, and every file byte-identical;
restoring an older dump brought back the vault backup that had since been
replaced.

