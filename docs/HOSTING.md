# Hosting central

Where central runs, why, and how to bring it up. The self-hosted stack's own deploy guide is [`stack/README.md`](../stack/README.md); the push relay's is [`relay/README.md`](../relay/README.md).

## Running central yourself

`stack/` is central as containers — the same services as the managed project,
plus Caddy for TLS — and is what `api.joinrift.app` runs. Its README is the
deploy guide:

```bash
cd stack && ./setup.py --domain central.example.com --fcm key.json && ./up.sh
```

Without `--domain` it is a local stack on `127.0.0.1:28000`. Proved locally on
26 September 2026: all seven migrations apply and re-apply; moderator sign-in
with a second factor, and its lockout, from `rift-admin`; the nightly sweep
and a push request from the database to their functions; `publish_server`
refusing every internal address; confirmation email with Rift's template, its
link confirming the account; TLS through Caddy (with its local issuer — a real
certificate needs a real domain). Off-box backups run hourly, encrypted, to an
S3 bucket, and a wiped stack has been restored from them — see `stack/README.md`.

The managed project's own steps are further down, under *Deploying the managed project*, and stay until it is retired.

## The machine

A Contabo Cloud VPS 4 (4 vCPU, 8 GB, 100 GB SSD), Ubuntu 26.04, bought 29
September 2026 after Leaseweb declined the order at its identity check — it
sells to businesses, and there was none to register. The reasoning below was
written for Leaseweb and holds for Contabo, which is the fallback it names;
the one-way upgrade applies to both.

Brought up on 29 September 2026:

- **Access:** SSH by key only, no passwords, and no root login — an admin
  user with sudo. The firewall admits SSH (rate-limited), 80 and 443 (TCP,
  and UDP for HTTP/3). Docker publishes nothing else: Kong is on 127.0.0.1.
  Security updates install themselves; a kernel update waits for a reboot.
- **Updating:** the Forgejo server does not expose SSH to the internet, so the
  machine holds no credential for any repository. A workstation pushes to a
  checkout on it (`receive.denyCurrentBranch updateInstead`), and `./up.sh`
  there applies the change: `git push <server> dev`, then `./up.sh`.
- **DNS:** `A` and `AAAA` for `api.joinrift.app`, not proxied, so Caddy holds
  the certificate itself and nothing sits in front of the WebSockets.
- **Two gigabytes of swap** and a cap on container logs (5 × 20 MB each), so a
  spike or a chatty service cannot take the disk or the database with it.

- **Email:** SES SMTP credentials of its own (IAM, `ap-southeast-1`), not the
  managed project's — those cannot be read back out of it.
- **Backups:** hourly to R2, with the bucket's lifecycle and lock rules in
  place, and the bucket's token accepting requests from this machine's
  addresses only.

Proved that day: a Let's Encrypt certificate on the first request, every
migration applied, the nightly sweep answering `200`, the scheduled jobs and
both config rows present, SES accepting a message sent with this machine's
login, a backup uploaded to R2 — and the same token refused from any other
address, and refused deleting a locked dump from this one; a signup's
confirmation email arriving in a real inbox with Rift's template, and its link
confirming the account and landing on `/email-confirmation/`. Not yet: a real
push, IPv6 reached from outside, and any client pointed at it.

**Production from 3 October 2026.** The database and stored files were deleted
and rebuilt from the migrations as they stand (it held no accounts), so the
database is exactly the locked baseline rather than the result of re-running
edited files over each other; `.env`, and so every key, URL and the TLS
certificate, stayed. Checked after: Realtime's tenant seeded, both config rows
and both jobs present, the sweep `200`, Auth and REST answering with a key and
REST refusing without one, and a signup to SES's simulator address sending its
confirmation (the account deleted after). The same day the hourly backups were
found to have failed on every run since the first one by hand on 29 September:
that run left its lock file in `/tmp` owned by the deploy user, which the timer,
running as root, may not open (`fs.protected_regular = 2`). The lock is now
taken on `backup.sh` itself, and a run by the timer's own service succeeded.
Nothing watched for it, which is the monitoring this machine still lacks.

## Where central goes when it leaves

Decided 24 September 2026, before the first real user, which is the only
reason it is cheap to decide at all. **Leaseweb VPS 1 — €4.99/month, Frankfurt
or Amsterdam, monthly billing.** 4 vCPU, 6 GB RAM, 100 GB local NVMe, 30 TB
traffic.

The shape of the argument matters more than the provider, because the provider
will change and the reasoning will not.

**Why not stay managed.** Free covers central today — it is 14 MB and a
handful of accounts. The moment it needs a name of its own it needs Pro plus
the Custom Domain add-on, which is $35/month to solve a problem a VPS solves
by having a DNS record. Moving before there are installs pinned to
`<ref>.supabase.co` means the hostname question never has to be paid for at
all. That is the whole timing argument: this is cheap now and expensive later,
and nothing about it gets better by waiting.

**Why not AWS.** Four to six times the price for the same box — Lightsail's
8 GB bundle is $44, an equivalent EC2 instance with its disk is around $55 —
and egress is metered at roughly $0.09/GB where a VPS includes tens of
terabytes. For a service that ships attachments and vault backups, a terabyte
of egress a month would cost more than the machine. Getting EC2 near VPS money
needs a one-to-three-year commitment, which is the opposite of starting small.
The one real argument for AWS is that SES already lives there, and one bill is
worth something — just not $35 a month at this size.

**Why not Hetzner, which would otherwise have won.** It is the only provider
found that lets CPU and RAM scale *reversibly* (rescale with the disk left
alone) and grows storage independently through Volumes. It is also, as of
September 2026, unbuyable: the entire CX and CAX line reads "not available",
Hetzner's own status page carries a standing *Limited availability of Cloud
plans* incident, and new customers are restricted from creating cloud servers
at all. A product that cannot be ordered is not a choice.

**Why not Contabo.** Against VPS 1 it is *more* expensive (~€6.20), on SATA
SSD rather than NVMe, behind a 200 Mbit port, and operationally wobblier —
independent uptime testing lands under its own advertised figure, and its
Object Storage cluster was degraded the day before this was written, which is
the product the storage plan below depends on.

**Why not Leaseweb's own Public Cloud**, which is the same company selling the
parts separately — compute, network block storage and addresses billed and
resized independently, hourly, with an API. It is the nicer shape and it costs
considerably more for equivalent specs. It also puts the database's `fsync` on
a network device instead of a local NVMe, which is the one latency a Postgres
box actually feels.

### What follows from this choice

**Upgrades are one-way, so start at the bottom.** Neither Leaseweb nor Contabo
supports a downgrade — the documented answer at both is "order a smaller one
and migrate". Upgrading, though, is a button. When up is easy and down is
impossible, buying headroom in advance is just paying early for a size you may
never need. The trigger to move to VPS 2 (€8.99, 6 vCPU / 16 GB / 200 GB) is
**concurrent connections into the low thousands**: Realtime costs 85–230 KB
per socket, the stack idles around 1.5 GB, and 6 GB stops being comfortable
somewhere in that range.

**Disk now, object storage later, and never both.** `STORAGE_BACKEND` is one
global setting — there is no per-bucket backend, so buckets cannot be split
between a local disk and a bucket. The file backend writes objects at
`<bucket>/<name>/<version>`, which is the S3 key layout on a local filesystem,
so the migration is a sync of that tree plus an environment change; Postgres is
untouched, because `storage.objects` is the authority either way. The one thing
that does not survive a plain copy is the per-object metadata the file backend
keeps in extended attributes — which for Rift is cosmetic, since every blob is
ciphertext and image transformation is off. The consequence worth remembering:
**storage growth never forces a machine upgrade**, because the escape hatch is
a backend swap rather than a bigger disk.

**The directory needs moderation before it is public, and that is now a
hosting requirement rather than a product nicety.** Leaseweb's documented
reflex on an abuse report is to null-route the address first. Central serves
the public server directory — names, descriptions and icons, in plaintext,
written by strangers — so one ugly listing is one report away from taking down
the address that every client uses for accounts, DMs and backups. End-to-end
encryption does not help here; it means nobody can verify the complaint is
bogus either.

**Backups leave the box.** A provider snapshot protects the disk, not the
decision to keep everything on one machine. Central holds the account rows and
the encrypted vault backups, and the migrations plus this README can rebuild
everything except the data. An off-box `pg_dump` is what makes a null-route or
a dead host an hour of work instead of a catastrophe.

Prices here are September 2026 and this tier repriced at least twice during the
year — Hetzner in June, Leaseweb in August, Netcup across its G12.5 line.
Treat every figure above as needing a check rather than a quote.

## The two ceilings on managed hosting

Central is the one part of Rift that cannot be somebody else's problem, and it
is currently a managed Supabase project. Two limits will eventually end that
arrangement. They are unrelated, they arrive at different times, and only one
of them is about growth — which is worth keeping straight, because the cheap
answer to one is not an answer to the other.

**Capacity: concurrent Realtime connections.** 200 included on Free, 500 on Pro,
and — this is the part that matters — **over that it is a meter, not a wall**:
$10 per additional 1,000 peak connections, billed against the highest
simultaneous count in the cycle. Messages are metered the same way, 5 million
included on Pro and $2.50 per million after.

So the cap does not stop Rift working at 501 users; it starts charging. There
are two ways it becomes a wall rather than a bill. With a spend cap on (and
always on Free) an overage buys a notification and a grace period instead of an
invoice. And a project that *sustains* consumption far past its plan can be
suspended by hand, which shows up as `RealtimeDisabledForTenant`: new
connections fail and live subscriptions stop receiving anything.

Central's Realtime carries `user:<id>` and nothing else — DMs and friend
activity — so its connection count is very close to "people with the app open
right now", whatever servers they are on and however quiet they are. Its
*message* count is not: DM traffic only, because typing is not relayed here.
That is worth keeping true, since typing indicators are what would turn a
modest meter into the dominant line on the bill.

None of this is about query cost, and no amount of schema work moves it. A
connection is a socket and something like 85–230 KB of Realtime memory; a
faster query does not let a tenant hold more of them. The one change that ever
moved this number was giving each client a single socket per server instead of
eight, which was worth about 8× and cannot be repeated — one is the floor. For
reference, a self-hosted Realtime measured on a 20-core development box held
10,000 connections in 1.6 GiB and sustained ~97,000 deliveries a second. The
software is nowhere near the constraint; the plan is.

**Lock-in: the vendor hostname.** `SupabaseConfig.supabaseUrl` is compiled into
every client that has ever been installed, and it is currently
`<ref>.supabase.co`. Giving the project a name we own means Supabase's Custom
Domain add-on: $10 per domain per month, Pro-and-above, on top of the $25.

That is the cheapest item on this page and the one with a deadline. A name we
own can be repointed at a self-hosted stack with a DNS change; a vendor URL
cannot be repointed at all, and every install made before the switch is pinned
to it for as long as that install survives. The add-on is worth buying before
the first real user, not when the move is wanted.

The push relay already solves this problem for itself, and the way it does so
is not available here. `push.joinrift.app` is a **Cloudflare Worker** custom
domain — free — forwarding to the function URL, which works because a push is
one POST with no session and no upgrade. Central's API is GoTrue redirects,
PostgREST and WebSockets, so a forwarder in front of it is not a DNS change but
a proxy with opinions about every one of those.

So the distinction is: the connection cap is hit by growing and answered with
money, and the hostname is hit by wanting to leave and answered with an app
update. The second is the one that compounds, because every day on a vendor URL
adds installs pinned to it. If central is ever going to be self-hosted, the
hostname is the thing to do first and the capacity is only the thing that
decides when.

What self-hosting would have to replace: Postgres with `pg_cron` and `pg_net`,
GoTrue, PostgREST, Realtime, Storage, and the three edge functions — which are
ordinary Deno HTTP handlers and need no Supabase runtime; `relay/server.mjs`
already runs one of them on plain Node. SES and the Firebase credentials are
external either way and do not move.

## Deploying the managed project

```bash
supabase functions deploy publish_server --project-ref <ref>

# push_send is called by a database trigger, which carries no JWT.
TMPDIR=$HOME/tmp supabase functions deploy push_send \
  --project-ref <ref> --no-verify-jwt

# sweep_dm_attachments is called by a daily pg_cron job (006), also JWT-less.
TMPDIR=$HOME/tmp supabase functions deploy sweep_dm_attachments \
  --project-ref <ref> --no-verify-jwt
```

`TMPDIR` has to point somewhere Docker Desktop shares. `/tmp` is not, and the
bundler fails with "path is not shared from the host" rather than saying so.

Migrations go through the SQL editor or `psql`, in filename order, each once:
a managed project has no migrator. The stack's `up.sh` is one, and keeps its
record in `rift_central.migrations`.

The relay is deployed separately; see `relay/README.md`.

## Bringing up a project from nothing

The migration files are the schema and nothing else. A Supabase project
also holds settings, secrets and two rows that no migration can write, and the
schema comes up perfectly well without any of them — which is the problem. So
this is the list, and the last column is how to prove each one took, because
most of these fail by being quiet.

Applied in order. Steps 4 and 5 depend on the function URLs from step 2.

### 1. The schema

`psql` or the SQL editor, `migrations/*.sql` in filename order. `pg_net` and
`pg_cron` are created by the migrations themselves (001 and 006), so nothing
has to be enabled in the dashboard first. `pg_cron` only installs into the
database named by `cron.database_name`, which is `postgres` on a stock
project — the two scheduled jobs will not exist if it is not.

```sql
select jobname, schedule, active from cron.job;
-- central-dm-retention        17 3 * * *   t
-- central-dm-attachment-sweep 47 3 * * *   t
```

### 2. The three edge functions

The commands are above. `publish_server` keeps JWT verification; the other two
are called by the database, which carries no JWT, and will answer 401 to their
own callers if that flag is forgotten.

```bash
supabase functions list --project-ref <ref>   # three, ACTIVE, verify_jwt as above
```

### 3. The four secrets

`supabase secrets set NAME=value --project-ref <ref>`. The `SUPABASE_*` entries
alongside them are put there by the platform; these four are not.

| Secret | Read by | What it is |
|---|---|---|
| `RIFT_SECRET_KEY` | all three functions | The project's `sb_secret_…` key — what a function uses to reach the database as `service_role` |
| `PUSH_SECRET` | `push_send/relay.ts` | Proves a push request came from a database that was told it, not from the internet |
| `FCM_SERVICE_ACCOUNT` | `push_send/relay.ts` | The Firebase service-account JSON, whole, as one value |
| `ATTACHMENT_SWEEP_SECRET` | `sweep_dm_attachments/index.ts` | The same idea for the nightly sweep |

**`RIFT_SECRET_KEY` rather than the platform's `SUPABASE_SERVICE_ROLE_KEY`,
and this is the one item here that is a decision rather than a step.** A
project starts with two key systems live at once. The old one is a pair of
HS256 JWTs — `anon` and `service_role` — signed with a single project-wide
secret, and that secret is readable by anyone who can reach the management
API for the project, including through the PostgREST config endpoint. So the
legacy `service_role` key is a permanent, unexpiring, RLS-bypassing
credential recoverable from a settings page, and it does not expire until
2036.

Disabling the legacy keys is what takes that away, and the platform then
stops injecting `SUPABASE_SERVICE_ROLE_KEY` into functions — which is why the
functions have to be moved onto a key of their own *first*, or all three stop
being able to reach the database. Order:

1. `supabase secrets set RIFT_SECRET_KEY=sb_secret_…` (reveal it from the
   dashboard's API keys page, or `/v1/projects/<ref>/api-keys?reveal=true`)
2. deploy all three functions — each reads `RIFT_SECRET_KEY` and falls back to
   the legacy name, so this step is safe in either order with the one above
3. `PUT /v1/projects/<ref>/api-keys/legacy?enabled=false` — note the query
   string; a JSON body is rejected with a message about a missing string
4. revoke the HS256 signing key, which is what the old secret actually was:
   `PATCH /v1/projects/<ref>/config/auth/signing-keys/<hs256 id>` with
   `{"status":"revoked"}`. It will be `previously_used` next to an `in_use`
   ES256 key; sessions are ES256 and access tokens live an hour, so nothing
   signed with it is still valid by the time anyone gets here.

Done on the live project on 24 Sep 2026. To prove step 4 took, mint an HS256
`service_role` token with the old secret and call PostgREST with it: `401
Invalid API key` is the answer you want.

`supabase secrets list` shows a digest rather than the value, so a secret
cannot be read back out of the project to fill in step 4 — generate it once
and write both places in the same sitting, or generate a new one and rotate
both.

### 4. The two config rows — the step that gets missed

`push_config` and `attachment_sweep_config` hold one row each: the address the
database should call, and the copy of the secret it should send. Nothing but a
`SECURITY DEFINER` function can read either, which is why they are rows rather
than settings.

**Both callers treat a missing row as "not configured on this deployment" and
return.** `ring_recipient` (003) and `request_attachment_sweep` (006) both do
`SELECT * INTO v_cfg … IF v_cfg IS NULL THEN RETURN`. That is the right
behaviour — a deployment without Firebase should not raise on every DM — and
it means an empty table looks exactly like a working one from the outside. Both
were found empty on the live project on 24 Sep 2026, long after the features
were built and tested: the nightly sweep had never once run, and no central DM
had ever woken a phone.

```sql
INSERT INTO push_config (endpoint, secret) VALUES
  ('https://<ref>.supabase.co/functions/v1/push_send', '<PUSH_SECRET>')
ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, secret = EXCLUDED.secret;

INSERT INTO attachment_sweep_config (endpoint, secret) VALUES
  ('https://<ref>.supabase.co/functions/v1/sweep_dm_attachments', '<ATTACHMENT_SWEEP_SECRET>')
ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, secret = EXCLUDED.secret;
```

The function URL directly, not `push.joinrift.app`. The relay hostname exists so
that a *self-hosted* server never learns where the relay really is; central is
the project the function runs in and has no such distance to keep.

Prove it rather than assume it. The sweep can be fired by hand and says what it
did, which is the only one of these two that can be tested without a phone:

```sql
select request_attachment_sweep();
-- then, a few seconds later:
select status_code, content from net._http_response order by id desc limit 1;
-- 200 {"swept":0,"icons":0}
```

A non-200, or no row at all, means the endpoint or the secret is wrong. Push has
no such probe — it needs a real device — so check it with two accounts before
believing it.

### 5. Auth settings

None of this is in a migration; it is the project's auth config, set in the
dashboard under **Authentication** or PATCHed to `/v1/projects/<ref>/config/auth`.

| Setting | Value | Why |
|---|---|---|
| SMTP | Amazon SES, `email-smtp.ap-southeast-1.amazonaws.com:587`, sender `no-reply@joinrift.app` | The built-in sender is rate-limited to a handful an hour and is not for real accounts |
| `site_url` | `https://joinrift.app` | |
| `uri_allow_list` | `https://joinrift.app/email-confirmation/` | The client passes its redirect explicitly, and GoTrue refuses one that is not listed |
| `mailer_autoconfirm` | off | Confirmation is the point |
| `mailer_secure_email_change_enabled` | on | A change confirms at both addresses |
| `mailer_notifications_password_changed_enabled` | on | |
| `password_min_length` | 6 | |
| Email subjects and templates | from `email-templates/` | Seven templates, pasted in or PATCHed; that directory's README maps each file to its config field |

The templates are the one part of Rift's design that renders somewhere we do
not control, which is why they are version-controlled in the website repo
rather than left at GoTrue's defaults.

### 6. The relay

A Cloudflare Worker, `relay/wrangler.toml`, giving `push.joinrift.app` a
meaning and forwarding to the `push_send` function. `wrangler deploy` from
`relay/`. It is addressed by a hostname we own so the relay can move without
every self-hosted server learning that it did — see `relay/README.md`.

`push.joinrift.app` must resolve before push is enabled on any server. The
client checks it answers before writing it into one, so a missing DNS record
is a sentence rather than a silence.

### 7. The client

`SupabaseConfig` in the `rift` repo carries the project URL and the publishable
key — `sb_publishable_…`, not the legacy `anon` JWT, which step 3 turns off. A new project is a new URL and a new key, and every installed client is
pinned to the old ones — which is fine while there are no real accounts, and is
a migration once there are.
