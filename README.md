# rift-central

The tier every Rift client talks to, and nobody self-hosts.

A single Supabase project plus one Cloudflare Worker. Members do not need it —
the app's privacy mode contacts nothing but a server — but it is where the
things that cannot live on somebody else's machine go:

| What | Why it is central |
|---|---|
| Accounts and handles | One namespace, so a handle means one person |
| Encrypted vault backups | Ciphertext only; the key never leaves the device |
| Friends, blocks, direct messages | Between people who share no server yet |
| The public server directory | Opt-in listings, so a server can be found |
| The public bot directory | Opt-in listings and likes, so a bot can be found |
| The push relay | An FCM token is scoped to the app's Firebase project, so a self-hosted server cannot wake its own members' phones and has to ask |

What central learns by relaying a push is a device token and a moment: not the
sender, not the text, not the server or the channel. The payload is empty.

## Layout

```
migrations/                 the schema, applied in filename order
migrations/tests/           policy tests — what each role may actually reach
supabase/functions/         edge functions: publish_server, push_send
relay/                      the push relay's hosts — Node, Cloudflare, or the function
scripts/db_test.sh          runs the policy tests against a scratch database
```

`supabase/functions/` rather than `functions/` because that is the layout the
Supabase CLI deploys from; it is not a directory anybody chose.

## The policy tests

```bash
./scripts/db_test.sh
```

Against a scratch database in any Postgres container, never against the hosted
project — that one has real accounts on it. The scratch database gets a
stand-in for the parts of Supabase the migrations lean on, **all seven files
are applied**, and the suite ends in `ROLLBACK`.

The stand-in is deliberately faithful rather than convenient: it installs
Supabase's own default privileges, which grant `anon` EXECUTE on every new
function in `public`. That is what makes the last check worth running — it
asks what is reachable that nobody granted by name, which is a question a
policy test cannot ask, because by the time it runs a default grant looks
exactly like an intended one.

There are seven files and they are split by kind — tables, RPCs, triggers,
realtime, storage, jobs, security — not by feature. Each states the shape it
is meant to have rather than how the schema got there.

`RIFT_PG_CONTAINER` picks the container; it defaults to the one the app's local
development stack runs.

## The two directories

They look alike and are governed differently, which is the thing to know
before changing either.

A **server** listing reserves `(supabase_url, server_id)` — a pair that
exists whether or not its owner has claimed it. So the first account to
publish one holds the only slot, and a member of any server holds everything
needed to publish it. `publish_server` is therefore service-role only, behind
an edge function that redeems a one-time token against the server's own
domain. Domain control is the one thing central can actually verify.

A **bot** listing reserves nothing. It names no database central could ask,
points at no running thing, and two accounts listing a bot of the same name
are simply two rows. There is nothing an edge function could check, so
`publish_bot` is granted to `authenticated` and the uniqueness is per account
— the failure that rule avoids is an author permanently unable to list their
own work.

Ranking is a like rather than a rating. An average needs volume before it
means anything, and what a rating would really measure — does this bot work —
is invisible to a database that never touches the server the bot runs on.
Installs would be the better signal and cannot be counted: adding a bot is an
invite minted on the admin's own server, and central never hears about it.
`public_bots.like_count` is denormalised and recounted by trigger, because
the default browse order *is* that number and an `ORDER BY` over a subquery
cannot use an index.

## The relay

`supabase/functions/push_send/relay.ts` has **no imports** — `fetch`, `crypto.subtle`,
`btoa` and `Response` exist in Deno, Node 18+ and Workers alike — so the same
source runs in all three places and `relay/` holds only the adapters. See
`relay/README.md` for the ceiling on Workers, which is measured rather than
guessed, and for why the relay is addressed by a hostname Rift owns rather than
a vendor URL.

## Deploying

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

Migrations go through the SQL editor or `psql`, in filename order. There is no
migrator here — this is one project with one operator, and the ledger that
makes `rift-self-host` upgradable exists because that repo has neither.

The relay is deployed separately; see `relay/README.md`.

## The two ceilings on managed hosting

Central is the one part of Rift that cannot be somebody else's problem, and it
is currently a managed Supabase project. Two limits will eventually end that
arrangement. They are unrelated, they arrive at different times, and only one
of them is about growth — which is worth keeping straight, because the cheap
answer to one is not an answer to the other.

**Capacity: concurrent Realtime connections.** 200 on Free, 500 on Pro. Central's
Realtime carries `user:<id>` and nothing else — DMs, friend activity, typing —
so its connection count is very close to "people with the app open right now",
whatever servers they are on and however quiet they are. That makes the cap a
ceiling on *simultaneous users of Rift*, which is a smaller number than it
sounds like and arrives sooner than the storage or bandwidth limits do.

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
Domain add-on, which is Pro-and-above and billed on top of it.

The push relay already solves this problem for itself, and the way it does so
is not available here. `push.joinrift.app` is a **Cloudflare Worker** custom
domain — free — forwarding to the function URL, which works because a push is
one POST with no session and no upgrade. Central's API is GoTrue redirects,
PostgREST and WebSockets, so a forwarder in front of it is not a DNS change but
a proxy with opinions about every one of those.

So the distinction is: the connection cap is hit by growing, and the hostname
is hit by wanting to leave. The second is the one that compounds, because every
day on a vendor URL adds installs pinned to it — the move stops being a DNS
change and becomes an app update with a migration window. If central is ever
going to be self-hosted, the hostname is the thing to do first and the capacity
is the thing that decides when.

What self-hosting would have to replace: Postgres with `pg_cron` and `pg_net`,
GoTrue, PostgREST, Realtime, Storage, and the three edge functions — which are
ordinary Deno HTTP handlers and need no Supabase runtime; `relay/server.mjs`
already runs one of them on plain Node. SES and the Firebase credentials are
external either way and do not move.

## Bringing up a project from nothing

The seven migration files are the schema and nothing else. A Supabase project
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
| Email subjects and templates | from `rift-website/email-templates/` | Seven templates, pasted in or PATCHed; that directory's README maps each file to its config field |

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

## What is not here

A migration here and a migration in `rift-self-host` are different databases
with different operators, which is the whole point of the split. Nothing in this
repository is something a self-hoster runs.

## Where this sits

Rift is five repositories, meant to be cloned as siblings.

| Repo | Holds |
|---|---|
| `rift` | the client: Flutter app, Rust crate, `rift_crypto` |
| `rift-self-host` | a server's schema, endpoints and console — anyone runs one |
| `rift-central` | accounts, the public directory, the push relay — we run it |
| `rift-bot-sdk` | the TypeScript bot SDK |
| `rift-website` | joinrift.app, and the self-hosting docs |
