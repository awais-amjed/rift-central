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

# sweep_dm_attachments is called by a daily pg_cron job (018), also JWT-less.
TMPDIR=$HOME/tmp supabase functions deploy sweep_dm_attachments \
  --project-ref <ref> --no-verify-jwt
```

The attachment sweep needs one secret, set in two places that must match:
the function's `ATTACHMENT_SWEEP_SECRET` (`supabase secrets set`), and the row
it is sent from, which nothing but the database can read:

```sql
INSERT INTO attachment_sweep_config (endpoint, secret) VALUES
  ('https://<ref>.supabase.co/functions/v1/sweep_dm_attachments', '<secret>')
ON CONFLICT (id) DO UPDATE SET endpoint = EXCLUDED.endpoint, secret = EXCLUDED.secret;
```

Without that row the daily job does nothing, and attachments of expired DMs
stay in storage.

`TMPDIR` has to point somewhere Docker Desktop shares. `/tmp` is not, and the
bundler fails with "path is not shared from the host" rather than saying so.

Migrations go through the SQL editor or `psql`, in filename order. There is no
migrator here — this is one project with one operator, and the ledger that
makes `rift-self-host` upgradable exists because that repo has neither.

The relay is deployed separately; see `relay/README.md`.

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
