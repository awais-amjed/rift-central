# Developing rift-central

The layout of this repository and how its schema is tested. Back to the [README](../README.md).

## Layout

```
migrations/                 the schema, applied in filename order
migrations/tests/           policy tests — what each role may actually reach
supabase/functions/         edge functions: publish_server, push_send
relay/                      the push relay's hosts — Node, Cloudflare, or the function
scripts/db_test.sh          runs the policy tests against a scratch database
scripts/add_admin.sh        creates or removes a moderator account
stack/                      central self-hosted — compose, setup, deploy guide
email-templates/            the account emails Auth sends
```

`supabase/functions/` rather than `functions/` because that is the layout the
Supabase CLI deploys from; it is not a directory anybody chose.

## The policy tests

```bash
./scripts/db_test.sh
```

Against a scratch database in any Postgres container, never against the
production stack. The scratch database gets a
stand-in for the parts of Supabase the migrations lean on, **every numbered
file is applied** in order, and the suite ends in `ROLLBACK`. Before that,
`scripts/check_locked.sh` fails if a shipped migration was edited.

The stand-in is deliberately faithful rather than convenient: it installs
Supabase's own default privileges, which grant `anon` EXECUTE on every new
function in `public`. That is what makes the last check worth running — it
asks what is reachable that nobody granted by name, which is a question a
policy test cannot ask, because by the time it runs a default grant looks
exactly like an intended one.

`001` to `007` are the baseline central went to production on (Oct 3 2026),
split by kind — tables, RPCs, triggers, realtime, storage, jobs, security —
not by feature, each stating the shape it is meant to have. They are locked:
`migrations/locked.sha256` holds their checksums, a change to the schema is
the next numbered file, and `up.sh` runs each file once and records it in
`rift_central.migrations`. A new file adds its own line to `locked.sha256`
in the commit that adds it, and revokes and grants what it creates itself,
since the baseline's blanket revoke ran before it.

`RIFT_PG_CONTAINER` picks the container; it defaults to the one the app's local
development stack runs.

## The relay

`supabase/functions/push_send/relay.ts` has **no imports** — `fetch`, `crypto.subtle`,
`btoa` and `Response` exist in Deno, Node 18+ and Workers alike — so the same
source runs in all three places and `relay/` holds only the adapters. See
`relay/README.md` for the ceiling on Workers, which is measured rather than
guessed, and for why the relay is addressed by a hostname Rift owns rather than
a vendor URL.
