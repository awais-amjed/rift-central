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
| The push relay | An FCM token is scoped to the app's Firebase project, so a self-hosted server cannot wake its own members' phones and has to ask |

What central learns by relaying a push is a device token and a moment: not the
sender, not the text, not the server or the channel. The payload is empty.

## Layout

```
migrations/         the schema, applied in filename order
migrations/tests/   policy tests — what each role may actually reach
functions/          edge functions: publish_server, push_send
relay/              the push relay's hosts — Node, Cloudflare, or the function
scripts/db_test.sh  runs the policy tests against a scratch database
```

## The policy tests

```bash
./scripts/db_test.sh
```

Against a scratch database in any Postgres container, never against the hosted
project — that one has real accounts on it. The scratch database gets a small
`auth` shim so the migrations apply unchanged, and the suite ends in `ROLLBACK`.

`RIFT_PG_CONTAINER` picks the container; it defaults to the one the app's local
development stack runs.

## The relay

`functions/push_send/relay.ts` has **no imports** — `fetch`, `crypto.subtle`,
`btoa` and `Response` exist in Deno, Node 18+ and Workers alike — so the same
source runs in all three places and `relay/` holds only the adapters. See
`relay/README.md` for the ceiling on Workers, which is measured rather than
guessed, and for why the relay is addressed by a hostname Rift owns rather than
a vendor URL.

## What is not here

The self-hosted server's schema and endpoints are in `rift-self-host`; the
client is in `rift`. A migration here and a migration there are different
databases with different operators, which is the whole point of the split.
