# rift-central

The optional shared service behind [Rift](https://joinrift.app): accounts,
encrypted vault backups, friends and direct messages, the public server and bot
directories, and the push relay.

Rift works without it. The app's privacy mode talks to nothing but the servers
you join. Central is for the things that can't live on somebody else's server:

| What | Why it's central |
|---|---|
| Accounts and handles | One namespace, so a handle means one person |
| Encrypted vault backups | Ciphertext only; the key never leaves the device |
| Friends, blocks, direct messages | Between people who share no server yet |
| The public server and bot directories | Opt-in listings, so a server or a bot can be found |
| Directory moderation | Reports, and moderators who can hide a listing |
| The push relay | A phone's push token belongs to the app's Firebase project, so a self-hosted server can't wake its own members' phones and has to ask |

Relaying a push teaches central a device token and a moment — not the sender,
the text, the server or the channel. The payload is empty.

> The project runs central at `api.joinrift.app`. A self-hoster doesn't need
> this repository: to run your own server, see
> [`rift-self-host`](https://github.com/awais-amjed/rift-self-host).

## Run it locally

Central is a standard [Supabase](https://supabase.com) stack plus Caddy, in
[`stack/`](stack/):

```bash
cd stack
./setup.py          # local stack on 127.0.0.1:28000; add --domain for a real one
./up.sh
```

[`stack/README.md`](stack/README.md) is the full deploy guide: a fresh server,
TLS, email, and hourly encrypted backups with restore.

## Tests

```bash
RIFT_PG_CONTAINER=<postgres container> ./scripts/db_test.sh
```

Builds a scratch database from [`migrations/`](migrations/), applies all of it,
and checks what every role can actually reach — including anything reachable
that nobody granted on purpose. It never touches a real project.

## Documentation

| Document | For |
|---|---|
| [`stack/README.md`](stack/README.md) | deploying central on a server, and backups |
| [`docs/HOSTING.md`](docs/HOSTING.md) | where central runs and why, and the managed-project steps |
| [`docs/DIRECTORY.md`](docs/DIRECTORY.md) | how the two directories are governed and moderated |
| [`docs/DEVELOPING.md`](docs/DEVELOPING.md) | the layout, and how the schema is tested |
| [`relay/README.md`](relay/README.md) | the push relay, and where it can run |
| [`email-templates/README.md`](email-templates/README.md) | the account emails, and what renders them |

## What's in here

```
migrations/            the schema, policies and functions, split by kind
supabase/functions/    edge functions: publishing a server, sending a push, sweeping old files
relay/                 the push relay's hosts — Node, Cloudflare, or the function
stack/                 central as containers: compose, setup, deploy guide, backups
email-templates/       the account emails Auth sends, and why they are built as they are
scripts/               the schema tests, and adding or removing a moderator
```

Moderators are separate accounts with a second factor, managed with
`scripts/add_admin.sh` and working on a separate moderation site, never in
the app.

## Related repositories

| Repository | What it is |
|---|---|
| [`rift`](https://github.com/awais-amjed/rift) | the app — Flutter client for desktop, mobile and web |
| [`rift-self-host`](https://github.com/awais-amjed/rift-self-host) | a server anyone can run |
| **`rift-central`** | this: the optional shared service |
| [`rift-bot-sdk`](https://github.com/awais-amjed/rift-bot-sdk) | the TypeScript SDK for building bots |

## License

[AGPL-3.0](LICENSE).
