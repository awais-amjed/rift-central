# The central monitor

A Cloudflare Worker that checks `api.joinrift.app` every minute and the
backups every hour, and tells the owner when either changes: a post in a
private Rift channel through a webhook, and an email.

## Why it exists, and why here

On 9 October 2026 Contabo's network cut the VPS off for about seven and a
half hours. The machine stayed up — the hourly backup kept dumping the
database and failing to upload it — and nobody knew until somebody tried to
sign in. A week earlier the backups had failed on every run for four days,
and nobody knew about that either.

It runs on Cloudflare, not on the VPS, because a check on the machine that
lost its network would have kept running and told nobody.

It sends two ways because neither is enough alone. A Rift server wakes a
phone through central's push relay, so with central down the channel post
arrives silently. The email is what reaches a pocket.

## What it checks

| Every minute | The cheapest call that proves it answers |
|---|---|
| auth | `GET /auth/v1/health` |
| database | `is_handle_available` — a real query, where PostgREST's root comes from its cache |
| storage | `GET /storage/v1/status` |
| realtime | `GET /realtime/v1/api/ping` |
| functions | `GET /functions/v1/push_send` |

Each must answer within 10 seconds. **Down** is three failed checks in a
row, timed from the first, so a container restarting during a deploy says
nothing. **Working again** is two good ones in a row, so a machine answering
every other minute is reported down once.

At half past each hour it reads the newest object under `db/hourly/` in
the backup bucket, through an R2 binding (nothing on the VPS changes), and
writes when it is more than two hours old, when there is none, or when the
bucket cannot be read, and again when a fresh one turns up. That catches
both failures above: a dump that never uploads, and a run that never
starts. It does not see the storage sync that follows the dump.

Each alert is said once, when the state changes. The state lives in one
Durable Object, not KV: KV is eventually consistent, and a run elsewhere
reading a minute-old count would double an alert or miss one.

The decisions are plain functions in `watch.mjs`; `node --test monitor/`
runs their tests.

## Setting it up

Once, in the Cloudflare dashboard:

1. **Email Routing** on joinrift.app (Email → Email Routing). It adds an MX
   and an SPF record to the apex, which has neither.
2. Under its **Destination addresses**, add each address the alerts go to
   and click the link Cloudflare sends. Email Routing sends only to a
   verified one.

Then, from this folder, with wrangler logged in or `CLOUDFLARE_API_TOKEN`
set (Workers, plus R2 read: the deploy checks the bucket exists):

```
wrangler deploy
secret-tool lookup service rift-monitor-webhook | wrangler secret put RIFT_WEBHOOK_URL
printf %s 'one@example.com,two@example.com' | wrangler secret put ALERT_TO
```

The webhook belongs to a private channel on the owner's own server, not
central, which is what lets it be heard with central down. Its URL holds its
secret, so it lives in the keyring and reaches wrangler on stdin.

The first run with both secrets set posts and emails "Central monitor is
on", which is the test that both ways out work. Verified 15 October 2026 for
joinrift.app: the post and both emails arrived, the email in the inbox
rather than spam. Not yet seen live: a real down, up or backup alert.

## Trying it locally

`wrangler dev --test-scheduled`, with the two secrets in `.dev.vars`
(ignored), then `curl 'localhost:8787/__scheduled?cron=*+*+*+*+*'` for a
check of central and `cron=30+*+*+*+*` for the backups. `--var
CENTRAL_URL:http://10.255.255.1` makes central unreachable; the local R2
bucket starts empty. Email is not sent locally; wrangler writes each one to
a file under `.wrangler/` and logs its path.
