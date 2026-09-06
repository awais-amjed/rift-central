# The push relay

One endpoint. It takes "wake these devices" and turns it into FCM sends.

It exists because an FCM registration token is scoped to the Firebase project
the *app* was built against — Rift's — so a self-hosted server cannot wake its
own members' phones and has to ask central to. What central learns by doing
that is a device token and a moment: not the sender, not the text, not the
server or channel. The payload is empty either way.

## The one rule

**The relay is addressed by a hostname Rift owns, never a vendor URL.**

`SupabaseConfig.pushRelayEndpoint` is compiled into the app and written into
every self-hosted server's `push_config` when its admin turns notifications on.
If that address named a particular vendor, moving hosts would cost every
operator a re-enable — and the ones who didn't notice would silently stop
waking anyone. Behind a name we own, the relay can move as often as it likes.

Currently `https://push.joinrift.app`, live since 24 Aug 2026: a Cloudflare
custom domain bound to `rift-push-relay`, forwarding to the Supabase edge
function. The client checks the relay answers `GET` with `200` before writing
the address into a server, so a record that has been moved or not yet made is a
sentence on screen rather than months of undelivered pings.

## The code

`functions/push_send/relay.ts` is the whole
relay, and it has **no imports** — `fetch`, `crypto.subtle`, `btoa` and
`Response` exist in Deno, Node 18+ and Workers alike. Database access is plain
PostgREST rather than the Supabase client, for the same reason: one less
dependency to bundle and patch wherever this lands.

Every host is then a few lines of adapter:

| Host | Entry point | Notes |
|---|---|---|
| Supabase Edge Functions | `push_send/index.ts` | Where it runs today. Free tier ≈ 500k invocations/month |
| Node — VPS, Fly.io, Render | `relay/server.mjs` | Node strips the TypeScript; no build step |
| Cloudflare Workers | `relay/worker.js` | Also runs as a pass-through forwarder — see below |

All four read the same configuration: `SUPABASE_URL`,
`SUPABASE_SERVICE_ROLE_KEY`, `PUSH_SECRET`, `FCM_SERVICE_ACCOUNT`.

### Running it on Node

```
FCM_SERVICE_ACCOUNT="$(cat rift-service-key.json)" \
SUPABASE_URL=https://<ref>.supabase.co \
SUPABASE_SERVICE_ROLE_KEY=... \
PUSH_SECRET=... \
node relay/server.mjs
```

Add `"type": "module"` to the deployment's `package.json` to silence Node's
module-detection warning.

### Moving the relay

Edit `RELAY_BACKEND` in `relay/wrangler.toml` and `wrangler deploy`. That is
the whole procedure — no operator is involved, and no `push_config` row
changes. Removing the variable entirely makes the Worker *be* the relay rather
than forward to one; read the ceiling below before doing that.

### Giving the name a meaning

`push.joinrift.app` has to point at whatever is running the relay. A DNS record
does it when the relay is a host of its own. It cannot when the relay is a
Supabase edge function, because the function lives at a *path* and DNS only
knows hosts — so deploy `relay/worker.js` with `RELAY_BACKEND` set to the
function's URL and it passes requests through. Changing hosts is then editing
one binding.

## Before choosing Cloudflare Workers

Measured, not assumed. A Worker invocation may hold **six connections waiting
for response headers — on every plan, free and paid alike.** The relay makes
one HTTP call per device (FCM removed batch sending in June 2024; there is no
v1 equivalent), so a single invocation tops out around **20 devices/second**.

| Devices | One Worker invocation | One ordinary machine |
|---|---|---|
| 50 | 2.2s | 0.9s |
| 200 | ~8.7s | 1.0s |
| 400 | — | ~2s |

The free plan also caps a single invocation at **50 subrequests**; beyond that
it fails outright rather than slowing down. Paid raises that to 10,000, but
six connections is six connections, so the extra headroom is mostly theatre.

Splitting the fan-out across invocations *does* work — each gets its own six —
and 8 parallel invocations moved 400 devices in 2.8s. But that means chunking
at the caller. A Node process has no such ceiling and needs no chunking, which
is why the Worker is offered as a forwarder first and a relay second.
