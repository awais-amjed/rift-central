# The edge runtime's router

`main/index.ts` is Supabase's own router for a self-hosted edge runtime,
copied unmodified from [supabase/supabase](https://github.com/supabase/supabase)
(`docker/volumes/functions/main`) by way of `rift-self-host`, Apache-2.0 — its
licence text is `../volumes/db/LICENSE-APACHE-2.0`. It starts one worker per
request for the function named in the path.

Central's three functions are mounted beside it one by one in
`../docker-compose.yml`, so the runtime serves those and nothing else.

It runs with `VERIFY_JWT` off, as rift-self-host's does. On the managed project
`publish_server` kept the platform's JWT check, but that check was never the one
that mattered: the function reads the caller's token and asks Auth who it is
(`getUser`) before doing anything. The other two are called by the database
with a shared secret and no JWT at all.
