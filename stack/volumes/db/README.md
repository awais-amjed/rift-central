# Postgres init scripts

Copied unmodified from [supabase/supabase](https://github.com/supabase/supabase)
(`docker/volumes/db/`) by way of `rift-self-host`, Apache-2.0 — they keep that
licence rather than the repository's AGPL, and its text is in
`LICENSE-APACHE-2.0` beside them. They run once, when the database volume is
first created, and set the passwords and settings the Supabase services log in
with before any migration runs.

`webhooks.sql` is here although central has no database webhooks: it creates
the `supabase_functions_admin` role that `roles.sql` sets a password for, and
without it `roles.sql` stops at that line and no service can log in. Upstream's
`logs.sql`, `pooler.sql` and `_supabase.sql` are left out, since this stack
runs neither analytics nor Supavisor.
