#!/usr/bin/env bash
# Run the central tier's tests.
#
# Against a scratch database, never against the hosted project — that one has
# real accounts on it. The scratch database gets a stand-in for the parts of
# Supabase the migrations lean on, and then **all seven files are applied**.
#
# They used to be applied by an explicit list that left out the scheduling and
# the listing proof, because pg_cron only installs in one database and because
# the tests predated 015. That made the suite run against a schema nobody
# deploys — which is how it came to assert that a member may call
# `publish_server`, three migrations after that was revoked.
#
# Two things are checked:
#
#   1. the policy suite, which is what a role may reach through the rules;
#   2. **whether anything is reachable that nobody granted.** Supabase's
#      default privileges grant EXECUTE on every new function in `public` to
#      `anon` and `authenticated`, and `ALTER DEFAULT PRIVILEGES ... REVOKE`
#      does not undo them — revoking from a default that holds no explicit
#      grant is a no-op. So the blanket revoke in 007 only means anything
#      because it runs after every function exists, and this is the check that
#      keeps it that way.
#
# Everything runs in one transaction that ends in ROLLBACK, so it writes
# nothing. A failure raises, which aborts the transaction and exits non-zero.
#
#   ./scripts/db_test.sh
#
# Any Postgres container will do; it defaults to the one the app's local
# development stack runs.
set -euo pipefail

CONTAINER="${RIFT_PG_CONTAINER:-supabase-db}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="rift_central_test"

psql_main() { docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 "$@"; }
psql_scratch() { docker exec -i "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 -d "$SCRATCH" "$@"; }

# Applying the migrations to an empty database means every `DROP ... IF EXISTS`
# announces itself. The tests speak through NOTICE, so silence the migrations
# rather than the tests.
psql_migrate() {
  docker exec -i -e PGOPTIONS='-c client_min_messages=warning' \
    "$CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 -d "$SCRATCH" "$@"
}

echo "── central (scratch database) ──────────────────────────────"
psql_main -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1
psql_main -c "CREATE DATABASE $SCRATCH" >/dev/null
trap 'docker exec -i "$CONTAINER" psql -U postgres -q -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true' EXIT

psql_migrate <<'SQL' >/dev/null
-- The pieces of Supabase the migrations lean on. This has to be a faithful
-- stand-in and not a convenient one: the privilege check at the end is only
-- worth anything if the defaults here are the defaults production has.
CREATE SCHEMA IF NOT EXISTS auth;
-- pg_net is installed here, and the push functions name it in search_path.
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);

-- Exactly Supabase's own: nullif BEFORE the cast, or an empty setting — which
-- is what a RESET leaves behind — raises instead of reading as "nobody".
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID
  LANGUAGE sql STABLE AS $shim$
  SELECT coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid $shim$;

DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role NOLOGIN BYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA public, auth, extensions TO anon, authenticated, service_role;

-- Storage, as far as the bucket policies reach into it: the two tables they
-- name, and `foldername` copied from Supabase's definition. Supabase grants
-- members every privilege on objects and leaves the rest to RLS, so this does.
CREATE SCHEMA IF NOT EXISTS storage;
CREATE TABLE IF NOT EXISTS storage.buckets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, public BOOLEAN, file_size_limit BIGINT
);
CREATE TABLE IF NOT EXISTS storage.objects (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id  TEXT REFERENCES storage.buckets (id),
  name       TEXT,
  owner      UUID,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  metadata   JSONB
);
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
-- Storage's own index, and the collation is the point: `(bucket_id, name
-- COLLATE "C")` is what makes a prefix range on a folder an index scan, and
-- the icon ceiling in 005 is written against it.
CREATE INDEX IF NOT EXISTS idx_objects_bucket_id_name
  ON storage.objects (bucket_id, name COLLATE "C");
CREATE OR REPLACE FUNCTION storage.foldername(name TEXT) RETURNS TEXT[]
  LANGUAGE plpgsql IMMUTABLE AS $f$
DECLARE _parts TEXT[];
BEGIN
  SELECT string_to_array(name, '/') INTO _parts;
  RETURN _parts[1 : array_length(_parts, 1) - 1];
END $f$;
GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role;
GRANT ALL ON storage.objects TO authenticated, service_role;

-- The publication is Supabase's, not the migrations'. Nothing is added to it
-- any more — central broadcasts rather than replicating — but it has to exist.
DO $$ BEGIN CREATE PUBLICATION supabase_realtime;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- pg_cron only installs in the database named by `cron.database_name`, so the
-- schema is shimmed and the CREATE EXTENSION line is stripped below. It
-- records what was scheduled, which is enough to assert a job exists.
CREATE SCHEMA IF NOT EXISTS cron;
CREATE TABLE IF NOT EXISTS cron.job (
  jobid BIGSERIAL PRIMARY KEY, jobname TEXT UNIQUE, schedule TEXT, command TEXT
);
CREATE OR REPLACE FUNCTION cron.schedule(p_name TEXT, p_schedule TEXT, p_command TEXT)
  RETURNS BIGINT LANGUAGE sql AS $shim$
  INSERT INTO cron.job (jobname, schedule, command) VALUES (p_name, p_schedule, p_command)
  ON CONFLICT (jobname) DO UPDATE SET schedule = EXCLUDED.schedule, command = EXCLUDED.command
  RETURNING jobid $shim$;
CREATE OR REPLACE FUNCTION cron.unschedule(p_name TEXT)
  RETURNS BOOLEAN LANGUAGE sql AS $shim$
  DELETE FROM cron.job WHERE jobname = p_name RETURNING true $shim$;

-- Supabase's own default privileges, which are the environment these
-- migrations actually run in.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL     ON TABLES    TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL     ON SEQUENCES TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO postgres, anon, authenticated, service_role;
SQL

for f in "$ROOT"/migrations/[0-9][0-9][0-9]_*.sql; do
  # The extension warnings are pgcrypto's and pg_net's own functions, which
  # live in `extensions` on a real Supabase and in `public` here.
  sed 's/^CREATE EXTENSION IF NOT EXISTS pg_cron;/-- pg_cron: shimmed above/' "$f" \
    | psql_migrate -f - 2>&1 >/dev/null \
    | grep -v 'no privileges could be revoked' >&2 || true
  echo "   ok  $(basename "$f")"
done

echo
psql_scratch -f - < "$ROOT/migrations/tests/policies_test.sql" 2>&1 |
  sed 's/psql:<stdin>:[0-9]*: //'

echo
echo "── nothing is reachable that was not granted by name ────────"
psql_scratch <<'SQL' 2>&1 | sed 's/psql:<stdin>:[0-9]*: //'
SET client_min_messages = notice;
DO $$
DECLARE v_leaked TEXT;
BEGIN
  -- `is_handle_available` is the one thing anon is meant to reach: choosing a
  -- handle happens before there is an account to sign in with.
  SELECT string_agg(p.proname, ', ' ORDER BY p.proname) INTO v_leaked
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.prorettype <> 'trigger'::regtype
     AND p.proname <> 'is_handle_available'
     AND has_function_privilege('anon', p.oid, 'EXECUTE')
     AND NOT EXISTS (SELECT 1 FROM pg_depend d
                      WHERE d.objid = p.oid AND d.deptype = 'e');
  IF v_leaked IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL: anon can call %', v_leaked;
  END IF;
  RAISE NOTICE 'ok  anon can call nothing but is_handle_available';

  SELECT string_agg(c.relname || ' ' || pr.p, ', ' ORDER BY c.relname)
    INTO v_leaked
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) pr(p)
   WHERE c.relkind IN ('r','v') AND n.nspname = 'public'
     AND has_table_privilege('anon', c.oid, pr.p);
  IF v_leaked IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL: anon can reach %', v_leaked;
  END IF;
  RAISE NOTICE 'ok  anon can read and write no table';

  -- The heads table is the DM list's index. `dm_conversations` reads it as
  -- definer; a member reading it directly would be reading a list of who
  -- everybody talks to.
  IF has_table_privilege('authenticated', 'dm_conversation_heads', 'SELECT') THEN
    RAISE EXCEPTION 'FAIL: authenticated can read dm_conversation_heads';
  END IF;
  RAISE NOTICE 'ok  the conversation heads are read only through the RPC';
END $$;
SQL
echo
echo "   central: passed"
