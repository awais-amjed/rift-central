#!/usr/bin/env bash
# Run the central tier's policy tests.
#
# Against a scratch database, never against the hosted project — that one has
# real accounts on it. The scratch database gets a small `auth` shim (a users
# table and `auth.uid()` reading the JWT claim, which is what Supabase's own
# definition does) so the migrations apply unchanged.
#
# The suite ends in ROLLBACK, so it writes nothing. A failure raises, which
# aborts the transaction and exits non-zero.
#
# Only the migrations that define reachable surface are applied. 004 and 018
# (scheduling, which pg_cron only allows in one database), 006 (a drop), 008
# (realtime) and 015 are not what these tests are about, so the list is
# explicit rather than a glob.
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
psql_main -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null
psql_main -c "CREATE DATABASE $SCRATCH" >/dev/null
trap 'docker exec -i "$CONTAINER" psql -U postgres -q -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true' EXIT

psql_migrate <<'SQL' >/dev/null
-- The pieces of Supabase the migrations lean on. `auth.uid()` is copied from
-- Supabase's definition: policies are only as correct as this is.
CREATE SCHEMA IF NOT EXISTS auth;
-- 009 installs pg_net here, and 010-012 name it in their search_path.
CREATE SCHEMA IF NOT EXISTS extensions;
CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID
  LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid
$$;
DO $$ BEGIN CREATE ROLE anon NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE authenticated NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE ROLE service_role NOLOGIN BYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
GRANT USAGE ON SCHEMA public, auth, extensions TO anon, authenticated, service_role;
-- Storage, as far as 005 and 017 reach into it: the two tables their policies
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
CREATE OR REPLACE FUNCTION storage.foldername(name TEXT) RETURNS TEXT[]
  LANGUAGE plpgsql IMMUTABLE AS $f$
DECLARE _parts TEXT[];
BEGIN
  SELECT string_to_array(name, '/') INTO _parts;
  RETURN _parts[1 : array_length(_parts, 1) - 1];
END $f$;
GRANT USAGE ON SCHEMA storage TO anon, authenticated, service_role;
GRANT ALL ON storage.objects TO authenticated, service_role;
-- 011 publishes a table to Realtime. The publication is Supabase's, not the
-- migrations', so the shim provides an empty one to add to.
DO $$ BEGIN CREATE PUBLICATION supabase_realtime;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
SQL

for f in 001_schema 002_security 003_api 005_storage 007_public_servers 009_push 010_push_relays 011_notifications 012_friends 013_dm_conversations 014_friend_paging 016_handle_at_signup 017_attachment_cleanup; do
  psql_migrate -f - < "$ROOT/migrations/$f.sql" >/dev/null
done

psql_scratch -f - < "$ROOT/migrations/tests/policies_test.sql" 2>&1 |
  sed 's/psql:<stdin>:[0-9]*: //'
echo "   central: passed"
