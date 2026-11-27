-- ============================================================
-- Rift central — 025: one Google access token for every push worker
-- ============================================================
-- Item 15 of the Nov 27 review. To ring a phone, `push_send` trades a token
-- it signs with Rift's FCM key for a Google access token that lasts an hour,
-- and kept it in the worker's memory, meaning one exchange an hour. But the
-- functions' router retires a worker a minute after it starts, so a quiet
-- relay signed and exchanged a new one before almost every ring: an RSA
-- signature and a round trip to Google that the ring waited on.
--
-- The token now lives here, where the next worker finds it. Two functions
-- reach it, for the service role alone.
--
-- Not in `public`: PostgREST publishes that schema, and its tables are in
-- every backup. This one is neither, so the token is reachable only through
-- the two functions, and never written to R2. It is worth less than the key
-- that mints it (which every push worker already holds) and is dead within
-- the hour, but there is no reason for it to be anywhere else.
-- ============================================================

CREATE SCHEMA IF NOT EXISTS push_private;
REVOKE ALL ON SCHEMA push_private FROM PUBLIC, anon, authenticated, service_role;

CREATE TABLE IF NOT EXISTS push_private.access_token (
  id         BOOLEAN     PRIMARY KEY DEFAULT true CHECK (id),
  value      TEXT        NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
REVOKE ALL ON push_private.access_token FROM PUBLIC, anon, authenticated, service_role;

-- The token and when it expires (in seconds since 1970, as Google gives it),
-- while it has more than a minute left; null otherwise, and the worker mints
-- one. A minute, so a ring never goes out with a token that expires on the
-- way to Google.
CREATE OR REPLACE FUNCTION push_access_token() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT pg_catalog.jsonb_build_object(
           'value', value,
           'expires_at', pg_catalog.floor(pg_catalog.date_part('epoch', expires_at)))
    FROM push_private.access_token
   WHERE expires_at > pg_catalog.now() + interval '1 minute'
$$;

-- Keep a token just minted. Two workers minting in the same moment both
-- write; the one that lasts longer stays, so a slow writer never puts back
-- an older token over a newer one.
CREATE OR REPLACE FUNCTION keep_push_access_token(p_value TEXT, p_expires_at TIMESTAMPTZ)
  RETURNS VOID
  LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO push_private.access_token (value, expires_at)
  VALUES (p_value, p_expires_at)
  ON CONFLICT (id) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
   WHERE push_private.access_token.expires_at < EXCLUDED.expires_at
$$;

REVOKE ALL ON FUNCTION push_access_token()                           FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION keep_push_access_token(TEXT, TIMESTAMPTZ)     FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION push_access_token()                        TO service_role;
GRANT EXECUTE ON FUNCTION keep_push_access_token(TEXT, TIMESTAMPTZ)  TO service_role;
