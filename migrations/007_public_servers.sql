-- ============================================================
-- Rift central server — 007: the public server directory
-- ============================================================
-- A server created in the app existed nowhere but on its own Supabase project
-- and in the vaults of the people already on it. There was no way to find one
-- you had not been handed an invite to, which made "self-hosted" and "private"
-- the same word — an operator who *wanted* to be found had no way to say so.
--
-- Central is the only place both sides already share, so the directory lives
-- here for the same reason handles do: you cannot join a server you cannot
-- find. It is the same tier and the same tenancy argument — a listing is a few
-- hundred bytes, it is written when an admin changes it rather than per
-- message, and it costs the project nothing to keep.
--
-- What a listing holds is deliberately **plaintext and public**, and that is
-- not a weakening of the trust model: everything else central stores is
-- encrypted because it belongs to the user, whereas a listing is an
-- advertisement. Its whole purpose is to be read by strangers. Publishing is
-- opt-in, per server, and reversible.
--
-- What it does NOT hold: the server's service key, its LiveKit credentials, or
-- anything about its members. Joining goes through the target server's own
-- `register` exactly as an invite link does — central hands out the address,
-- never the authority.

-- ============================================================
-- Listings
-- ============================================================
-- The unique key is (supabase_url, server_id) rather than server_id alone
-- because one Supabase project can host several servers (self-hosted 001), and
-- because a server id is only meaningful next to the host that issued it.

CREATE TABLE IF NOT EXISTS public_servers (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- The account that published it. Deleting the account withdraws the listing,
  -- which is right: nobody else is in a position to keep it accurate.
  owner_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Where the server lives. Not a foreign key to anything — this database has
  -- never heard of that Supabase project and never will.
  supabase_url TEXT        NOT NULL CHECK (supabase_url ~ '^https?://[^ ]+$'
                                           AND length(supabase_url) <= 200),
  server_id    UUID        NOT NULL,

  -- An ordinary invite code on the target server, minted unlimited-use and
  -- permissionless by the admin's client. It is what makes the listing worth
  -- anything, and revoking it there is what makes a listing stop working
  -- without central being involved at all.
  invite_code  TEXT        NOT NULL CHECK (length(invite_code) BETWEEN 4 AND 64),

  name         TEXT        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 64),
  description  TEXT                 CHECK (length(description) <= 300),
  icon_url     TEXT                 CHECK (length(icon_url) <= 500),

  -- Up to five lowercase slugs, which is the whole of the browser's filtering.
  -- A fixed category list would need a migration every time a community turns
  -- out to be about something we didn't think of.
  tags         TEXT[]      NOT NULL DEFAULT '{}'
                           CHECK (cardinality(tags) <= 5
                                  AND array_to_string(tags, ',') ~
                                      '^([a-z0-9-]{2,20}(,[a-z0-9-]{2,20})*)?$'),

  -- Self-reported by the admin's client, because central cannot count members
  -- of a database it has no credentials for. Treat it as what the operator
  -- claimed when they last saved, which is what `updated_at` is shown for.
  member_count INTEGER     NOT NULL DEFAULT 0 CHECK (member_count >= 0),

  -- Delisting keeps the row (and its invite code, and its description) while
  -- taking it out of the browser, so hiding a server for a week is not the
  -- same act as giving up its listing.
  is_listed    BOOLEAN     NOT NULL DEFAULT TRUE,

  UNIQUE (supabase_url, server_id)
);

-- Browsing is "listed, most populous first"; searching adds an ILIKE on top of
-- it. The table is small enough that the tag filter can scan, but a GIN index
-- costs one line and stops that being true only by luck.
CREATE INDEX IF NOT EXISTS idx_public_servers_browse
  ON public_servers (is_listed, member_count DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_public_servers_tags ON public_servers USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_public_servers_owner ON public_servers (owner_id);

-- ============================================================
-- Grants and policies
-- ============================================================
-- Read and withdraw are table calls; everything that *writes* a listing goes
-- through publish_server() below, so there is no INSERT or UPDATE grant here
-- and correspondingly no policy for either.

REVOKE ALL ON public_servers FROM anon, authenticated;
GRANT SELECT, DELETE ON public_servers TO authenticated;

ALTER TABLE public_servers ENABLE ROW LEVEL SECURITY;

-- Listed rows are visible to every signed-in account — that is the point of a
-- directory. Your own are visible whether listed or not, or delisting one
-- would hide it from the person who has to manage it.
DROP POLICY IF EXISTS public_servers_select ON public_servers;
CREATE POLICY public_servers_select ON public_servers FOR SELECT TO authenticated
  USING (is_listed OR owner_id = auth.uid());

DROP POLICY IF EXISTS public_servers_delete_own ON public_servers;
CREATE POLICY public_servers_delete_own ON public_servers FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

-- ============================================================
-- Publishing
-- ============================================================
-- How many servers one account may list. Not a storage bound — a listing is
-- tiny — but a bound on how much of a directory one account can be.

CREATE OR REPLACE FUNCTION max_public_servers() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 10 $$;

-- Create or update your listing for one server, in one statement.
--
-- SECURITY DEFINER rather than INVOKER (which is what claim_handle needed for
-- the same upsert shape) because two of the checks here are over rows the
-- caller cannot see: the per-account cap counts their own rows, but the
-- ownership check has to read a row that may be *delisted and someone else's*,
-- which the select policy hides. Under INVOKER that case would surface as a
-- unique violation on (supabase_url, server_id) — a confusing error for a
-- comprehensible situation. `owner_id` is taken from auth.uid() and never from
-- the caller, so the definer rights widen nothing.
CREATE OR REPLACE FUNCTION publish_server(
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_invite_code  TEXT,
  p_name         TEXT,
  p_description  TEXT    DEFAULT NULL,
  p_icon_url     TEXT    DEFAULT NULL,
  p_tags         TEXT[]  DEFAULT '{}',
  p_member_count INTEGER DEFAULT 0,
  p_is_listed    BOOLEAN DEFAULT TRUE
) RETURNS public_servers
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_owner UUID;
  v_count INTEGER;
  v_row   public_servers;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  -- The listing is owned by an account, and an account here is its directory
  -- row — the same precondition send_dm() has for a sender.
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE supabase_url = p_supabase_url AND server_id = p_server_id;

  IF v_owner IS NOT NULL AND v_owner <> auth.uid() THEN
    RAISE EXCEPTION 'listing_owned_by_another_account';
  END IF;

  IF v_owner IS NULL THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = auth.uid();
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_url, tags,
                              member_count, is_listed)
       VALUES (auth.uid(), p_supabase_url, p_server_id, p_invite_code,
               btrim(p_name), p_description, p_icon_url,
               COALESCE(p_tags, '{}'), GREATEST(COALESCE(p_member_count, 0), 0),
               COALESCE(p_is_listed, TRUE))
  ON CONFLICT (supabase_url, server_id) DO UPDATE
          SET invite_code  = EXCLUDED.invite_code,
              name         = EXCLUDED.name,
              description  = EXCLUDED.description,
              icon_url     = EXCLUDED.icon_url,
              tags         = EXCLUDED.tags,
              member_count = EXCLUDED.member_count,
              is_listed    = EXCLUDED.is_listed,
              updated_at   = now()
    RETURNING * INTO v_row;

  RETURN v_row;
END; $$;

-- ============================================================
-- Function privileges
-- ============================================================

REVOKE ALL ON FUNCTION max_public_servers() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                      TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                         TEXT[], INTEGER, BOOLEAN)
  TO authenticated;

-- Unlike daily_dm_quota(), which the client learns through dm_quota() because
-- what it needs is the *remaining* count, the cap is the whole answer here —
-- an account can see its own listings and subtract. Granting the constant
-- lets the publish dialog say "9 of 10" instead of discovering the limit by
-- being refused.
GRANT EXECUTE ON FUNCTION max_public_servers() TO authenticated;
