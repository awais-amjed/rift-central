-- ============================================================
-- Rift central server — 015: a listing must be asked for by an admin
-- ============================================================
-- `publish_server` checked three things: that the caller was signed in, that
-- they had a profile, and that they were not colliding with somebody else's
-- listing. It did not check — and could not — that they administer the server
-- they were listing.
--
-- Central has never heard of a self-hosted database and shares no identity
-- with it: a member signs in there with a key derived on their device, and
-- here with a Rift account, and nothing links the two. So any signed-in
-- account holding a server's URL, id and an invite code could list it. Every
-- *member* of a server holds all three.
--
-- Three things that bought an attacker, in order of how bad they are:
--
--   1. A private server published to the directory with a working join link.
--   2. The listing squatted — (supabase_url, server_id) is unique, so the
--      first claimant holds the only slot and the real admin is refused with
--      `listing_owned_by_another_account` forever.
--   3. A description and tags of the squatter's choosing, under the server's
--      name.
--
-- 010_push_relays.sql met the same wall and answered it differently: it
-- dropped the uniqueness, so squatting a *credential* is harmless. That works
-- there because a relay credential is useless without its secret. A listing is
-- not — it is public, and being the only one is the point.
--
-- The fix is that central asks the server. An admin gets a one-time token from
-- their own server (self-hosted migration 042), central redeems it against
-- that server's domain, and only then writes the row. It binds a listing to
-- domain control, which is the one thing central can actually verify.
--
-- The check runs in the `publish_server` edge function, because it needs an
-- HTTP call. What this migration does is make that function the *only* way in.

-- ---------- who may publish ----------
-- Taken away from `authenticated` and given to the service role. The RPC is
-- unchanged otherwise: it still owns the cap, the ownership rule and the
-- upsert. It simply can no longer be called by the person it is deciding
-- about.

REVOKE EXECUTE ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                          TEXT[], INTEGER, BOOLEAN)
  FROM authenticated;

COMMENT ON FUNCTION publish_server(TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                   TEXT[], INTEGER, BOOLEAN) IS
  'Create or update a listing. Service role only: the edge function of the '
  'same name is the entry point, because it first proves — by redeeming a '
  'one-time token against the server''s own domain — that an admin of that '
  'server asked for this. auth.uid() is still the owner, and is still taken '
  'from the session rather than from an argument.';

-- ---------- who the listing belongs to ----------
-- `publish_server` reads `auth.uid()`, and under the service role there is no
-- session to read it from. The owner therefore has to be passed in, which
-- means this is the one argument the edge function must never take from its
-- caller — it takes it from the verified JWT instead.

CREATE OR REPLACE FUNCTION publish_server_as(
  p_owner        UUID,
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
  IF p_owner IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_owner) THEN
    RAISE EXCEPTION 'owner_has_no_profile';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE supabase_url = p_supabase_url AND server_id = p_server_id;

  -- Still refused, but it means something different now. Reaching this line
  -- takes a token from the server, so both accounts are administrators of it
  -- — a co-admin taking over a colleague's listing rather than a stranger
  -- taking one hostage.
  IF v_owner IS NOT NULL AND v_owner <> p_owner THEN
    RAISE EXCEPTION 'listing_owned_by_another_account';
  END IF;

  IF v_owner IS NULL THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = p_owner;
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_url, tags,
                              member_count, is_listed)
       VALUES (p_owner, p_supabase_url, p_server_id, p_invite_code,
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

COMMENT ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                      TEXT[], INTEGER, BOOLEAN) IS
  'publish_server with the owner passed in rather than read from a session, '
  'for the edge function that has already verified both the caller''s JWT and '
  'their administration of the server. Service role only.';

REVOKE ALL ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT, TEXT,
                                         TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;

-- ---------- https only ----------
-- The URL is now something central makes a request to, so what may be written
-- there is a security question rather than a formatting one. `http://` to a
-- link-local address is the cloud-metadata attack in one line; `https://` to a
-- private address is refused in the edge function, after resolution, where a
-- DNS answer can be checked.
--
-- NOT VALID, which is doing real work rather than being cautious. Adding a
-- plain CHECK validates every row already in the table, and development left
-- listings pointing at `http://localhost:8000` — so the migration would refuse
-- to apply and take the whole security fix down with it. NOT VALID applies the
-- rule to every insert and update from here on and leaves the existing rows
-- where they are. They are already unpublishable: the edge function refuses a
-- non-https URL before it asks anybody anything, so such a listing can only be
-- updated by first correcting its address.

ALTER TABLE public_servers DROP CONSTRAINT IF EXISTS public_servers_supabase_url_check;
ALTER TABLE public_servers ADD CONSTRAINT public_servers_supabase_url_check
  CHECK (supabase_url ~ '^https://[^ ]+$' AND length(supabase_url) <= 200)
  NOT VALID;
