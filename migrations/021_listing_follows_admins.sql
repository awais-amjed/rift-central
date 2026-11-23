-- ============================================================
-- Rift central — 021: a server's listing follows its admins
-- ============================================================
-- From the Nov 23 review of the directory. A listing belonged to the account
-- that published it first, for good: `publish_server_as` refused anybody else
-- with `listing_owned_by_another_account`. That rule predates the listing
-- proof. Before it, central could not tell an admin from any member, so the
-- first claim was the only one it could honour.
--
-- Since 013 every publish is behind a one-time token the server itself hands
-- only to its admins, redeemed by the `publish_server` edge function against
-- the server's own domain. So a publish that reaches this function was asked
-- for by an admin of that server, now. Refusing them left a server whose
-- first publisher was demoted, banned or simply gone with a listing nobody
-- who runs it could edit, delist or take down.
--
-- Now a verified publish by another account takes the listing over: the row
-- keeps its id, likes, reports and any moderator's hide, and changes owner.
-- The taker needs a free slot under the cap like any new listing, and a
-- publisher barred from the directory is still refused. The old
-- `publish_server` (no proof, service role only since 013) keeps the old
-- rule.
--
-- An icon lives in its publisher's own folder (016, `refuse_foreign_icon`),
-- checked only when the path changes. A takeover that kept the old owner's
-- path would leave the picture in a folder the listing's new owner does not
-- control, so the check now runs when the owner changes too.
-- ============================================================

CREATE OR REPLACE FUNCTION publish_server_as(
  p_owner        UUID,
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_invite_code  TEXT,
  p_name         TEXT,
  p_description  TEXT    DEFAULT NULL,
  p_icon_path    TEXT    DEFAULT NULL,
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
  IF EXISTS (SELECT 1 FROM directory_bans WHERE user_id = p_owner) THEN
    RAISE EXCEPTION 'publisher_banned';
  END IF;

  SELECT owner_id INTO v_owner FROM public_servers
   WHERE server_url_key(supabase_url) = server_url_key(p_supabase_url)
     AND server_id = p_server_id;

  -- A new listing, or one taken over: either way it is a new one to count.
  IF v_owner IS DISTINCT FROM p_owner THEN
    SELECT count(*) INTO v_count FROM public_servers WHERE owner_id = p_owner;
    IF v_count >= max_public_servers() THEN
      RAISE EXCEPTION 'listing_cap_reached';
    END IF;
  END IF;

  INSERT INTO public_servers (owner_id, supabase_url, server_id, invite_code,
                              name, description, icon_path, tags,
                              member_count, is_listed)
       VALUES (p_owner, p_supabase_url, p_server_id, p_invite_code,
               btrim(p_name), p_description, p_icon_path,
               COALESCE(p_tags, '{}'), GREATEST(COALESCE(p_member_count, 0), 0),
               COALESCE(p_is_listed, TRUE))
  ON CONFLICT (server_url_key(supabase_url), server_id) DO UPDATE
          SET owner_id     = EXCLUDED.owner_id,
              supabase_url = EXCLUDED.supabase_url,
              invite_code  = EXCLUDED.invite_code,
              name         = EXCLUDED.name,
              description  = EXCLUDED.description,
              icon_path    = EXCLUDED.icon_path,
              tags         = EXCLUDED.tags,
              member_count = EXCLUDED.member_count,
              is_listed    = EXCLUDED.is_listed,
              updated_at   = now()
    RETURNING * INTO v_row;

  RETURN v_row;
END; $$;

-- CREATE OR REPLACE keeps the grants, said again so this file stands alone:
-- the service role only, which is to say the edge function.
REVOKE ALL ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT,
                                         TEXT, TEXT[], INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION publish_server_as(UUID, TEXT, UUID, TEXT, TEXT, TEXT,
                                            TEXT, TEXT[], INTEGER, BOOLEAN)
  TO service_role;

CREATE OR REPLACE FUNCTION refuse_foreign_icon() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NEW.icon_path IS NOT NULL
     AND (TG_OP = 'INSERT'
          OR NEW.icon_path IS DISTINCT FROM OLD.icon_path
          OR NEW.owner_id IS DISTINCT FROM OLD.owner_id)
     AND split_part(NEW.icon_path, '/', 1) <> NEW.owner_id::text THEN
    RAISE EXCEPTION 'icon_not_yours';
  END IF;
  RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION refuse_foreign_icon() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS public_servers_own_icon ON public_servers;
CREATE TRIGGER public_servers_own_icon
  BEFORE INSERT OR UPDATE OF icon_path, owner_id ON public_servers
  FOR EACH ROW EXECUTE FUNCTION refuse_foreign_icon();
