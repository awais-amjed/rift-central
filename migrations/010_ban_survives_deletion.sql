-- ============================================================
-- Rift central — 010: a directory ban outlives the account
-- ============================================================
-- A directory ban (`directory_bans`) belongs to an account, and an account
-- can now be deleted by the person who holds it (the `delete_account`
-- function). Every row cascades from the Auth user, the ban and the hidden
-- listings with it, so a banned publisher could delete the account, sign up
-- again with the same address, and list the same server: re-listing needs
-- only a token from that server's own admin, which they still are.
--
-- So deleting a banned account leaves two marks behind
-- (`directory_ban_marks`):
--
--   * the account's email, as a SHA-256 of the address lowercased. Not the
--     address: nothing here needs to read it back, only to recognise it. A
--     new account signing up with it is banned again the moment its profile
--     row is made, with the original reason, and the mark is used up, so the
--     ban is back on an account and lifted the usual way;
--   * each server the account had listed, by (supabase_url, server_id), the
--     pair a listing reserves. A listing for one is refused
--     (`server_banned`) whoever publishes it, until a moderator lifts the
--     mark (`moderation_lift_ban_mark`).
--
-- Bots leave no mark: a bot listing reserves nothing (it names no database),
-- so there is nothing to re-list that a new bot could not be anyway, and the
-- email mark already bans the person behind it.
--
-- An address mark is defeated by a different address, as a ban always was by
-- a second account. What this closes is the one door deleting opened: the
-- same person, the same address, the same server, a clean slate.
-- ============================================================

CREATE TABLE IF NOT EXISTS directory_ban_marks (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind         TEXT        NOT NULL CHECK (kind IN ('email', 'server')),
  -- For 'email': hex SHA-256 of lower(btrim(address)).
  email_sha256 TEXT        CHECK (email_sha256 ~ '^[0-9a-f]{64}$'),
  -- For 'server': the pair a listing reserves.
  supabase_url TEXT,
  server_id    UUID,
  reason       TEXT        CHECK (length(reason) <= 300),
  banned_by    UUID        REFERENCES central_admins(user_id) ON DELETE SET NULL,
  CHECK ((kind = 'email')  = (email_sha256 IS NOT NULL)),
  CHECK ((kind = 'server') = (supabase_url IS NOT NULL AND server_id IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_directory_ban_marks_email
  ON directory_ban_marks (email_sha256) WHERE kind = 'email';
CREATE UNIQUE INDEX IF NOT EXISTS uq_directory_ban_marks_server
  ON directory_ban_marks (supabase_url, server_id) WHERE kind = 'server';

-- Nobody reads it but the functions below: no policy, and no grant.
ALTER TABLE directory_ban_marks ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON directory_ban_marks FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION ban_mark_email_hash(p_email TEXT) RETURNS TEXT
  LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(lower(btrim(p_email)), 'UTF8')), 'hex')
$$;

-- ---------- leaving the marks ----------
-- On the Auth user, before the cascade takes the ban and the listings it has
-- to read. Whichever way the account goes — `delete_account`, a dashboard, a
-- script — goes through here.
CREATE OR REPLACE FUNCTION mark_deleted_ban() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_ban directory_bans%ROWTYPE;
BEGIN
  SELECT * INTO v_ban FROM directory_bans WHERE user_id = OLD.id;
  IF NOT FOUND THEN
    RETURN OLD;
  END IF;

  IF NULLIF(btrim(OLD.email), '') IS NOT NULL THEN
    INSERT INTO directory_ban_marks (kind, email_sha256, reason, banned_by)
    VALUES ('email', ban_mark_email_hash(OLD.email), v_ban.reason, v_ban.banned_by)
    ON CONFLICT (email_sha256) WHERE kind = 'email' DO NOTHING;
  END IF;

  INSERT INTO directory_ban_marks (kind, supabase_url, server_id, reason, banned_by)
  SELECT 'server', p.supabase_url, p.server_id, v_ban.reason, v_ban.banned_by
    FROM public_servers p
   WHERE p.owner_id = OLD.id
  ON CONFLICT (supabase_url, server_id) WHERE kind = 'server' DO NOTHING;

  RETURN OLD;
END; $$;

DROP TRIGGER IF EXISTS users_mark_deleted_ban ON auth.users;
CREATE TRIGGER users_mark_deleted_ban BEFORE DELETE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION mark_deleted_ban();

-- ---------- the same address again ----------
-- When the profile row is made, not at sign-up: an address that never claims
-- a handle never publishes either, and this way the ban lands on the row the
-- directory checks.
CREATE OR REPLACE FUNCTION reapply_marked_ban() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_email TEXT;
  v_mark  directory_ban_marks%ROWTYPE;
BEGIN
  SELECT email INTO v_email FROM auth.users WHERE id = NEW.id;
  IF NULLIF(btrim(v_email), '') IS NULL THEN
    RETURN NULL;
  END IF;

  DELETE FROM directory_ban_marks
   WHERE kind = 'email' AND email_sha256 = ban_mark_email_hash(v_email)
  RETURNING * INTO v_mark;
  IF FOUND THEN
    INSERT INTO directory_bans (user_id, banned_by, reason)
    VALUES (NEW.id, v_mark.banned_by, v_mark.reason)
    ON CONFLICT (user_id) DO NOTHING;
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS users_reapply_marked_ban ON users;
CREATE TRIGGER users_reapply_marked_ban AFTER INSERT ON users
  FOR EACH ROW EXECUTE FUNCTION reapply_marked_ban();

-- ---------- the same server again ----------
-- On the table rather than in `publish_server_as`, so no path that writes a
-- listing can skip it. Only an insert: a marked server has no row to update,
-- since the cascade that made the mark took it.
CREATE OR REPLACE FUNCTION refuse_marked_server() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM directory_ban_marks
              WHERE kind = 'server'
                AND supabase_url = NEW.supabase_url
                AND server_id = NEW.server_id) THEN
    RAISE EXCEPTION 'server_banned';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS public_servers_refuse_marked ON public_servers;
CREATE TRIGGER public_servers_refuse_marked BEFORE INSERT ON public_servers
  FOR EACH ROW EXECUTE FUNCTION refuse_marked_server();

-- ---------- moderators ----------
-- What is left of deleted bans, newest first. An email mark shows no address,
-- because there is none to show.
CREATE OR REPLACE FUNCTION moderation_ban_marks() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_out JSONB;
BEGIN
  PERFORM assert_central_admin();
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', k.id, 'kind', k.kind, 'created_at', k.created_at,
           'supabase_url', k.supabase_url, 'server_id', k.server_id,
           'reason', k.reason, 'banned_by', m.name)
           ORDER BY k.created_at DESC), '[]'::jsonb)
    INTO v_out
    FROM directory_ban_marks k
    LEFT JOIN central_admins m ON m.user_id = k.banned_by;
  RETURN v_out;
END; $$;

CREATE OR REPLACE FUNCTION moderation_lift_ban_mark(p_id UUID) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM assert_central_admin();
  DELETE FROM directory_ban_marks WHERE id = p_id;
END; $$;

-- 007's blanket revoke ran before these existed.
REVOKE ALL ON FUNCTION ban_mark_email_hash(TEXT)           FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION mark_deleted_ban()               FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION reapply_marked_ban()             FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION refuse_marked_server()           FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_ban_marks()           FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_lift_ban_mark(UUID)   FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION moderation_ban_marks()         TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_lift_ban_mark(UUID) TO authenticated;
