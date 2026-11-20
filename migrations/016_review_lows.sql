-- ============================================================
-- Rift central — 016: the review's smaller holes
-- ============================================================
-- From the Nov 18 review's Low findings, each closed where it opened:
--
--   7   A moderator's hide went with the account: deleting it took the hidden
--       listing, and the same server published from a new account came back
--       shown. Deleting now leaves a `hidden` mark, like a ban's (010), and
--       the next listing of that server lands hidden with the same reason.
--   8   `friend_request` by id told an account it was blocked. Being blocked
--       now answers `no_such_user`, as the by-handle path always has.
--   11  `block_user` took any id, and the blocked list then gave back the
--       handle and both public keys of a stranger. Blocking now needs the
--       relationship the client can already see (`knows_user`); anything
--       else answers as an id with no profile.
--   12  A listing's `icon_path` was taken as given, so one could name another
--       account's icon: pinning it against the sweep and spending that
--       owner's twelve. An icon must now sit in the publisher's own folder.
--   18  A blocked sender could still rewrite old messages, and each edit rang
--       the blocker. Editing a DM now needs the two to be friends, as
--       sending one does.
--   19  A phone that changed hands kept ringing for its old account: the new
--       owner's upsert of the same token hit the old row's policy. The row
--       now moves to whoever registers the token, which is the account
--       signed in on that phone.
--   20  A like could be added to a bot nobody may see, and its success
--       said the bot existed. A like now needs a bot the caller can read.
-- ============================================================

-- ============================================================
-- 7. A hide outlives the account
-- ============================================================

ALTER TABLE directory_ban_marks DROP CONSTRAINT IF EXISTS directory_ban_marks_kind_check;
ALTER TABLE directory_ban_marks ADD CONSTRAINT directory_ban_marks_kind_check
  CHECK (kind IN ('email', 'server', 'hidden'));
-- A `hidden` mark names a server the way a `server` mark does.
ALTER TABLE directory_ban_marks DROP CONSTRAINT IF EXISTS directory_ban_marks_check1;
ALTER TABLE directory_ban_marks ADD CONSTRAINT directory_ban_marks_check1
  CHECK ((kind IN ('server', 'hidden')) = (supabase_url IS NOT NULL AND server_id IS NOT NULL));

CREATE INDEX IF NOT EXISTS directory_ban_marks_hidden_key
  ON directory_ban_marks (server_url_key(supabase_url), server_id)
  WHERE kind = 'hidden';

-- On the Auth user, like `mark_deleted_ban`, and for the listings a ban did
-- not already mark: a banned account's servers are refused outright, which
-- is more than hidden.
CREATE OR REPLACE FUNCTION mark_deleted_hides() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO directory_ban_marks (kind, supabase_url, server_id, reason)
  SELECT 'hidden', p.supabase_url, p.server_id, p.hidden_reason
    FROM public_servers p
   WHERE p.owner_id = OLD.id
     AND p.hidden_at IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM directory_bans b WHERE b.user_id = OLD.id)
     AND NOT EXISTS (SELECT 1 FROM directory_ban_marks k
                      WHERE k.kind = 'hidden'
                        AND server_url_key(k.supabase_url) = server_url_key(p.supabase_url)
                        AND k.server_id = p.server_id);
  RETURN OLD;
END; $$;

DROP TRIGGER IF EXISTS users_mark_deleted_hides ON auth.users;
CREATE TRIGGER users_mark_deleted_hides BEFORE DELETE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION mark_deleted_hides();

-- The next listing of a marked server is hidden as it is made, and the mark
-- is used up: the hide is back on a row, where a moderator lifts it the
-- usual way.
CREATE OR REPLACE FUNCTION rehide_marked_server() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_mark directory_ban_marks%ROWTYPE;
BEGIN
  DELETE FROM directory_ban_marks
   WHERE id = (SELECT k.id FROM directory_ban_marks k
                WHERE k.kind = 'hidden'
                  AND server_url_key(k.supabase_url) = server_url_key(NEW.supabase_url)
                  AND k.server_id = NEW.server_id
                LIMIT 1)
  RETURNING * INTO v_mark;
  IF FOUND THEN
    NEW.hidden_at     := now();
    NEW.hidden_reason := v_mark.reason;
    NEW.icon_path     := NULL;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS public_servers_rehide_marked ON public_servers;
CREATE TRIGGER public_servers_rehide_marked BEFORE INSERT ON public_servers
  FOR EACH ROW EXECUTE FUNCTION rehide_marked_server();

-- ============================================================
-- 8. Being blocked looks like nobody
-- ============================================================

CREATE OR REPLACE FUNCTION friend_request(p_user UUID) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me  UUID := auth.uid();
  v_low UUID;
  v_high UUID;
  v_row friendships%ROWTYPE;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  IF p_user = v_me THEN RAISE EXCEPTION 'cannot_friend_self'; END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = v_me) THEN
    RAISE EXCEPTION 'sender_has_no_profile';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;
  -- Theirs first, and in the same words the by-handle path uses, so the
  -- answer does not say who decided.
  IF EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = p_user AND b.blocked_id = v_me) THEN
    RAISE EXCEPTION 'no_such_user';
  END IF;
  IF EXISTS (SELECT 1 FROM blocks b WHERE b.blocker_id = v_me AND b.blocked_id = p_user) THEN
    RAISE EXCEPTION 'blocked';
  END IF;

  v_low  := LEAST(v_me, p_user);
  v_high := GREATEST(v_me, p_user);

  SELECT * INTO v_row FROM friendships f
   WHERE f.low_id = v_low AND f.high_id = v_high FOR UPDATE;

  IF NOT FOUND THEN
    INSERT INTO friendships (low_id, high_id, requester_id, status)
         VALUES (v_low, v_high, v_me, 'pending')
    ON CONFLICT (low_id, high_id) DO NOTHING;
    RETURN 'outgoing';
  END IF;

  IF v_row.status = 'accepted' THEN RETURN 'friends'; END IF;
  IF v_row.requester_id = v_me THEN RETURN 'outgoing'; END IF;

  UPDATE friendships SET status = 'accepted', updated_at = now()
   WHERE low_id = v_low AND high_id = v_high;
  RETURN 'friends';
END; $$;

-- ============================================================
-- 11. Blocking needs a relationship
-- ============================================================

CREATE OR REPLACE FUNCTION block_user(p_user UUID) RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;
  IF p_user = v_me THEN RAISE EXCEPTION 'cannot_block_self'; END IF;
  -- Somebody the client can see: a friend, a request either way, or a
  -- conversation. An id with none of those answers as one with no profile,
  -- or the blocked list would hand back its handle and keys.
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user)
     OR NOT knows_user(p_user) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;

  INSERT INTO blocks (blocker_id, blocked_id) VALUES (v_me, p_user)
  ON CONFLICT DO NOTHING;

  -- See 002: a block takes the friendship, pending or not, with it.
  DELETE FROM friendships
   WHERE low_id = LEAST(v_me, p_user) AND high_id = GREATEST(v_me, p_user);
  RETURN 'blocked';
END; $$;

-- ============================================================
-- 12. An icon from the publisher's own folder
-- ============================================================
-- On the tables, so every path that writes a listing goes through it, and
-- only when the icon changes: a listing that already names one keeps
-- republishing.

CREATE OR REPLACE FUNCTION refuse_foreign_icon() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NEW.icon_path IS NOT NULL
     AND (TG_OP = 'INSERT' OR NEW.icon_path IS DISTINCT FROM OLD.icon_path)
     AND split_part(NEW.icon_path, '/', 1) <> NEW.owner_id::text THEN
    RAISE EXCEPTION 'icon_not_yours';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS public_servers_own_icon ON public_servers;
CREATE TRIGGER public_servers_own_icon BEFORE INSERT OR UPDATE OF icon_path ON public_servers
  FOR EACH ROW EXECUTE FUNCTION refuse_foreign_icon();

DROP TRIGGER IF EXISTS public_bots_own_icon ON public_bots;
CREATE TRIGGER public_bots_own_icon BEFORE INSERT OR UPDATE OF icon_path ON public_bots
  FOR EACH ROW EXECUTE FUNCTION refuse_foreign_icon();

-- ============================================================
-- 18. Editing a DM needs the friendship sending one does
-- ============================================================
-- `friendship_state` rather than `are_friends`: a policy runs as the member,
-- who may ask about their own relationships and nobody else's.

DROP POLICY IF EXISTS dm_messages_update_own ON dm_messages;
CREATE POLICY dm_messages_update_own ON dm_messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid() AND friendship_state(recipient_id) = 'friends')
  WITH CHECK (sender_id = auth.uid() AND friendship_state(recipient_id) = 'friends');

-- ============================================================
-- 19. A token belongs to the account that registered it last
-- ============================================================
-- Before the insert's conflict check, so the upsert the app sends finds no
-- other account's row in its way. Taking a row needs the token itself, which
-- only the phone it names has.

CREATE OR REPLACE FUNCTION take_device_token() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  DELETE FROM device_tokens WHERE token = NEW.token AND user_id <> NEW.user_id;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS device_tokens_take ON device_tokens;
CREATE TRIGGER device_tokens_take BEFORE INSERT ON device_tokens
  FOR EACH ROW EXECUTE FUNCTION take_device_token();

-- ============================================================
-- 20. A like needs a bot the caller can see
-- ============================================================
-- The subquery runs under `public_bots_select`, so a delisted or hidden bot
-- (not one's own) is the same as no bot.

DROP POLICY IF EXISTS bot_likes_insert_own ON bot_likes;
CREATE POLICY bot_likes_insert_own ON bot_likes FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid()
              AND EXISTS (SELECT 1 FROM public_bots b WHERE b.id = bot_id));

-- ============================================================
-- Grants
-- ============================================================

REVOKE ALL ON FUNCTION mark_deleted_hides()   FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION rehide_marked_server() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION refuse_foreign_icon()  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION take_device_token()    FROM PUBLIC, anon, authenticated;
