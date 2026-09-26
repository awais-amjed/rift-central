-- ============================================================
-- Rift central — 003: the triggers
-- ============================================================
-- What the database keeps true regardless of who is writing: the server's
-- stamp on a DM, the owner pinned onto a device token, and the conversation
-- heads that keep the DM list from scanning the table.
-- ============================================================

-- New sends go through send_dm() so the quota is enforced in one place, but
-- edits and deletes are ordinary RLS writes — so the server's word about who
-- sent a message and when still has to be enforced here rather than trusted
-- from the client.
CREATE OR REPLACE FUNCTION attest_dm() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.sender_id  := auth.uid();
    NEW.created_at := now();
    NEW.edited_at  := NULL;
    RETURN NEW;
  END IF;

  NEW.id           := OLD.id;
  NEW.sender_id    := OLD.sender_id;
  NEW.recipient_id := OLD.recipient_id;
  NEW.created_at   := OLD.created_at;
  IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    NEW.edited_at := now();
  ELSE
    NEW.edited_at := OLD.edited_at;
  END IF;
  RETURN NEW;
END; $$;

-- Stamped rather than accepted from the client, the same way `dm_messages`
-- stamps its sender: a client that could name the owner could register its
-- token against somebody else's account and receive that person's doorbells.
CREATE OR REPLACE FUNCTION stamp_device_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  NEW.user_id := auth.uid();
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

-- Stamped, not accepted: a client that could name the owner could mute
-- somebody else's conversations, which is a quiet way of making sure a person
-- never hears from anyone again.
CREATE OR REPLACE FUNCTION stamp_notification_pref()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

-- ============================================================
-- 7. Ringing
-- ============================================================
-- `send_dm` already refuses anything from a non-friend, so the friendship
-- check here is belt and braces — but this trigger is the
-- loudest thing the server can do, it fires on an INSERT rather than on the
-- RPC, and a future path into `dm_messages` that forgets the gate should not
-- also get to wake somebody's phone.
--
-- Note the order: the friendship check sits *above* the notification level,
-- because a level is a preference about people you have accepted and a
-- stranger has never had the chance to be given one.

CREATE OR REPLACE FUNCTION ring_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg push_config;
BEGIN
  IF NOT are_friends(NEW.sender_id, NEW.recipient_id) THEN
    RETURN NEW;
  END IF;
  IF notify_level_for(NEW.recipient_id, 'dm', NEW.sender_id) = 'none' THEN
    RETURN NEW;
  END IF;

  SELECT * INTO v_cfg FROM push_config LIMIT 1;
  IF v_cfg IS NULL THEN
    RETURN NEW;   -- push not configured on this deployment
  END IF;

  IF EXISTS (
    SELECT 1 FROM dm_messages d
     WHERE d.recipient_id = NEW.recipient_id
       AND d.sender_id    = NEW.sender_id
       AND d.id < NEW.id
       AND d.id > COALESCE((SELECT r.last_read_id FROM read_state r
                             WHERE r.user_id = NEW.recipient_id
                               AND r.scope = 'dm'
                               AND r.scope_id = NEW.sender_id), 0)
  ) THEN
    RETURN NEW;
  END IF;

  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object(
                 'Content-Type', 'application/json',
                 'x-push-secret', v_cfg.secret
               ),
    body    := jsonb_build_object('recipient', NEW.recipient_id)
  );
  RETURN NEW;
END; $$;

-- ============================================================
-- 2. Keeping them true
-- ============================================================
-- An insert is the easy half — a new message is always the newest, so both
-- sides move forward. GREATEST rather than a bare assignment because a
-- backfill or a repair may run beside it, and a head that goes backwards is a
-- conversation that jumps down the list.

CREATE OR REPLACE FUNCTION remember_dm_head() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO dm_conversation_heads (user_id, peer_id, last_message_id)
  VALUES (NEW.sender_id, NEW.recipient_id, NEW.id),
         (NEW.recipient_id, NEW.sender_id, NEW.id)
      ON CONFLICT (user_id, peer_id) DO UPDATE
     SET last_message_id = GREATEST(dm_conversation_heads.last_message_id,
                                    EXCLUDED.last_message_id);
  RETURN NULL;
END $$;

-- A delete only matters when it takes the head with it, which is the rare
-- case: `send_dm`'s trim and the nightly retention job both delete the
-- *oldest* messages, and the only other delete is somebody removing their own
-- message — usually not the newest one either.
--
-- When it is the head, the replacement is one backwards walk of
-- `idx_dm_messages_pair`; when there is nothing left, the conversation is
-- over and the row goes. Written per side, because a message you deleted may
-- still leave the other side's head where it was.

CREATE OR REPLACE FUNCTION forget_dm_head() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_newest BIGINT;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM dm_conversation_heads h
     WHERE h.last_message_id = OLD.id
       AND ((h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
         OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id))
  ) THEN
    RETURN NULL;   -- something older went; the head still stands
  END IF;

  SELECT max(d.id) INTO v_newest
    FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)
           = LEAST(OLD.sender_id, OLD.recipient_id)
     AND GREATEST(d.sender_id, d.recipient_id)
           = GREATEST(OLD.sender_id, OLD.recipient_id);

  IF v_newest IS NULL THEN
    DELETE FROM dm_conversation_heads h
     WHERE (h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
        OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id);
  ELSE
    UPDATE dm_conversation_heads h
       SET last_message_id = v_newest
     WHERE ((h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
         OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id))
       AND h.last_message_id = OLD.id;
  END IF;
  RETURN NULL;
END $$;

-- ---------- the like count ----------
-- `public_bots.like_count` is `bot_likes` counted, kept in step here rather
-- than read on every browse: the directory's default order *is* this number,
-- and `ORDER BY (SELECT count(*) …)` cannot use an index.
--
-- SECURITY DEFINER because the person liking has no UPDATE grant on
-- `public_bots` — the whole point is that a listing is written by its owner
-- and by nobody else. Liking is the one thing anybody may change about
-- somebody else's row, and this is the only path that changes it.
--
-- Recounted from the table rather than incremented. A delta is one lost or
-- replayed statement away from a count that nothing will ever correct, and
-- there is no cheap way to notice; the subquery is a primary-key range scan
-- on rows for one bot.
CREATE OR REPLACE FUNCTION recount_bot_likes() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot UUID := COALESCE(NEW.bot_id, OLD.bot_id);
BEGIN
  UPDATE public_bots
     SET like_count = (SELECT count(*) FROM bot_likes WHERE bot_id = v_bot)
   WHERE id = v_bot;
  RETURN NULL;
END; $$;

-- A like is the caller's, whatever the insert said. The policy says the same
-- thing, and both are cheap; this is the one that survives the policy being
-- rewritten.
CREATE OR REPLACE FUNCTION stamp_bot_like() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.created_at := now();
  RETURN NEW;
END; $$;

-- ---------- a moderator is not a Rift account ----------
-- Kept true from both sides, because either write alone would let the two
-- meet: making an existing Rift account a moderator, or a moderator claiming
-- a handle and so becoming one. See `central_admins` in 001 for why.
CREATE OR REPLACE FUNCTION refuse_moderator_profile() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM central_admins WHERE user_id = NEW.id) THEN
    RAISE EXCEPTION 'moderator_accounts_have_no_profile';
  END IF;
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION refuse_profile_moderator() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id) THEN
    RAISE EXCEPTION 'rift_accounts_cannot_moderate';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS attest_dm_messages ON dm_messages;
CREATE TRIGGER attest_dm_messages BEFORE INSERT OR UPDATE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION attest_dm();

DROP TRIGGER IF EXISTS device_tokens_stamp ON device_tokens;
CREATE TRIGGER device_tokens_stamp BEFORE INSERT OR UPDATE ON device_tokens
  FOR EACH ROW EXECUTE FUNCTION stamp_device_owner();

DROP TRIGGER IF EXISTS dm_messages_ring ON dm_messages;
CREATE TRIGGER dm_messages_ring AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION ring_recipient();

DROP TRIGGER IF EXISTS notification_prefs_stamp ON notification_prefs;
CREATE TRIGGER notification_prefs_stamp BEFORE INSERT OR UPDATE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION stamp_notification_pref();

DROP TRIGGER IF EXISTS dm_messages_head ON dm_messages;
CREATE TRIGGER dm_messages_head AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION remember_dm_head();

DROP TRIGGER IF EXISTS dm_messages_head_gone ON dm_messages;
CREATE TRIGGER dm_messages_head_gone AFTER DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION forget_dm_head();

DROP TRIGGER IF EXISTS bot_likes_stamp ON bot_likes;
CREATE TRIGGER bot_likes_stamp BEFORE INSERT ON bot_likes
  FOR EACH ROW EXECUTE FUNCTION stamp_bot_like();

DROP TRIGGER IF EXISTS bot_likes_recount ON bot_likes;
CREATE TRIGGER bot_likes_recount AFTER INSERT OR DELETE ON bot_likes
  FOR EACH ROW EXECUTE FUNCTION recount_bot_likes();

DROP TRIGGER IF EXISTS users_not_moderators ON users;
CREATE TRIGGER users_not_moderators BEFORE INSERT ON users
  FOR EACH ROW EXECUTE FUNCTION refuse_moderator_profile();

DROP TRIGGER IF EXISTS moderators_not_users ON central_admins;
CREATE TRIGGER moderators_not_users BEFORE INSERT OR UPDATE ON central_admins
  FOR EACH ROW EXECUTE FUNCTION refuse_profile_moderator();
