-- ============================================================
-- Rift central server — 021: DMs by broadcast, and one conversation at a time
-- ============================================================
-- Two costs that grew with everybody rather than with the person involved.
--
-- Postgres Changes. Every signed-in device watched dm_messages,
-- notification_prefs, friendships and blocks, and Realtime re-ran the read
-- policy for each watcher on each row, on one thread — the thing Supabase's
-- own guidance says to stop doing at about 3,000 watchers. The database now
-- says what happened, once, to the one private topic that should hear it:
--
--   user:<user id>   dm          a DM arrived          {id, sender_id}
--                    dm_changed  one was edited or     {message_id, sender_id}
--                                deleted by its sender
--                    prefs       a notification level moved
--                    graph       a friendship or one of your blocks moved
--
-- and none of those tables is published any more. Deletes are new: a DELETE
-- event cannot be filtered to its recipient, so the old subscription never
-- carried them, and a deleted DM stayed on screen until the conversation was
-- reopened.
--
-- The conversation list. Every incoming DM made every one of the recipient's
-- devices re-read the whole list, and the list is built from every DM the
-- account has sent or received in thirty days. [p_peer] asks for one row
-- instead, read through the pair index, in exactly the shape the list uses —
-- the same function, so the two cannot drift.

-- ============================================================
-- 1. One conversation, or a page of them
-- ============================================================
-- 014's version, with two changes:
--
-- * [p_peer] narrows it to that one conversation. The two branches of
--   `paired` are exclusive by a condition on the argument alone, so the
--   planner runs only the one that applies, and the narrow one is a walk of
--   idx_dm_messages_pair.
-- * Finding the newest message per peer sorts ids, not rows. It used to carry
--   every column through the DISTINCT ON, ciphertext included — up to 16 KB a
--   message, for every message in the window, to keep thirty.

DROP FUNCTION IF EXISTS dm_conversations(INTEGER, BIGINT);

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL,
  p_peer   UUID    DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH paired AS (
    SELECT d.id,
           CASE WHEN d.sender_id = auth.uid()
                THEN d.recipient_id ELSE d.sender_id END AS peer
      FROM dm_messages d
     WHERE p_peer IS NULL
       AND auth.uid() IN (d.sender_id, d.recipient_id)
    UNION ALL
    SELECT d.id, p_peer AS peer
      FROM dm_messages d
     WHERE p_peer IS NOT NULL
       AND LEAST(d.sender_id, d.recipient_id) = LEAST(auth.uid(), p_peer)
       AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(auth.uid(), p_peer)
  ),
  newest AS (
    SELECT DISTINCT ON (peer) id, peer
      FROM paired
     -- Here rather than in the client: a filter on the far side of the page
     -- boundary silently shortens every page it touches.
     WHERE NOT EXISTS (
       SELECT 1 FROM blocks b
        WHERE b.blocker_id = auth.uid() AND b.blocked_id = peer)
     ORDER BY peer, id DESC
  ),
  -- One row past the page, so "there is more" is proved rather than guessed
  -- from a full page. Same trick the message history uses.
  page AS (
    SELECT * FROM newest
     WHERE p_before IS NULL OR id < p_before
     ORDER BY id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100) + 1
  ),
  kept AS (
    SELECT d.*, p.peer
      FROM (SELECT * FROM page
             ORDER BY id DESC
             LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)) p
      JOIN dm_messages d ON d.id = p.id
  ),
  rows AS (
    SELECT jsonb_build_object(
             'peer_id',            u.id,
             'handle',             u.handle,
             'chat_public_key',    u.chat_public_key,
             'signing_public_key', u.signing_public_key,
             -- Where the caller stands with this person, for the tile's menu.
             -- 'blocked' never appears: those rows are gone above.
             'state', app_friend_state(u.id),
             -- Null means "whatever the default for a DM is". The client owns
             -- that word, so the column is sent as it is rather than resolved.
             'level', (SELECT np.level FROM notification_prefs np
                        WHERE np.user_id = auth.uid()
                          AND np.scope = 'dm'::notify_scope
                          AND np.scope_id = u.id),
             -- What a "mark read" writes back. It has to come from the same
             -- read as the count, or the cursor would skip messages counted a
             -- moment earlier.
             'latest_inbound', COALESCE(
               (SELECT max(d.id) FROM dm_messages d
                 WHERE d.recipient_id = auth.uid() AND d.sender_id = u.id), 0),
             'unread', (
               SELECT count(*) FROM dm_messages d
                WHERE d.recipient_id = auth.uid()
                  AND d.sender_id = u.id
                  AND d.id > COALESCE(
                        (SELECT rs.last_read_id FROM read_state rs
                          WHERE rs.user_id = auth.uid()
                            AND rs.scope = 'dm'::read_scope
                            AND rs.scope_id = u.id), 0)),
             'last_message', jsonb_build_object(
               'id',           k.id,
               'created_at',   k.created_at,
               'sender_id',    k.sender_id,
               'recipient_id', k.recipient_id,
               'ciphertext',   k.ciphertext,
               'nonce',        k.nonce,
               'signature',    k.signature,
               'key_version',  k.key_version,
               'edited_at',    k.edited_at)
           ) AS row,
           k.id AS sort_id
      FROM kept k
      JOIN users u ON u.id = k.peer
  )
  SELECT jsonb_build_object(
           'conversations',
           COALESCE((SELECT jsonb_agg(row ORDER BY sort_id DESC) FROM rows),
                    '[]'::jsonb),
           'has_more',
           (SELECT count(*) FROM page) > (SELECT count(*) FROM kept));
$$;

COMMENT ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) IS
  'The caller''s DM conversations, newest first, a page at a time — or, given '
  'p_peer, just the one with that person.';

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) FROM public, anon;
GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) TO authenticated;

-- ============================================================
-- 2. Saying it
-- ============================================================
-- `realtime.send` swallows its own failures, so a broadcast that cannot be
-- delivered never fails the write behind it. The test database has no
-- Realtime at all, hence the check.

CREATE OR REPLACE FUNCTION realtime_ready() RETURNS BOOLEAN
  LANGUAGE sql STABLE AS $$
  SELECT to_regprocedure('realtime.send(jsonb,text,text,boolean)') IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION tell_user(p_user UUID, p_event TEXT, p_payload JSONB)
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF p_user IS NULL OR NOT realtime_ready() THEN
    RETURN;
  END IF;
  PERFORM realtime.send(p_payload, p_event, 'user:' || p_user, true);
END $$;

REVOKE ALL ON FUNCTION tell_user(UUID, TEXT, JSONB) FROM public, anon, authenticated;

-- ---------- DMs ----------
-- A delete is news only when its sender made it. Retention's nightly purge runs
-- with nobody signed in, and send_dm's trimming of a conversation past 500 says
-- so in `rift.quiet_deletes`; telling a recipient about either would be a
-- broadcast per row for something nobody did.

CREATE OR REPLACE FUNCTION announce_dm() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM tell_user(NEW.recipient_id, 'dm',
      jsonb_build_object('id', NEW.id, 'sender_id', NEW.sender_id));
  ELSIF TG_OP = 'UPDATE' THEN
    PERFORM tell_user(NEW.recipient_id, 'dm_changed',
      jsonb_build_object('message_id', NEW.id, 'sender_id', NEW.sender_id));
  ELSIF auth.uid() = OLD.sender_id
        AND COALESCE(current_setting('rift.quiet_deletes', true), '') <> 'on' THEN
    PERFORM tell_user(OLD.recipient_id, 'dm_changed',
      jsonb_build_object('message_id', OLD.id, 'sender_id', OLD.sender_id));
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS dm_messages_announce ON dm_messages;
CREATE TRIGGER dm_messages_announce
  AFTER INSERT OR UPDATE OR DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION announce_dm();

-- ---------- a level set on another device ----------

CREATE OR REPLACE FUNCTION announce_prefs() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM tell_user(OLD.user_id, 'prefs', '{}'::jsonb);
  ELSE
    PERFORM tell_user(NEW.user_id, 'prefs', '{}'::jsonb);
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS notification_prefs_announce ON notification_prefs;
CREATE TRIGGER notification_prefs_announce
  AFTER INSERT OR UPDATE OR DELETE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION announce_prefs();

-- ---------- the friend graph ----------
-- A friendship is both people's, so both hear it. A block is the blocker's
-- alone: nothing anywhere lets the blocked side learn of it, and a broadcast
-- to them would be the first thing that did.

CREATE OR REPLACE FUNCTION announce_friendship() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_low  UUID;
  v_high UUID;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_low := OLD.low_id;  v_high := OLD.high_id;
  ELSE
    v_low := NEW.low_id;  v_high := NEW.high_id;
  END IF;
  PERFORM tell_user(v_low,  'graph', '{}'::jsonb);
  PERFORM tell_user(v_high, 'graph', '{}'::jsonb);
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS friendships_announce ON friendships;
CREATE TRIGGER friendships_announce
  AFTER INSERT OR UPDATE OR DELETE ON friendships
  FOR EACH ROW EXECUTE FUNCTION announce_friendship();

CREATE OR REPLACE FUNCTION announce_block() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM tell_user(OLD.blocker_id, 'graph', '{}'::jsonb);
  ELSE
    PERFORM tell_user(NEW.blocker_id, 'graph', '{}'::jsonb);
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS blocks_announce ON blocks;
CREATE TRIGGER blocks_announce
  AFTER INSERT OR UPDATE OR DELETE ON blocks
  FOR EACH ROW EXECUTE FUNCTION announce_block();

REVOKE ALL ON FUNCTION announce_dm()         FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION announce_prefs()      FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION announce_friendship() FROM public, anon, authenticated;
REVOKE ALL ON FUNCTION announce_block()      FROM public, anon, authenticated;

-- ---------- send_dm: 019's version, trimming quietly ----------

CREATE OR REPLACE FUNCTION send_dm(
  recipient   UUID,
  ciphertext  TEXT,
  nonce       TEXT,
  signature   TEXT,
  key_version INTEGER
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_quota CONSTANT INTEGER := daily_dm_quota();
  -- 004's number. Past it the oldest ciphertext is gone for good.
  v_cap   CONSTANT INTEGER := 500;
  v_me    UUID := auth.uid();
  v_sent  INTEGER;
  v_id    BIGINT;
  v_at    TIMESTAMPTZ;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF recipient = v_me THEN
    RAISE EXCEPTION 'cannot_dm_self';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = v_me) THEN
    RAISE EXCEPTION 'sender_has_no_profile';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = recipient) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;
  IF length(ciphertext) > 16384 OR length(nonce) > 64
     OR length(signature) > 128 OR key_version < 1 THEN
    RAISE EXCEPTION 'envelope_invalid';
  END IF;

  -- The gate. `blocked` is not raised separately: blocking deletes the
  -- friendship, so a blocked pair is a pair that is not friends, and the
  -- sender learns exactly what a stranger learns.
  IF NOT are_friends(v_me, recipient) THEN
    RAISE EXCEPTION 'not_friends';
  END IF;

  SELECT count(*) INTO v_sent FROM dm_messages
   WHERE sender_id = v_me AND created_at > now() - interval '24 hours';
  IF v_sent >= v_quota THEN
    RAISE EXCEPTION 'quota_exceeded';
  END IF;

  INSERT INTO dm_messages
         (sender_id, recipient_id, ciphertext, nonce, signature, key_version)
  VALUES (v_me, recipient, ciphertext, nonce, signature, key_version)
  RETURNING id, created_at INTO v_id, v_at;

  -- Written in idx_dm_messages_pair's own terms, so both halves are index
  -- scans of this one conversation; `id <= NULL` deletes nothing. Quietly:
  -- nobody deleted these, the cap did.
  PERFORM set_config('rift.quiet_deletes', 'on', true);
  DELETE FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = LEAST(v_me, recipient)
     AND GREATEST(sender_id, recipient_id) = GREATEST(v_me, recipient)
     AND id <= (
       SELECT d.id FROM dm_messages d
        WHERE LEAST(d.sender_id, d.recipient_id) = LEAST(v_me, recipient)
          AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(v_me, recipient)
        ORDER BY d.id DESC
       OFFSET v_cap LIMIT 1);
  PERFORM set_config('rift.quiet_deletes', 'off', true);

  -- `state` is always 'friends' — nothing else gets this far. It is still in
  -- the answer because the client compares it with what it believes and
  -- re-reads the graph when they differ.
  RETURN jsonb_build_object(
    'id', v_id, 'created_at', v_at, 'state', 'friends',
    'remaining', v_quota - v_sent - 1, 'quota', v_quota
  );
END; $$;

-- ============================================================
-- 3. Who may join
-- ============================================================
-- Your own topic, to listen. Nobody sends to a topic here but the database,
-- so there is no rule for sending, and without one a client cannot.

CREATE OR REPLACE FUNCTION can_join_topic(p_topic TEXT) RETURNS BOOLEAN
  LANGUAGE sql STABLE AS $$
  SELECT auth.uid() IS NOT NULL AND p_topic = 'user:' || auth.uid()
$$;

REVOKE ALL ON FUNCTION can_join_topic(TEXT) FROM public, anon;
GRANT EXECUTE ON FUNCTION can_join_topic(TEXT) TO authenticated;

DO $$
BEGIN
  IF to_regclass('realtime.messages') IS NULL THEN
    RETURN;  -- the test database
  END IF;
  DROP POLICY IF EXISTS central_topic_read ON realtime.messages;
  CREATE POLICY central_topic_read ON realtime.messages
    FOR SELECT TO authenticated
    USING (can_join_topic(realtime.topic()));
END $$;

-- ============================================================
-- 4. Nothing is watched any more
-- ============================================================

DO $$
DECLARE
  v_table TEXT;
BEGIN
  FOREACH v_table IN ARRAY ARRAY['dm_messages', 'notification_prefs',
                                 'friendships', 'blocks'] LOOP
    BEGIN
      EXECUTE format('ALTER PUBLICATION supabase_realtime DROP TABLE %I', v_table);
    EXCEPTION WHEN undefined_object OR undefined_table THEN NULL;
    END;
  END LOOP;
END $$;
