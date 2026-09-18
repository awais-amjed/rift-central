-- ============================================================
-- Rift central — 022: a conversation knows its own newest message
-- ============================================================
-- `dm_conversations()` read every DM you had ever exchanged with anybody in
-- order to hand back thirty rows. It could not do otherwise: the list is
-- ordered by each conversation's newest message, and the only way to find
-- that was `DISTINCT ON (peer)` over the whole of `dm_messages`, peer by peer,
-- sorted. Measured on a copy of this schema with 200 conversations of 500
-- messages — the per-conversation cap 019 enforces, so this is the shape a
-- heavy account actually has:
--
--   dm_conversations() ....................... 230-270 ms
--   dm_conversations(30, NULL, <peer>) .......     2.4 ms
--
-- The narrow one is a hundred times faster because naming both people lets it
-- walk `idx_dm_messages_pair`. The wide one has no such index and cannot have
-- one:
--
--   * **There is no column to index.** "Peer" means whoever is not the
--     caller — a CASE evaluated per query, different for every account that
--     asks. An index is a fixed structure; this is not a fixed value.
--   * **A conversation lives under two keys.** What you sent is filed by
--     sender, what you received by recipient, and the newest message may be
--     either. No single index sees a whole conversation.
--   * **Even a perfect index would only save the sort.** `DISTINCT ON` still
--     walks every one of your messages to find each peer's maximum.
--
-- So this is the index, written by hand, because Postgres cannot derive it:
-- one row per person you talk to, holding the id of that conversation's
-- newest message. The list becomes a range scan of your own rows, newest
-- first, stop at thirty — the cost of a page rather than the cost of your
-- history.
--
-- Two rows per conversation, one from each side, rather than one keyed on the
-- ordered pair. A pair key sorts by whichever uuid happens to be lower, so
-- "my conversations" would be a scan of both halves and a merge; a row per
-- participant makes it one index and one direction. A conversation is small
-- and a duplicate of two uuids and a bigint is nothing next to what it buys.

-- ============================================================
-- 1. The heads
-- ============================================================

CREATE TABLE IF NOT EXISTS dm_conversation_heads (
  user_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_message_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, peer_id)
);

COMMENT ON TABLE dm_conversation_heads IS
  'One row per person you have a conversation with, holding that '
  'conversation''s newest message id. Maintained by trigger; it is what makes '
  'the conversation list cost a page instead of a history.';

-- The whole point: your conversations, newest first, without a sort.
CREATE INDEX IF NOT EXISTS idx_dm_conversation_heads_recent
  ON dm_conversation_heads (user_id, last_message_id DESC);

-- Nobody reaches this directly. `dm_conversations` is SECURITY DEFINER and is
-- the only reader; a client that could read it could read who talks to whom.
ALTER TABLE dm_conversation_heads ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON dm_conversation_heads FROM anon, authenticated;

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

REVOKE ALL ON FUNCTION remember_dm_head() FROM public, anon, authenticated;

DROP TRIGGER IF EXISTS dm_messages_head ON dm_messages;
CREATE TRIGGER dm_messages_head AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION remember_dm_head();

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

REVOKE ALL ON FUNCTION forget_dm_head() FROM public, anon, authenticated;

DROP TRIGGER IF EXISTS dm_messages_head_gone ON dm_messages;
CREATE TRIGGER dm_messages_head_gone AFTER DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION forget_dm_head();

-- ---------- what is already here ----------
-- The one scan of the old shape, run once, so no account opens the app to an
-- empty list. Idempotent: re-running it changes nothing.

INSERT INTO dm_conversation_heads (user_id, peer_id, last_message_id)
SELECT side.me, side.peer, max(side.id)
  FROM (SELECT sender_id    AS me, recipient_id AS peer, id FROM dm_messages
        UNION ALL
        SELECT recipient_id AS me, sender_id    AS peer, id FROM dm_messages) side
 GROUP BY side.me, side.peer
    ON CONFLICT (user_id, peer_id) DO UPDATE
   SET last_message_id = GREATEST(dm_conversation_heads.last_message_id,
                                  EXCLUDED.last_message_id);

-- ============================================================
-- 3. The list, read from the heads
-- ============================================================
-- 021's function with its first two CTEs replaced. Everything from `kept`
-- down is unchanged: the same envelope, the same badge, the same friend
-- state, the same spare row proving `has_more`.
--
-- `p_peer` no longer needs a branch of its own. One conversation is one row
-- of the same index, which is what the two-branch `paired` CTE was working
-- around.

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL,
  p_peer   UUID    DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH page AS (
    SELECT h.last_message_id AS id, h.peer_id AS peer
      FROM dm_conversation_heads h
     WHERE h.user_id = auth.uid()
       AND (p_peer IS NULL OR h.peer_id = p_peer)
       -- Here rather than in the client: a filter on the far side of the page
       -- boundary silently shortens every page it touches.
       AND NOT EXISTS (
         SELECT 1 FROM blocks b
          WHERE b.blocker_id = auth.uid() AND b.blocked_id = h.peer_id)
       AND (p_before IS NULL OR h.last_message_id < p_before)
     ORDER BY h.last_message_id DESC
     -- One row past the page, so "there is more" is proved rather than
     -- guessed from a full page. Same trick the message history uses.
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
  'p_peer, just the one with that person. Read from dm_conversation_heads, so '
  'it costs a page rather than a history.';

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) FROM public, anon;
GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT, UUID) TO authenticated;
