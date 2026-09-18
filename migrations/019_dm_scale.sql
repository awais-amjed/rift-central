-- ============================================================
-- Rift central server — 019: DM limits that cost what they touch
-- ============================================================
-- Three queries grew with the size of the whole table rather than with the
-- one account or conversation they were about:
--
--   * The daily quota (send_dm, dm_quota) counts a sender's last 24 hours, but
--     the only index on the sender was (sender_id, id), so every send walked
--     every message that account had ever sent.
--   * Retention's age limit filtered on created_at, which had no index: a full
--     scan of dm_messages every night.
--   * Retention's 500-per-conversation cap ranked every row in the table by
--     conversation, every night, to find the few past the cap.
--
-- The first two get indexes. The third moves to the one moment a conversation
-- can go past the cap — a send — where it is a walk down one conversation's
-- index instead of a sort of everyone's. 020 takes it out of the nightly job.

CREATE INDEX IF NOT EXISTS idx_dm_messages_sender_created
  ON dm_messages (sender_id, created_at);

CREATE INDEX IF NOT EXISTS idx_dm_messages_created
  ON dm_messages (created_at);

-- ---------- send_dm: 012's version, plus the cap ----------

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
  -- 004's number. Past it the oldest ciphertext is gone for good, exactly as
  -- the nightly job used to do it, only without waiting for the night.
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
  -- sender learns exactly what a stranger learns. Which of the two blocked the
  -- other — or whether anybody did — is nobody's business but the blocker's.
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

  -- Written in idx_dm_messages_pair's own terms (LEAST, GREATEST, id), so both
  -- halves are index scans of this one conversation. The inner query finds the
  -- newest message that no longer fits; nothing is past the cap when it finds
  -- none, and `id <= NULL` deletes nothing.
  DELETE FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = LEAST(v_me, recipient)
     AND GREATEST(sender_id, recipient_id) = GREATEST(v_me, recipient)
     AND id <= (
       SELECT d.id FROM dm_messages d
        WHERE LEAST(d.sender_id, d.recipient_id) = LEAST(v_me, recipient)
          AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(v_me, recipient)
        ORDER BY d.id DESC
       OFFSET v_cap LIMIT 1);

  -- `state` is always 'friends' — nothing else gets this far. It is still in
  -- the answer because the client compares it with what it believes and
  -- re-reads the graph when they differ, which is how a device that missed a
  -- Realtime frame notices.
  RETURN jsonb_build_object(
    'id', v_id, 'created_at', v_at, 'state', 'friends',
    'remaining', v_quota - v_sent - 1, 'quota', v_quota
  );
END; $$;
