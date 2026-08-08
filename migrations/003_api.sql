-- ============================================================
-- Rift central server — 003: RPCs
-- ============================================================
-- Central has no edge functions at all. Everything a client does here is either
-- a policy-checked table call or one of these.

-- How many messages one account may send per rolling day. The funnel limit
-- that keeps central's hosting cost flat; enforced server-side so a modified
-- client can't spend more.
CREATE OR REPLACE FUNCTION daily_dm_quota() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

-- ============================================================
-- Claiming a handle
-- ============================================================
-- Creating or refreshing your own directory row. A client cannot do this as a
-- plain upsert: PostgREST writes every column of the payload into the DO UPDATE
-- clause, `id` included, and `id` is deliberately not in the UPDATE grant — so
-- the statement is refused before it ever reaches a policy, whether or not the
-- row exists. This does the same upsert without touching the key.
--
-- SECURITY INVOKER on purpose: the grants and policies in 002 still apply, so
-- this widens nothing. It only spells the statement in a way the grants allow.
CREATE OR REPLACE FUNCTION claim_handle(
  p_handle             TEXT,
  p_chat_public_key    TEXT,
  p_signing_public_key TEXT
) RETURNS VOID
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  INSERT INTO users (id, handle, chat_public_key, signing_public_key)
       VALUES (auth.uid(), p_handle, p_chat_public_key, p_signing_public_key)
  ON CONFLICT (id) DO UPDATE
          SET handle             = EXCLUDED.handle,
              chat_public_key    = EXCLUDED.chat_public_key,
              signing_public_key = EXCLUDED.signing_public_key;
END; $$;

-- ============================================================
-- Sending
-- ============================================================
-- The one write path for new messages. It exists because a daily counter is
-- not a row predicate: the check is over *other* rows, and it has to happen in
-- the same statement that inserts, or two clients race past the limit.

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
  v_sent  INTEGER;
  v_id    BIGINT;
  v_at    TIMESTAMPTZ;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  IF recipient = auth.uid() THEN
    RAISE EXCEPTION 'cannot_dm_self';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = auth.uid()) THEN
    RAISE EXCEPTION 'sender_has_no_profile';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = recipient) THEN
    RAISE EXCEPTION 'recipient_has_no_profile';
  END IF;
  IF length(ciphertext) > 16384 OR length(nonce) > 64
     OR length(signature) > 128 OR key_version < 1 THEN
    RAISE EXCEPTION 'envelope_invalid';
  END IF;

  SELECT count(*) INTO v_sent FROM dm_messages
   WHERE sender_id = auth.uid() AND created_at > now() - interval '24 hours';
  IF v_sent >= v_quota THEN
    RAISE EXCEPTION 'quota_exceeded';
  END IF;

  INSERT INTO dm_messages
         (sender_id, recipient_id, ciphertext, nonce, signature, key_version)
  VALUES (auth.uid(), recipient, ciphertext, nonce, signature, key_version)
  RETURNING id, created_at INTO v_id, v_at;

  RETURN jsonb_build_object(
    'id', v_id, 'created_at', v_at,
    'remaining', v_quota - v_sent - 1, 'quota', v_quota
  );
END; $$;

CREATE OR REPLACE FUNCTION dm_quota() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_quota CONSTANT INTEGER := daily_dm_quota();
  v_sent  INTEGER;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  SELECT count(*) INTO v_sent FROM dm_messages
   WHERE sender_id = auth.uid() AND created_at > now() - interval '24 hours';
  RETURN jsonb_build_object('quota', v_quota,
                            'remaining', greatest(v_quota - v_sent, 0));
END; $$;

-- ============================================================
-- Unread
-- ============================================================
-- Same two functions as the self-hosted schema, same shapes, minus the channel
-- half — so the client asks both tiers the same questions.

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'dms', COALESCE((
      SELECT jsonb_object_agg(sender_id, n) FROM (
        SELECT d.sender_id, count(*) AS n
          FROM dm_messages d
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'dm'
           AND r.scope_id = d.sender_id
         WHERE d.recipient_id = auth.uid()
           AND d.id > COALESCE(r.last_read_id, 0)
         GROUP BY d.sender_id
      ) d), '{}'::jsonb)
  );
$$;

CREATE OR REPLACE FUNCTION mark_read(
  p_scope        read_scope,
  p_scope_id     UUID,
  p_last_read_id BIGINT DEFAULT 0
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_target BIGINT := p_last_read_id;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF v_target <= 0 THEN
    SELECT COALESCE(max(d.id), 0) INTO v_target
      FROM dm_messages d
     WHERE d.sender_id = p_scope_id AND d.recipient_id = auth.uid();
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
       VALUES (auth.uid(), p_scope, p_scope_id, v_target)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
          SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
              updated_at   = now()
    RETURNING last_read_id INTO v_target;

  RETURN v_target;
END; $$;

-- ============================================================
-- Conversation list
-- ============================================================

CREATE OR REPLACE FUNCTION dm_conversations() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(row ORDER BY (row->'last_message'->>'id')::BIGINT DESC), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'peer_id',              u.id,
               'peer_name',            u.handle,
               'peer_chat_public_key', u.chat_public_key,
               'peer_public_key',      u.signing_public_key,
               'last_message', jsonb_build_object(
                 'id',           l.id,
                 'created_at',   l.created_at,
                 'sender_id',    l.sender_id,
                 'recipient_id', l.recipient_id,
                 'ciphertext',   l.ciphertext,
                 'nonce',        l.nonce,
                 'signature',    l.signature,
                 'key_version',  l.key_version,
                 'edited_at',    l.edited_at
               )
             ) AS row
        FROM (
          SELECT DISTINCT ON (peer) *
            FROM (
              SELECT d.*,
                     CASE WHEN d.sender_id = auth.uid()
                          THEN d.recipient_id ELSE d.sender_id END AS peer
                FROM dm_messages d
            ) paired
           ORDER BY peer, id DESC
        ) l
        JOIN users u ON u.id = l.peer
    ) rows;
$$;

-- ============================================================
-- Function privileges
-- ============================================================

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION claim_handle(TEXT, TEXT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION send_dm(UUID, TEXT, TEXT, TEXT, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION dm_quota()          TO authenticated;
GRANT EXECUTE ON FUNCTION unread_counts()     TO authenticated;
GRANT EXECUTE ON FUNCTION mark_read(read_scope, UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION dm_conversations()  TO authenticated;
