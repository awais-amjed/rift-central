-- ============================================================
-- Rift central — 013: the conversation list, answered by the database
-- ============================================================
-- The self-hosted tier already learned this lesson. `003_api.sql` says it in a
-- comment above its own `dm_conversations`:
--
--   "This was an edge function that pulled a thousand rows and grouped them in
--    TypeScript; DISTINCT ON does it in the database and returns only what's
--    shown."
--
-- Central was still running the version that lesson was about — in Dart rather
-- than TypeScript, but the same shape: `listRecentMessages(limit: 1000)`, then
-- a client-side scan for the newest row per peer and a second scan for the
-- unread counts. Three things were wrong with it, and only the first is about
-- bandwidth:
--
--   1. A thousand envelopes crossed the wire to render a list of, typically,
--      a dozen rows.
--   2. Past a thousand *total* envelopes it stopped being correct. An old
--      conversation fell off the list silently, and since those same rows were
--      where the unread badges came from, the badge went with it.
--   3. It could not page. There was nowhere to put the 31st conversation,
--      because the client had no cursor into a list it was deriving.
--
-- So the whole question moves here, and the answer carries everything a row
-- draws: the peer, their published keys, the newest envelope, the unread count,
-- the newest inbound id a "mark read" writes back, and how much that person is
-- allowed to interrupt. One paged call replaces four unbounded ones —
-- `listRecentMessages`, `directory_profiles`, `listReadCursors` and
-- `listNotificationLevels`, the last two of which grow a row per conversation
-- and so had a ceiling of their own.
--
-- ---------- why SECURITY DEFINER ----------
--
-- The same reason `directory_profiles` (012) is. `users_select_directory` is
-- relationship-scoped — `id = auth.uid() OR knows_user(id)` — and a
-- conversation must keep opening after an unfriend or a block, because a DM key
-- is derived from the peer's published X25519 key and re-read on every launch.
-- A version that stopped answering would quietly make the other person's copy
-- of the conversation undecryptable. So the gate here is the same one
-- `directory_profiles` uses and no wider: a row appears only for somebody the
-- caller has actually exchanged a message with, which is exactly what having a
-- conversation means.

-- ---------- and why the old one is dropped ----------
--
-- There *was* a `dm_conversations()` here, added in 003 and never called by
-- anything. Two reasons not to keep it alongside the paged one. It is
-- unbounded, which is the problem being fixed. And it is `SECURITY INVOKER`,
-- so since 012 narrowed `users_select_directory` to `knows_user(id)` its JOIN
-- to `users` would silently drop the conversation with anybody unfriended or
-- blocked — the same failure `directory_profiles` exists to avoid, sitting
-- unnoticed in an uncalled function. Two functions of the same name, one of
-- them wrong, is not a thing to leave for the next reader.

-- ============================================================
-- 1. Indexes for the per-peer questions
-- ============================================================
-- `idx_dm_messages_recipient (recipient_id, id)` already exists and answers
-- "my inbox, newest first". What the unread count and the newest-inbound id ask
-- is narrower — *this peer's* messages to me — and the pair columns let both be
-- an index range scan instead of a filter over the whole inbox.

CREATE INDEX IF NOT EXISTS idx_dm_messages_inbound_pair
  ON dm_messages (recipient_id, sender_id, id);

CREATE INDEX IF NOT EXISTS idx_dm_messages_outbound_pair
  ON dm_messages (sender_id, recipient_id, id);

-- ============================================================
-- 2. One page of conversations
-- ============================================================
-- Keyset-paged on the last message's id, descending — the order the list is
-- already in, and a stable one: a conversation's position changes only when
-- somebody says something in it, at which point it moves to the top rather than
-- shifting the page boundary underneath a reader.
--
-- The count is exact rather than capped. It is one index range scan over one
-- pair's messages, and a badge that said "99+" would be a second thing for the
-- two tiers to disagree about — the self-hosted side counts `notifications`
-- rows exactly.

DROP FUNCTION IF EXISTS dm_conversations();

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH newest AS (
    SELECT DISTINCT ON (peer) *
      FROM (
        SELECT d.*,
               CASE WHEN d.sender_id = auth.uid()
                    THEN d.recipient_id ELSE d.sender_id END AS peer
          FROM dm_messages d
         WHERE auth.uid() IN (d.sender_id, d.recipient_id)
      ) paired
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
    SELECT * FROM page
     ORDER BY id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)
  ),
  rows AS (
    SELECT jsonb_build_object(
             'peer_id',            u.id,
             'handle',             u.handle,
             'chat_public_key',    u.chat_public_key,
             'signing_public_key', u.signing_public_key,
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

COMMENT ON FUNCTION dm_conversations(INTEGER, BIGINT) IS
  'One page of the caller''s conversations, newest first: the peer and their '
  'published keys, the newest envelope, the unread count, the newest inbound '
  'id a mark-read writes back, and the notification level. Keyset-paged on the '
  'last message id via p_before. SECURITY DEFINER on the same gate as '
  'directory_profiles — a message exchanged, not a friendship — because a '
  'conversation must keep opening after an unfriend or the peer''s copy of it '
  'becomes undecryptable.';

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT) FROM public, anon;
GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT) TO authenticated;
