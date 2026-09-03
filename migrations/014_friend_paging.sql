-- ============================================================
-- Rift central — 014: the friends graph, a tab at a time
-- ============================================================
-- `friend_list()` returns all four buckets in one call, and 012 gives the
-- reason: the client needs all of them to draw anything, so fetching them
-- separately means drawing a screen from four different moments.
--
-- That was true, and it is what this migration makes untrue. Only a handful of
-- *derived facts* were ever needed outside their own tab:
--
--   * how many requests are waiting  — the badge on the app rail, which is on
--     screen wherever you are;
--   * who is blocked                 — the conversation list leaves them out;
--   * where you stand with one peer  — what a conversation tile's menu offers.
--
-- None of those needs the rows. So the counts become a scalar, the block filter
-- moves into `dm_conversations` where the rows it filters already are, and the
-- per-peer state rides on the conversation row beside the unread count and the
-- notification level. What is left is three lists that are each only read by
-- the tab showing them — and those can be fetched when that tab is opened, and
-- paged.
--
-- ---------- the bug this fixes ----------
--
-- `FriendDirectory.visible` drops blocked peers from the conversation list
-- *after* the page arrives. That was fine while the list was the whole thing.
-- It stopped being fine in 013, which made the list paged: a page of thirty
-- containing four blocked peers renders twenty-six rows, while `has_more` and
-- the cursor were both computed for thirty. The list is quietly shorter than it
-- should be, and every further page compounds it.
--
-- A filter has to be on the same side of the page boundary as the paging. This
-- puts it there.

-- ============================================================
-- 1. Where one account stands with one person
-- ============================================================
-- The same four answers `FriendDirectory.stateFor` gave, asked about one peer
-- instead of derived from four whole lists. Named for the client's enum so the
-- two cannot drift: `friends`, `incoming`, `outgoing`, `blocked`, `none`.

CREATE OR REPLACE FUNCTION app_friend_state(p_peer UUID) RETURNS TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT CASE
    -- First, and it wins any disagreement: blocking tears the friendship down
    -- with it, so the two cannot both be true — but "blocked" is the answer
    -- that fails safe if they ever are.
    WHEN EXISTS (SELECT 1 FROM blocks b
                  WHERE b.blocker_id = auth.uid() AND b.blocked_id = p_peer)
      THEN 'blocked'
    WHEN EXISTS (SELECT 1 FROM friendships f
                  WHERE f.low_id = LEAST(auth.uid(), p_peer)
                    AND f.high_id = GREATEST(auth.uid(), p_peer)
                    AND f.status = 'accepted')
      THEN 'friends'
    WHEN EXISTS (SELECT 1 FROM friendships f
                  WHERE f.low_id = LEAST(auth.uid(), p_peer)
                    AND f.high_id = GREATEST(auth.uid(), p_peer)
                    AND f.status = 'pending' AND f.requester_id = auth.uid())
      THEN 'outgoing'
    WHEN EXISTS (SELECT 1 FROM friendships f
                  WHERE f.low_id = LEAST(auth.uid(), p_peer)
                    AND f.high_id = GREATEST(auth.uid(), p_peer)
                    AND f.status = 'pending')
      THEN 'incoming'
    ELSE 'none'
  END
$$;

-- ============================================================
-- 2. Conversations exclude blocked peers, and carry the state
-- ============================================================
-- Replaces 013's version. Two changes, and the comments from 013 still stand
-- for everything else it does. After the state function above, because a SQL
-- body is parsed when it is created and cannot call something that is not
-- there yet.
--
-- Blocking takes away reach and discoverability; it does not erase what was
-- said, so the messages are still readable rows. Something has to leave those
-- conversations out of the list, and it is this, not the client.

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
             -- Where the caller stands with this person, for the tile's menu.
             -- On the row because that is the only place it is asked, and
             -- because the alternative was holding the whole graph to answer
             -- it. 'blocked' never appears: those rows are gone above.
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

-- ============================================================
-- 3. How many, without the rows
-- ============================================================
-- What the rail badge and the three tab labels need, and all they need. Small
-- enough to be eager, which is the whole reason the rows no longer have to be.

CREATE OR REPLACE FUNCTION friend_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'friends',  (SELECT count(*) FROM friendships f
                  WHERE auth.uid() IN (f.low_id, f.high_id)
                    AND f.status = 'accepted'),
    -- Incoming only. Waiting for an answer is not something to be notified
    -- about, so an outgoing request is not in the badge.
    'incoming', (SELECT count(*) FROM friendships f
                  WHERE auth.uid() IN (f.low_id, f.high_id)
                    AND f.status = 'pending' AND f.requester_id <> auth.uid()),
    'outgoing', (SELECT count(*) FROM friendships f
                  WHERE auth.uid() IN (f.low_id, f.high_id)
                    AND f.status = 'pending' AND f.requester_id = auth.uid()),
    'blocked',  (SELECT count(*) FROM blocks b WHERE b.blocker_id = auth.uid()))
$$;

COMMENT ON FUNCTION friend_counts() IS
  'How many friends, requests each way, and blocks — for the rail badge and '
  'the tab labels, so the rows behind them can wait until a tab is opened.';

-- ============================================================
-- 4. One tab of the graph, paged
-- ============================================================
-- Keyset-paged on the peer's handle, which is the order the tabs are already
-- in. A handle is unique, so it is a total order on its own and needs no
-- tiebreaker — unlike a display name, which is why the member roster's cursor
-- (self-hosted 039) carries an id alongside it.

CREATE OR REPLACE FUNCTION friend_bucket(
  p_bucket TEXT,
  p_after  TEXT    DEFAULT NULL,
  p_limit  INTEGER DEFAULT 30
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me    UUID    := auth.uid();
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100);
  v_rows  JSONB;
  v_n     INTEGER;
BEGIN
  IF v_me IS NULL THEN RAISE EXCEPTION 'not_authenticated'; END IF;

  -- The block list is its own table and its own shape (`since` comes from the
  -- block, not a friendship), so it is its own branch rather than a fourth
  -- status. SECURITY DEFINER matters most here: 012's directory policy hides
  -- these rows once the friendship is gone, and a blocked list with no handles
  -- in it is a list of UUIDs nobody can unblock on purpose.
  IF p_bucket = 'blocked' THEN
    SELECT jsonb_agg(row ORDER BY handle), count(*) INTO v_rows, v_n
      FROM (
        SELECT u.handle,
               jsonb_build_object(
                 'id', u.id, 'handle', u.handle,
                 'chat_public_key', u.chat_public_key,
                 'signing_public_key', u.signing_public_key,
                 'since', b.created_at) AS row
          FROM blocks b JOIN users u ON u.id = b.blocked_id
         WHERE b.blocker_id = v_me
           AND (p_after IS NULL OR u.handle > p_after)
         ORDER BY u.handle
         LIMIT v_limit + 1) capped;
  ELSE
    SELECT jsonb_agg(row ORDER BY handle), count(*) INTO v_rows, v_n
      FROM (
        SELECT u.handle,
               jsonb_build_object(
                 'id', u.id, 'handle', u.handle,
                 'chat_public_key', u.chat_public_key,
                 'signing_public_key', u.signing_public_key,
                 'since', f.updated_at) AS row
          FROM friendships f
          JOIN users u
            ON u.id = CASE WHEN f.low_id = v_me THEN f.high_id ELSE f.low_id END
         WHERE v_me IN (f.low_id, f.high_id)
           AND f.status = (CASE WHEN p_bucket = 'friends'
                                THEN 'accepted' ELSE 'pending' END)::friend_status
           -- `outgoing` is the ones this account sent, `incoming` the ones it
           -- received; `friends` does not ask the question.
           AND (p_bucket = 'friends'
                OR (f.requester_id = v_me) = (p_bucket = 'outgoing'))
           AND (p_after IS NULL OR u.handle > p_after)
         ORDER BY u.handle
         LIMIT v_limit + 1) capped;
  END IF;

  RETURN jsonb_build_object(
    -- The spare row proves there is another page; it is not part of this one.
    'rows', COALESCE(
      CASE WHEN v_n > v_limit
           THEN (SELECT jsonb_agg(e) FROM (
                   SELECT e FROM jsonb_array_elements(v_rows) e LIMIT v_limit) t)
           ELSE v_rows END, '[]'::jsonb),
    'has_more', COALESCE(v_n, 0) > v_limit);
END; $$;

COMMENT ON FUNCTION friend_bucket(TEXT, TEXT, INTEGER) IS
  'One tab of the friends page — friends, incoming, outgoing or blocked — '
  'keyset-paged on the peer''s handle via p_after. Fetched when that tab is '
  'opened: nothing outside it reads these rows since friend_counts and the '
  'per-conversation state took over the jobs that did.';

-- ============================================================
-- 5. Privileges
-- ============================================================

REVOKE ALL ON FUNCTION app_friend_state(UUID)                  FROM public, anon;
REVOKE ALL ON FUNCTION friend_counts()                         FROM public, anon;
REVOKE ALL ON FUNCTION friend_bucket(TEXT, TEXT, INTEGER)      FROM public, anon;

GRANT EXECUTE ON FUNCTION app_friend_state(UUID)               TO authenticated;
GRANT EXECUTE ON FUNCTION friend_counts()                      TO authenticated;
GRANT EXECUTE ON FUNCTION friend_bucket(TEXT, TEXT, INTEGER)   TO authenticated;

-- ============================================================
-- 6. What this replaces
-- ============================================================
-- `friend_list()` and its `_friend_bucket` helper answered all four buckets at
-- once, and nothing calls them any more: the counts are `friend_counts`, the
-- rows are `friend_bucket` a tab at a time, and the one per-peer question the
-- conversation list asked now rides on the conversation row.
--
-- Dropped rather than left. They are `SECURITY DEFINER` and they resolve the
-- caller's whole social graph — exactly the kind of thing that should not sit
-- around uncalled, and exactly the kind of thing a future caller would reach
-- for without noticing it cannot page.
DROP FUNCTION IF EXISTS friend_list();
DROP FUNCTION IF EXISTS _friend_bucket(UUID, friend_status, BOOLEAN);
