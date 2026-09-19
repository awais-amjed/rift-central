-- ============================================================
-- Rift central — 023: a badge stops counting past ninety-nine
-- ============================================================
-- `unread_counts()` counts every unread DM a person has, exactly, and then
-- the client draws "99+" over anything above ninety-nine. So the difference
-- between the true answer and the drawn one is invisible, and the cost of
-- computing it is not: the count is unbounded, which means it grows with the
-- size of the backlog rather than with the size of the screen.
--
-- Self-hosted migration 020 made the same change for channels and gave the
-- reasoning; this is the central tier catching up. It is the last unbounded
-- read on either side.
--
-- Measured on 200,000 accounts, 5,100,000 DMs, 1,200,000 conversations:
--
--   503 conversations, ~40 unread each ......  22.6 ms  →  13.1 ms
--   the same, with 100,000 unread in one ....  235   ms  →  12.2 ms
--
-- The first column is what the size of a backlog costs. The second is that
-- it costs nothing, which is the point: somebody who has ignored a group of
-- friends for a year pays for the conversations they have, not the messages
-- in them.
--
-- ---------- why it is driven from the conversations ----------
--
-- The old shape was one grouped scan of `dm_messages` — every inbound
-- message the caller has, grouped by sender, joined to the read cursor. A
-- cap cannot be applied to that: `LIMIT` on a grouped query limits the
-- groups, not the rows inside them.
--
-- Driving from `dm_conversation_heads` (022) instead gives a loop over the
-- conversations, each of which is a walk of
-- `idx_dm_messages_inbound_pair (recipient_id, sender_id, id)` from the
-- cursor forward, stopping at the cap. A constant sender and a constant
-- cursor are what let the planner use that index as a range — written as one
-- statement with a correlated subquery it chooses a scan instead, which is
-- the trap 020 documents at length.
--
-- SECURITY DEFINER, because `dm_conversation_heads` is deliberately
-- unreadable by `authenticated` (022: no grant, no policy). Every query
-- below is pinned to `auth.uid()`, and the inbound filter is *stricter* than
-- `dm_messages_select` would be — unread mail is what was sent to you, not
-- what you sent.

CREATE OR REPLACE FUNCTION unread_cap() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

COMMENT ON FUNCTION unread_cap() IS
  'Where a badge stops counting. UnreadBadge draws "99+" above ninety-nine, '
  'so a hundred and five thousand are the same picture.';

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_dms    JSONB := '{}'::jsonb;
  v_peer   RECORD;
  v_cursor BIGINT;
  v_n      INTEGER;
BEGIN
  IF v_me IS NULL THEN
    RETURN jsonb_build_object('dms', '{}'::jsonb,
                              'prefs', jsonb_build_object('dms', '{}'::jsonb));
  END IF;

  FOR v_peer IN
    SELECT h.peer_id FROM dm_conversation_heads h WHERE h.user_id = v_me
  LOOP
    SELECT r.last_read_id INTO v_cursor
      FROM read_state r
     WHERE r.user_id = v_me AND r.scope = 'dm' AND r.scope_id = v_peer.peer_id;
    v_cursor := COALESCE(v_cursor, 0);

    SELECT count(*) INTO v_n FROM (
      SELECT 1 FROM dm_messages d
       WHERE d.recipient_id = v_me
         AND d.sender_id = v_peer.peer_id
         AND d.id > v_cursor
       ORDER BY d.id
       LIMIT unread_cap()
    ) capped;

    IF v_n > 0 THEN
      v_dms := v_dms || jsonb_build_object(v_peer.peer_id::TEXT, v_n);
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'dms', v_dms,
    'prefs', jsonb_build_object(
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::text)
          FROM notification_prefs p
         WHERE p.user_id = v_me AND p.scope = 'dm'), '{}'::jsonb)
    ));
END $$;

COMMENT ON FUNCTION unread_counts() IS
  'Unread DM badges and notification levels: {dms, prefs}. Counts stop at '
  'unread_cap(), so the work is the number of conversations rather than the '
  'number of messages in them.';

REVOKE ALL ON FUNCTION unread_counts() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION unread_counts() TO authenticated;
