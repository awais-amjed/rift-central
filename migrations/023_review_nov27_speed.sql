-- ============================================================
-- Rift central — 023: the Nov 27 review's speed fixes
-- ============================================================
-- From the speed half of the Nov 27 review. None of these changes what
-- anybody may see or do; each makes something cost what it touches. Each is
-- said again beside its code:
--
--   1. Listing the DM-file bucket ran `dm_attachment_readable` once for every
--      file in the bucket (Storage filters a list by prefix with LIKE, which
--      is not leakproof, so the policy runs first, on every row). Measured
--      2.1 s per list call at 300,000 files, and 15.6 s, past the statement
--      timeout, with real conversations behind it. The policy is now a set of
--      folders worked out once per statement.
--   2. Reading `users` with no id ran `knows_user` once per account: 933 ms
--      at 50,000 accounts. The policy is now the caller's known ids, worked
--      out once, which the primary key answers.
--   3. Ten foreign keys had no index, so deleting an account or a listing
--      scanned each of their tables; two `dm_messages` indexes duplicated
--      others and cost two index writes per message.
--   4. `mark_read` wrote a new row version when the cursor did not move.
--   5. `moderation_accounts` returned every account in one answer (16 MB of
--      JSON at 50,000 accounts). The admin site now pages them, and asks for
--      the totals on their own.
-- ============================================================

-- ---------- 1. the DM-file bucket ----------
-- Who may read a file in someone's folder is unchanged: its owner, and
-- anyone the owner has sent a DM that is still kept. Before, that was asked
-- per file; now it is a list of folders made once per statement, which a
-- hashed sub-plan checks each row against. `IN (SELECT …)` and not
-- `= ANY (ARRAY(…))`: the array is searched from the start for every row,
-- which for a well-connected account was 9.2 s across the bucket. Measured
-- on the review's data (300,000 files, 1.4 M messages), the whole bucket:
-- 2.3 s before, about 100 ms after, for an ordinary member and for the
-- account with the most conversations alike (Nov 27).
--
-- `dm_conversation_heads` holds a row for a pair exactly while a message
-- between them is kept (`remember_dm_head`, `forget_dm_head`), so it names
-- every peer who could have sent one; the EXISTS keeps those who did.
CREATE OR REPLACE FUNCTION dm_attachment_folders() RETURNS SETOF TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT auth.uid()::TEXT WHERE auth.uid() IS NOT NULL
  UNION ALL
  SELECT h.peer_id::TEXT
    FROM dm_conversation_heads h
   WHERE h.user_id = auth.uid()
     AND EXISTS (SELECT 1 FROM dm_messages m
                  WHERE m.sender_id = h.peer_id AND m.recipient_id = auth.uid());
$$;

REVOKE ALL ON FUNCTION dm_attachment_folders() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION dm_attachment_folders() TO authenticated;

-- A file always sits in a folder: uploads land only under
-- `auth.uid()::text/` (`central_dm_att_insert`).
DROP POLICY IF EXISTS central_dm_att_select ON storage.objects;
CREATE POLICY central_dm_att_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'central-dm-attachments'
         AND strpos(name, '/') > 0
         AND split_part(name, '/', 1) IN (SELECT dm_attachment_folders()));

-- Nothing calls the old per-file test any more, but it stays, answering the
-- same, for one index probe: the pair-and-sender form settled on a generic
-- plan that walked all the uploader's sent messages (4,999 calls on one
-- folder, 12.6 s; this form, 38 ms).
CREATE OR REPLACE FUNCTION dm_attachment_readable(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_folder TEXT := NULLIF(split_part(p_name, '/', 1), p_name);
BEGIN
  IF v_me IS NULL OR v_folder IS NULL THEN
    RETURN FALSE;
  END IF;
  IF v_folder = v_me::TEXT THEN
    RETURN TRUE;
  END IF;
  IF v_folder !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN FALSE;
  END IF;
  RETURN EXISTS (SELECT 1 FROM dm_messages m
                  WHERE m.sender_id = v_folder::UUID AND m.recipient_id = v_me);
END $$;

-- ---------- 2. who you can look up ----------
-- The same people `knows_user` answers for: yourself, anyone you have a
-- `friendships` row with (whatever its state), and anyone you have a DM with
-- (`dm_conversation_heads`, kept exactly while one is). As an array the
-- policy is an index condition on `users`' primary key. Measured at 50,000
-- accounts (Nov 27): an unfiltered read 965 ms before, 0.5 ms after for an
-- ordinary member and 11 ms for one with 5,000 friends. The cost moves to a
-- read by id for that account, 0.2 ms to 9 ms; an ordinary one's stays
-- 0.4 ms.
CREATE OR REPLACE FUNCTION known_user_ids() RETURNS SETOF UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT auth.uid() WHERE auth.uid() IS NOT NULL
  UNION
  SELECT CASE WHEN f.low_id = auth.uid() THEN f.high_id ELSE f.low_id END
    FROM friendships f
   WHERE f.low_id = auth.uid() OR f.high_id = auth.uid()
  UNION
  SELECT h.peer_id FROM dm_conversation_heads h WHERE h.user_id = auth.uid();
$$;

REVOKE ALL ON FUNCTION known_user_ids() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION known_user_ids() TO authenticated;

DROP POLICY IF EXISTS users_select_directory ON users;
CREATE POLICY users_select_directory ON users FOR SELECT TO authenticated
  USING (id = ANY (ARRAY(SELECT known_user_ids())));

-- ---------- 3. indexes ----------
-- Each foreign key here is checked by a scan of its table when the row it
-- names is deleted (an account, a listing). `friendships.requester_id` was a
-- 10 ms scan of 205,000 rows per account deletion in the review's data.
CREATE INDEX IF NOT EXISTS idx_friendships_requester
  ON friendships (requester_id);
CREATE INDEX IF NOT EXISTS idx_dm_conversation_heads_peer
  ON dm_conversation_heads (peer_id);
CREATE INDEX IF NOT EXISTS idx_dm_message_pins_user_high
  ON dm_message_pins (user_high);
CREATE INDEX IF NOT EXISTS idx_dm_message_pins_pinned_by
  ON dm_message_pins (pinned_by) WHERE pinned_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_directory_reports_server_listing
  ON directory_reports (server_listing_id) WHERE server_listing_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_directory_reports_bot_listing
  ON directory_reports (bot_listing_id) WHERE bot_listing_id IS NOT NULL;
-- The moderator who acted, on four tables: removing a moderator account
-- checks each of them.
CREATE INDEX IF NOT EXISTS idx_bug_reports_resolved_by
  ON bug_reports (resolved_by) WHERE resolved_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_directory_reports_resolved_by
  ON directory_reports (resolved_by) WHERE resolved_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_directory_ban_marks_banned_by
  ON directory_ban_marks (banned_by) WHERE banned_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_directory_bans_banned_by
  ON directory_bans (banned_by) WHERE banned_by IS NOT NULL;
-- No foreign key, but `hold_renamed_handle` and `hold_deleted_handle` look a
-- hold up by it.
CREATE INDEX IF NOT EXISTS idx_released_handles_previous_owner
  ON released_handles (previous_owner) WHERE previous_owner IS NOT NULL;

-- `(sender_id, id)` and `(recipient_id, id)` lead with the same column as
-- `idx_dm_messages_outbound_pair` / `idx_dm_messages_sender_created` and
-- `idx_dm_messages_inbound_pair`, which answer everything they did. Together
-- they were a quarter of the table's index bytes (76 MB each at 1.39 M rows).
DROP INDEX IF EXISTS idx_dm_messages_sender;
DROP INDEX IF EXISTS idx_dm_messages_recipient;

-- ---------- 4. a read cursor that did not move ----------
-- Same answer as before: the cursor, which never goes backwards. The update
-- is skipped when it would not move it, so a repeated call writes nothing
-- (and `announce_read` already stayed quiet for it).
CREATE OR REPLACE FUNCTION mark_read(
  p_scope        read_scope,
  p_scope_id     UUID,
  p_last_read_id BIGINT DEFAULT 0
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_target BIGINT := p_last_read_id;
  v_kept   BIGINT;
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
          SET last_read_id = EXCLUDED.last_read_id,
              updated_at   = now()
        WHERE read_state.last_read_id < EXCLUDED.last_read_id
    RETURNING last_read_id INTO v_kept;

  IF v_kept IS NULL THEN
    SELECT r.last_read_id INTO v_kept
      FROM read_state r
     WHERE r.user_id = auth.uid() AND r.scope = p_scope AND r.scope_id = p_scope_id;
  END IF;
  RETURN v_kept;
END; $$;

-- ---------- 5. the accounts list, a page at a time ----------
-- `moderation_accounts` stays, for an admin site from before this, but the
-- site now asks for these two. The totals are counted in the database; a
-- page carries a row as `moderation_accounts` does, newest first, and the
-- listing counts and sessions are worked out for its rows only. At 50,000
-- accounts: the whole list 514 ms, the totals 37 ms, a page of 100 19 ms
-- and 33 kB (Nov 27).
CREATE OR REPLACE FUNCTION moderation_account_stats() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_out JSONB;
BEGIN
  PERFORM assert_central_admin();

  WITH s AS (
    SELECT x.user_id,
           GREATEST(max(x.updated_at), max(x.refreshed_at AT TIME ZONE 'UTC')) AS last_refresh
      FROM auth.sessions x
     GROUP BY x.user_id
  ), a AS (
    SELECT a.created_at, GREATEST(a.last_sign_in_at, s.last_refresh) AS last_active
      FROM auth.users a
      LEFT JOIN s ON s.user_id = a.id
     WHERE NOT EXISTS (SELECT 1 FROM central_admins m WHERE m.user_id = a.id)
  )
  SELECT jsonb_build_object(
           'accounts',     count(*),
           'active_today', count(*) FILTER (WHERE last_active > now() - interval '1 day'),
           'active_week',  count(*) FILTER (WHERE last_active > now() - interval '7 days'),
           'new_week',     count(*) FILTER (WHERE created_at  > now() - interval '7 days'))
    INTO v_out
    FROM a;
  RETURN v_out;
END; $$;

-- [p_before_at, p_before_id] is the last row of the page before, both or
-- neither. [p_search] matches anywhere in the handle or the email, ignoring
-- case.
CREATE OR REPLACE FUNCTION moderation_accounts_page(
  p_before_at TIMESTAMPTZ DEFAULT NULL,
  p_before_id UUID        DEFAULT NULL,
  p_search    TEXT        DEFAULT NULL,
  p_limit     INTEGER     DEFAULT 100
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_out   JSONB;
  v_q     TEXT    := NULLIF(lower(left(btrim(COALESCE(p_search, '')), 100)), '');
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 100), 1), 500);
BEGIN
  PERFORM assert_central_admin();

  WITH page AS (
    SELECT a.id, a.email, a.created_at, a.email_confirmed_at, a.last_sign_in_at, u.handle
      FROM auth.users a
      LEFT JOIN users u ON u.id = a.id
     WHERE NOT EXISTS (SELECT 1 FROM central_admins m WHERE m.user_id = a.id)
       AND (p_before_at IS NULL OR (a.created_at, a.id) < (p_before_at, p_before_id))
       AND (v_q IS NULL
            OR strpos(lower(COALESCE(u.handle, '')), v_q) > 0
            OR strpos(lower(COALESCE(a.email, '')), v_q) > 0)
     ORDER BY a.created_at DESC, a.id DESC
     LIMIT v_limit
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'id', p.id, 'handle', p.handle, 'email', p.email,
           'created_at', p.created_at,
           'email_confirmed_at', p.email_confirmed_at,
           'last_active_at', GREATEST(p.last_sign_in_at, s.last_refresh),
           'sessions', COALESCE(s.sessions, 0),
           'servers_listed', (SELECT count(*) FROM public_servers ps WHERE ps.owner_id = p.id),
           'bots_listed', (SELECT count(*) FROM public_bots b WHERE b.owner_id = p.id),
           'banned', EXISTS (SELECT 1 FROM directory_bans d WHERE d.user_id = p.id))
           ORDER BY p.created_at DESC, p.id DESC), '[]'::jsonb)
    INTO v_out
    FROM page p
    LEFT JOIN LATERAL (
      SELECT count(*) AS sessions,
             GREATEST(max(x.updated_at), max(x.refreshed_at AT TIME ZONE 'UTC')) AS last_refresh
        FROM auth.sessions x
       WHERE x.user_id = p.id
    ) s ON TRUE;
  RETURN v_out;
END; $$;

REVOKE ALL ON FUNCTION moderation_account_stats() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION moderation_accounts_page(TIMESTAMPTZ, UUID, TEXT, INTEGER)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION moderation_account_stats() TO authenticated;
GRANT EXECUTE ON FUNCTION moderation_accounts_page(TIMESTAMPTZ, UUID, TEXT, INTEGER)
  TO authenticated;
