-- ============================================================
-- Rift central — 022: the Nov 27 review's security fixes
-- ============================================================
-- From the Nov 27 review of 013–021. Four small changes, each said again
-- beside its code:
--
--   1. A handle given up can no longer be taken in the moment it is given up.
--      `refuse_held_handle` checks the hold before the write, and the hold is
--      written by the releasing transaction's own AFTER trigger. A claim that
--      was already waiting on the unique index when that transaction
--      committed had passed the check, and won: the 30-day hold (020) was
--      beaten by asking in a loop while a rename or a deletion ran. Now the
--      check is made again after the write, when the waiter can see the
--      other's commit.
--   2. `send_dm` to an id with no account answers `not_friends`, as being
--      blocked does. A separate `recipient_has_no_profile` told a blocked
--      sender, by the difference, that the account was there.
--   3. A listing's or a bot's like count no longer drifts when two likes land
--      at once. Each count was taken in a snapshot from before the other
--      like committed; the row is now locked first, so the second count sees
--      the first like.
--   4. Read cursors and notification levels other people kept for a deleted
--      account (`read_state`, `notification_prefs`, scope 'dm') are removed
--      each night. `scope_id` has no foreign key, so the account's deletion
--      leaves them, and with them its id.
-- ============================================================

-- ---------- 1. the hold, checked again after the write ----------
-- The same test as `refuse_held_handle`. In READ COMMITTED each statement in
-- a function takes a fresh snapshot, so by the time this runs a claim that
-- waited on the unique index sees the hold the other transaction committed.
-- The BEFORE trigger stays: it gives a handle back to its previous owner and
-- clears that hold, which this one then finds gone.
CREATE OR REPLACE FUNCTION refuse_held_handle_after() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.handle IS NOT DISTINCT FROM OLD.handle THEN
    RETURN NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM released_handles r
              WHERE r.handle = NEW.handle
                AND r.released_at > now() - make_interval(days => handle_hold_days())
                AND r.previous_owner IS DISTINCT FROM NEW.id) THEN
    RAISE EXCEPTION 'handle_held' USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NULL;
END; $$;
REVOKE ALL ON FUNCTION refuse_held_handle_after() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS users_refuse_held_handle_after ON users;
CREATE TRIGGER users_refuse_held_handle_after AFTER INSERT OR UPDATE OF handle ON users
  FOR EACH ROW EXECUTE FUNCTION refuse_held_handle_after();

-- ---------- 2. send_dm: no account reads as not a friend ----------
-- 002's function with the `recipient_has_no_profile` check taken out; the
-- friends gate answers for it.
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
  -- The per-conversation cap. Past it the oldest ciphertext is gone for good.
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
  IF length(ciphertext) > 16384 OR length(nonce) > 64
     OR length(signature) > 128 OR key_version < 1 THEN
    RAISE EXCEPTION 'envelope_invalid';
  END IF;

  -- The gate. `blocked` is not raised separately: blocking deletes the
  -- friendship, so a blocked pair is a pair that is not friends, and the
  -- sender learns exactly what a stranger learns. An id with no account is
  -- not a friend either, and answers the same (022): a separate answer for
  -- it told a blocked sender, by the difference, that the account existed.
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
-- CREATE OR REPLACE keeps the grants, said again so this file stands alone.
REVOKE ALL ON FUNCTION send_dm(UUID, TEXT, TEXT, TEXT, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION send_dm(UUID, TEXT, TEXT, TEXT, INTEGER) TO authenticated;

-- ---------- 3. like counts that hold under concurrent likes ----------
-- Lock the listing first, then count in a statement of its own: a like that
-- committed while this one waited for the lock is in the count.
CREATE OR REPLACE FUNCTION recount_server_likes() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_listing UUID := COALESCE(NEW.listing_id, OLD.listing_id);
  v_count   INTEGER;
BEGIN
  PERFORM 1 FROM public_servers WHERE id = v_listing FOR UPDATE;
  SELECT count(*) INTO v_count FROM server_likes WHERE listing_id = v_listing;
  UPDATE public_servers SET like_count = v_count WHERE id = v_listing;
  RETURN NULL;
END; $$;
REVOKE ALL ON FUNCTION recount_server_likes() FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION recount_bot_likes() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot   UUID := COALESCE(NEW.bot_id, OLD.bot_id);
  v_count INTEGER;
BEGIN
  PERFORM 1 FROM public_bots WHERE id = v_bot FOR UPDATE;
  SELECT count(*) INTO v_count FROM bot_likes WHERE bot_id = v_bot;
  UPDATE public_bots SET like_count = v_count WHERE id = v_bot;
  RETURN NULL;
END; $$;
REVOKE ALL ON FUNCTION recount_bot_likes() FROM PUBLIC, anon, authenticated;

-- ---------- 4. what other people kept about a deleted account ----------
-- Nightly rather than on each deletion: `scope_id` has no index of its own,
-- and one on a table written by every mark_read would cost more than a
-- scan once a night. At 03:52, between the night's other jobs.
CREATE OR REPLACE FUNCTION prune_deleted_peers() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  DELETE FROM read_state r
   WHERE r.scope = 'dm'
     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = r.scope_id);
  DELETE FROM notification_prefs n
   WHERE n.scope = 'dm'
     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = n.scope_id);
END; $$;
REVOKE ALL ON FUNCTION prune_deleted_peers() FROM PUBLIC, anon, authenticated;

SELECT cron.unschedule('central-deleted-peer-prune')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-deleted-peer-prune');

SELECT cron.schedule(
  'central-deleted-peer-prune',
  '52 3 * * *',
  $$ SELECT public.prune_deleted_peers(); $$
);
