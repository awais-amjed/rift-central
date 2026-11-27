-- ============================================================
-- Rift central — 024: the app-speed half of the Nov 27 review
-- ============================================================
-- Two of the review's client costs have a part here. Neither changes what
-- anybody may see or do.
--
--   1. A friend action rang `graph` on both people's topics, the actor's
--      included, and the acting device re-read the graph for its own change
--      twice: once when the RPC answered and once more for the ring. The
--      ring on the actor's own topic now names the session that acted, so
--      that device can let it pass; the other side, and the actor's other
--      devices, hear it as before.
--   2. `friend_counts` read the caller's friendships three times, once per
--      count. Now once.
-- ============================================================

-- ---------- 1. who rang ----------
-- The session id, not the account: the account's other devices must still
-- re-read, since nothing else tells them. Only on the actor's own topic,
-- which only the actor can join; the other side's ring stays `{}`, so it
-- learns nothing it did not before. A write with no session behind it (an
-- edge function deleting an account, a moderator) names none, and every
-- device re-reads.
CREATE OR REPLACE FUNCTION graph_ring(p_user UUID) RETURNS JSONB
  LANGUAGE sql STABLE AS $$
  SELECT CASE
           WHEN p_user = auth.uid() AND auth.jwt() ->> 'session_id' IS NOT NULL
             THEN jsonb_build_object('session', auth.jwt() ->> 'session_id')
           ELSE '{}'::jsonb
         END
$$;

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
  PERFORM tell_user(v_low,  'graph', graph_ring(v_low));
  PERFORM tell_user(v_high, 'graph', graph_ring(v_high));
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION announce_block() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM tell_user(OLD.blocker_id, 'graph', graph_ring(OLD.blocker_id));
  ELSE
    PERFORM tell_user(NEW.blocker_id, 'graph', graph_ring(NEW.blocker_id));
  END IF;
  RETURN NULL;
END $$;

-- ---------- 2. the counts in one pass ----------
-- The same four numbers. Measured 17.6 ms at 5,000 friends with three passes
-- (Nov 27 review); one pass reads each row once.
CREATE OR REPLACE FUNCTION friend_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'friends',  count(*) FILTER (WHERE f.status = 'accepted'),
    -- Incoming only. Waiting for an answer is not something to be notified
    -- about, so an outgoing request is not in the badge.
    'incoming', count(*) FILTER (WHERE f.status = 'pending'
                                   AND f.requester_id <> me.id),
    'outgoing', count(*) FILTER (WHERE f.status = 'pending'
                                   AND f.requester_id = me.id),
    'blocked',  (SELECT count(*) FROM blocks b WHERE b.blocker_id = me.id))
    FROM (SELECT auth.uid() AS id) me
    LEFT JOIN friendships f ON me.id IN (f.low_id, f.high_id)
   GROUP BY me.id
$$;

REVOKE ALL ON FUNCTION graph_ring(UUID)       FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION announce_friendship()  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION announce_block()       FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION friend_counts()        FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION friend_counts()     TO authenticated;
