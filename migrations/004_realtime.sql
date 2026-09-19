-- ============================================================
-- Rift central — 004: what a client is told
-- ============================================================
-- Central broadcasts; it does not replicate. No table is in
-- `supabase_realtime`: a published table has every change decoded by Realtime
-- whether or not anybody is watching, and the row that comes out is the stored
-- row. Instead each change a client needs is announced by a trigger onto
-- `user:<id>`, a topic only that person may join.
-- ============================================================

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

-- ============================================================
-- 3. Who may join
-- ============================================================
-- Your own topic, to listen. Nobody sends to a topic here but the database,
-- so there is no rule for sending, and without one a client cannot.

CREATE OR REPLACE FUNCTION can_join_topic(p_topic TEXT) RETURNS BOOLEAN
  LANGUAGE sql STABLE AS $$
  SELECT auth.uid() IS NOT NULL AND p_topic = 'user:' || auth.uid()
$$;

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

CREATE TRIGGER dm_messages_announce
  AFTER INSERT OR UPDATE OR DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION announce_dm();

CREATE TRIGGER notification_prefs_announce
  AFTER INSERT OR UPDATE OR DELETE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION announce_prefs();

CREATE TRIGGER friendships_announce
  AFTER INSERT OR UPDATE OR DELETE ON friendships
  FOR EACH ROW EXECUTE FUNCTION announce_friendship();

CREATE TRIGGER blocks_announce
  AFTER INSERT OR UPDATE OR DELETE ON blocks
  FOR EACH ROW EXECUTE FUNCTION announce_block();
