-- ============================================================
-- Rift central — 011: per-conversation notification levels
-- ============================================================
-- The central half of the self-hosted server's 012. Same table, same defaults,
-- same client path — minus the channel half, because central has no rooms.
--
-- So there are two levels here in practice, `all` and `none`: a DM is somebody
-- talking to you, and there is nobody else in it to be named among. `mentions`
-- exists in the type only so both tiers spell the setting the same way; a row
-- that somehow says it reads as `all`, which is the answer that loses nobody a
-- message.

DO $$ BEGIN
  CREATE TYPE notify_level AS ENUM ('all', 'mentions', 'none');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Spelled the same way as on a self-hosted server so both tiers answer one
-- client path, `server` included — central has no servers to scope anything
-- to, in the same way it has no channels and `read_scope` carries 'channel'
-- here regardless. An unused value costs nothing; two different types would
-- cost a branch in every caller.
DO $$ BEGIN
  CREATE TYPE notify_scope AS ENUM ('server', 'channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Keyed exactly like `read_state`. A row exists only where somebody has
-- changed something, so the default costs no write and "reset" is a DELETE.
CREATE TABLE IF NOT EXISTS notification_prefs (
  user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope      notify_scope NOT NULL,
  -- The other person's user id, for 'dm'.
  scope_id   UUID         NOT NULL,
  level      notify_level NOT NULL,
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);

-- Stamped, not accepted: a client that could name the owner could mute
-- somebody else's conversations, which is a quiet way of making sure a person
-- never hears from anyone again.
CREATE OR REPLACE FUNCTION stamp_notification_pref()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS notification_prefs_stamp ON notification_prefs;
CREATE TRIGGER notification_prefs_stamp BEFORE INSERT OR UPDATE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION stamp_notification_pref();

ALTER TABLE notification_prefs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notification_prefs_own ON notification_prefs;
CREATE POLICY notification_prefs_own ON notification_prefs FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

REVOKE ALL ON notification_prefs FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_prefs TO authenticated;

-- What a conversation is set to, default included. SECURITY DEFINER because
-- the ring trigger asks it about the *recipient*, whose rows the sender's
-- session may not read.
CREATE OR REPLACE FUNCTION notify_level_for(
  p_user UUID, p_scope public.notify_scope, p_scope_id UUID
) RETURNS public.notify_level LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT COALESCE(
    (SELECT p.level FROM notification_prefs p
      WHERE p.user_id = p_user AND p.scope = p_scope AND p.scope_id = p_scope_id),
    'all'::notify_level
  );
$$;

REVOKE ALL ON FUNCTION notify_level_for(UUID, public.notify_scope, UUID)
  FROM public, anon, authenticated;

-- Watched, so a level set on one device reaches the others.
--
-- Without this the setting is per-device in everything but storage: written to
-- central, read once at sign-in, and never looked at again — so the desktop
-- you left open goes on announcing a conversation you muted on your phone.
-- Own-row RLS applies to a subscription as it does to a read, so what arrives
-- is only ever your own rows.
--
-- `REPLICA IDENTITY FULL` because clearing a pref is a DELETE, and a default
-- replica identity ships only the primary key — which here is the whole of
-- what the row said. 008 argues for publishing only what something actually
-- subscribes to; this is now one of those things.
ALTER TABLE notification_prefs REPLICA IDENTITY FULL;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE notification_prefs;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- Ringing, with the level applied
-- ============================================================
-- Replaces 010's version. The unread gate is unchanged — a doorbell says *look
-- again*, and says nothing new while the badge is already lit — and a muted
-- conversation simply never gets past the first line.

CREATE OR REPLACE FUNCTION ring_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg push_config;
BEGIN
  IF notify_level_for(NEW.recipient_id, 'dm', NEW.sender_id) = 'none' THEN
    RETURN NEW;
  END IF;

  SELECT * INTO v_cfg FROM push_config LIMIT 1;
  IF v_cfg IS NULL THEN
    RETURN NEW;   -- push not configured on this deployment
  END IF;

  IF EXISTS (
    SELECT 1 FROM dm_messages d
     WHERE d.recipient_id = NEW.recipient_id
       AND d.sender_id    = NEW.sender_id
       AND d.id < NEW.id
       AND d.id > COALESCE((SELECT r.last_read_id FROM read_state r
                             WHERE r.user_id = NEW.recipient_id
                               AND r.scope = 'dm'
                               AND r.scope_id = NEW.sender_id), 0)
  ) THEN
    RETURN NEW;
  END IF;

  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object(
                 'Content-Type', 'application/json',
                 'x-push-secret', v_cfg.secret
               ),
    body    := jsonb_build_object('recipient', NEW.recipient_id)
  );
  RETURN NEW;
END; $$;

-- ============================================================
-- Telling the client
-- ============================================================
-- Folded into `unread_counts()` for the same reason as on a self-hosted
-- server: every caller of one wants the other, and asking twice means drawing
-- badges from one moment and mute state from another. Same shape as there,
-- minus the channels.

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
      ) d), '{}'::jsonb),
    'prefs', jsonb_build_object(
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::text)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'dm'), '{}'::jsonb)
    )
  );
$$;

GRANT EXECUTE ON FUNCTION unread_counts() TO authenticated;
