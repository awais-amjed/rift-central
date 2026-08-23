-- ============================================================
-- 009 — Push notifications
-- ============================================================
-- Local notifications only fire while the process is alive. On Android that
-- means they stop as soon as the system suspends the app, which is most of the
-- time — so a message arriving then was silently lost until the user next
-- opened Rift. Only a push can wake it.
--
-- What travels in a push is nothing: no sender, no text, no conversation, not
-- even ciphertext. An FCM payload is readable by Google and forwardable by
-- whatever relays it, so anything put in one is disclosed to both. This is a
-- doorbell — the same shape as the Realtime doorbells the client already uses,
-- where the database is the truth and the ping only says "look again". The
-- phone holds the keys, so it can fetch and decrypt the message itself once it
-- is awake, and the notification loses no detail for being announced by an
-- empty envelope.

CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;

-- ---------- where an account can be reached ----------
-- A row is a device, not a person: the same account on a phone and a tablet is
-- two rows and both should ring. The token is the key because FCM hands the
-- same one back to a reinstalled app, and a device that changes hands must
-- replace the previous owner's row rather than accumulate beside it.

CREATE TABLE IF NOT EXISTS device_tokens (
  token      TEXT        PRIMARY KEY,
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform   TEXT        NOT NULL CHECK (platform IN ('android', 'ios', 'web')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens (user_id);

-- Stamped rather than accepted from the client, the same way `dm_messages`
-- stamps its sender: a client that could name the owner could register its
-- token against somebody else's account and receive that person's doorbells.
CREATE OR REPLACE FUNCTION stamp_device_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  NEW.user_id := auth.uid();
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS device_tokens_stamp ON device_tokens;
CREATE TRIGGER device_tokens_stamp BEFORE INSERT OR UPDATE ON device_tokens
  FOR EACH ROW EXECUTE FUNCTION stamp_device_owner();

ALTER TABLE device_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_tokens_own ON device_tokens;
CREATE POLICY device_tokens_own ON device_tokens FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

REVOKE ALL ON device_tokens FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_tokens TO authenticated;

-- ---------- where to ring ----------
-- One row, and nobody can read it. The sender lives in an edge function
-- holding the FCM credentials; this is only the address and the shared secret
-- that proves a call came from here. RLS with no policy at all is the point:
-- the trigger below reaches it as SECURITY DEFINER and no session ever can.

CREATE TABLE IF NOT EXISTS push_config (
  id       BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
  endpoint TEXT    NOT NULL,
  secret   TEXT    NOT NULL
);

ALTER TABLE push_config ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON push_config FROM anon, authenticated;

-- ---------- ringing ----------
-- Fired from the row rather than from `send_dm`, so a message inserted by any
-- future path still rings. `net.http_post` queues and returns immediately: the
-- push must not be able to slow down, or fail, the send that caused it — a
-- delivered message with no doorbell is a much smaller problem than a message
-- that could not be sent because a push gateway was down.

CREATE OR REPLACE FUNCTION ring_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg push_config;
BEGIN
  SELECT * INTO v_cfg FROM push_config LIMIT 1;
  IF v_cfg IS NULL THEN
    RETURN NEW;   -- push not configured on this deployment
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

DROP TRIGGER IF EXISTS dm_messages_ring ON dm_messages;
CREATE TRIGGER dm_messages_ring AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION ring_recipient();
