-- ============================================================
-- Rift central server — 010: relaying pushes for self-hosted servers
-- ============================================================
-- An FCM registration token is scoped to the Firebase project the app was
-- built against, so only the holder of Rift's credentials can wake a Rift
-- install. Somebody running their own server has no such credentials and must
-- not be handed them — which would leave every self-hosted community unable to
-- reach its own members' phones. So they ask here, and central forwards.
--
-- The whole of what central learns by forwarding is a device token and a
-- moment. Not the sender, not the text, not the server or channel it happened
-- in: the payload `push_send` builds is empty either way (009).
--
-- What makes that safe to offer is that it is *credentialled*. Without one,
-- this would be an open FCM proxy for Rift's project, and anyone who came by a
-- token could ring the phone behind it. A credential is enrolled by a signed-in
-- central account — the server's admin — which gives every forward an owner,
-- a daily ceiling and a revoke button.

-- ---------- credentials ----------
-- No uniqueness on (supabase_url, server_id), deliberately. A unique key would
-- let the first account to name somebody else's server hold the only slot for
-- it, and central cannot check who really administers a database it has never
-- heard of. Minting a second credential for the same server is harmless: it is
-- only usable by whoever holds its secret, and the server itself stores one.
--
-- The URL and id are recorded for the owner's benefit — so a revoke list reads
-- as server names rather than as opaque ids. Nothing here trusts them.

CREATE TABLE IF NOT EXISTS push_relays (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  supabase_url TEXT        NOT NULL CHECK (supabase_url ~ '^https?://[^ ]+$'
                                           AND length(supabase_url) <= 200),
  server_id    UUID        NOT NULL,
  label        TEXT                 CHECK (length(label) <= 64),

  -- Only the digest. The secret is shown once, at enrolment, and written
  -- straight into the asking server's `push_config`; a leak of this table
  -- forwards nothing.
  secret_hash  TEXT        NOT NULL,

  -- A ceiling per calendar day (UTC), rolled by `claim_relay_push`. Generous
  -- for a community server and small enough that a stolen credential is a
  -- nuisance rather than a bill.
  daily_cap    INTEGER     NOT NULL DEFAULT 20000 CHECK (daily_cap > 0),
  rung_today   INTEGER     NOT NULL DEFAULT 0,
  window_date  DATE        NOT NULL DEFAULT current_date,

  is_disabled  BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_push_relays_owner ON push_relays (owner_id);

ALTER TABLE push_relays ENABLE ROW LEVEL SECURITY;

-- Owners may look at and revoke their own credentials, and nothing else. The
-- column grant is what keeps `secret_hash` and the counters out of reach even
-- though the row is theirs.
DROP POLICY IF EXISTS push_relays_own_read ON push_relays;
CREATE POLICY push_relays_own_read ON push_relays FOR SELECT TO authenticated
  USING (owner_id = auth.uid());

DROP POLICY IF EXISTS push_relays_own_delete ON push_relays;
CREATE POLICY push_relays_own_delete ON push_relays FOR DELETE TO authenticated
  USING (owner_id = auth.uid());

REVOKE ALL ON push_relays FROM anon, authenticated;
GRANT SELECT (id, created_at, supabase_url, server_id, label, is_disabled)
  ON push_relays TO authenticated;
GRANT DELETE ON push_relays TO authenticated;

-- ---------- enrolling ----------
-- The one moment the secret exists outside this table. The caller is the
-- server's admin, signed in to central; their client writes what comes back
-- into that server's `push_config` over its own admin-only endpoint. Neither
-- half is enough alone, which is what makes squatting on a (url, id) pair
-- pointless.

CREATE OR REPLACE FUNCTION enroll_push_relay(
  p_supabase_url TEXT,
  p_server_id    UUID,
  p_label        TEXT DEFAULT NULL
) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_owner  UUID := auth.uid();
  v_secret TEXT;
  v_id     UUID;
BEGIN
  IF v_owner IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  -- A bound on minting, not on servers: nobody administers twenty servers and
  -- re-enrols each of them often, and an account that appears to is scripted.
  IF (SELECT count(*) FROM push_relays WHERE owner_id = v_owner) >= 20 THEN
    RAISE EXCEPTION 'too_many_relays';
  END IF;

  v_secret := encode(gen_random_bytes(32), 'base64');

  INSERT INTO push_relays (owner_id, supabase_url, server_id, label, secret_hash)
  VALUES (v_owner, p_supabase_url, p_server_id, p_label,
          encode(digest(v_secret, 'sha256'), 'hex'))
  RETURNING id INTO v_id;

  RETURN jsonb_build_object('relay_id', v_id, 'secret', v_secret);
END; $$;

REVOKE ALL ON FUNCTION enroll_push_relay(TEXT, UUID, TEXT) FROM public;
GRANT EXECUTE ON FUNCTION enroll_push_relay(TEXT, UUID, TEXT) TO authenticated;

-- ---------- spending ----------
-- Verify, meter and increment in one statement, because `push_send` runs many
-- at once and two forwards that each read 19,999 must not both be allowed.
-- Returns false for an unknown id, a wrong secret, a revoked credential and an
-- exhausted day alike: a caller learns only that it may not send.

CREATE OR REPLACE FUNCTION claim_relay_push(
  p_relay_id UUID,
  p_secret   TEXT,
  p_count    INTEGER
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_ok BOOLEAN;
BEGIN
  UPDATE push_relays
     SET rung_today  = CASE WHEN window_date = current_date
                            THEN rung_today + p_count ELSE p_count END,
         window_date = current_date
   WHERE id = p_relay_id
     AND NOT is_disabled
     AND secret_hash = encode(digest(p_secret, 'sha256'), 'hex')
     AND (CASE WHEN window_date = current_date THEN rung_today + p_count
               ELSE p_count END) <= daily_cap
   RETURNING true INTO v_ok;

  RETURN COALESCE(v_ok, false);
END; $$;

-- The service role only — this is `push_send`'s, and a client holding a secret
-- has no business spending it directly.
REVOKE ALL ON FUNCTION claim_relay_push(UUID, TEXT, INTEGER) FROM public, anon, authenticated;

-- ============================================================
-- Ringing central's own DMs: only when something changes
-- ============================================================
-- 009 rang the recipient on every insert. That is one wake, one relay call and
-- a little of somebody's battery per message, and all but the first of a burst
-- say nothing the first did not — the phone reads everything unread when it
-- wakes, so a doorbell during a conversation you already have unread is a
-- notification you have already been given.
--
-- Per conversation rather than per account: a first message from someone new
-- has to ring even while an unread thread with somebody else is sitting there.

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
