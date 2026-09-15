-- ============================================================
-- Rift central server — 017: attachments leave with their messages
-- ============================================================
-- Until this, nothing ever deleted a central DM attachment. 005 let members
-- upload and read blobs but not delete them, so the app's "deleting a message
-- deletes its files" call removed nothing, and 004's retention sweep deletes
-- message rows while every blob they pointed at stays in storage for good.
--
-- Two halves, the same split as a self-hosted server:
--   * the uploader deletes a message's blobs when deleting the message. The app
--     holds the paths (they are inside the encrypted body) and already asks;
--     the policy below is what lets the request do anything.
--   * a daily sweep removes everything retention made unreachable. Postgres
--     cannot delete a blob — `storage.protect_delete()` refuses direct DELETE on
--     `storage.objects` — so the database only decides *which*, and an edge
--     function holding the service key carries it out (018 schedules it).

-- ---------- the uploader's half ----------
-- Own folder only. Objects are written as `<uploader uid>/<random>.bin`, and a
-- recipient deleting a message they received cannot happen (002 gives delete to
-- the sender alone), so the sender is the only person who ever needs this.

DROP POLICY IF EXISTS central_dm_att_delete ON storage.objects;
CREATE POLICY central_dm_att_delete ON storage.objects FOR DELETE TO authenticated
  USING (bucket_id = 'central-dm-attachments'
         AND (storage.foldername(name))[1] = auth.uid()::text);

-- ---------- the sweep's half ----------
-- Which blobs are safe to delete, found without any message-to-blob link — the
-- server cannot have one, because the paths live inside encrypted bodies.
--
-- Age is enough. 004 deletes every message older than 30 days, and a blob is
-- uploaded moments before the message that carries its key, so a blob older
-- than 30 days belongs to a message that no longer exists. One more day of
-- margin covers the retention job itself running late.
--
-- What this does not catch early: blobs of messages removed by the 500-per-
-- conversation cap, or of messages whose insert failed after the upload. Blob
-- names say only who uploaded them, not which conversation they belong to, so
-- those wait out the same 31 days. That bounds them; it does not leak them.

CREATE OR REPLACE FUNCTION expired_dm_attachments(p_limit INTEGER DEFAULT 1000)
  RETURNS TEXT[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, storage AS $$
  SELECT COALESCE(array_agg(name ORDER BY created_at), '{}'::TEXT[])
    FROM (
      SELECT o.name, o.created_at
        FROM storage.objects o
       WHERE o.bucket_id = 'central-dm-attachments'
         AND o.created_at < now() - interval '31 days'
       ORDER BY o.created_at
       LIMIT GREATEST(p_limit, 0)
    ) oldest;
$$;

-- The edge function reaches it through PostgREST with the service key. Nobody
-- else has a use for a list of other people's blob names.
REVOKE ALL ON FUNCTION expired_dm_attachments(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION expired_dm_attachments(INTEGER) TO service_role;

-- Where the sweep function lives, and the secret that proves a call came from
-- this database. One row that no session can read, exactly like push_config:
-- only the SECURITY DEFINER function below reaches it.
CREATE TABLE IF NOT EXISTS attachment_sweep_config (
  id       BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
  endpoint TEXT    NOT NULL,
  secret   TEXT    NOT NULL
);

ALTER TABLE attachment_sweep_config ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON attachment_sweep_config FROM anon, authenticated;

-- Ask the edge function to sweep. Queued by pg_net and returns at once; the
-- function drains the backlog in batches on its own. Does nothing on a
-- deployment that has not configured a sweep.
CREATE OR REPLACE FUNCTION request_attachment_sweep()
  RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg attachment_sweep_config;
BEGIN
  SELECT * INTO v_cfg FROM attachment_sweep_config LIMIT 1;
  IF v_cfg IS NULL THEN
    RETURN;
  END IF;

  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object(
                 'Content-Type', 'application/json',
                 'x-sweep-secret', v_cfg.secret
               ),
    body    := '{}'::jsonb
  );
END; $$;

REVOKE ALL ON FUNCTION request_attachment_sweep() FROM PUBLIC, anon, authenticated;
