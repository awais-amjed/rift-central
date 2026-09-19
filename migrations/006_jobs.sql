-- ============================================================
-- Rift central — 006: scheduled work
-- ============================================================
-- DM retention, and the sweep that removes an attachment whose message is
-- gone. Both run on pg_cron.
-- ============================================================

-- ============================================================
-- Retention
-- ============================================================
-- The two limits that make central affordable, enforced by the database rather
-- than by clients: nothing older than 30 days, and no more than 500 messages
-- per conversation. Both are hard deletes — past the cap the ciphertext is
-- gone, and clients simply render what is still there.
--
-- This is the difference between the tiers stated as a cron job: a self-hosted
-- server keeps everything, because it is somebody's own disk.

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.unschedule('central-dm-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-dm-retention');

SELECT cron.schedule(
  'central-dm-retention',
  '17 3 * * *',
  $$
  DELETE FROM dm_messages WHERE created_at < now() - interval '30 days';

  DELETE FROM dm_messages WHERE id IN (
    SELECT id FROM (
      SELECT id,
             row_number() OVER (
               PARTITION BY LEAST(sender_id, recipient_id),
                            GREATEST(sender_id, recipient_id)
               ORDER BY id DESC
             ) AS rn
        FROM dm_messages
    ) ranked
    WHERE rn > 500
  );
  $$
);

-- ---------- the sweep's half ----------
-- Which blobs are safe to delete, found without any message-to-blob link — the
-- server cannot have one, because the paths live inside encrypted bodies.
--
-- Age is enough. Retention deletes every message older than 30 days, and a blob is
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

-- ============================================================
-- Run the attachment sweep daily
-- ============================================================
-- pg_cron only installs in the database named by `cron.database_name`, which
-- is why everything scheduled lives in this one file.
--
-- Half an hour after the retention job (03:17), so the messages that expire
-- today are already gone. The sweep only removes blobs older than 31 days, so
-- the order is tidiness rather than correctness.

SELECT cron.unschedule('central-dm-attachment-sweep')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-dm-attachment-sweep');

SELECT cron.schedule(
  'central-dm-attachment-sweep',
  '47 3 * * *',
  $$SELECT request_attachment_sweep()$$
);

-- ============================================================
-- Retention keeps only the age limit
-- ============================================================
-- Age only, with no ranking: `send_dm` keeps each conversation to its newest
-- 500 as it goes, so the night has only the 30 days to enforce, and
-- idx_dm_messages_created makes that a range scan.

SELECT cron.unschedule('central-dm-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'central-dm-retention');

SELECT cron.schedule(
  'central-dm-retention',
  '17 3 * * *',
  $$ DELETE FROM dm_messages WHERE created_at < now() - interval '30 days'; $$
);
