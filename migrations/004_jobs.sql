-- ============================================================
-- Rift central server — 004: retention
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
